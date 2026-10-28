use super::{ExecutionIdentity, Observation, unavailable};
use std::{
    io,
    mem::{MaybeUninit, size_of},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
};

// XNU's private flavour 18 combines BSD metadata with the exec-sensitive identity.
const PROC_PIDT_BSDINFOWITHUNIQID: i32 = 18;
const PROC_FLAG_TRACED: u32 = 2;
const PROC_FLAG_INEXIT: u32 = 4;

#[repr(C)]
struct UniqueInfo {
    executable_uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    generation: u32,
    original_parent_generation: u32,
    reserved: [u64; 2],
}

#[repr(C)]
struct ProcessInfo {
    bsd: libc::proc_bsdinfo,
    unique: UniqueInfo,
}

const _: () = assert!(size_of::<UniqueInfo>() == 56 && size_of::<ProcessInfo>() == 192);

pub(crate) fn peer_token(stream: &UnixStream) -> io::Result<[u32; 8]> {
    let mut token = [0u32; 8];
    let mut length = size_of_val(&token) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of_val(&token)
        || token[5] <= 1
    {
        return Err(unavailable());
    }
    Ok(token)
}

pub(super) fn executable(pid: u32) -> io::Result<String> {
    let mut buffer = [0u8; 4096];
    let count =
        unsafe { libc::proc_pidpath(pid as i32, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if count <= 0 || count as usize >= buffer.len() {
        return Err(unavailable());
    }
    std::str::from_utf8(&buffer[..count as usize])
        .map(str::to_owned)
        .map_err(|_| unavailable())
}

pub(super) fn observe(pid: u32) -> io::Result<Observation> {
    let pid = i32::try_from(pid).map_err(|_| unavailable())?;
    if pid <= 1 {
        return Err(unavailable());
    }
    let mut info = MaybeUninit::<ProcessInfo>::uninit();
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDT_BSDINFOWITHUNIQID,
            0,
            info.as_mut_ptr().cast(),
            size_of::<ProcessInfo>() as i32,
        )
    };
    if bytes != size_of::<ProcessInfo>() as i32 {
        return Err(unavailable());
    }
    let info = unsafe { info.assume_init() };
    if info.bsd.pbi_pid != pid as u32
        || !matches!(info.bsd.pbi_status, 2..=4)
        || info.bsd.pbi_flags & (PROC_FLAG_TRACED | PROC_FLAG_INEXIT) != 0
        || info.unique.unique_id == 0
        || info.unique.generation == 0
        || info.unique.original_parent_generation == 0
    {
        return Err(unavailable());
    }
    Ok(Observation {
        identity: ExecutionIdentity {
            pid: info.bsd.pbi_pid,
            uid: info.bsd.pbi_uid,
            unique_id: info.unique.unique_id,
            generation: info.unique.generation,
        },
        parent_pid: info.bsd.pbi_ppid,
        parent_unique_id: info.unique.parent_unique_id,
        parent_generation: info.unique.original_parent_generation,
    })
}

pub(super) struct Watch(OwnedFd);

impl Watch {
    pub(super) fn new() -> io::Result<Self> {
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    pub(super) fn register(&self, pid: u32) -> io::Result<()> {
        let event = libc::kevent {
            ident: pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        if unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn unchanged(&self) -> io::Result<()> {
        let mut event = MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let count = unsafe {
            libc::kevent(
                self.0.as_raw_fd(),
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &timeout,
            )
        };
        if count != 0 {
            return Err(unavailable());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ProcessPeer;
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::{net::UnixListener, process::CommandExt};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

    struct Shell {
        child: Child,
        input: ChildStdin,
        output: BufReader<ChildStdout>,
    }

    impl Shell {
        fn new() -> Self {
            let mut child = Command::new("/bin/zsh")
                .arg("-f")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap();
            let input = child.stdin.take().unwrap();
            let output = BufReader::new(child.stdout.take().unwrap());
            let mut shell = Self {
                child,
                input,
                output,
            };
            shell.command("print ready");
            shell
        }

        fn command(&mut self, command: &str) {
            writeln!(self.input, "{command}").unwrap();
            self.input.flush().unwrap();
            let mut line = String::new();
            self.output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "ready");
        }
    }

    impl Drop for Shell {
        fn drop(&mut self) {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn connected_shell(indirect: bool) -> (Shell, ProcessPeer, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer");
        let listener = UnixListener::bind(&path).unwrap();
        let mut shell = Shell::new();
        let path = path.to_str().unwrap().replace('\'', "'\\''");
        let connect = format!("zmodload zsh/net/socket; zsocket '{path}' || exit 1; print ready");
        if indirect {
            shell.command(&format!("( ({connect}; sleep 30; :) & wait) & wait"));
        } else {
            shell.command(&connect);
        }
        let (stream, _) = listener.accept().unwrap();
        let peer = ProcessPeer::capture(&stream, peer_token(&stream).unwrap()).unwrap();
        (shell, peer, directory)
    }

    #[test]
    fn native_descendants_without_a_pty_cannot_use_an_unrelated_shell_root() {
        let (shell, peer, _directory) = connected_shell(true);
        let other = Shell::new();
        let root = peer.root(shell.child.id()).unwrap();
        assert!(root.verify_descendant(&peer).is_ok());
        assert!(peer.root(other.child.id()).is_err());
    }

    #[test]
    fn retained_peer_and_root_both_reject_same_image_exec_after_capture() {
        let (mut shell, peer, _directory) = connected_shell(false);
        let root = peer.root(shell.child.id()).unwrap();
        shell.command("exec /bin/zsh -f\nprint ready");
        assert!(peer.revalidate().is_err());
        assert!(root.verify_descendant(&peer).is_err());
        assert!(root.revalidate().is_err());
    }

    #[test]
    fn native_same_image_exec_changes_generation_before_event_consumption() {
        let mut shell = Shell::new();
        let before = observe(shell.child.id()).unwrap();
        let watch = Watch::new().unwrap();
        watch.register(before.identity.pid).unwrap();
        assert!(watch.unchanged().is_ok());
        shell.command("exec /bin/zsh -f\nprint ready");
        let after = observe(shell.child.id()).unwrap();
        assert_eq!(before.identity.pid, after.identity.pid);
        assert_eq!(before.identity.unique_id, after.identity.unique_id);
        assert_ne!(before.identity.generation, after.identity.generation);
        assert!(watch.unchanged().is_err());
    }

    #[test]
    fn native_exit_invalidates_query_and_watch() {
        let mut shell = Shell::new();
        let watch = Watch::new().unwrap();
        watch.register(shell.child.id()).unwrap();
        shell.child.kill().unwrap();
        shell.child.wait().unwrap();
        assert!(observe(shell.child.id()).is_err());
        assert!(watch.unchanged().is_err());
    }

    #[test]
    fn native_queries_identify_the_current_process_without_a_terminal() {
        let observed = observe(std::process::id()).unwrap();
        assert_eq!(observed.identity.pid, std::process::id());
        assert_eq!(observed.identity.uid, unsafe { libc::geteuid() });
        assert_ne!(observed.identity.unique_id, 0);
        assert_ne!(observed.identity.generation, 0);
        assert!(observe(u32::MAX).is_err());
    }
}
