use super::{ExecutionIdentity, Observation, unavailable};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use std::{
    ffi::{CString, OsStr},
    io,
    mem::{MaybeUninit, size_of},
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, net::UnixStream, process::ExitStatusExt},
    path::Path,
    process::ExitStatus,
};

pub struct NativeStdio<'a> {
    pub stdin: BorrowedFd<'a>,
    pub stdout: BorrowedFd<'a>,
    pub stderr: BorrowedFd<'a>,
}

pub struct NativeChild {
    pid: u32,
    status: Option<ExitStatus>,
}

impl NativeChild {
    pub fn spawn(
        executable: &Path,
        args: &[String],
        cwd: &Path,
        environment: &[(&str, &OsStr)],
        stdio: NativeStdio<'_>,
    ) -> io::Result<Self> {
        if !executable.is_absolute() || !cwd.is_absolute() {
            return Err(unavailable());
        }
        let executable = native_string(executable.as_os_str().as_bytes())?;
        let cwd = native_string(cwd.as_os_str().as_bytes())?;
        let mut arguments = vec![executable.clone()];
        arguments.extend(
            args.iter()
                .map(|arg| native_string(arg.as_bytes()))
                .collect::<io::Result<Vec<_>>>()?,
        );
        let environment = environment
            .iter()
            .map(|(name, value)| {
                if name.is_empty() || name.contains('=') {
                    return Err(unavailable());
                }
                let mut entry = name.as_bytes().to_vec();
                entry.push(b'=');
                entry.extend_from_slice(value.as_bytes());
                native_string(&entry)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut argv = arguments
            .iter()
            .map(|arg| arg.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        argv.push(std::ptr::null_mut());
        let mut envp = environment
            .iter()
            .map(|entry| entry.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        envp.push(std::ptr::null_mut());
        let mut actions = SpawnActions::new()?;
        let mut attributes = SpawnAttributes::new()?;
        for (source, target) in [(stdio.stdin, 0), (stdio.stdout, 1), (stdio.stderr, 2)] {
            if source.as_raw_fd() < 3 {
                return Err(unavailable());
            }
            native_result(unsafe {
                libc::posix_spawn_file_actions_adddup2(&mut actions.0, source.as_raw_fd(), target)
            })?;
        }
        let mut sources = [
            stdio.stdin.as_raw_fd(),
            stdio.stdout.as_raw_fd(),
            stdio.stderr.as_raw_fd(),
        ];
        sources.sort_unstable();
        for (index, source) in sources.iter().enumerate() {
            if index == 0 || sources[index - 1] != *source {
                native_result(unsafe {
                    libc::posix_spawn_file_actions_addclose(&mut actions.0, *source)
                })?;
            }
        }
        native_result(unsafe {
            libc::posix_spawn_file_actions_addchdir_np(&mut actions.0, cwd.as_ptr())
        })?;
        let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        unsafe {
            libc::sigemptyset(&mut mask);
        }
        native_result(unsafe { libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) })?;
        unsafe {
            libc::sigaddset(&mut mask, libc::SIGPIPE);
        }
        native_result(unsafe { libc::posix_spawnattr_setsigdefault(&mut attributes.0, &mask) })?;
        native_result(unsafe {
            libc::posix_spawnattr_setflags(
                &mut attributes.0,
                (libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                    | libc::POSIX_SPAWN_SETSIGMASK
                    | libc::POSIX_SPAWN_SETSIGDEF) as i16,
            )
        })?;
        let mut pid = 0;
        native_result(unsafe {
            libc::posix_spawn(
                &mut pid,
                executable.as_ptr(),
                &actions.0,
                &attributes.0,
                argv.as_ptr(),
                envp.as_ptr(),
            )
        })?;
        if pid <= 1 {
            return Err(unavailable());
        }
        Ok(Self {
            pid: pid as u32,
            status: None,
        })
    }

    pub fn id(&self) -> u32 {
        self.pid
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.reap(libc::WNOHANG)
    }
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.reap(0)?.ok_or_else(unavailable)
    }

    pub fn kill(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        if unsafe { libc::kill(self.pid as i32, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn reap(&mut self, flags: i32) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid as i32, &mut status, flags) };
            if result == 0 {
                return Ok(None);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            self.status = Some(ExitStatus::from_raw(status));
            return Ok(self.status);
        }
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

fn native_string(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid process argument"))
}

fn native_result(status: i32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

struct SpawnActions(libc::posix_spawn_file_actions_t);

impl SpawnActions {
    fn new() -> io::Result<Self> {
        let mut actions = std::ptr::null_mut();
        native_result(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
        Ok(Self(actions))
    }
}

impl Drop for SpawnActions {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

struct SpawnAttributes(libc::posix_spawnattr_t);

impl SpawnAttributes {
    fn new() -> io::Result<Self> {
        let mut attributes = std::ptr::null_mut();
        native_result(unsafe { libc::posix_spawnattr_init(&mut attributes) })?;
        Ok(Self(attributes))
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

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

pub(super) fn verify_running_code(pid: u32, path: &str, requirement: &str) -> io::Result<()> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(i32::try_from(pid).map_err(|_| unavailable())?);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(io::Error::other)?;
    let requirement: SecRequirement = requirement.parse().map_err(io::Error::other)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(io::Error::other)?;
    if executable(pid)? != path {
        return Err(unavailable());
    }
    Ok(())
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
    use super::super::{OwnedChildIdentity, ProcessPeer};
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsFd;
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
        assert!(root.verify_process(&peer).is_err());
        assert!(peer.own_root().unwrap().verify_process(&peer).is_ok());
        assert!(peer.root(other.child.id()).is_err());
    }

    #[test]
    fn retained_peer_and_root_both_reject_same_image_exec_after_capture() {
        let (mut shell, peer, _directory) = connected_shell(false);
        let root = peer.root(shell.child.id()).unwrap();
        assert!(root.verify_process(&peer).is_ok());
        shell.command("exec /bin/zsh -f\nprint ready");
        assert!(peer.revalidate().is_err());
        assert!(root.verify_process(&peer).is_err());
        assert!(root.verify_descendant(&peer).is_err());
        assert!(root.revalidate().is_err());
    }

    #[test]
    fn process_scope_ends_when_the_requesting_process_exits() {
        let (mut shell, peer, _directory) = connected_shell(false);
        let root = peer.own_root().unwrap();
        assert!(root.verify_process(&peer).is_ok());
        shell.child.kill().unwrap();
        shell.child.wait().unwrap();
        assert!(root.verify_process(&peer).is_err());
        assert!(root.revalidate().is_err());
    }

    #[test]
    fn socket_peer_guard_rejects_exec_without_private_process_queries() {
        let (mut shell, peer, _directory) = connected_shell(false);
        let identity = crate::peer_identity::PeerIdentity::capture(&peer.stream).unwrap();
        let socket = identity.socket_peer(&peer.stream).unwrap();
        assert!(socket.revalidate().is_ok());
        shell.command("exec /bin/zsh -f\nprint ready");
        assert!(socket.revalidate().is_err());
        assert!(socket.revalidate().is_err());
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

    fn owned_shell_identity(shell: &Shell) -> OwnedChildIdentity {
        let executable = std::path::Path::new("/bin/zsh");
        let requirement = crate::peer_identity::requirement_for_path(executable).unwrap();
        OwnedChildIdentity::capture(&shell.child, executable, &requirement).unwrap()
    }

    #[test]
    fn owned_child_requires_the_configured_running_executable() {
        let shell = Shell::new();
        let identity = owned_shell_identity(&shell);
        assert!(identity.revalidate().is_ok());
        let different = std::path::Path::new("/bin/sh");
        let different_requirement = crate::peer_identity::requirement_for_path(different).unwrap();
        assert!(
            OwnedChildIdentity::capture(&shell.child, different, &different_requirement).is_err()
        );
        assert!(
            OwnedChildIdentity::capture(
                &shell.child,
                std::path::Path::new("/bin/zsh"),
                &different_requirement
            )
            .is_err()
        );
        assert!(
            OwnedChildIdentity::capture(
                &shell.child,
                std::path::Path::new("/bin/zsh"),
                "anchor apple"
            )
            .is_err()
        );
    }

    #[test]
    fn owned_child_same_image_exec_permanently_ends_delivery_authority() {
        let mut shell = Shell::new();
        let identity = owned_shell_identity(&shell);
        assert!(identity.revalidate().is_ok());
        shell.command("exec /bin/zsh -f\nprint ready");
        assert!(identity.revalidate().is_err());
        assert!(identity.revalidate().is_err());
    }

    #[test]
    fn owned_child_exit_ends_delivery_authority() {
        let mut shell = Shell::new();
        let identity = owned_shell_identity(&shell);
        shell.child.kill().unwrap();
        shell.child.wait().unwrap();
        assert!(identity.revalidate().is_err());
        assert!(identity.revalidate().is_err());
    }

    #[test]
    fn owned_child_cannot_recover_after_an_intermediate_different_image_exec() {
        let mut shell = Shell::new();
        let identity = owned_shell_identity(&shell);
        shell.command("exec /bin/sh\nprintf 'ready\\n'");
        shell.command("exec /bin/zsh -f\nprint ready");
        assert!(identity.revalidate().is_err());
    }

    #[test]
    fn owned_child_exec_during_code_validation_rejects_before_admission() {
        let mut shell = Shell::new();
        let identity = owned_shell_identity(&shell);
        assert!(
            identity
                .revalidate_with(|| {
                    shell.command("exec /bin/zsh -f\nprint ready");
                    Ok(())
                })
                .is_err()
        );
        assert!(identity.revalidate().is_err());
    }

    #[test]
    fn owned_child_lost_monitor_and_failed_code_validation_are_permanent() {
        for lost_monitor in [false, true] {
            let shell = Shell::new();
            let identity = owned_shell_identity(&shell);
            if lost_monitor {
                *identity.watch.lock().unwrap() = None;
            } else {
                assert!(identity.revalidate_with(|| Err(unavailable())).is_err());
            }
            assert!(identity.revalidate().is_err());
            assert!(identity.revalidate().is_err());
        }
    }

    #[test]
    fn owned_child_parent_generation_mismatch_permanently_rejects() {
        let shell = Shell::new();
        let mut identity = owned_shell_identity(&shell);
        let parent = identity.parent;
        identity.parent.generation = parent.generation.wrapping_add(1);
        assert!(identity.revalidate().is_err());
        identity.parent = parent;
        assert!(identity.revalidate().is_err());
    }

    #[test]
    fn native_spawn_preserves_only_explicit_stdio_and_returns_the_child_status() {
        let extra = std::fs::File::open("/dev/null").unwrap();
        let flags = unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(
            unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        let (input, mut writer) = io::pipe().unwrap();
        let (mut output, stdout) = io::pipe().unwrap();
        let (mut errors, stderr) = io::pipe().unwrap();
        let executable = Path::new("/bin/zsh");
        let requirement = crate::peer_identity::requirement_for_path(executable).unwrap();
        let script = format!(
            "IFS= read -r value; if : < /dev/fd/{}; then exit 24; fi; print -rn -- \"$value\"; print -rn -u2 -- diagnostic; exit 23",
            extra.as_raw_fd()
        );
        let mut child = NativeChild::spawn(
            executable,
            &["-f".into(), "-c".into(), script],
            Path::new("/"),
            &[("PATH", OsStr::new("/usr/bin:/bin"))],
            NativeStdio {
                stdin: input.as_fd(),
                stdout: stdout.as_fd(),
                stderr: stderr.as_fd(),
            },
        )
        .unwrap();
        drop((input, stdout, stderr));
        let identity =
            OwnedChildIdentity::capture_native(&child, executable, &requirement).unwrap();
        identity.revalidate().unwrap();
        writer.write_all(b"native-input\n").unwrap();
        drop(writer);
        assert_eq!(child.wait().unwrap().code(), Some(23));
        assert_eq!(child.try_wait().unwrap().unwrap().code(), Some(23));
        let mut text = String::new();
        output.read_to_string(&mut text).unwrap();
        assert_eq!(text, "native-input");
        text.clear();
        errors.read_to_string(&mut text).unwrap();
        assert!(text.ends_with("diagnostic"));
        assert!(identity.revalidate().is_err());
    }
}
