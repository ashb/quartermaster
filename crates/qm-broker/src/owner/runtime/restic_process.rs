use qm_macos::process_scope::{NativeChild, NativeStdio, OwnedChildIdentity};
use std::{
    ffi::OsStr,
    io::{self, PipeReader, PipeWriter},
    os::fd::{AsFd, AsRawFd},
    path::Path,
    process::ExitStatus,
};

const F_SETNOSIGPIPE: libc::c_int = 73;

pub(super) struct Launch {
    child: NativeChild,
    identity: OwnedChildIdentity,
    password: Option<PipeWriter>,
    atomic_limit: usize,
    stdout: Option<PipeReader>,
    stderr: Option<PipeReader>,
}

pub(super) fn validate_arguments(args: &[String]) -> io::Result<()> {
    let mut repo = None;
    let mut arguments = args.iter();
    while let Some(arg) = arguments.next() {
        let option = arg.split('=').next().unwrap();
        if arg == "--"
            || arg == "-o"
            || arg == "-p"
            || arg.starts_with("--option")
            || (arg.starts_with("--") && option.contains("password"))
            || arg.starts_with("--from-")
            || arg.starts_with("--repository")
            || arg.starts_with("--repo-file")
            || arg.starts_with("--stdin")
        {
            return Err(io::Error::other(
                "unsupported Restic credential or input option",
            ));
        }
        let path = if arg == "--repo" || arg == "-r" {
            Some(
                arguments
                    .next()
                    .ok_or_else(|| io::Error::other("missing repository path"))?
                    .as_str(),
            )
        } else if let Some(path) = arg.strip_prefix("--repo=") {
            Some(path)
        } else if let Some(path) = arg.strip_prefix("-r") {
            Some(path.strip_prefix('=').unwrap_or(path))
        } else {
            if arg.starts_with('-') && !arg.starts_with("--") && arg.len() != 2 {
                return Err(io::Error::other(
                    "unsupported Restic shorthand bundle or attached value",
                ));
            }
            None
        };
        if let Some(path) = path
            && (repo.replace(path).is_some() || !Path::new(path).is_absolute())
        {
            return Err(io::Error::other(
                "Restic handoff currently requires one absolute local repository path",
            ));
        }
    }
    if repo.is_none() {
        return Err(io::Error::other(
            "specify --repo with an absolute local repository path",
        ));
    }
    Ok(())
}

impl Launch {
    pub(super) fn start(
        executable: &Path,
        args: &[String],
        cwd: &Path,
        expected_requirement: &str,
    ) -> io::Result<Self> {
        validate_arguments(args)?;
        let mut arguments = vec!["--password-file".into(), "/dev/fd/0".into()];
        arguments.extend_from_slice(args);
        Self::spawn(executable, &arguments, cwd, expected_requirement)
    }

    pub(super) fn spawn(
        executable: &Path,
        args: &[String],
        cwd: &Path,
        expected_requirement: &str,
    ) -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        let read_fd = reader.as_raw_fd();
        let write_fd = writer.as_raw_fd();
        if read_fd < 3 || write_fd < 3 {
            return Err(io::Error::other("password pipe descriptor unavailable"));
        }
        let flags = unsafe { libc::fcntl(write_fd, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(write_fd, F_SETNOSIGPIPE, 1) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let atomic_limit = unsafe { libc::fpathconf(write_fd, libc::_PC_PIPE_BUF) };
        if atomic_limit <= 0 {
            return Err(io::Error::other("password pipe capacity unavailable"));
        }
        let home = std::env::var_os("HOME").filter(|home| Path::new(home).is_absolute());
        let mut environment = vec![("PATH", OsStr::new("/usr/bin:/bin"))];
        if let Some(home) = &home {
            environment.push(("HOME", home.as_os_str()));
        }
        let (stdout, output) = io::pipe()?;
        let (stderr, errors) = io::pipe()?;
        let child = NativeChild::spawn(
            executable,
            args,
            cwd,
            &environment,
            NativeStdio {
                stdin: reader.as_fd(),
                stdout: output.as_fd(),
                stderr: errors.as_fd(),
            },
        )?;
        drop((reader, output, errors));
        let identity =
            OwnedChildIdentity::capture_native(&child, executable, expected_requirement)?;
        Ok(Self {
            child,
            identity,
            password: Some(writer),
            atomic_limit: atomic_limit as usize,
            stdout: Some(stdout),
            stderr: Some(stderr),
        })
    }

    pub(super) fn release_checked(
        &mut self,
        password: &[u8],
        before_write: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let writer = self
            .password
            .take()
            .ok_or_else(|| io::Error::other("password delivery consumed"))?;
        if password.is_empty()
            || password.len() > self.atomic_limit
            || password
                .iter()
                .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
        {
            return Err(io::Error::other("password is not a supported single line"));
        }
        self.identity.revalidate()?;
        before_write()?;
        let written =
            unsafe { libc::write(writer.as_raw_fd(), password.as_ptr().cast(), password.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != password.len() {
            return Err(io::Error::other("uncertain password delivery"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn release(&mut self, password: &[u8]) -> io::Result<()> {
        self.release_checked(password, || Ok(()))
    }

    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }

    pub(super) fn identity(&self) -> &OwnedChildIdentity {
        &self.identity
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    pub(super) fn take_stdout(&mut self) -> Option<PipeReader> {
        self.stdout.take()
    }

    pub(super) fn take_stderr(&mut self) -> Option<PipeReader> {
        self.stderr.take()
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        self.password.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read},
        os::fd::{FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };

    fn fixture(script: &str) -> Launch {
        let executable = Path::new("/bin/bash");
        let requirement = qm_macos::peer_identity::requirement_for_path(executable).unwrap();
        Launch::spawn(
            executable,
            &[
                "-c".into(),
                script.into(),
                "fixture".into(),
                "/dev/fd/0".into(),
            ],
            Path::new("/"),
            &requirement,
        )
        .unwrap()
    }

    #[test]
    fn password_pipe_delivers_once_only_to_the_owned_child() {
        let mut launch = fixture("IFS= read -r value < \"$1\"; test \"$value\" = dummy-password");
        launch.release(b"dummy-password").unwrap();
        assert!(launch.release(b"second-password").is_err());
        assert!(wait(&mut launch).success());
    }

    #[test]
    fn secret_source_overrides_are_rejected_before_spawn() {
        for argument in [
            "--password-file=other",
            "--password-command=cat",
            "--new-password-file",
            "--password-file2",
            "--insecure-no-password",
            "-pother",
            "-vpother",
            "--stdin",
            "--stdin-from-command",
        ] {
            assert!(
                Launch::start(
                    Path::new("/missing"),
                    &[argument.into()],
                    Path::new("/"),
                    "missing"
                )
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported")
            );
        }
    }

    #[test]
    fn unsupported_repository_and_shorthand_options_are_rejected_before_spawn() {
        for args in [
            vec!["--repo", "/tmp/local", "-qr", "s3:bucket", "snapshots"],
            vec!["--repo", "/tmp/local", "-ofoo=bar", "snapshots"],
            vec!["--repo", "/tmp/local", "-qo", "foo=bar", "snapshots"],
            vec!["-rs3:bucket", "snapshots"],
            vec!["--repo=sftp:host:/repo", "snapshots"],
            vec!["--repo=/tmp/local", "--repo=/tmp/other", "snapshots"],
        ] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            let error = Launch::start(Path::new("/missing"), &args, Path::new("/"), "missing")
                .err()
                .unwrap();
            assert_ne!(error.kind(), io::ErrorKind::NotFound, "{args:?}");
        }
    }

    #[test]
    fn supported_local_arguments_reach_native_spawn() {
        for repo in [
            vec!["--repo", "/tmp/local"],
            vec!["--repo=/tmp/local"],
            vec!["-r", "/tmp/local"],
            vec!["-r/tmp/local"],
            vec!["-r=/tmp/local"],
        ] {
            let args = repo
                .into_iter()
                .chain(["-q", "--no-cache", "snapshots"])
                .map(String::from)
                .collect::<Vec<_>>();
            let error = Launch::start(Path::new("/missing"), &args, Path::new("/"), "missing")
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::NotFound, "{args:?}");
        }
    }

    fn wait(launch: &mut Launch) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = launch.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn invalid_passwords_consume_delivery_without_writing_bytes() {
        for password in [
            b"".as_slice(),
            b"first\nsecond",
            b"first\rsecond",
            b"first\0second",
            &vec![b'x'; 65536],
        ] {
            let mut launch = fixture("value=; IFS= read -r value < \"$1\"; test -z \"$value\"");
            assert!(launch.release(password).is_err());
            assert!(launch.release(b"replacement").is_err());
            assert!(wait(&mut launch).success());
        }
    }

    #[test]
    fn final_admission_rejection_closes_the_pipe_without_bytes_or_retry() {
        let mut launch = fixture("value=; IFS= read -r value < \"$1\"; test -z \"$value\"");
        let mut checked = false;
        assert!(
            launch
                .release_checked(b"dummy-password", || {
                    checked = true;
                    Err(io::Error::other("cancelled"))
                })
                .is_err()
        );
        assert!(checked);
        assert!(launch.release(b"replacement").is_err());
        assert!(wait(&mut launch).success());
    }

    #[test]
    fn recipient_exit_prevents_password_delivery() {
        let mut launch = fixture("IFS= read -r value < \"$1\"");
        assert_eq!(unsafe { libc::kill(launch.pid() as i32, libc::SIGKILL) }, 0);
        assert!(!wait(&mut launch).success());
        assert!(launch.release(b"dummy-password").is_err());
    }

    #[test]
    fn a_closed_recipient_pipe_fails_without_a_sigpipe_or_retry() {
        let mut launch =
            fixture("eval \"exec ${1##*/}<&-\"; printf 'closed\\n'; while :; do :; done");
        let mut output = BufReader::new(launch.take_stdout().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "closed\n");
        assert!(launch.release(b"dummy-password").is_err());
        assert!(launch.release(b"replacement").is_err());
    }

    #[test]
    fn dropped_launch_kills_and_reaps_a_child_waiting_for_approval() {
        let launch = fixture("IFS= read -r value < \"$1\"");
        let pid = launch.pid() as i32;
        drop(launch);
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn child_output_and_failure_status_remain_separate_from_password_delivery() {
        let mut launch =
            fixture("IFS= read -r value < \"$1\"; printf output; printf diagnostic >&2; exit 23");
        let mut stdout = launch.take_stdout().unwrap();
        let mut stderr = launch.take_stderr().unwrap();
        launch.release(b"dummy-password").unwrap();
        assert_eq!(wait(&mut launch).code(), Some(23));
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        assert_eq!(output, "output");
        output.clear();
        stderr.read_to_string(&mut output).unwrap();
        assert_eq!(output, "diagnostic");
    }

    #[test]
    fn child_environment_is_allowlisted_and_stdin_is_closed() {
        let mut launch = fixture(
            "IFS= read -r value < \"$1\"; if IFS= read -r input; then exit 23; fi; /usr/bin/env",
        );
        let mut stdout = launch.take_stdout().unwrap();
        launch.release(b"dummy-password").unwrap();
        assert!(wait(&mut launch).success());
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        for line in output.lines() {
            let (name, _) = line.split_once('=').unwrap();
            assert!(
                matches!(name, "HOME" | "PATH" | "PWD" | "SHLVL" | "_"),
                "unexpected environment variable {name}"
            );
        }
        assert!(output.lines().any(|line| line == "PATH=/usr/bin:/bin"));
    }

    #[test]
    fn child_cannot_inherit_an_unrelated_descriptor_without_cloexec() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 512) };
        assert!(raw >= 512);
        let extra = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(
            unsafe { libc::fcntl(extra.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let mut launch = fixture(&format!(
            "IFS= read -r value < \"$1\"; if : < /dev/fd/{raw}; then exit 23; fi"
        ));
        launch.release(b"dummy-password").unwrap();
        assert!(wait(&mut launch).success());
    }

    #[test]
    fn spawn_and_identity_failure_return_without_retaining_a_child() {
        assert!(Launch::start(Path::new("/missing"), &[], Path::new("/"), "missing").is_err());
        assert!(
            Launch::spawn(
                Path::new("/bin/bash"),
                &["-c".into(), "read value".into()],
                Path::new("/"),
                "wrong requirement",
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires QM_TEST_RESTIC pointing to a native Restic executable"]
    fn native_restic_initialises_and_opens_a_disposable_repository() {
        let executable = std::path::PathBuf::from(std::env::var_os("QM_TEST_RESTIC").unwrap());
        let requirement = qm_macos::peer_identity::requirement_for_path(&executable).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        let repository = repository.to_str().unwrap();
        for arguments in [
            vec!["--repo".into(), repository.into(), "init".into()],
            vec!["--repo".into(), repository.into(), "snapshots".into()],
            vec![format!("--repo={repository}"), "snapshots".into()],
            vec!["-r".into(), repository.into(), "snapshots".into()],
            vec![format!("-r{repository}"), "snapshots".into()],
            vec![format!("-r={repository}"), "snapshots".into()],
        ] {
            let mut args = vec!["--no-cache".into(), "-q".into()];
            args.extend(arguments);
            let mut launch =
                Launch::start(&executable, &args, directory.path(), &requirement).unwrap();
            let mut stdout = launch.take_stdout().unwrap();
            let mut stderr = launch.take_stderr().unwrap();
            launch
                .release(b"quartermaster-disposable-dummy-password")
                .unwrap();
            let status = wait(&mut launch);
            let mut output = Vec::new();
            stdout.read_to_end(&mut output).unwrap();
            stderr.read_to_end(&mut output).unwrap();
            assert!(
                status.success(),
                "{status}: {}",
                String::from_utf8_lossy(&output)
            );
            assert!(
                !String::from_utf8_lossy(&output)
                    .contains("quartermaster-disposable-dummy-password")
            );
        }
    }
}
