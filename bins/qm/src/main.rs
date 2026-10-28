mod paths;

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::Path,
    process::{ExitCode, ExitStatus, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    process::Command,
    signal::unix::{Signal, SignalKind, signal},
};

const USAGE: &str = "Usage: qm run gh -- [gh arguments]\n\nRun gh through Quartermaster using temporary configuration.";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Help,
    Gh(Vec<OsString>),
}

fn parse(args: &[OsString]) -> io::Result<Invocation> {
    match args {
        [] => Ok(Invocation::Help),
        [help] if help == "--help" || help == "-h" => Ok(Invocation::Help),
        [run, gh, separator, rest @ ..] if run == "run" && gh == "gh" && separator == "--" => {
            Ok(Invocation::Gh(rest.to_vec()))
        }
        _ => Err(io::Error::other(USAGE)),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let args = match parse(&args) {
        Ok(Invocation::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Invocation::Gh(args)) => args,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let result = (|| {
        let paths = paths::Paths::discover()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(run(&args, &paths))
    })();
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("qm: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[OsString], paths: &paths::Paths) -> io::Result<u8> {
    let mut signals = Signals::new()?;
    let mut backend = Command::new(&paths.backend);
    backend
        .arg("start")
        .stdout(Stdio::null())
        .kill_on_drop(true);
    let status = supervise(&mut backend.spawn()?, &mut signals).await?;
    if !status.success() {
        return Err(io::Error::other("could not start Quartermaster"));
    }
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::UnixStream::connect(&paths.socket).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    tokio::select! {
        result = ready => result.map_err(|_| io::Error::other("Quartermaster socket did not become ready"))?,
        signal = signals.next() => return Ok(128 + signal as u8),
    }
    let mut gh = Command::new("gh");
    gh.args(args);
    run_gh(&paths.socket, &std::env::temp_dir(), &mut gh, &mut signals)
        .await
        .map(exit_code)
}

struct GhConfig {
    directory: TempDir,
}

impl GhConfig {
    fn new_in(socket: &Path, temporary: &Path) -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("qm-gh-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(temporary)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("config.yml"))?;
        writeln!(file, "http_unix_socket: {}", serde_json::to_string(socket)?)?;
        Ok(Self { directory })
    }

    fn configure(&self, command: &mut Command) {
        command
            .env("GH_CONFIG_DIR", self.directory.path())
            .env("GH_TOKEN", "quartermaster-local-only")
            .env("GH_ENTERPRISE_TOKEN", "quartermaster-local-only")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GITHUB_ENTERPRISE_TOKEN")
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
            .kill_on_drop(true);
    }
}

async fn run_gh(
    socket: &Path,
    temporary: &Path,
    command: &mut Command,
    signals: &mut Signals,
) -> io::Result<ExitStatus> {
    let config = GhConfig::new_in(socket, temporary)?;
    config.configure(command);
    let result = supervise(&mut command.spawn()?, signals).await;
    config.directory.close()?;
    result
}

struct Signals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
    quit: Signal,
}

impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            quit: signal(SignalKind::quit())?,
        })
    }

    async fn next(&mut self) -> i32 {
        tokio::select! {
            _ = self.interrupt.recv() => libc::SIGINT,
            _ = self.terminate.recv() => libc::SIGTERM,
            _ = self.hangup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
        }
    }
}

async fn supervise(
    child: &mut tokio::process::Child,
    signals: &mut Signals,
) -> io::Result<ExitStatus> {
    loop {
        tokio::select! {
            status = child.wait() => return status,
            signal = signals.next() => {
                if let Some(pid) = child.id()
                    && unsafe { libc::kill(pid as i32, signal) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) { return Err(error); }
                }
            }
        }
    }
}

fn exit_code(status: ExitStatus) -> u8 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, fs, os::unix::fs::PermissionsExt, path::Path, time::Instant};

    #[test]
    fn gh_arguments_are_forwarded_without_shell_interpretation() {
        let args: Vec<OsString> = [
            "run",
            "gh",
            "--",
            "api",
            "a b",
            "$(touch never)",
            "--jq",
            ".number",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(parse(&args).unwrap(), Invocation::Gh(args[3..].to_vec()));
        for args in [
            vec!["run", "git", "--"],
            vec!["run", "gh"],
            vec!["run", "gh", "api"],
        ] {
            assert!(parse(&args.into_iter().map(Into::into).collect::<Vec<_>>()).is_err());
        }
    }

    #[test]
    fn configuration_is_private_escaped_and_removed_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let config =
            GhConfig::new_in(Path::new("/socket with \"quotes\"\n.sock"), root.path()).unwrap();
        let directory = config.directory.path().to_owned();
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let file = directory.join("config.yml");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = fs::read_to_string(file).unwrap();
        let encoded = text.strip_prefix("http_unix_socket: ").unwrap().trim_end();
        assert_eq!(
            serde_json::from_str::<String>(encoded).unwrap(),
            "/socket with \"quotes\"\n.sock"
        );
        drop(config);
        assert!(!directory.exists());
    }

    #[tokio::test]
    async fn child_environment_and_exit_status_are_preserved_without_leaving_config() {
        for code in [0, 23] {
            let root = tempfile::tempdir().unwrap();
            let record = root.path().join("record");
            let temporary = root.path().join("temporary");
            fs::create_dir(&temporary).unwrap();
            let mut command = tokio::process::Command::new("/bin/sh");
            command.args(["-c", "printf '%s\\n' \"$GH_HOST\" \"$GH_TOKEN\" \"${GITHUB_TOKEN-unset}\" \"$GH_CONFIG_DIR\" > \"$RECORD\"; exit \"$EXPECTED_CODE\""])
            .env("GH_HOST", "github.example").env("GH_TOKEN", "old-token").env("GITHUB_TOKEN", "fallback-token").env("RECORD", &record).env("EXPECTED_CODE", code.to_string());
            let status = run_gh(
                Path::new("/dummy.sock"),
                &temporary,
                &mut command,
                &mut Signals::new().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(exit_code(status), code);
            let record = fs::read_to_string(record).unwrap();
            let lines: Vec<_> = record.lines().collect();
            assert_eq!(
                &lines[..3],
                ["github.example", "quartermaster-local-only", "unset"]
            );
            assert!(!Path::new(lines[3]).exists());
            assert_eq!(fs::read_dir(temporary).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn a_missing_gh_executable_does_not_leave_configuration() {
        let root = tempfile::tempdir().unwrap();
        let mut command = tokio::process::Command::new(root.path().join("missing-gh"));
        assert!(
            run_gh(
                Path::new("/dummy.sock"),
                root.path(),
                &mut command,
                &mut Signals::new().unwrap()
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn termination_signals_reach_the_child_and_remove_configuration() {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            let root = tempfile::tempdir().unwrap();
            let mut fixture = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "tests::signal_fixture"])
                .env("QM_TEST_ROOT", root.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !root.path().join("ready").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !root.path().join("ready").exists() {
                let _ = fixture.kill();
                let status = fixture.wait().unwrap();
                panic!("signal fixture did not start: {status}");
            }
            assert_eq!(unsafe { libc::kill(fixture.id() as i32, signal) }, 0);
            let status = loop {
                if let Some(status) = fixture.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = fixture.kill();
                    let _ = fixture.wait();
                    panic!("signal fixture did not exit");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(128 + signal));
            let directory = fs::read_to_string(root.path().join("ready")).unwrap();
            assert!(!Path::new(directory.trim()).exists());
        }
    }

    #[test]
    #[ignore = "subprocess fixture for signal forwarding"]
    fn signal_fixture() {
        let root = std::path::PathBuf::from(std::env::var_os("QM_TEST_ROOT").unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf '%s\\n' \"$GH_CONFIG_DIR\" > \"$READY\"; exec /bin/sleep 60",
            ])
            .env("READY", root.join("ready"));
        let status = runtime
            .block_on(async {
                run_gh(
                    Path::new("/dummy.sock"),
                    &root,
                    &mut command,
                    &mut Signals::new().unwrap(),
                )
                .await
            })
            .unwrap();
        std::process::exit(i32::from(exit_code(status)));
    }
}
