use super::*;
use crate::owner::{
    github::https::Connector,
    test_support::{self, github},
};
use std::process::{Command, Stdio};

const RUN: &str = include_str!("../../../tests/fixtures/github-logs/run.json");
const JOBS: &str = include_str!("../../../tests/fixtures/github-logs/jobs.json");
const WORKFLOW: &str = include_str!("../../../tests/fixtures/github-logs/workflow.json");
const ZIP: &[u8] = include_bytes!("../../../tests/fixtures/github-logs/run.zip");
const READS: &str = include_str!("../../../tests/fixtures/github-logs/reads.json");

fn confined_command(executable: &std::ffi::OsStr, socket: &std::path::Path) -> Command {
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.args([
        "-p",
        r#"(version 1)
(allow default)
(deny network*)
(allow network-outbound (remote unix-socket (path-literal (param "SOCKET"))))"#,
        "-D",
    ]);
    command
        .arg(format!("SOCKET={}", socket.display()))
        .arg(executable);
    command
}

#[test]
fn sandbox_denies_tcp_connections() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let output = confined_command(
        std::ffi::OsStr::new("/usr/bin/nc"),
        std::path::Path::new("/tmp/qm-unused.sock"),
    )
    .args([
        "-v",
        "-z",
        "-G",
        "1",
        "127.0.0.1",
        &listener.local_addr().unwrap().port().to_string(),
    ])
    .output()
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn target(request: &str) -> &str {
    request.split_whitespace().nth(1).unwrap()
}

fn api_reply(request: &str) -> github::Reply {
    let target = target(request);
    let path = target.split('?').next().unwrap();
    if path.ends_with("/logs") {
        return github::redirect(&format!(
            "https://results-receiver.actions.githubusercontent.com{path}?sig=private-storage-canary"
        ));
    }
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    let body: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap()
    };
    let reads: Vec<Value> = serde_json::from_str(READS).unwrap();
    if let Some(reply) = reads
        .iter()
        .find(|reply| reply["target"] == target && reply["body"] == body)
    {
        return github::text(reply["response"].as_str().unwrap());
    }
    let prefix = "/repos/example/one";
    match path.strip_prefix(prefix).unwrap() {
        "" => github::repository(123),
        "/actions/runs/101" | "/actions/runs/101/attempts/2" => github::text(RUN),
        "/actions/workflows/201" => github::text(WORKFLOW),
        "/actions/runs/101/jobs" | "/actions/runs/101/attempts/2/jobs" => github::text(JOBS),
        _ => panic!("unexpected gh request: {target}"),
    }
}

fn bind_installed_gh(shared: &Shared, stream: &UnixStream) {
    let peer = PeerIdentity::capture(stream).unwrap();
    let mut policy: Value = serde_json::from_slice(&test_support::policy_bytes(
        (OffsetDateTime::now_utc() + Duration::from_secs(60))
            .unix_timestamp()
            .try_into()
            .unwrap(),
    ))
    .unwrap();
    policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
    policy["grants"][0]["codeHash"] = json!(peer.code_hash());
    policy["grants"][0]["repository"] = "example/one".into();
    policy["grants"][0]["effects"] =
        json!({"kind":"categories","categories":["repository","issues","actions","output"]});
    shared
        .0
        .lock()
        .unwrap()
        .authorizer
        .seed_native_fixture_grants(&serde_json::to_vec(&policy).unwrap());
}

#[test]
fn reads_and_log_downloads_use_the_broker() {
    let executable = std::env::var_os("QM_GH_EXECUTABLE")
        .expect("set QM_GH_EXECUTABLE to the installed gh path");
    for args in [
        vec!["issue", "list"],
        vec!["issue", "view", "1"],
        vec!["run", "view", "101", "--log"],
    ] {
        let logs = args.contains(&"--log");
        let (blob, blob_worker) = github::serve_routes(true, |_| github::binary(ZIP.to_vec()));
        let (receiver, receiver_worker) = github::serve_routes(true, |request| {
            github::redirect(&format!(
                "https://productionresultssa1.blob.core.windows.net{}",
                target(request)
            ))
        });
        let (api, api_worker) = github::serve_routes(false, api_reply);
        let (_root, paths, shared, _server, _client) = super::github_tests::setup(api);
        shared.0.lock().unwrap().github = Connector::FixtureWithStorage {
            api,
            receiver,
            blob,
        };
        let profile = tempfile::Builder::new()
            .prefix("qm-gh-")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = profile.path().canonicalize().unwrap().join("http.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        fs::write(
            profile.path().join("config.yml"),
            format!(
                "http_unix_socket: {}\nprompt: disabled\ngit_protocol: ssh\n",
                socket.display()
            ),
        )
        .unwrap();
        fs::write(profile.path().join("hosts.yml"), "github.com:\n  user: fixture\n  oauth_token: dummy-local-auth\n  git_protocol: https\n").unwrap();
        let mut command = confined_command(&executable, &socket);
        command
            .args(&args)
            .current_dir(profile.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", profile.path())
            .env("GH_CONFIG_DIR", profile.path())
            .env("XDG_CACHE_HOME", profile.path().join("cache"))
            .env("GH_REPO", "example/one")
            .env("GH_HOST", "github.com")
            .env("GH_PROMPT_DISABLED", "1")
            .env("GH_NO_UPDATE_NOTIFIER", "1")
            .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
            .env("GH_PAGER", "cat")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let configuration = fs::read(profile.path().join("config.yml")).unwrap();
        let authentication = fs::read(profile.path().join("hosts.yml")).unwrap();
        let mut child = command.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let output_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let error_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let mut bound = false;
        let mut handled = Vec::new();
        let until = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !bound {
                        bind_installed_gh(&shared, &stream);
                        bound = true;
                    }
                    stream.set_nonblocking(false).unwrap();
                    let result = handle_http(&mut stream, &shared, &paths);
                    if result.is_err() {
                        let _ = http::response(&mut stream, OperationResponse::Denied);
                    }
                    handled.push(result);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("{error}"),
            }
            if Instant::now() >= until {
                child.kill().unwrap();
                panic!("gh fixture timed out: {args:?}");
            }
        }
        let status = child.wait().unwrap();
        let stdout = String::from_utf8(output_reader.join().unwrap()).unwrap();
        let stderr = String::from_utf8(error_reader.join().unwrap()).unwrap();
        let api_requests = api_worker.join().unwrap();
        let storage_requests: Vec<_> = receiver_worker
            .join()
            .unwrap()
            .into_iter()
            .chain(blob_worker.join().unwrap())
            .collect();
        assert!(status.success(), "{args:?}: {stderr}; broker={handled:?}");
        assert!(handled.iter().all(Result::is_ok));
        assert!(!stdout.is_empty());
        if logs {
            assert!(stdout.contains("ZIP_BUILD_CANARY"));
            assert!(stdout.contains("ZIP_LINT_CANARY"));
        }
        for canary in [
            "quartermaster-dummy-canary",
            "private-storage-canary",
            "results-receiver",
            "blob.core.windows.net",
        ] {
            assert!(!stdout.contains(canary) && !stderr.contains(canary));
        }
        assert_eq!(!storage_requests.is_empty(), logs);
        assert!(
            storage_requests
                .iter()
                .all(|request| !request.contains("Authorization:")
                    && !request.contains("dummy-local-auth")
                    && !request.contains("quartermaster-dummy-canary"))
        );
        assert!(api_requests.iter().all(|request| request.contains("Authorization: Bearer quartermaster-dummy-canary")));
        assert_eq!(
            fs::read(profile.path().join("config.yml")).unwrap(),
            configuration
        );
        assert_eq!(
            fs::read(profile.path().join("hosts.yml")).unwrap(),
            authentication
        );
        if logs {
            drop(listener);
            let failed = command.output().unwrap();
            assert!(!failed.status.success());
            assert!(String::from_utf8_lossy(&failed.stderr).contains("http.sock"));
        }
    }
}
