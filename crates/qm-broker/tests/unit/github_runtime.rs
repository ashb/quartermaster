use super::*;
use crate::owner::{
    github::https::Connector,
    test_support::{self, github},
};
use std::net::SocketAddr;

fn setup(
    address: SocketAddr,
    budget: u32,
) -> (
    tempfile::TempDir,
    ServicePaths,
    Shared,
    UnixStream,
    UnixStream,
) {
    let root = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: root.path().join("nonexistent.app"),
        root: root.path().to_owned(),
    };
    let (server, client) = UnixStream::pair().unwrap();
    let peer = PeerIdentity::capture(&server).unwrap();
    let mut policy: Value = serde_json::from_slice(&test_support::policy_bytes(
        (time::OffsetDateTime::now_utc() + Duration::from_secs(60))
            .unix_timestamp()
            .try_into()
            .unwrap(),
        budget,
    ))
    .unwrap();
    policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
    policy["grants"][0]["codeHash"] = json!(peer.code_hash());
    policy["grants"][0]["repository"] = "example/one".into();
    let mut list = policy["grants"][0].clone();
    list["id"] = "22222222222222222222222222222222".into();
    list["action"] = "listIssues".into();
    policy["grants"].as_array_mut().unwrap().push(list);
    let path = paths.root.join("github.json");
    fs::write(&path, br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one","writes":true}]}"#).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut state = OwnerState::new().unwrap();
    state.refresh_policy(&paths).unwrap();
    state
        .authorizer
        .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
    state.github = Connector::fixture(address);
    test_support::vault::install(
        &mut state.provider,
        test_support::vault::snapshot("github-read"),
    );
    (
        root,
        paths,
        Arc::new((Mutex::new(state), Condvar::new())),
        server,
        client,
    )
}

fn request(
    server: &mut UnixStream,
    client: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
    target: &str,
) -> io::Result<String> {
    client.write_all(format!("GET {target} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer untrusted-caller-token\r\n\r\n").as_bytes()).unwrap();
    handle_http(server, shared, paths)?;
    server.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    Ok(response)
}

#[test]
fn github_runtime_returns_actual_issue_and_list_json_through_verified_ingress_with_no_ui() {
    for target in [
        "/repos/example/one/issues/987654321",
        "/repos/example/one/issues?state=all&per_page=30&page=2",
    ] {
        let reply = if target.contains('?') {
            github::list()
        } else {
            github::issue(987654321)
        };
        let (address, worker) = github::serve(vec![github::repository(123), reply]);
        let (_root, paths, shared, mut server, mut client) = setup(address, 2);
        let response = request(&mut server, &mut client, &shared, &paths, target).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Actual fixture issue"));
        assert!(!response.contains("quartermaster_local_simulation"));
        assert!(!response.contains("quartermaster-dummy-canary"));
        assert!(shared.0.lock().unwrap().ui.is_none());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /repos/example/one HTTP/1.1"));
        let destination = target.replace("/repos/example/one/", "/repositories/123/");
        assert!(requests[1].starts_with(&format!("GET {destination} HTTP/1.1")));
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("untrusted-caller-token"))
        );
    }
}

#[test]
fn github_runtime_rejects_recreated_repository_and_returns_fixed_credential_errors_before_issue_dispatch()
 {
    for unauthorized in [false, true] {
        let reply = if unauthorized {
            github::unauthorized()
        } else {
            github::repository(456)
        };
        let (address, worker) = github::serve(vec![reply]);
        let (_root, paths, shared, mut server, mut client) = setup(address, 2);
        let result = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/987654321",
        );
        if unauthorized {
            let response = result.unwrap();
            assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
            assert!(response.contains("GitHub rejected the configured credential"));
            assert!(!response.contains("private upstream"));
        } else {
            assert!(result.is_err());
        }
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].contains("/issues/"));
    }
}

#[test]
fn github_runtime_read_redirect_reauthorizes_and_debits_the_next_target_without_a_new_prompt() {
    for budget in [1, 2] {
        let replies = if budget == 1 {
            vec![
                github::repository(123),
                github::redirect("https://api.github.com/repositories/123/issues/43"),
            ]
        } else {
            vec![
                github::repository(123),
                github::redirect("https://api.github.com/repositories/123/issues/43"),
                github::repository(123),
                github::issue(43),
            ]
        };
        let (address, worker) = github::serve(replies);
        let (_root, paths, shared, mut server, mut client) = setup(address, budget);
        let result = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/42",
        );
        if budget == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().contains("Actual fixture issue 43"));
        }
        assert!(shared.0.lock().unwrap().ui.is_none());
        assert_eq!(
            worker.join().unwrap().len(),
            if budget == 1 { 2 } else { 4 }
        );
    }
}

#[test]
fn github_runtime_redirect_loops_and_other_repositories_stop_before_another_credential_handoff() {
    for target in [
        "https://api.github.com/repos/example/one/issues/42",
        "https://api.github.com/repos/example/two/issues/42",
        "https://elsewhere.invalid/repos/example/one/issues/42",
    ] {
        let (address, worker) =
            github::serve(vec![github::repository(123), github::redirect(target)]);
        let (_root, paths, shared, mut server, mut client) = setup(address, 4);
        let result = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/42",
        );
        if let Ok(response) = result {
            assert!(
                response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
                "accepted {target}"
            );
        }
        assert_eq!(worker.join().unwrap().len(), 2);
    }
}

#[test]
fn github_runtime_follows_at_most_three_separately_admitted_read_redirects() {
    for redirects in [3, 4] {
        let mut replies = Vec::new();
        for step in 0..redirects {
            replies.push(github::repository(123));
            replies.push(github::redirect(&format!(
                "https://api.github.com/repositories/123/issues/{}",
                43 + step
            )));
        }
        if redirects == 3 {
            replies.push(github::repository(123));
            replies.push(github::issue(45));
        }
        let (address, worker) = github::serve(replies);
        let (_root, paths, shared, mut server, mut client) = setup(address, 10);
        let result = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/42",
        );
        if redirects == 3 {
            assert!(result.unwrap().contains("Actual fixture issue 45"));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(worker.join().unwrap().len(), 8);
    }
}

#[test]
fn github_runtime_preserves_cursor_pagination_and_debits_each_page_without_a_frontend() {
    let next = "https://api.github.com/repositories/123/issues?state=all&per_page=1&page=2&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D";
    let (address, worker) = github::serve(vec![
        github::repository(123),
        github::list_page(42, Some(next)),
        github::repository(123),
        github::list_page(43, None),
    ]);
    let (_root, paths, shared, mut server, mut client) = setup(address, 2);
    let first = request(
        &mut server,
        &mut client,
        &shared,
        &paths,
        "/repos/example/one/issues?state=all&per_page=1",
    )
    .unwrap();
    assert!(first.contains("Actual fixture issue 42"));
    let next = first
        .lines()
        .find_map(|line| line.strip_prefix("Link: <"))
        .unwrap()
        .split_once('>')
        .unwrap()
        .0;
    let target = next.strip_prefix("https://api.github.com").unwrap();
    let (mut server, mut client) = UnixStream::pair().unwrap();
    let second = request(&mut server, &mut client, &shared, &paths, target).unwrap();
    assert!(second.contains("Actual fixture issue 43"));
    assert!(shared.0.lock().unwrap().ui.is_none());
    let (mut server, mut client) = UnixStream::pair().unwrap();
    assert!(request(&mut server, &mut client, &shared, &paths, target).is_err());
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].starts_with("GET /repositories/123/issues?state=all&per_page=1&page=2&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D HTTP/1.1"));
}

#[test]
fn github_runtime_repo_replacement_after_metadata_cannot_redirect_the_credential_or_issue_read() {
    let (address, worker) = github::serve(vec![
        github::repository(123),
        github::replaced_repository_issue(42),
    ]);
    let (_root, paths, shared, mut server, mut client) = setup(address, 2);
    let response = request(
        &mut server,
        &mut client,
        &shared,
        &paths,
        "/repos/example/one/issues/42",
    )
    .unwrap();
    assert!(response.contains("Original repository issue"));
    assert!(!response.contains("Recreated repository issue"));
    let requests = worker.join().unwrap();
    assert!(requests[1].starts_with("GET /repositories/123/issues/42 HTTP/1.1"));
}

#[test]
fn github_runtime_a_nonreading_client_cannot_keep_a_response_worker_past_its_deadline() {
    let (address, upstream) = github::serve(vec![github::repository(123), github::large_issue(42)]);
    let (_root, paths, shared, mut server, client) = setup(address, 2);
    let (id, principal, connector) = {
        let mut state = shared.0.lock().unwrap();
        state.refresh_policy(&paths).unwrap();
        let (principal, _) =
            VerifiedPrincipal::capture(&server, state.authorizer.session()).unwrap();
        let config = state.authorizer.github_configuration().unwrap();
        let request = http_request::read_configured(
            &mut std::io::Cursor::new(
                "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
            ),
            Some(config),
        )
        .unwrap();
        let outcome = state.authorize(&principal, request, &paths).unwrap();
        let id = state.operations.register(outcome, Instant::now()).unwrap();
        let selection = CredentialSelection::at_generation(
            state.provider.snapshot().unwrap(),
            state.provider.generation(),
        );
        state
            .operations
            .select_credential(id, &principal, selection)
            .unwrap();
        (id, principal, state.github.clone())
    };
    let deadline = Deadline::after(Duration::from_secs(3)).unwrap();
    let metadata = shared
        .0
        .lock()
        .unwrap()
        .prepare_metadata(id, &principal, &paths)
        .unwrap();
    let prepared = connector
        .connect(deadline)
        .unwrap()
        .stage_metadata(metadata)
        .unwrap();
    let receipt = shared
        .0
        .lock()
        .unwrap()
        .handoff_metadata(prepared, &principal, &paths)
        .unwrap();
    let binding = receipt.response().unwrap();
    let request = shared
        .0
        .lock()
        .unwrap()
        .prepare_github(id, &principal, &paths, binding)
        .unwrap();
    let prepared =
        PreparedOperation::github(request, connector.connect(deadline).unwrap()).unwrap();
    let receipt = shared
        .0
        .lock()
        .unwrap()
        .handoff(prepared, &principal, &paths)
        .unwrap();
    let public = receipt.response();
    assert!(matches!(public, OperationResponse::Github(_)));
    assert_eq!(upstream.join().unwrap().len(), 2);
    let (send, receive) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = response_until(
            &mut server,
            public,
            Deadline::after(Duration::from_millis(20)).unwrap(),
        );
        send.send(result.is_err()).unwrap();
    });
    let timed_out = receive.recv_timeout(Duration::from_secs(1));
    drop(client);
    worker.join().unwrap();
    assert!(timed_out.unwrap());
}
