mod approval;
mod control;
mod dispatch;
mod error;

mod http;
mod policy_source;
mod settings;
mod state;
mod vault_workflow;

use crate::owner::transport::OperationResponse;
use error::{Error, Fault, Result};
use ring::rand::{SecureRandom, SystemRandom};
use state::OwnerState;
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
        },
    },
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, mpsc},
};

const SERVICE: &str = "dev.quartermaster.debug.backend";
const PROFILE: &str = "development";

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new().fill(&mut bytes)?;
    Ok(bytes)
}

#[derive(Clone)]
struct ServicePaths {
    app: PathBuf,
    root: PathBuf,
    policy: Arc<policy_source::PolicySource>,
    settings: Option<Arc<crate::owner::settings::Store>>,
}

type PolicyInput =
    std::result::Result<policy_source::Observation, crate::owner::policy::AuthorizationError>;

impl ServicePaths {
    fn load_policy(&self) -> PolicyInput {
        self.policy.snapshot()
    }

    fn vault_root(&self) -> Result<PathBuf, crate::owner::vault::Error> {
        Ok(self
            .policy
            .provider()
            .map_err(|_| crate::owner::vault::Error::Storage)?
            .map_or_else(|| self.root.clone(), |pin| pin.root(&self.root)))
    }

    fn vault_source(&self) -> Result<crate::owner::vault::Source, crate::owner::vault::Error> {
        let pin = self
            .policy
            .provider()
            .map_err(|_| crate::owner::vault::Error::Storage)?;
        let root = pin
            .as_ref()
            .map_or_else(|| self.root.clone(), |pin| pin.root(&self.root));
        let source = crate::owner::vault::Source::capture(&root)?;
        if let Some(pin) = pin {
            let identity = source.identity()?;
            if identity.binding != pin.binding
                || identity.scope != pin.scope
                || identity.device_key != pin.device_key
            {
                return Err(qm_providers::ProviderError::AccountMismatch.into());
            }
        }
        Ok(source)
    }
}

#[cfg(test)]
mod settings_boundary_tests {
    use super::*;

    #[test]
    fn a_user_writable_configuration_cannot_activate_or_restore_policy() {
        let root = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: "/unused.app".into(),
            root: root.path().to_owned(),
            policy: Arc::default(),
            settings: None,
        };
        let file = root.path().join("github.json");
        for unverified in [false, true, false] {
            fs::write(&file, format!(r#"{{"version":1,"mode":"github","repositories":[{{"id":123,"owner":"example","name":"one"}}],"approveUnverifiedRequests":{unverified}}}"#)).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(paths.load_policy().unwrap().current().unwrap().1.is_err());
        }
        fs::remove_file(file).unwrap();
        assert!(paths.load_policy().unwrap().current().unwrap().1.is_err());
    }
}

type Shared = Arc<(Mutex<OwnerState>, Condvar)>;

pub(super) fn serve(options: crate::ServiceOptions) -> Result<()> {
    if objc2::MainThreadMarker::new().is_none() {
        return Err(Error::State(Fault::MainThreadRequired));
    }
    let paths = ServicePaths {
        app: options.bundle_root,
        root: options.storage_root,
        policy: Arc::default(),
        settings: crate::owner::settings::Store::native().ok().map(Arc::new),
    };
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.root.join("backend.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::State(Fault::AlreadyRunning));
    }
    let socket = paths.root.join("github.sock");
    if let Ok(metadata) = fs::symlink_metadata(&socket) {
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::State(Fault::InvalidSocket));
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let mut state = OwnerState::for_service()?;
    match paths.settings.as_ref().map(|store| store.load()) {
        Some(Ok(Some(manager))) => {
            state.approval_public_key = Some(manager.record().public_key().to_vec());
            paths.policy.install(&manager)?;
            state.administration.manager = Some(manager);
        }
        Some(Ok(None)) => {}
        Some(Err(_)) | None => state.administration.unavailable = true,
    }
    let shared = Arc::new((Mutex::new(state), Condvar::new()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .thread_name("quartermaster-runtime")
        .enable_all()
        .build()?;
    let event_loop = crate::platform::macos::event_loop::EventLoop::new()?;
    let native = control::listen(Arc::clone(&shared), paths.clone(), runtime.handle().clone())?;
    listener.set_nonblocking(true)?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::UnixListener::from_std(listener)?
    };
    let ingress_shared = Arc::clone(&shared);
    let expiration_shared = Arc::clone(&shared);
    let expiration = runtime.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            if let (Ok(now), Ok(mut state)) = (
                qm_macos::presence_clock::monotonic_raw(),
                expiration_shared.0.lock(),
            ) {
                state.administration.expire(now);
            }
        }
    });
    let stop = event_loop.stop_handle();
    let (finished, completion) = mpsc::sync_channel(1);
    let ingress = runtime.spawn(async move {
        struct StopOnDrop(crate::platform::macos::event_loop::Stop);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.stop();
            }
        }
        let _stop = StopOnDrop(stop);
        let _ = finished.send(serve_ingress(listener, ingress_shared, paths).await);
    });
    println!("Quartermaster listening at {}.", socket.display());
    let result = event_loop.run().map_err(Error::from);
    shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?
        .end_host_session()?;
    shared.1.notify_all();
    drop(native);
    ingress.abort();
    expiration.abort();
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    fs::remove_file(socket)?;
    result.and_then(|()| {
        completion
            .try_recv()
            .unwrap_or_else(|_| Err(Error::State(Fault::IngressUnavailable)))
    })
}

async fn serve_ingress(
    listener: tokio::net::UnixListener,
    shared: Shared,
    paths: ServicePaths,
) -> Result<()> {
    let (send, receive) = tokio::sync::mpsc::channel::<tokio::net::UnixStream>(8);
    let receive = Arc::new(tokio::sync::Mutex::new(receive));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let receive = Arc::clone(&receive);
        let shared = Arc::clone(&shared);
        let paths = paths.clone();
        workers.spawn(async move {
            loop {
                let Some(stream) = receive.lock().await.recv().await else {
                    return Ok::<(), Error>(());
                };
                let mut stream = stream.into_std()?;
                stream.set_nonblocking(false)?;
                let shared = Arc::clone(&shared);
                let paths = paths.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = http::handle_http(&mut stream, &shared, &paths) {
                        eprintln!("Request denied: {error}");
                        let _ = http::response(&mut stream, OperationResponse::Denied);
                    }
                })
                .await?;
            }
        });
    }
    loop {
        tokio::select! {
            result = workers.join_next() => {
                return match result {
                    Some(Ok(Err(error))) => Err(error),
                    _ => Err(Error::State(Fault::IngressUnavailable)),
                };
            }
            incoming = listener.accept() => {
                let (stream, _) = incoming?;
                match send.try_send(stream) {
                    Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {},
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Err(Error::State(Fault::IngressUnavailable)),
                }
            }
        }
    }
}

#[cfg(test)]
use {
    self::{
        approval::{
            ApprovalCompletion, ApprovalDelivery, FrozenProvider, ProviderPresentation,
            ReviewContext, begin_native_presence, complete_native_presence,
        },
        control::handle,
        http::{handle_http, response_until},
    },
    crate::owner::{
        deadline::Deadline,
        dispatch::{CredentialSelection, PreparedOperation},
        identity::VerifiedPrincipal,
        operation::{CancellationResult, OperationId},
        policy::AuthorizationOutcome,
        protocol::{Client, Reply, decode_client, encode_reply},
        request as http_request,
    },
    base64::{Engine, engine::general_purpose::STANDARD as BASE64},
    qm_macos::{
        peer_identity::PeerIdentity,
        presence_clock::{MonotonicTimestamp, monotonic_raw as presence_now},
    },
    serde_json::{Value, json},
    std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    },
    time::OffsetDateTime,
};

#[cfg(test)]
mod authentication_tests {
    use super::*;
    use ring::signature::EcdsaKeyPair;

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: ServicePaths,
        key: EcdsaKeyPair,
        state: OwnerState,
        receive: mpsc::Receiver<ApprovalCompletion>,
        review: Value,
        id: OperationId,
    }

    fn staged(cold: bool) -> Fixture {
        let (directory, paths, key, mut state, receive) = tests::fixture_with_cache(cold);
        let id = state.pending.as_ref().unwrap().id;
        state.pending.as_mut().unwrap().delivered = false;
        let Reply::Review { approval } =
            handle(Client::Next {}, &mut state, &paths.load_policy()).unwrap()
        else {
            panic!("expected approval review");
        };
        let review = serde_json::to_value(approval).unwrap();
        Fixture {
            _directory: directory,
            paths,
            key,
            state,
            receive,
            review,
            id,
        }
    }

    fn authenticate(fixture: &mut Fixture) -> (MonotonicTimestamp, Value) {
        thread::sleep(Duration::from_millis(3));
        let authenticated = presence_now().unwrap();
        let work = begin_native_presence(
            fixture.id,
            authenticated,
            &mut fixture.state,
            &fixture.paths.load_policy(),
            crate::owner::vault::Source::capture(&fixture.paths.root)
                .and_then(|source| source.identity()),
        )
        .unwrap();
        if let Some((source, operation)) = work {
            assert!(fixture.state.provider.snapshot().is_none());
            let snapshot = super::super::vault::fixture::open(source);
            super::super::vault::finish_unlock(
                &fixture.paths.root,
                &mut fixture.state.provider,
                operation,
                snapshot,
            )
            .unwrap();
        }
        let Reply::Challenge { authorization } = complete_native_presence(
            fixture.id,
            &mut fixture.state,
            &fixture.paths.load_policy(),
            crate::owner::vault::Source::capture(&fixture.paths.root)
                .and_then(|source| source.identity()),
        )
        .unwrap() else {
            panic!("expected approval challenge");
        };
        (authenticated, serde_json::to_value(authorization).unwrap())
    }

    #[test]
    fn cold_cache_open_binds_actual_digest_and_exact_original_event_before_a_single_use_write() {
        let mut fixture = staged(true);
        let (authenticated, challenge) = authenticate(&mut fixture);
        assert_eq!(challenge["review"], fixture.review);
        assert_eq!(challenge["authenticated"], json!(authenticated));
        assert_eq!(
            challenge["expires"],
            json!(authenticated.checked_add(Duration::from_secs(30)).unwrap())
        );
        assert_eq!(
            challenge["credentialDigest"],
            BASE64.encode(
                fixture
                    .state
                    .provider
                    .snapshot()
                    .unwrap()
                    .credential_digest()
            )
        );
        let bytes = BASE64.decode(challenge["bytes"].as_str().unwrap()).unwrap();
        let created = fixture.state.pending.as_ref().unwrap().created();
        assert_eq!(
            &bytes[bytes.len() - 16..],
            &authenticated
                .checked_duration_since(created)
                .unwrap()
                .as_nanos()
                .to_be_bytes()
        );
        let principal = Arc::clone(&fixture.state.pending.as_ref().unwrap().principal);
        assert!(
            fixture
                .state
                .prepare(fixture.id, &principal, &fixture.paths.load_policy())
                .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream),
            (0, 0)
        );
        let signature = fixture.key.sign(&SystemRandom::new(), &bytes).unwrap();
        handle(
            Client::Proof {
                id: fixture.id.to_string(),
                signature: BASE64.encode(signature.as_ref()),
            },
            &mut fixture.state,
            &fixture.paths.load_policy(),
        )
        .unwrap();
        let ready = fixture.receive.try_recv().unwrap();
        let frame = fixture
            .state
            .prepare(ready.id, &ready.principal, &fixture.paths.load_policy())
            .unwrap();
        let prepared = PreparedOperation::new(frame, fixture.state.upstream.connect().unwrap());
        let response = fixture
            .state
            .handoff(prepared, &ready.principal, &fixture.paths.load_policy())
            .unwrap()
            .response();
        assert_eq!(response, OperationResponse::IssueClosed);
        assert!(
            fixture
                .state
                .prepare(fixture.id, &principal, &fixture.paths.load_policy())
                .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream).0,
            1
        );
    }

    #[test]
    fn warm_cache_still_requires_a_new_request_bound_proof() {
        let mut fixture = staged(false);
        let (_, challenge) = authenticate(&mut fixture);
        assert_eq!(challenge["review"], fixture.review);
        let principal = Arc::clone(&fixture.state.pending.as_ref().unwrap().principal);

        assert!(
            fixture
                .state
                .prepare(fixture.id, &principal, &fixture.paths.load_policy())
                .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream),
            (0, 0)
        );
    }

    #[test]
    fn warm_cache_cannot_supply_a_newly_frozen_enrollment_or_cache_revision() {
        let mut fixture = staged(false);
        let snapshot = super::super::test_support::vault::snapshot("github-write");
        let replacement = super::super::vault::fixture::put(&fixture.paths.root, &snapshot);
        let pending = fixture.state.pending.as_mut().unwrap();
        let frozen = &mut pending.provider;
        frozen.identity = replacement.identity().unwrap();
        frozen.source = Some(replacement);
        thread::sleep(Duration::from_millis(3));

        assert!(
            begin_native_presence(
                fixture.id,
                presence_now().unwrap(),
                &mut fixture.state,
                &fixture.paths.load_policy(),
                crate::owner::vault::Source::capture(&fixture.paths.root)
                    .and_then(|source| source.identity())
            )
            .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream),
            (0, 0)
        );
    }

    #[test]
    fn explicit_lock_or_cache_replacement_rejects_late_authenticated_unwrap() {
        for replace in [false, true] {
            let mut fixture = staged(true);
            thread::sleep(Duration::from_millis(3));
            let (source, operation) = begin_native_presence(
                fixture.id,
                presence_now().unwrap(),
                &mut fixture.state,
                &fixture.paths.load_policy(),
                crate::owner::vault::Source::capture(&fixture.paths.root)
                    .and_then(|source| source.identity()),
            )
            .unwrap()
            .unwrap();
            let snapshot = super::super::vault::fixture::open(source);
            if replace {
                let replacement = super::super::test_support::vault::snapshot_with(
                    "github-write",
                    "33333333-3333-4333-8333-333333333333",
                    [4; 16],
                );
                super::super::vault::fixture::put(&fixture.paths.root, &replacement);
            } else {
                fixture.state.provider.lock().unwrap();
            }

            assert!(
                super::super::vault::finish_unlock(
                    &fixture.paths.root,
                    &mut fixture.state.provider,
                    operation,
                    snapshot
                )
                .is_err()
            );
            assert!(
                complete_native_presence(
                    fixture.id,
                    &mut fixture.state,
                    &fixture.paths.load_policy(),
                    crate::owner::vault::Source::capture(&fixture.paths.root)
                        .and_then(|source| source.identity())
                )
                .is_err()
            );
            assert!(fixture.state.provider.snapshot().is_none());
            assert_eq!(
                super::super::transport::fixture::observe(&fixture.state.upstream),
                (0, 0)
            );
        }
    }

    #[test]
    fn canceled_write_or_ui_exit_does_not_resurrect_proof_when_an_authorized_unlock_finishes() {
        for disconnect in [false, true] {
            let mut fixture = staged(true);
            thread::sleep(Duration::from_millis(3));
            let (source, operation) = begin_native_presence(
                fixture.id,
                presence_now().unwrap(),
                &mut fixture.state,
                &fixture.paths.load_policy(),
                crate::owner::vault::Source::capture(&fixture.paths.root)
                    .and_then(|source| source.identity()),
            )
            .unwrap()
            .unwrap();
            if disconnect {
                fixture.state.disconnect_ui();
            } else {
                let reply = handle(
                    Client::Cancel {
                        id: fixture.id.to_string(),
                    },
                    &mut fixture.state,
                    &fixture.paths.load_policy(),
                )
                .unwrap();
                assert!(matches!(reply, Reply::Canceled));
            }
            let snapshot = super::super::vault::fixture::open(source);
            super::super::vault::finish_unlock(
                &fixture.paths.root,
                &mut fixture.state.provider,
                operation,
                snapshot,
            )
            .unwrap();

            assert!(fixture.state.provider.snapshot().is_some());
            assert!(
                complete_native_presence(
                    fixture.id,
                    &mut fixture.state,
                    &fixture.paths.load_policy(),
                    crate::owner::vault::Source::capture(&fixture.paths.root)
                        .and_then(|source| source.identity())
                )
                .is_err()
            );
            assert!(fixture.receive.try_recv().is_err());
            assert_eq!(
                super::super::transport::fixture::observe(&fixture.state.upstream),
                (0, 0)
            );
        }
    }
}
#[cfg(test)]
mod github_tests {
    use super::*;
    use crate::owner::{
        github::https::Connector,
        test_support::{self, github},
    };
    use std::net::SocketAddr;

    fn setup(
        address: SocketAddr,
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
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let (server, client) = UnixStream::pair().unwrap();
        let peer = PeerIdentity::capture(&server).unwrap();
        let mut policy: Value = serde_json::from_slice(&test_support::policy_bytes(
            (time::OffsetDateTime::now_utc() + Duration::from_secs(60))
                .unix_timestamp()
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
        policy["grants"][0]["codeHash"] = json!(peer.code_hash());
        policy["grants"][0]["repository"] = "example/one".into();
        let mut list = policy["grants"][0].clone();
        list["id"] = "22222222222222222222222222222222".into();
        list["effects"]["effects"] = serde_json::json!(["listIssues"]);
        policy["grants"].as_array_mut().unwrap().push(list);
        paths.policy.set_fixture(crate::owner::policy::Policy::default().with_github(
            crate::owner::github::configuration::GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one","writes":true}]}"#).unwrap()
        ));
        let mut state = OwnerState::new().unwrap();
        state.refresh_policy(&paths.load_policy()).unwrap();
        state
            .authorizer
            .seed_native_fixture_grants(&serde_json::to_vec(&policy).unwrap());
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
    ) -> Result<String> {
        client.write_all(format!("GET {target} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nAuthorization: Bearer untrusted-caller-token\r\n\r\n").as_bytes()).unwrap();
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
            let (_root, paths, shared, mut server, mut client) = setup(address);
            let response = request(&mut server, &mut client, &shared, &paths, target).unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(response.contains("Actual fixture issue"));
            assert!(!response.contains("quartermaster_local_simulation"));
            assert!(!response.contains("quartermaster-dummy-canary"));
            assert!(shared.0.lock().unwrap().ui.is_none());
            let requests = worker.join().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests[0].starts_with("GET /repos/example/one HTTP/1.1"));
            assert!(requests[1].starts_with(&format!("GET {target} HTTP/1.1")));
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
            let (_root, paths, shared, mut server, mut client) = setup(address);
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
    fn github_runtime_read_redirect_reauthorizes_the_next_target_without_a_new_prompt() {
        let replies = vec![
            github::repository(123),
            github::redirect("https://api.github.com/repos/example/one/issues/43"),
            github::repository(123),
            github::issue(43),
        ];
        let (address, worker) = github::serve(replies);
        let (_root, paths, shared, mut server, mut client) = setup(address);
        let result = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/42",
        );
        assert!(result.unwrap().contains("Actual fixture issue 43"));
        assert!(shared.0.lock().unwrap().ui.is_none());
        assert_eq!(worker.join().unwrap().len(), 4);
    }

    #[test]
    fn github_runtime_redirect_loops_and_other_repositories_stop_before_another_credential_handoff()
    {
        for target in [
            "https://api.github.com/repos/example/one/issues/42",
            "https://api.github.com/repos/example/two/issues/42",
            "https://elsewhere.invalid/repos/example/one/issues/42",
        ] {
            let (address, worker) =
                github::serve(vec![github::repository(123), github::redirect(target)]);
            let (_root, paths, shared, mut server, mut client) = setup(address);
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
                    "https://api.github.com/repos/example/one/issues/{}",
                    43 + step
                )));
            }
            if redirects == 3 {
                replies.push(github::repository(123));
                replies.push(github::issue(45));
            }
            let (address, worker) = github::serve(replies);
            let (_root, paths, shared, mut server, mut client) = setup(address);
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
    fn github_runtime_preserves_cursor_pagination_without_a_frontend() {
        let next = "https://api.github.com/repos/example/one/issues?state=all&per_page=1&page=2&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D";
        let (address, worker) = github::serve(vec![
            github::repository(123),
            github::list_page(42, Some(next)),
            github::repository(123),
            github::list_page(43, None),
        ]);
        let (_root, paths, shared, mut server, mut client) = setup(address);
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
        assert!(requests[3].starts_with("GET /repos/example/one/issues?state=all&per_page=1&page=2&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D HTTP/1.1"));
    }

    #[test]
    fn github_runtime_named_repository_reads_preserve_the_path_after_metadata_changes() {
        let (address, worker) = github::serve(vec![
            github::repository(123),
            github::replaced_repository_issue(42),
        ]);
        let (_root, paths, shared, mut server, mut client) = setup(address);
        let response = request(
            &mut server,
            &mut client,
            &shared,
            &paths,
            "/repos/example/one/issues/42",
        )
        .unwrap();
        assert!(response.contains("Recreated repository issue"));
        assert!(!response.contains("Original repository issue"));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /repos/example/one HTTP/1.1\r\n"));
        assert!(requests[1].starts_with("GET /repos/example/one/issues/42 HTTP/1.1\r\n"));
    }

    #[test]
    fn github_runtime_a_nonreading_client_cannot_keep_a_response_worker_past_its_deadline() {
        let (address, upstream) =
            github::serve(vec![github::repository(123), github::large_issue(42)]);
        let (_root, paths, shared, mut server, client) = setup(address);
        let (id, principal, connector) = {
            let mut state = shared.0.lock().unwrap();
            state.refresh_policy(&paths.load_policy()).unwrap();
            let (principal, _) =
                VerifiedPrincipal::capture(&server, state.authorizer.session()).unwrap();
            let config = state.authorizer.github_configuration().unwrap();
            let request = http_request::read_configured(
                &mut std::io::Cursor::new(
                    "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n",
                ),
                Some(config),
            )
            .unwrap();
            let outcome = state
                .authorize(
                    &principal,
                    request,
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding()),
                )
                .unwrap();
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
            .prepare_metadata(id, &principal, &paths.load_policy())
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
            .handoff_metadata(prepared, &principal, &paths.load_policy())
            .unwrap();
        let binding = receipt.response().unwrap();
        let request = shared
            .0
            .lock()
            .unwrap()
            .prepare_github(id, &principal, &paths.load_policy(), binding)
            .unwrap();
        let prepared =
            PreparedOperation::github(request, connector.connect(deadline).unwrap()).unwrap();
        let receipt = shared
            .0
            .lock()
            .unwrap()
            .handoff(prepared, &principal, &paths.load_policy())
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
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::operation::Admission;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn a_changed_selected_credential_requires_fresh_grant_approval() {
        let (_root, paths, _key, mut state, _receive) = fixture();
        state.cancel_pending();
        let principal = crate::owner::test_support::principal(state.authorizer.session());
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        crate::owner::test_support::approval::read_grant(
            &mut state.operations,
            &mut state.authorizer,
            &principal,
            &snapshot,
        );
        let changed = crate::owner::test_support::vault::snapshot_with(
            "github-write",
            "33333333-3333-4333-8333-333333333333",
            [4; 16],
        );
        crate::owner::test_support::vault::install(&mut state.provider, changed);
        assert!(matches!(
            state.authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding())
            ),
            Ok(AuthorizationOutcome::RequireApproval(_))
        ));
    }

    #[test]
    fn expired_or_revoked_reads_require_fresh_approval_and_can_recover() {
        for expire in [false, true] {
            let (_root, paths, _key, mut state, _receive) = fixture();
            state.cancel_pending();
            let principal = crate::owner::test_support::principal(state.authorizer.session());
            let snapshot = crate::owner::test_support::vault::snapshot("github-write");
            crate::owner::test_support::approval::read_grant(
                &mut state.operations,
                &mut state.authorizer,
                &principal,
                &snapshot,
            );
            if expire {
                state
                    .authorizer
                    .install(
                        Ok(crate::owner::policy::fixture::FixturePolicy::default()),
                        OffsetDateTime::now_utc() + Duration::from_secs(7200),
                        Instant::now(),
                    )
                    .unwrap();
            } else {
                state.authorizer.revoke_read_grants().unwrap();
            }
            assert!(matches!(
                state.authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding())
                ),
                Ok(AuthorizationOutcome::RequireApproval(_))
            ));
            assert!(
                state
                    .authorizer
                    .authorize(
                        &principal,
                        crate::owner::test_support::read_request(),
                        Instant::now()
                    )
                    .is_err()
            );
            crate::owner::test_support::approval::read_grant(
                &mut state.operations,
                &mut state.authorizer,
                &principal,
                &snapshot,
            );
            assert!(matches!(
                state.authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding())
                ),
                Ok(AuthorizationOutcome::Allowed(_))
            ));
        }
    }

    #[test]
    fn an_ungranted_read_requires_grant_approval_without_authorizing_a_write() {
        let (_root, paths, _key, mut state, _receive) = fixture();
        state.cancel_pending();
        let principal = crate::owner::test_support::principal(state.authorizer.session());
        let outcome = state
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding()),
            )
            .unwrap();
        let AuthorizationOutcome::RequireApproval(requirement) = outcome else {
            panic!("ungranted read was allowed");
        };
        let claims = serde_json::to_value(requirement.grant_claims().unwrap()).unwrap();
        assert_eq!(claims["purpose"], "quartermaster.read-grant.v2");
        assert_eq!(claims["grant"]["codeHash"], "11".repeat(20));
        assert_eq!(claims["grant"]["role"], "github-write");
        assert!(
            state
                .authorizer
                .authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    Instant::now()
                )
                .is_err()
        );
    }

    #[test]
    fn enrollment_accepts_an_explicit_item_selector_without_changing_authority_fields() {
        for selected in [None, Some("22222222-2222-4222-8222-222222222222")] {
            let mut message = json!({"kind":"vaultLogin", "server":"https://vault.example.invalid", "email":"dummy@example.invalid", "password":"dummy"});
            if let Some(selected) = selected {
                message["itemId"] = json!(selected);
            }
            assert!(matches!(
                decode_client(&serde_json::to_vec(&message).unwrap()).unwrap(),
                Client::VaultLogin { item_id, .. } if item_id.as_deref() == selected
            ));
            message["role"] = json!("arbitrary-role");
            assert!(decode_client(&serde_json::to_vec(&message).unwrap()).is_err());
        }
    }

    pub(super) fn fixture() -> (
        tempfile::TempDir,
        ServicePaths,
        EcdsaKeyPair,
        OwnerState,
        mpsc::Receiver<ApprovalCompletion>,
    ) {
        fixture_with_cache(false)
    }

    pub(super) fn fixture_with_cache(
        cold: bool,
    ) -> (
        tempfile::TempDir,
        ServicePaths,
        EcdsaKeyPair,
        OwnerState,
        mpsc::Receiver<ApprovalCompletion>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: "/unused.app".into(),
            root: directory.path().canonicalize().unwrap(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .unwrap();
        let mut state = OwnerState::new().unwrap();
        handle(
            Client::Enroll {
                public_key: BASE64.encode(key.public_key()),
            },
            &mut state,
            &paths.load_policy(),
        )
        .unwrap();
        let created = presence_now().unwrap();
        let principal = Arc::new(VerifiedPrincipal::fixture(
            501,
            "11".repeat(20),
            state.authorizer.session(),
        ));
        let request = http_request::read(&mut std::io::Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
        let outcome = state
            .authorizer
            .authorize(&principal, request, Instant::now())
            .unwrap();
        let id = state.operations.register(outcome, Instant::now()).unwrap();
        let snapshot = super::super::test_support::vault::snapshot("github-write");
        let source = super::super::vault::fixture::put(&paths.root, &snapshot);
        let identity = source.identity().unwrap();
        if !cold {
            let unlock = state.provider.begin_unlock(identity.clone()).unwrap();
            state
                .provider
                .finish_unlock(unlock, &identity, snapshot)
                .unwrap();
        }
        let generation = state.provider.generation();
        let context = ReviewContext {
            read_roots: Vec::new(),
            provider: ProviderPresentation::new(&identity, generation),
            operation_id: id.to_string(),
            created,
            process_chain: vec!["dummy test process · PID 1".into()],
            peer: qm_macos::peer_identity::PeerPresentation {
                pid: 1,
                executable: "/dummy/test".into(),
                signing_identifier: "dummy.test".into(),
                team_identifier: None,
                cd_hash: principal.code_hash().into(),
                ad_hoc: true,
                ancestry_complete: true,
                ancestry_note: None,
                command_line: None,
            },
        };
        let request = super::super::review::ReviewDocument::new(
            state.operations.request(id, &principal).unwrap().clone(),
            None,
            context,
        )
        .unwrap();
        state
            .operations
            .bind_review(id, &principal, &request)
            .unwrap();
        state
            .operations
            .begin_approval(id, &principal, &state.ui.as_ref().unwrap().session)
            .unwrap();
        let (completion, receive) = mpsc::sync_channel(1);
        state.pending = Some(ApprovalDelivery {
            id,
            principal,
            request,
            provider: FrozenProvider {
                source: Some(source),
                identity,
                generation,
            },
            context_lease: None,
            delivered: false,
            completion,
        });
        handle(Client::Next {}, &mut state, &paths.load_policy()).unwrap();
        (directory, paths, key, state, receive)
    }

    fn request_id(state: &OwnerState) -> String {
        state.pending.as_ref().unwrap().id.to_string()
    }

    fn admit_test(
        state: &mut OwnerState,
        ready: &ApprovalCompletion,
        paths: &ServicePaths,
    ) -> Result<Admission> {
        let prepared = state.prepare(ready.id, &ready.principal, &paths.load_policy())?;
        state
            .operations
            .ready(ready.id, &ready.principal, &prepared)?;
        let snapshot = state
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        state
            .operations
            .check_snapshot(ready.id, &ready.principal, snapshot)?;
        let admission = state.operations.admit(
            ready.id,
            &ready.principal,
            &mut state.authorizer,
            Instant::now(),
        )?;
        if !admission.accepts(&prepared) {
            return Err(Error::State(Fault::InvalidOperation));
        }
        Ok(admission)
    }

    fn proof(state: &mut OwnerState, paths: &ServicePaths, key: &EcdsaKeyPair) -> Client {
        thread::sleep(Duration::from_millis(2));
        let id = state.pending.as_ref().unwrap().id;
        assert!(
            begin_native_presence(
                id,
                presence_now().unwrap(),
                state,
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root)
                    .and_then(|source| source.identity())
            )
            .unwrap()
            .is_none()
        );
        let Reply::Challenge { authorization } = complete_native_presence(
            id,
            state,
            &paths.load_policy(),
            crate::owner::vault::Source::capture(&paths.root).and_then(|source| source.identity()),
        )
        .unwrap() else {
            panic!("expected approval challenge");
        };
        let challenge = BASE64.decode(authorization.bytes).unwrap();
        let signature = key.sign(&SystemRandom::new(), &challenge).unwrap();
        Client::Proof {
            id: request_id(state),
            signature: BASE64.encode(signature),
        }
    }

    #[test]
    fn payload_codec_rejects_forged_flags_unknown_operations_and_unbounded_data() {
        assert!(matches!(
            decode_client(br#"{"kind":"hello"}"#).unwrap(),
            Client::Hello {}
        ));
        for message in [
            json!({"kind": "hello", "approved": true}),
            json!({"kind": "allow"}),
            json!({"kind": "proof", "id": "request", "signature": "", "status": "PASS"}),
        ] {
            assert!(decode_client(&serde_json::to_vec(&message).unwrap()).is_err());
        }
        assert!(decode_client(&vec![b' '; 16385]).is_err());
    }

    #[test]
    fn explicit_vault_sync_is_decoded_without_accepting_client_authority_fields() {
        assert!(matches!(
            decode_client(br#"{"kind":"vaultSync"}"#).unwrap(),
            Client::VaultSync {}
        ));
        assert!(decode_client(br#"{"kind":"vaultSync","approved":true}"#).is_err());
    }

    #[test]
    fn approval_key_continuity_survives_ui_disconnect_within_the_backend_session() {
        let (_directory, paths, key, mut state, _receive) = fixture();
        state.disconnect_ui();
        handle(
            Client::Enroll {
                public_key: BASE64.encode(key.public_key()),
            },
            &mut state,
            &paths.load_policy(),
        )
        .unwrap();
        state.disconnect_ui();
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let replacement =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .unwrap();

        assert!(
            handle(
                Client::Enroll {
                    public_key: BASE64.encode(replacement.public_key())
                },
                &mut state,
                &paths.load_policy()
            )
            .is_err()
        );
        assert_eq!(
            state.approval_public_key.as_deref(),
            Some(key.public_key().as_ref())
        );
        assert!(state.ui.is_none());
    }

    #[test]
    fn verified_receipt_dispatches_once_and_replay_cannot_authorize() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        let Client::Proof { id, signature } = &message else {
            unreachable!()
        };
        let replay = Client::Proof {
            id: id.clone(),
            signature: signature.clone(),
        };
        assert!(matches!(
            handle(message, &mut state, &paths.load_policy()).unwrap(),
            Reply::Accepted
        ));
        let grant = receive.try_recv().unwrap();
        let admission = admit_test(&mut state, &grant, &paths).unwrap();
        assert_eq!(
            admission.request().action(),
            http_request::Action::CloseIssue
        );
        assert!(handle(replay, &mut state, &paths.load_policy()).is_err());
        assert!(receive.try_recv().is_err());
    }

    #[test]
    fn missing_presence_or_invalid_signature_never_yields_a_grant() {
        for authenticated in [false, true] {
            let (_directory, paths, key, mut state, receive) = fixture();
            if authenticated {
                let _ = proof(&mut state, &paths, &key);
            }
            assert!(
                handle(
                    Client::Proof {
                        id: request_id(&state),
                        signature: BASE64.encode([1; 64])
                    },
                    &mut state,
                    &paths.load_policy()
                )
                .is_err()
            );
            assert!(receive.try_recv().is_err());
        }
    }

    #[test]
    fn cancellation_and_invalid_presence_times_cannot_authorize() {
        let (_directory, paths, _key, mut state, receive) = fixture();
        assert!(
            begin_native_presence(
                state.pending.as_ref().unwrap().id,
                presence_now()
                    .unwrap()
                    .checked_add(Duration::from_secs(1))
                    .unwrap(),
                &mut state,
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root)
                    .and_then(|source| source.identity())
            )
            .is_err()
        );
        assert!(
            state
                .operations
                .authentication_offset(
                    state.pending.as_ref().unwrap().id,
                    &state.pending.as_ref().unwrap().principal
                )
                .is_err()
        );
        let canceled_id = request_id(&state);
        handle(
            Client::Cancel {
                id: request_id(&state),
            },
            &mut state,
            &paths.load_policy(),
        )
        .unwrap();
        assert!(state.pending.is_none());
        assert!(receive.try_recv().is_err());
        assert!(
            handle(
                Client::Proof {
                    id: canceled_id,
                    signature: String::new()
                },
                &mut state,
                &paths.load_policy()
            )
            .is_err()
        );
    }

    #[test]
    fn ui_session_loss_revokes_a_minted_but_undispatched_grant() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        handle(message, &mut state, &paths.load_policy()).unwrap();
        let grant = receive.try_recv().unwrap();
        state.disconnect_ui();
        assert!(admit_test(&mut state, &grant, &paths).is_err());
    }

    #[test]
    fn vault_status_is_noninteractive_and_contains_only_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: "/unused.app".into(),
            root: directory.path().canonicalize().unwrap(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let shared = Arc::new((Mutex::new(OwnerState::new().unwrap()), Condvar::new()));

        let reply = Reply::VaultStatus(vault_workflow::cache_status(&paths.root, &shared).unwrap());
        let reply: Value = serde_json::from_slice(&encode_reply(&reply).unwrap()).unwrap();

        assert_eq!(reply["kind"], "vaultStatus");
        assert_eq!(reply["state"], "unenrolled");
        assert!(reply.get("password").is_none());
        assert!(reply.get("token").is_none());
        assert!(shared.0.lock().unwrap().provider.snapshot().is_none());
    }

    #[test]
    fn cache_lock_contention_reports_busy_without_blocking_cancellation_or_losing_warm_state() {
        let (_directory, paths, _key, state, _receive) = fixture();
        let id = state.pending.as_ref().unwrap().id.to_string();
        let digest = state.provider.snapshot().unwrap().credential_digest();
        let cache = super::super::persistence::store(&paths.root).unwrap();
        let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(paths.root.join("vault/vault.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let worker_state = Arc::clone(&shared);
        let worker_paths = paths.clone();
        let (send, receive) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            send.send(
                vault_workflow::cache_status(&worker_paths.root, &worker_state)
                    .map(Reply::VaultStatus),
            )
            .unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        if result.is_err() {
            drop(lock);
            worker.join().unwrap();
            panic!("cache contention blocked the owner mutex");
        }
        worker.join().unwrap();
        let Reply::VaultStatus(status) = result.unwrap().unwrap() else {
            panic!("expected vault status");
        };
        assert_eq!(status.state, crate::VaultState::Busy);
        let mut state = shared.0.try_lock().unwrap();
        assert_eq!(
            state.provider.snapshot().unwrap().credential_digest(),
            digest
        );
        assert!(matches!(
            handle(Client::Cancel { id }, &mut state, &paths.load_policy()).unwrap(),
            Reply::Canceled
        ));
        assert!(state.pending.is_none());
        assert_eq!(
            state.provider.snapshot().unwrap().credential_digest(),
            digest
        );
        drop(lock);
        assert_eq!(
            (cache.load().unwrap(), cache.load_enrollment().unwrap()),
            before
        );
        drop(state);
        assert!(matches!(
            vault_workflow::cache_status(&paths.root, &shared)
                .unwrap()
                .state,
            crate::VaultState::OnlineUnlocked
        ));
    }

    #[test]
    fn locking_the_vault_revokes_outstanding_approval_authority() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        handle(message, &mut state, &paths.load_policy()).unwrap();
        let grant = receive.try_recv().unwrap();

        handle(Client::VaultLock {}, &mut state, &paths.load_policy()).unwrap();

        assert!(state.pending.is_none());
        assert!(state.provider.snapshot().is_none());
        assert!(state.ui.is_none());
        assert!(admit_test(&mut state, &grant, &paths).is_err());
    }

    #[test]
    fn acknowledged_cancellation_after_proof_prevents_dispatch() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        handle(message, &mut state, &paths.load_policy()).unwrap();
        let grant = receive.try_recv().unwrap();
        let reply = handle(
            Client::Cancel {
                id: request_id(&state),
            },
            &mut state,
            &paths.load_policy(),
        )
        .unwrap();
        let mut requests = 0;

        let result = admit_test(&mut state, &grant, &paths).map(|_| {
            requests += 1;
        });

        assert!(matches!(reply, Reply::Canceled));
        assert!(result.is_err());
        assert_eq!(requests, 0);
    }

    #[test]
    fn a_completed_proof_reports_the_actual_cancellation_order() {
        for admitted in [false, true] {
            let (_directory, paths, key, mut state, receive) = fixture();
            let message = proof(&mut state, &paths, &key);
            let id = request_id(&state);
            handle(message, &mut state, &paths.load_policy()).unwrap();
            let ready = receive.try_recv().unwrap();
            if admitted {
                admit_test(&mut state, &ready, &paths).unwrap();
            }
            for _ in 0..2 {
                let reply = handle(
                    Client::Cancel { id: id.clone() },
                    &mut state,
                    &paths.load_policy(),
                )
                .unwrap();
                if admitted {
                    assert!(matches!(reply, Reply::AlreadyAdmitted));
                } else {
                    assert!(matches!(reply, Reply::Canceled));
                }
            }
            assert!(matches!(
                handle(
                    Client::Cancel {
                        id: "unknown".into()
                    },
                    &mut state,
                    &paths.load_policy()
                )
                .unwrap(),
                Reply::UnknownOperation
            ));
        }
    }

    #[test]
    fn concurrent_duplicate_proofs_yield_only_one_ready_operation() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let Client::Proof { id, signature } = proof(&mut state, &paths, &key) else {
            unreachable!()
        };
        let state = Arc::new(Mutex::new(state));
        let paths = Arc::new(paths);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let state = Arc::clone(&state);
                let paths = Arc::clone(&paths);
                let barrier = Arc::clone(&barrier);
                let message = Client::Proof {
                    id: id.clone(),
                    signature: signature.clone(),
                };
                thread::spawn(move || {
                    barrier.wait();
                    handle(message, &mut state.lock().unwrap(), &paths.load_policy()).is_ok()
                })
            })
            .collect();

        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|accepted| *accepted)
                .count(),
            1
        );
        assert!(receive.try_recv().is_ok());
        assert!(receive.try_recv().is_err());
    }

    #[test]
    fn restarting_the_owner_cannot_replay_a_previous_ready_operation() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        handle(message, &mut state, &paths.load_policy()).unwrap();
        let ready = receive.try_recv().unwrap();
        let mut restarted = OwnerState::new().unwrap();

        assert_ne!(state.authorizer.session(), restarted.authorizer.session());
        assert!(admit_test(&mut restarted, &ready, &paths).is_err());
        assert!(restarted.ui.is_none());
        assert!(restarted.pending.is_none());
    }

    #[test]
    fn configured_read_runs_without_a_frontend_or_presence() {
        let root = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: "/must-not-be-launched.app".into(),
            root: root.path().to_path_buf(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let mut state = OwnerState::new().unwrap();
        let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60)).unix_timestamp() as u64;
        state
            .authorizer
            .seed_fixture_grants(&crate::owner::test_support::policy_bytes(expires));
        let principal = super::super::identity::VerifiedPrincipal::fixture(
            501,
            "11".repeat(20),
            state.authorizer.session(),
        );

        for _ in 0..2 {
            let AuthorizationOutcome::Allowed(permit) = state
                .authorize(
                    &principal,
                    super::super::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding()),
                )
                .unwrap()
            else {
                panic!()
            };
            state
                .authorizer
                .admit(permit, &principal, Instant::now())
                .unwrap();
        }

        assert!(
            state
                .authorize(
                    &principal,
                    super::super::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding())
                )
                .is_ok()
        );
        assert!(state.ui.is_none());
        assert!(state.pending.is_none());
    }

    #[test]
    fn ending_the_os_session_cancels_approval_and_locks_the_cache_without_automatic_reactivation() {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
        let generation = state.provider.generation();
        state.end_host_session().unwrap();
        assert!(state.pending.is_none());
        assert!(state.ui.is_none());
        assert!(state.provider.snapshot().is_none());
        assert_ne!(state.provider.generation(), generation);
        assert!(handle(Client::Hello {}, &mut state, &paths.load_policy()).is_err());
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        assert!(vault_workflow::cache_status(&paths.root, &shared).is_ok());
        let mut state = shared.0.lock().unwrap();
        state.refresh_policy(&paths.load_policy()).unwrap();
        assert!(matches!(
            state.authorizer.authorize(
                &principal,
                crate::owner::test_support::read_request(),
                Instant::now()
            ),
            Err(super::super::policy::AuthorizationError::SessionRevoked)
        ));
    }

    #[test]
    fn ending_the_os_session_prevents_an_already_prepared_read_from_handing_off() {
        let root = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            root: root.path().to_owned(),
            app: "/unused.app".into(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let mut state = OwnerState::new().unwrap();
        let principal =
            VerifiedPrincipal::fixture(501, "11".repeat(20), state.authorizer.session());
        let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60))
            .unix_timestamp()
            .try_into()
            .unwrap();
        state
            .authorizer
            .seed_fixture_grants(&crate::owner::test_support::policy_bytes(expires));
        crate::owner::test_support::vault::install(
            &mut state.provider,
            crate::owner::test_support::vault::snapshot("github-read"),
        );
        let outcome = state
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding()),
            )
            .unwrap();
        let id = state.operations.register(outcome, Instant::now()).unwrap();
        let selection = CredentialSelection::at_generation(
            state.provider.snapshot().unwrap(),
            state.provider.generation(),
        );
        state
            .operations
            .select_credential(id, &principal, selection)
            .unwrap();
        let request = state.prepare(id, &principal, &paths.load_policy()).unwrap();
        let prepared = PreparedOperation::new(request, state.upstream.connect().unwrap());
        state.end_host_session().unwrap();
        assert!(
            state
                .handoff(prepared, &principal, &paths.load_policy())
                .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&state.upstream).1,
            0
        );
    }

    #[test]
    fn host_lock_and_wake_preserve_scoped_reads_and_cache() {
        for event in [
            crate::platform::HostSessionEvent::Sleep,
            crate::platform::HostSessionEvent::Wake,
            crate::platform::HostSessionEvent::ScreenLock,
            crate::platform::HostSessionEvent::Inactive,
            crate::platform::HostSessionEvent::ConsoleChange,
        ] {
            let (_directory, paths, _key, mut state, _receive) = fixture();
            let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
            let write = state.pending.as_ref().unwrap().id;
            let generation = state.provider.generation();
            let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60))
                .unix_timestamp()
                .try_into()
                .unwrap();
            let mut policy: Value =
                serde_json::from_slice(&crate::owner::test_support::policy_bytes(expires)).unwrap();
            policy["grants"][0]["role"] = "github-write".into();
            state
                .authorizer
                .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
            let outcome = state
                .authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding()),
                )
                .unwrap();
            let read = state.operations.register(outcome, Instant::now()).unwrap();
            let selection =
                CredentialSelection::at_generation(state.provider.snapshot().unwrap(), generation);
            state
                .operations
                .select_credential(read, &principal, selection)
                .unwrap();
            let prepared = PreparedOperation::new(
                state
                    .prepare(read, &principal, &paths.load_policy())
                    .unwrap(),
                state.upstream.connect().unwrap(),
            );
            state.host_events.record(event);
            state.synchronize_host_events().unwrap();
            assert!(state.authorizer.session_active());
            assert!(state.pending.is_none());
            assert!(state.ui.is_none());
            assert!(
                state
                    .operations
                    .check_wait(write, &principal, Instant::now())
                    .is_err()
            );
            assert_eq!(state.provider.generation(), generation);
            assert!(state.provider.snapshot().is_some());
            state
                .handoff(prepared, &principal, &paths.load_policy())
                .unwrap();
            let outcome = state
                .authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding()),
                )
                .unwrap();
            let super::super::policy::AuthorizationOutcome::Allowed(permit) = outcome else {
                panic!()
            };
            state
                .authorizer
                .admit(permit, &principal, Instant::now())
                .unwrap();
            assert!(matches!(
                state.authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    &paths.load_policy(),
                    crate::owner::vault::Source::capture(&paths.root)
                        .map(|source| source.binding())
                ),
                Ok(AuthorizationOutcome::Allowed(_))
            ));
            assert!(
                state
                    .authorizer
                    .authorize(
                        &principal,
                        crate::owner::test_support::read_request(),
                        Instant::now()
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    fn host_lock_cancels_a_pending_write_before_any_policy_reload() {
        let (_directory, _paths, _key, mut state, _receive) = fixture();
        let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
        let id = state.pending.as_ref().unwrap().id;
        state
            .host_session_event(crate::platform::HostSessionEvent::ScreenLock)
            .unwrap();
        assert!(state.pending.is_none());
        assert!(state.ui.is_none());
        assert!(
            state
                .operations
                .check_wait(id, &principal, Instant::now())
                .is_err()
        );
        assert!(state.provider.snapshot().is_some());
    }

    #[test]
    fn stricter_host_policy_and_logout_revoke_read_authority_and_lock_the_cache() {
        for logout in [false, true] {
            let (_directory, _paths, _key, mut state, _receive) = fixture();
            if !logout {
                state.session_policy.reads_survive_lock = false;
            }
            state
                .host_session_event(if logout {
                    crate::platform::HostSessionEvent::Logout
                } else {
                    crate::platform::HostSessionEvent::ScreenLock
                })
                .unwrap();
            assert!(!state.authorizer.session_active());
            assert!(state.provider.snapshot().is_none());
        }
    }

    #[test]
    fn verified_socket_read_returns_a_response_without_launching_the_frontend() {
        let root = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: root.path().join("nonexistent.app"),
            root: root.path().to_path_buf(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let peer = qm_macos::peer_identity::PeerIdentity::capture(&server).unwrap();
        let mut policy: Value = serde_json::from_slice(&super::super::test_support::policy_bytes(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
        ))
        .unwrap();
        policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
        policy["grants"][0]["codeHash"] = json!(peer.code_hash());
        let mut state = OwnerState::new().unwrap();
        state
            .authorizer
            .seed_native_fixture_grants(&serde_json::to_vec(&policy).unwrap());
        crate::owner::test_support::vault::install(
            &mut state.provider,
            super::super::test_support::vault::snapshot("github-read"),
        );
        let upstream = state.upstream.clone();
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        client.write_all(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n").unwrap();

        handle_http(&mut server, &shared, &paths).unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"state\":\"open\""));
        assert!(response.contains("\"quartermaster_local_simulation\":true"));
        assert!(shared.0.lock().unwrap().ui.is_none());
        assert_eq!(super::super::transport::fixture::observe(&upstream).0, 1);
    }

    #[test]
    fn a_waiting_connection_does_not_block_an_independent_authorized_read() {
        let root = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: root.path().join("nonexistent.app"),
            root: root.path().to_path_buf(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let socket = root.path().join("ingress.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let slow_client = UnixStream::connect(&socket).unwrap();
        let mut read_client = UnixStream::connect(&socket).unwrap();
        let peer = PeerIdentity::capture(&read_client).unwrap();
        let mut policy: Value = serde_json::from_slice(&super::super::test_support::policy_bytes(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
        ))
        .unwrap();
        policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
        policy["grants"][0]["codeHash"] = json!(peer.code_hash());
        let mut state = OwnerState::new().unwrap();
        state
            .authorizer
            .seed_native_fixture_grants(&serde_json::to_vec(&policy).unwrap());
        crate::owner::test_support::vault::install(
            &mut state.provider,
            super::super::test_support::vault::snapshot("github-read"),
        );
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let listener = {
            let _entered = runtime.enter();
            tokio::net::UnixListener::from_std(listener).unwrap()
        };
        let worker = runtime.spawn(serve_ingress(listener, shared, paths));
        read_client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        read_client.write_all(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n").unwrap();
        let mut response = String::new();

        let read = read_client.read_to_string(&mut response);
        drop(slow_client);
        worker.abort();
        runtime.shutdown_timeout(Duration::from_secs(2));

        read.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn a_prepared_read_cannot_survive_lock_and_unlock_of_the_identical_cache() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ServicePaths {
            app: "/unused.app".into(),
            root: directory.path().canonicalize().unwrap(),
            settings: None,
            policy: Arc::new(policy_source::PolicySource::fixture(
                crate::owner::policy::Policy::default(),
            )),
        };
        let mut state = OwnerState::new().unwrap();
        let principal =
            VerifiedPrincipal::fixture(501, "11".repeat(20), state.authorizer.session());
        let policy = super::super::test_support::policy_bytes(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
        );
        state.authorizer.seed_fixture_grants(&policy);
        crate::owner::test_support::vault::install(
            &mut state.provider,
            super::super::test_support::vault::snapshot("github-read"),
        );
        let outcome = state
            .authorize(
                &principal,
                super::super::test_support::read_request(),
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding()),
            )
            .unwrap();
        let id = state.operations.register(outcome, Instant::now()).unwrap();
        state
            .operations
            .select_credential(
                id,
                &principal,
                crate::owner::test_support::vault::selection(state.provider.snapshot().unwrap()),
            )
            .unwrap();
        let request = state.prepare(id, &principal, &paths.load_policy()).unwrap();
        let upstream = state.upstream.clone();
        let prepared = PreparedOperation::new(request, upstream.connect().unwrap());

        handle(Client::VaultLock {}, &mut state, &paths.load_policy()).unwrap();
        crate::owner::test_support::vault::install(
            &mut state.provider,
            super::super::test_support::vault::snapshot("github-read"),
        );
        let result = state.handoff(prepared, &principal, &paths.load_policy());
        let admitted = result.is_ok();
        if let Ok(receipt) = result {
            let _ = receipt.response();
        }

        assert!(!admitted);
        assert_eq!(super::super::transport::fixture::observe(&upstream), (0, 0));
    }

    #[test]
    fn a_standalone_unlock_can_finish_after_ui_exit_and_serve_an_independent_read() {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        let id = state.pending.as_ref().unwrap().id;
        let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
        state.provider.lock().unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let source = super::super::vault::fixture::put(&paths.root, &snapshot);
        let unlock = state
            .provider
            .begin_unlock(source.identity().unwrap())
            .unwrap();

        state.disconnect_ui();
        super::super::vault::finish_unlock(&paths.root, &mut state.provider, unlock, snapshot)
            .unwrap();

        assert!(state.ui.is_none());
        assert_eq!(
            state.operations.cancel(id, &principal),
            CancellationResult::Canceled
        );
        let mut policy: Value = serde_json::from_slice(&crate::owner::test_support::policy_bytes(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
        ))
        .unwrap();
        policy["grants"][0]["role"] = "github-write".into();
        state
            .authorizer
            .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
        let outcome = state
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths.load_policy(),
                crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding()),
            )
            .unwrap();
        let read = state.operations.register(outcome, Instant::now()).unwrap();
        state
            .operations
            .select_credential(
                read,
                &principal,
                CredentialSelection::at_generation(
                    state.provider.snapshot().unwrap(),
                    state.provider.generation(),
                ),
            )
            .unwrap();
        let request = state
            .prepare(read, &principal, &paths.load_policy())
            .unwrap();
        let prepared = PreparedOperation::new(request, state.upstream.connect().unwrap());
        let response = state
            .handoff(prepared, &principal, &paths.load_policy())
            .unwrap()
            .response();
        assert_eq!(response, OperationResponse::IssueOpen);
        assert_eq!(
            super::super::transport::fixture::observe(&state.upstream).0,
            1
        );
    }

    #[test]
    fn final_write_handoff_checks_the_shared_clock_even_if_instant_has_not_expired() {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        handle(message, &mut state, &paths.load_policy()).unwrap();
        let ready = receive.try_recv().unwrap();
        let frame = state
            .prepare(ready.id, &ready.principal, &paths.load_policy())
            .unwrap();
        let upstream = state.upstream.clone();
        let prepared = PreparedOperation::new(frame, upstream.connect().unwrap());
        let future = presence_now()
            .unwrap()
            .checked_add(Duration::from_secs(30))
            .unwrap();
        let result =
            state.handoff_with_clock(prepared, &ready.principal, &paths.load_policy(), || {
                Ok(future)
            });
        let admitted = result.is_ok();
        if let Ok(receipt) = result {
            let _ = receipt.response();
        }

        assert!(!admitted);
        assert_eq!(super::super::transport::fixture::observe(&upstream), (0, 0));
    }

    #[test]
    fn a_staged_approval_cannot_accept_presence_without_a_native_context() {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        let id = request_id(&state);
        assert!(
            handle(
                Client::Presence {
                    id,
                    authenticated: presence_now().unwrap()
                },
                &mut state,
                &paths.load_policy()
            )
            .is_err()
        );
        assert!(
            state
                .operations
                .authentication_offset(
                    state.pending.as_ref().unwrap().id,
                    &state.pending.as_ref().unwrap().principal
                )
                .is_err()
        );
        assert_eq!(
            super::super::transport::fixture::observe(&state.upstream),
            (0, 0)
        );
    }
}
