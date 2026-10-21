use super::*;
use crate::owner::policy::fixture::FixturePolicy;
use crate::owner::{
    dispatch::PreparedOperation,
    github::{configuration::GitHubConfig, repository::RepositoryLookup},
    identity::VerifiedPrincipal,
    operation::{CancellationResult, OperationRegistry},
    policy::Authorizer,
    request,
    test_support::{self, vault},
    transport::OperationResponse,
};
use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io::{Cursor, Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Instant,
};

fn client_config(trusted: bool) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if trusted {
        roots
            .add(CertificateDer::from(
                include_bytes!("../fixtures/tls/dummy-ca.der").to_vec(),
            ))
            .unwrap();
    }
    configuration(roots).unwrap()
}

fn peer(
    stall: bool,
) -> (
    std::net::SocketAddr,
    mpsc::Sender<()>,
    thread::JoinHandle<Vec<u8>>,
) {
    peer_response(stall, None)
}

fn peer_response(
    stall: bool,
    metadata_id: Option<u64>,
) -> (
    std::net::SocketAddr,
    mpsc::Sender<()>,
    thread::JoinHandle<Vec<u8>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (resume, receive) = mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        if stall {
            receive.recv().unwrap();
        }
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("../fixtures/tls/dummy-cert.der").to_vec(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        include_bytes!("../fixtures/tls/dummy-key.der").to_vec(),
                    )),
                )
                .unwrap();
        let mut tls = ServerConnection::new(Arc::new(config)).unwrap();
        let mut input = Vec::new();
        let mut stream = rustls::Stream::new(&mut tls, &mut socket);
        while !input.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            match stream.read(&mut byte) {
                Ok(1) => input.push(byte[0]),
                _ => return input,
            }
        }
        let body = metadata_id.map(|id| format!("{{\"id\":{id},\"full_name\":\"example/one\"}}")).unwrap_or_else(|| r#"{"number":42,"state":"open","url":"https://api.github.com/repos/example/one/issues/42","repository_url":"https://api.github.com/repos/example/one","title":"Actual fixture response"}"#.to_owned());
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        input
    });
    (address, resume, worker)
}

fn prepared(
    expired: bool,
) -> (
    Authorizer,
    VerifiedPrincipal,
    OperationRegistry,
    crate::owner::operation::OperationId,
    qm_providers::VaultSnapshot,
    crate::owner::dispatch::PreparedGitHubRequest,
) {
    let now = Instant::now()
        - if expired {
            Duration::from_secs(20)
        } else {
            Duration::ZERO
        };
    let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}]}"#).unwrap();
    let request = request::read_configured(&mut Cursor::new("GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer untrusted-caller-token\r\nCookie: forbidden\r\n\r\n"), Some(&config)).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&test_support::policy_bytes(1010, 1)).unwrap();
    document["grants"][0]["repository"] = "example/one".into();
    let mut authorizer = Authorizer::new([1; 16]);
    authorizer
        .install(
            Ok(
                FixturePolicy::decode(&serde_json::to_vec(&document).unwrap())
                    .unwrap()
                    .with_github(config.clone()),
            ),
            test_support::wall(1000),
            now,
        )
        .unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let snapshot = vault::snapshot("github-read");
    let selection = vault::selection(&snapshot);
    let binding = RepositoryLookup::new(
        &config,
        &request,
        selection.clone(),
        authorizer.policy_generation(),
    )
    .unwrap()
    .verify_fixture(br#"{"id":123,"full_name":"example/one"}"#)
    .unwrap();
    let mut registry = OperationRegistry::default();
    let id = registry
        .register(authorizer.authorize(&principal, request, now).unwrap(), now)
        .unwrap();
    registry
        .select_credential(id, &principal, selection)
        .unwrap();
    let request = crate::owner::execution::prepare_github(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        binding,
        now,
    )
    .unwrap();
    (authorizer, principal, registry, id, snapshot, request)
}

#[test]
fn github_https_stages_an_immutable_encrypted_request_and_sends_once_only_after_admission() {
    let (mut authorizer, principal, mut registry, _id, snapshot, request) = prepared(false);
    let (address, _, worker) = peer(false);
    let transport = ReadyGitHub::connect_to(
        address,
        client_config(true),
        Deadline::after(Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let operation = PreparedOperation::github(request, transport).unwrap();
    let receipt = operation
        .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
        .unwrap();
    assert!(matches!(receipt.response(), OperationResponse::Github(_)));
    let input = String::from_utf8(worker.join().unwrap()).unwrap();
    assert!(
        input.starts_with("GET /repositories/123/issues/42 HTTP/1.1\r\nHost: api.github.com\r\n")
    );
    assert_eq!(
        input
            .matches("Authorization: Bearer quartermaster-dummy-canary")
            .count(),
        1
    );
    assert!(input.contains("X-GitHub-Api-Version: 2026-03-10\r\n"));
    assert!(!input.contains("untrusted-caller-token"));
    assert!(!input.contains("Cookie:"));
    let config = authorizer.github_configuration().unwrap();
    let request = request::read_configured(
        &mut Cursor::new(
            "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ),
        Some(config),
    )
    .unwrap();
    assert!(
        authorizer
            .authorize(&principal, request, Instant::now())
            .is_err()
    );
}

#[test]
fn github_https_cancel_expiry_policy_session_and_credential_changes_send_zero_application_bytes() {
    for change in ["cancel", "expiry", "policy", "session", "credential"] {
        let (mut authorizer, principal, mut registry, id, snapshot, request) =
            prepared(change == "expiry");
        let (address, resume, worker) = peer(true);
        let connection = thread::spawn(move || {
            ReadyGitHub::connect_to(
                address,
                client_config(true),
                Deadline::after(Duration::from_secs(2)).unwrap(),
            )
        });
        match change {
            "cancel" => assert_eq!(
                registry.cancel(id, &principal),
                CancellationResult::Canceled
            ),
            "policy" => {
                authorizer
                    .install(
                        Ok(FixturePolicy::default()),
                        test_support::wall(1000),
                        Instant::now(),
                    )
                    .unwrap();
            }
            "session" => authorizer.revoke_session(),
            _ => {}
        }
        resume.send(()).unwrap();
        let transport = connection.join().unwrap().unwrap();
        let operation = PreparedOperation::github(request, transport).unwrap();
        let replacement = vault::snapshot_with(
            "github-read",
            "33333333-3333-4333-8333-333333333333",
            [9; 16],
        );
        assert!(
            operation
                .handoff(
                    &mut registry,
                    &mut authorizer,
                    &principal,
                    if change == "credential" {
                        &replacement
                    } else {
                        &snapshot
                    }
                )
                .is_err()
        );
        assert!(
            worker.join().unwrap().is_empty(),
            "sent application bytes after {change}"
        );
    }
}

#[test]
fn github_https_tampered_encrypted_records_send_nothing_without_spending_the_read_budget() {
    let (mut authorizer, principal, mut registry, id, snapshot, request) = prepared(false);
    let (address, _, worker) = peer(false);
    let transport = ReadyGitHub::connect_to(
        address,
        client_config(true),
        Deadline::after(Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let mut prepared = transport.stage(request).unwrap();
    prepared.records.bytes[0] ^= 1;
    let operation = PreparedOperation::Github(Box::new(prepared));
    assert!(
        operation
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .is_err()
    );
    assert!(worker.join().unwrap().is_empty());
    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::Canceled
    );
    let request = request::read_configured(
        &mut Cursor::new(
            "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ),
        authorizer.github_configuration(),
    )
    .unwrap();
    assert!(
        authorizer
            .authorize(&principal, request, Instant::now())
            .is_ok()
    );
}

#[test]
fn github_https_handshake_timeout_and_untrusted_certificate_never_send_http() {
    for trusted in [false, true] {
        let (address, resume, worker) = peer(trusted);
        let result = ReadyGitHub::connect_to(
            address,
            client_config(trusted),
            Deadline::after(Duration::from_millis(50)).unwrap(),
        );
        assert!(result.is_err());
        if trusted {
            resume.send(()).unwrap();
        }
        assert!(worker.join().unwrap().is_empty());
    }
}

#[test]
fn github_https_metadata_authority_can_only_lookup_the_pinned_repository_and_preserves_issue_budget()
 {
    let (mut authorizer, principal, mut registry, id, snapshot, _) = prepared(false);
    let request = crate::owner::execution::prepare_metadata(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    let (address, _, worker) = peer_response(false, Some(123));
    let transport = ReadyGitHub::connect_to(
        address,
        client_config(true),
        Deadline::after(Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let prepared = transport.stage_metadata(request).unwrap();
    let admission = registry
        .admit_metadata(
            prepared.request(),
            &principal,
            &authorizer,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
    let binding = prepared.handoff(admission).unwrap().response().unwrap();
    let input = String::from_utf8(worker.join().unwrap()).unwrap();
    assert!(input.starts_with("GET /repos/example/one HTTP/1.1\r\n"));
    assert!(!input.contains("/issues/"));
    let request = crate::owner::execution::prepare_github(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        binding,
        Instant::now(),
    )
    .unwrap();
    let (address, _, worker) = peer(false);
    let transport = ReadyGitHub::connect_to(
        address,
        client_config(true),
        Deadline::after(Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let prepared = PreparedOperation::github(request, transport).unwrap();
    assert!(matches!(
        prepared
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .unwrap()
            .response(),
        OperationResponse::Github(_)
    ));
    assert!(!worker.join().unwrap().is_empty());
}

#[test]
fn github_https_metadata_cancellation_and_policy_change_send_zero_application_bytes() {
    for cancel in [true, false] {
        let (mut authorizer, principal, mut registry, id, snapshot, _) = prepared(false);
        let request = crate::owner::execution::prepare_metadata(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        let (address, _, worker) = peer_response(false, Some(123));
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let prepared = transport.stage_metadata(request).unwrap();
        if cancel {
            assert_eq!(
                registry.cancel(id, &principal),
                CancellationResult::Canceled
            );
        } else {
            authorizer
                .install(
                    Ok(FixturePolicy::default()),
                    test_support::wall(1000),
                    Instant::now(),
                )
                .unwrap();
        }
        assert!(
            registry
                .admit_metadata(
                    prepared.request(),
                    &principal,
                    &authorizer,
                    &snapshot,
                    Instant::now()
                )
                .is_err()
        );
        drop(prepared);
        assert!(worker.join().unwrap().is_empty());
    }
}

#[test]
fn github_https_expired_preparation_does_not_start_dns() {
    let (started, receive) = mpsc::channel();
    assert!(
        resolve_with(Deadline::after(Duration::ZERO).unwrap(), move || {
            started.send(()).unwrap();
            Ok(Vec::new())
        })
        .is_err()
    );
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    );
}

#[test]
fn github_https_stalled_dns_keeps_its_worker_reservation_until_lookup_finishes() {
    let mut releases = Vec::new();
    let mut completions = Vec::new();
    let mut waiters = Vec::new();
    for _ in 0..4 {
        let (started, received) = mpsc::sync_channel(0);
        let (release, resume) = mpsc::sync_channel(0);
        let (complete, completed) = mpsc::sync_channel(0);
        waiters.push(thread::spawn(move || {
            resolve_with(
                Deadline::after(Duration::from_millis(50)).unwrap(),
                move || {
                    started.send(()).unwrap();
                    resume.recv().unwrap();
                    complete.send(()).unwrap();
                    Ok(vec!["127.0.0.1:443".parse().unwrap()])
                },
            )
        }));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        releases.push(release);
        completions.push(completed);
    }
    for waiter in waiters {
        assert!(waiter.join().unwrap().is_err());
    }
    let (started, receive) = mpsc::channel();
    let refused = resolve_with(
        Deadline::after(Duration::from_secs(1)).unwrap(),
        move || {
            started.send(()).unwrap();
            Ok(Vec::new())
        },
    );
    for (release, completed) in releases.into_iter().zip(completions) {
        release.send(()).unwrap();
        completed.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    assert!(refused.is_err());
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    );
}
