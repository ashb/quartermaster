use super::*;
use crate::owner::policy::fixture::FixturePolicy;
use crate::owner::{
    identity::VerifiedPrincipal,
    operation::{CancellationResult, OperationRegistry},
    policy::{AuthorizationOutcome, Authorizer},
    test_support::{
        policy_bytes, read_request,
        vault::{snapshot, snapshot_with},
    },
};
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::owner::transport::{self, DummyUpstream, OperationResponse};

fn fixture(
    role: &str,
) -> (
    Authorizer,
    VerifiedPrincipal,
    OperationRegistry,
    OperationId,
    qm_providers::VaultSnapshot,
    Instant,
) {
    let now = Instant::now();
    let mut authorizer = Authorizer::new([1; 16]);
    let mut policy: serde_json::Value = serde_json::from_slice(&policy_bytes(1010, 2)).unwrap();
    policy["grants"][0]["role"] = role.into();
    authorizer
        .install(
            FixturePolicy::decode(&serde_json::to_vec(&policy).unwrap()),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let mut registry = OperationRegistry::default();
    let id = registry
        .register(
            authorizer
                .authorize(&principal, read_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    let snapshot = snapshot(role);
    registry
        .select_credential(
            id,
            &principal,
            crate::owner::test_support::vault::selection(&snapshot),
        )
        .unwrap();
    (authorizer, principal, registry, id, snapshot, now)
}

#[test]
fn an_allow_grant_builds_the_exact_credential_bearing_read_without_a_proof() {
    let (authorizer, principal, registry, id, snapshot, now) = fixture("github-read");

    let prepared = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();

    assert_eq!(prepared.bytes(), b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nAuthorization: Bearer quartermaster-dummy-canary\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

#[test]
fn a_host_can_select_a_write_credential_for_a_mediated_read_without_authorizing_a_write() {
    let (authorizer, principal, registry, id, snapshot, now) = fixture("github-write");

    assert!(
        crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            now
        )
        .is_ok()
    );
    let close = crate::owner::test_support::close_request();
    assert!(matches!(
        authorizer.authorize(&principal, close, now).unwrap(),
        crate::owner::policy::AuthorizationOutcome::RequireApproval(_)
    ));
}

#[test]
fn canceled_expired_or_revoked_operations_cannot_acquire_plaintext() {
    for case in 0..3 {
        let (mut authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
        if case == 0 {
            assert_eq!(
                registry.cancel(id, &principal),
                CancellationResult::Canceled
            );
        }
        if case == 1 {
            authorizer.revoke_session();
        }

        assert!(
            crate::owner::execution::prepare_simulation(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                if case == 2 {
                    now + Duration::from_secs(10)
                } else {
                    now
                }
            )
            .is_err()
        );
    }
}

#[test]
fn acquisition_rejects_a_different_item_role_or_cache_checkpoint() {
    let (authorizer, principal, registry, id, _snapshot, now) = fixture("github-read");
    for changed in [
        snapshot("github-write"),
        snapshot_with(
            "github-read",
            "33333333-3333-4333-8333-333333333333",
            [3; 16],
        ),
        snapshot_with(
            "github-read",
            "22222222-2222-4222-8222-222222222222",
            [4; 16],
        ),
    ] {
        assert!(
            crate::owner::execution::prepare_simulation(
                &registry,
                id,
                &principal,
                &authorizer,
                &changed,
                now
            )
            .is_err()
        );
    }
}

#[test]
fn an_unselected_credential_cannot_be_acquired_or_added_after_preparation() {
    let (authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
    let prepared = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();
    registry.ready(id, &principal, &prepared).unwrap();

    assert!(
        registry
            .select_credential(
                id,
                &principal,
                crate::owner::test_support::vault::selection(&snapshot)
            )
            .is_err()
    );
    let next = registry
        .register(
            authorizer
                .authorize(&principal, read_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    assert!(
        crate::owner::execution::prepare_simulation(
            &registry,
            next,
            &principal,
            &authorizer,
            &snapshot,
            now
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn an_admitted_read_sends_one_authenticated_request_and_returns_no_credential() {
    let (mut authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());

    let response = prepared
        .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
        .unwrap()
        .response();

    assert_eq!(response, OperationResponse::IssueOpen);
    assert_eq!(transport::fixture::observe(&upstream).0, 1);
    assert!(
        !response
            .public_parts()
            .1
            .contains("quartermaster-dummy-canary")
    );
}

#[cfg(unix)]
#[test]
fn canceled_or_expired_preparations_send_zero_upstream_bytes() {
    for canceled in [false, true] {
        let (mut authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
        let request = crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            now,
        )
        .unwrap();
        let upstream = DummyUpstream::default();
        let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
        if canceled {
            registry.cancel(id, &principal);
        }

        let result = prepared.handoff_at(
            &mut registry,
            &mut authorizer,
            &principal,
            &snapshot,
            || {
                if canceled {
                    now
                } else {
                    now + Duration::from_secs(10)
                }
            },
        );

        assert!(result.is_err());
        assert_eq!(transport::fixture::observe(&upstream), (0, 0));
    }
}

#[cfg(unix)]
#[test]
fn late_credential_change_after_preparation_sends_zero_upstream_bytes() {
    let (mut authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
    let changed = snapshot_with(
        "github-read",
        "22222222-2222-4222-8222-222222222222",
        [8; 16],
    );

    assert!(
        prepared
            .handoff(&mut registry, &mut authorizer, &principal, &changed)
            .is_err()
    );
    assert_eq!(transport::fixture::observe(&upstream), (0, 0));
}

#[cfg(unix)]
#[test]
fn lost_redirected_or_credential_echo_responses_never_retry_or_expose_material() {
    for reply in [
        transport::fixture::Reply::Lost,
        transport::fixture::Reply::Redirect,
        transport::fixture::Reply::Echo,
    ] {
        let (mut authorizer, principal, mut registry, id, snapshot, now) = fixture("github-read");
        let request = crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            now,
        )
        .unwrap();
        let (ready, probe) = transport::fixture::fault(reply);
        let prepared = PreparedOperation::new(request, ready);

        let response = prepared
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .unwrap()
            .response();

        assert_eq!(response, OperationResponse::Uncertain);
        assert_eq!(transport::fixture::counts(&probe).0, 1);
        assert!(
            !response
                .public_parts()
                .1
                .contains("quartermaster-dummy-canary")
        );
        assert!(
            crate::owner::execution::prepare_simulation(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                now
            )
            .is_err()
        );
    }
}

#[test]
fn bearer_validation_rejects_header_injection_empty_and_unbounded_material() {
    assert!(validate_token(b"ghp_valid-token.123").is_ok());
    for invalid in [
        b"".as_slice(),
        b"token\r\nHost: other",
        b"token\0",
        b"token with space",
        &[b'a'; 4097],
    ] {
        assert!(validate_token(invalid).is_err());
    }
}

#[cfg(unix)]
#[test]
fn final_handoff_samples_the_clock_after_connection_preparation() {
    let (mut authorizer, principal, mut registry, _, snapshot, now) = fixture("github-read");
    authorizer
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 1)),
            crate::owner::test_support::wall(1009) + Duration::from_millis(900),
            now,
        )
        .unwrap();
    let id = registry
        .register(
            authorizer
                .authorize(&principal, read_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    registry
        .select_credential(
            id,
            &principal,
            crate::owner::test_support::vault::selection(&snapshot),
        )
        .unwrap();
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
    std::thread::sleep(Duration::from_millis(150));

    let result = prepared.handoff(&mut registry, &mut authorizer, &principal, &snapshot);

    assert!(result.is_err());
    assert_eq!(transport::fixture::observe(&upstream), (0, 0));
}

#[cfg(unix)]
#[test]
fn an_allowed_read_cannot_acquire_a_mandatory_write_without_proof() {
    let (authorizer, principal, mut registry, _, _, now) = fixture("github-write");
    let snapshot = snapshot("github-write");
    let id = registry
        .register(
            authorizer
                .authorize(&principal, crate::owner::test_support::close_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    assert!(
        registry
            .select_credential(
                id,
                &principal,
                crate::owner::test_support::vault::selection(&snapshot),
            )
            .is_err()
    );
    let upstream = DummyUpstream::default();
    let connection = upstream.connect().unwrap();

    assert!(
        crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            now
        )
        .is_err()
    );
    drop(connection);

    assert_eq!(transport::fixture::observe(&upstream), (0, 0));
}

#[cfg(unix)]
#[test]
fn a_signed_write_changes_the_dummy_issue_once_and_cannot_be_replayed() {
    let (mut authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
    let (id, _session) = crate::owner::test_support::approval::write(
        &mut registry,
        &authorizer,
        &principal,
        &snapshot,
    );
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());

    let response = prepared
        .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
        .unwrap()
        .response();
    registry.finish(id, response.completion()).unwrap();

    assert_eq!(response, OperationResponse::IssueClosed);
    assert_eq!(transport::fixture::observe(&upstream).0, 1);
    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::AlreadyAdmitted
    );
    assert!(
        crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            Instant::now()
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn invalidating_approval_authority_rejects_an_old_proof_and_preserves_independent_read_authority() {
    let (mut authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
    let (id, _session) = crate::owner::test_support::approval::write(
        &mut registry,
        &authorizer,
        &principal,
        &snapshot,
    );
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
    authorizer.revoke_approvals();
    assert!(
        prepared
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .is_err()
    );
    assert_eq!(transport::fixture::observe(&upstream).1, 0);
    let AuthorizationOutcome::Allowed(read) = authorizer
        .authorize(&principal, read_request(), Instant::now())
        .unwrap()
    else {
        panic!()
    };
    authorizer.admit(read, &principal, Instant::now()).unwrap();
    let (fresh, _session) = crate::owner::test_support::approval::write(
        &mut registry,
        &authorizer,
        &principal,
        &snapshot,
    );
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        fresh,
        &principal,
        &authorizer,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    PreparedOperation::new(request, upstream.connect().unwrap())
        .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
        .unwrap()
        .response();
    assert_eq!(transport::fixture::observe(&upstream).0, 1);
}

#[cfg(unix)]
#[test]
fn cancel_expiry_or_proof_revocation_after_preparing_a_write_sends_zero_bytes() {
    for case in 0..3 {
        let (mut authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
        let (id, session) = crate::owner::test_support::approval::write(
            &mut registry,
            &authorizer,
            &principal,
            &snapshot,
        );
        let now = Instant::now();
        let request = crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            now,
        )
        .unwrap();
        let upstream = DummyUpstream::default();
        let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
        if case == 0 {
            assert_eq!(
                registry.cancel_interactive(id, [2; 16]),
                CancellationResult::Canceled
            );
        } else if case == 2 {
            session.revoke().unwrap();
        }

        let result = prepared.handoff_at(
            &mut registry,
            &mut authorizer,
            &principal,
            &snapshot,
            || {
                if case == 1 {
                    now + Duration::from_secs(30)
                } else {
                    now
                }
            },
        );

        assert!(result.is_err(), "case {case}");
        assert_eq!(transport::fixture::observe(&upstream), (0, 0));
    }
}

#[cfg(unix)]
#[test]
fn altered_method_origin_resource_headers_or_body_cannot_reach_transport() {
    for field in [
        "PATCH",
        "github.example.invalid",
        "/issues/42",
        "Bearer",
        "closed",
    ] {
        let (mut authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
        let (id, _session) = crate::owner::test_support::approval::write(
            &mut registry,
            &authorizer,
            &principal,
            &snapshot,
        );
        let mut request = crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        let offset = request
            .bytes()
            .windows(field.len())
            .position(|bytes| bytes == field.as_bytes())
            .unwrap();
        request.0.bytes[offset] ^= 1;
        let upstream = DummyUpstream::default();
        let prepared = PreparedOperation::new(request, upstream.connect().unwrap());

        assert!(
            prepared
                .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
                .is_err()
        );
        assert_eq!(transport::fixture::observe(&upstream), (0, 0));
    }
}

#[cfg(unix)]
#[test]
fn a_frame_from_another_operation_cannot_be_substituted_at_readiness() {
    let (authorizer, principal, mut registry, first, snapshot, now) = fixture("github-read");
    let second = registry
        .register(
            authorizer
                .authorize(&principal, read_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    registry
        .select_credential(
            second,
            &principal,
            crate::owner::test_support::vault::selection(&snapshot),
        )
        .unwrap();
    let frame = crate::owner::execution::prepare_simulation(
        &registry,
        first,
        &principal,
        &authorizer,
        &snapshot,
        now,
    )
    .unwrap();

    assert!(registry.ready(second, &principal, &frame).is_err());
    assert!(registry.ready(first, &principal, &frame).is_ok());
}

#[cfg(unix)]
#[test]
fn lost_redirected_or_secret_echo_write_responses_consume_authority_without_retry() {
    for reply in [
        transport::fixture::Reply::Lost,
        transport::fixture::Reply::Redirect,
        transport::fixture::Reply::Echo,
    ] {
        let (mut authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
        let (id, _session) = crate::owner::test_support::approval::write(
            &mut registry,
            &authorizer,
            &principal,
            &snapshot,
        );
        let request = crate::owner::execution::prepare_simulation(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        let (ready, probe) = transport::fixture::fault(reply);

        let response = PreparedOperation::new(request, ready)
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .unwrap()
            .response();
        registry.finish(id, response.completion()).unwrap();

        assert_eq!(response, OperationResponse::Uncertain);
        assert_eq!(transport::fixture::counts(&probe).0, 1);
        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::AlreadyAdmitted
        );
        assert!(
            crate::owner::execution::prepare_simulation(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                Instant::now()
            )
            .is_err()
        );
        assert!(
            !response
                .public_parts()
                .1
                .contains("quartermaster-dummy-canary")
        );
    }
}

#[cfg(unix)]
#[test]
fn simultaneous_handoffs_can_send_only_one_request_with_the_last_budget_unit() {
    use std::sync::{Arc, Barrier, Mutex};
    let (_, principal, mut registry, _, snapshot, now) = fixture("github-read");
    let mut authorizer = Authorizer::new([1; 16]);
    authorizer
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 1)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let upstream = DummyUpstream::default();
    let prepared: Vec<_> = (0..2)
        .map(|_| {
            let id = registry
                .register(
                    authorizer
                        .authorize(&principal, read_request(), now)
                        .unwrap(),
                    now,
                )
                .unwrap();
            registry
                .select_credential(
                    id,
                    &principal,
                    crate::owner::test_support::vault::selection(&snapshot),
                )
                .unwrap();
            let request = crate::owner::execution::prepare_simulation(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                now,
            )
            .unwrap();
            PreparedOperation::new(request, upstream.connect().unwrap())
        })
        .collect();
    let owner = Arc::new(Mutex::new((authorizer, registry, snapshot)));
    let principal = Arc::new(principal);
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = prepared
        .into_iter()
        .map(|prepared| {
            let owner = Arc::clone(&owner);
            let principal = Arc::clone(&principal);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let result = {
                    let mut guard = owner.lock().unwrap();
                    let (authorizer, registry, snapshot) = &mut *guard;
                    prepared.handoff(registry, authorizer, &principal, snapshot)
                };
                result.ok().map(|receipt| receipt.response())
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .count();

    assert_eq!(successes, 1);
    assert_eq!(transport::fixture::observe(&upstream).0, 1);
}

#[cfg(unix)]
#[test]
fn write_cancellation_racing_with_handoff_agrees_with_the_actual_request_count() {
    use std::sync::{Arc, Barrier, Mutex};
    let (authorizer, principal, mut registry, _, snapshot, _) = fixture("github-write");
    let (id, _session) = crate::owner::test_support::approval::write(
        &mut registry,
        &authorizer,
        &principal,
        &snapshot,
    );
    let request = crate::owner::execution::prepare_simulation(
        &registry,
        id,
        &principal,
        &authorizer,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    let upstream = DummyUpstream::default();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());
    let owner = Arc::new(Mutex::new((authorizer, registry, snapshot)));
    let principal = Arc::new(principal);
    let barrier = Arc::new(Barrier::new(2));
    let worker_owner = Arc::clone(&owner);
    let worker_principal = Arc::clone(&principal);
    let worker_barrier = Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        let result = {
            let mut guard = worker_owner.lock().unwrap();
            let (authorizer, registry, snapshot) = &mut *guard;
            prepared.handoff(registry, authorizer, &worker_principal, snapshot)
        };
        result.ok().map(|receipt| receipt.response())
    });

    barrier.wait();
    let canceled = owner.lock().unwrap().1.cancel(id, &principal);
    let response = worker.join().unwrap();

    match canceled {
        CancellationResult::Canceled => {
            assert_eq!(response, None);
            assert_eq!(transport::fixture::observe(&upstream), (0, 0));
        }
        CancellationResult::AlreadyAdmitted => {
            assert_eq!(response, Some(OperationResponse::IssueClosed));
            assert_eq!(transport::fixture::observe(&upstream).0, 1);
        }
        CancellationResult::UnknownOperation => panic!("registered operation disappeared"),
    }
}
