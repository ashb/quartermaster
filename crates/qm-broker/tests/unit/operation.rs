use super::*;
use crate::owner::policy::fixture::FixturePolicy;
use crate::owner::{
    dispatch,
    identity::VerifiedPrincipal,
    request,
    test_support::{policy_bytes, read_request},
};
use qm_providers::ApprovalSession;
use std::{
    io::Cursor,
    sync::{Arc, Barrier, Mutex},
    thread,
    time::Duration,
};

fn fixture(budget: u32) -> (Authorizer, VerifiedPrincipal, OperationRegistry, Instant) {
    let now = Instant::now();
    let mut authorizer = Authorizer::new([1; 16]);
    authorizer
        .install(
            FixturePolicy::decode(&policy_bytes(1010, budget)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    (
        authorizer,
        VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]),
        OperationRegistry::default(),
        now,
    )
}

#[test]
fn a_failed_signing_transition_revokes_the_record_instead_of_leaving_partial_state() {
    for invalid_offset in [false, true] {
        let (authorizer, principal, mut registry, created) = fixture(2);
        let id = registry
            .register(
                authorizer
                    .authorize(
                        &principal,
                        crate::owner::test_support::close_request(),
                        created,
                    )
                    .unwrap(),
                created,
            )
            .unwrap();
        let review = crate::owner::test_support::approval::review(
            registry.request(id, &principal).unwrap().clone(),
            None,
        );
        registry.bind_review(id, &principal, &review).unwrap();
        let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
        registry.begin_approval(id, &principal, &session).unwrap();
        let authenticated = Instant::now();
        if invalid_offset {
            assert!(
                registry
                    .authentication(
                        id,
                        &principal,
                        authenticated,
                        authenticated,
                        Duration::from_secs(120)
                    )
                    .is_err()
            );
        } else {
            registry
                .authentication(
                    id,
                    &principal,
                    authenticated,
                    authenticated,
                    authenticated.duration_since(created),
                )
                .unwrap();
            session.revoke().unwrap();
            let snapshot = crate::owner::test_support::vault::snapshot("github-write");
            assert!(
                registry
                    .challenge(
                        id,
                        &principal,
                        crate::owner::test_support::vault::selection(&snapshot)
                    )
                    .is_err()
            );
        }
        assert_eq!(registry.state(id), Some(OperationState::Revoked));
        assert!(registry.begin_approval(id, &principal, &session).is_err());
    }
}

#[test]
fn interactive_intent_can_be_canceled_before_any_credential_is_selected() {
    let (authorizer, principal, mut registry, now) = fixture(2);
    let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
    let id = registry
        .register(authorizer.authorize(&principal, request, now).unwrap(), now)
        .unwrap();
    let review = crate::owner::test_support::approval::review(
        registry.request(id, &principal).unwrap().clone(),
        None,
    );
    registry.bind_review(id, &principal, &review).unwrap();
    let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
    registry.begin_approval(id, &principal, &session).unwrap();

    assert_eq!(
        registry.cancel_interactive(id, [3; 16]),
        CancellationResult::UnknownOperation
    );
    assert_eq!(
        registry.cancel_interactive(id, [2; 16]),
        CancellationResult::Canceled
    );
    assert!(registry.check_wait(id, &principal, now).is_err());
}

fn read(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    principal: &VerifiedPrincipal,
    now: Instant,
) -> OperationId {
    let id = registry
        .register(
            authorizer
                .authorize(principal, read_request(), now)
                .unwrap(),
            now,
        )
        .unwrap();
    registry
        .select_credential(
            id,
            principal,
            crate::owner::test_support::vault::selection(
                &crate::owner::test_support::vault::snapshot("github-read"),
            ),
        )
        .unwrap();
    id
}

fn ready(
    registry: &mut OperationRegistry,
    authorizer: &Authorizer,
    id: OperationId,
    principal: &VerifiedPrincipal,
) -> Result<(), dispatch::Error> {
    let request = registry
        .request(id, principal)
        .map_err(dispatch::Error::Operation)?;
    let snapshot = crate::owner::test_support::vault::snapshot(request.role());
    let prepared = crate::owner::execution::prepare_simulation(
        registry,
        id,
        principal,
        authorizer,
        &snapshot,
        Instant::now(),
    )?;
    registry
        .ready(id, principal, &prepared)
        .map_err(dispatch::Error::Operation)
}

fn approved_write(
    registry: &mut OperationRegistry,
    authorizer: &mut Authorizer,
    principal: &VerifiedPrincipal,
) -> (OperationId, ApprovalSession) {
    approved_write_at(
        registry,
        authorizer,
        principal,
        Instant::now(),
        Duration::ZERO,
    )
}

fn approved_write_at(
    registry: &mut OperationRegistry,
    authorizer: &mut Authorizer,
    principal: &VerifiedPrincipal,
    created: Instant,
    proof_delay: Duration,
) -> (OperationId, ApprovalSession) {
    crate::owner::test_support::approval::write_at(
        registry,
        authorizer,
        principal,
        &crate::owner::test_support::vault::snapshot("github-write"),
        created,
        proof_delay,
    )
}

#[test]
fn timely_authentication_preserves_its_dispatch_window_after_the_pending_deadline() {
    let (mut authorizer, principal, mut registry, now) = fixture(1);
    let (id, _session) = approved_write_at(
        &mut registry,
        &mut authorizer,
        &principal,
        now - Duration::from_secs(119),
        Duration::from_secs(2),
    );
    ready(&mut registry, &authorizer, id, &principal).unwrap();

    assert!(
        registry
            .admit(
                id,
                &principal,
                &mut authorizer,
                Instant::now() + Duration::from_secs(2)
            )
            .is_ok()
    );
}

#[test]
fn authentication_must_be_fresh_within_the_original_wait_and_cannot_be_replaced() {
    for (offset, delay, allowed) in [
        (Duration::ZERO, Duration::ZERO, true),
        (Duration::ZERO, Duration::from_secs(30), false),
        (Duration::from_secs(120), Duration::ZERO, false),
        (Duration::from_secs(121), Duration::ZERO, false),
    ] {
        let (authorizer, principal, mut registry, now) = fixture(1);
        let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
        let id = registry
            .register(authorizer.authorize(&principal, request, now).unwrap(), now)
            .unwrap();
        let document = crate::owner::test_support::approval::review(
            registry.request(id, &principal).unwrap().clone(),
            None,
        );
        registry.bind_review(id, &principal, &document).unwrap();
        let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
        registry.begin_approval(id, &principal, &session).unwrap();
        let result =
            registry.authentication(id, &principal, now + offset, now + offset + delay, offset);
        assert_eq!(result.is_ok(), allowed);
        assert!(
            registry
                .authentication(
                    id,
                    &principal,
                    now + Duration::from_secs(120),
                    now + Duration::from_secs(120),
                    Duration::from_secs(120),
                )
                .is_err()
        );
    }
}

#[test]
fn an_unrelated_ui_session_cannot_cancel_or_retarget_an_operation() {
    let (mut authorizer, principal, mut registry, _) = fixture(1);
    let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);

    assert_eq!(
        registry.cancel_interactive(id, [9; 16]),
        CancellationResult::UnknownOperation
    );
    assert_eq!(registry.state(id), Some(OperationState::Preparing));
    assert_eq!(
        registry.cancel_interactive(id, [2; 16]),
        CancellationResult::Canceled
    );
    assert_eq!(
        registry.cancel_interactive(id, [2; 16]),
        CancellationResult::Canceled
    );
}

#[test]
fn a_ready_write_cannot_outlive_its_original_authentication_event() {
    let (mut authorizer, principal, mut registry, _) = fixture(1);
    let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);
    ready(&mut registry, &authorizer, id, &principal).unwrap();

    assert!(
        registry
            .admit(
                id,
                &principal,
                &mut authorizer,
                Instant::now() + Duration::from_secs(30)
            )
            .is_err()
    );
    assert_eq!(registry.state(id), Some(OperationState::Expired));
}

#[test]
fn ui_disconnection_cancels_its_write_and_preserves_independent_reads() {
    let (mut authorizer, principal, mut registry, now) = fixture(2);
    let (write, _session) = approved_write(&mut registry, &mut authorizer, &principal);
    let first = read(&mut registry, &authorizer, &principal, now);

    registry.cancel_interactive_session([2; 16]);

    assert_eq!(registry.state(write), Some(OperationState::Canceled));
    assert_eq!(registry.state(first), Some(OperationState::Preparing));
    ready(&mut registry, &authorizer, first, &principal).unwrap();
    assert!(
        registry
            .admit(first, &principal, &mut authorizer, now)
            .is_ok()
    );
    let second = read(&mut registry, &authorizer, &principal, now);
    ready(&mut registry, &authorizer, second, &principal).unwrap();
    assert!(
        registry
            .admit(second, &principal, &mut authorizer, now)
            .is_ok()
    );
}

#[test]
fn cancellation_and_admission_have_one_consistent_winner() {
    let (authorizer, principal, mut registry, now) = fixture(1);
    let id = read(&mut registry, &authorizer, &principal, now);
    ready(&mut registry, &authorizer, id, &principal).unwrap();
    let owner = Arc::new(Mutex::new((authorizer, registry)));
    let principal = Arc::new(principal);
    let barrier = Arc::new(Barrier::new(2));
    let executing_owner = Arc::clone(&owner);
    let executing_principal = Arc::clone(&principal);
    let executing_barrier = Arc::clone(&barrier);
    let admission = thread::spawn(move || {
        executing_barrier.wait();
        let mut owner = executing_owner.lock().unwrap();
        let (authorizer, registry) = &mut *owner;
        registry
            .admit(id, &executing_principal, authorizer, now)
            .is_ok()
    });
    barrier.wait();
    let cancellation = owner.lock().unwrap().1.cancel(id, &principal);

    assert!(matches!(
        (cancellation, admission.join().unwrap()),
        (CancellationResult::Canceled, false) | (CancellationResult::AlreadyAdmitted, true)
    ));
}

#[test]
fn cancellation_after_verified_proof_prevents_admission_and_remains_observable() {
    let (mut authorizer, principal, mut registry, _) = fixture(2);
    let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);
    ready(&mut registry, &authorizer, id, &principal).unwrap();

    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::Canceled
    );
    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::Canceled
    );
    assert!(
        registry
            .admit(id, &principal, &mut authorizer, Instant::now())
            .is_err()
    );
    assert_eq!(registry.state(id), Some(OperationState::Canceled));
}

#[test]
fn cancellation_during_preparation_does_not_spend_the_grant_budget() {
    let (mut authorizer, principal, mut registry, now) = fixture(1);
    let canceled = read(&mut registry, &authorizer, &principal, now);
    assert_eq!(
        registry.cancel(canceled, &principal),
        CancellationResult::Canceled
    );
    assert!(ready(&mut registry, &authorizer, canceled, &principal).is_err());
    let id = read(&mut registry, &authorizer, &principal, now);
    ready(&mut registry, &authorizer, id, &principal).unwrap();

    assert!(registry.admit(id, &principal, &mut authorizer, now).is_ok());
    assert!(
        authorizer
            .authorize(&principal, read_request(), now)
            .is_err()
    );
}

#[test]
fn admitted_operations_report_already_admitted_and_cannot_execute_twice() {
    let (mut authorizer, principal, mut registry, now) = fixture(1);
    let id = read(&mut registry, &authorizer, &principal, now);
    ready(&mut registry, &authorizer, id, &principal).unwrap();
    let admission = registry
        .admit(id, &principal, &mut authorizer, now)
        .unwrap();
    assert_eq!(admission.request().action(), request::Action::ReadIssue);

    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::AlreadyAdmitted
    );
    assert!(
        registry
            .admit(id, &principal, &mut authorizer, now)
            .is_err()
    );
    registry.finish(id, Completion::Uncertain).unwrap();
    assert_eq!(
        registry.cancel(id, &principal),
        CancellationResult::AlreadyAdmitted
    );
    assert!(
        authorizer
            .authorize(&principal, read_request(), now)
            .is_err()
    );
}

#[test]
fn wrong_owner_and_unknown_ids_do_not_report_cancellation() {
    let (authorizer, principal, mut registry, now) = fixture(1);
    let id = read(&mut registry, &authorizer, &principal, now);
    let other = VerifiedPrincipal::fixture(502, "11".repeat(20), [1; 16]);

    assert_eq!(
        registry.cancel(id, &other),
        CancellationResult::UnknownOperation
    );
    assert_eq!(
        registry.cancel(
            OperationId::parse("00000000000000000000000000000000").unwrap(),
            &principal
        ),
        CancellationResult::UnknownOperation
    );
    assert_eq!(registry.state(id), Some(OperationState::Preparing));
}

#[test]
fn final_admission_rechecks_revocation_and_expiry() {
    for changed in [false, true] {
        let (mut authorizer, principal, mut registry, now) = fixture(1);
        let id = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, id, &principal).unwrap();
        if changed {
            authorizer.revoke_read_grants().unwrap();
        }

        assert!(
            registry
                .admit(
                    id,
                    &principal,
                    &mut authorizer,
                    if changed {
                        now
                    } else {
                        now + Duration::from_secs(10)
                    }
                )
                .is_err()
        );
        assert!(matches!(
            registry.state(id),
            Some(OperationState::Revoked | OperationState::Expired)
        ));
    }
}

#[test]
fn two_concurrently_prepared_operations_cannot_spend_the_same_last_budget_unit() {
    let (authorizer, principal, mut registry, now) = fixture(1);
    let first = read(&mut registry, &authorizer, &principal, now);
    let second = read(&mut registry, &authorizer, &principal, now);
    ready(&mut registry, &authorizer, first, &principal).unwrap();
    ready(&mut registry, &authorizer, second, &principal).unwrap();
    let owner = Arc::new(Mutex::new((authorizer, registry)));
    let principal = Arc::new(principal);
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .map(|id| {
            let owner = Arc::clone(&owner);
            let principal = Arc::clone(&principal);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut owner = owner.lock().unwrap();
                let (authorizer, registry) = &mut *owner;
                registry.admit(id, &principal, authorizer, now).is_ok()
            })
        })
        .collect();

    assert_eq!(
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|allowed| *allowed)
            .count(),
        1
    );
}

#[test]
fn canceled_write_leaves_independent_read_grants_and_budgets_valid() {
    let (mut authorizer, principal, mut registry, now) = fixture(2);
    let (write, _session) = approved_write(&mut registry, &mut authorizer, &principal);
    assert_eq!(
        registry.cancel(write, &principal),
        CancellationResult::Canceled
    );

    for _ in 0..2 {
        let id = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, id, &principal).unwrap();
        assert!(registry.admit(id, &principal, &mut authorizer, now).is_ok());
        registry.finish(id, Completion::Completed).unwrap();
    }
}

#[test]
fn terminal_records_remain_bounded_until_the_originating_connection_ends() {
    let (authorizer, principal, mut registry, now) = fixture(1);
    for _ in 0..128 {
        let id = read(&mut registry, &authorizer, &principal, now);
        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::Canceled
        );
    }
    let allowed = authorizer
        .authorize(&principal, read_request(), now)
        .unwrap();
    assert!(matches!(
        registry.register(allowed, now),
        Err(OperationError::Capacity)
    ));
    registry.release_connection(&principal);
    assert!(
        registry
            .register(
                authorizer
                    .authorize(&principal, read_request(), now)
                    .unwrap(),
                now
            )
            .is_ok()
    );
}
