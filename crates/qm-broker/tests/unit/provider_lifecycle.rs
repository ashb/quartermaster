use super::*;
use crate::owner::test_support::vault::{snapshot, snapshot_at};

fn identity(snapshot: &qm_providers::VaultSnapshot) -> CacheIdentity {
    CacheIdentity {
        binding: snapshot.binding().clone(),
        scope: "0123456789abcdef0123456789abcdef".into(),
        device_key: [7; 32],
        checkpoint: snapshot.checkpoint(),
        synchronized_at: snapshot.synchronized_at(),
        revision: PersistedRevision([8; 32]),
    }
}

fn unlocked() -> (ProviderState, CacheIdentity) {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let ticket = state.begin_unlock(identity.clone()).unwrap();
    state.finish_unlock(ticket, &identity, snapshot).unwrap();
    (state, identity)
}

#[test]
fn canceling_pending_provider_work_preserves_the_warm_snapshot_and_rejects_late_completion() {
    let (mut state, identity) = unlocked();
    let generation = state.generation();
    let (operation, _) = state.begin_refresh(&identity).unwrap();
    state.cancel_pending();
    assert_eq!(state.generation(), generation);
    assert!(state.snapshot_for(&identity).is_ok());
    assert!(matches!(
        state.check(&operation, identity.revision),
        Err(Error::Superseded)
    ));
    assert!(matches!(state.begin_refresh(&identity), Err(Error::Busy)));
    state.release(&operation);
    assert!(state.begin_refresh(&identity).is_ok());
}

#[test]
fn canceling_pending_unlock_cannot_install_a_cache_after_the_host_locks() {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let operation = state.begin_unlock(identity.clone()).unwrap();
    state.cancel_pending();
    assert!(matches!(
        state.finish_unlock(operation, &identity, snapshot),
        Err(Error::Superseded)
    ));
    assert!(state.snapshot().is_none());
}

#[test]
fn provider_lifecycle_rejects_an_unlock_that_finishes_after_an_explicit_lock() {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let ticket = state.begin_unlock(identity.clone()).unwrap();

    state.lock().unwrap();
    let result = state.finish_unlock(ticket, &identity, snapshot);

    assert!(matches!(result, Err(Error::Superseded)));
    assert!(state.snapshot().is_none());
    assert!(state.begin_unlock(identity).is_ok());
}

#[test]
fn provider_lifecycle_does_not_allow_a_second_provider_worker_to_overlap() {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let ticket = state.begin_unlock(identity.clone()).unwrap();

    state.lock().unwrap();

    assert!(matches!(
        state.begin_unlock(identity.clone()),
        Err(Error::Busy)
    ));
    assert!(state.finish_unlock(ticket, &identity, snapshot).is_err());
    assert!(state.begin_unlock(identity).is_ok());
}

#[test]
fn provider_lifecycle_rejects_a_changed_key_account_checkpoint_or_file_revision() {
    for case in 0..5 {
        let snapshot = snapshot("github-write");
        let original = identity(&snapshot);
        let mut changed = original.clone();
        match case {
            0 => changed.device_key[0] ^= 1,
            1 => changed.scope = "fedcba9876543210fedcba9876543210".into(),
            2 => {
                changed.binding = snapshot_at(
                    "github-write",
                    "33333333-3333-4333-8333-333333333333",
                    [3; 16],
                    original.synchronized_at,
                )
                .binding()
                .clone()
            }
            3 => changed.checkpoint[0] ^= 1,
            4 => changed.revision.0[0] ^= 1,
            _ => unreachable!(),
        }
        let mut state = ProviderState::default();
        let ticket = state.begin_unlock(original).unwrap();

        assert!(
            state.finish_unlock(ticket, &changed, snapshot).is_err(),
            "case {case}"
        );
        assert!(state.snapshot().is_none());
    }
}

#[test]
fn provider_lifecycle_rejects_an_older_refresh_without_replacing_the_current_snapshot() {
    let (mut state, identity) = unlocked();
    let (ticket, _source) = state.begin_refresh(&identity).unwrap();
    let older = snapshot_at(
        "github-write",
        "22222222-2222-4222-8222-222222222222",
        [9; 16],
        identity.synchronized_at - std::time::Duration::from_secs(1),
    );

    assert!(matches!(
        state.prepare_update(ticket, identity.revision, older),
        Err(Error::Stale)
    ));
    assert_eq!(state.snapshot().unwrap().checkpoint(), [3; 16]);
    assert_eq!(
        state.snapshot().unwrap().synchronized_at(),
        crate::owner::test_support::wall(1_792_483_200)
    );
}

#[test]
fn provider_lifecycle_rejects_refresh_completion_after_lock_without_installation() {
    let (mut state, identity) = unlocked();
    let (ticket, _source) = state.begin_refresh(&identity).unwrap();
    let refreshed = snapshot_at(
        "github-write",
        "22222222-2222-4222-8222-222222222222",
        [9; 16],
        identity.synchronized_at + std::time::Duration::from_secs(1),
    );
    state.lock().unwrap();

    assert!(matches!(
        state.prepare_update(ticket, identity.revision, refreshed),
        Err(Error::Superseded)
    ));
    assert!(state.snapshot().is_none());
}

#[test]
fn provider_lifecycle_refresh_updates_the_credential_generation_only_after_publication() {
    let (mut state, original) = unlocked();
    let generation = state.generation();
    let (ticket, _source) = state.begin_refresh(&original).unwrap();
    let refreshed = snapshot_at(
        "github-write",
        "22222222-2222-4222-8222-222222222222",
        [9; 16],
        original.synchronized_at + std::time::Duration::from_secs(1),
    );
    let mut committed = identity(&refreshed);
    committed.revision = PersistedRevision([9; 32]);

    state
        .prepare_update(ticket, original.revision, refreshed)
        .unwrap()
        .install(committed.clone())
        .unwrap();

    assert_ne!(state.generation(), generation);
    assert_eq!(state.snapshot().unwrap().checkpoint(), [9; 16]);
    assert!(state.begin_refresh(&original).is_err());
    assert!(state.begin_refresh(&committed).is_ok());
}

#[test]
fn provider_lifecycle_dropping_a_failed_update_keeps_the_prior_snapshot_usable() {
    let (mut state, identity) = unlocked();
    let generation = state.generation();
    let (ticket, _source) = state.begin_refresh(&identity).unwrap();
    let refreshed = snapshot_at(
        "github-write",
        "22222222-2222-4222-8222-222222222222",
        [9; 16],
        identity.synchronized_at + std::time::Duration::from_secs(1),
    );

    drop(
        state
            .prepare_update(ticket, identity.revision, refreshed)
            .unwrap(),
    );

    assert_eq!(state.generation(), generation);
    assert_eq!(state.snapshot().unwrap().checkpoint(), [3; 16]);
    assert!(state.begin_refresh(&identity).is_ok());
}

#[test]
fn provider_lifecycle_discard_invalidates_a_pending_unlock_even_when_the_worker_is_busy() {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let pending = state.begin_unlock(identity.clone()).unwrap();

    assert!(matches!(
        state.begin_discard(identity.revision),
        Err(Error::Busy)
    ));
    assert!(matches!(
        state.finish_unlock(pending, &identity, snapshot),
        Err(Error::Superseded)
    ));
    assert!(state.snapshot().is_none());
    assert!(state.begin_discard(identity.revision).is_ok());
}

#[test]
fn provider_lifecycle_account_replacement_invalidates_a_pending_unlock() {
    let snapshot = snapshot("github-write");
    let identity = identity(&snapshot);
    let mut state = ProviderState::default();
    let pending = state.begin_unlock(identity.clone()).unwrap();

    assert!(matches!(
        state.begin_login(None, time::OffsetDateTime::UNIX_EPOCH, identity.revision),
        Err(Error::Busy)
    ));
    assert!(state.finish_unlock(pending, &identity, snapshot).is_err());
    assert!(state.snapshot().is_none());
}

#[test]
fn provider_lifecycle_login_publishes_only_the_frozen_existing_binding() {
    let (mut state, source) = unlocked();
    let ticket = state
        .begin_login(
            Some(source.binding.clone()),
            source.synchronized_at,
            source.revision,
        )
        .unwrap();
    let changed = snapshot_at(
        "github-write",
        "33333333-3333-4333-8333-333333333333",
        [9; 16],
        source.synchronized_at + std::time::Duration::from_secs(1),
    );

    assert!(matches!(
        state.prepare_update(ticket, source.revision, changed),
        Err(Error::Changed)
    ));
    assert!(state.snapshot().is_none());
}
