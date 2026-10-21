#![forbid(unsafe_code)]

use qm_providers::{ProviderBinding, VaultSnapshot};
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ProviderGeneration(u64);

impl ProviderGeneration {
    pub(super) fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PersistedRevision(pub(super) [u8; 32]);

#[derive(Clone, PartialEq, Eq)]
pub(super) struct CacheIdentity {
    pub(super) binding: ProviderBinding,
    pub(super) scope: String,
    pub(super) device_key: [u8; 32],
    pub(super) checkpoint: [u8; 16],
    pub(super) synchronized_at: OffsetDateTime,
    pub(super) revision: PersistedRevision,
}

impl CacheIdentity {
    fn matches(&self, snapshot: &VaultSnapshot) -> bool {
        &self.binding == snapshot.binding()
            && self.checkpoint == snapshot.checkpoint()
            && self.synchronized_at == snapshot.synchronized_at()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Superseded,
    Changed,
    Locked,
    Stale,
    Exhausted,
}

enum Work {
    Unlock(CacheIdentity),
    Refresh(CacheIdentity),
    Login {
        binding: Option<ProviderBinding>,
        minimum_sync: OffsetDateTime,
    },
    Discard,
}

pub(super) struct ProviderOperation {
    id: u64,
    generation: ProviderGeneration,
    revision: PersistedRevision,
    work: Work,
}

struct UnlockedSnapshot {
    snapshot: Arc<VaultSnapshot>,
    identity: CacheIdentity,
}

struct ActiveWork {
    id: u64,
    canceled: bool,
}

#[derive(Default)]
pub(super) struct ProviderState {
    generation: ProviderGeneration,
    next_id: u64,
    active: Option<ActiveWork>,
    unlocked: Option<UnlockedSnapshot>,
}

impl ProviderState {
    pub(super) fn snapshot(&self) -> Option<&VaultSnapshot> {
        self.unlocked
            .as_ref()
            .map(|unlocked| unlocked.snapshot.as_ref())
    }

    pub(super) fn snapshot_for(&self, identity: &CacheIdentity) -> Result<&VaultSnapshot, Error> {
        let unlocked = self.unlocked.as_ref().ok_or(Error::Locked)?;
        if &unlocked.identity != identity {
            return Err(Error::Changed);
        }
        Ok(&unlocked.snapshot)
    }

    pub(super) fn generation(&self) -> ProviderGeneration {
        self.generation
    }

    pub(super) fn cancel_pending(&mut self) {
        if let Some(active) = &mut self.active {
            active.canceled = true;
        }
    }

    pub(super) fn lock(&mut self) -> Result<(), Error> {
        self.generation = self.next_generation()?;
        self.unlocked = None;
        Ok(())
    }

    fn next_generation(&self) -> Result<ProviderGeneration, Error> {
        self.generation
            .0
            .checked_add(1)
            .map(ProviderGeneration)
            .ok_or(Error::Exhausted)
    }

    fn reserve(
        &mut self,
        work: Work,
        revision: PersistedRevision,
    ) -> Result<ProviderOperation, Error> {
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        self.next_id = self.next_id.checked_add(1).ok_or(Error::Exhausted)?;
        self.active = Some(ActiveWork {
            id: self.next_id,
            canceled: false,
        });
        Ok(ProviderOperation {
            id: self.next_id,
            generation: self.generation,
            revision,
            work,
        })
    }

    pub(super) fn begin_unlock(
        &mut self,
        identity: CacheIdentity,
    ) -> Result<ProviderOperation, Error> {
        self.reserve(Work::Unlock(identity.clone()), identity.revision)
    }

    pub(super) fn begin_login(
        &mut self,
        binding: Option<ProviderBinding>,
        minimum_sync: OffsetDateTime,
        revision: PersistedRevision,
    ) -> Result<ProviderOperation, Error> {
        self.lock()?;
        self.reserve(
            Work::Login {
                binding,
                minimum_sync,
            },
            revision,
        )
    }

    pub(super) fn begin_discard(
        &mut self,
        revision: PersistedRevision,
    ) -> Result<ProviderOperation, Error> {
        self.lock()?;
        self.reserve(Work::Discard, revision)
    }

    pub(super) fn revise_source(
        &self,
        operation: &mut ProviderOperation,
        revision: PersistedRevision,
    ) -> Result<(), Error> {
        self.check(operation, operation.revision)?;
        operation.revision = revision;
        Ok(())
    }

    pub(super) fn check_discard(
        &self,
        operation: &ProviderOperation,
        revision: PersistedRevision,
    ) -> Result<(), Error> {
        self.check(operation, revision)?;
        if !matches!(operation.work, Work::Discard) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    pub(super) fn begin_refresh(
        &mut self,
        identity: &CacheIdentity,
    ) -> Result<(ProviderOperation, Arc<VaultSnapshot>), Error> {
        let unlocked = self.unlocked.as_ref().ok_or(Error::Locked)?;
        if &unlocked.identity != identity {
            return Err(Error::Changed);
        }
        let snapshot = Arc::clone(&unlocked.snapshot);
        let operation = self.reserve(Work::Refresh(identity.clone()), identity.revision)?;
        Ok((operation, snapshot))
    }

    pub(super) fn check(
        &self,
        operation: &ProviderOperation,
        revision: PersistedRevision,
    ) -> Result<(), Error> {
        if self
            .active
            .as_ref()
            .is_none_or(|active| active.id != operation.id || active.canceled)
            || operation.generation != self.generation
        {
            return Err(Error::Superseded);
        }
        if operation.revision != revision {
            return Err(Error::Changed);
        }
        Ok(())
    }

    pub(super) fn release(&mut self, operation: &ProviderOperation) {
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.id == operation.id)
        {
            self.active = None;
        }
    }

    pub(super) fn finish_unlock(
        &mut self,
        operation: ProviderOperation,
        current: &CacheIdentity,
        snapshot: VaultSnapshot,
    ) -> Result<(), Error> {
        let result =
            self.check(&operation, current.revision)
                .and_then(|()| match &operation.work {
                    Work::Unlock(expected)
                        if expected == current && expected.matches(&snapshot) =>
                    {
                        Ok(())
                    }
                    _ => Err(Error::Changed),
                });
        self.release(&operation);
        result?;
        self.unlocked = Some(UnlockedSnapshot {
            snapshot: Arc::new(snapshot),
            identity: current.clone(),
        });
        Ok(())
    }

    pub(super) fn prepare_update(
        &mut self,
        operation: ProviderOperation,
        current: PersistedRevision,
        snapshot: VaultSnapshot,
    ) -> Result<Update<'_>, Error> {
        let validation = self.check(&operation, current).and_then(|()| {
            let (binding, minimum_sync) = match &operation.work {
                Work::Refresh(expected) => (Some(&expected.binding), expected.synchronized_at),
                Work::Login {
                    binding,
                    minimum_sync,
                } => (binding.as_ref(), *minimum_sync),
                _ => return Err(Error::Changed),
            };
            if binding.is_some_and(|binding| binding != snapshot.binding()) {
                return Err(Error::Changed);
            }
            if snapshot.synchronized_at() < minimum_sync {
                return Err(Error::Stale);
            }
            self.next_generation()
        });
        let generation = match validation {
            Ok(generation) => generation,
            Err(error) => {
                self.release(&operation);
                return Err(error);
            }
        };
        Ok(Update {
            state: self,
            operation,
            snapshot: Some(snapshot),
            generation,
        })
    }
}

pub(super) struct Update<'a> {
    state: &'a mut ProviderState,
    operation: ProviderOperation,
    snapshot: Option<VaultSnapshot>,
    generation: ProviderGeneration,
}

impl Update<'_> {
    pub(super) fn install(mut self, identity: CacheIdentity) -> Result<(), Error> {
        if let Work::Refresh(original) = &self.operation.work
            && (identity.binding != original.binding
                || identity.scope != original.scope
                || identity.device_key != original.device_key)
        {
            return Err(Error::Changed);
        }
        if !identity.matches(self.snapshot.as_ref().unwrap()) {
            return Err(Error::Changed);
        }
        self.state.unlocked = Some(UnlockedSnapshot {
            snapshot: Arc::new(self.snapshot.take().unwrap()),
            identity,
        });
        self.state.generation = self.generation;
        Ok(())
    }
}

impl Drop for Update<'_> {
    fn drop(&mut self) {
        self.state.release(&self.operation);
    }
}

#[cfg(test)]
mod tests {
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
}
