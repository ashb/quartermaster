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

#[derive(Default)]
pub(super) struct ProviderState {
    generation: ProviderGeneration,
    next_id: u64,
    active: Option<u64>,
    active_canceled: bool,
    snapshot: Option<Arc<VaultSnapshot>>,
    identity: Option<CacheIdentity>,
}

impl ProviderState {
    pub(super) fn snapshot(&self) -> Option<&VaultSnapshot> {
        self.snapshot.as_deref()
    }

    pub(super) fn snapshot_for(&self, identity: &CacheIdentity) -> Result<&VaultSnapshot, Error> {
        if self.identity.as_ref() != Some(identity) {
            return Err(Error::Changed);
        }
        self.snapshot().ok_or(Error::Locked)
    }

    pub(super) fn generation(&self) -> ProviderGeneration {
        self.generation
    }

    pub(super) fn cancel_pending(&mut self) {
        self.active_canceled = self.active.is_some();
    }

    pub(super) fn lock(&mut self) -> Result<(), Error> {
        self.generation = self.next_generation()?;
        self.snapshot = None;
        self.identity = None;
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
        self.active = Some(self.next_id);
        self.active_canceled = false;
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
        if self.identity.as_ref() != Some(identity) {
            return Err(Error::Changed);
        }
        let snapshot = Arc::clone(self.snapshot.as_ref().ok_or(Error::Locked)?);
        let operation = self.reserve(Work::Refresh(identity.clone()), identity.revision)?;
        Ok((operation, snapshot))
    }

    pub(super) fn check(
        &self,
        operation: &ProviderOperation,
        revision: PersistedRevision,
    ) -> Result<(), Error> {
        if self.active != Some(operation.id)
            || self.active_canceled
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
        if self.active == Some(operation.id) {
            self.active = None;
            self.active_canceled = false;
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
        self.snapshot = Some(Arc::new(snapshot));
        self.identity = Some(current.clone());
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
        self.state.snapshot = self.snapshot.take().map(Arc::new);
        self.state.identity = Some(identity);
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
#[path = "../../tests/unit/provider_lifecycle.rs"]
mod tests;
