use crate::owner::policy::{AuthorizationError, Policy};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

type Decoded = Result<Policy, AuthorizationError>;

#[derive(Default)]
pub(super) struct PolicySource {
    state: Mutex<SourceState>,
    current: Arc<AtomicU64>,
}

struct SourceState {
    fingerprint: Option<Result<[u8; 32], AuthorizationError>>,
    approved: Decoded,
    provider: Option<crate::owner::settings::ProviderPin>,
}

impl Default for SourceState {
    fn default() -> Self {
        Self {
            fingerprint: None,
            approved: Err(AuthorizationError::InvalidPolicy),
            provider: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct Stamp {
    current: Arc<AtomicU64>,
    epoch: u64,
}

impl Stamp {
    pub(super) fn same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.current, &other.current) && self.epoch == other.epoch
    }
}

pub(super) struct Observation {
    stamp: Stamp,
    decoded: Decoded,
}

impl Observation {
    pub(super) fn current(&self) -> Result<(&Stamp, Decoded), AuthorizationError> {
        if self.stamp.current.load(Ordering::Acquire) != self.stamp.epoch {
            return Err(AuthorizationError::PolicyChanged);
        }
        Ok((&self.stamp, self.decoded.clone()))
    }
}

impl PolicySource {
    pub(super) fn snapshot(&self) -> Result<Observation, AuthorizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorizationError::InvalidPolicy)?;
        let decoded = state.approved.clone();
        self.observe(&mut state, decoded)
    }

    pub(super) fn install<C>(
        &self,
        manager: &crate::owner::settings::Manager<C>,
    ) -> Result<(), AuthorizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorizationError::InvalidPolicy)?;
        state.approved = manager.policy();
        state.provider = manager.record().provider().cloned();
        let decoded = state.approved.clone();
        self.observe(&mut state, decoded)?;
        Ok(())
    }

    pub(super) fn suspend(&self) -> Result<(), AuthorizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorizationError::InvalidPolicy)?;
        state.approved = Err(AuthorizationError::InvalidPolicy);
        let decoded = state.approved.clone();
        self.observe(&mut state, decoded)?;
        Ok(())
    }

    pub(super) fn provider(
        &self,
    ) -> Result<Option<crate::owner::settings::ProviderPin>, AuthorizationError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| AuthorizationError::InvalidPolicy)?
            .provider
            .clone())
    }

    #[cfg(test)]
    pub(super) fn fixture(policy: Policy) -> Self {
        Self {
            state: Mutex::new(SourceState {
                approved: Ok(policy),
                ..SourceState::default()
            }),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn set_fixture(&self, policy: Policy) {
        let mut state = self.state.lock().unwrap();
        state.approved = Ok(policy);
        let decoded = state.approved.clone();
        self.observe(&mut state, decoded).unwrap();
    }

    #[cfg(test)]
    pub(super) fn read(
        &self,
        load: impl FnOnce() -> Decoded,
    ) -> Result<Observation, AuthorizationError> {
        let mut state = self.state.lock().map_err(|_| {
            self.current.store(u64::MAX, Ordering::Release);
            AuthorizationError::InvalidPolicy
        })?;
        let decoded = load();
        self.observe(&mut state, decoded)
    }

    fn observe(
        &self,
        state: &mut SourceState,
        decoded: Decoded,
    ) -> Result<Observation, AuthorizationError> {
        let fingerprint = decoded.as_ref().map(Policy::digest).map_err(Clone::clone);
        let mut epoch = self.current.load(Ordering::Acquire);
        if state.fingerprint.as_ref() != Some(&fingerprint) {
            epoch = epoch
                .checked_add(1)
                .filter(|epoch| *epoch != u64::MAX)
                .ok_or_else(|| {
                    self.current.store(u64::MAX, Ordering::Release);
                    AuthorizationError::InvalidPolicy
                })?;
            state.fingerprint = Some(fingerprint);
            self.current.store(epoch, Ordering::Release);
        }
        if epoch == u64::MAX {
            return Err(AuthorizationError::InvalidPolicy);
        }
        Ok(Observation {
            stamp: Stamp {
                current: Arc::clone(&self.current),
                epoch,
            },
            decoded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_observations_cannot_restore_previous_policy() {
        let source = PolicySource::default();
        let old = source.read(|| Ok(Policy::default())).unwrap();
        let new = source
            .read(|| Err(AuthorizationError::InvalidPolicy))
            .unwrap();
        assert!(matches!(
            old.current(),
            Err(AuthorizationError::PolicyChanged)
        ));
        assert!(matches!(
            new.current().unwrap().1,
            Err(AuthorizationError::InvalidPolicy)
        ));
    }

    #[test]
    fn unchanged_reads_share_an_epoch_but_change_and_reversion_do_not() {
        let source = PolicySource::default();
        let first = source.read(|| Ok(Policy::default())).unwrap();
        let same = source.read(|| Ok(Policy::default())).unwrap();
        assert!(first.stamp.same_as(&same.stamp));
        source
            .read(|| Err(AuthorizationError::InvalidPolicy))
            .unwrap();
        let reverted = source.read(|| Ok(Policy::default())).unwrap();
        assert!(!first.stamp.same_as(&reverted.stamp));
        assert!(first.current().is_err());
        assert!(reverted.current().is_ok());
    }

    #[test]
    fn poisoned_and_exhausted_sources_stay_unavailable() {
        let source = PolicySource::default();
        let observation = source.read(|| Ok(Policy::default())).unwrap();
        let _ = std::panic::catch_unwind(|| {
            let _guard = source.state.lock().unwrap();
            panic!("poison the reader");
        });
        assert!(source.read(|| Ok(Policy::default())).is_err());
        assert!(observation.current().is_err());
        let exhausted = PolicySource::default();
        exhausted.current.store(u64::MAX - 1, Ordering::Release);
        assert!(exhausted.read(|| Ok(Policy::default())).is_err());
        assert!(exhausted.read(|| Ok(Policy::default())).is_err());
    }
}
