use super::super::OwnerState;
use super::{
    ChangeContext, Fault, Manager, ProviderGeneration, Result, ServicePaths, Shared, Source, now,
};
use crate::{
    owner::{
        protocol::{ControlError, Reply},
        provider_lifecycle::CacheIdentity,
        settings::Migration,
    },
    platform::macos::ipc,
};

struct Import {
    migration: Migration,
    generation: ProviderGeneration,
    epoch: u64,
    session: [u8; 16],
}

impl Import {
    fn capture(id: &str, peer: &ipc::PeerHandle, state: &mut OwnerState) -> Result<Self> {
        state.ensure_interactive()?;
        let session = state.administration.check(peer)?;
        let migration = state
            .administration
            .manager
            .as_ref()
            .and_then(Manager::migration)
            .filter(|migration| migration.source.id == id)
            .ok_or(ControlError::Denied)?
            .clone();
        Ok(Self {
            migration,
            generation: state.provider.generation(),
            epoch: state.administration.epoch,
            session,
        })
    }

    fn review(
        self,
        peer: &ipc::PeerHandle,
        state: &mut OwnerState,
        source: Option<Source>,
        identity: Option<CacheIdentity>,
    ) -> Result<Reply> {
        state.ensure_interactive()?;
        if state.administration.check(peer)? != self.session
            || state.administration.epoch != self.epoch
        {
            return Err(Fault::Canceled.into());
        }
        if state.pending.is_some()
            || state.administration.staging
            || state.administration.registering
        {
            return Err(ControlError::Busy.into());
        }
        if state.provider.generation() != self.generation {
            return Err(Fault::ProviderChanged.into());
        }
        let manager = state
            .administration
            .manager
            .as_mut()
            .ok_or(ControlError::Denied)?;
        let context = ChangeContext {
            generation: self.generation,
            source,
            identity,
            warm: None,
            provider_changed: self.migration.provider.is_some(),
            pin: self.migration.provider,
            lease: None,
        };
        let review = manager.prepare_import(
            &self.migration.source.id,
            peer.id().value(),
            self.session,
            now()?,
            context,
        )?;
        Ok(Reply::SettingsReview { review })
    }
}

pub(super) fn prepare(
    id: &str,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let import = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        Import::capture(id, peer, &mut state)?
    };
    let (source, identity) = match &import.migration.provider {
        Some(pin) => {
            let source = Source::capture(&pin.root(&paths.root))?;
            let identity = source.identity()?;
            if identity.binding != pin.binding
                || identity.scope != pin.scope
                || identity.device_key != pin.device_key
            {
                return Err(Fault::ProviderChanged.into());
            }
            (Some(source), Some(identity))
        }
        None => (None, None),
    };
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    import.review(peer, &mut state, source, identity)
}

#[cfg(test)]
mod tests {
    use super::super::{Error, tests::Harness};
    use super::*;
    use serde_json::json;

    #[test]
    fn a_failed_import_preparation_cannot_cancel_a_different_pending_review() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let candidate = harness.require_import();
        let pending = harness.call(
            json!({"kind":"prepareSettingsImport", "id":candidate["source"]["id"]}),
            None,
        );
        assert_eq!(pending["kind"], "settingsReview");
        let failed = harness.call(
            json!({"kind":"prepareSettingsImport", "id":"stale import"}),
            None,
        );
        assert_eq!(failed["kind"], "error");
        let state = harness.shared.0.lock().unwrap();
        let peer = &state.administration.session.as_ref().unwrap().peer;
        assert!(
            state
                .administration
                .manager
                .as_ref()
                .unwrap()
                .pending(pending["review"]["id"].as_str().unwrap(), peer.id().value())
        );
    }

    #[test]
    fn canceling_during_cache_inspection_cannot_create_a_late_import_review() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let candidate = harness.require_import();
        let (import, peer) = {
            let mut state = harness.shared.0.lock().unwrap();
            let peer = state.administration.session.as_ref().unwrap().peer.clone();
            (
                Import::capture(
                    candidate["source"]["id"].as_str().unwrap(),
                    &peer,
                    &mut state,
                )
                .unwrap(),
                peer,
            )
        };
        let pin = import.migration.provider.as_ref().unwrap();
        let source = Source::capture(&pin.root(&harness.paths.root)).unwrap();
        let identity = source.identity().unwrap();
        assert_eq!(
            harness.call(json!({"kind":"settingsCancel"}), None)["kind"],
            "canceled"
        );
        let mut state = harness.shared.0.lock().unwrap();
        assert!(matches!(
            import.review(&peer, &mut state, Some(source), Some(identity)),
            Err(Error::State(Fault::Canceled))
        ));
        assert!(state.administration.manager.as_ref().unwrap().idle());
        assert!(
            state
                .administration
                .manager
                .as_ref()
                .unwrap()
                .migration()
                .is_some()
        );
    }
}
