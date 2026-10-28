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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Import,
    Discard,
}

struct MigrationReview {
    action: Action,
    migration: Migration,
    generation: ProviderGeneration,
    epoch: u64,
    session: [u8; 16],
}

impl MigrationReview {
    fn capture(
        id: &str,
        action: Action,
        peer: &ipc::PeerHandle,
        state: &mut OwnerState,
    ) -> Result<Self> {
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
            action,
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
            provider_changed: self.action == Action::Discard || self.migration.provider.is_some(),
            pin: if self.action == Action::Import {
                self.migration.provider
            } else {
                None
            },
            lease: None,
        };
        let prepare = match self.action {
            Action::Import => Manager::prepare_import,
            Action::Discard => Manager::prepare_discard,
        };
        let review = prepare(
            manager,
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
    prepare_migration(id, Action::Import, peer, shared, paths)
}

pub(super) fn discard(
    id: &str,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    prepare_migration(id, Action::Discard, peer, shared, paths)
}

fn prepare_migration(
    id: &str,
    action: Action,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let import = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        MigrationReview::capture(id, action, peer, &mut state)?
    };
    let pin = if action == Action::Import {
        import.migration.provider.as_ref()
    } else {
        None
    };
    let (source, identity) = match pin {
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
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn discarding_legacy_settings_never_needs_or_deletes_the_old_cache() {
        for condition in ["valid", "missing", "corrupt"] {
            let harness = Harness::new();
            let review = harness.review();
            let challenge = harness.authenticate(&review);
            assert_eq!(
                harness.proof(&review, &challenge)["kind"],
                "settingsApplied"
            );
            let migration = harness.require_import();
            let pin: super::super::ProviderPin =
                serde_json::from_value(migration["provider"].clone()).unwrap();
            let cache = pin.root(&harness.paths.root).join("vault/vault.cache");
            match condition {
                "missing" => std::fs::remove_file(&cache).unwrap(),
                "corrupt" => std::fs::write(&cache, b"damaged encrypted cache").unwrap(),
                _ => {}
            }
            let retained = std::fs::read(&cache).ok();
            let prepared = harness.call(
                json!({"kind":"prepareSettingsDiscard", "id":migration["source"]["id"]}),
                None,
            );
            assert_eq!(
                prepared["kind"], "settingsReview",
                "{condition}: {prepared}"
            );
            let review = &prepared["review"];
            let document: serde_json::Value = serde_json::from_slice(
                &super::super::BASE64
                    .decode(review["document"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(document["migration"], migration["source"]);
            assert_eq!(
                document["proposed"]["settings"],
                json!({"github":null,"mutations":"requireApproval"})
            );
            assert!(document["proposed"]["provider"].is_null());
            let challenge = harness.authenticate(review);
            assert_eq!(harness.proof(review, &challenge)["kind"], "settingsApplied");
            assert_eq!(harness.proof(review, &challenge)["kind"], "error");
            let status = harness.call(json!({"kind":"settingsStatus"}), None);
            assert_eq!(status["settings"]["state"], "configured");
            assert_eq!(status["settings"]["revision"], 2);
            assert!(status["settings"]["migration"].is_null());
            assert!(status["settings"]["provider"].is_null());
            assert_eq!(std::fs::read(&cache).ok(), retained);
            let loaded = harness
                .paths
                .settings
                .as_ref()
                .unwrap()
                .load::<()>()
                .unwrap()
                .unwrap();
            assert!(loaded.migration().is_none());
            assert!(loaded.record().provider().is_none());
            assert!(loaded.policy().is_err());
            assert!(
                harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .provider
                    .snapshot()
                    .is_none()
            );
        }
    }

    #[test]
    fn canceling_a_discard_preserves_the_migration_and_does_not_enable_edits() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let migration = harness.require_import();
        assert_eq!(
            harness.call(json!({"kind":"prepareSettingsDiscard","id":"stale"}), None)["kind"],
            "error"
        );
        let prepared = harness.call(
            json!({"kind":"prepareSettingsDiscard","id":migration["source"]["id"]}),
            None,
        );
        assert_eq!(prepared["kind"], "settingsReview", "{prepared}");
        let challenge = harness.authenticate(&prepared["review"]);
        assert_eq!(
            harness.call(
                json!({"kind":"settingsCancel","id":prepared["review"]["id"]}),
                None
            )["kind"],
            "canceled"
        );
        assert_eq!(
            harness.proof(&prepared["review"], &challenge)["kind"],
            "error"
        );
        let status = harness.call(json!({"kind":"settingsStatus"}), None);
        assert_eq!(status["settings"]["migration"], migration);
        assert_eq!(harness.call(json!({"kind":"prepareSettings","revision":1,"settings":{"github":null,"mutations":"deny"},"provider":{"kind":"keep"}}), None)["kind"], "error");
    }

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
                MigrationReview::capture(
                    candidate["source"]["id"].as_str().unwrap(),
                    Action::Import,
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
