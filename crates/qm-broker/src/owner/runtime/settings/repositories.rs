use super::{ChangeContext, Error, Fault, Result, ServicePaths, Shared, Source, now};
use crate::{
    owner::{
        deadline::Deadline,
        persistence,
        protocol::{ControlError, Reply},
        settings::{Manager, ProviderChoice, RepositoryName, Revision, Settings},
    },
    platform::macos::ipc,
};
use qm_macos::{
    cache_store::{CacheStore, TimeMachineExclusion},
    presence_clock::MonotonicTimestamp,
};
use std::time::Duration;

fn manager<'a>(
    state: &'a mut super::super::OwnerState,
    id: &str,
    peer: &ipc::PeerHandle,
) -> Result<&'a mut Manager<ChangeContext>> {
    state.ensure_interactive()?;
    let generation = state.provider.generation();
    state.administration.check(peer)?;
    let manager = state
        .administration
        .manager
        .as_mut()
        .ok_or(ControlError::Denied)?;
    if manager.context(id, peer.id().value())?.generation != generation {
        return Err(Fault::ProviderChanged.into());
    }
    Ok(manager)
}

pub(super) fn cancel_matching(id: &str, peer: &ipc::PeerHandle, shared: &Shared) {
    if let Ok(mut state) = shared.0.lock()
        && state
            .administration
            .manager
            .as_ref()
            .is_some_and(|manager| manager.pending(id, peer.id().value()))
    {
        state.administration.cancel_changes();
    }
}

pub(super) fn needed(id: &str, peer: &ipc::PeerHandle, shared: &Shared) -> Result<bool> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    Ok(manager(&mut state, id, peer)?.lookup_count(id, peer.id().value())? != 0)
}

pub(super) fn prepare(
    revision: Revision,
    settings: Settings,
    provider: ProviderChoice,
    additions: Vec<RepositoryName>,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let reply = super::prepare(revision, settings, provider, peer, shared)?;
    if additions.is_empty() {
        return Ok(reply);
    }
    let Reply::SettingsReview { review } = reply else {
        return Err(ControlError::Unavailable.into());
    };
    let id = review.id;
    let result = (|| {
        let (review, pin) = {
            let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
            let manager = manager(&mut state, &id, peer)?;
            let review = manager.add_repositories(&id, peer.id().value(), additions)?;
            let pin = manager
                .context(&id, peer.id().value())?
                .pin
                .clone()
                .ok_or(ControlError::Denied)?;
            (review, pin)
        };
        let source = Source::capture(&pin.root(&paths.root))?;
        let identity = source.identity()?;
        if identity.binding != pin.binding
            || identity.scope != pin.scope
            || identity.device_key != pin.device_key
        {
            return Err(Fault::ProviderChanged.into());
        }
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        manager(&mut state, &id, peer)?.with_context(
            &id,
            peer.id().value(),
            |context| -> Result<()> {
                if context
                    .identity
                    .as_ref()
                    .is_some_and(|expected| expected != &identity)
                {
                    return Err(Fault::ProviderChanged.into());
                }
                context.source = Some(source);
                context.identity = Some(identity);
                Ok(())
            },
        )??;
        Ok(Reply::SettingsReview { review })
    })();
    if result.is_err() {
        cancel_matching(&id, peer, shared);
    }
    result
}

fn cache_guard(
    id: &str,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<CacheStore<TimeMachineExclusion>> {
    let (pin, expected) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        let context = manager(&mut state, id, peer)?.context(id, peer.id().value())?;
        (
            context.pin.clone().ok_or(ControlError::Denied)?,
            context.identity.clone().ok_or(ControlError::Denied)?,
        )
    };
    let cache = persistence::store(&pin.root(&paths.root))?.transaction()?;
    let current = Source::capture_store(&cache)?.identity()?;
    if current != expected
        || current.binding != pin.binding
        || current.scope != pin.scope
        || current.device_key != pin.device_key
    {
        return Err(Fault::ProviderChanged.into());
    }
    Ok(cache)
}

pub(super) fn resolve(
    id: &str,
    authenticated: MonotonicTimestamp,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let (count, connector) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        let count = manager(&mut state, id, peer)?.lookup_count(id, peer.id().value())?;
        (count, state.github.clone())
    };
    let deadline = Deadline::at(authenticated, Duration::from_secs(30))?;
    for _ in 0..count {
        let request = {
            let _cache = cache_guard(id, peer, shared, paths)?;
            let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
            let manager = manager(&mut state, id, peer)?;
            let snapshot = manager
                .context(id, peer.id().value())?
                .warm
                .as_ref()
                .ok_or(Fault::VaultLocked)?;
            manager.prepare_lookup(id, peer.id().value(), snapshot, now()?)?
        };
        let prepared = connector.connect(deadline)?.stage_lookup(request)?;
        let in_flight = {
            let _cache = cache_guard(id, peer, shared, paths)?;
            let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
            let manager = manager(&mut state, id, peer)?;
            prepared.validate()?;
            let admission = manager.admit_lookup(prepared.request(), now()?)?;
            prepared.handoff(admission)?
        };
        let result = in_flight
            .response()
            .map_err(|_| Error::State(Fault::RepositoryMismatch))?;
        let _cache = cache_guard(id, peer, shared, paths)?;
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        manager(&mut state, id, peer)?.accept_lookup(result, now()?)?;
    }
    let _cache = cache_guard(id, peer, shared, paths)?;
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    let authorization =
        manager(&mut state, id, peer)?.resolved_challenge(id, peer.id().value(), now()?)?;
    Ok(Reply::SettingsChallenge { authorization })
}

#[cfg(test)]
mod tests {
    use super::super::tests::Harness;
    use super::*;
    use crate::{
        owner::{github::https::Connector, test_support::github, vault},
        platform::HostSessionEvent,
    };
    use objc2_local_authentication::LAContext;
    use serde_json::{Value, json};
    use std::{thread, time::Instant};

    fn rules() -> Value {
        json!({"github":{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true},"mutations":"requireApproval"})
    }

    fn setup() -> Harness {
        let harness = Harness::new();
        let review = harness.review_with_settings(rules());
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        harness
    }

    fn review(harness: &Harness) -> Value {
        let reply = harness.call(json!({"kind":"prepareSettings","revision":1,"settings":rules(),"provider":{"kind":"keep"},"additions":[{"owner":"example","name":"one"}]}), None);
        assert_eq!(reply["kind"], "settingsReview", "{reply}");
        reply["review"].clone()
    }

    fn fixture_authentication(
        harness: &Harness,
        review: &Value,
    ) -> (ipc::PeerHandle, MonotonicTimestamp) {
        let authenticated = now().unwrap();
        let mut state = harness.shared.0.lock().unwrap();
        let peer = state.administration.session.as_ref().unwrap().peer.clone();
        let manager = manager(&mut state, review["id"].as_str().unwrap(), &peer).unwrap();
        manager
            .authenticate(
                review["id"].as_str().unwrap(),
                peer.id().value(),
                authenticated,
                authenticated,
            )
            .unwrap();
        manager
            .with_context(
                review["id"].as_str().unwrap(),
                peer.id().value(),
                |context| {
                    context.warm = Some(vault::fixture::open(context.source.take().unwrap()));
                },
            )
            .unwrap();
        (peer, authenticated)
    }

    #[test]
    fn native_named_saves_require_protected_context_use_even_with_a_warm_snapshot() {
        for cold in [false, true] {
            let harness = setup();
            if cold {
                harness.shared.0.lock().unwrap().provider.lock().unwrap();
            }
            let (address, server) = github::serve(vec![github::repository(456)]);
            harness.shared.0.lock().unwrap().github = Connector::fixture(address);
            let review = review(&harness);
            let context = unsafe { LAContext::new() };
            unsafe {
                context.setInteractionNotAllowed(true);
            }
            let reply = harness.call(json!({"kind":"settingsPresence","id":review["id"],"authenticated":u64::from(now().unwrap())}), Some(&context));
            assert_eq!(reply["kind"], "error", "{reply}");
            assert!(server.join().unwrap().is_empty());
            assert_eq!(
                harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["revision"],
                1
            );
        }
    }

    #[test]
    fn metadata_transport_completes_the_same_settings_transaction_before_its_single_signature() {
        let harness = setup();
        let (address, server) = github::serve(vec![github::repository(456)]);
        harness.shared.0.lock().unwrap().github = Connector::fixture(address);
        let review = review(&harness);
        let (peer, authenticated) = fixture_authentication(&harness, &review);
        let Reply::SettingsChallenge { authorization } = resolve(
            review["id"].as_str().unwrap(),
            authenticated,
            &peer,
            &harness.shared,
            &harness.paths,
        )
        .unwrap() else {
            panic!("missing challenge");
        };
        let challenge = serde_json::to_value(authorization).unwrap();
        assert_eq!(challenge["review"]["id"], review["id"]);
        assert_eq!(challenge["authenticated"], u64::from(authenticated));
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["revision"],
            1
        );
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let status = harness.call(json!({"kind":"settingsStatus"}), None);
        assert_eq!(
            status["settings"]["settings"]["github"]["repositories"][0]["id"],
            456
        );
        assert_eq!(harness.proof(&review, &challenge)["kind"], "error");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("GET /repos/example/one HTTP/1.1\r\nHost: api.github.com\r\n")
        );
    }

    #[test]
    fn canceled_or_changed_authority_during_metadata_io_cannot_produce_a_save_challenge() {
        for event in ["cancel", "vaultLock", "screenLock", "cache"] {
            let harness = setup();
            let (reply, entered, release) = github::gated(github::repository(456));
            let (address, server) = github::serve(vec![reply]);
            harness.shared.0.lock().unwrap().github = Connector::fixture(address);
            let review = review(&harness);
            let (peer, authenticated) = fixture_authentication(&harness, &review);
            let shared = harness.shared.clone();
            let paths = harness.paths.clone();
            let id = review["id"].as_str().unwrap().to_owned();
            let pending =
                thread::spawn(move || resolve(&id, authenticated, &peer, &shared, &paths));
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            let started = Instant::now();
            match event {
                "cancel" => assert_eq!(
                    harness.call(json!({"kind":"settingsCancel","id":review["id"]}), None)["kind"],
                    "canceled"
                ),
                "vaultLock" => assert_eq!(
                    harness.call(json!({"kind":"vaultLock"}), None)["kind"],
                    "vaultStatus"
                ),
                "cache" => std::fs::write(
                    harness
                        .paths
                        .root
                        .join("enrollments")
                        .join("a".repeat(32))
                        .join("vault/vault.cache"),
                    b"changed",
                )
                .unwrap(),
                _ => harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .host_events
                    .record(HostSessionEvent::ScreenLock),
            }
            assert!(started.elapsed() < Duration::from_secs(1));
            release.send(()).unwrap();
            assert!(pending.join().unwrap().is_err(), "{event}");
            assert_eq!(
                harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["revision"],
                1
            );
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn metadata_redirects_and_authentication_failures_leave_approved_settings_unchanged() {
        for reply in [
            github::redirect("https://api.github.com/repos/another/one"),
            github::unauthorized(),
        ] {
            let harness = setup();
            let (address, server) = github::serve(vec![reply]);
            harness.shared.0.lock().unwrap().github = Connector::fixture(address);
            let review = review(&harness);
            let (peer, authenticated) = fixture_authentication(&harness, &review);
            assert!(
                resolve(
                    review["id"].as_str().unwrap(),
                    authenticated,
                    &peer,
                    &harness.shared,
                    &harness.paths
                )
                .is_err()
            );
            assert_eq!(
                harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["revision"],
                1
            );
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }
}
