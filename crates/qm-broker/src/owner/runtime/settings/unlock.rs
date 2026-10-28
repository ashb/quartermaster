use super::super::OwnerState;
use super::{
    BASE64, Engine, Fault, ProviderGeneration, ProviderPin, Result, Revision, ServicePaths, Shared,
    Source, now,
};
use crate::{
    owner::{
        protocol::{ControlError, Reply, VaultUnlockReview},
        provider_lifecycle::{CacheIdentity, ProviderOperation},
    },
    platform::macos::ipc,
};
use qm_macos::{cache_key::NativeAuthenticationContext, presence_clock::MonotonicTimestamp};
use qm_providers::VaultSnapshot;
use std::{mem, path::PathBuf, time::Duration};

const REVIEW_LIFETIME: Duration = Duration::from_secs(120);
const AUTHENTICATION_LIFETIME: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Binding {
    revision: Revision,
    pin: ProviderPin,
    session: [u8; 16],
    peer: ipc::ConnectionId,
    generation: ProviderGeneration,
    epoch: u64,
}

impl Binding {
    fn capture(revision: Revision, peer: &ipc::PeerHandle, state: &mut OwnerState) -> Result<Self> {
        state.ensure_interactive()?;
        let session = state.administration.check(peer)?;
        ensure_idle(state)?;
        let manager = state
            .administration
            .manager
            .as_ref()
            .ok_or(ControlError::Denied)?;
        if manager.record().revision() != revision {
            return Err(ControlError::ProviderChanged.into());
        }
        Ok(Self {
            revision,
            pin: manager
                .record()
                .provider()
                .ok_or(ControlError::Denied)?
                .clone(),
            session,
            peer: peer.id(),
            generation: state.provider.generation(),
            epoch: state.administration.epoch,
        })
    }

    fn check(&self, peer: &ipc::PeerHandle, state: &mut OwnerState) -> Result<()> {
        state.ensure_interactive()?;
        if self.peer != peer.id()
            || state.administration.check(peer)? != self.session
            || state.administration.epoch != self.epoch
            || state.provider.generation() != self.generation
        {
            return Err(Fault::Canceled.into());
        }
        let manager = state
            .administration
            .manager
            .as_ref()
            .ok_or(ControlError::Denied)?;
        if !manager.idle()
            || manager.migration().is_some()
            || manager.record().revision() != self.revision
            || manager.record().provider() != Some(&self.pin)
        {
            return Err(ControlError::ProviderChanged.into());
        }
        Ok(())
    }
}

fn ensure_idle(state: &OwnerState) -> Result<()> {
    let admin = &state.administration;
    if state.pending.is_some()
        || admin.staging
        || admin.registering
        || admin.unlock.is_some()
        || !admin
            .manager
            .as_ref()
            .is_some_and(|manager| manager.idle() && manager.migration().is_none())
    {
        return Err(ControlError::Busy.into());
    }
    Ok(())
}

struct Reservation {
    source: Source,
    root: PathBuf,
    identity: CacheIdentity,
    operation: ProviderOperation,
}

enum Phase {
    Review(Box<Reservation>),
    Opening { deadline: MonotonicTimestamp },
}

pub(super) struct PendingUnlock {
    id: String,
    created: MonotonicTimestamp,
    binding: Binding,
    phase: Phase,
}

impl PendingUnlock {
    pub(super) fn expired(&self, now: MonotonicTimestamp) -> bool {
        match self.phase {
            Phase::Review(_) => now
                .checked_duration_since(self.created)
                .is_none_or(|age| age >= REVIEW_LIFETIME),
            Phase::Opening { deadline } => now >= deadline,
        }
    }

    fn begin(
        &mut self,
        authenticated: MonotonicTimestamp,
        now: MonotonicTimestamp,
    ) -> Result<(Reservation, MonotonicTimestamp)> {
        if u64::from(authenticated) == 0
            || authenticated
                .checked_duration_since(self.created)
                .is_none_or(|age| age >= REVIEW_LIFETIME)
            || now
                .checked_duration_since(authenticated)
                .is_none_or(|age| age >= AUTHENTICATION_LIFETIME)
        {
            return Err(ControlError::Expired.into());
        }
        if !matches!(self.phase, Phase::Review(_)) {
            return Err(ControlError::Denied.into());
        }
        let deadline = authenticated
            .checked_add(AUTHENTICATION_LIFETIME)
            .ok_or(Fault::InvalidClock)?;
        let Phase::Review(reservation) = mem::replace(&mut self.phase, Phase::Opening { deadline })
        else {
            unreachable!()
        };
        Ok((*reservation, deadline))
    }
}

pub(super) fn prepare(
    revision: Revision,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let (binding, created) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        (Binding::capture(revision, peer, &mut state)?, now()?)
    };
    let root = binding.pin.root(&paths.root);
    let source = Source::capture(&root)?;
    let identity = source.identity()?;
    if identity.binding != binding.pin.binding
        || identity.scope != binding.pin.scope
        || identity.device_key != binding.pin.device_key
    {
        return Err(Fault::ProviderChanged.into());
    }
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    binding.check(peer, &mut state)?;
    ensure_idle(&state)?;
    if now()?
        .checked_duration_since(created)
        .is_none_or(|age| age >= REVIEW_LIFETIME)
    {
        return Err(ControlError::Expired.into());
    }
    let operation = state.provider.begin_unlock(identity.clone())?;
    let id = BASE64.encode(super::super::random::<16>()?);
    let review = VaultUnlockReview {
        id: id.clone(),
        created,
        revision,
        session: BASE64.encode(binding.session),
        provider: binding.pin.clone(),
    };
    state.administration.unlock = Some(PendingUnlock {
        id,
        created,
        binding,
        phase: Phase::Review(Box::new(Reservation {
            source,
            root,
            identity,
            operation,
        })),
    });
    Ok(Reply::VaultUnlockReview { review })
}

struct Opening {
    id: String,
    binding: Binding,
    deadline: MonotonicTimestamp,
    root: PathBuf,
    identity: CacheIdentity,
    operation: ProviderOperation,
}

fn begin(
    id: &str,
    authenticated: MonotonicTimestamp,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    at: MonotonicTimestamp,
) -> Result<(Opening, Source)> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    let binding = state
        .administration
        .unlock
        .as_ref()
        .filter(|pending| pending.id == id)
        .ok_or(ControlError::Denied)?
        .binding
        .clone();
    binding.check(peer, &mut state)?;
    let pending = state
        .administration
        .unlock
        .as_mut()
        .filter(|pending| pending.id == id)
        .ok_or(Fault::Canceled)?;
    let (reservation, deadline) = pending.begin(authenticated, at)?;
    let Reservation {
        source,
        root,
        identity,
        operation,
    } = reservation;
    Ok((
        Opening {
            id: id.into(),
            binding,
            deadline,
            root,
            identity,
            operation,
        },
        source,
    ))
}

impl Opening {
    fn finish(
        self,
        snapshot: VaultSnapshot,
        current: &CacheIdentity,
        peer: &ipc::PeerHandle,
        shared: &Shared,
        clock: impl FnOnce() -> Result<MonotonicTimestamp>,
    ) -> Result<()> {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        self.binding.check(peer, &mut state)?;
        let at = clock()?;
        if at >= self.deadline {
            return Err(ControlError::Expired.into());
        }
        if !state.administration.unlock.as_ref().is_some_and(|pending| {
            pending.id == self.id
                && matches!(pending.phase, Phase::Opening { deadline } if deadline == self.deadline)
        }) {
            return Err(Fault::Canceled.into());
        }
        if current != &self.identity {
            return Err(Fault::ProviderChanged.into());
        }
        state
            .provider
            .finish_unlock(self.operation, current, snapshot)?;
        state.administration.unlock.take();
        Ok(())
    }
}

pub(super) fn presence(
    id: &str,
    authenticated: MonotonicTimestamp,
    context: &NativeAuthenticationContext<'_>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
) -> Result<Reply> {
    let peer = connection.handle();
    let (opening, source) = begin(id, authenticated, &peer, shared, now()?)?;
    let _lease = connection.context_lease(opening.deadline)?;
    if Source::capture(&opening.root)?.identity()? != opening.identity {
        return Err(Fault::ProviderChanged.into());
    }
    if now()? >= opening.deadline {
        return Err(ControlError::Expired.into());
    }
    let snapshot = source.unlock_authenticated(context)?;
    let root = opening.root.clone();
    {
        let cache = crate::owner::persistence::store(&root)?.transaction()?;
        let current = Source::capture_store(&cache)?.identity()?;
        opening.finish(snapshot, &current, &peer, shared, || {
            now().map_err(Into::into)
        })?;
    }
    Ok(Reply::VaultStatus(
        super::super::vault_workflow::cache_status(&root, shared)?,
    ))
}

pub(super) fn cancel_matching(id: &str, peer: &ipc::PeerHandle, shared: &Shared) {
    if let Ok(mut state) = shared.0.lock()
        && state
            .administration
            .unlock
            .as_ref()
            .is_some_and(|pending| pending.id == id && pending.binding.peer == peer.id())
    {
        state.administration.unlock.take();
    }
}

pub(super) fn cancel(id: &str, peer: &ipc::PeerHandle, shared: &Shared) -> Result<Reply> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    state.administration.check(peer)?;
    let matches = state
        .administration
        .unlock
        .as_ref()
        .is_some_and(|pending| pending.id == id && pending.binding.peer == peer.id());
    if matches {
        state.administration.unlock.take();
    }
    Ok(if matches {
        Reply::Canceled
    } else {
        Reply::UnknownOperation
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::Harness;
    use super::*;
    use crate::owner::{
        policy::{AuthorizationError, AuthorizationOutcome},
        request, test_support, vault,
    };
    use crate::platform::HostSessionEvent;
    use serde_json::json;
    use std::{io::Cursor, time::Instant};

    fn prepare_opening(harness: &Harness) -> (Opening, Source, ipc::PeerHandle) {
        let review = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        assert_eq!(review["kind"], "vaultUnlockReview", "{review}");
        let peer = harness
            .shared
            .0
            .lock()
            .unwrap()
            .administration
            .session
            .as_ref()
            .unwrap()
            .peer
            .clone();
        let at = now().unwrap();
        let (opening, source) = begin(
            review["review"]["id"].as_str().unwrap(),
            at,
            &peer,
            &harness.shared,
            at,
        )
        .unwrap();
        (opening, source, peer)
    }

    fn assert_no_api_authority(state: &OwnerState) {
        let principal = test_support::principal(state.authorizer.session());
        let config = state.authorizer.github_configuration().unwrap();
        let read = request::read_configured(&mut Cursor::new(b"GET /repos/example/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"), Some(config)).unwrap();
        assert!(read.matches_configuration(config));
        assert!(matches!(
            state.authorizer.authorize(&principal, read, Instant::now()),
            Err(AuthorizationError::Denied)
        ));
        let write = request::read_configured(&mut Cursor::new(b"PATCH /repos/example/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}"), Some(config)).unwrap();
        assert!(matches!(
            state
                .authorizer
                .authorize(&principal, write, Instant::now()),
            Ok(AuthorizationOutcome::RequireApproval(_))
        ));
    }

    #[test]
    fn installing_an_unwrapped_snapshot_creates_no_api_authority_or_settings_change() {
        let harness = Harness::configured_locked();
        let before = harness.call(json!({"kind":"settingsStatus"}), None)["settings"].clone();
        assert_no_api_authority(&harness.shared.0.lock().unwrap());
        let (opening, source, peer) = prepare_opening(&harness);
        let current = source.identity().unwrap();
        let snapshot = vault::fixture::open(source);
        opening
            .finish(snapshot, &current, &peer, &harness.shared, || {
                now().map_err(Into::into)
            })
            .unwrap();
        let state = harness.shared.0.lock().unwrap();
        assert!(state.provider.snapshot().is_some());
        assert!(state.administration.unlock.is_none());
        assert_no_api_authority(&state);
        drop(state);
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"],
            before
        );
        assert_eq!(
            harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None)["kind"],
            "vaultUnlockReview"
        );
    }

    #[test]
    fn canceled_disconnected_and_host_changed_unlocks_cannot_install_after_unwrap() {
        for event in [
            "cancel",
            "disconnect",
            "lock",
            "screen",
            "sleep",
            "wake",
            "logout",
            "settings",
            "source",
            "expiry",
        ] {
            let harness = Harness::configured_locked();
            let (opening, source, peer) = prepare_opening(&harness);
            let snapshot = vault::fixture::open(source);
            let mut current = Source::capture(&opening.root).unwrap().identity().unwrap();
            let deadline = opening.deadline;
            {
                let mut state = harness.shared.0.lock().unwrap();
                match event {
                    "cancel" => {
                        state.administration.unlock.take();
                    }
                    "disconnect" => state.administration.disconnect(peer.id()),
                    "lock" => state.lock_vault().unwrap(),
                    "settings" => state.administration.cancel_changes(),
                    "screen" => state
                        .host_session_event(HostSessionEvent::ScreenLock)
                        .unwrap(),
                    "sleep" => state.host_session_event(HostSessionEvent::Sleep).unwrap(),
                    "wake" => state.host_session_event(HostSessionEvent::Wake).unwrap(),
                    "logout" => state.host_session_event(HostSessionEvent::Logout).unwrap(),
                    "source" => current.device_key = [99; 32],
                    _ => {}
                }
            }
            let at = if event == "expiry" {
                deadline
            } else {
                now().unwrap()
            };
            assert!(
                opening
                    .finish(snapshot, &current, &peer, &harness.shared, || Ok(at))
                    .is_err(),
                "{event}"
            );
            assert!(
                harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .provider
                    .snapshot()
                    .is_none(),
                "{event}"
            );
        }
    }

    #[test]
    fn authentication_and_installation_enforce_the_original_deadlines() {
        for (authentication_offset, completion_age, allowed) in [
            (119, 0, true),
            (119, 29, true),
            (120, 0, false),
            (121, 0, false),
            (0, 30, false),
        ] {
            let harness = Harness::configured_locked();
            let review = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
            let id = review["review"]["id"].as_str().unwrap();
            let (peer, created) = {
                let state = harness.shared.0.lock().unwrap();
                (
                    state.administration.session.as_ref().unwrap().peer.clone(),
                    state.administration.unlock.as_ref().unwrap().created,
                )
            };
            let authenticated = created
                .checked_add(Duration::from_secs(authentication_offset))
                .unwrap();
            let completed = authenticated
                .checked_add(Duration::from_secs(completion_age))
                .unwrap();
            let result = begin(id, authenticated, &peer, &harness.shared, completed);
            assert_eq!(result.is_ok(), allowed);
            if let Ok((opening, source)) = result {
                assert_eq!(
                    opening.deadline,
                    authenticated.checked_add(AUTHENTICATION_LIFETIME).unwrap()
                );
                let current = source.identity().unwrap();
                let snapshot = vault::fixture::open(source);
                harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .administration
                    .expire(completed);
                assert!(
                    opening
                        .finish(snapshot, &current, &peer, &harness.shared, || Ok(completed))
                        .is_ok()
                );
            }
        }
    }

    #[test]
    fn future_authentication_and_replayed_presence_do_not_open_the_cache() {
        let harness = Harness::configured_locked();
        let review = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        let id = review["review"]["id"].as_str().unwrap();
        let peer = harness
            .shared
            .0
            .lock()
            .unwrap()
            .administration
            .session
            .as_ref()
            .unwrap()
            .peer
            .clone();
        let at = now().unwrap();
        assert!(
            begin(
                id,
                at.checked_add(Duration::from_secs(1)).unwrap(),
                &peer,
                &harness.shared,
                at
            )
            .is_err()
        );
        let (opening, source) = begin(id, at, &peer, &harness.shared, at).unwrap();
        assert!(begin(id, at, &peer, &harness.shared, at).is_err());
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
        drop((opening, source));
    }

    #[test]
    fn another_peer_cannot_prepare_use_or_cancel_the_unlock_reservation() {
        let harness = Harness::configured_locked();
        let other = Harness::new();
        let foreign_peer = other
            .shared
            .0
            .lock()
            .unwrap()
            .administration
            .session
            .as_ref()
            .unwrap()
            .peer
            .clone();
        let review = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        let id = review["review"]["id"].as_str().unwrap();
        assert!(prepare(Revision(1), &foreign_peer, &harness.shared, &harness.paths).is_err());
        let at = now().unwrap();
        assert!(begin(id, at, &foreign_peer, &harness.shared, at).is_err());
        assert!(cancel(id, &foreign_peer, &harness.shared).is_err());
        cancel_matching(id, &foreign_peer, &harness.shared);
        assert_eq!(
            harness.call(json!({"kind":"vaultUnlockCancel","id":id}), None)["kind"],
            "canceled"
        );
    }

    #[test]
    fn a_changed_provider_or_settings_revision_invalidates_the_frozen_review() {
        for field in ["revision", "provider"] {
            let harness = Harness::configured_locked();
            let (mut opening, source, peer) = prepare_opening(&harness);
            let current = source.identity().unwrap();
            let snapshot = vault::fixture::open(source);
            if field == "revision" {
                opening.binding.revision = Revision(2);
            } else {
                opening.binding.pin.device_key = [99; 32];
            }
            assert!(
                opening
                    .finish(snapshot, &current, &peer, &harness.shared, || now()
                        .map_err(Into::into))
                    .is_err()
            );
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
}
