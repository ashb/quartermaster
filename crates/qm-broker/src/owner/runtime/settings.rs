use super::{
    ServicePaths, Shared,
    error::{Error, Fault, Result},
    random,
};
use crate::{
    owner::{
        protocol::{Client, ControlError, Reply, StagedItemCatalogue},
        provider_lifecycle::{CacheIdentity, ProviderGeneration},
        settings::{Manager, Proposal, ProviderChoice, ProviderPin, Revision, Snapshot},
        vault::{self, Source},
    },
    platform::macos::ipc,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_macos::presence_clock::{MonotonicTimestamp, monotonic_raw as now};
use qm_providers::{RbwProvider, VaultSnapshot};
use std::{sync::Arc, time::Duration};

mod import;
mod repositories;
mod unlock;

struct Enrollment {
    ticket: String,
    pin: ProviderPin,
    identity: CacheIdentity,
    snapshot: Option<VaultSnapshot>,
    expires: MonotonicTimestamp,
}

struct EnrollmentReservation {
    id: [u8; 16],
    session: [u8; 16],
    revision: Revision,
    generation: ProviderGeneration,
    allow_warm: bool,
}
pub(super) struct ChangeContext {
    generation: ProviderGeneration,
    source: Option<Source>,
    identity: Option<CacheIdentity>,
    warm: Option<VaultSnapshot>,
    provider_changed: bool,
    pin: Option<ProviderPin>,
    lease: Option<ipc::ContextLease>,
}

pub(super) struct Session {
    pub(super) peer: ipc::PeerHandle,
    pub(super) id: [u8; 16],
}

#[derive(Default)]
pub(super) struct Administration {
    pub(super) manager: Option<Manager<ChangeContext>>,
    pub(super) session: Option<Session>,
    pub(super) unavailable: bool,
    epoch: u64,
    staging: Option<EnrollmentReservation>,
    registering: bool,
    staged: Option<Enrollment>,
    unlock: Option<unlock::PendingUnlock>,
}

impl Administration {
    pub(super) fn expire(&mut self, now: MonotonicTimestamp) {
        if self
            .unlock
            .as_ref()
            .is_some_and(|pending| pending.expired(now))
        {
            self.unlock.take();
        }
        if self
            .staged
            .as_ref()
            .is_some_and(|staged| now >= staged.expires)
        {
            self.staged.take();
        }
        if let Some(manager) = &mut self.manager {
            manager.expire(now);
        }
    }
    pub(super) fn manages_cache(&self, peer: &ipc::PeerHandle) -> bool {
        self.check(peer).is_ok()
            && self
                .manager
                .as_ref()
                .is_some_and(|manager| manager.stable() && manager.record().provider().is_some())
    }
    pub(super) fn cancel_changes(&mut self) {
        self.cancel_approvals();
        self.staged.take();
        self.staging.take();
    }

    pub(super) fn console_changed(&mut self) {
        self.cancel_approvals();
        if let Some(staging) = &mut self.staging {
            staging.allow_warm = false;
        }
        if let Some(staged) = &mut self.staged {
            staged.snapshot.take();
        }
    }

    fn cancel_approvals(&mut self) {
        self.unlock.take();
        if let (Some(manager), Some(session)) = (&mut self.manager, &self.session) {
            manager.cancel_connection(session.peer.id().value());
        }
        self.registering = false;
        match self.epoch.checked_add(1) {
            Some(epoch) => self.epoch = epoch,
            None => self.unavailable = true,
        }
    }

    pub(super) fn disconnect(&mut self, connection: ipc::ConnectionId) {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.peer.id() == connection)
        {
            self.cancel_changes();
            self.session = None;
        }
    }

    fn check(&self, peer: &ipc::PeerHandle) -> Result<[u8; 16]> {
        if self.unavailable || !peer.is_connected() {
            return Err(ControlError::Unavailable.into());
        }
        self.session
            .as_ref()
            .filter(|session| session.peer.id() == peer.id())
            .map(|session| session.id)
            .ok_or_else(|| ControlError::Denied.into())
    }
}

pub(super) fn status(
    shared: &Shared,
    paths: &ServicePaths,
    connection: ipc::ConnectionId,
) -> Result<Reply> {
    let state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    let admin = &state.administration;
    let record = admin.manager.as_ref().map(Manager::record);
    let status = if admin.unavailable
        || paths.settings.is_none()
        || admin.manager.as_ref().is_some_and(Manager::failed)
    {
        "unavailable"
    } else if admin
        .manager
        .as_ref()
        .is_some_and(|manager| !manager.stable())
    {
        "applying"
    } else if admin
        .manager
        .as_ref()
        .is_some_and(|manager| manager.migration().is_some())
    {
        "migrationRequired"
    } else if record.is_some_and(|record| record.settings().is_some()) {
        "configured"
    } else {
        "unconfigured"
    };
    let settings = Snapshot {
        state: status,
        revision: record.map_or(Revision(0), |record| record.revision()),
        session: admin
            .session
            .as_ref()
            .filter(|session| session.peer.id() == connection)
            .map(|session| BASE64.encode(session.id)),
        settings: record.and_then(|record| record.settings()).cloned(),
        provider: record.and_then(|record| record.provider()).cloned(),
        migration: admin.manager.as_ref().and_then(Manager::migration).cloned(),
    };
    Ok(Reply::SettingsStatus {
        settings: Box::new(settings),
    })
}

pub(super) fn message(
    request: Client,
    context: Option<&qm_macos::cache_key::NativeAuthenticationContext<'_>>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
    runtime: &tokio::runtime::Handle,
    work_limit: &Arc<tokio::sync::Semaphore>,
) -> Result<ipc::Response> {
    if let Client::VaultUnlockPresence { id, authenticated } = &request {
        let result = match context {
            Some(context) => unlock::presence(id, *authenticated, context, connection, shared),
            None => Err(Fault::NativeContextRequired.into()),
        };
        if result.is_err() {
            unlock::cancel_matching(id, &connection.handle(), shared);
        }
        connection.release_context();
        shared.1.notify_all();
        let result = result.or_else(|error| match error {
            Error::Vault(error) => Ok(Reply::VaultStatus(vault::error_reply(error))),
            error => Err(error),
        });
        return super::control::encode_result(result).map(Into::into);
    }
    if let Client::VaultUnlockCancel { id } = &request {
        if context.is_some() {
            connection.release_context();
            return Err(Fault::UnexpectedContext.into());
        }
        return super::control::encode_result(unlock::cancel(id, &connection.handle(), shared))
            .map(Into::into);
    }
    if let Client::SettingsPresence { id, authenticated } = &request {
        let result = match context {
            Some(context) => presence(id, *authenticated, context, connection, shared),
            None => Err(Fault::NativeContextRequired.into()),
        };
        if result.is_err() {
            if let Ok(mut state) = shared.0.lock()
                && state
                    .administration
                    .session
                    .as_ref()
                    .is_some_and(|session| session.peer.id() == connection.id())
                && state
                    .administration
                    .manager
                    .as_ref()
                    .is_some_and(|manager| manager.pending(id, connection.id().value()))
            {
                state.administration.cancel_changes();
            }
            connection.release_context();
        }
        if result.is_err() || !repositories::needed(id, &connection.handle(), shared)? {
            return super::control::encode_result(result).map(Into::into);
        }
    }
    if context.is_some() && !matches!(&request, Client::SettingsPresence { .. }) {
        connection.release_context();
        return Err(Fault::UnexpectedContext.into());
    }
    if let Client::SettingsCancel { id } = request {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.administration.check(&connection.handle())?;
        let reply = if let Some(id) = id {
            match state
                .administration
                .manager
                .as_mut()
                .ok_or(ControlError::Denied)?
                .cancel(&id, connection.id().value())
            {
                Ok(true) => {
                    state.administration.cancel_changes();
                    Reply::Canceled
                }
                Ok(false) => Reply::UnknownOperation,
                Err(crate::owner::settings::Error::Busy) => Reply::AlreadyAdmitted,
                Err(error) => return Err(error.into()),
            }
        } else if state
            .administration
            .manager
            .as_ref()
            .is_some_and(Manager::committing)
        {
            Reply::AlreadyAdmitted
        } else {
            state.administration.cancel_changes();
            Reply::Canceled
        };
        return super::control::encode_result(Ok(reply)).map(Into::into);
    }
    let permit = match Arc::clone(work_limit).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            if let Client::SettingsPresence { id, .. } = &request {
                repositories::cancel_matching(id, &connection.handle(), shared);
                connection.release_context();
            }
            return Err(ControlError::Busy.into());
        }
    };
    let peer = connection.handle();
    let shared = Arc::clone(shared);
    let paths = paths.clone();
    let cleanup_shared = Arc::clone(&shared);
    let cleanup_peer = peer.clone();
    // Preparation and enrollment failures cannot cancel another operation's reservation.
    let cancel_on_error = !matches!(
        &request,
        Client::PrepareSettingsImport { .. }
            | Client::PrepareSettingsDiscard { .. }
            | Client::PrepareVaultUnlock { .. }
            | Client::PrepareSettings { .. }
            | Client::StageEnrollment { .. }
    );
    let cleanup_id = match &request {
        Client::SettingsPresence { id, .. } | Client::SettingsProof { id, .. } => Some(id.clone()),
        _ => None,
    };
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _permit = permit;
        let result = match request {
            Client::StageEnrollment {
                server,
                email,
                password,
            } => {
                eprintln!("Vault login requested");
                let result = stage(server, email, password, &peer, &shared, &paths).await;
                if let Err(error) = &result {
                    match error {
                        Error::Vault(error) => eprintln!("Vault login failed: {error:?}"),
                        Error::Protocol(code) => eprintln!("Vault login refused: {code:?}"),
                        Error::State(fault) => eprintln!("Vault login interrupted: {fault:?}"),
                        _ => eprintln!("Vault login failed: {error}"),
                    }
                }
                result
            }
            request => tokio::task::spawn_blocking(move || match request {
                Client::SettingsStatus {} => status(&shared, &paths, peer.id()),
                Client::PrepareSettingsImport { id } => {
                    import::prepare(&id, &peer, &shared, &paths)
                }
                Client::PrepareSettingsDiscard { id } => {
                    import::discard(&id, &peer, &shared, &paths)
                }
                Client::PrepareVaultUnlock { revision } => {
                    unlock::prepare(revision, &peer, &shared, &paths)
                }
                Client::SettingsRegister { public_key } => {
                    register(&public_key, &peer, &shared, &paths)
                }
                Client::PrepareSettings {
                    revision,
                    settings,
                    provider,
                    additions,
                } => repositories::prepare(
                    revision, settings, provider, additions, &peer, &shared, &paths,
                ),
                Client::SettingsPresence { id, authenticated } => {
                    repositories::resolve(&id, authenticated, &peer, &shared, &paths)
                }
                Client::SettingsProof { id, signature } => {
                    commit(&id, &signature, &peer, &shared, &paths)
                }
                _ => Err(ControlError::Denied.into()),
            })
            .await
            .map_err(Error::from)
            .and_then(|result| result),
        };
        if result.is_err()
            && cancel_on_error
            && let Ok(mut state) = cleanup_shared.0.lock()
            && state
                .administration
                .session
                .as_ref()
                .is_some_and(|session| session.peer.id() == cleanup_peer.id())
            && cleanup_id.as_ref().is_none_or(|id| {
                state
                    .administration
                    .manager
                    .as_ref()
                    .is_some_and(|manager| manager.pending(id, cleanup_peer.id().value()))
            })
        {
            state.administration.cancel_changes();
        }
        let _ = send.send(
            super::control::encode_result(result)
                .unwrap_or_else(|_| br#"{"kind":"error","code":"unavailable"}"#.to_vec()),
        );
    });
    Ok(ipc::Response::Deferred(receive))
}

fn register(
    key: &str,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let key = BASE64.decode(key)?;
    let epoch = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        let admin = &mut state.administration;
        if admin.registering
            || admin.staging.is_some()
            || admin
                .manager
                .as_ref()
                .is_some_and(|manager| !manager.idle() && !manager.failed())
        {
            return Err(ControlError::Busy.into());
        }
        if let Some(session) = &admin.session {
            if session.peer.id() == peer.id()
                && admin.manager.as_ref().is_some_and(|manager| {
                    !manager.failed() && manager.record().public_key() == key
                })
            {
                drop(state);
                return status(shared, paths, peer.id());
            }
            if session.peer.id() != peer.id() && session.peer.is_connected() {
                return Err(ControlError::Denied.into());
            }
        }
        admin.cancel_changes();
        admin.registering = true;
        admin.epoch
    };
    let loaded = paths
        .settings
        .as_ref()
        .ok_or(ControlError::Unavailable)?
        .register(&key);
    {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        if !peer.is_connected() || state.administration.epoch != epoch {
            return Err(Fault::Canceled.into());
        }
        state.administration.registering = false;
        let manager = loaded?;
        state.administration.unavailable = false;
        paths.policy.install(&manager)?;
        state.approval_public_key = Some(manager.record().public_key().to_vec());
        state.administration.manager = Some(manager);
        state.administration.session = Some(Session {
            peer: peer.clone(),
            id: random()?,
        });
    }
    status(shared, paths, peer.id())
}

fn prepare(
    revision: Revision,
    settings: crate::owner::settings::Settings,
    choice: ProviderChoice,
    peer: &ipc::PeerHandle,
    shared: &Shared,
) -> Result<Reply> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    state.ensure_interactive()?;
    if state.pending.is_some() {
        return Err(ControlError::Busy.into());
    }
    let generation = state.provider.generation();
    let admin = &mut state.administration;
    let session = admin.check(peer)?;
    if admin.staging.is_some() || admin.registering || admin.unlock.is_some() {
        return Err(ControlError::Busy.into());
    }
    let manager = admin.manager.as_mut().ok_or(ControlError::Denied)?;
    if !manager.idle() {
        return Err(ControlError::Busy.into());
    }
    let old = manager.record().provider().cloned();
    let prepared_at = now()?;
    let (pin, source, identity, warm) = match choice {
        ProviderChoice::Keep => (old.clone(), None, None, None),
        ProviderChoice::Forget => (None, None, None, None),
        ProviderChoice::Staged { ticket } => {
            let staged = admin
                .staged
                .as_mut()
                .filter(|staged| staged.ticket == ticket && prepared_at < staged.expires)
                .ok_or(ControlError::Denied)?;
            (
                Some(staged.pin.clone()),
                None,
                Some(staged.identity.clone()),
                staged.snapshot.take(),
            )
        }
    };
    let provider_changed = old != pin;
    let context = ChangeContext {
        generation,
        source,
        identity,
        warm,
        provider_changed,
        pin: pin.clone(),
        lease: None,
    };
    let review = manager.prepare(
        peer.id().value(),
        session,
        Proposal {
            revision,
            settings,
            provider: pin,
        },
        prepared_at,
        context,
    )?;
    Ok(Reply::SettingsReview { review })
}

fn presence(
    id: &str,
    authenticated: MonotonicTimestamp,
    context: &qm_macos::cache_key::NativeAuthenticationContext<'_>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
) -> Result<Reply> {
    let deadline = authenticated
        .checked_add(Duration::from_secs(30))
        .ok_or(Fault::InvalidClock)?;
    let lease = connection.context_lease(deadline)?;
    let (challenge, source) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        let generation = state.provider.generation();
        let admin = &mut state.administration;
        admin.check(&connection.handle())?;
        let manager = admin.manager.as_mut().ok_or(ControlError::Denied)?;
        if manager.context(id, connection.id().value())?.generation != generation {
            return Err(ControlError::Denied.into());
        }
        let challenge = manager.authenticate(id, connection.id().value(), authenticated, now()?)?;
        let source = manager.with_context(id, connection.id().value(), |context| {
            context.lease = Some(lease);
            context.source.take()
        })?;
        (challenge, source)
    };
    if let Some(source) = source {
        let snapshot = source.unlock_authenticated(context)?;
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        let generation = state.provider.generation();
        let admin = &mut state.administration;
        admin.check(&connection.handle())?;
        if now()?
            .checked_duration_since(authenticated)
            .is_none_or(|age| age >= Duration::from_secs(30))
        {
            return Err(ControlError::Expired.into());
        }
        let manager = admin.manager.as_mut().ok_or(ControlError::Denied)?;
        if manager.context(id, connection.id().value())?.generation != generation {
            return Err(ControlError::Denied.into());
        }
        manager.with_context(id, connection.id().value(), |context| {
            context.warm = Some(snapshot)
        })?;
    }
    Ok(Reply::SettingsChallenge {
        authorization: challenge,
    })
}

fn commit(
    id: &str,
    signature: &str,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let store = paths.settings.as_ref().ok_or(ControlError::Unavailable)?;
    let signature = BASE64.decode(signature)?;
    let frozen = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        state.administration.check(peer)?;
        let manager = state
            .administration
            .manager
            .as_ref()
            .ok_or(ControlError::Denied)?;
        let context = manager.context(id, peer.id().value())?;
        if context.generation != state.provider.generation()
            || context.identity.is_some() != context.warm.is_some()
        {
            return Err(ControlError::Denied.into());
        }
        match (&context.pin, &context.identity) {
            (Some(pin), Some(identity)) => Some((pin.clone(), identity.clone())),
            (_, None) => None,
            _ => return Err(ControlError::Denied.into()),
        }
    };
    let cache = if let Some((pin, expected)) = &frozen {
        let cache = crate::owner::persistence::store(&pin.root(&paths.root))?.transaction()?;
        let current = Source::capture_store(&cache)?.identity()?;
        if current != *expected
            || current.binding != pin.binding
            || current.scope != pin.scope
            || current.device_key != pin.device_key
        {
            return Err(Fault::ProviderChanged.into());
        }
        Some(cache)
    } else {
        None
    };
    let (admission, operation) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        state.administration.check(peer)?;
        let manager = state
            .administration
            .manager
            .as_mut()
            .ok_or(ControlError::Denied)?;
        let mut verified = manager.approve(id, peer.id().value(), &signature, now()?)?;
        verified.context_mut().lease.take();
        let preparation: Result<_> = (|| {
            if verified.context().generation != state.provider.generation() {
                return Err(Fault::ProviderChanged.into());
            }
            paths.policy.suspend()?;
            state.authorizer.invalidate_policy()?;
            state.cancel_pending();
            if let Some(ui) = state.ui.take() {
                state.operations.cancel_interactive_session(ui.session.id());
            }
            let operation = if verified.context().provider_changed {
                state.provider.lock()?;
                verified
                    .context()
                    .identity
                    .as_ref()
                    .map(|identity| state.provider.begin_unlock(identity.clone()))
                    .transpose()?
            } else {
                state.provider.cancel_pending();
                None
            };
            state.ensure_interactive()?;
            state.administration.check(peer)?;
            Ok((operation, now()?))
        })();
        let (operation, admitted_at) = match preparation {
            Ok(prepared) => prepared,
            Err(error) => {
                state
                    .administration
                    .manager
                    .as_mut()
                    .ok_or(ControlError::Denied)?
                    .abort(verified);
                return Err(error);
            }
        };
        let admitted = state
            .administration
            .manager
            .as_mut()
            .ok_or(ControlError::Denied)?
            .admit(verified, admitted_at);
        match admitted {
            Ok(admission) => (admission, operation),
            Err(error) => {
                if let Some(operation) = operation {
                    state.provider.release(&operation);
                }
                return Err(error.into());
            }
        }
    };
    let publication = store.publish(admission);
    let current = cache
        .as_ref()
        .map(|cache| Source::capture_store(cache).and_then(|source| source.identity()))
        .transpose();
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    let completed = state
        .administration
        .manager
        .as_mut()
        .ok_or(ControlError::Denied)?
        .finish(publication);
    let mut context = match completed {
        Ok(context) => context,
        Err(error) => {
            if let Some(operation) = operation {
                state.provider.release(&operation);
            }
            return Err(error.into());
        }
    };
    state.administration.staged.take();
    if let Some(operation) = operation {
        match (current, context.identity.take(), context.warm.take()) {
            (Ok(Some(current)), Some(expected), Some(snapshot))
                if current == expected && state.ensure_host_session().is_ok() =>
            {
                let _ = state.provider.finish_unlock(operation, &current, snapshot);
            }
            _ => state.provider.release(&operation),
        }
    }
    let manager = state
        .administration
        .manager
        .as_ref()
        .ok_or(ControlError::Denied)?;
    let revision = manager.record().revision();
    paths.policy.install(manager)?;
    match state.refresh_policy(&paths.load_policy()) {
        Ok(())
        | Err(Error::Authorization(
            crate::owner::policy::AuthorizationError::Denied
            | crate::owner::policy::AuthorizationError::SessionRevoked,
        )) => {}
        Err(error) => return Err(error),
    }
    Ok(Reply::SettingsApplied { revision })
}

async fn stage(
    server: String,
    email: String,
    password: zeroize::Zeroizing<String>,
    peer: &ipc::PeerHandle,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let id = begin_enrollment(peer, shared)?;
    let result = async {
        if password.is_empty() || password.len() > 4096 {
            eprintln!("Vault login rejected: password is empty or exceeds the size limit");
            return Err(ControlError::Denied.into());
        }
        let snapshot = RbwProvider::enroll(&server, &email, password.as_bytes(), vault::LIMITS)
            .await
            .map_err(vault::Error::from)?;
        drop(password);
        {
            let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
            state.ensure_interactive()?;
            enrollment_reservation(id, peer, &state)?;
        }
        let root = paths.root.clone();
        tokio::task::spawn_blocking(move || vault::stage_inactive(&root, snapshot))
            .await
            .map_err(Error::from)?
            .map_err(Error::from)
    }
    .await;
    finish_enrollment(id, result, peer, shared)
}

fn begin_enrollment(peer: &ipc::PeerHandle, shared: &Shared) -> Result<[u8; 16]> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    state.ensure_interactive()?;
    let generation = state.provider.generation();
    let admin = &mut state.administration;
    let session = admin.check(peer)?;
    if admin.staging.is_some()
        || admin.registering
        || admin.unlock.is_some()
        || admin.manager.as_ref().is_none_or(|manager| !manager.idle())
    {
        return Err(ControlError::Busy.into());
    }
    let id = random()?;
    admin.staged.take();
    admin.staging = Some(EnrollmentReservation {
        id,
        session,
        revision: admin.manager.as_ref().unwrap().record().revision(),
        generation,
        allow_warm: true,
    });
    Ok(id)
}

fn enrollment_reservation<'a>(
    id: [u8; 16],
    peer: &ipc::PeerHandle,
    state: &'a super::OwnerState,
) -> Result<&'a EnrollmentReservation> {
    let admin = &state.administration;
    let session = admin.check(peer)?;
    admin
        .staging
        .as_ref()
        .filter(|reservation| {
            reservation.id == id
                && reservation.session == session
                && reservation.generation == state.provider.generation()
                && admin
                    .manager
                    .as_ref()
                    .is_some_and(|manager| manager.record().revision() == reservation.revision)
        })
        .ok_or_else(|| Fault::Canceled.into())
}

fn finish_enrollment(
    id: [u8; 16],
    result: Result<vault::StagedCache>,
    peer: &ipc::PeerHandle,
    shared: &Shared,
) -> Result<Reply> {
    let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    let valid = state
        .ensure_interactive()
        .and_then(|()| enrollment_reservation(id, peer, &state).map(|_| ()));
    let admin = &mut state.administration;
    let reservation = admin.staging.take_if(|reservation| reservation.id == id);
    valid?;
    let reservation = reservation.ok_or(Fault::Canceled)?;
    let staged = result?;
    let catalogue = staged.snapshot.item_summaries().map_or(
        StagedItemCatalogue::Unavailable,
        StagedItemCatalogue::bounded,
    );
    let pin = ProviderPin {
        slot: staged.slot,
        binding: staged.identity.binding.clone(),
        scope: staged.identity.scope.clone(),
        device_key: staged.identity.device_key,
    };
    let ticket = BASE64.encode(random::<16>()?);
    let expires = now()?
        .checked_add(Duration::from_secs(120))
        .ok_or(Fault::InvalidClock)?;
    admin.staged = Some(Enrollment {
        ticket: ticket.clone(),
        pin: pin.clone(),
        identity: staged.identity,
        snapshot: reservation.allow_warm.then_some(staged.snapshot),
        expires,
    });
    Ok(Reply::EnrollmentStaged {
        ticket,
        provider: pin,
        catalogue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        HostSessionEvent,
        macos::ipc::test_support::{Fixture, send, start_send},
    };
    use objc2::rc::Retained;
    use objc2_foundation::NSXPCConnection;
    use objc2_local_authentication::LAContext;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use serde_json::{Value, json};
    use std::{
        io,
        sync::{Condvar, Mutex},
    };

    pub(super) struct Harness {
        pub(super) client: Retained<NSXPCConnection>,
        _native: Fixture,
        _runtime: tokio::runtime::Runtime,
        _directory: tempfile::TempDir,
        pub(super) paths: ServicePaths,
        pub(super) shared: Shared,
        key: EcdsaKeyPair,
    }

    impl Harness {
        pub(super) fn new() -> Self {
            Self::with_store(crate::owner::settings::Store::memory())
        }

        fn with_store(store: crate::owner::settings::Store) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let paths = ServicePaths {
                app: "/unused.app".into(),
                root: directory.path().canonicalize().unwrap(),
                policy: Arc::default(),
                settings: Some(Arc::new(store)),
            };
            let shared = Arc::new((
                Mutex::new(super::super::OwnerState::new().unwrap()),
                Condvar::new(),
            ));
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .build()
                .unwrap();
            let handle = runtime.handle().clone();
            let owner = Arc::clone(&shared);
            let service = paths.clone();
            let limit = Arc::new(tokio::sync::Semaphore::new(8));
            let native = Fixture::new(move |event| {
                super::super::control::handle_event(event, &owner, &service, &handle, &limit)
                    .or_else(|error| {
                        super::super::control::encode_result(Err(error)).map(Into::into)
                    })
                    .map_err(io::Error::other)
            });
            let client = native.client();
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let harness = Self {
                client,
                _native: native,
                _runtime: runtime,
                _directory: directory,
                paths,
                shared,
                key,
            };
            let reply = harness.call(json!({"kind":"settingsRegister", "publicKey": BASE64.encode(harness.key.public_key().as_ref())}), None);
            assert_eq!(reply["settings"]["state"], "unconfigured");
            harness
        }

        pub(super) fn call(&self, request: Value, context: Option<&LAContext>) -> Value {
            serde_json::from_slice(&send(
                &self.client,
                &serde_json::to_vec(&request).unwrap(),
                context,
            ))
            .unwrap()
        }

        pub(super) fn review(&self) -> Value {
            self.review_with_settings(json!({"github":{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}],"approveUnverifiedRequests":true},"mutations":"requireApproval"}))
        }

        pub(super) fn review_with_settings(&self, settings: Value) -> Value {
            let staged = self.staged_cache();
            let pin = ProviderPin {
                slot: staged.slot,
                binding: staged.identity.binding.clone(),
                scope: staged.identity.scope.clone(),
                device_key: staged.identity.device_key,
            };
            self.shared.0.lock().unwrap().administration.staged = Some(Enrollment {
                ticket: "selection".into(),
                pin,
                identity: staged.identity,
                snapshot: Some(staged.snapshot),
                expires: now()
                    .unwrap()
                    .checked_add(Duration::from_secs(120))
                    .unwrap(),
            });
            let reply = self.call(json!({"kind":"prepareSettings", "revision":0, "settings":settings, "provider":{"kind":"staged","ticket":"selection"}}), None);
            assert_eq!(reply["kind"], "settingsReview", "{reply}");
            let review = reply["review"].clone();
            let document = BASE64.decode(review["document"].as_str().unwrap()).unwrap();
            assert!(
                !String::from_utf8(document)
                    .unwrap()
                    .contains("quartermaster-dummy-canary")
            );
            review
        }

        fn staged_cache(&self) -> vault::StagedCache {
            let snapshot = crate::owner::test_support::vault::snapshot("github-write");
            let slot = "a".repeat(32);
            let identity =
                vault::fixture::put(&self.paths.root.join("enrollments").join(&slot), &snapshot)
                    .identity()
                    .unwrap();
            vault::StagedCache {
                slot,
                identity,
                snapshot: snapshot.into(),
            }
        }

        fn peer(&self) -> ipc::PeerHandle {
            self.shared
                .0
                .lock()
                .unwrap()
                .administration
                .session
                .as_ref()
                .unwrap()
                .peer
                .clone()
        }

        pub(super) fn authenticate(&self, review: &Value) -> Value {
            let context = unsafe { LAContext::new() };
            let reply = self.call(json!({"kind":"settingsPresence", "id":review["id"], "authenticated":u64::from(now().unwrap())}), Some(&context));
            assert_eq!(reply["kind"], "settingsChallenge", "{reply}");
            reply["authorization"].clone()
        }

        pub(super) fn proof(&self, review: &Value, challenge: &Value) -> Value {
            self.call(self.proof_command(review, challenge), None)
        }

        fn proof_command(&self, review: &Value, challenge: &Value) -> Value {
            let bytes = BASE64.decode(challenge["bytes"].as_str().unwrap()).unwrap();
            let signature = self.key.sign(&SystemRandom::new(), &bytes).unwrap();
            json!({"kind":"settingsProof", "id":review["id"], "signature":BASE64.encode(signature.as_ref())})
        }

        pub(super) fn require_import(&self) -> Value {
            let store = self.paths.settings.as_ref().unwrap();
            crate::owner::settings::use_legacy_format(store);
            let manager = store.load().unwrap().unwrap();
            self.paths.policy.install(&manager).unwrap();
            self.shared.0.lock().unwrap().administration.manager = Some(manager);
            self.call(json!({"kind":"settingsStatus"}), None)["settings"]["migration"].clone()
        }

        pub(super) fn configured_locked() -> Self {
            let harness = Self::new();
            let review = harness.review();
            let challenge = harness.authenticate(&review);
            assert_eq!(
                harness.proof(&review, &challenge)["kind"],
                "settingsApplied"
            );
            assert_eq!(
                harness.call(json!({"kind":"vaultLock"}), None)["state"],
                "locked"
            );
            harness
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.client.invalidate();
        }
    }

    #[test]
    fn a_large_account_still_stages_when_picker_metadata_is_unavailable() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();
        let items: Vec<_> = (1..=1001)
            .map(|index| format!("22222222-2222-4222-8222-{index:012}"))
            .collect();
        let credential = crate::owner::test_support::vault::snapshot("github-write").credential;
        let snapshot = crate::owner::test_support::vault::catalogue(
            credential,
            &items.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let mut staged = harness.staged_cache();
        staged.identity = vault::fixture::put(
            &harness.paths.root.join("enrollments").join(&staged.slot),
            &snapshot,
        )
        .identity()
        .unwrap();
        staged.snapshot = snapshot.into();

        let reply = finish_enrollment(id, Ok(staged), &peer, &harness.shared).unwrap();
        assert!(matches!(
            reply,
            Reply::EnrollmentStaged {
                catalogue: StagedItemCatalogue::Unavailable,
                ..
            }
        ));
        assert!(crate::owner::protocol::encode_reply(&reply).is_ok());
        let state = harness.shared.0.lock().unwrap();
        assert!(state.administration.staged.is_some());
        assert!(
            state
                .administration
                .manager
                .as_ref()
                .unwrap()
                .record()
                .provider()
                .is_none()
        );
    }

    #[test]
    fn console_changes_during_enrollment_force_a_cold_completion_without_selecting_a_provider() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();
        let staged = harness.staged_cache();
        for _ in 0..2 {
            let mut state = harness.shared.0.lock().unwrap();
            state
                .host_events
                .record(crate::platform::HostSessionEvent::ConsoleChange);
            state.ensure_interactive().unwrap();
            assert!(!state.administration.staging.as_ref().unwrap().allow_warm);
        }

        let reply = finish_enrollment(id, Ok(staged), &peer, &harness.shared).unwrap();

        let Reply::EnrollmentStaged {
            ticket,
            provider,
            catalogue,
        } = reply
        else {
            panic!("expected an inactive enrollment");
        };
        let state = harness.shared.0.lock().unwrap();
        let staged = state.administration.staged.as_ref().unwrap();
        let StagedItemCatalogue::Available { items } = catalogue else {
            panic!("expected selectable item metadata");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "22222222-2222-4222-8222-222222222222");
        let encoded = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(encoded.as_object().unwrap().len(), 2);
        assert!(encoded["name"].is_string());
        assert_eq!(staged.ticket, ticket);
        assert!(staged.pin == provider);
        assert!(staged.snapshot.is_none());
        assert!(state.administration.staging.is_none());
        assert!(state.provider.snapshot().is_none());
        let record = state.administration.manager.as_ref().unwrap().record();
        assert_eq!(record.revision(), Revision(0));
        assert!(record.provider().is_none());
    }

    #[test]
    fn a_console_change_discards_a_completed_enrollments_warm_snapshot_and_keeps_its_ticket() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();
        let reply =
            finish_enrollment(id, Ok(harness.staged_cache()), &peer, &harness.shared).unwrap();
        let Reply::EnrollmentStaged { ticket, .. } = reply else {
            panic!("expected an inactive enrollment");
        };
        let mut state = harness.shared.0.lock().unwrap();
        assert!(
            state
                .administration
                .staged
                .as_ref()
                .unwrap()
                .snapshot
                .is_some()
        );

        state
            .host_session_event(crate::platform::HostSessionEvent::ConsoleChange)
            .unwrap();

        let staged = state.administration.staged.as_ref().unwrap();
        assert_eq!(staged.ticket, ticket);
        assert!(staged.snapshot.is_none());
        assert!(state.provider.snapshot().is_none());
    }

    #[test]
    fn a_console_change_does_not_mask_a_failed_provider_login_or_block_a_retry() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();
        harness
            .shared
            .0
            .lock()
            .unwrap()
            .host_events
            .record(crate::platform::HostSessionEvent::ConsoleChange);

        let failed = finish_enrollment(
            id,
            Err(vault::Error::from(qm_providers::ProviderError::InvalidCredentials).into()),
            &peer,
            &harness.shared,
        );

        assert!(matches!(
            failed,
            Err(Error::Vault(vault::Error::Provider(
                qm_providers::ProviderError::InvalidCredentials
            )))
        ));
        assert_ne!(begin_enrollment(&peer, &harness.shared).unwrap(), id);
    }

    #[test]
    fn cancel_disconnect_and_host_revocation_remove_enrollment_reservations_and_cold_drafts() {
        for completed in [false, true] {
            for action in [
                "cancel",
                "disconnect",
                "lock",
                "screen-lock",
                "sleep",
                "wake",
                "inactive",
                "logout",
            ] {
                let harness = Harness::new();
                let peer = harness.peer();
                let id = begin_enrollment(&peer, &harness.shared).unwrap();
                let mut staged = Some(harness.staged_cache());
                if completed {
                    finish_enrollment(id, Ok(staged.take().unwrap()), &peer, &harness.shared)
                        .unwrap();
                }
                {
                    let mut state = harness.shared.0.lock().unwrap();
                    state
                        .host_session_event(HostSessionEvent::ConsoleChange)
                        .unwrap();
                    match action {
                        "cancel" => state.administration.cancel_changes(),
                        "disconnect" => state.administration.disconnect(peer.id()),
                        "lock" => state.lock_vault().unwrap(),
                        action => state
                            .host_session_event(match action {
                                "screen-lock" => HostSessionEvent::ScreenLock,
                                "sleep" => HostSessionEvent::Sleep,
                                "wake" => HostSessionEvent::Wake,
                                "inactive" => HostSessionEvent::Inactive,
                                "logout" => HostSessionEvent::Logout,
                                _ => unreachable!(),
                            })
                            .unwrap(),
                    }
                }
                let completion = staged.map_or_else(|| Err(ControlError::Unavailable.into()), Ok);

                assert!(
                    finish_enrollment(id, completion, &peer, &harness.shared).is_err(),
                    "{action}, completed={completed}"
                );

                let state = harness.shared.0.lock().unwrap();
                assert!(state.administration.staging.is_none(), "{action}");
                assert!(state.administration.staged.is_none(), "{action}");
                assert!(state.provider.snapshot().is_none(), "{action}");
            }
        }
    }

    #[test]
    fn changed_provider_revision_or_settings_session_rejects_the_original_enrollment_completion() {
        for changed in ["provider", "revision", "session"] {
            let harness = Harness::new();
            let peer = harness.peer();
            let id = begin_enrollment(&peer, &harness.shared).unwrap();
            let staged = harness.staged_cache();
            {
                let mut state = harness.shared.0.lock().unwrap();
                match changed {
                    "provider" => state.provider.lock().unwrap(),
                    "revision" => {
                        state.administration.manager =
                            Some(crate::owner::test_support::vault::manager())
                    }
                    "session" => {
                        state.administration.session.as_mut().unwrap().id = random().unwrap()
                    }
                    _ => unreachable!(),
                }
            }

            assert!(
                matches!(
                    finish_enrollment(id, Ok(staged), &peer, &harness.shared),
                    Err(Error::State(Fault::Canceled))
                ),
                "{changed}"
            );

            let state = harness.shared.0.lock().unwrap();
            assert!(state.administration.staging.is_none());
            assert!(state.administration.staged.is_none());
            assert!(state.provider.snapshot().is_none());
        }
    }

    #[test]
    fn a_stale_enrollment_completion_cannot_cancel_or_complete_a_new_login() {
        for succeeded in [false, true] {
            let harness = Harness::new();
            let peer = harness.peer();
            let first = begin_enrollment(&peer, &harness.shared).unwrap();
            let first_result = if succeeded {
                Ok(harness.staged_cache())
            } else {
                Err(ControlError::Unavailable.into())
            };
            harness.call(json!({"kind":"settingsCancel"}), None);
            let next = begin_enrollment(&peer, &harness.shared).unwrap();

            assert!(matches!(
                finish_enrollment(first, first_result, &peer, &harness.shared),
                Err(Error::State(Fault::Canceled))
            ));

            assert_eq!(
                harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .administration
                    .staging
                    .as_ref()
                    .unwrap()
                    .id,
                next
            );
            assert!(matches!(
                finish_enrollment(next, Ok(harness.staged_cache()), &peer, &harness.shared),
                Ok(Reply::EnrollmentStaged { .. })
            ));
        }
    }

    #[test]
    fn a_rejected_duplicate_native_login_does_not_cancel_the_current_reservation() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();

        let duplicate = harness.call(json!({"kind":"stageEnrollment", "server":"https://example.invalid", "email":"dummy@example.invalid", "password":""}), None);

        assert_eq!(duplicate["code"], "busy", "{duplicate}");
        assert!(matches!(
            finish_enrollment(id, Ok(harness.staged_cache()), &peer, &harness.shared),
            Ok(Reply::EnrollmentStaged { .. })
        ));
    }

    #[test]
    fn a_rejected_settings_review_does_not_cancel_the_current_enrollment() {
        let harness = Harness::new();
        let peer = harness.peer();
        let id = begin_enrollment(&peer, &harness.shared).unwrap();

        let duplicate = harness.call(
            json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"}, "provider":{"kind":"keep"}}),
            None,
        );

        assert_eq!(duplicate["code"], "busy", "{duplicate}");
        assert!(matches!(
            finish_enrollment(id, Ok(harness.staged_cache()), &peer, &harness.shared),
            Ok(Reply::EnrollmentStaged { .. })
        ));
    }

    #[test]
    fn console_changes_preserve_an_inactive_enrollment_for_a_fresh_settings_review() {
        let harness = Harness::new();
        let first = harness.review();
        {
            let mut state = harness.shared.0.lock().unwrap();
            state
                .host_session_event(crate::platform::HostSessionEvent::ConsoleChange)
                .unwrap();
            assert!(state.administration.manager.as_ref().unwrap().idle());
            assert!(state.administration.staged.is_some());
            assert!(state.provider.snapshot().is_none());
        }
        let next = harness.call(
            json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"}, "provider":{"kind":"staged","ticket":"selection"}}),
            None,
        );
        assert_eq!(next["kind"], "settingsReview", "{next}");
        assert_ne!(first["id"], next["review"]["id"]);
        let state = harness.shared.0.lock().unwrap();
        let peer = &state.administration.session.as_ref().unwrap().peer;
        let context = state
            .administration
            .manager
            .as_ref()
            .unwrap()
            .context(next["review"]["id"].as_str().unwrap(), peer.id().value())
            .unwrap();
        assert!(context.warm.is_none());
        assert!(context.source.is_some());
        assert!(context.identity.is_some());
        drop(state);
        let without_presence = harness.call(
            json!({"kind":"settingsPresence", "id":next["review"]["id"], "authenticated":u64::from(now().unwrap())}),
            None,
        );
        assert_eq!(without_presence["kind"], "error");
        let state = harness.shared.0.lock().unwrap();
        assert!(state.provider.snapshot().is_none());
        assert_eq!(
            state
                .administration
                .manager
                .as_ref()
                .unwrap()
                .record()
                .revision(),
            Revision(0)
        );
    }

    #[test]
    fn a_cold_enrollment_rejects_cache_substitution_before_a_fresh_review() {
        let harness = Harness::new();
        harness.review();
        harness
            .shared
            .0
            .lock()
            .unwrap()
            .host_session_event(crate::platform::HostSessionEvent::ConsoleChange)
            .unwrap();
        vault::fixture::put(
            &harness.paths.root.join("enrollments").join("a".repeat(32)),
            &crate::owner::test_support::vault::snapshot_at(
                "github-write",
                "22222222-2222-4222-8222-222222222222",
                [9; 16],
                crate::owner::test_support::wall(1_792_483_201),
            ),
        );

        let next = harness.call(
            json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"}, "provider":{"kind":"staged","ticket":"selection"}}),
            None,
        );

        assert_eq!(next["kind"], "error", "{next}");
        let state = harness.shared.0.lock().unwrap();
        let manager = state.administration.manager.as_ref().unwrap();
        assert!(manager.idle());
        assert_eq!(manager.record().revision(), Revision(0));
        assert!(manager.record().provider().is_none());
        assert!(state.provider.snapshot().is_none());
    }

    #[test]
    fn an_expired_cold_enrollment_cannot_be_used_to_prepare_settings() {
        let harness = Harness::new();
        harness.review();
        {
            let mut state = harness.shared.0.lock().unwrap();
            state
                .host_session_event(crate::platform::HostSessionEvent::ConsoleChange)
                .unwrap();
            let expires = state.administration.staged.as_ref().unwrap().expires;
            state.administration.expire(expires);
        }

        let next = harness.call(
            json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"}, "provider":{"kind":"staged","ticket":"selection"}}),
            None,
        );

        assert_eq!(next["kind"], "error", "{next}");
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

    #[test]
    fn console_changes_release_native_settings_contexts_and_reject_old_proofs() {
        let harness = Harness::new();
        let first = harness.review();
        let first_challenge = harness.authenticate(&first);
        harness
            .shared
            .0
            .lock()
            .unwrap()
            .host_session_event(crate::platform::HostSessionEvent::ConsoleChange)
            .unwrap();
        let next = harness.call(
            json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"}, "provider":{"kind":"keep"}}),
            None,
        );
        assert_eq!(next["kind"], "settingsReview", "{next}");
        let next_challenge = harness.authenticate(&next["review"]);
        assert_eq!(harness.proof(&first, &first_challenge)["kind"], "error");
        assert_eq!(
            harness.proof(&next["review"], &next_challenge)["kind"],
            "settingsApplied"
        );
    }

    #[test]
    fn vault_unlock_preparation_preserves_settings_and_cancel_releases_the_reservation() {
        let harness = Harness::configured_locked();
        let before = harness.call(json!({"kind":"settingsStatus"}), None)["settings"].clone();
        assert_eq!(
            harness.call(json!({"kind":"prepareVaultUnlock","revision":0}), None)["kind"],
            "error"
        );
        let prepared = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        assert_eq!(prepared["kind"], "vaultUnlockReview", "{prepared}");
        assert_eq!(prepared["review"]["revision"], 1);
        assert_eq!(prepared["review"]["provider"], before["provider"]);
        assert_eq!(prepared["review"]["session"], before["session"]);
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"],
            before
        );
        assert_eq!(
            harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None)["kind"],
            "error"
        );
        assert_eq!(
            harness.call(
                json!({"kind":"vaultUnlockCancel","id":prepared["review"]["id"]}),
                None
            )["kind"],
            "canceled"
        );
        let next = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        assert_eq!(next["kind"], "vaultUnlockReview", "{next}");
        assert_ne!(next["review"]["id"], prepared["review"]["id"]);
        assert_eq!(
            harness.call(
                json!({"kind":"vaultUnlockCancel","id":prepared["review"]["id"]}),
                None
            )["kind"],
            "unknownOperation"
        );
        assert_eq!(
            harness.call(
                json!({"kind":"vaultUnlockCancel","id":next["review"]["id"]}),
                None
            )["kind"],
            "canceled"
        );
    }

    #[test]
    fn vault_unlock_requires_a_native_context_and_cleans_up_after_failure() {
        let harness = Harness::configured_locked();
        let prepared = harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None);
        assert_eq!(prepared["kind"], "vaultUnlockReview", "{prepared}");
        let rejected = harness.call(json!({"kind":"vaultUnlockPresence","id":prepared["review"]["id"],"authenticated":u64::from(now().unwrap())}), None);
        assert_eq!(rejected["kind"], "error");
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
        assert_eq!(
            harness.call(json!({"kind":"prepareVaultUnlock","revision":1}), None)["kind"],
            "vaultUnlockReview"
        );
    }

    #[test]
    fn settings_native_ipc_publishes_only_the_signed_selection_and_rejects_replay() {
        let harness = Harness::new();
        let review = harness.review();
        assert!(
            harness
                .paths
                .load_policy()
                .unwrap()
                .current()
                .unwrap()
                .1
                .is_err()
        );
        let challenge = harness.authenticate(&review);
        let reply = harness.proof(&review, &challenge);
        assert_eq!(reply["kind"], "settingsApplied", "{reply}");
        assert_eq!(reply["revision"], 1);
        assert!(
            harness
                .paths
                .load_policy()
                .unwrap()
                .current()
                .unwrap()
                .1
                .is_ok()
        );
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["provider"]["slot"],
            "a".repeat(32)
        );
        assert_eq!(harness.proof(&review, &challenge)["kind"], "error");
    }

    #[test]
    fn native_import_keeps_previous_settings_visible_but_inactive_and_requires_authenticated_unwrap()
     {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let document: Value =
            serde_json::from_slice(&BASE64.decode(review["document"].as_str().unwrap()).unwrap())
                .unwrap();
        let migration = harness.require_import();
        let status = harness.call(json!({"kind":"settingsStatus"}), None);
        assert_eq!(status["settings"]["state"], "migrationRequired");
        assert!(status["settings"]["provider"].is_null());
        assert_eq!(migration["settings"], document["proposed"]["settings"]);
        assert_eq!(migration["provider"], document["proposed"]["provider"]);
        let importing = harness.call(
            json!({"kind":"prepareSettingsImport", "id":migration["source"]["id"]}),
            None,
        );
        assert_eq!(importing["kind"], "settingsReview", "{importing}");
        let context = unsafe { LAContext::new() };
        let response = harness.call(json!({"kind":"settingsPresence", "id":importing["review"]["id"], "authenticated":u64::from(now().unwrap())}), Some(&context));
        assert_eq!(response["kind"], "error");
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["state"],
            "migrationRequired"
        );
        assert!(
            harness
                .paths
                .settings
                .as_ref()
                .unwrap()
                .load::<()>()
                .unwrap()
                .unwrap()
                .migration()
                .is_some()
        );
    }

    #[test]
    fn native_import_cannot_select_another_source_or_substituted_cache() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let migration = harness.require_import();
        assert_eq!(
            harness.call(
                json!({"kind":"prepareSettingsImport", "id":"different"}),
                None
            )["kind"],
            "error"
        );
        let pin: ProviderPin = serde_json::from_value(migration["provider"].clone()).unwrap();
        vault::fixture::put(
            &pin.root(&harness.paths.root),
            &crate::owner::test_support::vault::snapshot_for_account(
                "github-write",
                "22222222-2222-4222-8222-222222222222",
                [3; 16],
                crate::owner::test_support::wall(1_792_483_200),
                "33333333-3333-4333-8333-333333333333",
            ),
        );
        assert_eq!(
            harness.call(
                json!({"kind":"prepareSettingsImport", "id":migration["source"]["id"]}),
                None
            )["kind"],
            "error"
        );
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["state"],
            "migrationRequired"
        );
    }

    #[test]
    fn native_import_uses_the_existing_signature_flow_and_does_not_recur_after_publication() {
        let harness = Harness::new();
        let prepared = harness.call(json!({"kind":"prepareSettings", "revision":0, "settings":{"github":null,"mutations":"deny"},"provider":{"kind":"keep"}}), None);
        let challenge = harness.authenticate(&prepared["review"]);
        assert_eq!(
            harness.proof(&prepared["review"], &challenge)["kind"],
            "settingsApplied"
        );
        let migration = harness.require_import();
        let prepared = harness.call(
            json!({"kind":"prepareSettingsImport", "id":migration["source"]["id"]}),
            None,
        );
        harness.call(
            json!({"kind":"settingsCancel", "id":prepared["review"]["id"]}),
            None,
        );
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["state"],
            "migrationRequired"
        );
        let prepared = harness.call(
            json!({"kind":"prepareSettingsImport", "id":migration["source"]["id"]}),
            None,
        );
        let challenge = harness.authenticate(&prepared["review"]);
        assert_eq!(
            harness.proof(&prepared["review"], &challenge)["kind"],
            "settingsApplied"
        );
        let status = harness.call(json!({"kind":"settingsStatus"}), None);
        assert_eq!(status["settings"]["state"], "configured");
        assert!(status["settings"]["migration"].is_null());
        assert!(
            harness
                .paths
                .settings
                .as_ref()
                .unwrap()
                .load::<()>()
                .unwrap()
                .unwrap()
                .migration()
                .is_none()
        );
    }

    #[test]
    fn settings_native_ipc_operation_registration_can_resume_after_canceled_settings() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let registration =
            json!({"kind":"enroll", "publicKey":BASE64.encode(harness.key.public_key().as_ref())});
        assert_eq!(harness.call(registration.clone(), None)["kind"], "enrolled");
        harness.call(json!({"kind":"settingsCancel"}), None);
        assert_eq!(harness.call(registration.clone(), None)["kind"], "enrolled");
        assert_eq!(harness.call(json!({"kind":"next"}), None)["kind"], "idle");
        let intruder = harness._native.client();
        let rejected: Value = serde_json::from_slice(&send(
            &intruder,
            &serde_json::to_vec(&registration).unwrap(),
            None,
        ))
        .unwrap();
        assert_eq!(rejected["kind"], "error");
        intruder.invalidate();
        assert_eq!(
            harness.call(
                json!({"kind":"enroll", "publicKey":BASE64.encode([4;65])}),
                None
            )["kind"],
            "error"
        );
        assert_eq!(harness.call(json!({"kind":"next"}), None)["kind"], "idle");
    }

    #[test]
    fn settings_persisted_status_follows_the_protected_selection_without_unlocking() {
        let harness = Harness::new();
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        assert_eq!(
            harness.proof(&review, &challenge)["kind"],
            "settingsApplied"
        );
        let status = crate::owner::settings::persisted_status(
            &harness.paths.root,
            harness.paths.settings.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(status.state, crate::VaultState::Locked);
        assert_eq!(
            status.binding.unwrap(),
            harness
                .shared
                .0
                .lock()
                .unwrap()
                .provider
                .snapshot()
                .unwrap()
                .binding()
                .clone()
        );
    }

    #[test]
    fn settings_native_ipc_cancel_or_cache_replacement_prevents_selection() {
        for failure in ["cancel", "cache", "missing-context", "signature"] {
            let harness = Harness::new();
            let review = harness.review();
            let challenge = harness.authenticate(&review);
            match failure {
                "cancel" => {
                    harness.call(json!({"kind":"settingsCancel", "id":review["id"]}), None);
                }
                "cache" => {
                    std::fs::write(
                        harness
                            .paths
                            .root
                            .join("enrollments")
                            .join("a".repeat(32))
                            .join("vault")
                            .join("vault.cache"),
                        b"changed",
                    )
                    .unwrap();
                }
                "missing-context" => {
                    harness.call(json!({"kind":"settingsPresence", "id":review["id"], "authenticated":u64::from(now().unwrap())}), None);
                }
                _ => {
                    harness.call(
                        json!({"kind":"settingsProof", "id":review["id"], "signature":"AA=="}),
                        None,
                    );
                }
            }
            assert_eq!(
                harness.proof(&review, &challenge)["kind"],
                "error",
                "{failure}"
            );
            let status = harness.call(json!({"kind":"settingsStatus"}), None);
            assert_eq!(status["settings"]["revision"], 0, "{failure}");
            assert!(status["settings"]["provider"].is_null());
            assert!(
                harness
                    .shared
                    .0
                    .lock()
                    .unwrap()
                    .administration
                    .manager
                    .as_ref()
                    .unwrap()
                    .idle()
            );
        }
    }

    #[test]
    fn settings_native_ipc_cancel_during_protected_publication_reports_already_admitted() {
        let (store, entered, release) = crate::owner::settings::Store::paused();
        let harness = Harness::with_store(store);
        let review = harness.review();
        let challenge = harness.authenticate(&review);
        let proof = start_send(
            &harness.client,
            &serde_json::to_vec(&harness.proof_command(&review, &challenge)).unwrap(),
            None,
        );
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        let reply = harness.call(json!({"kind":"settingsCancel"}), None);
        let during = harness.call(json!({"kind":"settingsStatus"}), None);
        release.send(()).unwrap();
        let applied: Value =
            serde_json::from_slice(&proof.recv_timeout(Duration::from_secs(3)).unwrap().unwrap())
                .unwrap();
        assert_eq!(reply["kind"], "alreadyAdmitted");
        assert_eq!(during["settings"]["state"], "applying");
        assert_eq!(applied["kind"], "settingsApplied", "{applied}");
        assert_eq!(
            harness.call(json!({"kind":"settingsStatus"}), None)["settings"]["revision"],
            1
        );
    }
}
