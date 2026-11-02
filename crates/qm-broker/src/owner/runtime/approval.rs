use super::error::{Error, Fault, Result};
use super::{ServicePaths, Shared, state::OwnerState};
use crate::owner::{
    identity::VerifiedPrincipal,
    operation::OperationId,
    protocol::{ApprovalChallenge, ApprovalReview, Reply},
    provider_lifecycle::{CacheIdentity, ProviderGeneration},
};
use crate::platform::macos::ipc::{self, ConnectionId};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_macos::{
    peer_identity::PeerIdentity,
    presence_clock::{MonotonicTimestamp, monotonic_raw as presence_now},
};
use qm_providers::ApprovalSession;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use std::{
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
pub(super) struct FrozenProvider {
    pub(super) source: Option<crate::owner::vault::Source>,
    pub(super) identity: CacheIdentity,
    pub(super) generation: ProviderGeneration,
}

pub(super) struct ApprovalDelivery {
    pub(super) id: OperationId,
    pub(super) principal: Arc<VerifiedPrincipal>,
    pub(super) request: crate::owner::review::ReviewDocument<ReviewContext>,
    pub(super) provider: FrozenProvider,
    pub(super) context_lease: Option<ipc::ContextLease>,
    pub(super) delivered: bool,
    pub(super) completion: mpsc::SyncSender<ApprovalCompletion>,
    pub(super) _queue_ticket: Option<Arc<crate::owner::approval_queue::Ticket>>,
    pub(super) authenticated: Option<MonotonicTimestamp>,
}

pub(super) use crate::owner::protocol::ProviderPresentation;

impl ProviderPresentation {
    pub(super) fn new(
        identity: &CacheIdentity,
        generation: ProviderGeneration,
        binding: &qm_providers::ProviderBinding,
    ) -> Self {
        Self {
            server: binding.server().into(),
            account: binding.account_id().into(),
            email: binding.email().into(),
            item: binding.item_id().into(),
            field: "LoginPassword".into(),
            role: binding.role().into(),
            enrollment: identity.scope.clone(),
            generation: generation.value(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReviewContext {
    pub(super) provider: ProviderPresentation,
    pub(super) operation_id: String,
    pub(super) created: MonotonicTimestamp,
    pub(super) peer: qm_macos::peer_identity::PeerPresentation,
    pub(super) process_chain: Vec<String>,
    pub(super) read_roots: Vec<crate::owner::identity::RootDescription>,
}

impl crate::owner::review::CredentialContext for ReviewContext {
    fn credential_role(&self) -> &str {
        &self.provider.role
    }
}

impl ApprovalDelivery {
    pub(super) fn check(&self, state: &OwnerState) -> Result<()> {
        self.check_deadline(presence_now()?)?;
        if self.provider.generation != state.provider.generation() {
            return Err(Fault::ProviderChanged.into());
        }
        Ok(())
    }

    fn check_deadline(&self, now: MonotonicTimestamp) -> Result<()> {
        if let Some(authenticated) = self.authenticated {
            check_authenticated_deadline(authenticated, now)
        } else if now
            .checked_duration_since(self.created())
            .is_none_or(|age| age >= Duration::from_secs(120))
        {
            Err(Fault::ApprovalExpired.into())
        } else {
            Ok(())
        }
    }

    pub(super) fn created(&self) -> MonotonicTimestamp {
        self.request.context().created
    }

    pub(super) fn review(
        &self,
        ui: &UiSession,
        policy: [u8; 32],
        nonce: [u8; 32],
    ) -> ApprovalReview {
        ApprovalReview {
            id: self.id.to_string(),
            created: self.created(),
            session: BASE64.encode(ui.session.id()),
            policy: BASE64.encode(policy),
            nonce: BASE64.encode(nonce),
            request: BASE64.encode(self.request.bytes()),
            request_digest: BASE64.encode(digest(&SHA256, self.request.bytes())),
            provider: self.request.context().provider.clone(),
        }
    }
}
pub(super) struct ApprovalCompletion {
    pub(super) id: OperationId,
    pub(super) principal: Arc<VerifiedPrincipal>,
}
pub(super) struct UiSession {
    pub(super) session: ApprovalSession,
    pub(super) connection: Option<ConnectionId>,
}

fn check_frontend(expected: Option<&str>, app: &std::path::Path) -> Result<()> {
    let expected = expected.ok_or(Error::State(Fault::UiDisconnected))?;
    let installed = qm_macos::peer_identity::requirement_for_path(app)
        .map_err(|_| Error::State(Fault::UiDisconnected))?;
    if installed != expected {
        return Err(Error::State(Fault::FrontendChanged));
    }
    Ok(())
}

pub(super) fn wait_for_turn(
    principal: &VerifiedPrincipal,
    stream: &std::os::unix::net::UnixStream,
    created: MonotonicTimestamp,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Arc<crate::owner::approval_queue::Ticket>> {
    let ticket = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.refresh_policy(&paths.load_policy())?;
        state.ensure_interactive()?;
        state
            .approval_queue
            .enqueue()
            .ok_or(Fault::ApprovalPending)?
    };
    loop {
        principal.revalidate()?;
        if !super::http::connected(stream) {
            return Err(Fault::Canceled.into());
        }
        if presence_now()?
            .checked_duration_since(created)
            .is_none_or(|age| age >= Duration::from_secs(120))
        {
            return Err(Fault::ApprovalExpired.into());
        }
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.refresh_policy(&paths.load_policy())?;
        state.ensure_interactive()?;
        if !state.approval_queue.contains(&ticket) {
            return Err(Fault::Canceled.into());
        }
        if state.pending.is_none() && state.approval_queue.is_front(&ticket) {
            return Ok(ticket);
        }
        drop(
            shared
                .1
                .wait_timeout(state, Duration::from_millis(50))
                .map_err(|_| Fault::StateUnavailable)?,
        );
    }
}

pub(super) fn request_approval(
    id: OperationId,
    principal: &Arc<VerifiedPrincipal>,
    mut peer: PeerIdentity,
    created: MonotonicTimestamp,
    shared: &Shared,
    paths: &ServicePaths,
    stream: &std::os::unix::net::UnixStream,
) -> Result<mpsc::Receiver<ApprovalCompletion>> {
    {
        let state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.check_review_context(id, principal)?;
    }
    let slot = wait_for_turn(principal, stream, created, shared, paths)?;
    let (generation, frontend_requirement) = {
        let state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.check_review_context(id, principal)?;
        (
            state.provider.generation(),
            state.frontend_requirement.clone(),
        )
    };
    check_frontend(frontend_requirement.as_deref(), &paths.app)?;
    let source = paths.vault_source()?;
    let identity = source.identity()?;
    let (operation, authorization, read_roots, frozen, binding) = {
        let state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        if state.provider.generation() != generation {
            return Err(Error::State(Fault::ProviderChanged));
        }
        (
            state.operations.request(id, principal)?.clone(),
            state.operations.grant_claims(id, principal)?,
            state.operations.root_choices(id, principal)?,
            FrozenProvider {
                source: Some(source),
                identity,
                generation,
            },
            state.github_binding()?,
        )
    };
    peer.observe_display_context();
    let context = ReviewContext {
        provider: ProviderPresentation::new(&frozen.identity, frozen.generation, &binding),
        operation_id: id.to_string(),
        created,
        read_roots,
        process_chain: peer.process_chain(),
        peer: peer.presentation(),
    };
    let document = crate::owner::review::ReviewDocument::new(operation, authorization, context)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    crate::platform::macos::application::launch_application(&paths.app, deadline)
        .map_err(|_| Error::State(Fault::LaunchFailed))?;
    let state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    let (state, _) = shared
        .1
        .wait_timeout_while(
            state,
            deadline.saturating_duration_since(Instant::now()),
            |s| s.ui.is_none(),
        )
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    drop(state);
    let current = paths.vault_source()?;
    let policy = paths.load_policy();
    let mut state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    state.refresh_policy(&policy)?;
    if !state.approval_queue.is_front(&slot) {
        return Err(Fault::Canceled.into());
    }
    if state.pending.is_some() {
        return Err(Error::State(Fault::ApprovalPending));
    }
    if state.provider.generation() != frozen.generation
        || current.revision != frozen.identity.revision
    {
        return Err(Error::State(Fault::ProviderChanged));
    }
    state.operations.bind_review(id, principal, &document)?;
    let OwnerState { operations, ui, .. } = &mut *state;
    let ui = ui
        .as_ref()
        .ok_or_else(|| Error::State(Fault::UiDisconnected))?;
    operations.begin_approval(id, principal, &ui.session)?;
    let (completion, receive) = mpsc::sync_channel(1);
    state.pending = Some(ApprovalDelivery {
        id,
        _queue_ticket: Some(slot),
        authenticated: None,
        principal: Arc::clone(principal),
        request: document,
        provider: frozen,
        context_lease: None,
        delivered: false,
        completion,
    });
    Ok(receive)
}

pub(super) fn check_authenticated_deadline(
    authenticated: MonotonicTimestamp,
    now: MonotonicTimestamp,
) -> Result<()> {
    if now
        .checked_duration_since(authenticated)
        .is_none_or(|age| age >= Duration::from_secs(30))
    {
        return Err(Fault::ApprovalExpired.into());
    }
    Ok(())
}

pub(super) fn proof(id: &str, signature: &[u8], state: &mut OwnerState) -> Result<Reply> {
    state.ensure_interactive()?;
    let id = OperationId::parse(id)?;
    let pending = state
        .pending
        .as_ref()
        .filter(|p| p.id == id && p.delivered)
        .ok_or(Fault::PendingMissing)?;
    pending.check(state)?;
    let authenticated = pending.authenticated.ok_or(Fault::ReviewNotPresented)?;
    check_authenticated_deadline(authenticated, presence_now()?)?;
    state.operations.proof(
        id,
        &pending.principal,
        &state.authorizer,
        signature,
        Instant::now(),
    )?;
    let pending = state.pending.as_mut().unwrap();
    pending.context_lease.take();
    pending
        .completion
        .send(ApprovalCompletion {
            id,
            principal: Arc::clone(&pending.principal),
        })
        .map_err(|_| Fault::Canceled)?;
    Ok(Reply::Accepted)
}

pub(super) fn begin_native_presence(
    id: OperationId,
    authenticated: MonotonicTimestamp,
    state: &mut OwnerState,
    policy: &super::PolicyInput,
    current: Result<CacheIdentity, crate::owner::vault::Error>,
) -> Result<
    Option<(
        crate::owner::vault::Source,
        crate::owner::provider_lifecycle::ProviderOperation,
    )>,
> {
    state.refresh_policy(policy)?;
    state.ensure_interactive()?;
    state
        .pending
        .as_ref()
        .filter(|p| p.id == id)
        .ok_or(Fault::PendingMissing)?
        .check(state)?;
    let pending = state.pending.as_mut().unwrap();
    if !pending.delivered {
        return Err(Error::State(Fault::ReviewNotPresented));
    }
    let anchor = Instant::now();
    let age = presence_now()?
        .checked_duration_since(authenticated)
        .filter(|age| *age < Duration::from_secs(30))
        .ok_or_else(|| Error::State(Fault::ApprovalExpired))?;
    let offset = authenticated
        .checked_duration_since(pending.created())
        .filter(|offset| *offset < Duration::from_secs(120))
        .ok_or_else(|| Error::State(Fault::ApprovalExpired))?;
    let frozen = &mut pending.provider;
    if frozen.generation != state.provider.generation() || current? != frozen.identity {
        return Err(Error::State(Fault::ProviderChanged));
    }
    let at = anchor
        .checked_sub(age + Duration::from_millis(1))
        .ok_or_else(|| Error::State(Fault::InvalidClock))?;
    state
        .operations
        .authentication(id, &pending.principal, at, anchor, offset)?;
    pending.authenticated = Some(authenticated);
    if state.provider.snapshot().is_some() {
        state.provider.snapshot_for(&frozen.identity)?;
        return Ok(None);
    }
    let operation = state.provider.begin_unlock(frozen.identity.clone())?;
    let source = frozen
        .source
        .take()
        .ok_or_else(|| Error::State(Fault::CacheOpening))?;
    Ok(Some((source, operation)))
}

pub(super) fn complete_native_presence(
    id: OperationId,
    state: &mut OwnerState,
    policy: &super::PolicyInput,
    current: Result<CacheIdentity, crate::owner::vault::Error>,
) -> Result<Reply> {
    state.refresh_policy(policy)?;
    state.ensure_interactive()?;
    let pending = state
        .pending
        .as_ref()
        .filter(|pending| pending.id == id)
        .ok_or_else(|| Error::State(Fault::Canceled))?;
    pending.check(state)?;
    let offset = state
        .operations
        .authentication_offset(id, &pending.principal)?;
    let authenticated = pending
        .created()
        .checked_add(offset)
        .ok_or_else(|| Error::State(Fault::InvalidClock))?;
    if presence_now()?
        .checked_duration_since(authenticated)
        .is_none_or(|age| age >= Duration::from_secs(30))
    {
        return Err(Error::State(Fault::ApprovalExpired));
    }
    let frozen = &pending.provider;
    let snapshot = state.provider.snapshot_for(&frozen.identity)?;
    let current = current?;
    if frozen.generation != state.provider.generation() || current != frozen.identity {
        return Err(Error::State(Fault::ProviderChanged));
    }
    let selection = state.github_selection(snapshot)?;
    let challenge = state
        .operations
        .challenge(id, &pending.principal, selection)?;
    let authenticated = pending
        .created()
        .checked_add(challenge.offset)
        .ok_or_else(|| Error::State(Fault::InvalidClock))?;
    let ui = state
        .ui
        .as_ref()
        .ok_or_else(|| Error::State(Fault::UiDisconnected))?;
    let policy = state.authorizer.policy_digest()?;
    let nonce = state.operations.approval_nonce(id, &pending.principal)?;
    let expires = authenticated
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| Error::State(Fault::InvalidClock))?;
    Ok(Reply::Challenge {
        authorization: ApprovalChallenge {
            review: pending.review(ui, policy, nonce),
            credential_digest: BASE64.encode(challenge.credential_digest),
            authenticated,
            expires,
            bytes: BASE64.encode(challenge.bytes),
        },
    })
}

pub(super) fn native_presence(
    id: &str,
    authenticated: MonotonicTimestamp,
    context: &qm_macos::cache_key::NativeAuthenticationContext<'_>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    let id = OperationId::parse(id)?;
    let result = (|| {
        let deadline = authenticated
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| Error::State(Fault::InvalidClock))?;
        let lease = connection.context_lease(deadline)?;
        let current = paths.vault_source().and_then(|source| source.identity());
        let policy = paths.load_policy();
        let work = {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            if !connection.is_connected()
                || state
                    .ui
                    .as_ref()
                    .is_none_or(|ui| ui.connection != Some(connection.id()))
            {
                return Err(Error::State(Fault::UiDisconnected));
            }
            let work = begin_native_presence(id, authenticated, &mut state, &policy, current)?;
            state.pending.as_mut().unwrap().context_lease = Some(lease);
            work
        };
        if let Some((source, operation)) = work {
            let result = presence_now().map_err(Error::from).and_then(|now| {
                if now
                    .checked_duration_since(authenticated)
                    .is_none_or(|age| age >= Duration::from_secs(30))
                {
                    return Err(Error::State(Fault::ApprovalExpired));
                }
                source.unlock_authenticated(context).map_err(Error::from)
            });
            let identity = paths.vault_source().and_then(|source| source.identity());
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            state.ensure_host_session()?;
            match result {
                Ok(snapshot) => state
                    .provider
                    .finish_unlock(operation, &identity?, snapshot)?,
                Err(error) => {
                    state.provider.release(&operation);
                    return Err(error);
                }
            }
        }
        let current = paths.vault_source().and_then(|source| source.identity());
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        complete_native_presence(id, &mut state, &policy, current)
    })();
    if result.is_err() {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == id)
        {
            state.cancel_pending();
        }
    }
    result
}

#[cfg(test)]
mod frontend_tests {
    use super::*;
    use qm_macos::peer_identity::requirement_for_path;

    #[test]
    fn waiting_request_advances_after_completion_but_not_after_global_revocation() {
        for invalidation in 0..3 {
            let (_directory, paths, _key, mut state, _receive) = super::super::tests::fixture();
            let policy = paths.load_policy();
            let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
            state.pending.as_mut().unwrap()._queue_ticket =
                Some(state.approval_queue.enqueue().unwrap());
            let shared = Arc::new((std::sync::Mutex::new(state), std::sync::Condvar::new()));
            let worker_shared = Arc::clone(&shared);
            let (stream, _caller) = std::os::unix::net::UnixStream::pair().unwrap();
            let (send, receive) = mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = wait_for_turn(
                    &principal,
                    &stream,
                    presence_now().unwrap(),
                    &worker_shared,
                    &paths,
                );
                send.send(result).unwrap();
            });
            assert!(matches!(
                receive.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            {
                let mut state = shared.0.lock().unwrap();
                match invalidation {
                    0 => state.cancel_pending(),
                    1 => state.disconnect_ui(),
                    _ => {
                        super::super::control::handle(
                            crate::owner::protocol::Client::RevokeReadGrant {
                                id: "aa".repeat(16),
                            },
                            &mut state,
                            &policy,
                        )
                        .unwrap();
                    }
                }
            }
            shared.1.notify_all();
            let result = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            if invalidation != 0 {
                assert!(matches!(result, Err(Error::State(Fault::Canceled))));
            } else {
                let ticket = result.unwrap();
                assert!(shared.0.lock().unwrap().approval_queue.is_front(&ticket));
            }
            worker.join().unwrap();
        }
    }

    #[test]
    fn expired_or_disconnected_waiters_never_take_an_approval_slot() {
        for disconnected in [false, true] {
            let (_directory, paths, _key, mut state, _receive) = super::super::tests::fixture();
            let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
            state.pending.as_mut().unwrap()._queue_ticket =
                Some(state.approval_queue.enqueue().unwrap());
            let shared = Arc::new((std::sync::Mutex::new(state), std::sync::Condvar::new()));
            let (stream, caller) = std::os::unix::net::UnixStream::pair().unwrap();
            let created = if disconnected {
                presence_now().unwrap()
            } else {
                0.into()
            };
            if disconnected {
                drop(caller);
            }
            let result = wait_for_turn(&principal, &stream, created, &shared, &paths);
            assert!(matches!(
                result,
                Err(Error::State(Fault::Canceled | Fault::ApprovalExpired))
            ));
            assert!(shared.0.lock().unwrap().pending.is_some());
        }
    }

    #[test]
    fn frontend_preflight_rejects_changed_missing_or_invalid_code() {
        let executable = std::env::current_exe().unwrap();
        let expected = requirement_for_path(&executable).unwrap();
        assert!(check_frontend(Some(&expected), &executable).is_ok());
        let other = requirement_for_path(std::path::Path::new("/usr/bin/true")).unwrap();
        assert_ne!(expected, other);
        assert!(matches!(
            check_frontend(Some(&other), &executable),
            Err(Error::State(Fault::FrontendChanged))
        ));
        assert!(matches!(
            check_frontend(None, &executable),
            Err(Error::State(Fault::UiDisconnected))
        ));
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("frontend");
        for exists in [false, true] {
            if exists {
                std::fs::write(&app, b"not signed code").unwrap();
            }
            assert!(matches!(
                check_frontend(Some(&expected), &app),
                Err(Error::State(Fault::UiDisconnected))
            ));
        }
    }
}
