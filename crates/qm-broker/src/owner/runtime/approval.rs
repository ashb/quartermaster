use super::error::{Error, Fault, Result};
use super::{ServicePaths, Shared, state::OwnerState};
use crate::owner::{
    dispatch::CredentialSelection,
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
    process::Command,
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
}

pub(super) use crate::owner::protocol::ProviderPresentation;

impl ProviderPresentation {
    pub(super) fn new(identity: &CacheIdentity, generation: ProviderGeneration) -> Self {
        let binding = &identity.binding;
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
pub(super) fn request_approval(
    id: OperationId,
    principal: &Arc<VerifiedPrincipal>,
    mut peer: PeerIdentity,
    created: MonotonicTimestamp,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<mpsc::Receiver<ApprovalCompletion>> {
    let generation = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?
        .provider
        .generation();
    let source = paths.vault_source()?;
    let identity = source.identity()?;
    let (operation, authorization, read_roots, frozen) = {
        let state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        if state.provider.generation() != generation {
            return Err(Error::State(Fault::ProviderChanged));
        }
        if identity.binding.field() != &qm_providers::CredentialField::LoginPassword {
            return Err(Error::State(Fault::UnsupportedField));
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
        )
    };
    peer.observe_command_line();
    let context = ReviewContext {
        provider: ProviderPresentation::new(&frozen.identity, frozen.generation),
        operation_id: id.to_string(),
        created,
        read_roots,
        process_chain: peer.process_chain(),
        peer: peer.presentation(),
    };
    let document = crate::owner::review::ReviewDocument::new(operation, authorization, context)?;
    if !Command::new("/usr/bin/open")
        .arg("-a")
        .arg(&paths.app)
        .status()?
        .success()
    {
        return Err(Error::State(Fault::LaunchFailed));
    }
    let state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    let (state, _) = shared
        .1
        .wait_timeout_while(state, Duration::from_secs(15), |s| s.ui.is_none())
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    drop(state);
    let current = paths.vault_source()?;
    let policy = paths.load_policy();
    let mut state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    state.refresh_policy(&policy)?;
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
        principal: Arc::clone(principal),
        request: document,
        provider: frozen,
        context_lease: None,
        delivered: false,
        completion,
    });
    Ok(receive)
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
    let pending = state
        .pending
        .as_mut()
        .filter(|pending| pending.id == id)
        .ok_or_else(|| Error::State(Fault::PendingMissing))?;
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
    let pending = state
        .pending
        .as_ref()
        .filter(|pending| pending.id == id)
        .ok_or_else(|| Error::State(Fault::Canceled))?;
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
    let selection = CredentialSelection::at_generation(snapshot, state.provider.generation());
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
}
