use super::{ServicePaths, Shared, checked, failure, state::OwnerState};
use crate::owner::{
    dispatch::CredentialSelection,
    identity::VerifiedPrincipal,
    operation::OperationId,
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
use serde_json::{Value, json};
use std::{
    io,
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

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProviderPresentation {
    pub(super) server: String,
    pub(super) account: String,
    pub(super) email: String,
    pub(super) item: String,
    pub(super) field: &'static str,
    pub(super) role: String,
    pub(super) enrollment: String,
    pub(super) generation: u64,
}

impl ProviderPresentation {
    pub(super) fn new(identity: &CacheIdentity, generation: ProviderGeneration) -> Self {
        let binding = &identity.binding;
        Self {
            server: binding.server().into(),
            account: binding.account_id().into(),
            email: binding.email().into(),
            item: binding.item_id().into(),
            field: "LoginPassword",
            role: binding.role().into(),
            enrollment: identity.scope.clone(),
            generation: generation.value(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ReviewContext {
    pub(super) provider: ProviderPresentation,
    pub(super) operation_id: String,
    pub(super) created: MonotonicTimestamp,
    pub(super) peer: qm_macos::peer_identity::PeerPresentation,
    pub(super) process_chain: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApprovalReview<'a> {
    pub(super) id: String,
    pub(super) created: MonotonicTimestamp,
    pub(super) session: String,
    pub(super) policy: String,
    pub(super) nonce: String,
    pub(super) request: String,
    pub(super) request_digest: String,
    pub(super) provider: &'a ProviderPresentation,
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
    ) -> ApprovalReview<'_> {
        ApprovalReview {
            id: self.id.to_string(),
            created: self.created(),
            session: BASE64.encode(ui.session.id()),
            policy: BASE64.encode(policy),
            nonce: BASE64.encode(nonce),
            request: BASE64.encode(self.request.bytes()),
            request_digest: BASE64.encode(digest(&SHA256, self.request.bytes())),
            provider: &self.request.context().provider,
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
) -> io::Result<mpsc::Receiver<ApprovalCompletion>> {
    let (operation, authorization, frozen) = {
        let state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
        let source = crate::owner::vault::Source::capture(&paths.root)
            .map_err(|_| failure("cache unavailable"))?;
        let identity = source
            .identity()
            .map_err(|_| failure("cache unavailable"))?;
        if identity.binding.field() != &qm_providers::CredentialField::LoginPassword {
            return Err(failure("unsupported credential field"));
        }
        (
            checked(state.operations.request(id, principal))?.clone(),
            checked(state.operations.grant_claims(id, principal))?,
            FrozenProvider {
                source: Some(source),
                identity,
                generation: state.provider.generation(),
            },
        )
    };
    peer.observe_command_line();
    let context = ReviewContext {
        provider: ProviderPresentation::new(&frozen.identity, frozen.generation),
        operation_id: id.to_string(),
        created,
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
        return Err(failure("cannot launch approval app"));
    }
    let state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
    let (mut state, _) = shared
        .1
        .wait_timeout_while(state, Duration::from_secs(15), |s| s.ui.is_none())
        .map_err(|_| failure("state unavailable"))?;
    state.refresh_policy(paths)?;
    if state.pending.is_some() {
        return Err(failure("another approval is pending"));
    }
    if state.provider.generation() != frozen.generation
        || crate::owner::vault::Source::capture(&paths.root)
            .map_err(|_| failure("cache unavailable"))?
            .revision
            != frozen.identity.revision
    {
        return Err(failure("provider selection changed"));
    }
    checked(state.operations.bind_review(id, principal, &document))?;
    let OwnerState { operations, ui, .. } = &mut *state;
    let ui = ui
        .as_ref()
        .ok_or_else(|| failure("approval UI did not connect"))?;
    checked(operations.begin_approval(id, principal, &ui.session))?;
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
    paths: &ServicePaths,
) -> io::Result<
    Option<(
        crate::owner::vault::Source,
        crate::owner::provider_lifecycle::ProviderOperation,
    )>,
> {
    state.refresh_policy(paths)?;
    let pending = state
        .pending
        .as_mut()
        .filter(|pending| pending.id == id)
        .ok_or_else(|| failure("no matching pending request"))?;
    if !pending.delivered {
        return Err(failure("review has not been presented"));
    }
    let anchor = Instant::now();
    let age = presence_now()?
        .checked_duration_since(authenticated)
        .filter(|age| *age < Duration::from_secs(30))
        .ok_or_else(|| failure("expired authentication"))?;
    let offset = authenticated
        .checked_duration_since(pending.created())
        .filter(|offset| *offset < Duration::from_secs(120))
        .ok_or_else(|| failure("expired pending request"))?;
    let frozen = &mut pending.provider;
    if frozen.generation != state.provider.generation()
        || crate::owner::vault::Source::capture(&paths.root)
            .and_then(|source| source.identity())
            .map_err(|_| failure("cache unavailable"))?
            != frozen.identity
    {
        return Err(failure("provider selection changed"));
    }
    let at = anchor
        .checked_sub(age + Duration::from_millis(1))
        .ok_or_else(|| failure("invalid presence clock"))?;
    checked(
        state
            .operations
            .authentication(id, &pending.principal, at, anchor, offset),
    )?;
    if state.provider.snapshot().is_some() {
        checked(state.provider.snapshot_for(&frozen.identity))?;
        return Ok(None);
    }
    let operation = checked(state.provider.begin_unlock(frozen.identity.clone()))?;
    let source = frozen
        .source
        .take()
        .ok_or_else(|| failure("cache already being opened"))?;
    Ok(Some((source, operation)))
}

pub(super) fn complete_native_presence(
    id: OperationId,
    state: &mut OwnerState,
    paths: &ServicePaths,
) -> io::Result<Value> {
    state.refresh_policy(paths)?;
    let pending = state
        .pending
        .as_ref()
        .filter(|pending| pending.id == id)
        .ok_or_else(|| failure("request cancelled"))?;
    let offset = checked(
        state
            .operations
            .authentication_offset(id, &pending.principal),
    )?;
    let authenticated = pending
        .created()
        .checked_add(offset)
        .ok_or_else(|| failure("invalid authentication clock"))?;
    if presence_now()?
        .checked_duration_since(authenticated)
        .is_none_or(|age| age >= Duration::from_secs(30))
    {
        return Err(failure("authentication expired"));
    }
    let frozen = &pending.provider;
    let snapshot = checked(state.provider.snapshot_for(&frozen.identity))?;
    let current = crate::owner::vault::Source::capture(&paths.root)
        .and_then(|source| source.identity())
        .map_err(|_| failure("cache unavailable"))?;
    if frozen.generation != state.provider.generation() || current != frozen.identity {
        return Err(failure("provider selection changed"));
    }
    let selection = CredentialSelection::at_generation(snapshot, state.provider.generation());
    let challenge = checked(
        state
            .operations
            .challenge(id, &pending.principal, selection),
    )?;
    let authenticated = pending
        .created()
        .checked_add(challenge.offset)
        .ok_or_else(|| failure("invalid authentication clock"))?;
    let ui = state
        .ui
        .as_ref()
        .ok_or_else(|| failure("UI disconnected"))?;
    let policy = checked(state.authorizer.policy_digest())?;
    let nonce = checked(state.operations.approval_nonce(id, &pending.principal))?;
    let expires = authenticated
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| failure("invalid clock"))?;
    Ok(json!({"kind": "challenge", "authorization": {
        "review": pending.review(ui, policy, nonce), "credentialDigest": BASE64.encode(challenge.credential_digest),
        "authenticated": authenticated, "expires": expires, "bytes": BASE64.encode(challenge.bytes)
    }}))
}

pub(super) fn native_presence(
    id: &str,
    authenticated: MonotonicTimestamp,
    context: &qm_macos::cache_key::NativeAuthenticationContext<'_>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
) -> io::Result<Value> {
    let id = checked(OperationId::parse(id))?;
    let deadline = authenticated
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| failure("invalid authentication deadline"))?;
    let lease = connection.context_lease(deadline)?;
    let work = {
        let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
        if !connection.is_connected()
            || state
                .ui
                .as_ref()
                .is_none_or(|ui| ui.connection != Some(connection.id()))
        {
            return Err(failure("UI disconnected"));
        }
        let work = begin_native_presence(id, authenticated, &mut state, paths)?;
        state.pending.as_mut().unwrap().context_lease = Some(lease);
        work
    };
    if let Some((source, operation)) = work {
        let result = presence_now().and_then(|now| {
            if now
                .checked_duration_since(authenticated)
                .is_none_or(|age| age >= Duration::from_secs(30))
            {
                return Err(failure("authentication expired"));
            }
            source
                .unlock_authenticated(context)
                .map_err(|_| failure("cache authentication failed"))
        });
        let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
        match result {
            Ok(snapshot) => crate::owner::vault::finish_unlock(
                &paths.root,
                &mut state.provider,
                operation,
                snapshot,
            )
            .map_err(|_| failure("cache unlock superseded"))?,
            Err(_) => {
                state.provider.release(&operation);
                return Err(failure("cache authentication failed"));
            }
        }
    }
    let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
    complete_native_presence(id, &mut state, paths)
}
