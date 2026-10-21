use super::{
    PROFILE, SERVICE, ServicePaths, Shared,
    approval::{self, UiSession},
    checked, failure, random,
    state::OwnerState,
    vault_workflow::vault_operation,
};
use crate::{
    owner::{
        operation::{CancellationResult, OperationId},
        protocol::{Client, ControlError, Reply, decode_client, encode_reply},
    },
    platform::macos::ipc::{self, Event},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_macos::{
    peer_identity::requirement_for_path, presence_clock::monotonic_raw as presence_now,
};
use qm_providers::ApprovalSession;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
pub(super) fn handle(
    message: Client,
    state: &mut OwnerState,
    paths: &ServicePaths,
) -> io::Result<Reply> {
    if !matches!(&message, Client::VaultStatus {}) {
        state.ensure_host_session()?;
    }
    if matches!(
        &message,
        Client::Enroll { .. } | Client::Next {} | Client::Presence { .. } | Client::Proof { .. }
    ) {
        state.refresh_policy(paths)?;
    }
    match message {
        Client::RevokeReadGrants {} => {
            checked(state.authorizer.revoke_read_grants())?;
            state.disconnect_ui();
            Ok(Reply::ReadGrantsRevoked)
        }
        Client::VaultStatus {} => Ok(Reply::VaultStatus(crate::owner::vault::status(
            &paths.root,
            state.provider.snapshot(),
        ))),
        Client::VaultLock {} => {
            state.disconnect_ui();
            checked(state.provider.lock())?;
            Ok(Reply::VaultStatus(crate::owner::vault::status(
                &paths.root,
                None,
            )))
        }
        Client::VaultLogin { .. }
        | Client::VaultUnlock {}
        | Client::VaultSync {}
        | Client::VaultDiscard {} => Err(failure("vault operation requires asynchronous handling")),
        Client::Hello {} => Ok(Reply::Hello { profile: PROFILE }),
        Client::Enroll { public_key } => {
            if state.ui.is_some() {
                return Err(failure("already enrolled connection"));
            }
            let key = BASE64.decode(public_key).map_err(io::Error::other)?;
            let id = random()?;
            let session = checked(ApprovalSession::new(
                id,
                checked(state.authorizer.policy_digest())?,
                &key,
            ))?;
            if state
                .approval_public_key
                .as_ref()
                .is_some_and(|stored| stored != &key)
            {
                return Err(failure(
                    "approval key changed; explicit re-enrolment required",
                ));
            }
            state.approval_public_key = Some(key);
            state.ui = Some(UiSession {
                session,
                connection: None,
            });
            Ok(Reply::Enrolled)
        }
        Client::Next {} => {
            let ui = state.ui.as_ref().ok_or_else(|| failure("not enrolled"))?;
            let Some(pending) = state.pending.as_mut().filter(|p| !p.delivered) else {
                return Ok(Reply::Idle);
            };
            pending.delivered = true;
            Ok(Reply::Review {
                approval: pending.review(
                    ui,
                    checked(state.authorizer.policy_digest())?,
                    checked(
                        state
                            .operations
                            .approval_nonce(pending.id, &pending.principal),
                    )?,
                ),
            })
        }
        Client::Presence { .. } => Err(failure("native authentication context required")),
        Client::Proof { id, signature } => {
            let id = checked(OperationId::parse(&id))?;
            let pending = state
                .pending
                .as_mut()
                .filter(|pending| pending.id == id)
                .ok_or_else(|| failure("no matching pending request"))?;
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
                return Err(failure("proof expired"));
            }
            let signature = BASE64.decode(signature).map_err(io::Error::other)?;
            checked(state.operations.proof(
                id,
                &pending.principal,
                &state.authorizer,
                &signature,
                Instant::now(),
            ))?;
            pending.context_lease.take();
            pending
                .completion
                .send(approval::ApprovalCompletion {
                    id,
                    principal: Arc::clone(&pending.principal),
                })
                .map_err(|_| failure("request cancelled"))?;
            Ok(Reply::Accepted)
        }
        Client::Cancel { id } => {
            let result = match (OperationId::parse(&id), state.ui.as_ref()) {
                (Ok(id), Some(ui)) => state.operations.cancel_interactive(id, ui.session.id()),
                _ => CancellationResult::UnknownOperation,
            };
            if result == CancellationResult::Canceled
                && state
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.id.to_string() == id)
            {
                state.cancel_pending();
            }
            Ok(match result {
                CancellationResult::Canceled => Reply::Canceled,
                CancellationResult::AlreadyAdmitted => Reply::AlreadyAdmitted,
                CancellationResult::UnknownOperation => Reply::UnknownOperation,
            })
        }
    }
}

pub(super) fn serve_xpc(shared: Shared, paths: ServicePaths) -> io::Result<()> {
    let requirement = requirement_for_path(&paths.app)?;
    let lifecycle = Arc::clone(&shared);
    let result = ipc::serve(SERVICE, &requirement, move |event| {
        let Event::Message {
            connection,
            context,
            payload,
        } = event
        else {
            if let Event::HostSession(event) = event {
                let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
                state.host_session_event(event)?;
                shared.1.notify_all();
                eprintln!("Host session event: {event:?}");
                return Ok(Vec::new());
            }
            let Event::Disconnected(id) = event else {
                unreachable!()
            };
            let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
            if state
                .ui
                .as_ref()
                .is_some_and(|ui| ui.connection == Some(id))
            {
                state.disconnect_ui();
                shared.1.notify_all();
            }
            return Ok(Vec::new());
        };
        let result = checked(decode_client(payload)).and_then(|request| {
            process_message(request, context.as_ref(), &connection, &shared, &paths)
        });
        if result.is_err() {
            connection.release_context();
        }
        shared.1.notify_all();
        let reply = result.unwrap_or_else(|error| Reply::Error {
            code: ControlError::from(error),
        });
        encode_reply(&reply).map_err(io::Error::other)
    });
    lifecycle
        .0
        .lock()
        .map_err(|_| failure("state unavailable"))?
        .authorizer
        .revoke_session();
    result
}

fn process_message(
    request: Client,
    context: Option<&qm_macos::cache_key::NativeAuthenticationContext<'_>>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
) -> io::Result<Reply> {
    {
        let state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
        if !matches!(&request, Client::VaultStatus {}) {
            state.ensure_host_session()?;
        }
        if state
            .ui
            .as_ref()
            .is_some_and(|ui| ui.connection != Some(connection.id()))
        {
            return Err(failure("different UI connection"));
        }
    }
    let enrollment = matches!(&request, Client::Enroll { .. });
    match request {
        Client::Presence { id, authenticated } => match context {
            Some(context) => {
                approval::native_presence(&id, authenticated, context, connection, shared, paths)
            }
            None => Err(failure("native authentication context required")),
        },
        request @ (Client::VaultLogin { .. }
        | Client::VaultUnlock {}
        | Client::VaultSync {}
        | Client::VaultDiscard {})
            if context.is_none() =>
        {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(io::Error::other)?
                .block_on(vault_operation(request, connection, shared, paths))
                .map(Reply::VaultStatus)
        }
        request if context.is_none() => {
            let mut state = shared.0.lock().map_err(|_| failure("state unavailable"))?;
            if !connection.is_connected()
                || state
                    .ui
                    .as_ref()
                    .is_some_and(|ui| ui.connection != Some(connection.id()))
            {
                return Err(failure("UI disconnected"));
            }
            let reply = handle(request, &mut state, paths);
            if enrollment && reply.is_ok() {
                state.ui.as_mut().unwrap().connection = Some(connection.id());
            }
            reply
        }
        _ => Err(failure("unexpected native authentication context")),
    }
}
