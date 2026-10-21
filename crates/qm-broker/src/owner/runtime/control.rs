use super::{
    PROFILE, SERVICE, ServicePaths, Shared,
    approval::{self, UiSession},
    checked, failure, random,
    state::OwnerState,
    vault_workflow::vault_operation,
};
use crate::{
    owner::operation::{CancellationResult, OperationId},
    platform::macos::ipc::{self, Event},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_macos::{
    peer_identity::requirement_for_path,
    presence_clock::{MonotonicTimestamp, monotonic_raw as presence_now},
};
use qm_providers::ApprovalSession;
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[cfg(test)]
use {rama_net_apple_xpc::XpcMessage, std::collections::BTreeMap};
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Client {
    Hello {},
    Enroll {
        #[serde(rename = "publicKey")]
        public_key: String,
    },
    Next {},
    Presence {
        id: String,
        authenticated: MonotonicTimestamp,
    },
    Proof {
        id: String,
        signature: String,
    },
    Cancel {
        id: String,
    },
    VaultStatus {},
    VaultLogin {
        server: String,
        email: String,
        password: Zeroizing<String>,
        #[serde(rename = "itemId")]
        item_id: Option<String>,
    },
    VaultLock {},
    VaultUnlock {},
    VaultSync {},
    VaultDiscard {},
    RevokeReadGrants {},
}

#[cfg(test)]
pub(super) fn unpack(message: &XpcMessage) -> io::Result<Client> {
    let XpcMessage::Dictionary(fields) = message else {
        return Err(failure("invalid envelope"));
    };
    if fields.len() != 2 || fields.get("version") != Some(&XpcMessage::Uint64(1)) {
        return Err(failure("unsupported protocol"));
    }
    let Some(XpcMessage::Data(bytes)) = fields.get("payload") else {
        return Err(failure("invalid payload"));
    };
    if bytes.len() > 16384 {
        return Err(failure("payload exceeds limit"));
    }
    serde_json::from_slice(bytes).map_err(|_| failure("invalid message payload"))
}
#[cfg(test)]
pub(super) fn pack(value: Value) -> io::Result<XpcMessage> {
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() > 16384 {
        return Err(failure("response exceeds limit"));
    }
    Ok(XpcMessage::Dictionary(BTreeMap::from([
        ("version".into(), XpcMessage::Uint64(1)),
        ("payload".into(), XpcMessage::Data(bytes)),
    ])))
}
pub(super) fn handle(
    message: Client,
    state: &mut OwnerState,
    paths: &ServicePaths,
) -> io::Result<Value> {
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
            Ok(json!({"kind":"readGrantsRevoked"}))
        }
        Client::VaultStatus {} => checked(serde_json::to_value(crate::owner::vault::status(
            &paths.root,
            state.provider.snapshot(),
        ))),
        Client::VaultLock {} => {
            state.disconnect_ui();
            checked(state.provider.lock())?;
            checked(serde_json::to_value(crate::owner::vault::status(
                &paths.root,
                None,
            )))
        }
        Client::VaultLogin { .. }
        | Client::VaultUnlock {}
        | Client::VaultSync {}
        | Client::VaultDiscard {} => Err(failure("vault operation requires asynchronous handling")),
        Client::Hello {} => Ok(json!({"kind": "hello", "profile": PROFILE})),
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
            Ok(json!({"kind": "enrolled"}))
        }
        Client::Next {} => {
            let ui = state.ui.as_ref().ok_or_else(|| failure("not enrolled"))?;
            let Some(pending) = state.pending.as_mut().filter(|p| !p.delivered) else {
                return Ok(json!({"kind": "idle"}));
            };
            pending.delivered = true;
            Ok(
                json!({"kind": "review", "id": pending.id.to_string(), "created": pending.created(),
                "session": BASE64.encode(ui.session.id()), "policy": BASE64.encode(checked(state.authorizer.policy_digest())?),
                "approval": pending.review(ui, checked(state.authorizer.policy_digest())?, checked(state.operations.approval_nonce(pending.id, &pending.principal))?),
                "requestDigest": BASE64.encode(digest(&SHA256, pending.request.bytes())), "request": BASE64.encode(pending.request.bytes())}),
            )
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
            Ok(json!({"kind": "accepted"}))
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
            Ok(json!({"kind": match result {
                CancellationResult::Canceled => "canceled",
                CancellationResult::AlreadyAdmitted => "alreadyAdmitted",
                CancellationResult::UnknownOperation => "unknownOperation",
            }}))
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
        let request: Client =
            serde_json::from_slice(payload).map_err(|_| failure("invalid message payload"))?;
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
        let result = match request {
            Client::Presence { id, authenticated } => match context.as_ref() {
                Some(context) => approval::native_presence(
                    &id,
                    authenticated,
                    context,
                    &connection,
                    &shared,
                    &paths,
                ),
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
                    .block_on(vault_operation(request, &connection, &shared, &paths))
                    .and_then(|status| checked(serde_json::to_value(status)))
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
                let reply = handle(request, &mut state, &paths);
                if enrollment && reply.is_ok() {
                    state.ui.as_mut().unwrap().connection = Some(connection.id());
                }
                reply
            }
            _ => Err(failure("unexpected native authentication context")),
        };
        if result.is_err() {
            connection.release_context();
        }
        shared.1.notify_all();
        serde_json::to_vec(&result?).map_err(io::Error::other)
    });
    lifecycle
        .0
        .lock()
        .map_err(|_| failure("state unavailable"))?
        .authorizer
        .revoke_session();
    result
}
