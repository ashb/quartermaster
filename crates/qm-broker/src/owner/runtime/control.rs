use super::error::{Error, Fault, Result};
use super::{
    PROFILE, SERVICE, ServicePaths, Shared,
    approval::{self, UiSession},
    random,
    state::OwnerState,
    vault_workflow::{cache_status, vault_operation},
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
    policy: &super::PolicyInput,
) -> Result<Reply> {
    if !matches!(&message, Client::VaultStatus {}) {
        state.ensure_host_session()?;
    }
    if matches!(
        &message,
        Client::Enroll { .. } | Client::Next {} | Client::Presence { .. } | Client::Proof { .. }
    ) {
        state.refresh_policy(policy)?;
        state.ensure_interactive()?;
    }
    match message {
        Client::RevokeReadGrants {} => {
            state.authorizer.revoke_read_grants()?;
            state.disconnect_ui();
            Ok(Reply::ReadGrantsRevoked)
        }
        Client::VaultStatus {} => Err(Error::State(Fault::UnsupportedVaultCommand)),
        Client::VaultLock {} => {
            state.lock_vault()?;
            Ok(Reply::VaultStatus(crate::owner::vault::locked_status()))
        }
        Client::VaultLogin { .. }
        | Client::VaultUnlock {}
        | Client::VaultSync {}
        | Client::VaultDiscard {} => Err(Error::State(Fault::UnsupportedVaultCommand)),
        Client::SettingsRegister { .. }
        | Client::SettingsStatus {}
        | Client::PrepareSettingsImport { .. }
        | Client::StageEnrollment { .. }
        | Client::PrepareSettings { .. }
        | Client::SettingsPresence { .. }
        | Client::SettingsProof { .. }
        | Client::SettingsCancel { .. } => Err(Error::Protocol(ControlError::Denied)),
        Client::Hello {} => Ok(Reply::Hello { profile: PROFILE }),
        Client::Enroll { public_key } => {
            let key = BASE64.decode(public_key).map_err(Error::from)?;
            if state.ui.is_some() {
                return if state.approval_public_key.as_deref() == Some(key.as_slice()) {
                    Ok(Reply::Enrolled)
                } else {
                    Err(Fault::ApprovalKeyChanged.into())
                };
            }
            let id = random()?;
            let session = ApprovalSession::new(id, state.authorizer.policy_digest()?, &key)?;
            if state
                .approval_public_key
                .as_ref()
                .is_some_and(|stored| stored != &key)
            {
                return Err(Error::State(Fault::ApprovalKeyChanged));
            }
            state.approval_public_key = Some(key);
            state.ui = Some(UiSession {
                session,
                connection: None,
            });
            Ok(Reply::Enrolled)
        }
        Client::Next {} => {
            let ui = state
                .ui
                .as_ref()
                .ok_or_else(|| Error::State(Fault::UiNotEnrolled))?;
            let Some(pending) = state.pending.as_mut().filter(|p| !p.delivered) else {
                return Ok(Reply::Idle);
            };
            pending.delivered = true;
            Ok(Reply::Review {
                approval: pending.review(
                    ui,
                    state.authorizer.policy_digest()?,
                    state
                        .operations
                        .approval_nonce(pending.id, &pending.principal)?,
                ),
            })
        }
        Client::Presence { .. } => Err(Error::State(Fault::NativeContextRequired)),
        Client::Proof { id, signature } => {
            let id = OperationId::parse(&id)?;
            let pending = state
                .pending
                .as_mut()
                .filter(|pending| pending.id == id)
                .ok_or_else(|| Error::State(Fault::PendingMissing))?;
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
            let signature = BASE64.decode(signature).map_err(Error::from)?;
            state.operations.proof(
                id,
                &pending.principal,
                &state.authorizer,
                &signature,
                Instant::now(),
            )?;
            pending.context_lease.take();
            pending
                .completion
                .send(approval::ApprovalCompletion {
                    id,
                    principal: Arc::clone(&pending.principal),
                })
                .map_err(|_| Error::State(Fault::Canceled))?;
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

pub(super) fn listen(
    shared: Shared,
    paths: ServicePaths,
    runtime: tokio::runtime::Handle,
) -> Result<impl Sized> {
    let requirement = requirement_for_path(&paths.app)?;
    let events = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?
        .host_events
        .clone();
    let work_limit = Arc::new(tokio::sync::Semaphore::new(8));
    ipc::listen(SERVICE, &requirement, events, move |event| {
        handle_event(event, &shared, &paths, &runtime, &work_limit)
            .or_else(|error| encode_result(Err(error)).map(Into::into))
            .map_err(io::Error::other)
    })
    .map_err(Error::from)
}

pub(super) fn handle_event(
    event: Event<'_>,
    shared: &Shared,
    paths: &ServicePaths,
    runtime: &tokio::runtime::Handle,
    work_limit: &Arc<tokio::sync::Semaphore>,
) -> Result<ipc::Response> {
    let Event::Message {
        connection,
        context,
        payload,
    } = event
    else {
        if let Event::HostSession(event) = event {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            state.synchronize_host_events()?;
            shared.1.notify_all();
            eprintln!("Host session event: {event:?}");
            return Ok(Vec::new().into());
        }
        let Event::Disconnected(id) = event else {
            unreachable!()
        };
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.administration.disconnect(id);
        if state
            .ui
            .as_ref()
            .is_some_and(|ui| ui.connection == Some(id))
        {
            state.disconnect_ui();
            shared.1.notify_all();
        }
        return Ok(Vec::new().into());
    };
    let request = decode_client(payload).map_err(Error::from);
    if request.as_ref().is_ok_and(Client::is_settings) {
        return super::settings::message(
            request?,
            context.as_ref(),
            &connection,
            shared,
            paths,
            runtime,
            work_limit,
        );
    }
    if matches!(
        &request,
        Ok(Client::VaultLogin { .. } | Client::VaultDiscard {})
    ) {
        connection.release_context();
        return encode_result(Err(Error::Protocol(ControlError::Denied))).map(Into::into);
    }
    if context.is_none() && matches!(&request, Ok(Client::VaultUnlock {} | Client::VaultSync {})) {
        let request = request?;
        let generation = {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            state.ensure_host_session()?;
            if (state
                .ui
                .as_ref()
                .is_none_or(|ui| ui.connection != Some(connection.id()))
                && !state.administration.manages_cache(&connection.handle()))
                || !connection.is_connected()
            {
                return encode_result(Err(Error::State(Fault::UiNotEnrolled))).map(Into::into);
            }
            state.provider.generation()
        };
        let connection = connection.handle();
        let permit = Arc::clone(work_limit)
            .try_acquire_owned()
            .map_err(|_| Error::Provider(crate::owner::provider_lifecycle::Error::Busy))?;
        let shared = Arc::clone(shared);
        let paths = paths.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        runtime.spawn(async move {
            let _permit = permit;
            let result = vault_operation(request, &connection, &shared, &paths, generation)
                .await
                .map(Reply::VaultStatus);
            shared.1.notify_all();
            let _ = send.send(
                encode_result(result)
                    .unwrap_or_else(|_| br#"{"kind":"error","code":"unavailable"}"#.to_vec()),
            );
        });
        return Ok(ipc::Response::Deferred(receive));
    }
    if context.is_none() && matches!(&request, Ok(Client::VaultStatus {} | Client::VaultLock {})) {
        {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            if !connection.is_connected()
                || state
                    .ui
                    .as_ref()
                    .is_some_and(|ui| ui.connection != Some(connection.id()))
            {
                return encode_result(Err(Error::State(Fault::UiDisconnected))).map(Into::into);
            }
            if matches!(&request, Ok(Client::VaultLock {})) {
                state.ensure_host_session()?;
                state.lock_vault()?;
                return encode_result(Ok(Reply::VaultStatus(crate::owner::vault::locked_status())))
                    .map(Into::into);
            }
        }
        let shared = Arc::clone(shared);
        let paths = paths.clone();
        let permit = Arc::clone(work_limit)
            .try_acquire_owned()
            .map_err(|_| Error::Provider(crate::owner::provider_lifecycle::Error::Busy))?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        runtime.spawn_blocking(move || {
            let _permit = permit;
            let _ = send.send(
                encode_result(
                    paths
                        .vault_root()
                        .map_err(Error::from)
                        .and_then(|root| cache_status(&root, &shared))
                        .map(Reply::VaultStatus),
                )
                .unwrap_or_else(|_| br#"{"kind":"error","code":"unavailable"}"#.to_vec()),
            );
        });
        return Ok(ipc::Response::Deferred(receive));
    }
    if context.is_none()
        && matches!(
            &request,
            Ok(Client::Enroll { .. } | Client::Next {} | Client::Proof { .. })
        )
    {
        let basis = {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            state.ensure_interactive()?;
            (
                state.provider.generation(),
                state.ui.as_ref().map(|ui| ui.session.id()),
            )
        };
        let permit = Arc::clone(work_limit)
            .try_acquire_owned()
            .map_err(|_| Error::Provider(crate::owner::provider_lifecycle::Error::Busy))?;
        let connection = connection.handle();
        let shared = Arc::clone(shared);
        let paths = paths.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        runtime.spawn_blocking(move || {
            let _permit = permit;
            let policy = paths.load_policy();
            let result = (|| {
                let mut state = shared
                    .0
                    .lock()
                    .map_err(|_| Error::State(Fault::StateUnavailable))?;
                if basis
                    != (
                        state.provider.generation(),
                        state.ui.as_ref().map(|ui| ui.session.id()),
                    )
                {
                    return Err(Error::State(Fault::UiDisconnected));
                }
                plain_message(request?, &connection, &mut state, &policy)
            })();
            shared.1.notify_all();
            let _ = send.send(
                encode_result(result)
                    .unwrap_or_else(|_| br#"{"kind":"error","code":"unavailable"}"#.to_vec()),
            );
        });
        return Ok(ipc::Response::Deferred(receive));
    }
    let result = request
        .and_then(|request| process_message(request, context.as_ref(), &connection, shared, paths));
    if result.is_err() {
        connection.release_context();
    }
    shared.1.notify_all();
    encode_result(result).map(Into::into)
}

pub(super) fn encode_result(result: Result<Reply>) -> Result<Vec<u8>> {
    let reply = result.unwrap_or_else(|error| Reply::Error {
        code: ControlError::from(error),
    });
    encode_reply(&reply).map_err(Error::from)
}

fn process_message(
    request: Client,
    context: Option<&qm_macos::cache_key::NativeAuthenticationContext<'_>>,
    connection: &ipc::Connection<'_>,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<Reply> {
    {
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        if !matches!(&request, Client::VaultStatus {}) {
            state.ensure_host_session()?;
        }
        if state
            .ui
            .as_ref()
            .is_some_and(|ui| ui.connection != Some(connection.id()))
        {
            return Err(Error::State(Fault::UiDisconnected));
        }
    }
    match request {
        Client::Presence { id, authenticated } => match context {
            Some(context) => {
                approval::native_presence(&id, authenticated, context, connection, shared, paths)
            }
            None => Err(Error::State(Fault::NativeContextRequired)),
        },
        request if context.is_none() => {
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            plain_message(
                request,
                &connection.handle(),
                &mut state,
                &Err(crate::owner::policy::AuthorizationError::InvalidPolicy),
            )
        }
        _ => Err(Error::State(Fault::UnexpectedContext)),
    }
}

fn plain_message(
    request: Client,
    connection: &ipc::PeerHandle,
    state: &mut OwnerState,
    policy: &super::PolicyInput,
) -> Result<Reply> {
    if !connection.is_connected()
        || state
            .ui
            .as_ref()
            .is_some_and(|ui| ui.connection != Some(connection.id()))
    {
        return Err(Error::State(Fault::UiDisconnected));
    }
    let enrollment = matches!(&request, Client::Enroll { .. });
    let reply = handle(request, state, policy);
    if enrollment && reply.is_ok() {
        state.ui.as_mut().unwrap().connection = Some(connection.id());
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        owner::{policy::Policy, runtime::tests::fixture},
        platform::macos::ipc::test_support::{Fixture, send, start_send},
    };
    use std::{
        sync::{Condvar, Mutex, mpsc},
        thread,
    };

    #[test]
    fn legacy_vault_login_cannot_bypass_settings_approval_over_native_ipc() {
        let (_directory, paths, _key, state, _receive) = fixture();
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let work_limit = Arc::new(tokio::sync::Semaphore::new(8));
        let native = Fixture::new(move |event| {
            if let Event::Message { connection, .. } = &event
                && let Some(ui) = shared.0.lock().unwrap().ui.as_mut()
            {
                ui.connection = Some(connection.id());
            }
            handle_event(event, &shared, &paths, &handle, &work_limit)
                .or_else(|error| encode_result(Err(error)).map(Into::into))
                .map_err(io::Error::other)
        });
        let client = native.client();
        let reply = send(&client, br#"{"kind":"vaultLogin","server":"https://vault.example.invalid","email":"dummy@example.invalid","password":""}"#, None);
        let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(reply["kind"], "error");
        assert_eq!(reply["code"], "denied");
        client.invalidate();
    }

    #[test]
    fn settings_inspection_survives_invalid_operation_policy_without_activating_it() {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        paths.policy.suspend().unwrap();
        state.authorizer.invalidate_policy().unwrap();
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let owner = Arc::clone(&shared);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let work_limit = Arc::new(tokio::sync::Semaphore::new(8));
        let native = Fixture::new(move |event| {
            handle_event(event, &owner, &paths, &handle, &work_limit)
                .or_else(|error| encode_result(Err(error)).map(Into::into))
                .map_err(io::Error::other)
        });
        let client = native.client();
        let reply: serde_json::Value =
            serde_json::from_slice(&send(&client, br#"{"kind":"settingsStatus"}"#, None)).unwrap();
        assert_eq!(reply["kind"], "settingsStatus");
        assert_eq!(reply["settings"]["revision"], 0);
        assert!(shared.0.lock().unwrap().authorizer.policy_digest().is_err());
        client.invalidate();
    }

    #[test]
    fn a_stalled_policy_read_cannot_block_cancel_or_lock_on_the_same_native_connection() {
        for lock in [false, true] {
            let (_directory, paths, _key, state, _receive) = fixture();
            let id = state.pending.as_ref().unwrap().id.to_string();
            let shared = Arc::new((Mutex::new(state), Condvar::new()));
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .build()
                .unwrap();
            let handle = runtime.handle().clone();
            let work_limit = Arc::new(tokio::sync::Semaphore::new(8));
            let source = Arc::clone(&paths.policy);
            let (entered, ready) = mpsc::sync_channel(1);
            let (release, wait) = mpsc::sync_channel(1);
            let loader = thread::spawn(move || {
                source
                    .read(|| {
                        entered.send(()).unwrap();
                        wait.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(Policy::default())
                    })
                    .is_ok()
            });
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            let owner = Arc::clone(&shared);
            let (scheduled, observed) = mpsc::sync_channel(1);
            let native = Fixture::new(move |event| {
                let next = matches!(&event, Event::Message { payload, .. } if *payload == br#"{"kind":"next"}"#);
                if let Event::Message { connection, .. } = &event
                    && let Some(ui) = owner.0.lock().unwrap().ui.as_mut()
                {
                    ui.connection = Some(connection.id());
                }
                let response = handle_event(event, &owner, &paths, &handle, &work_limit)
                    .or_else(|error| encode_result(Err(error)).map(Into::into))
                    .map_err(io::Error::other);
                if next {
                    scheduled.send(()).unwrap();
                }
                response
            });
            let client = native.client();
            let pending = start_send(&client, br#"{"kind":"next"}"#, None);
            observed.recv_timeout(Duration::from_secs(2)).unwrap();
            let command = if lock {
                Client::VaultLock {}
            } else {
                Client::Cancel { id }
            };
            let acknowledgment = send(&client, &serde_json::to_vec(&command).unwrap(), None);
            assert!(shared.0.lock().unwrap().pending.is_none());
            let reply: serde_json::Value = serde_json::from_slice(&acknowledgment).unwrap();
            assert_eq!(reply["kind"], if lock { "vaultStatus" } else { "canceled" });
            release.send(()).unwrap();
            assert!(loader.join().unwrap());
            let reply: serde_json::Value = serde_json::from_slice(
                &pending
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(reply["kind"], if lock { "error" } else { "idle" });
            client.invalidate();
            drop(native);
        }
    }
}
