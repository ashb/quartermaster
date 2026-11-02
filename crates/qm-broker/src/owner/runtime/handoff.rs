use super::{
    OwnerState, ServicePaths, Shared,
    approval::{ApprovalAction, ApprovalDelivery, FrozenProvider},
    error::{Error, Fault, Result},
    restic_process::Launch,
};
use crate::owner::{
    identity::VerifiedPrincipal,
    operation::OperationId,
    protocol::{ApprovalReview, ProviderPresentation, Reply},
    provider_lifecycle::{CacheIdentity, ProviderGeneration},
    settings::Revision,
    signing::Signing,
    vault,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_macos::{
    peer_identity::requirement_for_path,
    presence_clock::{MonotonicTimestamp, monotonic_raw as now},
};
use qm_providers::{ProviderBinding, RbwProvider, SelectedCredential};
use serde::Deserialize;
use std::{
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::ExitStatusExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt as _;

const LIMIT: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invocation {
    arguments: Vec<String>,
    working_directory: PathBuf,
}

impl Invocation {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        let value: Self = serde_json::from_slice(bytes)?;
        if bytes.len() > LIMIT
            || value.arguments.len() > 256
            || value.arguments.iter().any(|arg| arg.contains('\0'))
            || !value.working_directory.is_absolute()
            || value
                .working_directory
                .to_str()
                .is_none_or(|s| s.contains('\0'))
        {
            return Err(io::Error::other("invalid Restic invocation"));
        }
        super::restic_process::validate_arguments(&value.arguments)?;
        Ok(value)
    }
}

pub(super) struct Dispatch {
    pub(super) wire: ApprovalReview,
    pub(super) signing: Signing<SelectedCredential>,
    pub(super) binding: ProviderBinding,
    requester: UnixStream,
    ui_peer: crate::platform::macos::ipc::PeerHandle,
    revision: Revision,
    root: PathBuf,
    launch: Launch,
    completion: mpsc::SyncSender<Launch>,
}

fn current_revision(state: &OwnerState) -> Result<Revision> {
    let manager = state
        .administration
        .manager
        .as_ref()
        .filter(|manager| manager.stable())
        .ok_or(Fault::ProviderChanged)?;
    Ok(manager.record().revision())
}

fn check_admission(
    state: &mut OwnerState,
    session: [u8; 16],
    generation: ProviderGeneration,
    revision: Revision,
    ui_connected: bool,
) -> Result<()> {
    state.ensure_interactive()?;
    if !ui_connected
        || state
            .ui
            .as_ref()
            .is_none_or(|ui| ui.session.id() != session)
        || state.provider.generation() != generation
        || current_revision(state)? != revision
    {
        return Err(Fault::ProviderChanged.into());
    }
    Ok(())
}

impl Dispatch {
    pub(super) fn check(&self, pending: &ApprovalDelivery, state: &OwnerState) -> Result<()> {
        if !self.ui_peer.is_connected() {
            return Err(Fault::UiDisconnected.into());
        }
        if current_revision(state)? != self.revision
            || state.provider.generation() != pending.provider.generation
            || state
                .ui
                .as_ref()
                .is_none_or(|ui| BASE64.encode(ui.session.id()) != self.wire.session)
            || (!pending.resolving_credential
                && vault::Source::capture(&self.root)?.identity()? != pending.provider.identity)
        {
            return Err(Fault::ProviderChanged.into());
        }
        connected(&self.requester)?;
        pending.principal.revalidate()?;
        self.launch.identity().revalidate()?;
        Ok(())
    }

    pub(super) fn dispatch(
        mut self,
        signature: &[u8],
        provider: FrozenProvider,
        principal: &VerifiedPrincipal,
        authenticated: MonotonicTimestamp,
        state: &mut OwnerState,
    ) -> Result<Reply> {
        let approved = self.signing.approve(signature)?;
        let expected = qm_providers::RequestBinding {
            session_id: BASE64
                .decode(&self.wire.session)?
                .try_into()
                .map_err(|_| Fault::InvalidOperation)?,
            policy_digest: BASE64
                .decode(&self.wire.policy)?
                .try_into()
                .map_err(|_| Fault::InvalidOperation)?,
            request_digest: BASE64
                .decode(&self.wire.request_digest)?
                .try_into()
                .map_err(|_| Fault::InvalidOperation)?,
            credential_digest: approved.selection.credential_digest(),
        };
        approved.proof.verify_for_owner(&expected)?;
        if approved.selection.binding() != &self.binding {
            return Err(Fault::ProviderChanged.into());
        }
        let password = approved
            .selection
            .decrypt_selected_for_owner()
            .map_err(vault::Error::from)?;
        approved.proof.dispatch(|_| {
            self.launch.release_checked(&password, || {
                check_admission(
                    state,
                    expected.session_id,
                    provider.generation,
                    self.revision,
                    self.ui_peer.is_connected(),
                )
                .map_err(io::Error::other)?;
                if vault::Source::capture(&self.root)
                    .and_then(|s| s.identity())
                    .map_err(|error| io::Error::other(Error::from(error)))?
                    != provider.identity
                {
                    return Err(io::Error::other("vault changed before password release"));
                }
                connected(&self.requester)?;
                principal.revalidate()?;
                super::approval::check_authenticated_deadline(authenticated, now()?)
                    .map_err(io::Error::other)?;
                approved.deadline.remaining().map_err(io::Error::other)?;
                state.admitted_approval = Some((self.wire.id.clone(), expected.session_id));
                Ok(())
            })
        })??;
        self.completion
            .send(self.launch)
            .map_err(|_| Fault::Canceled)?;
        Ok(Reply::Accepted)
    }
}

fn connected(stream: &UnixStream) -> io::Result<()> {
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
        return Ok(());
    }
    Err(io::Error::other(
        "Restic requester disconnected or sent unexpected data",
    ))
}

pub(super) async fn selection(
    id: OperationId,
    shared: &Shared,
    paths: &ServicePaths,
    binding: &ProviderBinding,
) -> Result<(SelectedCredential, CacheIdentity, ProviderGeneration)> {
    let source = paths.vault_source()?;
    let (operation, snapshot) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.ensure_interactive()?;
        let pending = state
            .pending
            .as_ref()
            .filter(|p| p.id == id)
            .ok_or(Fault::Canceled)?;
        pending.check(&state)?;
        if !pending.resolving_credential || source.identity()? != pending.provider.identity {
            return Err(Fault::ProviderChanged.into());
        }
        state.provider.begin_refresh(&source.identity()?)?
    };
    let result = RbwProvider::new(snapshot.binding().clone(), vault::LIMITS)
        .map_err(vault::Error::from)?
        .sync_selected(&snapshot, binding)
        .await;
    let refreshed = match result {
        Ok(result) => result,
        Err(error) => {
            shared
                .0
                .lock()
                .map_err(|_| Fault::StateUnavailable)?
                .provider
                .release(&operation);
            return Err(vault::Error::from(error).into());
        }
    };
    let checkpoint = refreshed.source.checkpoint();
    let (operation, prepared) =
        super::vault_workflow::prepare_cache_update(shared, paths, operation, refreshed.source)
            .await?;
    let publication = vault::publication(&paths.vault_root()?, prepared)?;
    super::vault_workflow::finish_publication_with(
        publication,
        operation,
        shared,
        |state, previous, identity| {
            super::approval::adopt_refreshed_source(id, state, previous, identity)
        },
    )?;
    let selected = refreshed.selected.map_err(vault::Error::from)?;
    if selected.binding() != binding {
        return Err(Fault::ProviderChanged.into());
    }
    let source = paths.vault_source()?.identity()?;
    let state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
    if state.provider.snapshot_for(&source)?.checkpoint() != checkpoint {
        return Err(Fault::ProviderChanged.into());
    }
    Ok((selected, source, state.provider.generation()))
}

fn prepare(
    stream: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<(String, mpsc::Receiver<Launch>)> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let size = u32::from_be_bytes(length) as usize;
    if size > LIMIT {
        return Err(Fault::InvalidOperation.into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    let invocation = Invocation::decode(&bytes).map_err(|_| Fault::InvalidOperation)?;
    let id = super::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let (principal, mut peer) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.refresh_policy(&paths.load_policy())?;
        state.ensure_interactive()?;
        VerifiedPrincipal::capture(stream, state.authorizer.session())?
    };
    let slot = super::approval::wait_for_turn(&principal, stream, now()?, shared, paths)?;
    let source = paths.vault_source()?;
    let identity = source.identity()?;
    let (revision, configuration, binding, frontend, generation) = {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        state.refresh_policy(&paths.load_policy())?;
        state.ensure_interactive()?;
        if state.pending.is_some() || state.approval_starting.is_some() {
            return Err(Fault::ApprovalPending.into());
        }
        let manager = state
            .administration
            .manager
            .as_ref()
            .filter(|m| m.stable())
            .ok_or(Fault::ProviderChanged)?;
        let config = manager
            .record()
            .settings()
            .and_then(|s| s.restic())
            .filter(|c| c.enabled)
            .cloned()
            .ok_or(Fault::ResticDisabled)?;
        let record = manager.record();
        let binding = record
            .settings()
            .ok_or(Fault::ResticDisabled)?
            .restic_binding(&record.provider().ok_or(Fault::ProviderChanged)?.binding)?;
        let revision = manager.record().revision();
        state.approval_starting = Some(id.clone());
        (
            revision,
            config,
            binding,
            state.frontend_requirement.clone(),
            state.provider.generation(),
        )
    };
    let result = (|| {
        super::approval::check_frontend(frontend.as_deref(), &paths.app)?;
        let executable = Path::new(&configuration.executable).canonicalize()?;
        let requirement = requirement_for_path(&executable)?;
        let launch = Launch::start(
            &executable,
            &invocation.arguments,
            &invocation.working_directory,
            &requirement,
        )?;
        peer.observe_display_context();
        let deadline = Instant::now() + Duration::from_secs(15);
        crate::platform::macos::application::launch_application(&paths.app, deadline)
            .map_err(|_| Fault::LaunchFailed)?;
        let state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        let (mut state, _) = shared
            .1
            .wait_timeout_while(
                state,
                deadline.saturating_duration_since(Instant::now()),
                |s| s.ui.is_none(),
            )
            .map_err(|_| Fault::StateUnavailable)?;
        state.refresh_policy(&paths.load_policy())?;
        state.ensure_interactive()?;
        if !state.approval_queue.is_front(&slot)
            || state.approval_starting.as_deref() != Some(&id)
            || current_revision(&state)? != revision
            || state.pending.is_some()
        {
            return Err(Fault::Canceled.into());
        }
        let root = paths.vault_root()?;
        if state.provider.generation() != generation
            || paths.vault_source()?.identity()? != identity
        {
            return Err(Fault::ProviderChanged.into());
        }
        let provider = ProviderPresentation::new(&identity, generation, &binding);
        let created = now()?;
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(invocation.arguments);
        let document = serde_json::to_vec(&serde_json::json!({
            "kind":"credentialHandoff", "tool":"restic", "credentialName":configuration.item_name.as_deref().unwrap_or("Name unavailable"),
            "recipient":{"pid":launch.pid(), "execution":launch.identity().identity().binding(),
                "executable":executable, "requirement":requirement},
            "command":command,"workingDirectory":invocation.working_directory,
            "requester":peer.presentation(),"provider":provider,"created":created,"operationId":id,
            "settingsRevision":revision,
        }))
        .map_err(io::Error::other)?;
        if document.len() > LIMIT {
            return Err(Fault::InvalidOperation.into());
        }
        let ui = state.ui.as_ref().ok_or(Fault::UiDisconnected)?;
        let ui_peer = ui.peer.clone().ok_or(Fault::UiDisconnected)?;
        let request_digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &document)
            .as_ref()
            .try_into()
            .unwrap();
        let mut signing = Signing::default();
        signing.begin(&ui.session, request_digest, Instant::now())?;
        let wire = ApprovalReview {
            id: id.clone(),
            created,
            session: BASE64.encode(ui.session.id()),
            policy: BASE64.encode(state.authorizer.policy_digest()?),
            nonce: BASE64.encode(signing.nonce()?),
            request: BASE64.encode(document),
            request_digest: BASE64.encode(request_digest),
            provider,
        };
        let (completion, receive) = mpsc::sync_channel(1);
        let pending = ApprovalDelivery {
            _queue_ticket: Some(slot),
            id: OperationId::parse(&id)?,
            principal: Arc::new(principal),
            provider: FrozenProvider {
                source: Some(source),
                identity,
                generation,
            },
            context_lease: None,
            delivered: false,
            authenticated: None,
            resolving_credential: false,
            action: ApprovalAction::Handoff(Box::new(Dispatch {
                wire,
                signing,
                binding,
                requester: stream.try_clone()?,
                ui_peer,
                revision,
                root,
                launch,
                completion,
            })),
        };
        pending.check(&state)?;
        state.pending = Some(pending);
        state.approval_starting = None;
        Ok((id.clone(), receive))
    })();
    if result.is_err() {
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        if state.approval_starting.as_deref() == Some(&id) {
            state.approval_starting = None;
        }
    }
    result
}

fn frame(stream: &mut UnixStream, kind: u8, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn nonblocking(fd: &impl AsRawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn relay(mut launch: Launch, stream: &mut UnixStream) -> Result<()> {
    let mut stdout = launch.take_stdout().ok_or(Fault::InvalidOperation)?;
    let mut stderr = launch.take_stderr().ok_or(Fault::InvalidOperation)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut open = [true, true];
    let mut status = None;
    loop {
        connected(stream)?;
        for (index, reader) in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read]
            .into_iter()
            .enumerate()
        {
            if !open[index] {
                continue;
            }
            let mut bytes = [0; 16384];
            match reader.read(&mut bytes) {
                Ok(0) => open[index] = false,
                Ok(count) => frame(stream, index as u8 + 1, &bytes[..count])?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        if status.is_none() {
            status = launch.try_wait()?;
        }
        if let Some(status) = status
            && !open.iter().any(|open| *open)
        {
            frame(
                stream,
                3,
                &[status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u8],
            )?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn handle(mut stream: UnixStream, shared: &Shared, paths: &ServicePaths) {
    let result = (|| {
        let (id, receive) = prepare(&mut stream, shared, paths)?;
        let result = loop {
            match receive.recv_timeout(Duration::from_millis(50)) {
                Ok(launch) => break relay(launch, &mut stream),
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(Fault::Canceled.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let check = (|| {
                        connected(&stream)?;
                        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
                        state.refresh_policy(&paths.load_policy())?;
                        state.ensure_interactive()?;
                        state
                            .pending
                            .as_ref()
                            .filter(|p| p.id.to_string() == id)
                            .ok_or(Fault::Canceled)?
                            .check(&state)
                    })();
                    if let Err(error) = check {
                        break Err(error);
                    }
                }
            }
        };
        let mut state = shared.0.lock().map_err(|_| Fault::StateUnavailable)?;
        if state
            .pending
            .as_ref()
            .is_some_and(|p| p.id.to_string() == id)
        {
            state.cancel_pending();
        }
        result
    })();
    if let Err(error) = result {
        let _ = frame(&mut stream, 4, failure_message(&error).as_bytes());
    }
}

fn failure_message(error: &Error) -> &'static str {
    match error {
        Error::State(Fault::ResticDisabled) => {
            "Enable Restic in Quartermaster's Tools settings first."
        }
        Error::State(Fault::InvalidOperation) => {
            "Unsupported Restic invocation. Use one --repo /absolute/local/path; password overrides and stdin are unavailable."
        }
        Error::State(Fault::Canceled) => {
            "The password release was cancelled. No further release will be attempted."
        }
        Error::State(Fault::ApprovalExpired) => {
            "The password release approval expired. Run the command again to request approval."
        }
        Error::State(Fault::ApprovalPending)
        | Error::Provider(crate::owner::provider_lifecycle::Error::Busy) => {
            "Quartermaster is handling another approval or vault operation. Retry when it finishes."
        }
        Error::State(
            Fault::UiDisconnected
            | Fault::UiNotEnrolled
            | Fault::LaunchFailed
            | Fault::FrontendChanged,
        ) => {
            "The approval app is unavailable. Open Quartermaster from the same build as its backend and retry."
        }
        Error::Vault(_) | Error::Provider(_) => {
            "Could not select the vault password. Check the Restic item, vault connection and unlock state."
        }
        _ => {
            "Quartermaster could not complete the Restic handoff. Check the configured native executable and retry."
        }
    }
}

pub(super) async fn serve(
    listener: tokio::net::UnixListener,
    shared: Shared,
    paths: ServicePaths,
) -> Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(
        crate::owner::approval_queue::CAPACITY,
    ));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            let message =
                b"Quartermaster is handling too many Restic requests. Retry when one finishes.";
            let mut reply = vec![4];
            reply.extend_from_slice(&(message.len() as u32).to_be_bytes());
            reply.extend_from_slice(message);
            let _ = tokio::time::timeout(Duration::from_secs(1), stream.write_all(&reply)).await;
            continue;
        };
        let shared = Arc::clone(&shared);
        let paths = paths.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Ok(stream) = stream.into_std()
                && stream.set_nonblocking(false).is_ok()
            {
                handle(stream, &shared, &paths);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_rechecks_lifecycle_even_when_the_console_stays_interactive() {
        for invalidation in 0..5 {
            let (_directory, _paths, key, mut state, _receive) = super::super::tests::fixture();
            use ring::signature::KeyPair as _;
            state.administration.manager = Some(
                crate::owner::settings::Manager::unconfigured_fixture(key.public_key().as_ref()),
            );
            let session = state.ui.as_ref().unwrap().session.id();
            let generation = state.provider.generation();
            let revision = current_revision(&state).unwrap();
            check_admission(&mut state, session, generation, revision, true).unwrap();
            let mut peer_live = true;
            let mut checked_revision = revision;
            match invalidation {
                0 => state
                    .host_events
                    .record(crate::platform::HostSessionEvent::Wake),
                1 => state
                    .host_events
                    .record(crate::platform::HostSessionEvent::ScreenLock),
                2 => peer_live = false,
                3 => {
                    state.provider.lock().unwrap();
                }
                _ => checked_revision = Revision(revision.0 + 1),
            }
            assert!(
                check_admission(&mut state, session, generation, checked_revision, peer_live)
                    .is_err()
            );
        }
    }

    #[test]
    fn cancellation_after_release_reports_admission_only_to_its_original_ui_session() {
        let (_directory, paths, _key, mut state, _receive) = super::super::tests::fixture();
        let id = "aa".repeat(16);
        state.admitted_approval = Some((id.clone(), state.ui.as_ref().unwrap().session.id()));
        assert!(matches!(
            super::super::control::handle(
                crate::owner::protocol::Client::Cancel { id: id.clone() },
                &mut state,
                &paths.load_policy()
            )
            .unwrap(),
            Reply::AlreadyAdmitted
        ));
        state.disconnect_ui();
        assert!(matches!(
            super::super::control::handle(
                crate::owner::protocol::Client::Cancel { id },
                &mut state,
                &paths.load_policy()
            )
            .unwrap(),
            Reply::UnknownOperation
        ));
    }

    fn invocation(args: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"arguments":args,"workingDirectory":"/tmp"}))
            .unwrap()
    }

    #[test]
    fn local_repository_arguments_are_frozen_without_shell_interpretation() {
        let input = invocation(&["--repo", "/tmp/test repo", "backup", "$(no shell)"]);
        let decoded = Invocation::decode(&input).unwrap();
        assert_eq!(decoded.arguments[3], "$(no shell)");
    }

    #[test]
    fn rejects_remote_ambiguous_and_password_override_invocations() {
        for args in [
            vec!["snapshots"],
            vec!["-r", "s3:bucket", "snapshots"],
            vec!["--repo", "/tmp/a", "--repo=/tmp/b", "init"],
            vec![
                "--repo=/tmp/a",
                "--password-command=cat /tmp/password",
                "init",
            ],
            vec!["--repo=/tmp/a", "--stdin", "backup"],
            vec!["--repo=/tmp/a", "-o", "foo=bar", "init"],
        ] {
            assert!(Invocation::decode(&invocation(&args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn rejects_shorthand_repository_and_option_bypasses() {
        for suffix in [
            vec!["-qr", "s3:bucket", "snapshots"],
            vec!["-qr/some/local/path", "snapshots"],
            vec!["-ofoo=bar", "snapshots"],
            vec!["-qo", "foo=bar", "snapshots"],
            vec!["-qpother", "snapshots"],
            vec!["--insecure-no-password", "snapshots"],
        ] {
            let mut args = vec!["--repo", "/tmp/local"];
            args.extend(suffix);
            assert!(Invocation::decode(&invocation(&args)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn accepts_supported_local_repository_spellings_and_single_flags() {
        for repo in [
            vec!["--repo", "/tmp/local"],
            vec!["--repo=/tmp/local"],
            vec!["-r", "/tmp/local"],
            vec!["-r/tmp/local"],
            vec!["-r=/tmp/local"],
        ] {
            let mut args = repo;
            args.extend(["-q", "--no-cache", "snapshots"]);
            assert!(Invocation::decode(&invocation(&args)).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn requester_disconnect_and_extra_input_prevent_release() {
        let (server, mut client) = UnixStream::pair().unwrap();
        connected(&server).unwrap();
        client.write_all(b"x").unwrap();
        assert!(connected(&server).is_err());
        drop(client);
        assert!(connected(&server).is_err());
        let (server, client) = UnixStream::pair().unwrap();
        drop(client);
        assert!(connected(&server).is_err());
    }
    mod native {
        use super::super::super::{approval, control};
        use super::*;
        use crate::platform::macos::ipc::{
            self,
            test_support::{Fixture, send},
        };
        use ring::signature::KeyPair as _;

        #[test]
        fn locked_and_warm_handoffs_use_the_shared_authentication_and_cancellation_lifecycle() {
            for (cold, invalidation) in [true, false]
                .into_iter()
                .flat_map(|cold| (0..4).map(move |invalidation| (cold, invalidation)))
            {
                let (_directory, paths, key, mut state, _receive) =
                    super::super::super::tests::fixture_with_cache(cold);
                let (peer_send, peer_receive) = mpsc::sync_channel(1);
                let listener = Fixture::new(move |event| {
                    if let ipc::Event::Message { connection, .. } = event {
                        peer_send.send(connection.handle()).unwrap();
                    }
                    Ok(Vec::new())
                });
                let client = listener.client();
                send(&client, b"peer", None);
                let peer = peer_receive.recv().unwrap();
                state.administration.manager =
                    Some(crate::owner::settings::Manager::unconfigured_fixture(
                        key.public_key().as_ref(),
                    ));
                let revision = current_revision(&state).unwrap();
                let mut pending = state.pending.take().unwrap();
                state.operations.cancel(pending.id, &pending.principal);
                let wire = pending.review(
                    state.ui.as_ref().unwrap(),
                    state.authorizer.policy_digest().unwrap(),
                    [0; 32],
                );
                let mut signing = Signing::default();
                let digest = BASE64
                    .decode(&wire.request_digest)
                    .unwrap()
                    .try_into()
                    .unwrap();
                signing
                    .begin(&state.ui.as_ref().unwrap().session, digest, Instant::now())
                    .unwrap();
                let nonce = signing.nonce().unwrap();
                let wire = ApprovalReview {
                    nonce: BASE64.encode(nonce),
                    ..wire
                };
                let executable = Path::new("/bin/cat");
                let launch = Launch::spawn(
                    executable,
                    &[],
                    Path::new("/tmp"),
                    &requirement_for_path(executable).unwrap(),
                )
                .unwrap();
                let pid = launch.pid();
                let (requester, _caller) = UnixStream::pair().unwrap();
                let (completion, receive) = mpsc::sync_channel(1);
                pending.action = ApprovalAction::Handoff(Box::new(Dispatch {
                    wire,
                    signing,
                    binding: crate::owner::test_support::vault::binding(
                        "restic-password",
                        "22222222-2222-4222-8222-222222222222",
                    ),
                    requester,
                    ui_peer: peer,
                    revision,
                    root: paths.root.clone(),
                    launch,
                    completion,
                }));
                let id = pending.id;
                state.pending = Some(pending);
                std::thread::sleep(Duration::from_millis(3));
                let authenticated = now().unwrap();
                let work = approval::begin_native_presence(
                    id,
                    authenticated,
                    &mut state,
                    &paths.load_policy(),
                    paths.vault_source().and_then(|s| s.identity()),
                )
                .unwrap();
                assert_eq!(work.is_some(), cold);
                if let Some((source, operation)) = work {
                    let snapshot = vault::fixture::open(source);
                    vault::finish_unlock(&paths.root, &mut state.provider, operation, snapshot)
                        .unwrap();
                }
                let pending = state.pending.as_ref().unwrap();
                assert_eq!(pending.handoff().unwrap().signing.nonce().unwrap(), nonce);
                assert!(
                    pending
                        .handoff()
                        .unwrap()
                        .signing
                        .authenticated_at()
                        .is_some()
                );
                assert!(state.provider.snapshot().is_some());
                assert!(receive.try_recv().is_err());
                assert!(
                    approval::check_authenticated_deadline(
                        authenticated,
                        authenticated.checked_add(Duration::from_secs(30)).unwrap()
                    )
                    .is_err()
                );
                state.pending.as_mut().unwrap().resolving_credential = true;
                if invalidation == 0 {
                    let identity = state.pending.as_ref().unwrap().provider.identity.clone();
                    let previous = state.provider.generation();
                    let (operation, _) = state.provider.begin_refresh(&identity).unwrap();
                    let snapshot = crate::owner::test_support::vault::snapshot_at(
                        "github-write",
                        "22222222-2222-4222-8222-222222222222",
                        [9; 16],
                        identity.synchronized_at + Duration::from_secs(1),
                    );
                    let prepared = vault::fixture::prepared(&paths.root, snapshot);
                    let shared =
                        Arc::new((std::sync::Mutex::new(state), std::sync::Condvar::new()));
                    let publication = vault::publication(&paths.root, prepared).unwrap();
                    super::super::super::vault_workflow::finish_publication_with(
                        publication,
                        operation,
                        &shared,
                        |state, previous, identity| {
                            approval::adopt_refreshed_source(id, state, previous, identity)
                        },
                    )
                    .unwrap();
                    state = Arc::try_unwrap(shared)
                        .ok()
                        .unwrap()
                        .0
                        .into_inner()
                        .unwrap();
                    let pending = state.pending.as_ref().unwrap();
                    pending.check(&state).unwrap();
                    assert_ne!(state.provider.generation(), previous);
                    assert_eq!(pending.provider.generation, state.provider.generation());
                    assert_eq!(pending.handoff().unwrap().wire.nonce, BASE64.encode(nonce));
                }
                match invalidation {
                    0 => assert!(matches!(
                        control::handle(
                            crate::owner::protocol::Client::Cancel { id: id.to_string() },
                            &mut state,
                            &paths.load_policy()
                        )
                        .unwrap(),
                        Reply::Canceled
                    )),
                    1 => {
                        state.lock_vault().unwrap();
                    }
                    2 => state.disconnect_ui(),
                    _ => {
                        state
                            .host_events
                            .record(crate::platform::HostSessionEvent::ScreenLock);
                        state.synchronize_host_events().unwrap();
                    }
                }
                assert!(state.pending.is_none());
                assert!(matches!(
                    receive.try_recv(),
                    Err(mpsc::TryRecvError::Disconnected)
                ));
                assert!(approval::proof(&id.to_string(), b"late signature", &mut state).is_err());
                assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
            }
        }
    }
}
