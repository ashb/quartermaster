use super::error::{Error, Fault, Result};
use super::{ServicePaths, Shared, approval::request_approval};
use crate::owner::{
    deadline::Deadline,
    dispatch::{self, CredentialSelection, PreparedOperation},
    github::configuration::Mode,
    identity::VerifiedPrincipal,
    operation::OperationId,
    policy::AuthorizationOutcome,
    request as http_request,
    transport::OperationResponse,
};
use qm_macos::{peer_identity::PeerIdentity, presence_clock::monotonic_raw as presence_now};
use std::{
    io::{self, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
pub(super) fn response(stream: &mut UnixStream, response: OperationResponse) -> io::Result<()> {
    response_until(stream, response, Deadline::after(Duration::from_secs(5))?)
}

pub(super) fn response_until(
    stream: &mut UnixStream,
    response: OperationResponse,
    deadline: Deadline,
) -> io::Result<()> {
    let mut stream = ResponseWriter { stream, deadline };
    if let OperationResponse::Github(response) = response {
        return response.write(&mut stream);
    }
    let (status, body) = response.public_parts();
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub(super) struct ResponseWriter<'a> {
    stream: &'a mut UnixStream,
    deadline: Deadline,
}

impl Write for ResponseWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.deadline.remaining()?;
        self.stream
            .set_write_timeout(Some(remaining.min(Duration::from_secs(5))))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(super) fn connected(stream: &UnixStream) -> bool {
    let mut byte = [0u8];
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
}

pub(super) fn handle_http(
    stream: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let session = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?
        .authorizer
        .session();
    let (principal, peer) = VerifiedPrincipal::capture(stream, session)?;
    let principal = Arc::new(principal);
    let result = handle_verified_http(stream, shared, paths, &principal, peer);
    let mut state = shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?;
    if state
        .pending
        .as_ref()
        .is_some_and(|p| p.principal.binding() == principal.binding())
    {
        state.cancel_pending();
    }
    state.operations.release_connection(&principal);
    result
}

pub(super) fn handle_verified_http(
    stream: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
    principal: &Arc<VerifiedPrincipal>,
    peer: PeerIdentity,
) -> Result<()> {
    let config = {
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.refresh_policy(&policy)?;
        state.authorizer.github_configuration().cloned()
    };
    let request = http_request::read_configured(stream, config.as_ref())?;
    let created = presence_now()?;
    let cold = {
        let state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state
            .provider
            .snapshot()
            .is_none()
            .then_some(state.provider.generation())
    };
    let binding = if cold.is_some() {
        crate::owner::vault::Source::capture(&paths.root).map(|source| source.binding())
    } else {
        Ok(None)
    };
    let (id, interactive) = {
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        if cold.is_some_and(|generation| generation != state.provider.generation()) {
            return Err(Error::State(Fault::ProviderChanged));
        }
        let outcome = state.authorize(principal, request, &policy, binding)?;
        let interactive = matches!(&outcome, AuthorizationOutcome::RequireApproval(_));
        let id = state.operations.register(outcome, Instant::now())?;
        if !interactive {
            let snapshot = state
                .provider
                .snapshot()
                .ok_or_else(|| Error::State(Fault::VaultLocked))?;
            let selection =
                CredentialSelection::at_generation(snapshot, state.provider.generation());
            state
                .operations
                .select_credential(id, principal, selection)?;
        }
        (id, interactive)
    };
    if !interactive {
        return execute_ready(stream, shared, paths, principal, id);
    }
    let receive = request_approval(id, principal, peer, created, shared, paths)?;
    loop {
        shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?
            .operations
            .check_wait(id, principal, Instant::now())?;
        if !connected(stream) {
            return Err(Error::State(Fault::Canceled));
        }
        match receive.recv_timeout(Duration::from_millis(25)) {
            Ok(ready) => {
                if ready.id != id || ready.principal.binding() != principal.binding() {
                    return Err(Error::State(Fault::InvalidOperation));
                }
                return execute_ready(stream, shared, paths, principal, id);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Error::State(Fault::Canceled)),
        }
    }
}

pub(super) fn execute_ready(
    stream: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
    principal: &VerifiedPrincipal,
    id: OperationId,
) -> Result<()> {
    let mode = {
        let state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.operations.request(id, principal)?.mode()
    };
    if mode == Mode::Github {
        return execute_github(stream, shared, paths, principal, id);
    }
    let (request, upstream) = {
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        (
            state.prepare(id, principal, &policy)?,
            state.upstream.clone(),
        )
    };
    let transport = upstream.connect()?;
    let prepared = PreparedOperation::new(request, transport);
    if prepared.id() != id {
        return Err(Error::State(Fault::InvalidOperation));
    }
    let handoff = {
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        if !connected(stream) {
            return Err(Error::State(Fault::Canceled));
        }
        state.handoff(prepared, principal, &policy)
    };
    let outcome = match handoff {
        Ok(receipt) => receipt.response(),
        Err(Error::Dispatch(dispatch::Error::Uncertain)) => {
            return response(stream, OperationResponse::Uncertain).map_err(Error::from);
        }
        Err(error) => return Err(error),
    };
    shared
        .0
        .lock()
        .map_err(|_| Error::State(Fault::StateUnavailable))?
        .finish(id, &outcome)?;
    response(stream, outcome).map_err(Error::from)
}

pub(super) fn execute_github(
    stream: &mut UnixStream,
    shared: &Shared,
    paths: &ServicePaths,
    principal: &VerifiedPrincipal,
    mut id: OperationId,
) -> Result<()> {
    let (deadline, connector) = {
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.refresh_policy(&policy)?;
        let deadline =
            state
                .operations
                .read_deadline(id, principal, &state.authorizer, Instant::now())?;
        (deadline, state.github.clone())
    };
    let mut visited = Vec::new();
    for redirects in 0..=3 {
        let metadata = {
            let policy = paths.load_policy();
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            let digest = state.operations.request(id, principal)?.digest();
            if visited.contains(&digest) {
                return Err(Error::State(Fault::RedirectLoop));
            }
            visited.push(digest);
            state.prepare_metadata(id, principal, &policy)?
        };
        let prepared = connector.connect(deadline)?.stage_metadata(metadata)?;
        let receipt = {
            let policy = paths.load_policy();
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            if !connected(stream) {
                return Err(Error::State(Fault::Canceled));
            }
            state.handoff_metadata(prepared, principal, &policy)?
        };
        let binding = match receipt.response() {
            Ok(binding) => binding,
            Err(crate::owner::github::response::MetadataFailure::Public(public)) => {
                return response_until(stream, OperationResponse::Github(public), deadline)
                    .map_err(Error::from);
            }
            Err(crate::owner::github::response::MetadataFailure::Invalid) => {
                return Err(Error::State(Fault::RepositoryMismatch));
            }
        };
        let request = {
            let policy = paths.load_policy();
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            state.prepare_github(id, principal, &policy, binding)?
        };
        let prepared = PreparedOperation::github(request, connector.connect(deadline)?)?;
        let receipt = {
            let policy = paths.load_policy();
            let mut state = shared
                .0
                .lock()
                .map_err(|_| Error::State(Fault::StateUnavailable))?;
            if !connected(stream) {
                return Err(Error::State(Fault::Canceled));
            }
            state.handoff(prepared, principal, &policy)?
        };
        let outcome = receipt.response();
        let policy = paths.load_policy();
        let mut state = shared
            .0
            .lock()
            .map_err(|_| Error::State(Fault::StateUnavailable))?;
        state.finish(id, &outcome)?;
        match outcome {
            OperationResponse::Redirect(redirect) => {
                if redirects == 3 {
                    return Err(Error::State(Fault::RedirectLimit));
                }
                id = state.redirect(*redirect, principal, &policy)?;
            }
            response_body => {
                drop(state);
                return response_until(stream, response_body, deadline).map_err(Error::from);
            }
        }
    }
    Err(Error::State(Fault::RedirectLimit))
}
