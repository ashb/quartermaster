use super::{
    github::{configuration::Mode, repository::RepositoryBinding},
    identity::VerifiedPrincipal,
    operation::{OperationError, OperationId},
    policy::{AuthorizationError, Authorizer, ExecutableOperation},
    provider_lifecycle::ProviderGeneration,
    request::{FrozenOperation, SIMULATION_HOST},
};
use qm_providers::{ProviderBinding, ProviderError, VaultSnapshot};
use ring::digest::{SHA256, digest};
use std::fmt;
use std::ops::Deref;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CredentialSelection {
    generation: ProviderGeneration,
    binding: ProviderBinding,
    checkpoint: [u8; 16],
    digest: [u8; 32],
}

impl CredentialSelection {
    pub(super) fn same_credential(&self, other: &Self) -> bool {
        self.binding == other.binding && self.digest == other.digest
    }
    pub(super) fn at_generation(snapshot: &VaultSnapshot, generation: ProviderGeneration) -> Self {
        Self {
            generation,
            binding: snapshot.binding().clone(),
            checkpoint: snapshot.checkpoint(),
            digest: snapshot.credential_digest(),
        }
    }

    pub(super) fn generation(&self) -> ProviderGeneration {
        self.generation
    }

    pub(super) fn matches_snapshot(&self, snapshot: &VaultSnapshot) -> bool {
        self.binding == *snapshot.binding()
            && self.checkpoint == snapshot.checkpoint()
            && self.digest == snapshot.credential_digest()
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn role(&self) -> &str {
        self.binding.role()
    }
}

#[derive(Debug)]
pub(super) enum Error {
    Operation(OperationError),
    Authorization(AuthorizationError),
    Provider(ProviderError),
    CredentialMismatch,
    InvalidCredential,
    Uncertain,
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(error) => write!(formatter, "{error}"),
            Self::Authorization(error) => write!(formatter, "{error:?}"),
            Self::Provider(error) => write!(formatter, "{error:?}"),
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl std::error::Error for Error {}

pub(super) struct PreparedRequest {
    id: OperationId,
    selection: CredentialSelection,
    request_digest: [u8; 32],
    wire_digest: [u8; 32],
    bytes: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
    repository: Option<Box<RepositoryBinding>>,
}

enum Destination {
    Simulation,
    Github(Box<RepositoryBinding>),
}

pub(super) struct Acquisition<'a> {
    pub(super) id: OperationId,
    pub(super) operation: &'a ExecutableOperation,
    pub(super) authorizer: &'a Authorizer,
    pub(super) principal: &'a VerifiedPrincipal,
    pub(super) selection: &'a CredentialSelection,
    pub(super) snapshot: &'a VaultSnapshot,
    pub(super) now: std::time::Instant,
}

pub(super) struct PreparedSimulationRequest(PreparedRequest);
pub(super) struct PreparedGitHubRequest(PreparedRequest);

impl PreparedSimulationRequest {
    pub(super) fn acquire(input: Acquisition<'_>) -> Result<Self, Error> {
        PreparedRequest::acquire(input, Destination::Simulation).map(Self)
    }
}

impl PreparedGitHubRequest {
    pub(super) fn acquire(
        input: Acquisition<'_>,
        repository: RepositoryBinding,
    ) -> Result<Self, Error> {
        PreparedRequest::acquire(input, Destination::Github(Box::new(repository))).map(Self)
    }
    pub(super) fn repository(&self) -> &RepositoryBinding {
        self.0
            .repository
            .as_deref()
            .expect("GitHub preparation has a verified repository")
    }
}

impl Deref for PreparedSimulationRequest {
    type Target = PreparedRequest;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Deref for PreparedGitHubRequest {
    type Target = PreparedRequest;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PreparedRequest {
    fn acquire(input: Acquisition<'_>, destination: Destination) -> Result<Self, Error> {
        let Acquisition {
            id,
            operation,
            authorizer,
            principal,
            selection,
            snapshot,
            now,
        } = input;
        let repository = match destination {
            Destination::Simulation if operation.request().mode() == Mode::Simulation => None,
            Destination::Github(binding)
                if binding.matches(
                    operation.request(),
                    selection,
                    authorizer.policy_generation(),
                ) =>
            {
                Some(binding)
            }
            _ => return Err(Error::Unavailable),
        };
        if !selection.matches_snapshot(snapshot) {
            return Err(Error::CredentialMismatch);
        }
        authorizer
            .check_acquisition(operation, principal, selection, now)
            .map_err(Error::Authorization)?;
        let credential = snapshot
            .decrypt_selected_for_owner()
            .map_err(Error::Provider)?;
        validate_token(&credential)?;
        let request = operation.request();
        let mut bytes = Zeroizing::new(Vec::with_capacity(8192));
        let host = if repository.is_some() {
            "api.github.com"
        } else {
            SIMULATION_HOST
        };
        bytes.extend_from_slice(
            format!(
                "{} {} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer ",
                request.method(),
                request.wire_path()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(&credential);
        if repository.is_some() {
            bytes.extend_from_slice(b"\r\nUser-Agent: Quartermaster\r\nAccept: application/vnd.github+json\r\nAccept-Encoding: identity\r\nX-GitHub-Api-Version: 2026-03-10");
        }
        bytes.extend_from_slice(format!("\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", request.body().len()).as_bytes());
        bytes.extend_from_slice(request.body().as_bytes());
        let wire_digest = digest(&SHA256, &bytes).as_ref().try_into().unwrap();
        Ok(Self {
            id,
            selection: selection.clone(),
            request_digest: request.digest(),
            wire_digest,
            bytes,
            credential,
            repository,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn wire_digest(&self) -> [u8; 32] {
        self.wire_digest
    }
    pub(super) fn credential(&self) -> &[u8] {
        &self.credential
    }
    pub(super) fn selection(&self) -> &CredentialSelection {
        &self.selection
    }

    pub(super) fn matches(
        &self,
        id: OperationId,
        selection: &CredentialSelection,
        request: &FrozenOperation,
    ) -> bool {
        self.id == id
            && &self.selection == selection
            && self.request_digest == request.digest()
            && digest(&SHA256, &self.bytes).as_ref() == self.wire_digest
    }
}

pub(super) fn validate_token(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty()
        || bytes.len() > 4096
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(b))
    {
        return Err(Error::InvalidCredential);
    }
    Ok(())
}

#[cfg(unix)]
pub(super) enum PreparedOperation {
    Simulation {
        request: Box<PreparedSimulationRequest>,
        transport: super::transport::ReadyHttp,
    },
    Github(Box<super::github::https::PreparedGitHub>),
}

#[cfg(unix)]
pub(super) enum InFlightOperation {
    Simulation(super::transport::InFlightHttp),
    Github(Box<super::github::https::InFlightGitHub>),
}

#[cfg(unix)]
impl InFlightOperation {
    pub(super) fn response(self) -> super::transport::OperationResponse {
        match self {
            Self::Simulation(receipt) => receipt.response(),
            Self::Github(receipt) => (*receipt).response(),
        }
    }
}

#[cfg(unix)]
impl PreparedOperation {
    pub(super) fn new(
        request: PreparedSimulationRequest,
        transport: super::transport::ReadyHttp,
    ) -> Self {
        Self::Simulation {
            request: Box::new(request),
            transport,
        }
    }
    pub(super) fn github(
        request: PreparedGitHubRequest,
        transport: super::github::https::ReadyGitHub,
    ) -> Result<Self, Error> {
        transport
            .stage(request)
            .map(|prepared| Self::Github(Box::new(prepared)))
            .map_err(|_| Error::Unavailable)
    }
    fn request(&self) -> &PreparedRequest {
        match self {
            Self::Simulation { request, .. } => request,
            Self::Github(prepared) => prepared.request(),
        }
    }
    pub(super) fn id(&self) -> OperationId {
        self.request().id
    }

    pub(super) fn handoff(
        self,
        registry: &mut super::operation::OperationRegistry,
        authorizer: &mut Authorizer,
        principal: &VerifiedPrincipal,
        snapshot: &VaultSnapshot,
    ) -> Result<InFlightOperation, Error> {
        self.handoff_at(
            registry,
            authorizer,
            principal,
            snapshot,
            std::time::Instant::now,
        )
    }

    fn handoff_at(
        self,
        registry: &mut super::operation::OperationRegistry,
        authorizer: &mut Authorizer,
        principal: &VerifiedPrincipal,
        snapshot: &VaultSnapshot,
        clock: impl FnOnce() -> std::time::Instant,
    ) -> Result<InFlightOperation, Error> {
        let id = self.id();
        if let Self::Github(prepared) = &self {
            prepared.validate().map_err(|_| Error::Unavailable)?;
        }
        registry
            .check_snapshot(id, principal, snapshot)
            .map_err(Error::Operation)?;
        registry
            .ready(id, principal, self.request())
            .map_err(Error::Operation)?;
        let admission = registry
            .admit(id, principal, authorizer, clock())
            .map_err(Error::Operation)?;
        let result = match self {
            Self::Simulation { request, transport } => transport
                .handoff(admission, *request)
                .map(InFlightOperation::Simulation),
            Self::Github(prepared) => (*prepared)
                .handoff(admission)
                .map(|receipt| InFlightOperation::Github(Box::new(receipt))),
        };
        match result {
            Ok(receipt) => Ok(receipt),
            Err(_) => {
                registry
                    .finish(id, super::operation::Completion::Uncertain)
                    .map_err(Error::Operation)?;
                Err(Error::Uncertain)
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/dispatch.rs"]
mod tests;
