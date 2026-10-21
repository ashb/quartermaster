use super::{
    dispatch::{self, Acquisition, PreparedGitHubRequest, PreparedSimulationRequest},
    github::repository::{PreparedMetadata, RepositoryBinding},
    identity::VerifiedPrincipal,
    operation::{OperationId, OperationRegistry},
    policy::Authorizer,
};
use qm_providers::VaultSnapshot;
use std::time::Instant;

fn acquisition<'a>(
    registry: &'a OperationRegistry,
    id: OperationId,
    principal: &'a VerifiedPrincipal,
    authorizer: &'a Authorizer,
    snapshot: &'a VaultSnapshot,
    now: Instant,
) -> Result<Acquisition<'a>, dispatch::Error> {
    let preparation = registry
        .preparation(id, principal)
        .map_err(dispatch::Error::Operation)?;
    Ok(Acquisition {
        id,
        principal,
        authorizer,
        snapshot,
        now,
        operation: &preparation.operation,
        selection: &preparation.selection,
    })
}

pub(super) fn prepare_simulation(
    registry: &OperationRegistry,
    id: OperationId,
    principal: &VerifiedPrincipal,
    authorizer: &Authorizer,
    snapshot: &VaultSnapshot,
    now: Instant,
) -> Result<PreparedSimulationRequest, dispatch::Error> {
    PreparedSimulationRequest::acquire(acquisition(
        registry, id, principal, authorizer, snapshot, now,
    )?)
}

pub(super) fn prepare_github(
    registry: &OperationRegistry,
    id: OperationId,
    principal: &VerifiedPrincipal,
    authorizer: &Authorizer,
    snapshot: &VaultSnapshot,
    binding: RepositoryBinding,
    now: Instant,
) -> Result<PreparedGitHubRequest, dispatch::Error> {
    PreparedGitHubRequest::acquire(
        acquisition(registry, id, principal, authorizer, snapshot, now)?,
        binding,
    )
}

pub(super) fn prepare_metadata(
    registry: &OperationRegistry,
    id: OperationId,
    principal: &VerifiedPrincipal,
    authorizer: &Authorizer,
    snapshot: &VaultSnapshot,
    now: Instant,
) -> Result<PreparedMetadata, dispatch::Error> {
    PreparedMetadata::acquire(acquisition(
        registry, id, principal, authorizer, snapshot, now,
    )?)
}
