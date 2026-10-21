use super::{
    dispatch::{self, Acquisition, PreparedGitHubRequest, PreparedSimulationRequest},
    github::repository::{PreparedMetadata, RepositoryBinding, RepositoryLookup},
    identity::VerifiedPrincipal,
    operation::{OperationId, OperationRegistry},
    policy::{AuthorizationError, Authorizer},
    request::Action,
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
    let input = acquisition(registry, id, principal, authorizer, snapshot, now)?;
    if !matches!(
        input.operation.request().action(),
        Action::ListIssues | Action::ReadIssue
    ) {
        return Err(dispatch::Error::Authorization(AuthorizationError::Denied));
    }
    authorizer
        .check_acquisition(input.operation, principal, input.selection, now)
        .map_err(dispatch::Error::Authorization)?;
    let config = authorizer
        .github_configuration()
        .ok_or(dispatch::Error::Unavailable)?;
    let lookup = RepositoryLookup::new(
        config,
        input.operation.request(),
        input.selection.clone(),
        authorizer.policy_generation(),
    )
    .map_err(|_| dispatch::Error::Unavailable)?;
    PreparedMetadata::new(id, lookup, snapshot)
}
