use super::{ServicePaths, checked, failure, state::OwnerState};
use crate::owner::{
    dispatch::{
        self, InFlightOperation, PreparedGitHubRequest, PreparedOperation,
        PreparedSimulationRequest,
    },
    github::{
        https::{InFlightMetadata, PreparedMetadataTransport},
        repository::{PreparedMetadata, RepositoryBinding},
    },
    identity::VerifiedPrincipal,
    operation::OperationId,
    policy::AuthorizationOutcome,
    transport::OperationResponse,
};
use qm_macos::presence_clock::{MonotonicTimestamp, monotonic_raw as presence_now};
use std::{
    io,
    time::{Duration, Instant},
};
impl OwnerState {
    pub(super) fn handoff(
        &mut self,
        prepared: PreparedOperation,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
    ) -> Result<InFlightOperation, dispatch::Error> {
        self.handoff_with_clock(prepared, principal, paths, presence_now)
    }

    pub(super) fn handoff_with_clock(
        &mut self,
        prepared: PreparedOperation,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
        clock: impl FnOnce() -> io::Result<MonotonicTimestamp>,
    ) -> Result<InFlightOperation, dispatch::Error> {
        self.refresh_policy(paths)
            .map_err(|_| dispatch::Error::Unavailable)?;
        self.operations
            .check_provider_generation(prepared.id(), principal, self.provider.generation())
            .map_err(dispatch::Error::Operation)?;
        if let Some(pending) = self.pending.as_ref().filter(|p| p.id == prepared.id()) {
            let now = clock().map_err(|_| dispatch::Error::Unavailable)?;
            let offset = self
                .operations
                .authentication_offset(pending.id, &pending.principal)
                .map_err(dispatch::Error::Operation)?;
            if pending
                .created()
                .checked_add(offset)
                .and_then(|at| now.checked_duration_since(at))
                .is_none_or(|age| age >= Duration::from_secs(30))
            {
                self.cancel_pending();
                return Err(dispatch::Error::Authorization(
                    crate::owner::policy::AuthorizationError::Expired,
                ));
            }
        }
        let snapshot = self
            .provider
            .snapshot()
            .ok_or(dispatch::Error::CredentialMismatch)?;
        prepared.handoff(
            &mut self.operations,
            &mut self.authorizer,
            principal,
            snapshot,
        )
    }

    pub(super) fn prepare(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
    ) -> io::Result<PreparedSimulationRequest> {
        self.refresh_policy(paths)?;
        checked(self.operations.check_provider_generation(
            id,
            principal,
            self.provider.generation(),
        ))?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| failure("vault is locked"))?;
        checked(crate::owner::execution::prepare_simulation(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        ))
    }

    pub(super) fn finish(
        &mut self,
        id: OperationId,
        response: &OperationResponse,
    ) -> io::Result<()> {
        checked(self.operations.finish(id, response.completion()))
    }

    pub(super) fn prepare_metadata(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
    ) -> io::Result<PreparedMetadata> {
        self.refresh_policy(paths)?;
        checked(self.operations.check_provider_generation(
            id,
            principal,
            self.provider.generation(),
        ))?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| failure("vault is locked"))?;
        checked(crate::owner::execution::prepare_metadata(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        ))
    }

    pub(super) fn handoff_metadata(
        &mut self,
        prepared: PreparedMetadataTransport,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
    ) -> io::Result<InFlightMetadata> {
        self.refresh_policy(paths)?;
        checked(self.operations.check_provider_generation(
            prepared.request().id(),
            principal,
            self.provider.generation(),
        ))?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| failure("vault is locked"))?;
        prepared.validate()?;
        let admission = checked(self.operations.admit_metadata(
            prepared.request(),
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        ))?;
        prepared.handoff(admission)
    }

    pub(super) fn prepare_github(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
        binding: RepositoryBinding,
    ) -> io::Result<PreparedGitHubRequest> {
        self.refresh_policy(paths)?;
        checked(self.operations.check_provider_generation(
            id,
            principal,
            self.provider.generation(),
        ))?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| failure("vault is locked"))?;
        checked(crate::owner::execution::prepare_github(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            binding,
            Instant::now(),
        ))
    }

    pub(super) fn redirect(
        &mut self,
        redirect: crate::owner::transport::ReadRedirect,
        principal: &VerifiedPrincipal,
        paths: &ServicePaths,
    ) -> io::Result<OperationId> {
        self.refresh_policy(paths)?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| failure("vault is locked"))?;
        if redirect.selection.generation() != self.provider.generation()
            || !redirect.selection.matches_snapshot(snapshot)
        {
            return Err(failure("provider selection changed"));
        }
        let outcome = self
            .authorizer
            .authorize(principal, redirect.target, Instant::now())
            .map_err(|_| failure("redirect denied"))?;
        if !matches!(&outcome, AuthorizationOutcome::Allowed(_)) {
            return Err(failure("redirect requires approval"));
        }
        let id = checked(self.operations.register(outcome, Instant::now()))?;
        checked(
            self.operations
                .select_credential(id, principal, redirect.selection),
        )?;
        Ok(id)
    }
}
