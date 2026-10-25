use super::error::{Error, Fault, Result};
use super::{PolicyInput, state::OwnerState};
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
        policy: &PolicyInput,
    ) -> Result<InFlightOperation> {
        self.handoff_with_clock(prepared, principal, policy, presence_now)
    }

    pub(super) fn handoff_with_clock(
        &mut self,
        prepared: PreparedOperation,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
        clock: impl FnOnce() -> io::Result<MonotonicTimestamp>,
    ) -> Result<InFlightOperation> {
        self.refresh_policy(policy)?;
        self.operations.check_provider_generation(
            prepared.id(),
            principal,
            self.provider.generation(),
        )?;
        if let Some(pending) = self.pending.as_ref().filter(|p| p.id == prepared.id()) {
            let now = clock()?;
            let offset = self
                .operations
                .authentication_offset(pending.id, &pending.principal)?;
            if pending
                .created()
                .checked_add(offset)
                .and_then(|at| now.checked_duration_since(at))
                .is_none_or(|age| age >= Duration::from_secs(30))
            {
                self.cancel_pending();
                return Err(crate::owner::policy::AuthorizationError::Expired.into());
            }
        }
        let snapshot = self
            .provider
            .snapshot()
            .ok_or(Error::Dispatch(dispatch::Error::CredentialMismatch))?;
        prepared
            .handoff(
                &mut self.operations,
                &mut self.authorizer,
                principal,
                snapshot,
            )
            .map_err(Error::from)
    }

    pub(super) fn prepare(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
    ) -> Result<PreparedSimulationRequest> {
        self.refresh_policy(policy)?;
        self.operations
            .check_provider_generation(id, principal, self.provider.generation())?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        crate::owner::execution::prepare_simulation(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        )
        .map_err(Error::from)
    }

    pub(super) fn finish(&mut self, id: OperationId, response: &OperationResponse) -> Result<()> {
        self.operations
            .finish(id, response.completion())
            .map_err(Error::from)
    }

    pub(super) fn prepare_metadata(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
    ) -> Result<PreparedMetadata> {
        self.refresh_policy(policy)?;
        self.operations
            .check_provider_generation(id, principal, self.provider.generation())?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        crate::owner::execution::prepare_metadata(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        )
        .map_err(Error::from)
    }

    pub(super) fn handoff_metadata(
        &mut self,
        prepared: PreparedMetadataTransport,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
    ) -> Result<InFlightMetadata> {
        self.refresh_policy(policy)?;
        self.operations.check_provider_generation(
            prepared.request().id(),
            principal,
            self.provider.generation(),
        )?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        prepared.validate()?;
        let admission = self.operations.admit_metadata(
            prepared.request(),
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        )?;
        prepared.handoff(admission).map_err(Error::from)
    }

    pub(super) fn prepare_github(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
        binding: RepositoryBinding,
    ) -> Result<PreparedGitHubRequest> {
        self.refresh_policy(policy)?;
        self.operations
            .check_provider_generation(id, principal, self.provider.generation())?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        crate::owner::execution::prepare_github(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            binding,
            Instant::now(),
        )
        .map_err(Error::from)
    }

    pub(super) fn redirect(
        &mut self,
        redirect: crate::owner::transport::ReadRedirect,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
    ) -> Result<OperationId> {
        self.refresh_policy(policy)?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        if redirect.selection.generation() != self.provider.generation()
            || !redirect.selection.matches_snapshot(snapshot)
        {
            return Err(Error::State(Fault::ProviderChanged));
        }
        let outcome = self
            .authorizer
            .authorize(principal, redirect.target, Instant::now())
            .map_err(|_| Error::State(Fault::RedirectDenied))?;
        if !matches!(&outcome, AuthorizationOutcome::Allowed(_)) {
            return Err(Error::State(Fault::RedirectRequiresApproval));
        }
        let id = self.operations.register(outcome, Instant::now())?;
        self.operations
            .select_credential(id, principal, redirect.selection)?;
        Ok(id)
    }

    pub(super) fn prepare_unscoped_github(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        policy: &PolicyInput,
    ) -> Result<PreparedGitHubRequest> {
        self.refresh_policy(policy)?;
        self.operations
            .check_provider_generation(id, principal, self.provider.generation())?;
        let snapshot = self
            .provider
            .snapshot()
            .ok_or_else(|| Error::State(Fault::VaultLocked))?;
        crate::owner::execution::prepare_unscoped_github(
            &self.operations,
            id,
            principal,
            &self.authorizer,
            snapshot,
            Instant::now(),
        )
        .map_err(Error::from)
    }
}
