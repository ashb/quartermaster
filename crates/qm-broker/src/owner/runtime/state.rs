use super::{
    ServicePaths,
    approval::{ApprovalDelivery, UiSession},
    checked, failure, random,
};
use crate::owner::{
    dispatch::CredentialSelection,
    github::https::Connector,
    identity::VerifiedPrincipal,
    operation::OperationRegistry,
    policy::{AuthorizationError, AuthorizationOutcome, Authorizer, SessionPolicy},
    provider_lifecycle::ProviderState,
    request as http_request,
    transport::DummyUpstream,
};
use crate::platform::HostSessionEvent;
use std::{io, time::Instant};
pub(super) struct OwnerState {
    pub(super) ui: Option<UiSession>,
    pub(super) approval_public_key: Option<Vec<u8>>,
    pub(super) pending: Option<ApprovalDelivery>,
    pub(super) provider: ProviderState,
    pub(super) authorizer: Authorizer,
    pub(super) session_policy: SessionPolicy,
    pub(super) upstream: DummyUpstream,
    pub(super) github: Connector,
    pub(super) operations: OperationRegistry,
}

impl OwnerState {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self {
            ui: None,
            approval_public_key: None,
            pending: None,
            provider: ProviderState::default(),
            authorizer: Authorizer::new(random()?),
            session_policy: SessionPolicy::default(),
            upstream: DummyUpstream::default(),
            github: Connector::default(),
            operations: OperationRegistry::default(),
        })
    }

    pub(super) fn refresh_policy(&mut self, paths: &ServicePaths) -> io::Result<()> {
        match self
            .authorizer
            .install_current(crate::owner::persistence::policy(&paths.root))
        {
            Ok(true) => {
                self.cancel_pending();
                if let Some(ui) = &self.ui {
                    checked(
                        ui.session
                            .update_policy(checked(self.authorizer.policy_digest())?),
                    )?;
                }
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(error) => {
                self.disconnect_ui();
                Err(failure(format!("{error:?}")))
            }
        }
    }

    pub(super) fn authorize(
        &mut self,
        principal: &VerifiedPrincipal,
        request: http_request::FrozenOperation,
        paths: &ServicePaths,
    ) -> io::Result<AuthorizationOutcome> {
        self.refresh_policy(paths)?;
        let now = Instant::now();
        let outcome = self
            .authorizer
            .authorize(principal, request.clone(), now)
            .and_then(|outcome| {
                if let AuthorizationOutcome::Allowed(permit) = &outcome
                    && let Some(snapshot) = self.provider.snapshot()
                {
                    let selection =
                        CredentialSelection::at_generation(snapshot, self.provider.generation());
                    self.authorizer
                        .check_acquisition(permit, principal, &selection, now)?;
                }
                Ok(outcome)
            });
        match outcome {
            Err(
                AuthorizationError::Denied
                | AuthorizationError::Expired
                | AuthorizationError::BudgetExhausted
                | AuthorizationError::CredentialMismatch,
            ) if matches!(
                request.action(),
                http_request::Action::ReadIssue | http_request::Action::ListIssues
            ) =>
            {
                let role = match self.provider.snapshot() {
                    Some(snapshot) => snapshot.binding().role().to_owned(),
                    None => crate::owner::vault::Source::capture(&paths.root)
                        .map_err(|_| failure("cache unavailable"))?
                        .binding()
                        .ok_or_else(|| failure("vault is not enrolled"))?
                        .role()
                        .to_owned(),
                };
                checked(
                    self.authorizer
                        .request_read_grant(principal, request, &role),
                )
                .map(AuthorizationOutcome::RequireApproval)
            }
            outcome => checked(outcome),
        }
    }

    pub(super) fn cancel_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.operations.cancel(pending.id, &pending.principal);
        }
    }

    pub(super) fn disconnect_ui(&mut self) {
        if let Some(ui) = self.ui.take() {
            self.operations.cancel_interactive_session(ui.session.id());
        }
        self.cancel_pending();
    }

    pub(super) fn end_host_session(&mut self) -> io::Result<()> {
        if !self.authorizer.session_active() {
            return Ok(());
        }
        self.authorizer.revoke_session();
        self.disconnect_ui();
        checked(self.provider.lock())
    }

    pub(super) fn host_session_event(&mut self, event: HostSessionEvent) -> io::Result<()> {
        if !self.session_policy.preserves_reads(event) {
            return self.end_host_session();
        }
        self.authorizer.revoke_approvals();
        self.operations.cancel_approvals();
        self.disconnect_ui();
        self.provider.cancel_pending();
        Ok(())
    }

    pub(super) fn ensure_host_session(&self) -> io::Result<()> {
        if self.authorizer.session_active() {
            Ok(())
        } else {
            Err(failure(
                "host authorization session ended; restart the backend",
            ))
        }
    }
}
