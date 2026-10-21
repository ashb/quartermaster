use super::{
    deadline::{Deadline, Sample, continuous_now},
    dispatch::CredentialSelection,
    github::configuration::{GitHubConfig, Mode},
    grant::{GrantTable, GrantUse, ReadGrantClaims, ReadGrantProposal},
    identity::{PrincipalBinding, VerifiedPrincipal},
    request::{Action, FrozenOperation},
};
use qm_providers::{ApprovedRequest, RequestBinding};
use ring::digest::SHA256;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AuthorizationError {
    InvalidPolicy,
    Denied,
    Expired,
    BudgetExhausted,
    PolicyChanged,
    SessionRevoked,
    WrongPrincipal,
    InvalidApproval,
    CredentialMismatch,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum PolicyDecision {
    Allow,
    #[default]
    RequireApproval,
    Deny,
}

pub(super) struct SessionPolicy {
    pub(super) reads_survive_lock: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            reads_survive_lock: true,
        }
    }
}

impl SessionPolicy {
    pub(super) fn preserves_reads(&self, event: crate::platform::HostSessionEvent) -> bool {
        self.reads_survive_lock && event != crate::platform::HostSessionEvent::Logout
    }
}

#[derive(Serialize)]
pub(super) struct Policy {
    version: u8,
    writes: PolicyDecision,
    #[serde(skip)]
    github: Option<GitHubConfig>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            writes: PolicyDecision::RequireApproval,
            github: None,
        }
    }
}

impl Policy {
    pub(super) fn with_github(mut self, config: GitHubConfig) -> Self {
        self.github = Some(config);
        self
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = ring::digest::Context::new(&SHA256);
        hash.update(&serde_json::to_vec(self).expect("policy contains only serializable data"));
        if let Some(config) = &self.github {
            hash.update(b"\0quartermaster.github-configuration.v1\0");
            hash.update(&config.digest());
        }
        hash.finish().as_ref().try_into().unwrap()
    }
}

enum AuthorizationEvidence {
    PolicyAllow(GrantUse),
    VerifiedApproval(Box<ApprovalEvidence>),
}

struct ApprovalEvidence {
    approved: ApprovedRequest,
    expected: RequestBinding,
    authenticated: Instant,
    generation: u64,
    purpose: ApprovalPurpose,
}

enum ApprovalPurpose {
    Write,
    ReadGrant(Box<ApprovedReadGrant>),
}

struct ApprovedReadGrant {
    proposal: ReadGrantProposal,
    selection: CredentialSelection,
}

pub(super) struct ExecutableOperation {
    request: FrozenOperation,
    principal: PrincipalBinding,
    policy_generation: u64,
    session_generation: u64,
    evidence: AuthorizationEvidence,
}

pub(super) enum AuthorizationOutcome {
    Allowed(ExecutableOperation),
    RequireApproval(ApprovalRequirement),
}

pub(super) struct ApprovalRequirement {
    request: FrozenOperation,
    principal: PrincipalBinding,
    policy_generation: u64,
    session_generation: u64,
    approval_generation: u64,
    grant: Option<ReadGrantProposal>,
    review_digest: Option<[u8; 32]>,
}

impl AuthorizationOutcome {
    pub(super) fn principal(&self) -> &PrincipalBinding {
        match self {
            Self::Allowed(operation) => &operation.principal,
            Self::RequireApproval(requirement) => &requirement.principal,
        }
    }
}

impl ApprovalRequirement {
    pub(super) fn request(&self) -> &FrozenOperation {
        &self.request
    }

    pub(super) fn grant_claims(&self) -> Option<ReadGrantClaims> {
        self.grant.as_ref().map(ReadGrantProposal::claims)
    }

    pub(super) fn role(&self) -> &str {
        self.grant
            .as_ref()
            .map_or_else(|| self.request.role(), ReadGrantProposal::role)
    }

    pub(super) fn review_digest(&self) -> Option<[u8; 32]> {
        self.review_digest
    }

    pub(super) fn bind_review<C>(
        &mut self,
        document: &super::review::ReviewDocument<C>,
    ) -> Result<(), AuthorizationError> {
        let bytes = document.bytes();
        if bytes.len() > 12000
            || self.review_digest.is_some()
            || !document.matches(&self.request, self.grant_claims())
        {
            return Err(AuthorizationError::InvalidApproval);
        }
        self.review_digest = Some(
            ring::digest::digest(&SHA256, bytes)
                .as_ref()
                .try_into()
                .unwrap(),
        );
        Ok(())
    }
}

impl ExecutableOperation {
    pub(super) fn authentication_offset(&self) -> Option<Duration> {
        match &self.evidence {
            AuthorizationEvidence::PolicyAllow(_) => None,
            AuthorizationEvidence::VerifiedApproval(evidence) => {
                evidence.approved.authentication_offset()
            }
        }
    }
    pub(super) fn authenticated_at(&self) -> Option<Instant> {
        match &self.evidence {
            AuthorizationEvidence::PolicyAllow(_) => None,
            AuthorizationEvidence::VerifiedApproval(evidence) => Some(evidence.authenticated),
        }
    }
    pub(super) fn request(&self) -> &FrozenOperation {
        &self.request
    }

    pub(super) fn credential_role(&self) -> &str {
        match &self.evidence {
            AuthorizationEvidence::PolicyAllow(grant) => grant.role(),
            AuthorizationEvidence::VerifiedApproval(evidence) => match &evidence.purpose {
                ApprovalPurpose::Write => "github-write",
                ApprovalPurpose::ReadGrant(grant) => grant.selection.role(),
            },
        }
    }
}

pub(super) struct Authorizer {
    session: [u8; 16],
    session_generation: u64,
    approval_generation: u64,
    active: bool,
    policy_generation: u64,
    policy: Option<Policy>,
    grants: GrantTable,
}

impl Authorizer {
    pub(super) fn new(session: [u8; 16]) -> Self {
        Self {
            session,
            session_generation: 0,
            approval_generation: 0,
            active: true,
            policy_generation: 0,
            policy: Some(Policy::default()),
            grants: GrantTable::default(),
        }
    }

    pub(super) fn install_current(
        &mut self,
        decoded: Result<Policy, AuthorizationError>,
    ) -> Result<bool, AuthorizationError> {
        let anchor = continuous_now().map_err(|_| AuthorizationError::InvalidPolicy)?;
        let wall_now = OffsetDateTime::now_utc();
        let now = Instant::now();
        self.install_anchored(decoded, wall_now, now, anchor)
    }

    fn install_anchored(
        &mut self,
        decoded: Result<Policy, AuthorizationError>,
        wall_now: OffsetDateTime,
        now: Instant,
        anchor: Sample,
    ) -> Result<bool, AuthorizationError> {
        if let Ok(policy) = &decoded
            && self
                .policy
                .as_ref()
                .is_some_and(|old| old.digest() == policy.digest())
        {
            self.grants.clamp_expiry(wall_now, now, anchor);
            return Ok(false);
        }
        self.policy = None;
        self.grants = GrantTable::default();
        self.policy_generation = self
            .policy_generation
            .checked_add(1)
            .ok_or(AuthorizationError::InvalidPolicy)?;
        let policy = decoded?;
        self.policy = Some(policy);
        Ok(true)
    }

    pub(super) fn authorize(
        &self,
        principal: &VerifiedPrincipal,
        request: FrozenOperation,
        now: Instant,
    ) -> Result<AuthorizationOutcome, AuthorizationError> {
        self.check_principal(principal)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(AuthorizationError::InvalidPolicy)?;
        if request.mode()
            != policy
                .github
                .as_ref()
                .map_or(Mode::Simulation, GitHubConfig::mode)
        {
            return Err(AuthorizationError::Denied);
        }
        if request.mode() == Mode::Github
            && (request.action() == Action::CloseIssue
                || policy
                    .github
                    .as_ref()
                    .is_none_or(|config| !request.matches_configuration(config)))
        {
            return Err(AuthorizationError::Denied);
        }
        if request.action() == Action::CloseIssue {
            if policy.writes == PolicyDecision::Deny {
                return Err(AuthorizationError::Denied);
            }
            return Ok(AuthorizationOutcome::RequireApproval(ApprovalRequirement {
                request,
                principal: principal.binding(),
                policy_generation: self.policy_generation,
                session_generation: self.session_generation,
                approval_generation: self.approval_generation,
                grant: None,
                review_digest: None,
            }));
        }
        let grant = self
            .grants
            .authorize(principal, &request, self.session, now)?;
        Ok(AuthorizationOutcome::Allowed(ExecutableOperation {
            request,
            principal: principal.binding(),
            policy_generation: self.policy_generation,
            session_generation: self.session_generation,
            evidence: AuthorizationEvidence::PolicyAllow(grant),
        }))
    }

    pub(super) fn admit(
        &mut self,
        permit: ExecutableOperation,
        principal: &VerifiedPrincipal,
        now: Instant,
    ) -> Result<FrozenOperation, AuthorizationError> {
        self.check_execution(&permit, principal, now)?;
        match permit.evidence {
            AuthorizationEvidence::PolicyAllow(grant) => {
                self.grants
                    .consume(grant, principal, &permit.request, self.session, now)?;
            }
            AuthorizationEvidence::VerifiedApproval(evidence) => {
                let ApprovalEvidence {
                    approved,
                    expected,
                    purpose,
                    ..
                } = *evidence;
                if !approved
                    .dispatch(|binding| binding == &expected)
                    .map_err(|_| AuthorizationError::InvalidApproval)?
                {
                    return Err(AuthorizationError::InvalidApproval);
                }
                if let ApprovalPurpose::ReadGrant(grant) = purpose {
                    let ApprovedReadGrant {
                        proposal,
                        selection,
                    } = *grant;
                    self.grants.issue(proposal, selection, now)?;
                }
            }
        }
        Ok(permit.request)
    }

    fn check_execution(
        &self,
        permit: &ExecutableOperation,
        principal: &VerifiedPrincipal,
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        self.check_principal(principal)?;
        if permit.policy_generation != self.policy_generation || self.policy.is_none() {
            return Err(AuthorizationError::PolicyChanged);
        }
        if permit.session_generation != self.session_generation {
            return Err(AuthorizationError::SessionRevoked);
        }
        if permit.principal != principal.binding() {
            return Err(AuthorizationError::WrongPrincipal);
        }
        match &permit.evidence {
            AuthorizationEvidence::PolicyAllow(grant) => {
                if !matches!(
                    permit.request.action(),
                    Action::ListIssues | Action::ReadIssue
                ) {
                    return Err(AuthorizationError::Denied);
                }
                self.grants
                    .check(grant, principal, &permit.request, self.session, now)?;
            }
            AuthorizationEvidence::VerifiedApproval(evidence) => {
                let ApprovalEvidence {
                    approved,
                    expected,
                    authenticated,
                    generation,
                    purpose,
                } = evidence.as_ref();
                if *generation != self.approval_generation {
                    return Err(AuthorizationError::SessionRevoked);
                }
                match purpose {
                    ApprovalPurpose::Write if permit.request.action() == Action::CloseIssue => {}
                    ApprovalPurpose::ReadGrant(grant)
                        if matches!(
                            permit.request.action(),
                            Action::ListIssues | Action::ReadIssue
                        ) =>
                    {
                        grant.proposal.check(now)?;
                    }
                    _ => return Err(AuthorizationError::Denied),
                }
                Self::check_authentication(*authenticated, now)?;
                approved
                    .verify_for_owner(expected)
                    .map_err(|_| AuthorizationError::InvalidApproval)?;
            }
        }
        Ok(())
    }

    pub(super) fn check_acquisition(
        &self,
        permit: &ExecutableOperation,
        principal: &VerifiedPrincipal,
        selection: &CredentialSelection,
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        self.check_execution(permit, principal, now)?;
        if selection.role() != permit.credential_role() {
            return Err(AuthorizationError::CredentialMismatch);
        }
        if let AuthorizationEvidence::VerifiedApproval(evidence) = &permit.evidence
            && (evidence.expected.credential_digest != selection.digest()
                || matches!(&evidence.purpose, ApprovalPurpose::ReadGrant(grant)
                    if !grant.selection.same_credential(selection)))
        {
            return Err(AuthorizationError::CredentialMismatch);
        }
        if let AuthorizationEvidence::PolicyAllow(grant) = &permit.evidence
            && !self.grants.accepts(grant, selection)
        {
            return Err(AuthorizationError::CredentialMismatch);
        }
        Ok(())
    }

    pub(super) fn deadline(
        &self,
        permit: &ExecutableOperation,
        principal: &VerifiedPrincipal,
        now: Instant,
    ) -> Result<Deadline, AuthorizationError> {
        self.check_execution(permit, principal, now)?;
        match &permit.evidence {
            AuthorizationEvidence::PolicyAllow(grant) => {
                self.grants
                    .deadline(grant, principal, &permit.request, self.session, now)
            }
            AuthorizationEvidence::VerifiedApproval(evidence) => {
                let deadline = evidence
                    .authenticated
                    .checked_add(Duration::from_secs(30))
                    .ok_or(AuthorizationError::Expired)?;
                Deadline::from_instant(deadline).map_err(|_| AuthorizationError::Expired)
            }
        }
    }

    pub(super) fn approve(
        &self,
        requirement: ApprovalRequirement,
        approved: ApprovedRequest,
        expected: RequestBinding,
        authenticated: Instant,
        selection: CredentialSelection,
        now: Instant,
    ) -> Result<ExecutableOperation, AuthorizationError> {
        if !self.active
            || !requirement.principal.in_session(self.session)
            || requirement.session_generation != self.session_generation
            || requirement.approval_generation != self.approval_generation
        {
            return Err(AuthorizationError::SessionRevoked);
        }
        if requirement.policy_generation != self.policy_generation
            || expected.policy_digest != self.policy_digest()?
        {
            return Err(AuthorizationError::PolicyChanged);
        }
        Self::check_authentication(authenticated, now)?;
        approved
            .verify_for_owner(&expected)
            .map_err(|_| AuthorizationError::InvalidApproval)?;
        let purpose = if let Some(grant) = requirement.grant {
            if requirement.review_digest != Some(expected.request_digest)
                || selection.role() != grant.role()
                || selection.digest() != expected.credential_digest
            {
                return Err(AuthorizationError::InvalidApproval);
            }
            grant.check(now)?;
            ApprovalPurpose::ReadGrant(Box::new(ApprovedReadGrant {
                proposal: grant,
                selection,
            }))
        } else {
            ApprovalPurpose::Write
        };
        Ok(ExecutableOperation {
            request: requirement.request,
            principal: requirement.principal,
            policy_generation: requirement.policy_generation,
            session_generation: requirement.session_generation,
            evidence: AuthorizationEvidence::VerifiedApproval(Box::new(ApprovalEvidence {
                approved,
                expected,
                authenticated,
                generation: self.approval_generation,
                purpose,
            })),
        })
    }

    fn check_authentication(
        authenticated: Instant,
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        if now < authenticated || now.duration_since(authenticated) >= Duration::from_secs(30) {
            return Err(AuthorizationError::Expired);
        }
        Ok(())
    }

    fn check_principal(&self, principal: &VerifiedPrincipal) -> Result<(), AuthorizationError> {
        if !self.active {
            return Err(AuthorizationError::SessionRevoked);
        }
        if !principal.in_session(self.session) {
            return Err(AuthorizationError::WrongPrincipal);
        }
        Ok(())
    }

    pub(super) fn request_read_grant(
        &self,
        principal: &VerifiedPrincipal,
        request: FrozenOperation,
        role: &str,
    ) -> Result<ApprovalRequirement, AuthorizationError> {
        self.check_principal(principal)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(AuthorizationError::InvalidPolicy)?;
        if !matches!(request.action(), Action::ReadIssue | Action::ListIssues)
            || request.mode()
                != policy
                    .github
                    .as_ref()
                    .map_or(Mode::Simulation, GitHubConfig::mode)
            || (request.mode() == Mode::Github
                && policy
                    .github
                    .as_ref()
                    .is_none_or(|config| !request.matches_configuration(config)))
        {
            return Err(AuthorizationError::Denied);
        }
        let grant = ReadGrantProposal::new(principal, &request, role)?;
        Ok(ApprovalRequirement {
            request,
            principal: principal.binding(),
            policy_generation: self.policy_generation,
            session_generation: self.session_generation,
            approval_generation: self.approval_generation,
            grant: Some(grant),
            review_digest: None,
        })
    }

    pub(super) fn revoke_read_grants(&mut self) -> Result<(), AuthorizationError> {
        self.grants = GrantTable::default();
        self.policy_generation = self
            .policy_generation
            .checked_add(1)
            .ok_or(AuthorizationError::SessionRevoked)?;
        Ok(())
    }

    pub(super) fn revoke_session(&mut self) {
        self.active = false;
        self.grants = GrantTable::default();
        self.session_generation = self.session_generation.saturating_add(1);
    }

    pub(super) fn revoke_approvals(&mut self) {
        match self.approval_generation.checked_add(1) {
            Some(generation) => self.approval_generation = generation,
            None => self.revoke_session(),
        }
    }
    pub(super) fn session_active(&self) -> bool {
        self.active
    }

    pub(super) fn session(&self) -> [u8; 16] {
        self.session
    }

    pub(super) fn policy_digest(&self) -> Result<[u8; 32], AuthorizationError> {
        self.policy
            .as_ref()
            .map(Policy::digest)
            .ok_or(AuthorizationError::InvalidPolicy)
    }

    pub(super) fn github_configuration(&self) -> Option<&GitHubConfig> {
        self.policy.as_ref()?.github.as_ref()
    }
    pub(super) fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
}

#[cfg(test)]
#[path = "../../tests/unit/policy.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/read_grant.rs"]
mod read_grant_tests;

#[cfg(test)]
#[path = "../../tests/support/policy.rs"]
pub(super) mod fixture;
