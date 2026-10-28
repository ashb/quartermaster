use super::{
    deadline::{Deadline, Sample, continuous_now},
    dispatch::CredentialSelection,
    github::configuration::{GitHubConfig, Mode},
    grant::{GrantTable, GrantUse, ReadGrantClaims, ReadGrantProposal},
    identity::{PrincipalBinding, RootDescription, VerifiedPrincipal, VerifiedRoot},
    request::{Action, FrozenOperation},
};
use qm_providers::{ApprovedRequest, RequestBinding};
use ring::digest::SHA256;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AuthorizationError {
    InvalidPolicy,
    Denied,
    Expired,
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

#[derive(Clone, Serialize)]
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
    pub(super) fn with_mutation_rule(mut self, decision: PolicyDecision) -> Self {
        self.writes = decision;
        self
    }

    pub(super) fn with_github(mut self, config: GitHubConfig) -> Self {
        self.github = Some(config);
        self
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        let mut hash = ring::digest::Context::new(&SHA256);
        hash.update(&serde_json::to_vec(self).expect("policy contains only serializable data"));
        hash.update(b"\0quartermaster.github-pattern-catalog.v1\0");
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
    SingleUse { role: String },
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
    grant: Option<Box<ReadGrantProposal>>,
    read_role: Option<String>,
    roots: Vec<Arc<VerifiedRoot>>,
    grant_template: Option<Box<ReadGrantProposal>>,
    review: Option<BoundReview>,
}

struct BoundReview {
    digest: [u8; 32],
    credential_role: String,
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
        self.grant.as_deref().map(ReadGrantProposal::claims)
    }

    pub(super) fn role(&self) -> &str {
        if let Some(review) = &self.review {
            return &review.credential_role;
        }
        self.grant.as_deref().map_or_else(
            || {
                self.read_role
                    .as_deref()
                    .unwrap_or_else(|| self.request.role())
            },
            ReadGrantProposal::role,
        )
    }

    pub(super) fn root_choices(&self) -> Vec<RootDescription> {
        self.roots
            .iter()
            .map(|root| root.description().clone())
            .collect()
    }

    pub(super) fn select_root(
        &mut self,
        principal: &VerifiedPrincipal,
        id: Option<&str>,
    ) -> Result<(), AuthorizationError> {
        if self.read_role.is_none() {
            return Err(AuthorizationError::Denied);
        }
        self.grant = if let Some(id) = id {
            let root = self
                .roots
                .iter()
                .find(|root| root.description().id == id)
                .ok_or(AuthorizationError::Denied)?;
            let mut proposal = self
                .grant_template
                .clone()
                .ok_or(AuthorizationError::Denied)?;
            proposal.select(Arc::clone(root), principal)?;
            proposal.check(Instant::now())?;
            Some(proposal)
        } else {
            None
        };
        self.review = None;
        Ok(())
    }

    pub(super) fn review_digest(&self) -> Option<[u8; 32]> {
        self.review.as_ref().map(|review| review.digest)
    }

    pub(super) fn bind_review<C: super::review::CredentialContext>(
        &mut self,
        document: &super::review::ReviewDocument<C>,
    ) -> Result<(), AuthorizationError> {
        let bytes = document.bytes();
        if bytes.len() > crate::wire_limits::REVIEW_BYTES
            || self.review.is_some()
            || !document.matches(&self.request, self.grant_claims())
            || document.credential_role().is_empty()
            || (self.request.action() != Action::Api && document.credential_role() != self.role())
        {
            return Err(AuthorizationError::InvalidApproval);
        }
        self.review = Some(BoundReview {
            digest: ring::digest::digest(&SHA256, bytes)
                .as_ref()
                .try_into()
                .unwrap(),
            credential_role: document.credential_role().to_owned(),
        });
        Ok(())
    }
}

impl ExecutableOperation {
    pub(super) fn authentication_offset(&self) -> Option<Duration> {
        match &self.evidence {
            AuthorizationEvidence::PolicyAllow(_) => None,
            AuthorizationEvidence::VerifiedApproval(evidence) => {
                Some(evidence.approved.authentication_offset())
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
                ApprovalPurpose::SingleUse { role } => role,
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
        self.invalidate_policy()?;
        let policy = decoded?;
        self.policy = Some(policy);
        Ok(true)
    }

    pub(super) fn invalidate_policy(&mut self) -> Result<(), AuthorizationError> {
        self.policy = None;
        self.grants = GrantTable::default();
        self.policy_generation = self
            .policy_generation
            .checked_add(1)
            .ok_or(AuthorizationError::InvalidPolicy)?;
        Ok(())
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
        if request.mode() == Mode::Github {
            let config = policy.github.as_ref().ok_or(AuthorizationError::Denied)?;
            if !request.matches_service(config)
                || (!request.matches_configuration(config)
                    && !config.approves_unverified_requests())
            {
                return Err(AuthorizationError::Denied);
            }
        }
        if matches!(request.action(), Action::CloseIssue | Action::Api) {
            if request.has_mutation() && policy.writes == PolicyDecision::Deny {
                return Err(AuthorizationError::Denied);
            }
            return Ok(AuthorizationOutcome::RequireApproval(ApprovalRequirement {
                request,
                principal: principal.binding(),
                policy_generation: self.policy_generation,
                session_generation: self.session_generation,
                approval_generation: self.approval_generation,
                grant: None,
                read_role: None,
                roots: Vec::new(),
                grant_template: None,
                review: None,
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
                    self.grants.issue(proposal, principal, selection, now)?;
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
                    ApprovalPurpose::SingleUse { .. } => {}
                    ApprovalPurpose::ReadGrant(grant)
                        if matches!(
                            permit.request.action(),
                            Action::ListIssues | Action::ReadIssue
                        ) =>
                    {
                        grant.proposal.verify(principal, now)?;
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
        let review = requirement
            .review
            .as_ref()
            .ok_or(AuthorizationError::InvalidApproval)?;
        if review.digest != expected.request_digest
            || selection.role() != review.credential_role
            || selection.digest() != expected.credential_digest
        {
            return Err(AuthorizationError::InvalidApproval);
        }
        let purpose = if let Some(grant) = requirement.grant {
            if selection.role() != grant.role() {
                return Err(AuthorizationError::InvalidApproval);
            }
            grant.check(now)?;
            ApprovalPurpose::ReadGrant(Box::new(ApprovedReadGrant {
                proposal: *grant,
                selection,
            }))
        } else {
            ApprovalPurpose::SingleUse {
                role: review.credential_role.clone(),
            }
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
        principal
            .revalidate()
            .map_err(|_| AuthorizationError::WrongPrincipal)?;
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
        if !matches!(role, "github-read" | "github-write") {
            return Err(AuthorizationError::Denied);
        }
        let roots = principal.roots().unwrap_or_default();
        let grant = if let Some(root) = roots.first() {
            let mut grant = ReadGrantProposal::new(principal, &request, role)?;
            grant.select(Arc::clone(root), principal)?;
            Some(Box::new(grant))
        } else {
            None
        };
        Ok(ApprovalRequirement {
            request,
            principal: principal.binding(),
            policy_generation: self.policy_generation,
            session_generation: self.session_generation,
            approval_generation: self.approval_generation,
            grant_template: grant.clone(),
            grant,
            read_role: Some(role.into()),
            roots,
            review: None,
        })
    }

    pub(super) fn active_read_grants(&self) -> Vec<ReadGrantClaims> {
        self.grants.active(Instant::now())
    }

    pub(super) fn revoke_read_grant(&mut self, id: &str) {
        self.grants.revoke(id);
        self.revoke_approvals();
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
mod tests {
    use super::*;
    use crate::owner::policy::fixture::FixturePolicy;
    use crate::owner::{
        identity::VerifiedPrincipal,
        request,
        test_support::{policy_bytes, read_request},
    };
    use std::{io::Cursor, time::Instant};

    #[test]
    fn unverified_requests_require_one_use_approval_after_explicit_service_opt_in() {
        let now = Instant::now();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        for opt_in in [false, true] {
            let config = GitHubConfig::decode(
                &serde_json::to_vec(&serde_json::json!({
                    "version": 1, "mode": "github", "repositories": [],
                    "approveUnverifiedRequests": opt_in
                }))
                .unwrap(),
            )
            .unwrap();
            let mut owner = Authorizer::new([1; 16]);
            owner
                .install(
                    Ok(FixturePolicy::default().with_github(config.clone())),
                    crate::owner::test_support::wall(1000),
                    now,
                )
                .unwrap();
            let request = request::read_configured(&mut Cursor::new(
                "GET /future-api HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
            ), Some(&config)).unwrap();
            if opt_in {
                let AuthorizationOutcome::RequireApproval(requirement) =
                    owner.authorize(&principal, request, now).unwrap()
                else {
                    panic!("unmatched input cannot use a reusable grant")
                };
                assert!(requirement.grant_claims().is_none());
            } else {
                assert!(matches!(
                    owner.authorize(&principal, request, now),
                    Err(AuthorizationError::Denied)
                ));
            }
        }
    }

    #[test]
    fn known_mutation_denial_survives_unfamiliar_inputs_and_unverified_scope_opt_in() {
        let now = Instant::now();
        let config = GitHubConfig::decode(
            br#"{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true}"#,
        )
        .unwrap();
        let mut owner = Authorizer::new([1; 16]);
        let policy = FixturePolicy::decode(br#"{"version":1,"writes":"deny","grants":[]}"#)
            .unwrap()
            .with_github(config.clone());
        owner
            .install(Ok(policy), crate::owner::test_support::wall(1000), now)
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let body = r#"{"state":"closed","unfamiliar":true}"#;
        let request = request::read_configured(&mut Cursor::new(format!(
            "PATCH /repos/a/b/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()
        )), Some(&config)).unwrap();
        assert!(matches!(
            owner.authorize(&principal, request, now),
            Err(AuthorizationError::Denied)
        ));
    }

    fn with_github(policy: FixturePolicy, id: u64) -> FixturePolicy {
        let config = super::super::github::configuration::GitHubConfig::decode(
            &serde_json::to_vec(&serde_json::json!({"version":1,"mode":"simulation",
            "repositories":[{"id":id,"owner":"quartermaster","name":"demo"}]}))
            .unwrap(),
        )
        .unwrap();
        policy.with_github(config)
    }

    #[test]
    fn github_configuration_change_and_revert_revokes_old_authority() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let policy = || FixturePolicy::decode(&policy_bytes(1010)).unwrap();
        owner
            .install(
                Ok(with_github(policy(), 123)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let AuthorizationOutcome::Allowed(old) =
            owner.authorize(&principal, read_request(), now).unwrap()
        else {
            panic!()
        };
        assert!(
            !owner
                .install(
                    Ok(with_github(policy(), 123)),
                    crate::owner::test_support::wall(1000),
                    now
                )
                .unwrap()
        );
        assert!(
            owner
                .install(
                    Ok(with_github(policy(), 456)),
                    crate::owner::test_support::wall(1000),
                    now
                )
                .unwrap()
        );
        assert!(
            owner
                .install(
                    Ok(with_github(policy(), 123)),
                    crate::owner::test_support::wall(1000),
                    now
                )
                .unwrap()
        );

        assert!(owner.admit(old, &principal, now).is_err());
    }

    #[test]
    fn unchanged_github_configuration_preserves_existing_read_access() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let policy = || with_github(FixturePolicy::decode(&policy_bytes(1010)).unwrap(), 123);
        owner
            .install(Ok(policy()), crate::owner::test_support::wall(1000), now)
            .unwrap();
        let AuthorizationOutcome::Allowed(permit) =
            owner.authorize(&principal, read_request(), now).unwrap()
        else {
            panic!()
        };
        owner.admit(permit, &principal, now).unwrap();

        assert!(
            !owner
                .install(Ok(policy()), crate::owner::test_support::wall(1001), now)
                .unwrap()
        );
        assert!(owner.authorize(&principal, read_request(), now).is_ok());
    }

    #[test]
    fn github_mode_never_falls_back_to_the_simulation_operation() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let config = super::super::github::configuration::GitHubConfig::decode(
        br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"quartermaster","name":"demo","writes":true}]}"#
    ).unwrap();
        let policy = FixturePolicy::decode(&policy_bytes(1010))
            .unwrap()
            .with_github(config);
        owner
            .install(Ok(policy), crate::owner::test_support::wall(1000), now)
            .unwrap();

        assert!(matches!(
            owner.authorize(&principal, read_request(), now),
            Err(AuthorizationError::Denied)
        ));
        assert!(matches!(
            owner.authorize(&principal, crate::owner::test_support::close_request(), now),
            Err(AuthorizationError::Denied)
        ));
    }

    #[test]
    fn policy_allow_authorizes_repeated_reads_without_presence_or_ui() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);

        for _ in 0..2 {
            let AuthorizationOutcome::Allowed(permit) =
                owner.authorize(&principal, read_request(), now).unwrap()
            else {
                panic!("read requested approval")
            };
            assert_eq!(
                owner.admit(permit, &principal, now).unwrap().action(),
                request::Action::ReadIssue
            );
        }
        assert!(owner.authorize(&principal, read_request(), now).is_ok());
    }

    #[test]
    fn an_allow_policy_cannot_waive_mandatory_mutation_approval() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();

        assert!(matches!(
            owner.authorize(&principal, request, now).unwrap(),
            AuthorizationOutcome::RequireApproval(_)
        ));
    }

    #[test]
    fn deny_and_invalid_policy_never_issue_operation_authority() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        assert!(owner.authorize(&principal, read_request(), now).is_err());
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let AuthorizationOutcome::Allowed(permit) =
            owner.authorize(&principal, read_request(), now).unwrap()
        else {
            panic!()
        };

        assert!(
            owner
                .install(
                    FixturePolicy::decode(b"{\"approved\":true}"),
                    crate::owner::test_support::wall(1000),
                    now
                )
                .is_err()
        );
        assert!(owner.admit(permit, &principal, now).is_err());
        assert!(owner.authorize(&principal, read_request(), now).is_err());
    }

    #[test]
    fn an_explicit_deny_rejects_the_supported_mutation() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                FixturePolicy::decode(br#"{"version":1,"writes":"deny","grants":[]}"#),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();

        assert!(matches!(
            owner.authorize(&principal, request, now),
            Err(AuthorizationError::Denied)
        ));
    }
}

#[cfg(test)]
mod read_grant_tests {
    use super::*;
    use crate::owner::{operation::OperationRegistry, test_support};
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };

    #[test]
    fn unavailable_roots_allow_one_read_without_creating_reusable_authority() {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]).without_fixture_root();
        let snapshot = test_support::vault::snapshot("github-write");
        let requirement = owner
            .request_read_grant(&principal, test_support::read_request(), "github-write")
            .unwrap();
        assert!(requirement.grant_claims().is_none());
        assert!(requirement.root_choices().is_empty());
        assert_eq!(requirement.role(), "github-write");
        let mut operations = OperationRegistry::default();
        let (id, _session, _, _) = test_support::approval::sign(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            requirement,
            Instant::now(),
            Duration::ZERO,
        );
        let prepared = crate::owner::execution::prepare_simulation(
            &operations,
            id,
            &principal,
            &owner,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        operations.ready(id, &principal, &prepared).unwrap();
        operations
            .admit(id, &principal, &mut owner, Instant::now())
            .unwrap();
        assert!(owner.active_read_grants().is_empty());
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
    }

    #[test]
    fn root_invalidation_before_preparation_or_admission_prevents_issuance() {
        for prepared_first in [false, true] {
            let mut owner = Authorizer::new([1; 16]);
            let principal = test_support::principal([1; 16]);
            let snapshot = test_support::vault::snapshot("github-read");
            let requirement = owner
                .request_read_grant(&principal, test_support::read_request(), "github-read")
                .unwrap();
            let root = Arc::clone(&requirement.roots[0]);
            let mut operations = OperationRegistry::default();
            let (id, _session, _, _) = test_support::approval::sign(
                &mut operations,
                &owner,
                &principal,
                &snapshot,
                requirement,
                Instant::now(),
                Duration::ZERO,
            );
            if prepared_first {
                let prepared = crate::owner::execution::prepare_simulation(
                    &operations,
                    id,
                    &principal,
                    &owner,
                    &snapshot,
                    Instant::now(),
                )
                .unwrap();
                operations.ready(id, &principal, &prepared).unwrap();
                root.invalidate();
                assert!(
                    operations
                        .admit(id, &principal, &mut owner, Instant::now())
                        .is_err()
                );
            } else {
                root.invalidate();
                assert!(
                    crate::owner::execution::prepare_simulation(
                        &operations,
                        id,
                        &principal,
                        &owner,
                        &snapshot,
                        Instant::now()
                    )
                    .is_err()
                );
            }
            assert!(owner.active_read_grants().is_empty());
        }
    }

    #[test]
    fn changing_root_replaces_the_nonce_without_extending_expiry() {
        let owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let requirement = owner
            .request_read_grant(&principal, test_support::read_request(), "github-read")
            .unwrap();
        let claims = requirement.grant_claims();
        let selected = requirement.root_choices()[0].id.clone();
        let document = test_support::approval::selected_review(
            requirement.request().clone(),
            claims.clone(),
            "github-read",
        );
        let mut operations = OperationRegistry::default();
        let id = operations
            .register(
                AuthorizationOutcome::RequireApproval(requirement),
                Instant::now(),
            )
            .unwrap();
        let (session, _) = test_support::approval::session(&owner);
        operations.bind_review(id, &principal, &document).unwrap();
        operations.begin_approval(id, &principal, &session).unwrap();
        let original = operations.approval_nonce(id, &principal).unwrap();
        assert!(
            operations
                .select_root(id, &principal, original, Some("forged-root"))
                .is_err()
        );
        operations
            .select_root(id, &principal, original, None)
            .unwrap();
        assert!(operations.grant_claims(id, &principal).unwrap().is_none());
        let once = test_support::approval::selected_review(
            test_support::read_request(),
            None,
            "github-read",
        );
        operations.bind_review(id, &principal, &once).unwrap();
        operations.begin_approval(id, &principal, &session).unwrap();
        let nonce = operations.approval_nonce(id, &principal).unwrap();
        assert_ne!(nonce, original);
        assert!(
            operations
                .select_root(id, &principal, original, Some(&selected))
                .is_err()
        );
        operations
            .select_root(id, &principal, nonce, Some(&selected))
            .unwrap();
        assert!(operations.grant_claims(id, &principal).unwrap() == claims);
        operations.bind_review(id, &principal, &document).unwrap();
        operations.begin_approval(id, &principal, &session).unwrap();
        let nonce = operations.approval_nonce(id, &principal).unwrap();
        let now = Instant::now();
        operations
            .authentication(id, &principal, now, now, Duration::ZERO)
            .unwrap();
        assert!(operations.select_root(id, &principal, nonce, None).is_err());
    }

    #[test]
    fn pending_grant_rechecks_membership_before_credential_acquisition() {
        let owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let requirement = owner
            .request_read_grant(&principal, test_support::read_request(), "github-read")
            .unwrap();
        let root = Arc::clone(&requirement.roots[0]);
        let mut operations = OperationRegistry::default();
        let (id, _session, _, _) = test_support::approval::sign(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            requirement,
            Instant::now(),
            Duration::ZERO,
        );
        let moved = principal.with_fixture_root("reparented");
        assert!(root.live().is_ok());
        assert!(
            crate::owner::execution::prepare_simulation(
                &operations,
                id,
                &moved,
                &owner,
                &snapshot,
                Instant::now()
            )
            .is_err()
        );
    }

    #[test]
    fn targeted_revocation_preserves_other_roots_and_prevents_pending_issuance() {
        let mut owner = Authorizer::new([1; 16]);
        let first = test_support::principal([1; 16]);
        let second = test_support::principal([1; 16]).with_fixture_root("second-root");
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        test_support::approval::read_grant(&mut operations, &mut owner, &first, &snapshot);
        let claims = serde_json::to_value(&owner.active_read_grants()[0]).unwrap();
        let revoke = claims["grant"]["id"].as_str().unwrap();
        test_support::approval::read_grant(&mut operations, &mut owner, &second, &snapshot);
        let AuthorizationOutcome::Allowed(permit) = owner
            .authorize(&first, test_support::read_request(), Instant::now())
            .unwrap()
        else {
            panic!()
        };
        let (pending, _session, _, _) = test_support::approval::read_grant_at(
            &mut operations,
            &owner,
            &first,
            &snapshot,
            Instant::now(),
        );
        owner.revoke_read_grant(revoke);
        assert!(owner.admit(permit, &first, Instant::now()).is_err());
        assert!(
            owner
                .authorize(&first, test_support::read_request(), Instant::now())
                .is_err()
        );
        assert!(
            owner
                .authorize(&second, test_support::read_request(), Instant::now())
                .is_ok()
        );
        assert!(
            crate::owner::execution::prepare_simulation(
                &operations,
                pending,
                &first,
                &owner,
                &snapshot,
                Instant::now()
            )
            .is_err()
        );
        assert_eq!(owner.active_read_grants().len(), 1);
    }

    #[test]
    fn a_review_cannot_bind_a_different_operation_or_drop_its_grant_scope() {
        let owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let mut read = owner
            .request_read_grant(&principal, test_support::read_request(), "github-read")
            .unwrap();
        let document = test_support::approval::review(read.request().clone(), None);
        assert!(read.bind_review(&document).is_err());
        let AuthorizationOutcome::RequireApproval(mut write) = owner
            .authorize(&principal, test_support::close_request(), Instant::now())
            .unwrap()
        else {
            panic!()
        };
        let document = test_support::approval::review(test_support::read_request(), None);
        assert!(write.bind_review(&document).is_err());
    }

    #[test]
    fn simulation_grant_serialization_matches_the_native_review_fixture() {
        let owner = Authorizer::new([1; 16]);
        let requirement = owner
            .request_read_grant(
                &test_support::principal([1; 16]),
                test_support::read_request(),
                "github-write",
            )
            .unwrap();
        let mut review = serde_json::to_value(requirement.request()).unwrap();
        review["authorization"] =
            serde_json::to_value(requirement.grant_claims().unwrap()).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/simulation-read-grant.json")).unwrap();
        review["peer"] = fixture["peer"].clone();
        for field in ["id", "expiresUnix"] {
            review["authorization"]["grant"][field] =
                fixture["authorization"]["grant"][field].clone();
        }
        assert_eq!(review, fixture);
    }

    #[test]
    fn accepting_read_grant_proof_does_not_issue_reusable_authority_before_admission() {
        let owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            Instant::now(),
        );
        let other =
            VerifiedPrincipal::fixture_with_connection(501, "11".repeat(20), [1; 16], [4; 16]);

        assert!(
            owner
                .authorize(&other, test_support::read_request(), Instant::now())
                .is_err()
        );
        assert!(
            crate::owner::execution::prepare_simulation(
                &operations,
                id,
                &other,
                &owner,
                &snapshot,
                Instant::now()
            )
            .is_err()
        );
        assert!(
            crate::owner::execution::prepare_simulation(
                &operations,
                id,
                &principal,
                &owner,
                &snapshot,
                Instant::now()
            )
            .is_ok()
        );
    }

    #[test]
    fn cancel_or_ui_loss_before_read_admission_prevents_grant_issuance() {
        for disconnect in [false, true] {
            let mut owner = Authorizer::new([1; 16]);
            let principal = test_support::principal([1; 16]);
            let snapshot = test_support::vault::snapshot("github-read");
            let mut operations = OperationRegistry::default();
            let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
                &mut operations,
                &owner,
                &principal,
                &snapshot,
                Instant::now(),
            );
            let prepared = crate::owner::execution::prepare_simulation(
                &operations,
                id,
                &principal,
                &owner,
                &snapshot,
                Instant::now(),
            )
            .unwrap();
            operations.ready(id, &principal, &prepared).unwrap();
            if disconnect {
                operations.cancel_interactive_session([2; 16]);
                owner.revoke_approvals();
            } else {
                assert_eq!(
                    operations.cancel(id, &principal),
                    crate::owner::operation::CancellationResult::Canceled
                );
            }

            assert!(
                crate::owner::execution::prepare_simulation(
                    &operations,
                    id,
                    &principal,
                    &owner,
                    &snapshot,
                    Instant::now()
                )
                .is_err()
            );
            assert!(
                operations
                    .admit(id, &principal, &mut owner, Instant::now())
                    .is_err()
            );
            assert!(
                owner
                    .authorize(&principal, test_support::read_request(), Instant::now())
                    .is_err()
            );
        }
    }

    #[test]
    fn committed_read_grants_survive_ui_loss_and_cancel_reports_already_admitted() {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, _, _, _) =
            test_support::approval::read_grant(&mut operations, &mut owner, &principal, &snapshot);
        operations.cancel_interactive_session([2; 16]);
        owner.revoke_approvals();

        assert_eq!(
            operations.cancel(id, &principal),
            crate::owner::operation::CancellationResult::AlreadyAdmitted
        );
        let other =
            VerifiedPrincipal::fixture_with_connection(501, "11".repeat(20), [1; 16], [4; 16]);
        assert!(matches!(
            owner.authorize(&other, test_support::read_request(), Instant::now()),
            Ok(AuthorizationOutcome::Allowed(_))
        ));
    }

    #[test]
    fn read_grant_issuance_rechecks_the_original_authentication_deadline_at_admission() {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            Instant::now(),
        );
        let prepared = crate::owner::execution::prepare_simulation(
            &operations,
            id,
            &principal,
            &owner,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        operations.ready(id, &principal, &prepared).unwrap();
        assert!(
            operations
                .admit(
                    id,
                    &principal,
                    &mut owner,
                    Instant::now() + Duration::from_secs(31)
                )
                .is_err()
        );
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
    }

    #[test]
    fn waiting_for_grant_approval_does_not_spend_the_first_reads_dispatch_window() {
        let owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            Instant::now() - Duration::from_secs(90),
        );

        assert!(
            operations
                .dispatch_deadline(id, &principal, &owner, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn an_approval_from_a_previous_backend_cannot_mint_a_read_grant() {
        let old = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut requirement = old
            .request_read_grant(&principal, test_support::read_request(), "github-read")
            .unwrap();
        let document = test_support::approval::review(
            requirement.request().clone(),
            requirement.grant_claims(),
        );
        requirement.bind_review(&document).unwrap();
        let request_digest = ring::digest::digest(&ring::digest::SHA256, document.bytes())
            .as_ref()
            .try_into()
            .unwrap();
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .unwrap();
        let binding = RequestBinding {
            session_id: [2; 16],
            policy_digest: old.policy_digest().unwrap(),
            request_digest,
            credential_digest: snapshot.credential_digest(),
        };
        let session = qm_providers::ApprovalSession::new(
            binding.session_id,
            binding.policy_digest,
            key.public_key().as_ref(),
        )
        .unwrap();
        let intent = session.begin_intent(request_digest).unwrap();
        let authenticated = Instant::now();
        let pending = intent
            .authenticate(authenticated, Duration::ZERO)
            .unwrap()
            .bind_credential(binding.credential_digest)
            .unwrap();
        let bytes = pending.challenge().unwrap();
        let proof = pending
            .approve(key.sign(&random, &bytes).unwrap().as_ref())
            .unwrap();
        let restarted = Authorizer::new([9; 16]);

        assert!(
            restarted
                .approve(
                    requirement,
                    proof,
                    binding,
                    authenticated,
                    test_support::vault::selection(&snapshot),
                    Instant::now()
                )
                .is_err()
        );
        assert!(
            restarted
                .authorize(
                    &test_support::principal([9; 16]),
                    test_support::read_request(),
                    Instant::now()
                )
                .is_err()
        );
    }

    #[test]
    fn a_read_grant_cannot_switch_to_a_different_vault_item_with_the_same_ciphertext() {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        test_support::approval::read_grant(
            &mut OperationRegistry::default(),
            &mut owner,
            &principal,
            &snapshot,
        );
        let AuthorizationOutcome::Allowed(permit) = owner
            .authorize(&principal, test_support::read_request(), Instant::now())
            .unwrap()
        else {
            panic!()
        };
        let substituted = test_support::vault::snapshot_with(
            "github-read",
            "33333333-3333-4333-8333-333333333333",
            [3; 16],
        );
        assert_eq!(
            snapshot.credential_digest(),
            substituted.credential_digest()
        );
        assert!(
            owner
                .check_acquisition(
                    &permit,
                    &principal,
                    &test_support::vault::selection(&substituted),
                    Instant::now()
                )
                .is_err()
        );
    }

    #[test]
    fn a_read_grant_requires_verified_approval_and_is_reusable_only_in_its_backend_session() {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        test_support::approval::read_grant(&mut operations, &mut owner, &principal, &snapshot);

        for _ in 0..150 {
            let AuthorizationOutcome::Allowed(permit) = owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .unwrap()
            else {
                panic!("read requested approval")
            };
            owner.admit(permit, &principal, Instant::now()).unwrap();
        }
        let restarted = Authorizer::new([2; 16]);
        assert!(
            restarted
                .authorize(
                    &test_support::principal([2; 16]),
                    test_support::read_request(),
                    Instant::now()
                )
                .is_err()
        );
        assert!(matches!(
            owner
                .authorize(&principal, test_support::close_request(), Instant::now())
                .unwrap(),
            AuthorizationOutcome::RequireApproval(_)
        ));
    }

    #[test]
    fn read_grant_approval_cannot_be_replayed_before_or_after_revocation() {
        for revoke in [false, true] {
            let mut owner = Authorizer::new([1; 16]);
            let principal = test_support::principal([1; 16]);
            let snapshot = test_support::vault::snapshot("github-read");
            let mut operations = OperationRegistry::default();
            let (id, session, key, request_digest) = test_support::approval::read_grant(
                &mut operations,
                &mut owner,
                &principal,
                &snapshot,
            );
            if revoke {
                owner.revoke_read_grants().unwrap();
            } else {
                for _ in 0..150 {
                    let AuthorizationOutcome::Allowed(permit) = owner
                        .authorize(&principal, test_support::read_request(), Instant::now())
                        .unwrap()
                    else {
                        panic!()
                    };
                    owner.admit(permit, &principal, Instant::now()).unwrap();
                }
            }
            assert_eq!(
                owner
                    .authorize(&principal, test_support::read_request(), Instant::now())
                    .is_err(),
                revoke
            );
            let pending = session
                .begin_intent(request_digest)
                .unwrap()
                .authenticate(Instant::now(), Duration::ZERO)
                .unwrap()
                .bind_credential(snapshot.credential_digest())
                .unwrap();
            let bytes = pending.challenge().unwrap();
            let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
            assert!(
                operations
                    .proof(id, &principal, &owner, signature.as_ref(), Instant::now())
                    .is_err()
            );
            assert_eq!(
                owner
                    .authorize(&principal, test_support::read_request(), Instant::now())
                    .is_err(),
                revoke
            );
        }
    }
}

#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    use crate::owner::grant::GrantRule;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct FixturePolicy {
        version: u8,
        writes: PolicyDecision,
        grants: Vec<GrantRule>,
        #[serde(skip)]
        github: Option<GitHubConfig>,
    }

    impl Default for FixturePolicy {
        fn default() -> Self {
            Self {
                version: 1,
                writes: PolicyDecision::RequireApproval,
                grants: Vec::new(),
                github: None,
            }
        }
    }

    impl FixturePolicy {
        pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AuthorizationError> {
            let value: Self =
                serde_json::from_slice(bytes).map_err(|_| AuthorizationError::InvalidPolicy)?;
            if value.version != 1 {
                return Err(AuthorizationError::InvalidPolicy);
            }
            for grant in &value.grants {
                grant.validate()?;
            }
            Ok(value)
        }

        pub(crate) fn with_github(mut self, github: GitHubConfig) -> Self {
            self.github = Some(github);
            self
        }
    }

    impl Authorizer {
        pub(crate) fn install(
            &mut self,
            fixture: Result<FixturePolicy, AuthorizationError>,
            wall_now: OffsetDateTime,
            now: Instant,
        ) -> Result<bool, AuthorizationError> {
            let anchor = continuous_now().map_err(|_| AuthorizationError::InvalidPolicy)?;
            match fixture {
                Ok(fixture) => {
                    let changed = self.install_anchored(
                        Ok(Policy {
                            version: fixture.version,
                            writes: fixture.writes,
                            github: fixture.github,
                        }),
                        wall_now,
                        now,
                        anchor,
                    )?;
                    if changed {
                        self.grants =
                            GrantTable::new(&fixture.grants, self.session, wall_now, now, anchor)?;
                    }
                    Ok(changed)
                }
                Err(error) => self.install_anchored(Err(error), wall_now, now, anchor),
            }
        }

        #[cfg(target_os = "macos")]
        pub(crate) fn seed_native_fixture_grants(&mut self, bytes: &[u8]) {
            self.seed_fixture_grants(bytes);
            self.grants.seed_native_root(self.session);
        }

        pub(crate) fn seed_fixture_grants(&mut self, bytes: &[u8]) {
            let fixture = FixturePolicy::decode(bytes).unwrap();
            self.grants = GrantTable::new(
                &fixture.grants,
                self.session,
                OffsetDateTime::now_utc(),
                Instant::now(),
                continuous_now().unwrap(),
            )
            .unwrap();
        }
    }
}
