use super::github::repository::PreparedMetadata;
use super::{
    deadline::Deadline,
    dispatch::{self, CredentialSelection, PreparedRequest},
    identity::{PrincipalBinding, VerifiedPrincipal},
    policy::{
        ApprovalRequirement, AuthorizationError, AuthorizationOutcome, Authorizer,
        ExecutableOperation,
    },
    provider_lifecycle::ProviderGeneration,
    request::FrozenOperation,
};
use qm_providers::{ApprovalSession, AuthenticatedIntent, PendingApproval, PendingIntent};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::BTreeMap,
    fmt, mem,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct OperationId([u8; 16]);

impl OperationId {
    pub(super) fn parse(value: &str) -> Result<Self, OperationError> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(OperationError::UnknownOperation);
        }
        let mut bytes = [0; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| OperationError::UnknownOperation)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OperationState {
    AwaitingApproval,
    Preparing,
    Ready,
    Admitted,
    Completed,
    Uncertain,
    Canceled,
    Expired,
    Revoked,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CancellationResult {
    Canceled,
    AlreadyAdmitted,
    UnknownOperation,
}

#[derive(Debug)]
pub(super) enum OperationError {
    UnknownOperation,
    NotReady,
    Capacity,
    Unavailable,
    Authorization(AuthorizationError),
    CredentialMismatch,
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => write!(formatter, "{error:?}"),
            other => write!(formatter, "{other:?}"),
        }
    }
}

impl std::error::Error for OperationError {}

pub(super) enum Completion {
    Completed,
    Uncertain,
}

enum Phase {
    Awaiting(Box<AwaitingApproval>),
    Authorized(Box<ExecutableOperation>),
    Preparing(Box<Preparation>),
    Ready {
        preparation: Box<Preparation>,
        wire_digest: [u8; 32],
    },
    Admitted,
    Completed,
    Uncertain,
    Canceled,
    Expired,
    Revoked,
}

struct AwaitingApproval {
    requirement: ApprovalRequirement,
    signing: SigningPhase,
}

enum SigningPhase {
    Unbound,
    Reviewing(PendingIntent),
    Authenticated(AuthenticatedIntent),
    Challenged(Box<ChallengeAuthority>),
}

struct ChallengeAuthority {
    approval: PendingApproval,
    selection: CredentialSelection,
}

pub(super) struct Preparation {
    pub(super) operation: ExecutableOperation,
    pub(super) selection: CredentialSelection,
}

pub(super) struct SigningChallenge {
    pub(super) bytes: Vec<u8>,
    pub(super) credential_digest: [u8; 32],
    pub(super) offset: Duration,
}

struct Operation {
    owner: PrincipalBinding,
    phase: Phase,
    pending_deadline: Instant,
    created: Instant,
    continuous_deadline: Deadline,
    approval_session: Option<[u8; 16]>,
}

impl Phase {
    fn authenticated_at(&self) -> Option<Instant> {
        match self {
            Self::Awaiting(awaiting) => match &awaiting.signing {
                SigningPhase::Unbound => None,
                SigningPhase::Reviewing(_) => None,
                SigningPhase::Authenticated(intent) => Some(intent.authenticated_at()),
                SigningPhase::Challenged(challenge) => Some(challenge.approval.authenticated_at()),
            },
            Self::Authorized(operation) => operation.authenticated_at(),
            Self::Preparing(preparation) | Self::Ready { preparation, .. } => {
                preparation.operation.authenticated_at()
            }
            _ => None,
        }
    }

    #[cfg(test)]
    fn state(&self) -> OperationState {
        match self {
            Self::Awaiting(_) => OperationState::AwaitingApproval,
            Self::Authorized(_) | Self::Preparing(_) => OperationState::Preparing,
            Self::Ready { .. } => OperationState::Ready,
            Self::Admitted => OperationState::Admitted,
            Self::Completed => OperationState::Completed,
            Self::Uncertain => OperationState::Uncertain,
            Self::Canceled => OperationState::Canceled,
            Self::Expired => OperationState::Expired,
            Self::Revoked => OperationState::Revoked,
        }
    }
}

pub(super) struct Admission {
    id: OperationId,
    request: FrozenOperation,
    selection: CredentialSelection,
    wire_digest: [u8; 32],
}

pub(super) struct MetadataAdmission {
    id: OperationId,
    wire_digest: [u8; 32],
}

impl MetadataAdmission {
    pub(super) fn accepts(&self, request: &PreparedMetadata) -> bool {
        request.id() == self.id && request.wire_digest() == self.wire_digest && request.intact()
    }
}

impl Admission {
    pub(super) fn request(&self) -> &FrozenOperation {
        &self.request
    }
    pub(super) fn accepts(&self, prepared: &PreparedRequest) -> bool {
        prepared.wire_digest() == self.wire_digest
            && prepared.matches(self.id, &self.selection, &self.request)
    }
    pub(super) fn into_request(self) -> FrozenOperation {
        self.request
    }
}

#[derive(Default)]
pub(super) struct OperationRegistry {
    records: BTreeMap<OperationId, Operation>,
}

impl OperationRegistry {
    pub(super) fn register(
        &mut self,
        outcome: AuthorizationOutcome,
        now: Instant,
    ) -> Result<OperationId, OperationError> {
        if self.records.len() >= 128 {
            return Err(OperationError::Capacity);
        }
        let owner = outcome.principal().clone();
        let phase = match outcome {
            AuthorizationOutcome::Allowed(operation) => Phase::Authorized(Box::new(operation)),
            AuthorizationOutcome::RequireApproval(requirement) => {
                Phase::Awaiting(Box::new(AwaitingApproval {
                    requirement,
                    signing: SigningPhase::Unbound,
                }))
            }
        };
        let mut bytes = [0; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| OperationError::Unavailable)?;
        let id = OperationId(bytes);
        if self.records.contains_key(&id) {
            return Err(OperationError::Unavailable);
        }
        self.records.insert(
            id,
            Operation {
                owner,
                phase,
                pending_deadline: now
                    .checked_add(Duration::from_secs(120))
                    .ok_or(OperationError::Unavailable)?,
                created: now,
                continuous_deadline: Deadline::after(Duration::from_secs(30))
                    .map_err(|_| OperationError::Unavailable)?,
                approval_session: None,
            },
        );
        Ok(id)
    }

    fn owned(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&mut Operation, OperationError> {
        self.records
            .get_mut(&id)
            .filter(|record| record.owner == principal.binding())
            .ok_or(OperationError::UnknownOperation)
    }

    fn get(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&Operation, OperationError> {
        self.records
            .get(&id)
            .filter(|record| record.owner == principal.binding())
            .ok_or(OperationError::UnknownOperation)
    }

    pub(super) fn request(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&FrozenOperation, OperationError> {
        match &self.get(id, principal)?.phase {
            Phase::Awaiting(awaiting) => Ok(awaiting.requirement.request()),
            Phase::Authorized(operation) => Ok(operation.request()),
            Phase::Preparing(preparation) | Phase::Ready { preparation, .. } => {
                Ok(preparation.operation.request())
            }
            _ => Err(OperationError::NotReady),
        }
    }

    pub(super) fn grant_claims(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<Option<super::grant::ReadGrantClaims>, OperationError> {
        match &self.get(id, principal)?.phase {
            Phase::Awaiting(awaiting) => Ok(awaiting.requirement.grant_claims()),
            _ => Ok(None),
        }
    }

    pub(super) fn root_choices(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<Vec<super::identity::RootDescription>, OperationError> {
        match &self.get(id, principal)?.phase {
            Phase::Awaiting(awaiting) => Ok(awaiting.requirement.root_choices()),
            _ => Err(OperationError::NotReady),
        }
    }

    pub(super) fn select_root(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        nonce: [u8; 32],
        root: Option<&str>,
    ) -> Result<(), OperationError> {
        let Phase::Awaiting(awaiting) = &mut self.owned(id, principal)?.phase else {
            return Err(OperationError::NotReady);
        };
        let SigningPhase::Reviewing(intent) = &awaiting.signing else {
            return Err(OperationError::NotReady);
        };
        if intent.nonce() != nonce {
            return Err(OperationError::NotReady);
        }
        awaiting
            .requirement
            .select_root(principal, root)
            .map_err(OperationError::Authorization)?;
        awaiting.signing = SigningPhase::Unbound;
        Ok(())
    }

    pub(super) fn bind_review<C: super::review::CredentialContext>(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        document: &super::review::ReviewDocument<C>,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        let Phase::Awaiting(awaiting) = &mut record.phase else {
            return Err(OperationError::NotReady);
        };
        if !matches!(awaiting.signing, SigningPhase::Unbound) {
            return Err(OperationError::NotReady);
        }
        awaiting
            .requirement
            .bind_review(document)
            .map_err(OperationError::Authorization)
    }

    pub(super) fn begin_approval(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        session: &ApprovalSession,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        if record.approval_session.is_some_and(|id| id != session.id()) {
            return Err(OperationError::NotReady);
        }
        let Phase::Awaiting(awaiting) = &mut record.phase else {
            return Err(OperationError::NotReady);
        };
        if !matches!(awaiting.signing, SigningPhase::Unbound) {
            return Err(OperationError::NotReady);
        }
        let digest = awaiting
            .requirement
            .review_digest()
            .ok_or(OperationError::NotReady)?;
        let intent = session
            .begin_intent_at(digest, record.created)
            .map_err(|_| OperationError::NotReady)?;
        record.approval_session = Some(session.id());
        awaiting.signing = SigningPhase::Reviewing(intent);
        Ok(())
    }

    pub(super) fn approval_nonce(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<[u8; 32], OperationError> {
        let Phase::Awaiting(awaiting) = &self.get(id, principal)?.phase else {
            return Err(OperationError::NotReady);
        };
        match &awaiting.signing {
            SigningPhase::Reviewing(intent) => Ok(intent.nonce()),
            SigningPhase::Authenticated(intent) => Ok(intent.nonce()),
            SigningPhase::Challenged(challenge) => Ok(challenge.approval.nonce()),
            SigningPhase::Unbound => Err(OperationError::NotReady),
        }
    }

    pub(super) fn authentication_offset(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<Duration, OperationError> {
        let offset = match &self.get(id, principal)?.phase {
            Phase::Awaiting(awaiting) => match &awaiting.signing {
                SigningPhase::Authenticated(intent) => Some(intent.authentication_offset()),
                SigningPhase::Challenged(challenge) => {
                    Some(challenge.approval.authentication_offset())
                }
                _ => None,
            },
            Phase::Preparing(preparation) | Phase::Ready { preparation, .. } => {
                preparation.operation.authentication_offset()
            }
            _ => None,
        };
        offset.ok_or(OperationError::NotReady)
    }

    pub(super) fn authentication(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        authenticated: Instant,
        now: Instant,
        offset: Duration,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        if authenticated < record.created
            || authenticated >= record.pending_deadline
            || authenticated > now
            || now.duration_since(authenticated) >= Duration::from_secs(30)
        {
            return Err(OperationError::Authorization(AuthorizationError::Expired));
        }
        if !matches!(&record.phase, Phase::Awaiting(awaiting) if matches!(awaiting.signing, SigningPhase::Reviewing(_)))
        {
            return Err(OperationError::NotReady);
        }
        let Phase::Awaiting(mut awaiting) = mem::replace(&mut record.phase, Phase::Revoked) else {
            unreachable!()
        };
        let SigningPhase::Reviewing(intent) =
            mem::replace(&mut awaiting.signing, SigningPhase::Unbound)
        else {
            unreachable!()
        };
        let intent = intent
            .authenticate(authenticated, offset)
            .map_err(|_| OperationError::Authorization(AuthorizationError::InvalidApproval))?;
        awaiting.signing = SigningPhase::Authenticated(intent);
        record.phase = Phase::Awaiting(awaiting);
        Ok(())
    }

    pub(super) fn challenge(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        selection: CredentialSelection,
    ) -> Result<SigningChallenge, OperationError> {
        let record = self.owned(id, principal)?;
        let Phase::Awaiting(awaiting) = &mut record.phase else {
            return Err(OperationError::NotReady);
        };
        if selection.role() != awaiting.requirement.role() {
            return Err(OperationError::CredentialMismatch);
        }
        if !matches!(awaiting.signing, SigningPhase::Authenticated(_)) {
            return Err(OperationError::NotReady);
        }
        let Phase::Awaiting(mut awaiting) = mem::replace(&mut record.phase, Phase::Revoked) else {
            unreachable!()
        };
        let SigningPhase::Authenticated(intent) =
            mem::replace(&mut awaiting.signing, SigningPhase::Unbound)
        else {
            unreachable!()
        };
        let offset = intent.authentication_offset();
        let credential_digest = selection.digest();
        let approval = intent
            .bind_credential(credential_digest)
            .map_err(|_| OperationError::Authorization(AuthorizationError::InvalidApproval))?;
        let bytes = approval
            .challenge()
            .map_err(|_| OperationError::Authorization(AuthorizationError::Expired))?;
        awaiting.signing = SigningPhase::Challenged(Box::new(ChallengeAuthority {
            approval,
            selection,
        }));
        record.phase = Phase::Awaiting(awaiting);
        Ok(SigningChallenge {
            bytes,
            credential_digest,
            offset,
        })
    }

    pub(super) fn proof(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        authorizer: &Authorizer,
        signature: &[u8],
        now: Instant,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        if !matches!(&record.phase, Phase::Awaiting(awaiting) if matches!(awaiting.signing, SigningPhase::Challenged(_)))
        {
            return Err(OperationError::NotReady);
        }
        let Phase::Awaiting(awaiting) = mem::replace(&mut record.phase, Phase::Revoked) else {
            unreachable!()
        };
        let AwaitingApproval {
            requirement,
            signing,
        } = *awaiting;
        let SigningPhase::Challenged(challenge) = signing else {
            unreachable!()
        };
        let ChallengeAuthority {
            approval,
            selection,
        } = *challenge;
        let authenticated = approval.authenticated_at();
        let binding = approval.binding().clone();
        let proof = approval
            .approve(signature)
            .map_err(|_| OperationError::Authorization(AuthorizationError::InvalidApproval))?;
        let expires = authenticated
            .checked_add(Duration::from_secs(30))
            .ok_or(OperationError::Unavailable)?;
        let deadline = Deadline::from_instant(expires).map_err(|_| OperationError::Unavailable)?;
        let operation = authorizer
            .approve(
                requirement,
                proof,
                binding,
                authenticated,
                selection.clone(),
                now,
            )
            .map_err(OperationError::Authorization)?;
        record.created = authenticated;
        record.continuous_deadline = deadline;
        record.phase = Phase::Preparing(Box::new(Preparation {
            operation,
            selection,
        }));
        Ok(())
    }

    pub(super) fn check_wait(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        now: Instant,
    ) -> Result<(), OperationError> {
        let record = self.get(id, principal)?;
        if !matches!(
            record.phase,
            Phase::Awaiting(_) | Phase::Authorized(_) | Phase::Preparing(_) | Phase::Ready { .. }
        ) {
            return Err(OperationError::NotReady);
        }
        let expired = match record.phase.authenticated_at() {
            Some(authenticated) => {
                now < authenticated || now.duration_since(authenticated) >= Duration::from_secs(30)
            }
            None => now >= record.pending_deadline,
        };
        if expired {
            return Err(OperationError::Authorization(AuthorizationError::Expired));
        }
        Ok(())
    }

    pub(super) fn select_credential(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        selection: CredentialSelection,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        let Phase::Authorized(operation) = &record.phase else {
            return Err(OperationError::NotReady);
        };
        if operation.credential_role() != selection.role() {
            return Err(OperationError::CredentialMismatch);
        }
        let Phase::Authorized(operation) = mem::replace(&mut record.phase, Phase::Revoked) else {
            unreachable!()
        };
        record.phase = Phase::Preparing(Box::new(Preparation {
            operation: *operation,
            selection,
        }));
        Ok(())
    }

    pub(super) fn preparation(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&Preparation, OperationError> {
        let Phase::Preparing(preparation) = &self.get(id, principal)?.phase else {
            return Err(OperationError::NotReady);
        };
        Ok(preparation)
    }

    pub(super) fn ready(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        prepared: &PreparedRequest,
    ) -> Result<(), OperationError> {
        let record = self.owned(id, principal)?;
        let Phase::Preparing(preparation) = &record.phase else {
            return Err(OperationError::NotReady);
        };
        if !prepared.matches(id, &preparation.selection, preparation.operation.request()) {
            return Err(OperationError::CredentialMismatch);
        }
        let Phase::Preparing(preparation) = mem::replace(&mut record.phase, Phase::Revoked) else {
            unreachable!()
        };
        record.phase = Phase::Ready {
            preparation,
            wire_digest: prepared.wire_digest(),
        };
        Ok(())
    }

    pub(super) fn admit(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        authorizer: &mut Authorizer,
        now: Instant,
    ) -> Result<Admission, OperationError> {
        let record = self.owned(id, principal)?;
        if !matches!(record.phase, Phase::Ready { .. }) {
            return Err(OperationError::NotReady);
        }
        let Phase::Ready {
            preparation,
            wire_digest,
        } = mem::replace(&mut record.phase, Phase::Revoked)
        else {
            unreachable!()
        };
        let Preparation {
            operation,
            selection,
        } = *preparation;
        match authorizer.admit(operation, principal, now) {
            Ok(request) => {
                record.phase = Phase::Admitted;
                Ok(Admission {
                    id,
                    request,
                    selection,
                    wire_digest,
                })
            }
            Err(error) => {
                if error == AuthorizationError::Expired {
                    record.phase = Phase::Expired;
                }
                Err(OperationError::Authorization(error))
            }
        }
    }

    fn metadata_operation(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&Preparation, dispatch::Error> {
        let preparation = self
            .preparation(id, principal)
            .map_err(dispatch::Error::Operation)?;
        if !matches!(
            preparation.operation.request().action(),
            super::request::Action::ListIssues | super::request::Action::ReadIssue
        ) {
            return Err(dispatch::Error::Authorization(AuthorizationError::Denied));
        }
        Ok(preparation)
    }

    pub(super) fn dispatch_deadline(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        authorizer: &Authorizer,
        now: Instant,
    ) -> Result<Deadline, dispatch::Error> {
        let preparation = self
            .preparation(id, principal)
            .map_err(dispatch::Error::Operation)?;
        let record = self
            .get(id, principal)
            .map_err(dispatch::Error::Operation)?;
        let operation_deadline = preparation
            .operation
            .authenticated_at()
            .unwrap_or(record.created)
            .checked_add(Duration::from_secs(30))
            .ok_or(dispatch::Error::Unavailable)?;
        if now >= operation_deadline {
            return Err(dispatch::Error::Authorization(AuthorizationError::Expired));
        }
        let deadline = authorizer
            .deadline(&preparation.operation, principal, now)
            .map_err(dispatch::Error::Authorization)?;
        let uptime =
            Deadline::from_instant(operation_deadline).map_err(|_| dispatch::Error::Unavailable)?;
        let deadline = deadline
            .earliest(record.continuous_deadline)
            .earliest(uptime);
        deadline
            .remaining()
            .map_err(|_| dispatch::Error::Authorization(AuthorizationError::Expired))?;
        Ok(deadline)
    }

    pub(super) fn admit_metadata(
        &self,
        prepared: &PreparedMetadata,
        principal: &VerifiedPrincipal,
        authorizer: &Authorizer,
        snapshot: &qm_providers::VaultSnapshot,
        now: Instant,
    ) -> Result<MetadataAdmission, dispatch::Error> {
        let Preparation {
            operation,
            selection,
        } = self.metadata_operation(prepared.id(), principal)?;
        if !prepared.matches(
            prepared.id(),
            operation.request(),
            selection,
            authorizer.policy_generation(),
        ) || !selection.matches_snapshot(snapshot)
        {
            return Err(dispatch::Error::CredentialMismatch);
        }
        authorizer
            .check_acquisition(operation, principal, selection, now)
            .map_err(dispatch::Error::Authorization)?;
        Ok(MetadataAdmission {
            id: prepared.id(),
            wire_digest: prepared.wire_digest(),
        })
    }

    fn selection(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<&CredentialSelection, OperationError> {
        match &self.get(id, principal)?.phase {
            Phase::Preparing(preparation) | Phase::Ready { preparation, .. } => {
                Ok(&preparation.selection)
            }
            _ => Err(OperationError::NotReady),
        }
    }

    pub(super) fn check_snapshot(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        snapshot: &qm_providers::VaultSnapshot,
    ) -> Result<(), OperationError> {
        if !self.selection(id, principal)?.matches_snapshot(snapshot) {
            return Err(OperationError::CredentialMismatch);
        }
        Ok(())
    }

    pub(super) fn check_provider_generation(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        generation: ProviderGeneration,
    ) -> Result<(), OperationError> {
        if self.selection(id, principal)?.generation() != generation {
            return Err(OperationError::CredentialMismatch);
        }
        Ok(())
    }

    pub(super) fn cancel(
        &mut self,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> CancellationResult {
        let Ok(record) = self.owned(id, principal) else {
            return CancellationResult::UnknownOperation;
        };
        Self::cancel_record(record)
    }

    fn cancel_record(record: &mut Operation) -> CancellationResult {
        match record.phase {
            Phase::Admitted | Phase::Completed | Phase::Uncertain => {
                CancellationResult::AlreadyAdmitted
            }
            _ => {
                record.phase = Phase::Canceled;
                CancellationResult::Canceled
            }
        }
    }

    pub(super) fn cancel_interactive(
        &mut self,
        id: OperationId,
        session: [u8; 16],
    ) -> CancellationResult {
        let Some(record) = self
            .records
            .get_mut(&id)
            .filter(|record| record.approval_session == Some(session))
        else {
            return CancellationResult::UnknownOperation;
        };
        Self::cancel_record(record)
    }

    pub(super) fn cancel_interactive_session(&mut self, session: [u8; 16]) {
        for record in self
            .records
            .values_mut()
            .filter(|record| record.approval_session == Some(session))
        {
            Self::cancel_record(record);
        }
    }

    pub(super) fn cancel_approvals(&mut self) {
        for record in self.records.values_mut().filter(|record| {
            record.approval_session.is_some() || matches!(record.phase, Phase::Awaiting(_))
        }) {
            Self::cancel_record(record);
        }
    }

    pub(super) fn finish(
        &mut self,
        id: OperationId,
        completion: Completion,
    ) -> Result<(), OperationError> {
        let record = self
            .records
            .get_mut(&id)
            .ok_or(OperationError::UnknownOperation)?;
        if !matches!(record.phase, Phase::Admitted) {
            return Err(OperationError::NotReady);
        }
        record.phase = match completion {
            Completion::Completed => Phase::Completed,
            Completion::Uncertain => Phase::Uncertain,
        };
        Ok(())
    }

    pub(super) fn release_connection(&mut self, principal: &VerifiedPrincipal) {
        self.records
            .retain(|_, record| record.owner != principal.binding());
    }

    #[cfg(test)]
    fn state(&self, id: OperationId) -> Option<OperationState> {
        self.records.get(&id).map(|record| record.phase.state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::policy::fixture::FixturePolicy;
    use crate::owner::{
        dispatch,
        identity::VerifiedPrincipal,
        request,
        test_support::{policy_bytes, read_request},
    };
    use qm_providers::ApprovalSession;
    use std::{
        io::Cursor,
        sync::{Arc, Barrier, Mutex},
        thread,
        time::Duration,
    };

    fn fixture() -> (Authorizer, VerifiedPrincipal, OperationRegistry, Instant) {
        let now = Instant::now();
        let mut authorizer = Authorizer::new([1; 16]);
        authorizer
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        (
            authorizer,
            VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]),
            OperationRegistry::default(),
            now,
        )
    }

    #[test]
    fn a_failed_signing_transition_revokes_the_record_instead_of_leaving_partial_state() {
        for invalid_offset in [false, true] {
            let (authorizer, principal, mut registry, created) = fixture();
            let id = registry
                .register(
                    authorizer
                        .authorize(
                            &principal,
                            crate::owner::test_support::close_request(),
                            created,
                        )
                        .unwrap(),
                    created,
                )
                .unwrap();
            let review = crate::owner::test_support::approval::review(
                registry.request(id, &principal).unwrap().clone(),
                None,
            );
            registry.bind_review(id, &principal, &review).unwrap();
            let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
            registry.begin_approval(id, &principal, &session).unwrap();
            let authenticated = Instant::now();
            if invalid_offset {
                assert!(
                    registry
                        .authentication(
                            id,
                            &principal,
                            authenticated,
                            authenticated,
                            Duration::from_secs(120)
                        )
                        .is_err()
                );
            } else {
                registry
                    .authentication(
                        id,
                        &principal,
                        authenticated,
                        authenticated,
                        authenticated.duration_since(created),
                    )
                    .unwrap();
                session.revoke().unwrap();
                let snapshot = crate::owner::test_support::vault::snapshot("github-write");
                assert!(
                    registry
                        .challenge(
                            id,
                            &principal,
                            crate::owner::test_support::vault::selection(&snapshot)
                        )
                        .is_err()
                );
            }
            assert_eq!(registry.state(id), Some(OperationState::Revoked));
            assert!(registry.begin_approval(id, &principal, &session).is_err());
        }
    }

    #[test]
    fn interactive_intent_can_be_canceled_before_any_credential_is_selected() {
        let (authorizer, principal, mut registry, now) = fixture();
        let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
        let id = registry
            .register(authorizer.authorize(&principal, request, now).unwrap(), now)
            .unwrap();
        let review = crate::owner::test_support::approval::review(
            registry.request(id, &principal).unwrap().clone(),
            None,
        );
        registry.bind_review(id, &principal, &review).unwrap();
        let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
        registry.begin_approval(id, &principal, &session).unwrap();

        assert_eq!(
            registry.cancel_interactive(id, [3; 16]),
            CancellationResult::UnknownOperation
        );
        assert_eq!(
            registry.cancel_interactive(id, [2; 16]),
            CancellationResult::Canceled
        );
        assert!(registry.check_wait(id, &principal, now).is_err());
    }

    fn read(
        registry: &mut OperationRegistry,
        authorizer: &Authorizer,
        principal: &VerifiedPrincipal,
        now: Instant,
    ) -> OperationId {
        let id = registry
            .register(
                authorizer
                    .authorize(principal, read_request(), now)
                    .unwrap(),
                now,
            )
            .unwrap();
        registry
            .select_credential(
                id,
                principal,
                crate::owner::test_support::vault::selection(
                    &crate::owner::test_support::vault::snapshot("github-read"),
                ),
            )
            .unwrap();
        id
    }

    fn ready(
        registry: &mut OperationRegistry,
        authorizer: &Authorizer,
        id: OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<(), dispatch::Error> {
        let request = registry
            .request(id, principal)
            .map_err(dispatch::Error::Operation)?;
        let snapshot = crate::owner::test_support::vault::snapshot(request.role());
        let prepared = crate::owner::execution::prepare_simulation(
            registry,
            id,
            principal,
            authorizer,
            &snapshot,
            Instant::now(),
        )?;
        registry
            .ready(id, principal, &prepared)
            .map_err(dispatch::Error::Operation)
    }

    fn approved_write(
        registry: &mut OperationRegistry,
        authorizer: &mut Authorizer,
        principal: &VerifiedPrincipal,
    ) -> (OperationId, ApprovalSession) {
        approved_write_at(
            registry,
            authorizer,
            principal,
            Instant::now(),
            Duration::ZERO,
        )
    }

    fn approved_write_at(
        registry: &mut OperationRegistry,
        authorizer: &mut Authorizer,
        principal: &VerifiedPrincipal,
        created: Instant,
        proof_delay: Duration,
    ) -> (OperationId, ApprovalSession) {
        crate::owner::test_support::approval::write_at(
            registry,
            authorizer,
            principal,
            &crate::owner::test_support::vault::snapshot("github-write"),
            created,
            proof_delay,
        )
    }

    #[test]
    fn timely_authentication_preserves_its_dispatch_window_after_the_pending_deadline() {
        let (mut authorizer, principal, mut registry, now) = fixture();
        let (id, _session) = approved_write_at(
            &mut registry,
            &mut authorizer,
            &principal,
            now - Duration::from_secs(119),
            Duration::from_secs(2),
        );
        ready(&mut registry, &authorizer, id, &principal).unwrap();

        assert!(
            registry
                .admit(
                    id,
                    &principal,
                    &mut authorizer,
                    Instant::now() + Duration::from_secs(2)
                )
                .is_ok()
        );
    }

    #[test]
    fn one_use_api_dispatch_deadline_starts_at_authentication_after_a_long_user_wait() {
        let now = Instant::now();
        let created = now - Duration::from_secs(60);
        let config = crate::owner::github::configuration::GitHubConfig::decode(
            br#"{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true}"#,
        )
        .unwrap();
        let mut authorizer = Authorizer::new([1; 16]);
        authorizer
            .install(
                Ok(FixturePolicy::default().with_github(config.clone())),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = request::read_configured(
            &mut Cursor::new(
                "POST /future HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 0\r\n\r\n",
            ),
            Some(&config),
        )
        .unwrap();
        let document = crate::owner::test_support::approval::review(request.clone(), None);
        let mut registry = OperationRegistry::default();
        let id = registry
            .register(
                authorizer.authorize(&principal, request, created).unwrap(),
                created,
            )
            .unwrap();
        registry.owned(id, &principal).unwrap().continuous_deadline =
            Deadline::from_instant(created + Duration::from_secs(30)).unwrap();
        registry.bind_review(id, &principal, &document).unwrap();
        let (session, key) = crate::owner::test_support::approval::session(&authorizer);
        registry.begin_approval(id, &principal, &session).unwrap();
        registry
            .authentication(id, &principal, now, now, Duration::from_secs(60))
            .unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let challenge = registry
            .challenge(
                id,
                &principal,
                crate::owner::test_support::vault::selection(&snapshot),
            )
            .unwrap();
        let signature = key
            .sign(&ring::rand::SystemRandom::new(), &challenge.bytes)
            .unwrap();
        registry
            .proof(id, &principal, &authorizer, signature.as_ref(), now)
            .unwrap();
        assert!(
            registry
                .dispatch_deadline(id, &principal, &authorizer, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn one_use_api_challenge_rejects_a_role_different_from_the_presented_selection() {
        let now = Instant::now();
        let config = crate::owner::github::configuration::GitHubConfig::decode(
            br#"{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true}"#,
        )
        .unwrap();
        let mut authorizer = Authorizer::new([1; 16]);
        authorizer
            .install(
                Ok(FixturePolicy::default().with_github(config.clone())),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = request::read_configured(
            &mut Cursor::new("GET /future HTTP/1.1\r\nHost: api.github.com\r\n\r\n"),
            Some(&config),
        )
        .unwrap();
        let document = crate::owner::test_support::approval::selected_review(
            request.clone(),
            None,
            "github-read",
        );
        let mut registry = OperationRegistry::default();
        let id = registry
            .register(authorizer.authorize(&principal, request, now).unwrap(), now)
            .unwrap();
        registry.bind_review(id, &principal, &document).unwrap();
        let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
        registry.begin_approval(id, &principal, &session).unwrap();
        registry
            .authentication(id, &principal, now, now, Duration::ZERO)
            .unwrap();
        let replacement = crate::owner::test_support::vault::snapshot("github-write");
        assert!(matches!(
            registry.challenge(
                id,
                &principal,
                crate::owner::test_support::vault::selection(&replacement)
            ),
            Err(OperationError::CredentialMismatch)
        ));
    }

    #[test]
    fn authentication_must_be_fresh_within_the_original_wait_and_cannot_be_replaced() {
        for (offset, delay, allowed) in [
            (Duration::ZERO, Duration::ZERO, true),
            (Duration::ZERO, Duration::from_secs(30), false),
            (Duration::from_secs(120), Duration::ZERO, false),
            (Duration::from_secs(121), Duration::ZERO, false),
        ] {
            let (authorizer, principal, mut registry, now) = fixture();
            let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
            let id = registry
                .register(authorizer.authorize(&principal, request, now).unwrap(), now)
                .unwrap();
            let document = crate::owner::test_support::approval::review(
                registry.request(id, &principal).unwrap().clone(),
                None,
            );
            registry.bind_review(id, &principal, &document).unwrap();
            let (session, _key) = crate::owner::test_support::approval::session(&authorizer);
            registry.begin_approval(id, &principal, &session).unwrap();
            let result =
                registry.authentication(id, &principal, now + offset, now + offset + delay, offset);
            assert_eq!(result.is_ok(), allowed);
            assert!(
                registry
                    .authentication(
                        id,
                        &principal,
                        now + Duration::from_secs(120),
                        now + Duration::from_secs(120),
                        Duration::from_secs(120),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn an_unrelated_ui_session_cannot_cancel_or_retarget_an_operation() {
        let (mut authorizer, principal, mut registry, _) = fixture();
        let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);

        assert_eq!(
            registry.cancel_interactive(id, [9; 16]),
            CancellationResult::UnknownOperation
        );
        assert_eq!(registry.state(id), Some(OperationState::Preparing));
        assert_eq!(
            registry.cancel_interactive(id, [2; 16]),
            CancellationResult::Canceled
        );
        assert_eq!(
            registry.cancel_interactive(id, [2; 16]),
            CancellationResult::Canceled
        );
    }

    #[test]
    fn a_ready_write_cannot_outlive_its_original_authentication_event() {
        let (mut authorizer, principal, mut registry, _) = fixture();
        let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);
        ready(&mut registry, &authorizer, id, &principal).unwrap();

        assert!(
            registry
                .admit(
                    id,
                    &principal,
                    &mut authorizer,
                    Instant::now() + Duration::from_secs(30)
                )
                .is_err()
        );
        assert_eq!(registry.state(id), Some(OperationState::Expired));
    }

    #[test]
    fn ui_disconnection_cancels_its_write_and_preserves_independent_reads() {
        let (mut authorizer, principal, mut registry, now) = fixture();
        let (write, _session) = approved_write(&mut registry, &mut authorizer, &principal);
        let first = read(&mut registry, &authorizer, &principal, now);

        registry.cancel_interactive_session([2; 16]);

        assert_eq!(registry.state(write), Some(OperationState::Canceled));
        assert_eq!(registry.state(first), Some(OperationState::Preparing));
        ready(&mut registry, &authorizer, first, &principal).unwrap();
        assert!(
            registry
                .admit(first, &principal, &mut authorizer, now)
                .is_ok()
        );
        let second = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, second, &principal).unwrap();
        assert!(
            registry
                .admit(second, &principal, &mut authorizer, now)
                .is_ok()
        );
    }

    #[test]
    fn cancellation_and_admission_have_one_consistent_winner() {
        let (authorizer, principal, mut registry, now) = fixture();
        let id = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, id, &principal).unwrap();
        let owner = Arc::new(Mutex::new((authorizer, registry)));
        let principal = Arc::new(principal);
        let barrier = Arc::new(Barrier::new(2));
        let executing_owner = Arc::clone(&owner);
        let executing_principal = Arc::clone(&principal);
        let executing_barrier = Arc::clone(&barrier);
        let admission = thread::spawn(move || {
            executing_barrier.wait();
            let mut owner = executing_owner.lock().unwrap();
            let (authorizer, registry) = &mut *owner;
            registry
                .admit(id, &executing_principal, authorizer, now)
                .is_ok()
        });
        barrier.wait();
        let cancellation = owner.lock().unwrap().1.cancel(id, &principal);

        assert!(matches!(
            (cancellation, admission.join().unwrap()),
            (CancellationResult::Canceled, false) | (CancellationResult::AlreadyAdmitted, true)
        ));
    }

    #[test]
    fn cancellation_after_verified_proof_prevents_admission_and_remains_observable() {
        let (mut authorizer, principal, mut registry, _) = fixture();
        let (id, _session) = approved_write(&mut registry, &mut authorizer, &principal);
        ready(&mut registry, &authorizer, id, &principal).unwrap();

        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::Canceled
        );
        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::Canceled
        );
        assert!(
            registry
                .admit(id, &principal, &mut authorizer, Instant::now())
                .is_err()
        );
        assert_eq!(registry.state(id), Some(OperationState::Canceled));
    }

    #[test]
    fn cancellation_during_preparation_preserves_the_grant() {
        let (mut authorizer, principal, mut registry, now) = fixture();
        let canceled = read(&mut registry, &authorizer, &principal, now);
        assert_eq!(
            registry.cancel(canceled, &principal),
            CancellationResult::Canceled
        );
        assert!(ready(&mut registry, &authorizer, canceled, &principal).is_err());
        let id = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, id, &principal).unwrap();

        assert!(registry.admit(id, &principal, &mut authorizer, now).is_ok());
        assert!(
            authorizer
                .authorize(&principal, read_request(), now)
                .is_ok()
        );
    }

    #[test]
    fn admitted_operations_report_already_admitted_and_cannot_execute_twice() {
        let (mut authorizer, principal, mut registry, now) = fixture();
        let id = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, id, &principal).unwrap();
        let admission = registry
            .admit(id, &principal, &mut authorizer, now)
            .unwrap();
        assert_eq!(admission.request().action(), request::Action::ReadIssue);

        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::AlreadyAdmitted
        );
        assert!(
            registry
                .admit(id, &principal, &mut authorizer, now)
                .is_err()
        );
        registry.finish(id, Completion::Uncertain).unwrap();
        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::AlreadyAdmitted
        );
        assert!(
            authorizer
                .authorize(&principal, read_request(), now)
                .is_ok()
        );
    }

    #[test]
    fn wrong_owner_and_unknown_ids_do_not_report_cancellation() {
        let (authorizer, principal, mut registry, now) = fixture();
        let id = read(&mut registry, &authorizer, &principal, now);
        let other = VerifiedPrincipal::fixture(502, "11".repeat(20), [1; 16]);

        assert_eq!(
            registry.cancel(id, &other),
            CancellationResult::UnknownOperation
        );
        assert_eq!(
            registry.cancel(
                OperationId::parse("00000000000000000000000000000000").unwrap(),
                &principal
            ),
            CancellationResult::UnknownOperation
        );
        assert_eq!(registry.state(id), Some(OperationState::Preparing));
    }

    #[test]
    fn final_admission_rechecks_revocation_and_expiry() {
        for changed in [false, true] {
            let (mut authorizer, principal, mut registry, now) = fixture();
            let id = read(&mut registry, &authorizer, &principal, now);
            ready(&mut registry, &authorizer, id, &principal).unwrap();
            if changed {
                authorizer.revoke_read_grants().unwrap();
            }

            assert!(
                registry
                    .admit(
                        id,
                        &principal,
                        &mut authorizer,
                        if changed {
                            now
                        } else {
                            now + Duration::from_secs(10)
                        }
                    )
                    .is_err()
            );
            assert!(matches!(
                registry.state(id),
                Some(OperationState::Revoked | OperationState::Expired)
            ));
        }
    }

    #[test]
    fn separately_prepared_operations_can_share_the_same_live_grant() {
        let (authorizer, principal, mut registry, now) = fixture();
        let first = read(&mut registry, &authorizer, &principal, now);
        let second = read(&mut registry, &authorizer, &principal, now);
        ready(&mut registry, &authorizer, first, &principal).unwrap();
        ready(&mut registry, &authorizer, second, &principal).unwrap();
        let owner = Arc::new(Mutex::new((authorizer, registry)));
        let principal = Arc::new(principal);
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [first, second]
            .into_iter()
            .map(|id| {
                let owner = Arc::clone(&owner);
                let principal = Arc::clone(&principal);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let mut owner = owner.lock().unwrap();
                    let (authorizer, registry) = &mut *owner;
                    registry.admit(id, &principal, authorizer, now).is_ok()
                })
            })
            .collect();

        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|allowed| *allowed)
                .count(),
            2
        );
    }

    #[test]
    fn canceled_write_leaves_independent_read_grants_valid() {
        let (mut authorizer, principal, mut registry, now) = fixture();
        let (write, _session) = approved_write(&mut registry, &mut authorizer, &principal);
        assert_eq!(
            registry.cancel(write, &principal),
            CancellationResult::Canceled
        );

        for _ in 0..2 {
            let id = read(&mut registry, &authorizer, &principal, now);
            ready(&mut registry, &authorizer, id, &principal).unwrap();
            assert!(registry.admit(id, &principal, &mut authorizer, now).is_ok());
            registry.finish(id, Completion::Completed).unwrap();
        }
    }

    #[test]
    fn terminal_records_remain_bounded_until_the_originating_connection_ends() {
        let (authorizer, principal, mut registry, now) = fixture();
        for _ in 0..128 {
            let id = read(&mut registry, &authorizer, &principal, now);
            assert_eq!(
                registry.cancel(id, &principal),
                CancellationResult::Canceled
            );
        }
        let allowed = authorizer
            .authorize(&principal, read_request(), now)
            .unwrap();
        assert!(matches!(
            registry.register(allowed, now),
            Err(OperationError::Capacity)
        ));
        registry.release_connection(&principal);
        assert!(
            registry
                .register(
                    authorizer
                        .authorize(&principal, read_request(), now)
                        .unwrap(),
                    now
                )
                .is_ok()
        );
    }
}
