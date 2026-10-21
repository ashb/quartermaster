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
use qm_providers::{ApprovalSession, PendingApproval, PendingIntent};
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
    Authenticated(PendingIntent),
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
                SigningPhase::Reviewing(intent) | SigningPhase::Authenticated(intent) => {
                    intent.authenticated_at()
                }
                SigningPhase::Challenged(challenge) => challenge.approval.authenticated_at(),
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

    pub(super) fn bind_review<C>(
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
            SigningPhase::Reviewing(intent) | SigningPhase::Authenticated(intent) => {
                Ok(intent.nonce())
            }
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
                SigningPhase::Authenticated(intent) => intent.authentication_offset(),
                SigningPhase::Challenged(challenge) => challenge.approval.authentication_offset(),
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
        let SigningPhase::Reviewing(mut intent) =
            mem::replace(&mut awaiting.signing, SigningPhase::Unbound)
        else {
            unreachable!()
        };
        intent
            .record_shared_clock_authentication(authenticated, offset)
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
        let offset = intent
            .authentication_offset()
            .ok_or(OperationError::NotReady)?;
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
        let authenticated = approval
            .authenticated_at()
            .ok_or(OperationError::NotReady)?;
        let binding = approval.binding().clone();
        let proof = approval
            .approve(signature)
            .map_err(|_| OperationError::Authorization(AuthorizationError::InvalidApproval))?;
        let deadline = if requirement.grant_claims().is_some() {
            let expires = authenticated
                .checked_add(Duration::from_secs(30))
                .ok_or(OperationError::Unavailable)?;
            Some(Deadline::from_instant(expires).map_err(|_| OperationError::Unavailable)?)
        } else {
            None
        };
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
        if let Some(deadline) = deadline {
            record.created = authenticated;
            record.continuous_deadline = deadline;
        }
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

    pub(super) fn read_deadline(
        &self,
        id: OperationId,
        principal: &VerifiedPrincipal,
        authorizer: &Authorizer,
        now: Instant,
    ) -> Result<Deadline, dispatch::Error> {
        let preparation = self.metadata_operation(id, principal)?;
        let record = self
            .get(id, principal)
            .map_err(dispatch::Error::Operation)?;
        let operation_deadline = record
            .created
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
#[path = "../../tests/unit/operation.rs"]
mod tests;
