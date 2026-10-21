use qm_types::CredentialError;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PENDING_LIFETIME: Duration = Duration::from_secs(120);
const DISPATCH_LIFETIME: Duration = Duration::from_secs(30);
const DOMAIN: &[u8] = b"quartermaster.credential-approval.v1\0allow-once\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBinding {
    pub session_id: [u8; 16],
    pub policy_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub credential_digest: [u8; 32],
}

struct SessionState {
    active: bool,
    policy_digest: [u8; 32],
    generation: u64,
}

pub(super) struct Authority {
    session_id: [u8; 16],
    public_key: Vec<u8>,
    state: Mutex<SessionState>,
}

/// Host-owned approval authority. The key must come from broker enrolment, never
/// an incoming request. This does not authenticate a process or normalize a request.
pub struct ApprovalSession {
    authority: Arc<Authority>,
}

impl ApprovalSession {
    pub fn id(&self) -> [u8; 16] {
        self.authority.session_id
    }
    pub(super) fn authority(&self) -> Arc<Authority> {
        Arc::clone(&self.authority)
    }

    /// Accepts an enrolled P-256 public key in uncompressed SEC1 format.
    pub fn new(
        session_id: [u8; 16],
        policy_digest: [u8; 32],
        public_key: &[u8],
    ) -> Result<Self, CredentialError> {
        if public_key.len() != 65 || public_key[0] != 4 {
            return Err(CredentialError::InvalidApprovalKey);
        }
        Ok(Self {
            authority: Arc::new(Authority {
                session_id,
                public_key: public_key.to_vec(),
                state: Mutex::new(SessionState {
                    active: true,
                    policy_digest,
                    generation: 0,
                }),
            }),
        })
    }

    /// The broker must digest its frozen, verified request, including the principal,
    /// operation, resource, recipient and provider binding. Guest digests are untrusted.
    pub fn begin(
        &self,
        request_digest: [u8; 32],
        credential_digest: [u8; 32],
    ) -> Result<PendingApproval, CredentialError> {
        self.begin_intent(request_digest)?
            .bind_credential(credential_digest)
    }

    pub fn begin_intent(&self, request_digest: [u8; 32]) -> Result<PendingIntent, CredentialError> {
        self.begin_intent_at(request_digest, Instant::now())
    }

    /// The trusted owner supplies its original request creation time, before UI startup.
    pub fn begin_intent_at(
        &self,
        request_digest: [u8; 32],
        created_at: Instant,
    ) -> Result<PendingIntent, CredentialError> {
        let now = Instant::now();
        if now < created_at || now.duration_since(created_at) >= PENDING_LIFETIME {
            return Err(CredentialError::PendingExpired);
        }
        let state = self
            .authority
            .state
            .lock()
            .map_err(|_| CredentialError::StateUnavailable)?;
        if !state.active {
            return Err(CredentialError::SessionRevoked);
        }
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| CredentialError::RandomnessUnavailable)?;
        Ok(PendingIntent {
            authority: Arc::clone(&self.authority),
            session_id: self.authority.session_id,
            policy_digest: state.policy_digest,
            request_digest,
            generation: state.generation,
            nonce,
            created_at,
            authenticated_at: None,
            authentication_offset: None,
        })
    }

    pub fn update_policy(&self, policy_digest: [u8; 32]) -> Result<(), CredentialError> {
        let mut state = self
            .authority
            .state
            .lock()
            .map_err(|_| CredentialError::StateUnavailable)?;
        if !state.active {
            return Err(CredentialError::SessionRevoked);
        }
        if state.policy_digest != policy_digest {
            let Some(generation) = state.generation.checked_add(1) else {
                state.active = false;
                return Err(CredentialError::SessionRevoked);
            };
            state.generation = generation;
            state.policy_digest = policy_digest;
        }
        Ok(())
    }

    pub fn revoke(&self) -> Result<(), CredentialError> {
        self.authority
            .state
            .lock()
            .map_err(|_| CredentialError::StateUnavailable)?
            .active = false;
        Ok(())
    }
}

impl Drop for ApprovalSession {
    fn drop(&mut self) {
        let _ = self.revoke();
    }
}

/// Credential binding consumes this intent without replacing its nonce or authentication event.
pub struct PendingIntent {
    authority: Arc<Authority>,
    session_id: [u8; 16],
    policy_digest: [u8; 32],
    request_digest: [u8; 32],
    generation: u64,
    nonce: [u8; 32],
    created_at: Instant,
    authenticated_at: Option<Instant>,
    authentication_offset: Option<Duration>,
}

fn check_session(
    authority: &Authority,
    generation: u64,
    policy_digest: [u8; 32],
) -> Result<(), CredentialError> {
    let state = authority
        .state
        .lock()
        .map_err(|_| CredentialError::StateUnavailable)?;
    if !state.active {
        return Err(CredentialError::SessionRevoked);
    }
    if state.generation != generation || state.policy_digest != policy_digest {
        return Err(CredentialError::PolicyChanged);
    }
    Ok(())
}

impl PendingIntent {
    pub fn authenticated_at(&self) -> Option<Instant> {
        self.authenticated_at
    }

    pub fn authentication_offset(&self) -> Option<Duration> {
        self.authentication_offset
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// The trusted native adapter supplies elapsed time from its shared IPC clock.
    /// `at` retains the local dispatch deadline; the offset binds the UI's exact event.
    pub fn record_shared_clock_authentication(
        &mut self,
        at: Instant,
        offset: Duration,
    ) -> Result<(), CredentialError> {
        if offset >= PENDING_LIFETIME {
            return Err(CredentialError::PendingExpired);
        }
        self.record_observed_authentication(at)?;
        self.authentication_offset = Some(offset);
        Ok(())
    }

    /// Only the trusted native adapter may supply the original OS-success event.
    pub fn record_observed_authentication(&mut self, at: Instant) -> Result<(), CredentialError> {
        check_session(&self.authority, self.generation, self.policy_digest)?;
        if self.authenticated_at.is_some() {
            return Err(CredentialError::AlreadyAuthenticated);
        }
        let now = Instant::now();
        if at > now {
            return Err(CredentialError::MissingPresence);
        }
        if at < self.created_at || at.duration_since(self.created_at) >= PENDING_LIFETIME {
            return Err(CredentialError::PendingExpired);
        }
        if now.duration_since(at) >= DISPATCH_LIFETIME {
            return Err(CredentialError::DispatchExpired);
        }
        self.authenticated_at = Some(at);
        Ok(())
    }

    pub fn bind_credential(
        self,
        credential_digest: [u8; 32],
    ) -> Result<PendingApproval, CredentialError> {
        check_session(&self.authority, self.generation, self.policy_digest)?;
        let now = Instant::now();
        let pending = PendingApproval {
            authority: self.authority,
            binding: RequestBinding {
                session_id: self.session_id,
                policy_digest: self.policy_digest,
                request_digest: self.request_digest,
                credential_digest,
            },
            generation: self.generation,
            nonce: self.nonce,
            created_at: self.created_at,
            authenticated_at: self.authenticated_at,
            authentication_offset: self.authentication_offset,
        };
        if pending.authenticated_at.is_some() {
            pending.check_dispatch_at(|| now)?;
        } else if now < pending.created_at
            || now.duration_since(pending.created_at) >= PENDING_LIFETIME
        {
            return Err(CredentialError::PendingExpired);
        }
        Ok(pending)
    }
}

/// A pending request cannot expose a credential. Dropping it cancels that approval.
pub struct PendingApproval {
    authority: Arc<Authority>,
    binding: RequestBinding,
    generation: u64,
    nonce: [u8; 32],
    created_at: Instant,
    authenticated_at: Option<Instant>,
    authentication_offset: Option<Duration>,
}

impl PendingApproval {
    pub fn binding(&self) -> &RequestBinding {
        &self.binding
    }

    pub fn authenticated_at(&self) -> Option<Instant> {
        self.authenticated_at
    }

    pub fn authentication_offset(&self) -> Option<Duration> {
        self.authentication_offset
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    fn check_session(&self) -> Result<(), CredentialError> {
        check_session(&self.authority, self.generation, self.binding.policy_digest)
    }

    pub fn challenge(&self) -> Result<Vec<u8>, CredentialError> {
        self.check_dispatch_at(Instant::now)?;
        Ok(self.signing_bytes(
            self.authenticated_at
                .ok_or(CredentialError::MissingPresence)?,
        ))
    }

    /// Called only by the trusted host authentication callback at fresh OS success.
    /// Never expose this as a guest/UI timestamp or boolean IPC endpoint. The returned
    /// challenge must then be signed by the enrolled presence-protected key.
    pub fn record_authentication(&mut self) -> Result<Vec<u8>, CredentialError> {
        self.record_authentication_at(Instant::now())
    }

    /// Only a trusted native adapter may map a verified UI's OS authentication
    /// event into this clock. Receiving an unauthenticated timestamp is insufficient.
    pub fn record_observed_authentication(
        &mut self,
        at: Instant,
    ) -> Result<Vec<u8>, CredentialError> {
        if at > Instant::now() {
            return Err(CredentialError::MissingPresence);
        }
        self.record_authentication_at(at)
    }

    fn record_authentication_at(&mut self, now: Instant) -> Result<Vec<u8>, CredentialError> {
        self.check_session()?;
        if self.authenticated_at.is_some() {
            return Err(CredentialError::AlreadyAuthenticated);
        }
        if now < self.created_at || now.duration_since(self.created_at) >= PENDING_LIFETIME {
            return Err(CredentialError::PendingExpired);
        }
        self.authenticated_at = Some(now);
        Ok(self.signing_bytes(now))
    }

    fn signing_bytes(&self, authenticated_at: Instant) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(self.binding.session_id);
        bytes.extend(self.binding.policy_digest);
        bytes.extend(self.binding.request_digest);
        bytes.extend(self.binding.credential_digest);
        bytes.extend(self.nonce);
        bytes.extend(
            self.authentication_offset
                .unwrap_or_else(|| authenticated_at.duration_since(self.created_at))
                .as_nanos()
                .to_be_bytes(),
        );
        bytes
    }

    fn check_dispatch_at(&self, clock: impl FnOnce() -> Instant) -> Result<(), CredentialError> {
        self.check_session()?;
        let now = clock();
        let authenticated_at = self
            .authenticated_at
            .ok_or(CredentialError::MissingPresence)?;
        if now < authenticated_at || now.duration_since(authenticated_at) >= DISPATCH_LIFETIME {
            return Err(CredentialError::DispatchExpired);
        }
        Ok(())
    }

    /// Verification consumes the pending request. Its nonce cannot be reused for a
    /// second grant, and a replacement pending request has a fresh random nonce.
    pub fn approve(self, signature: &[u8]) -> Result<ApprovedRequest, CredentialError> {
        self.check_dispatch_at(Instant::now)?;
        let authenticated_at = self
            .authenticated_at
            .ok_or(CredentialError::MissingPresence)?;
        if signature.is_empty() || signature.len() > 72 {
            return Err(CredentialError::InvalidApprovalSignature);
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.authority.public_key)
            .verify(&self.signing_bytes(authenticated_at), signature)
            .map_err(|_| CredentialError::InvalidApprovalSignature)?;
        Ok(ApprovedRequest { pending: self })
    }
}

/// A single-use capability, constructed only by verified approval. No raw proof or
/// boolean can be converted into this type through an unchecked constructor.
///
/// ```compile_fail
/// let grant = qm_providers::ApprovedRequest { pending: todo!() };
/// ```
pub struct ApprovedRequest {
    pending: PendingApproval,
}

impl ApprovedRequest {
    pub fn authentication_offset(&self) -> Option<Duration> {
        self.pending.authentication_offset()
    }
    /// Trusted owners check the frozen binding before acquiring credential material.
    pub fn verify_for_owner(&self, expected: &RequestBinding) -> Result<(), CredentialError> {
        self.check()?;
        if self.binding() != expected {
            return Err(CredentialError::BindingMismatch);
        }
        Ok(())
    }

    pub fn dispatch<R>(
        self,
        send: impl FnOnce(&RequestBinding) -> R,
    ) -> Result<R, CredentialError> {
        self.check()?;
        Ok(send(self.binding()))
    }
    pub(super) fn belongs_to(&self, authority: &Arc<Authority>) -> bool {
        Arc::ptr_eq(&self.pending.authority, authority)
    }

    pub(super) fn check(&self) -> Result<(), CredentialError> {
        self.check_at(Instant::now)
    }

    pub(super) fn check_at(&self, clock: impl FnOnce() -> Instant) -> Result<(), CredentialError> {
        self.pending.check_dispatch_at(clock)
    }

    pub(super) fn binding(&self) -> &RequestBinding {
        &self.pending.binding
    }
}

#[cfg(test)]
#[path = "../tests/unit/approval.rs"]
mod tests;
