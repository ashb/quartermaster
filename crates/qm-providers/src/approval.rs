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

struct Authority {
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

/// Frozen request intent. Authentication consumes it before credential binding.
///
/// ```compile_fail
/// fn skip_presence(intent: qm_providers::PendingIntent) {
///     intent.bind_credential([0; 32]);
/// }
/// ```
pub struct PendingIntent {
    authority: Arc<Authority>,
    session_id: [u8; 16],
    policy_digest: [u8; 32],
    request_digest: [u8; 32],
    generation: u64,
    nonce: [u8; 32],
    created_at: Instant,
}

struct AuthenticationEvent {
    at: Instant,
    offset: Duration,
}

pub struct AuthenticatedIntent {
    intent: PendingIntent,
    authentication: AuthenticationEvent,
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
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// The trusted native adapter supplies the original OS event and shared-clock offset.
    pub fn authenticate(
        self,
        at: Instant,
        offset: Duration,
    ) -> Result<AuthenticatedIntent, CredentialError> {
        check_session(&self.authority, self.generation, self.policy_digest)?;
        let now = Instant::now();
        if at > now {
            return Err(CredentialError::MissingPresence);
        }
        if offset >= PENDING_LIFETIME
            || at < self.created_at
            || at.duration_since(self.created_at) >= PENDING_LIFETIME
        {
            return Err(CredentialError::PendingExpired);
        }
        if now.duration_since(at) >= DISPATCH_LIFETIME {
            return Err(CredentialError::DispatchExpired);
        }
        Ok(AuthenticatedIntent {
            intent: self,
            authentication: AuthenticationEvent { at, offset },
        })
    }
}

impl AuthenticatedIntent {
    pub fn nonce(&self) -> [u8; 32] {
        self.intent.nonce
    }

    pub fn authenticated_at(&self) -> Instant {
        self.authentication.at
    }

    pub fn authentication_offset(&self) -> Duration {
        self.authentication.offset
    }

    pub fn bind_credential(
        self,
        credential_digest: [u8; 32],
    ) -> Result<PendingApproval, CredentialError> {
        let intent = self.intent;
        let pending = PendingApproval {
            authority: intent.authority,
            binding: RequestBinding {
                session_id: intent.session_id,
                policy_digest: intent.policy_digest,
                request_digest: intent.request_digest,
                credential_digest,
            },
            generation: intent.generation,
            nonce: intent.nonce,
            authentication: self.authentication,
        };
        pending.check_dispatch_at(Instant::now)?;
        Ok(pending)
    }
}

/// Authenticated, credential-bound challenge. Dropping it cancels that approval.
pub struct PendingApproval {
    authority: Arc<Authority>,
    binding: RequestBinding,
    generation: u64,
    nonce: [u8; 32],
    authentication: AuthenticationEvent,
}

impl PendingApproval {
    pub fn binding(&self) -> &RequestBinding {
        &self.binding
    }

    pub fn authenticated_at(&self) -> Instant {
        self.authentication.at
    }

    pub fn authentication_offset(&self) -> Duration {
        self.authentication.offset
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub fn challenge(&self) -> Result<Vec<u8>, CredentialError> {
        self.check_dispatch_at(Instant::now)?;
        Ok(self.signing_bytes())
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(self.binding.session_id);
        bytes.extend(self.binding.policy_digest);
        bytes.extend(self.binding.request_digest);
        bytes.extend(self.binding.credential_digest);
        bytes.extend(self.nonce);
        bytes.extend(self.authentication.offset.as_nanos().to_be_bytes());
        bytes
    }

    fn check_dispatch_at(&self, clock: impl FnOnce() -> Instant) -> Result<(), CredentialError> {
        check_session(&self.authority, self.generation, self.binding.policy_digest)?;
        let now = clock();
        if now < self.authentication.at
            || now.duration_since(self.authentication.at) >= DISPATCH_LIFETIME
        {
            return Err(CredentialError::DispatchExpired);
        }
        Ok(())
    }

    /// Verification consumes the challenge; replacement intents have a fresh nonce.
    pub fn approve(self, signature: &[u8]) -> Result<ApprovedRequest, CredentialError> {
        self.check_dispatch_at(Instant::now)?;
        if signature.is_empty() || signature.len() > 72 {
            return Err(CredentialError::InvalidApprovalSignature);
        }
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.authority.public_key)
            .verify(&self.signing_bytes(), signature)
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
    pub fn authentication_offset(&self) -> Duration {
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
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    fn fixture() -> (EcdsaKeyPair, ApprovalSession) {
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .unwrap();
        let session = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
        (key, session)
    }

    fn pending(session: &ApprovalSession) -> PendingApproval {
        session
            .begin_intent([3; 32])
            .unwrap()
            .authenticate(Instant::now(), Duration::ZERO)
            .unwrap()
            .bind_credential([4; 32])
            .unwrap()
    }

    fn approve(key: &EcdsaKeyPair, pending: PendingApproval) -> ApprovedRequest {
        let signature = key
            .sign(&SystemRandom::new(), &pending.challenge().unwrap())
            .unwrap();
        pending.approve(signature.as_ref()).unwrap()
    }

    #[test]
    fn authenticated_intent_preserves_the_original_event_when_binding_the_credential() {
        let (key, session) = fixture();
        let intent = session.begin_intent([3; 32]).unwrap();
        let nonce = intent.nonce();
        let at = Instant::now();
        let offset = Duration::from_nanos(12_345_678);
        let authenticated = intent.authenticate(at, offset).unwrap();
        let pending = authenticated.bind_credential([4; 32]).unwrap();
        let bytes = pending.challenge().unwrap();
        assert_eq!(pending.authenticated_at(), at);
        assert_eq!(pending.authentication_offset(), offset);
        assert_eq!(pending.nonce(), nonce);
        assert_eq!(&bytes[bytes.len() - 16..], &offset.as_nanos().to_be_bytes());
        let approved = approve(&key, pending);
        assert_eq!(approved.authentication_offset(), offset);
        assert_eq!(
            approved.check_at(|| at + DISPATCH_LIFETIME),
            Err(CredentialError::DispatchExpired)
        );
    }

    #[test]
    fn observed_authentication_keeps_the_original_event_deadline() {
        let (_, session) = fixture();
        let created = Instant::now() - Duration::from_secs(100);
        let observed = Instant::now() - Duration::from_secs(20);
        let pending = session
            .begin_intent_at([3; 32], created)
            .unwrap()
            .authenticate(observed, observed.duration_since(created))
            .unwrap()
            .bind_credential([4; 32])
            .unwrap();
        assert_eq!(
            pending.check_dispatch_at(|| observed + DISPATCH_LIFETIME),
            Err(CredentialError::DispatchExpired)
        );
        assert_eq!(
            pending.check_dispatch_at(|| observed + Duration::from_secs(29)),
            Ok(())
        );
        assert_eq!(
            pending.check_dispatch_at(|| observed - Duration::from_nanos(1)),
            Err(CredentialError::DispatchExpired)
        );
    }

    #[test]
    fn authentication_rejects_future_expired_and_out_of_order_events() {
        let (_, session) = fixture();
        let created = Instant::now() - Duration::from_secs(100);
        for (at, offset, error) in [
            (
                Instant::now() + Duration::from_secs(1),
                Duration::ZERO,
                CredentialError::MissingPresence,
            ),
            (
                created - Duration::from_secs(1),
                Duration::ZERO,
                CredentialError::PendingExpired,
            ),
            (
                Instant::now() - DISPATCH_LIFETIME,
                Duration::from_secs(70),
                CredentialError::DispatchExpired,
            ),
            (
                Instant::now(),
                PENDING_LIFETIME,
                CredentialError::PendingExpired,
            ),
        ] {
            assert!(matches!(
                session.begin_intent_at([3; 32], created).unwrap().authenticate(at, offset),
                Err(actual) if actual == error
            ));
        }
    }

    #[test]
    fn credential_binding_cannot_restart_the_authentication_deadline() {
        let (_, session) = fixture();
        let mut authenticated = session
            .begin_intent([3; 32])
            .unwrap()
            .authenticate(Instant::now(), Duration::ZERO)
            .unwrap();
        authenticated.authentication.at = Instant::now() - DISPATCH_LIFETIME;
        assert!(matches!(
            authenticated.bind_credential([4; 32]),
            Err(CredentialError::DispatchExpired)
        ));
    }

    #[test]
    fn credential_binding_rejects_policy_replacement_and_session_revocation() {
        for revoke in [false, true] {
            let (_, session) = fixture();
            let authenticated = session
                .begin_intent([3; 32])
                .unwrap()
                .authenticate(Instant::now(), Duration::ZERO)
                .unwrap();
            if revoke {
                session.revoke().unwrap();
            } else {
                session.update_policy([9; 32]).unwrap();
            }
            assert!(authenticated.bind_credential([4; 32]).is_err());
        }
    }

    #[test]
    fn intent_preserves_request_creation_before_ui_connection_and_rejects_expired_waits() {
        let (_, session) = fixture();
        let created = Instant::now() - Duration::from_secs(100);
        let intent = session.begin_intent_at([3; 32], created).unwrap();
        assert_eq!(intent.created_at, created);
        for created in [
            Instant::now() - PENDING_LIFETIME,
            Instant::now() + Duration::from_secs(1),
        ] {
            assert!(matches!(
                session.begin_intent_at([3; 32], created),
                Err(CredentialError::PendingExpired)
            ));
        }
    }

    #[test]
    fn waiting_for_touch_does_not_spend_the_dispatch_window() {
        let (_, session) = fixture();
        let created = Instant::now() - Duration::from_secs(119);
        let at = Instant::now();
        let pending = session
            .begin_intent_at([3; 32], created)
            .unwrap()
            .authenticate(at, at.duration_since(created))
            .unwrap()
            .bind_credential([4; 32])
            .unwrap();
        assert_eq!(
            pending.check_dispatch_at(|| at + Duration::from_secs(29)),
            Ok(())
        );
        assert_eq!(
            pending.check_dispatch_at(|| at + DISPATCH_LIFETIME),
            Err(CredentialError::DispatchExpired)
        );
    }

    #[test]
    fn delayed_signature_verification_does_not_refresh_dispatch_lifetime() {
        let (key, session) = fixture();
        let created = Instant::now() - Duration::from_secs(100);
        let at = Instant::now() - Duration::from_secs(20);
        let pending = session
            .begin_intent_at([3; 32], created)
            .unwrap()
            .authenticate(at, at.duration_since(created))
            .unwrap()
            .bind_credential([4; 32])
            .unwrap();
        let approved = approve(&key, pending);
        assert_eq!(approved.check_at(|| at + Duration::from_secs(29)), Ok(()));
        assert_eq!(
            approved.check_at(|| at + DISPATCH_LIFETIME),
            Err(CredentialError::DispatchExpired)
        );
    }

    #[test]
    fn direct_dispatch_requires_a_live_approved_request() {
        let (key, session) = fixture();
        let grant = approve(&key, pending(&session));
        assert_eq!(
            grant.dispatch(|binding| binding.request_digest).unwrap(),
            [3; 32]
        );
        let revoked = approve(&key, pending(&session));
        session.revoke().unwrap();
        assert_eq!(
            revoked.dispatch(|_| panic!("revoked request reached dispatch")),
            Err(CredentialError::SessionRevoked)
        );
    }

    #[test]
    fn owner_verification_requires_the_exact_binding_and_live_approval() {
        let (key, session) = fixture();
        for field in 0..4 {
            let grant = approve(&key, pending(&session));
            let mut expected = RequestBinding {
                session_id: [1; 16],
                policy_digest: [2; 32],
                request_digest: [3; 32],
                credential_digest: [4; 32],
            };
            assert_eq!(grant.verify_for_owner(&expected), Ok(()));
            match field {
                0 => expected.session_id[0] ^= 1,
                1 => expected.policy_digest[0] ^= 1,
                2 => expected.request_digest[0] ^= 1,
                3 => expected.credential_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                grant.verify_for_owner(&expected),
                Err(CredentialError::BindingMismatch)
            );
        }
        let grant = approve(&key, pending(&session));
        session.revoke().unwrap();
        assert_eq!(grant.check(), Err(CredentialError::SessionRevoked));
    }

    #[test]
    fn replayed_receipts_fail_for_replacement_pending_requests_and_sessions() {
        let (key, session) = fixture();
        let original = pending(&session);
        let signature = key
            .sign(&SystemRandom::new(), &original.challenge().unwrap())
            .unwrap();
        original.approve(signature.as_ref()).unwrap();
        assert!(matches!(
            pending(&session).approve(signature.as_ref()),
            Err(CredentialError::InvalidApprovalSignature)
        ));
        let restarted = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
        assert!(matches!(
            pending(&restarted).approve(signature.as_ref()),
            Err(CredentialError::InvalidApprovalSignature)
        ));
    }

    #[test]
    fn signature_binds_every_field_and_the_domain() {
        let (key, session) = fixture();
        for offset in [
            0,
            DOMAIN.len(),
            DOMAIN.len() + 16,
            DOMAIN.len() + 48,
            DOMAIN.len() + 80,
            DOMAIN.len() + 112,
            DOMAIN.len() + 159,
        ] {
            let pending = pending(&session);
            let mut bytes = pending.challenge().unwrap();
            bytes[offset] ^= 1;
            let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
            assert!(matches!(
                pending.approve(signature.as_ref()),
                Err(CredentialError::InvalidApprovalSignature)
            ));
        }
    }

    #[test]
    fn malformed_signatures_and_unenrolled_keys_fail_closed() {
        assert!(matches!(
            ApprovalSession::new([1; 16], [2; 32], &[]),
            Err(CredentialError::InvalidApprovalKey)
        ));
        let (impostor, _) = fixture();
        let (_, session) = fixture();
        for bytes in [vec![], vec![1; 64], vec![0; 73], vec![0; 4096]] {
            assert!(matches!(
                pending(&session).approve(&bytes),
                Err(CredentialError::InvalidApprovalSignature)
            ));
        }
        let pending = pending(&session);
        let signature = impostor
            .sign(&SystemRandom::new(), &pending.challenge().unwrap())
            .unwrap();
        assert!(matches!(
            pending.approve(signature.as_ref()),
            Err(CredentialError::InvalidApprovalSignature)
        ));
    }

    #[test]
    fn revocation_or_policy_reversion_invalidates_all_stages() {
        for revoke in [false, true] {
            let (key, session) = fixture();
            let intent = session.begin_intent([3; 32]).unwrap();
            let pending = pending(&session);
            let grant = approve(&key, self::pending(&session));
            let error = if revoke {
                session.revoke().unwrap();
                CredentialError::SessionRevoked
            } else {
                session.update_policy([9; 32]).unwrap();
                session.update_policy([2; 32]).unwrap();
                CredentialError::PolicyChanged
            };
            assert!(
                matches!(intent.authenticate(Instant::now(), Duration::ZERO), Err(actual) if actual == error)
            );
            assert_eq!(pending.challenge(), Err(error.clone()));
            assert_eq!(grant.check(), Err(error));
        }
    }

    #[test]
    fn session_drop_revokes_outstanding_capabilities() {
        let (key, session) = fixture();
        let grant = approve(&key, pending(&session));
        drop(session);
        assert_eq!(grant.check(), Err(CredentialError::SessionRevoked));
    }
}
