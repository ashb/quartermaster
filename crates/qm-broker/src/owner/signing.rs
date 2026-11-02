use super::deadline::Deadline;
use qm_providers::{
    ApprovalSession, ApprovedRequest, AuthenticatedIntent, PendingApproval, PendingIntent,
    RequestBinding,
};
use qm_types::CredentialError;
use std::{
    mem,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) enum Signing<S> {
    #[default]
    Unbound,
    Reviewing(PendingIntent),
    Authenticated(AuthenticatedIntent),
    Challenged {
        approval: PendingApproval,
        selection: S,
        deadline: Deadline,
    },
}

pub(super) struct Verified<S> {
    pub(super) proof: ApprovedRequest,
    pub(super) binding: RequestBinding,
    pub(super) authenticated: Instant,
    pub(super) selection: S,
    pub(super) deadline: Deadline,
}

impl<S> Signing<S> {
    pub(super) fn begin(
        &mut self,
        session: &ApprovalSession,
        digest: [u8; 32],
        created: Instant,
    ) -> Result<(), CredentialError> {
        if !matches!(self, Self::Unbound) {
            return Err(CredentialError::AlreadyAuthenticated);
        }
        *self = Self::Reviewing(session.begin_intent_at(digest, created)?);
        Ok(())
    }

    pub(super) fn nonce(&self) -> Result<[u8; 32], CredentialError> {
        match self {
            Self::Reviewing(intent) => Ok(intent.nonce()),
            Self::Authenticated(intent) => Ok(intent.nonce()),
            Self::Challenged { approval, .. } => Ok(approval.nonce()),
            Self::Unbound => Err(CredentialError::MissingPresence),
        }
    }

    pub(super) fn authenticated_at(&self) -> Option<Instant> {
        match self {
            Self::Authenticated(intent) => Some(intent.authenticated_at()),
            Self::Challenged { approval, .. } => Some(approval.authenticated_at()),
            _ => None,
        }
    }

    pub(super) fn offset(&self) -> Option<Duration> {
        match self {
            Self::Authenticated(intent) => Some(intent.authentication_offset()),
            Self::Challenged { approval, .. } => Some(approval.authentication_offset()),
            _ => None,
        }
    }

    pub(super) fn authenticate(
        &mut self,
        at: Instant,
        offset: Duration,
    ) -> Result<(), CredentialError> {
        let Self::Reviewing(intent) = mem::take(self) else {
            return Err(CredentialError::MissingPresence);
        };
        *self = Self::Authenticated(intent.authenticate(at, offset)?);
        Ok(())
    }

    pub(super) fn challenge(
        &mut self,
        selection: S,
        digest: [u8; 32],
    ) -> Result<Vec<u8>, CredentialError> {
        let Self::Authenticated(intent) = mem::take(self) else {
            return Err(CredentialError::MissingPresence);
        };
        let expires = intent
            .authenticated_at()
            .checked_add(Duration::from_secs(30))
            .ok_or(CredentialError::DispatchExpired)?;
        let deadline =
            Deadline::from_instant(expires).map_err(|_| CredentialError::DispatchExpired)?;
        let approval = intent.bind_credential(digest)?;
        let bytes = approval.challenge()?;
        *self = Self::Challenged {
            approval,
            selection,
            deadline,
        };
        Ok(bytes)
    }

    pub(super) fn approve(&mut self, signature: &[u8]) -> Result<Verified<S>, CredentialError> {
        let Self::Challenged {
            approval,
            selection,
            deadline,
        } = mem::take(self)
        else {
            return Err(CredentialError::MissingPresence);
        };
        deadline
            .remaining()
            .map_err(|_| CredentialError::DispatchExpired)?;
        let authenticated = approval.authenticated_at();
        let binding = approval.binding().clone();
        let proof = approval.approve(signature)?;
        Ok(Verified {
            proof,
            binding,
            authenticated,
            selection,
            deadline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };

    #[test]
    fn one_lifecycle_binds_the_selection_and_consumes_proof_once() {
        let rng = SystemRandom::new();
        let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.as_ref(), &rng).unwrap();
        let session = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
        let mut signing = Signing::default();
        signing.begin(&session, [3; 32], Instant::now()).unwrap();
        let nonce = signing.nonce().unwrap();
        let at = Instant::now();
        signing.authenticate(at, Duration::ZERO).unwrap();
        assert_eq!(signing.nonce().unwrap(), nonce);
        let bytes = signing.challenge("selected item", [4; 32]).unwrap();
        let signature = key.sign(&rng, &bytes).unwrap();
        let approved = signing.approve(signature.as_ref()).unwrap();
        assert_eq!(approved.selection, "selected item");
        assert_eq!(approved.binding.credential_digest, [4; 32]);
        assert!(signing.approve(signature.as_ref()).is_err());
        approved
            .proof
            .dispatch(|binding| assert_eq!(binding.request_digest, [3; 32]))
            .unwrap();
    }

    #[test]
    fn failure_or_revocation_cannot_resume_a_signing_transition() {
        let rng = SystemRandom::new();
        let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.as_ref(), &rng).unwrap();
        for failure in 0..3 {
            let session =
                ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
            let mut signing = Signing::default();
            signing.begin(&session, [3; 32], Instant::now()).unwrap();
            if failure == 0 {
                assert!(
                    signing
                        .authenticate(Instant::now(), Duration::from_secs(120))
                        .is_err()
                );
                assert!(signing.challenge((), [4; 32]).is_err());
                continue;
            }
            signing
                .authenticate(Instant::now(), Duration::ZERO)
                .unwrap();
            let mut bytes = signing.challenge((), [4; 32]).unwrap();
            if failure == 1 {
                session.revoke().unwrap();
            } else {
                bytes[0] ^= 1;
            }
            let signature = key.sign(&rng, &bytes).unwrap();
            assert!(signing.approve(signature.as_ref()).is_err());
            assert!(signing.approve(signature.as_ref()).is_err());
        }
    }
}
