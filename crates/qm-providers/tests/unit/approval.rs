use super::*;
use crate::{EncryptedCredential, VaultKeys};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

fn fixture() -> (EcdsaKeyPair, ApprovalSession) {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .unwrap();
    let session = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    (key, session)
}

fn approve(key: &EcdsaKeyPair, mut pending: PendingApproval) -> ApprovedRequest {
    let bytes = pending.record_authentication().unwrap();
    let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
    pending.approve(signature.as_ref()).unwrap()
}

#[test]
fn waiting_for_touch_does_not_spend_the_dispatch_window() {
    let (_, session) = fixture();
    let mut pending = session.begin([3; 32], [4; 32]).unwrap();
    let authenticated_at = pending.created_at + Duration::from_secs(119);
    pending.record_authentication_at(authenticated_at).unwrap();

    assert_eq!(
        pending.check_dispatch_at(|| authenticated_at + Duration::from_secs(29)),
        Ok(())
    );
    assert_eq!(
        pending.check_dispatch_at(|| authenticated_at + DISPATCH_LIFETIME),
        Err(CredentialError::DispatchExpired)
    );
    assert_eq!(
        pending.check_dispatch_at(|| authenticated_at - Duration::from_nanos(1)),
        Err(CredentialError::DispatchExpired)
    );
}

#[test]
fn delayed_signature_verification_does_not_refresh_dispatch_lifetime() {
    let (key, session) = fixture();
    let mut pending = session.begin([3; 32], [4; 32]).unwrap();
    pending.created_at = Instant::now() - Duration::from_secs(100);
    let authenticated_at = pending.created_at + Duration::from_secs(80);
    let bytes = pending.record_authentication_at(authenticated_at).unwrap();
    let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();

    let approved = pending.approve(signature.as_ref()).unwrap();

    assert_eq!(
        approved.check_at(|| authenticated_at + Duration::from_secs(29)),
        Ok(())
    );
    assert_eq!(
        approved.check_at(|| authenticated_at + DISPATCH_LIFETIME),
        Err(CredentialError::DispatchExpired)
    );
}

#[test]
fn pending_expiry_and_duplicate_events_cannot_refresh_authentication() {
    let (_, session) = fixture();
    let mut expired = session.begin([3; 32], [4; 32]).unwrap();
    assert_eq!(
        expired.record_authentication_at(expired.created_at + PENDING_LIFETIME),
        Err(CredentialError::PendingExpired)
    );
    let mut pending = session.begin([3; 32], [4; 32]).unwrap();
    pending.record_authentication().unwrap();
    let original = pending.authenticated_at;
    assert_eq!(
        pending.record_authentication(),
        Err(CredentialError::AlreadyAuthenticated)
    );
    assert_eq!(pending.authenticated_at, original);
}

#[test]
fn signature_alone_without_a_trusted_host_event_cannot_mint_a_grant() {
    let (key, session) = fixture();
    let pending = session.begin([3; 32], [4; 32]).unwrap();
    let signature = key
        .sign(
            &SystemRandom::new(),
            &pending.signing_bytes(pending.created_at),
        )
        .unwrap();

    assert!(matches!(
        pending.approve(signature.as_ref()),
        Err(CredentialError::MissingPresence)
    ));
}

#[test]
fn replayed_receipts_fail_for_replacement_pending_requests_and_sessions() {
    let (key, session) = fixture();
    let mut original = session.begin([3; 32], [4; 32]).unwrap();
    let bytes = original.record_authentication().unwrap();
    let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
    original.approve(signature.as_ref()).unwrap();
    let mut replacement = session.begin([3; 32], [4; 32]).unwrap();
    replacement.record_authentication().unwrap();
    assert!(matches!(
        replacement.approve(signature.as_ref()),
        Err(CredentialError::InvalidApprovalSignature)
    ));

    let restarted = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    let mut replacement = restarted.begin([3; 32], [4; 32]).unwrap();
    replacement.record_authentication().unwrap();
    assert!(matches!(
        replacement.approve(signature.as_ref()),
        Err(CredentialError::InvalidApprovalSignature)
    ));
}

#[test]
fn signature_binds_every_field_and_the_domain() {
    let (key, session) = fixture();
    for field in 0..7 {
        let mut pending = session.begin([3; 32], [4; 32]).unwrap();
        let mut bytes = pending.record_authentication().unwrap();
        let offset = match field {
            0 => 0,
            1 => DOMAIN.len(),
            2 => DOMAIN.len() + 16,
            3 => DOMAIN.len() + 48,
            4 => DOMAIN.len() + 80,
            5 => DOMAIN.len() + 112,
            6 => bytes.len() - 1,
            _ => unreachable!(),
        };
        bytes[offset] ^= 1;
        let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
        assert!(
            matches!(
                pending.approve(signature.as_ref()),
                Err(CredentialError::InvalidApprovalSignature)
            ),
            "field {field}"
        );
    }
}

#[test]
fn malformed_signatures_and_public_keys_fail_closed() {
    assert!(matches!(
        ApprovalSession::new([1; 16], [2; 32], &[]),
        Err(CredentialError::InvalidApprovalKey)
    ));
    let (_, session) = fixture();
    for bytes in [vec![], vec![1; 64], vec![0; 73], vec![0; 4096]] {
        let mut pending = session.begin([3; 32], [4; 32]).unwrap();
        pending.record_authentication().unwrap();
        assert!(matches!(
            pending.approve(&bytes),
            Err(CredentialError::InvalidApprovalSignature)
        ));
    }
}

#[test]
fn revocation_or_policy_changes_invalidate_pending_and_approved_requests() {
    for revoke in [false, true] {
        let (key, session) = fixture();
        let mut pending = session.begin([3; 32], [4; 32]).unwrap();
        let grant = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
        let error = if revoke {
            session.revoke().unwrap();
            CredentialError::SessionRevoked
        } else {
            session.update_policy([9; 32]).unwrap();
            session.update_policy([2; 32]).unwrap();
            CredentialError::PolicyChanged
        };
        assert_eq!(pending.record_authentication(), Err(error.clone()));
        assert_eq!(grant.check(), Err(error));
    }
}

#[test]
fn session_drop_revokes_outstanding_capabilities() {
    let (key, session) = fixture();
    let grant = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
    drop(session);
    assert_eq!(grant.check(), Err(CredentialError::SessionRevoked));
}

#[test]
fn expired_grants_cannot_acquire_plaintext() {
    let (key, session) = fixture();
    let credential =
        EncryptedCredential::parse(include_str!("../fixtures/dummy.type2").trim()).unwrap();
    let mut grant = approve(&key, session.begin([3; 32], credential.digest()).unwrap());
    grant.pending.authenticated_at = Some(Instant::now() - DISPATCH_LIFETIME);
    let keys = VaultKeys::restore(&session, &(0..64).collect::<Vec<_>>()).unwrap();

    assert!(matches!(
        keys.decrypt(grant, &credential),
        Err(CredentialError::DispatchExpired)
    ));
}
