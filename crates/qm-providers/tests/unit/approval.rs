use super::*;
use crate::{EncryptedCredential, VaultKeys};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

#[test]
fn observed_authentication_keeps_the_original_event_deadline() {
    let (_, session) = fixture();
    let mut pending = session.begin([3; 32], [4; 32]).unwrap();
    pending.created_at = Instant::now() - Duration::from_secs(100);
    let observed = Instant::now() - Duration::from_secs(20);
    pending.record_observed_authentication(observed).unwrap();
    assert_eq!(
        pending.check_dispatch_at(|| observed + DISPATCH_LIFETIME),
        Err(CredentialError::DispatchExpired)
    );
    assert_eq!(
        pending.check_dispatch_at(|| observed + Duration::from_secs(29)),
        Ok(())
    );
}

#[test]
fn future_observed_authentication_cannot_prepare_a_challenge() {
    let (_, session) = fixture();
    let mut pending = session.begin([3; 32], [4; 32]).unwrap();
    assert_eq!(
        pending.record_observed_authentication(Instant::now() + Duration::from_secs(1)),
        Err(CredentialError::MissingPresence)
    );
    assert!(pending.authenticated_at.is_none());
}

#[test]
fn staged_binding_preserves_nonce_creation_and_the_original_authentication_deadline() {
    let (key, session) = fixture();
    let mut intent = session.begin_intent([3; 32]).unwrap();
    intent.created_at = Instant::now() - Duration::from_secs(129);
    let created = intent.created_at;
    let nonce = intent.nonce;
    let authenticated = Instant::now() - Duration::from_secs(20);
    intent
        .record_observed_authentication(authenticated)
        .unwrap();

    let pending = intent.bind_credential([4; 32]).unwrap();
    let bytes = pending.challenge().unwrap();

    assert_eq!(pending.nonce, nonce);
    assert_eq!(pending.created_at, created);
    assert_eq!(pending.authenticated_at, Some(authenticated));
    assert_eq!(pending.binding.credential_digest, [4; 32]);
    let proof = pending
        .approve(key.sign(&SystemRandom::new(), &bytes).unwrap().as_ref())
        .unwrap();
    assert_eq!(
        proof.check_at(|| authenticated + Duration::from_secs(29)),
        Ok(())
    );
    assert_eq!(
        proof.check_at(|| authenticated + Duration::from_secs(30)),
        Err(CredentialError::DispatchExpired)
    );
}

#[test]
fn staged_credential_binding_cannot_restart_an_expired_authentication_or_pending_wait() {
    let (_, session) = fixture();
    let mut expired = session.begin_intent([3; 32]).unwrap();
    expired.created_at = Instant::now() - Duration::from_secs(120);
    assert!(matches!(
        expired.bind_credential([4; 32]),
        Err(CredentialError::PendingExpired)
    ));
    let mut authenticated = session.begin_intent([3; 32]).unwrap();
    authenticated.created_at = Instant::now() - Duration::from_secs(100);
    authenticated
        .record_observed_authentication(Instant::now() - Duration::from_secs(20))
        .unwrap();
    authenticated.authenticated_at = Some(Instant::now() - Duration::from_secs(30));

    assert!(matches!(
        authenticated.bind_credential([4; 32]),
        Err(CredentialError::DispatchExpired)
    ));
}

#[test]
fn staged_binding_rejects_policy_replacement_or_session_revocation_before_binding() {
    for revoke in [false, true] {
        let (_, session) = fixture();
        let mut intent = session.begin_intent([3; 32]).unwrap();
        intent
            .record_observed_authentication(Instant::now())
            .unwrap();
        if revoke {
            session.revoke().unwrap();
        } else {
            session.update_policy([9; 32]).unwrap();
        }

        assert!(intent.bind_credential([4; 32]).is_err());
    }
}

#[test]
fn staged_intent_rejects_future_and_duplicate_authentication_events() {
    let (_, session) = fixture();
    let mut intent = session.begin_intent([3; 32]).unwrap();
    assert_eq!(
        intent.record_observed_authentication(Instant::now() + Duration::from_secs(1)),
        Err(CredentialError::MissingPresence)
    );
    intent
        .record_observed_authentication(Instant::now())
        .unwrap();

    assert_eq!(
        intent.record_observed_authentication(Instant::now()),
        Err(CredentialError::AlreadyAuthenticated)
    );
}

#[test]
fn staged_intent_can_preserve_request_creation_before_ui_connection() {
    let (_, session) = fixture();
    let created = Instant::now() - Duration::from_secs(100);

    let intent = session.begin_intent_at([3; 32], created).unwrap();

    assert_eq!(intent.created_at, created);
    assert!(matches!(
        session.begin_intent_at([3; 32], Instant::now() - Duration::from_secs(120)),
        Err(CredentialError::PendingExpired)
    ));
    assert!(matches!(
        session.begin_intent_at([3; 32], Instant::now() + Duration::from_secs(1)),
        Err(CredentialError::PendingExpired)
    ));
}

#[test]
fn staged_authentication_signs_the_exact_shared_clock_offset_without_changing_the_deadline() {
    let (_, session) = fixture();
    let mut intent = session.begin_intent([3; 32]).unwrap();
    let nonce = intent.nonce();
    let at = Instant::now();
    let offset = Duration::from_nanos(5_123_456_789);
    intent
        .record_shared_clock_authentication(at, offset)
        .unwrap();

    let pending = intent.bind_credential([4; 32]).unwrap();
    let challenge = pending.challenge().unwrap();
    assert_eq!(pending.nonce(), nonce);
    assert_eq!(
        &challenge[challenge.len() - 16..],
        &offset.as_nanos().to_be_bytes()
    );
    assert_eq!(pending.authenticated_at, Some(at));
    assert_eq!(
        pending.check_dispatch_at(|| at + DISPATCH_LIFETIME),
        Err(CredentialError::DispatchExpired)
    );
}

#[test]
fn staged_authentication_rejects_an_expired_shared_clock_wait() {
    let (_, session) = fixture();
    let mut intent = session.begin_intent([3; 32]).unwrap();

    assert_eq!(
        intent.record_shared_clock_authentication(Instant::now(), PENDING_LIFETIME),
        Err(CredentialError::PendingExpired)
    );
    intent
        .record_shared_clock_authentication(Instant::now(), Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        intent.record_shared_clock_authentication(Instant::now(), Duration::from_secs(1)),
        Err(CredentialError::AlreadyAuthenticated)
    );
}

#[test]
fn direct_dispatch_requires_a_live_approved_request() {
    let (key, session) = fixture();
    let grant = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
    let digest = grant.dispatch(|binding| binding.request_digest).unwrap();
    assert_eq!(digest, [3; 32]);
    let revoked = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
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
        let grant = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
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
    let grant = approve(&key, session.begin([3; 32], [4; 32]).unwrap());
    session.revoke().unwrap();
    assert_eq!(
        grant.verify_for_owner(&RequestBinding {
            session_id: [1; 16],
            policy_digest: [2; 32],
            request_digest: [3; 32],
            credential_digest: [4; 32]
        }),
        Err(CredentialError::SessionRevoked)
    );
}

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
