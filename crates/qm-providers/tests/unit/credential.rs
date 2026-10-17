use super::*;
use crate::{ApprovalSession, ApprovedRequest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use std::time::Duration;

const CIPHER: &str = include_str!("../fixtures/dummy.type2");

fn fixture(credential: &EncryptedCredential) -> (ApprovalSession, ApprovedRequest, VaultKeys) {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .unwrap();
    let session = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    let mut pending = session.begin([3; 32], credential.digest()).unwrap();
    let bytes = pending.record_authentication().unwrap();
    let signature = key.sign(&random, &bytes).unwrap();
    let approved = pending.approve(signature.as_ref()).unwrap();
    let keys = VaultKeys::restore(&session, &(0..64).collect::<Vec<_>>()).unwrap();
    (session, approved, keys)
}

#[test]
fn malformed_ciphertexts_and_missing_macs_are_rejected_before_decryption() {
    for input in ["", "!.bad", "2.bad", "7.bad", "4.AAAA", "2.!!!|!!!|!!!"] {
        assert!(EncryptedCredential::parse(input).is_err());
    }
    assert!(matches!(
        EncryptedCredential::parse(&"2".repeat(8193)),
        Err(CredentialError::InvalidCiphertext)
    ));
    let without_mac = CIPHER.trim().rsplit_once('|').unwrap().0;
    assert!(matches!(
        EncryptedCredential::parse(without_mac),
        Err(CredentialError::UnauthenticatedCiphertext)
    ));
}

#[test]
fn malformed_key_lengths_cannot_construct_vault_keys() {
    let encrypted = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let (session, _, _) = fixture(&encrypted);
    for length in [0, 1, 32, 63, 65, 4097] {
        assert!(matches!(
            VaultKeys::restore(&session, &vec![0; length]),
            Err(CredentialError::InvalidKeyLength)
        ));
    }
}

#[test]
fn wrong_keys_and_tampered_authenticated_ciphertext_never_produce_plaintext() {
    let encrypted = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let (session, approved, _) = fixture(&encrypted);
    let wrong = VaultKeys::restore(&session, &[0xff; 64]).unwrap();
    assert!(matches!(
        wrong.decrypt(approved, &encrypted),
        Err(CredentialError::DecryptionFailed)
    ));

    let mut cipher = CipherString::new(CIPHER.trim()).unwrap();
    let CipherString::Symmetric { ciphertext, .. } = &mut cipher else {
        unreachable!()
    };
    ciphertext[0] ^= 1;
    let tampered = EncryptedCredential::parse(&cipher.to_string()).unwrap();
    let (_session, approved, keys) = fixture(&tampered);
    assert!(matches!(
        keys.decrypt(approved, &tampered),
        Err(CredentialError::DecryptionFailed)
    ));
}

#[test]
fn approval_for_one_ciphertext_cannot_decrypt_another() {
    let original = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let (_session, approved, keys) = fixture(&original);
    let mut different = CipherString::new(CIPHER.trim()).unwrap();
    let CipherString::Symmetric { iv, .. } = &mut different else {
        unreachable!()
    };
    iv[0] ^= 1;
    let different = EncryptedCredential::parse(&different.to_string()).unwrap();

    assert!(matches!(
        keys.decrypt(approved, &different),
        Err(CredentialError::BindingMismatch)
    ));
}

#[test]
fn expiration_during_credential_acquisition_prevents_the_dispatch_callback() {
    let encrypted = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let (_session, approved, keys) = fixture(&encrypted);
    let data = keys.decrypt(approved, &encrypted).unwrap();

    assert_eq!(
        data.dispatch_at(
            || Instant::now() + Duration::from_secs(30),
            |_, _| panic!("must not dispatch")
        ),
        Err(CredentialError::DispatchExpired)
    );
}

#[test]
fn revocation_and_policy_change_after_decryption_prevent_the_dispatch_callback() {
    for revoke in [false, true] {
        let encrypted = EncryptedCredential::parse(CIPHER.trim()).unwrap();
        let (session, approved, keys) = fixture(&encrypted);
        let data = keys.decrypt(approved, &encrypted).unwrap();
        let error = if revoke {
            session.revoke().unwrap();
            CredentialError::SessionRevoked
        } else {
            session.update_policy([9; 32]).unwrap();
            CredentialError::PolicyChanged
        };

        assert_eq!(
            data.dispatch(|_, _| panic!("must not dispatch")),
            Err(error)
        );
    }
}
