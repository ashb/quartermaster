use qm_providers::{ApprovalSession, EncryptedCredential, VaultKeys};
use qm_types::CredentialError;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

const CIPHER: &str = include_str!("fixtures/dummy.type2");

fn signing_key() -> EcdsaKeyPair {
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random).unwrap()
}

#[test]
fn authenticated_credential_reaches_only_the_bound_approved_dispatch() {
    let key = signing_key();
    let session = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    let credential = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let mut pending = session.begin([3; 32], credential.digest()).unwrap();
    let challenge = pending.record_authentication().unwrap();
    let signature = key.sign(&SystemRandom::new(), &challenge).unwrap();
    let approved = pending.approve(signature.as_ref()).unwrap();
    let keys = VaultKeys::restore(&session, &(0..64).collect::<Vec<_>>()).unwrap();

    let data = keys.decrypt(approved, &credential).unwrap();

    data.dispatch(|request, bytes| {
        assert_eq!(request.request_digest, [3; 32]);
        assert_eq!(request.session_id, [1; 16]);
        assert_eq!(request.policy_digest, [2; 32]);
        assert_eq!(request.credential_digest, credential.digest());
        assert_eq!(bytes, b"quartermaster-dummy-canary");
    })
    .unwrap();
}

#[test]
fn a_signature_from_another_key_cannot_authorize_decryption() {
    let trusted = signing_key();
    let impostor = signing_key();
    let session = ApprovalSession::new([1; 16], [2; 32], trusted.public_key().as_ref()).unwrap();
    let credential = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let mut pending = session.begin([3; 32], credential.digest()).unwrap();
    let challenge = pending.record_authentication().unwrap();
    let signature = impostor.sign(&SystemRandom::new(), &challenge).unwrap();

    assert!(matches!(
        pending.approve(signature.as_ref()),
        Err(CredentialError::InvalidApprovalSignature)
    ));
}

#[test]
fn separately_constructed_authorities_cannot_authorize_an_existing_key_handle() {
    let key = signing_key();
    let owner = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    let keys = VaultKeys::restore(&owner, &(0..64).collect::<Vec<_>>()).unwrap();
    let lookalike = ApprovalSession::new([1; 16], [2; 32], key.public_key().as_ref()).unwrap();
    let credential = EncryptedCredential::parse(CIPHER.trim()).unwrap();
    let mut pending = lookalike.begin([3; 32], credential.digest()).unwrap();
    let challenge = pending.record_authentication().unwrap();
    let signature = key.sign(&SystemRandom::new(), &challenge).unwrap();
    let approved = pending.approve(signature.as_ref()).unwrap();

    assert!(matches!(
        keys.decrypt(approved, &credential),
        Err(CredentialError::BindingMismatch)
    ));
}
