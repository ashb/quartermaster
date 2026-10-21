use super::*;
use crate::vault::{VaultSnapshot, locked_keys};
use crate::{CredentialField, EncryptedCredential, ProviderBinding};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const IDENTITY: [u8; 32] = [7; 32];
const WRAPPED: [u8; 113] = [8; 113];

fn snapshot() -> VaultSnapshot {
    VaultSnapshot {
        binding: ProviderBinding::new(
            "https://vault.example.invalid",
            "11111111-1111-4111-8111-111111111111",
            "dummy@example.invalid",
            "22222222-2222-4222-8222-222222222222",
            CredentialField::LoginPassword,
            "github-write",
        )
        .unwrap(),
        credential: EncryptedCredential::parse(include_str!("../fixtures/dummy.type2").trim())
            .unwrap(),
        selected_key: Zeroizing::new((0..64).collect()),
        vault_key: Zeroizing::new((0..64).collect()),
        protected_key: include_str!("../fixtures/dummy.type2").trim().to_string(),
        kdf: crate::KdfParameters {
            algorithm: crate::KdfAlgorithm::Pbkdf2,
            iterations: 1,
            memory_mib: None,
            parallelism: None,
        },
        refresh_token: Zeroizing::new("dummy-sensitive-refresh-canary".into()),
        checkpoint: [3; 16],
        synchronized_at: OffsetDateTime::from_unix_timestamp(1_792_483_200).unwrap(),
    }
}

fn key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    SystemRandom::new().fill(key.as_mut()).unwrap();
    key
}

#[test]
fn encrypted_snapshot_roundtrips_only_with_its_key_and_exact_binding() {
    let original = snapshot();
    let key = key();

    let encrypted = SealedSnapshot::seal(&original, key.as_ref(), IDENTITY, &WRAPPED).unwrap();
    let decoded =
        SealedSnapshot::decode(encrypted.as_bytes(), original.binding(), &IDENTITY).unwrap();
    assert_eq!(decoded.wrapped_key(), &WRAPPED);
    let restored = decoded
        .open(key.as_ref(), original.synchronized_at())
        .unwrap();

    assert_eq!(restored.binding(), original.binding());
    assert_eq!(restored.credential_digest(), original.credential_digest());
    assert_eq!(restored.checkpoint(), [3; 16]);
    assert_eq!(
        restored.refresh_token.as_str(),
        "dummy-sensitive-refresh-canary"
    );
    restored
        .credential
        .authenticate(&locked_keys(&restored.selected_key).unwrap())
        .unwrap();
    for canary in [
        b"quartermaster-dummy-canary".as_slice(),
        b"dummy-sensitive-refresh-canary".as_slice(),
    ] {
        assert!(
            !encrypted
                .as_bytes()
                .windows(canary.len())
                .any(|bytes| bytes == canary)
        );
    }
}

#[test]
fn sealing_rejects_timestamp_precision_that_the_cache_format_cannot_preserve() {
    let mut snapshot = snapshot();
    snapshot.synchronized_at = snapshot.synchronized_at.replace_nanosecond(1).unwrap();

    assert!(matches!(
        SealedSnapshot::seal(&snapshot, &[6; 32], IDENTITY, &WRAPPED),
        Err(CacheError::InvalidSnapshot)
    ));
}

#[test]
fn wrong_key_tampering_and_mixed_wrapped_key_never_open() {
    let original = snapshot();
    let key = key();
    let encrypted = SealedSnapshot::seal(&original, key.as_ref(), IDENTITY, &WRAPPED).unwrap();
    let decoded =
        SealedSnapshot::decode(encrypted.as_bytes(), original.binding(), &IDENTITY).unwrap();
    assert!(matches!(
        decoded.open(&[0xff; 32], OffsetDateTime::UNIX_EPOCH),
        Err(CacheError::AuthenticationFailed)
    ));

    for offset in [
        0,
        8,
        12,
        encrypted.as_bytes().len() - 1,
        encrypted.as_bytes().len() - 20,
    ] {
        let mut changed = encrypted.as_bytes().to_vec();
        changed[offset] ^= 1;
        if let Ok(decoded) = SealedSnapshot::decode(&changed, original.binding(), &IDENTITY) {
            assert!(
                decoded
                    .open(key.as_ref(), OffsetDateTime::UNIX_EPOCH)
                    .is_err()
            );
        }
    }

    let mut changed = encrypted.as_bytes().to_vec();
    let header_length = u32::from_le_bytes(changed[8..12].try_into().unwrap()) as usize;
    let header = std::str::from_utf8(&changed[12..12 + header_length]).unwrap();
    let offset = header.find("8,8,8").unwrap() + 12;
    changed[offset] = b'9';
    let decoded = SealedSnapshot::decode(&changed, original.binding(), &IDENTITY).unwrap();
    assert!(matches!(
        decoded.open(key.as_ref(), OffsetDateTime::UNIX_EPOCH),
        Err(CacheError::AuthenticationFailed)
    ));
}

#[test]
fn identity_binding_version_size_and_observable_rollback_are_rejected() {
    let original = snapshot();
    let key = key();
    let encrypted = SealedSnapshot::seal(&original, key.as_ref(), IDENTITY, &WRAPPED).unwrap();
    let mut other = snapshot();
    other.binding = ProviderBinding::new(
        original.binding.server(),
        original.binding.account_id(),
        original.binding.email(),
        "33333333-3333-4333-8333-333333333333",
        CredentialField::LoginPassword,
        "github-write",
    )
    .unwrap();
    assert!(matches!(
        SealedSnapshot::decode(encrypted.as_bytes(), other.binding(), &IDENTITY),
        Err(CacheError::BindingMismatch)
    ));
    assert!(matches!(
        SealedSnapshot::decode(encrypted.as_bytes(), original.binding(), &[9; 32]),
        Err(CacheError::KeyMismatch)
    ));
    assert!(SealedSnapshot::decode(&vec![0; 262145], original.binding(), &IDENTITY).is_err());
    for size in [0, 1, 8, 11, 12, 24] {
        assert!(
            SealedSnapshot::decode(&encrypted.as_bytes()[..size], original.binding(), &IDENTITY)
                .is_err()
        );
    }
    let decoded =
        SealedSnapshot::decode(encrypted.as_bytes(), original.binding(), &IDENTITY).unwrap();
    assert!(matches!(
        decoded.open(
            key.as_ref(),
            original.synchronized_at() + std::time::Duration::from_secs(1)
        ),
        Err(CacheError::Stale)
    ));

    let mut unsupported = encrypted.as_bytes().to_vec();
    let offset = unsupported
        .windows(b"\"schema\":1".len())
        .position(|bytes| bytes == b"\"schema\":1")
        .unwrap();
    unsupported[offset + b"\"schema\":".len()] = b'2';
    assert!(matches!(
        SealedSnapshot::decode(&unsupported, original.binding(), &IDENTITY),
        Err(CacheError::UnsupportedVersion)
    ));
}

#[test]
fn sealing_uses_fresh_nonces_and_rejects_invalid_key_or_wrap_lengths() {
    let snapshot = snapshot();
    let key = key();
    let first = SealedSnapshot::seal(&snapshot, key.as_ref(), IDENTITY, &WRAPPED).unwrap();
    let second = SealedSnapshot::seal(&snapshot, key.as_ref(), IDENTITY, &WRAPPED).unwrap();
    assert_ne!(first.as_bytes(), second.as_bytes());
    assert!(matches!(
        SealedSnapshot::seal(&snapshot, &[0; 31], IDENTITY, &WRAPPED),
        Err(CacheError::InvalidKey)
    ));
    assert!(SealedSnapshot::seal(&snapshot, key.as_ref(), IDENTITY, &[0; 112]).is_err());
}
