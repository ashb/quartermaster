use super::{ProviderBinding, VaultSnapshot};
use crate::{EncryptedCredential, KdfParameters};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"QMVCACHE";
const MAX_CACHE: usize = 262144;
const MAX_HEADER: usize = 16384;

#[derive(Debug, PartialEq, Eq)]
pub enum CacheError {
    InvalidFormat,
    UnsupportedVersion,
    BindingMismatch,
    KeyMismatch,
    Stale,
    AuthenticationFailed,
    InvalidKey,
    RandomnessUnavailable,
    InvalidSnapshot,
}

/// Parsed header metadata is untrusted until `open` authenticates the complete envelope.
pub struct SealedSnapshot {
    bytes: Vec<u8>,
    header: Header,
    payload_offset: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: u32,
    rbw_version: String,
    binding: ProviderBinding,
    device_key: [u8; 32],
    wrapped_key: Vec<u8>,
    checkpoint: [u8; 16],
    #[serde(with = "time::serde::timestamp")]
    synchronized_at: OffsetDateTime,
    kdf: KdfParameters,
}

#[derive(Serialize)]
struct PayloadRef<'a> {
    cipher: &'a str,
    selected_key: &'a [u8],
    vault_key: &'a [u8],
    protected_key: &'a str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    cipher: String,
    selected_key: Zeroizing<Vec<u8>>,
    vault_key: Zeroizing<Vec<u8>>,
    protected_key: String,
    refresh_token: Zeroizing<String>,
}

impl SealedSnapshot {
    pub fn seal(
        snapshot: &VaultSnapshot,
        key: &[u8],
        identity: [u8; 32],
        wrapped: &[u8],
    ) -> Result<Self, CacheError> {
        if snapshot.synchronized_at <= OffsetDateTime::UNIX_EPOCH
            || snapshot.synchronized_at.nanosecond() != 0
        {
            return Err(CacheError::InvalidSnapshot);
        }
        let encryption = encryption_key(key)?;
        if wrapped.len() != 113 {
            return Err(CacheError::InvalidFormat);
        }
        let header = Header {
            schema: 1,
            rbw_version: "1.15.0".into(),
            binding: snapshot.binding.clone(),
            device_key: identity,
            wrapped_key: wrapped.to_vec(),
            checkpoint: snapshot.checkpoint,
            synchronized_at: snapshot.synchronized_at,
            kdf: snapshot.kdf,
        };
        let encoded_header = serde_json::to_vec(&header).map_err(|_| CacheError::InvalidFormat)?;
        if encoded_header.len() > MAX_HEADER {
            return Err(CacheError::InvalidFormat);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(encoded_header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded_header);
        let aad_length = bytes.len();
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| CacheError::RandomnessUnavailable)?;
        let mut payload = Zeroizing::new(
            serde_json::to_vec(&PayloadRef {
                cipher: snapshot.credential.encoded(),
                selected_key: &snapshot.selected_key,
                vault_key: &snapshot.vault_key,
                protected_key: &snapshot.protected_key,
                refresh_token: &snapshot.refresh_token,
            })
            .map_err(|_| CacheError::InvalidSnapshot)?,
        );
        if aad_length + 12 + payload.len() + 16 > MAX_CACHE {
            return Err(CacheError::InvalidSnapshot);
        }
        encryption
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&bytes[..]),
                &mut *payload,
            )
            .map_err(|_| CacheError::AuthenticationFailed)?;
        bytes.extend_from_slice(&nonce);
        let payload_offset = bytes.len();
        bytes.extend_from_slice(&payload);
        Ok(Self {
            bytes,
            header,
            payload_offset,
        })
    }

    pub fn decode(
        bytes: &[u8],
        binding: &ProviderBinding,
        identity: &[u8; 32],
    ) -> Result<Self, CacheError> {
        if bytes.len() < 40 || bytes.len() > MAX_CACHE || &bytes[..8] != MAGIC {
            return Err(CacheError::InvalidFormat);
        }
        let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if length > MAX_HEADER || 12 + length + 28 >= bytes.len() {
            return Err(CacheError::InvalidFormat);
        }
        let header: Header = serde_json::from_slice(&bytes[12..12 + length])
            .map_err(|_| CacheError::InvalidFormat)?;
        if header.schema != 1 || header.rbw_version != "1.15.0" {
            return Err(CacheError::UnsupportedVersion);
        }
        if &header.binding != binding {
            return Err(CacheError::BindingMismatch);
        }
        if &header.device_key != identity {
            return Err(CacheError::KeyMismatch);
        }
        if header.wrapped_key.len() != 113 || header.synchronized_at <= OffsetDateTime::UNIX_EPOCH {
            return Err(CacheError::InvalidFormat);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            header,
            payload_offset: 24 + length,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn wrapped_key(&self) -> &[u8] {
        &self.header.wrapped_key
    }

    pub fn checkpoint(&self) -> [u8; 16] {
        self.header.checkpoint
    }

    pub fn synchronized_at(&self) -> OffsetDateTime {
        self.header.synchronized_at
    }

    /// The caller supplies its observed high-water mark. Rolling back this file and
    /// all external state together cannot be detected by authenticated encryption.
    pub fn open(
        self,
        key: &[u8],
        minimum_sync: OffsetDateTime,
    ) -> Result<VaultSnapshot, CacheError> {
        let encryption = encryption_key(key)?;
        let nonce: [u8; 12] = self.bytes[self.payload_offset - 12..self.payload_offset]
            .try_into()
            .unwrap();
        let mut plaintext = Zeroizing::new(self.bytes[self.payload_offset..].to_vec());
        let opened = encryption
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&self.bytes[..self.payload_offset - 12]),
                &mut plaintext,
            )
            .map_err(|_| CacheError::AuthenticationFailed)?;
        if self.header.synchronized_at < minimum_sync {
            return Err(CacheError::Stale);
        }
        let payload: Payload =
            serde_json::from_slice(opened).map_err(|_| CacheError::InvalidSnapshot)?;
        let keys =
            super::locked_keys(&payload.selected_key).map_err(|_| CacheError::InvalidSnapshot)?;
        if payload.vault_key.len() != 64
            || payload.refresh_token.is_empty()
            || payload.refresh_token.len() > 16384
        {
            return Err(CacheError::InvalidSnapshot);
        }
        let credential =
            EncryptedCredential::parse(&payload.cipher).map_err(|_| CacheError::InvalidSnapshot)?;
        credential
            .authenticate(&keys)
            .map_err(|_| CacheError::InvalidSnapshot)?;
        EncryptedCredential::parse(&payload.protected_key)
            .map_err(|_| CacheError::InvalidSnapshot)?;
        Ok(VaultSnapshot {
            binding: self.header.binding,
            credential,
            selected_key: payload.selected_key,
            vault_key: payload.vault_key,
            protected_key: payload.protected_key,
            refresh_token: payload.refresh_token,
            checkpoint: self.header.checkpoint,
            synchronized_at: self.header.synchronized_at,
            kdf: self.header.kdf,
        })
    }
}

fn encryption_key(bytes: &[u8]) -> Result<LessSafeKey, CacheError> {
    if bytes.len() != 32 {
        return Err(CacheError::InvalidKey);
    }
    UnboundKey::new(&AES_256_GCM, bytes)
        .map(LessSafeKey::new)
        .map_err(|_| CacheError::InvalidKey)
}

#[cfg(test)]
mod tests {
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
            credential: EncryptedCredential::parse(
                include_str!("../../tests/fixtures/dummy.type2").trim(),
            )
            .unwrap(),
            selected_key: Zeroizing::new((0..64).collect()),
            vault_key: Zeroizing::new((0..64).collect()),
            protected_key: include_str!("../../tests/fixtures/dummy.type2")
                .trim()
                .to_string(),
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
                SealedSnapshot::decode(
                    &encrypted.as_bytes()[..size],
                    original.binding(),
                    &IDENTITY
                )
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
}
