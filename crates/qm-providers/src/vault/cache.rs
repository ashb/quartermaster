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
#[path = "../../tests/unit/vault_cache.rs"]
mod tests;
