use super::{ProviderBinding, ProviderError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentPhase {
    Intent,
    KeyCreated,
    Ready,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "Record")]
pub struct VaultEnrollment {
    schema: u32,
    binding: ProviderBinding,
    scope: String,
    phase: EnrollmentPhase,
    identity: Option<[u8; 32]>,
    #[serde(with = "time::serde::timestamp")]
    minimum_sync: OffsetDateTime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    binding: ProviderBinding,
    scope: String,
    phase: EnrollmentPhase,
    identity: Option<[u8; 32]>,
    #[serde(with = "time::serde::timestamp")]
    minimum_sync: OffsetDateTime,
}

fn valid_scope(scope: &str) -> bool {
    scope.len() == 32
        && scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl TryFrom<Record> for VaultEnrollment {
    type Error = &'static str;
    fn try_from(record: Record) -> Result<Self, Self::Error> {
        let valid_phase = match record.phase {
            EnrollmentPhase::Intent => {
                record.identity.is_none() && record.minimum_sync == OffsetDateTime::UNIX_EPOCH
            }
            EnrollmentPhase::KeyCreated => {
                record.identity.is_some() && record.minimum_sync == OffsetDateTime::UNIX_EPOCH
            }
            EnrollmentPhase::Ready => {
                record.identity.is_some() && record.minimum_sync > OffsetDateTime::UNIX_EPOCH
            }
        };
        if record.schema != 1 || !valid_scope(&record.scope) || !valid_phase {
            return Err("invalid_enrollment");
        }
        Ok(Self {
            schema: record.schema,
            binding: record.binding,
            scope: record.scope,
            phase: record.phase,
            identity: record.identity,
            minimum_sync: record.minimum_sync,
        })
    }
}

impl VaultEnrollment {
    pub fn begin(binding: ProviderBinding, scope: String) -> Result<Self, ProviderError> {
        if !valid_scope(&scope) {
            return Err(ProviderError::InvalidBinding);
        }
        Ok(Self {
            schema: 1,
            binding,
            scope,
            phase: EnrollmentPhase::Intent,
            identity: None,
            minimum_sync: OffsetDateTime::UNIX_EPOCH,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProviderError> {
        if bytes.len() > 16384 {
            return Err(ProviderError::CacheIncompatible);
        }
        serde_json::from_slice(bytes).map_err(|_| ProviderError::CacheIncompatible)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProviderError> {
        serde_json::to_vec(self).map_err(|_| ProviderError::CacheIncompatible)
    }
    pub fn record_key(&mut self, identity: [u8; 32]) -> Result<(), ProviderError> {
        if self.phase != EnrollmentPhase::Intent {
            return Err(ProviderError::KeyChanged);
        }
        self.identity = Some(identity);
        self.phase = EnrollmentPhase::KeyCreated;
        Ok(())
    }
    pub fn record_ready(&mut self, synchronized_at: OffsetDateTime) -> Result<(), ProviderError> {
        if self.identity.is_none()
            || synchronized_at <= OffsetDateTime::UNIX_EPOCH
            || synchronized_at < self.minimum_sync
            || synchronized_at.nanosecond() != 0
        {
            return Err(ProviderError::CacheIncompatible);
        }
        self.minimum_sync = synchronized_at;
        self.phase = EnrollmentPhase::Ready;
        Ok(())
    }
    pub fn phase(&self) -> EnrollmentPhase {
        self.phase
    }
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.identity
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn binding(&self) -> &ProviderBinding {
        &self.binding
    }
    pub fn minimum_sync(&self) -> OffsetDateTime {
        self.minimum_sync
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vault_lifecycle.rs"]
mod tests;
