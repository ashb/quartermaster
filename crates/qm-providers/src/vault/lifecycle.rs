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
mod tests {
    use super::*;
    use crate::CredentialField;

    const SCOPE: &str = "0123456789abcdef0123456789abcdef";

    fn binding() -> ProviderBinding {
        ProviderBinding::new(
            "https://vault.example.invalid",
            "11111111-1111-4111-8111-111111111111",
            "dummy@example.invalid",
            "22222222-2222-4222-8222-222222222222",
            CredentialField::LoginPassword,
            "github-write",
        )
        .unwrap()
    }

    #[test]
    fn persisted_enrollment_advances_from_intent_to_pinned_key_to_complete_cache() {
        let mut enrollment = VaultEnrollment::begin(binding(), SCOPE.into()).unwrap();
        assert_eq!(enrollment.phase(), EnrollmentPhase::Intent);
        assert_eq!(enrollment.identity(), None);
        assert!(
            enrollment
                .record_ready(OffsetDateTime::from_unix_timestamp(10).unwrap())
                .is_err()
        );
        enrollment = VaultEnrollment::decode(&enrollment.encode().unwrap()).unwrap();

        enrollment.record_key([7; 32]).unwrap();
        enrollment = VaultEnrollment::decode(&enrollment.encode().unwrap()).unwrap();
        assert_eq!(enrollment.phase(), EnrollmentPhase::KeyCreated);
        assert_eq!(enrollment.identity(), Some([7; 32]));
        enrollment
            .record_ready(OffsetDateTime::from_unix_timestamp(10).unwrap())
            .unwrap();
        enrollment = VaultEnrollment::decode(&enrollment.encode().unwrap()).unwrap();
        assert_eq!(enrollment.phase(), EnrollmentPhase::Ready);
        assert_eq!(
            enrollment.minimum_sync(),
            OffsetDateTime::from_unix_timestamp(10).unwrap()
        );
        assert_eq!(enrollment.binding(), &binding());
        assert_eq!(enrollment.scope(), SCOPE);
        assert!(enrollment.record_key([8; 32]).is_err());
        assert!(
            enrollment
                .record_ready(OffsetDateTime::from_unix_timestamp(9).unwrap())
                .is_err()
        );
        assert_eq!(enrollment.identity(), Some([7; 32]));
        assert_eq!(
            enrollment.minimum_sync(),
            OffsetDateTime::from_unix_timestamp(10).unwrap()
        );
        enrollment
            .record_ready(OffsetDateTime::from_unix_timestamp(11).unwrap())
            .unwrap();
    }

    #[test]
    fn inconsistent_enrollment_records_and_invalid_scopes_cannot_resume() {
        for scope in ["", "../other-key", "0123456789ABCDEF0123456789ABCDEF"] {
            assert!(VaultEnrollment::begin(binding(), scope.into()).is_err());
        }
        let enrollment = VaultEnrollment::begin(binding(), SCOPE.into()).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();
        for (field, invalid) in [
            ("schema", serde_json::json!(2)),
            ("phase", serde_json::json!("ready")),
            ("identity", serde_json::json!(vec![7u8; 32])),
            ("minimum_sync", serde_json::json!(10)),
            ("scope", serde_json::json!("../other-key")),
        ] {
            let mut invalid_value = value.clone();
            invalid_value[field] = invalid;
            assert!(
                VaultEnrollment::decode(&serde_json::to_vec(&invalid_value).unwrap()).is_err(),
                "{field}"
            );
        }
        assert!(VaultEnrollment::decode(b"not json").is_err());
        assert!(VaultEnrollment::decode(&vec![0; 16385]).is_err());
    }

    #[test]
    fn enrollment_rejects_timestamps_outside_the_supported_calendar_range() {
        let mut enrollment = VaultEnrollment::begin(binding(), SCOPE.into()).unwrap();
        enrollment.record_key([7; 32]).unwrap();
        enrollment
            .record_ready(OffsetDateTime::from_unix_timestamp(10).unwrap())
            .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();
        value["minimum_sync"] = serde_json::json!(u64::MAX);

        assert!(VaultEnrollment::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn enrollment_keeps_the_existing_unix_second_storage_format() {
        let mut enrollment = VaultEnrollment::begin(binding(), SCOPE.into()).unwrap();
        let intent: serde_json::Value =
            serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();
        assert_eq!(intent["minimum_sync"], 0);
        enrollment.record_key([7; 32]).unwrap();
        enrollment
            .record_ready(OffsetDateTime::from_unix_timestamp(1_792_483_200).unwrap())
            .unwrap();

        let ready: serde_json::Value =
            serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();

        assert_eq!(ready["minimum_sync"], 1_792_483_200u64);
    }

    #[test]
    fn enrollment_does_not_silently_truncate_a_subsecond_sync_checkpoint() {
        let mut enrollment = VaultEnrollment::begin(binding(), SCOPE.into()).unwrap();
        enrollment.record_key([7; 32]).unwrap();
        let timestamp = OffsetDateTime::from_unix_timestamp(10)
            .unwrap()
            .replace_nanosecond(1)
            .unwrap();

        assert!(enrollment.record_ready(timestamp).is_err());
        assert_eq!(enrollment.phase(), EnrollmentPhase::KeyCreated);
    }
}
