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
    let value: serde_json::Value = serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();
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
    let intent: serde_json::Value = serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();
    assert_eq!(intent["minimum_sync"], 0);
    enrollment.record_key([7; 32]).unwrap();
    enrollment
        .record_ready(OffsetDateTime::from_unix_timestamp(1_792_483_200).unwrap())
        .unwrap();

    let ready: serde_json::Value = serde_json::from_slice(&enrollment.encode().unwrap()).unwrap();

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
