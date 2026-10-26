#![forbid(unsafe_code)]

mod approval;
#[cfg(target_os = "macos")]
pub(super) mod retained;
mod store;

use super::{
    github::configuration::{GitHubConfig, Mode},
    policy::{AuthorizationError, Policy, PolicyDecision},
};
pub(super) use approval::{Admission, Challenge, Manager, Review};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_providers::ProviderBinding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub(super) use store::Store;

pub(super) const RECORD_LIMIT: usize = 96 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum ProviderChoice {
    Keep,
    Forget,
    Existing { provider: ProviderPin },
    Staged { ticket: String },
}

pub(super) struct Proposal {
    pub(super) revision: Revision,
    pub(super) settings: Settings,
    pub(super) provider: Option<ProviderPin>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Snapshot {
    pub(super) state: &'static str,
    pub(super) revision: Revision,
    pub(super) session: Option<String>,
    pub(super) settings: Option<Settings>,
    pub(super) provider: Option<ProviderPin>,
    pub(super) retained: Vec<ProviderPin>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Invalid,
    Stale,
    Busy,
    Expired,
    Storage,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub(super) struct Revision(pub(super) u64);

impl Revision {
    fn next(self) -> Result<Self, Error> {
        self.0.checked_add(1).map(Self).ok_or(Error::Invalid)
    }
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum MutationRule {
    RequireApproval,
    Deny,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    #[serde(default, deserialize_with = "decode_github")]
    github: Option<GitHubConfig>,
    mutations: MutationRule,
}

fn decode_github<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<GitHubConfig>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    value
        .map(|value| {
            let bytes = serde_json::to_vec(&value).map_err(serde::de::Error::custom)?;
            let config = GitHubConfig::decode(&bytes)
                .map_err(|_| serde::de::Error::custom("invalid GitHub configuration"))?;
            if config.mode() != Mode::Github {
                return Err(serde::de::Error::custom("unsupported service mode"));
            }
            Ok(config)
        })
        .transpose()
}

impl Settings {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 65536 {
            return Err(Error::Invalid);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }

    pub(super) fn policy(&self) -> Result<Policy, AuthorizationError> {
        let config = self.github.clone().ok_or(AuthorizationError::Denied)?;
        Ok(Policy::default()
            .with_github(config)
            .with_mutation_rule(match self.mutations {
                MutationRule::RequireApproval => PolicyDecision::RequireApproval,
                MutationRule::Deny => PolicyDecision::Deny,
            }))
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProviderPin {
    pub(super) slot: String,
    pub(super) binding: ProviderBinding,
    pub(super) scope: String,
    pub(super) device_key: [u8; 32],
}

impl ProviderPin {
    pub(super) fn validate(&self) -> Result<(), Error> {
        let hex = |s: &str| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !Self::valid_slot(&self.slot)
            || !hex(&self.scope)
            || self.device_key == [0; 32]
            || !matches!(self.binding.role(), "github-read" | "github-write")
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn valid_slot(slot: &str) -> bool {
        slot == "legacy"
            || (slot.len() == 32
                && slot
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    }

    pub(super) fn root(&self, base: &Path) -> PathBuf {
        if self.slot == "legacy" {
            base.to_owned()
        } else {
            base.join("enrollments").join(&self.slot)
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Record {
    version: u8,
    profile: String,
    revision: Revision,
    public_key: Vec<u8>,
    settings: Option<Settings>,
    provider: Option<ProviderPin>,
}

impl Record {
    pub(super) fn revision(&self) -> Revision {
        self.revision
    }
    pub(super) fn settings(&self) -> Option<&Settings> {
        self.settings.as_ref()
    }
    pub(super) fn provider(&self) -> Option<&ProviderPin> {
        self.provider.as_ref()
    }
    pub(super) fn unconfigured(key: &[u8]) -> Result<Self, Error> {
        if key.len() != 65 || key[0] != 4 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            version: 1,
            profile: "development".into(),
            revision: Revision(0),
            public_key: key.to_vec(),
            settings: None,
            provider: None,
        })
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > RECORD_LIMIT {
            return Err(Error::Invalid);
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if record.version != 1
            || record.profile != "development"
            || record.public_key.len() != 65
            || record.public_key[0] != 4
            || (record.revision == Revision(0)
                && (record.settings.is_some() || record.provider.is_some()))
        {
            return Err(Error::Invalid);
        }
        if let Some(settings) = &record.settings {
            Settings::decode(&serde_json::to_vec(settings).map_err(|_| Error::Invalid)?)?;
        }
        if let Some(provider) = &record.provider {
            provider.validate()?;
        }
        Ok(record)
    }

    pub(super) fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(target_os = "macos")]
pub(super) fn persisted_status(root: &Path, store: &Store) -> Result<crate::CacheStatus, Error> {
    let manager = store.load::<()>()?;
    let Some(pin) = manager
        .as_ref()
        .and_then(|manager| manager.record().provider())
    else {
        return Ok(crate::CacheStatus {
            kind: crate::StatusKind::VaultStatus,
            state: crate::VaultState::Unenrolled,
            binding: None,
            last_sync: None,
            error: None,
            observation: None,
        });
    };
    let observed =
        super::vault::Source::capture(&pin.root(root)).and_then(|source| source.identity());
    Ok(match observed {
        Ok(identity)
            if identity.binding == pin.binding
                && identity.scope == pin.scope
                && identity.device_key == pin.device_key =>
        {
            crate::CacheStatus {
                kind: crate::StatusKind::VaultStatus,
                state: crate::VaultState::Locked,
                binding: Some(identity.binding),
                last_sync: Some(identity.synchronized_at),
                error: None,
                observation: None,
            }
        }
        Ok(_) => super::vault::error_reply(qm_providers::ProviderError::AccountMismatch.into()),
        Err(error) => super::vault::error_reply(error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct StagedResource(Arc<AtomicUsize>);
    impl Drop for StagedResource {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn rules() -> Settings {
        Settings::decode(br#"{"github":{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}],"approveUnverifiedRequests":false},"mutations":"requireApproval"}"#).unwrap()
    }

    fn fixture() -> (EcdsaKeyPair, Manager) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let manager = Manager::new(Record::unconfigured(key.public_key().as_ref()).unwrap());
        (key, manager)
    }

    fn pin() -> ProviderPin {
        ProviderPin {
            slot: "legacy".into(),
            binding: crate::owner::test_support::vault::snapshot("github-write")
                .binding()
                .clone(),
            scope: "1".repeat(32),
            device_key: [1; 32],
        }
    }

    #[test]
    fn preferences_reject_unsupported_rules_and_ambiguous_repository_catalogs() {
        let valid = serde_json::to_vec(&rules()).unwrap();
        assert!(Settings::decode(&valid).is_ok());
        for bytes in [
            br#"{"github":null,"mutations":"allow"}"#.as_slice(),
            br#"{"github":{"version":1,"mode":"github","repositories":[{"id":1,"owner":"a","name":"b"},{"id":2,"owner":"A","name":"B"}]},"mutations":"deny"}"#.as_slice(),
            br#"{"github":null,"mutations":"deny","grants":[{}]}"#.as_slice(),
        ] {
            assert!(Settings::decode(bytes).is_err());
        }
    }

    #[test]
    fn the_swift_disabled_service_command_decodes_without_a_github_field() {
        let command = crate::owner::protocol::decode_client(include_bytes!("../../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/settings-disabled-command.json")).unwrap();
        let crate::owner::protocol::Client::PrepareSettings { settings, .. } = command else {
            panic!("wrong command")
        };
        assert!(settings.github.is_none());
        assert!(settings.policy().is_err());
    }

    #[test]
    fn the_swift_retained_selection_command_binds_the_complete_provider() {
        let command = crate::owner::protocol::decode_client(include_bytes!("../../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/settings-existing-command.json")).unwrap();
        let crate::owner::protocol::Client::PrepareSettings {
            revision,
            provider: ProviderChoice::Existing { provider },
            ..
        } = command
        else {
            panic!("wrong command")
        };
        assert_eq!(revision, Revision(4));
        assert_eq!(provider.slot, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            provider.binding.item_id(),
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(provider.scope, "0123456789abcdef0123456789abcdef");
        assert_eq!(provider.device_key, [7; 32]);
        assert!(provider.validate().is_ok());
    }

    #[test]
    fn unsigned_or_altered_settings_cannot_reach_commit_and_proofs_are_single_use() {
        let (key, mut manager) = fixture();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                1_000.into(),
                (),
            )
            .unwrap();
        assert!(
            manager
                .approve(&review.id, 7, b"unsigned", 1_001.into())
                .is_err()
        );
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                2_000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 2_001.into(), 2_002.into())
            .unwrap();
        let mut altered = BASE64.decode(&challenge.bytes).unwrap();
        altered[0] ^= 1;
        let signature = key.sign(&SystemRandom::new(), &altered).unwrap();
        assert!(
            manager
                .approve(&review.id, 7, signature.as_ref(), 2_003.into())
                .is_err()
        );
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: Some(pin()),
                },
                3_000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 3_001.into(), 3_002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 3_003.into())
            .unwrap();
        assert!(
            manager
                .approve(&review.id, 7, signature.as_ref(), 3_004.into())
                .is_err()
        );
        let admission = manager.admit(verified, 3_005.into()).unwrap();
        assert!(manager.policy().is_err());
        let record = admission.record().clone();
        manager
            .finish(store::Publication {
                admission,
                result: Ok(()),
            })
            .unwrap();
        assert_eq!(manager.record().revision, Revision(1));
        assert!(manager.policy().is_ok());
        let restarted: Manager =
            Manager::new(Record::decode(&serde_json::to_vec(&record).unwrap()).unwrap());
        assert!(restarted.policy().is_ok());
        assert_eq!(restarted.record().revision, Revision(1));
    }

    #[test]
    fn canceled_expired_or_wrong_connection_changes_never_commit() {
        for failure in ["cancel", "expiry", "connection"] {
            let (key, mut manager) = fixture();
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(0),
                        settings: rules(),
                        provider: None,
                    },
                    1_000.into(),
                    (),
                )
                .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
                .unwrap();
            let signature = key
                .sign(
                    &SystemRandom::new(),
                    &BASE64.decode(&challenge.bytes).unwrap(),
                )
                .unwrap();
            let (connection, now) = match failure {
                "cancel" => {
                    manager.cancel_connection(7);
                    (7, 1_003)
                }
                "connection" => (8, 1_003),
                _ => (7, 30_000_001_002),
            };
            assert!(
                manager
                    .approve(&review.id, connection, signature.as_ref(), now.into())
                    .is_err(),
                "{failure}"
            );
            assert_eq!(manager.record().revision, Revision(0));
            assert!(manager.policy().is_err());
        }
    }

    #[test]
    fn a_timely_settings_signature_cannot_extend_the_final_admission_deadline() {
        for offset in [29_999_999_999_u64, 30_000_000_000, 30_000_000_001] {
            let (key, mut manager) = fixture();
            let authenticated = qm_types::MonotonicTimestamp::from(1_001);
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(0),
                        settings: rules(),
                        provider: None,
                    },
                    1_000.into(),
                    (),
                )
                .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, authenticated, authenticated)
                .unwrap();
            let signature = key
                .sign(
                    &SystemRandom::new(),
                    &BASE64.decode(challenge.bytes).unwrap(),
                )
                .unwrap();
            let verified = manager
                .approve(&review.id, 7, signature.as_ref(), authenticated)
                .unwrap();
            let result = manager.admit(
                verified,
                authenticated
                    .checked_add(std::time::Duration::from_nanos(offset))
                    .unwrap(),
            );
            assert_eq!(result.is_ok(), offset < 30_000_000_000, "{offset}");
            assert_eq!(manager.record().revision, Revision(0));
        }
    }

    #[test]
    fn an_oversized_signed_envelope_is_rejected_before_publication_admission() {
        let (key, mut manager) = fixture();
        let mut value = serde_json::to_value(pin()).unwrap();
        value["binding"]["server"] =
            format!("https://vault.example.invalid/{}", "x".repeat(50_000)).into();
        let provider: ProviderPin = serde_json::from_value(value).unwrap();
        for revision in 0..2 {
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(revision),
                        settings: rules(),
                        provider: Some(provider.clone()),
                    },
                    1_000.into(),
                    (),
                )
                .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
                .unwrap();
            let signature = key
                .sign(
                    &SystemRandom::new(),
                    &BASE64.decode(challenge.bytes).unwrap(),
                )
                .unwrap();
            let verified = manager.approve(&review.id, 7, signature.as_ref(), 1_003.into());
            if revision == 0 {
                let admission = manager.admit(verified.unwrap(), 1_004.into()).unwrap();
                manager
                    .finish(store::Publication {
                        admission,
                        result: Ok(()),
                    })
                    .unwrap();
            } else {
                assert_eq!(verified.err(), Some(Error::Invalid));
                assert!(manager.idle());
                assert!(!manager.failed());
                assert!(manager.policy().is_ok());
            }
            assert_eq!(manager.record().revision, Revision(1));
        }
    }

    #[test]
    fn a_failed_protected_write_never_reactivates_previous_authority() {
        let (key, mut manager) = fixture();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                1_000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1_003.into())
            .unwrap();
        let admission = manager.admit(verified, 1_004.into()).unwrap();
        assert!(
            manager
                .finish(store::Publication {
                    admission,
                    result: Err(Error::Storage)
                })
                .is_err()
        );
        assert!(manager.policy().is_err());
        assert_eq!(manager.record().revision, Revision(0));
        assert!(
            manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(0),
                        settings: rules(),
                        provider: None
                    },
                    1_005.into(),
                    ()
                )
                .is_err()
        );
    }

    #[test]
    fn canceling_after_proof_prevents_admission_and_replaced_reviews_reject_old_signatures() {
        let (key, mut manager) = fixture();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                1_000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1_003.into())
            .unwrap();
        manager.cancel_connection(7);
        assert!(manager.admit(verified, 1_004.into()).is_err());
        let replacement = manager
            .prepare(
                7,
                [2; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                2_000.into(),
                (),
            )
            .unwrap();
        manager
            .authenticate(&replacement.id, 7, 2_001.into(), 2_002.into())
            .unwrap();
        assert!(
            manager
                .approve(&replacement.id, 7, signature.as_ref(), 2_003.into())
                .is_err()
        );
    }

    #[test]
    fn policy_reversion_advances_revision_and_cannot_restore_an_old_draft() {
        let (key, mut manager) = fixture();
        for (revision, mutations) in [(0, "requireApproval"), (1, "deny"), (2, "requireApproval")] {
            let settings = Settings::decode(
                format!(r#"{{"github":null,"mutations":"{mutations}"}}"#).as_bytes(),
            )
            .unwrap();
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(revision),
                        settings,
                        provider: None,
                    },
                    1_000.into(),
                    (),
                )
                .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
                .unwrap();
            let signature = key
                .sign(
                    &SystemRandom::new(),
                    &BASE64.decode(&challenge.bytes).unwrap(),
                )
                .unwrap();
            let verified = manager
                .approve(&review.id, 7, signature.as_ref(), 1_003.into())
                .unwrap();
            let admission = manager.admit(verified, 1_004.into()).unwrap();
            manager
                .finish(store::Publication {
                    admission,
                    result: Ok(()),
                })
                .unwrap();
        }
        assert_eq!(manager.record().revision, Revision(3));
        assert!(
            manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(1),
                        settings: rules(),
                        provider: None
                    },
                    2_000.into(),
                    ()
                )
                .is_err()
        );
    }

    #[test]
    fn approving_service_rules_without_a_provider_does_not_authorize_credential_use() {
        let (key, mut manager) = fixture();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: None,
                },
                1_000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1_003.into())
            .unwrap();
        let admission = manager.admit(verified, 1_004.into()).unwrap();
        manager
            .finish(store::Publication {
                admission,
                result: Ok(()),
            })
            .unwrap();
        assert!(manager.record().settings().is_some());
        assert!(manager.policy().is_err());
    }

    #[test]
    fn rejected_canceled_and_failed_publications_drop_their_staged_resources() {
        for failure in ["signature", "cancel", "cancel-after-proof", "storage"] {
            let (key, _) = fixture();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut manager: Manager<StagedResource> =
                Manager::new(Record::unconfigured(key.public_key().as_ref()).unwrap());
            let review = manager
                .prepare(
                    7,
                    [1; 16],
                    Proposal {
                        revision: Revision(0),
                        settings: rules(),
                        provider: Some(pin()),
                    },
                    1_000.into(),
                    StagedResource(Arc::clone(&drops)),
                )
                .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, 1_001.into(), 1_002.into())
                .unwrap();
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            if failure == "signature" {
                assert!(
                    manager
                        .approve(&review.id, 7, b"invalid", 1_003.into())
                        .is_err()
                );
            } else if failure == "cancel" {
                manager.cancel_connection(7);
            } else {
                let signature = key
                    .sign(
                        &SystemRandom::new(),
                        &BASE64.decode(&challenge.bytes).unwrap(),
                    )
                    .unwrap();
                let verified = manager
                    .approve(&review.id, 7, signature.as_ref(), 1_003.into())
                    .unwrap();
                if failure == "cancel-after-proof" {
                    manager.cancel_connection(7);
                    assert!(manager.admit(verified, 1_004.into()).is_err());
                } else {
                    let admission = manager.admit(verified, 1_004.into()).unwrap();
                    assert!(
                        manager
                            .finish(store::Publication {
                                admission,
                                result: Err(Error::Storage)
                            })
                            .is_err()
                    );
                }
            }
            assert_eq!(drops.load(Ordering::SeqCst), 1, "{failure}");
        }
    }

    #[test]
    fn expired_reviews_release_staged_resources_at_the_authentication_deadline() {
        let (key, _) = fixture();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut manager = Manager::new(Record::unconfigured(key.public_key().as_ref()).unwrap());
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: rules(),
                    provider: Some(pin()),
                },
                1_000.into(),
                StagedResource(Arc::clone(&drops)),
            )
            .unwrap();
        manager
            .authenticate(&review.id, 7, 2_000.into(), 3_000.into())
            .unwrap();
        manager.expire(30_000_001_999.into());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        manager.expire(30_000_002_000.into());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(manager.idle());
    }
}
