#![forbid(unsafe_code)]

mod approval;
mod migration;
mod store;

use super::{
    github::configuration::{GitHubConfig, Mode},
    policy::{AuthorizationError, Policy, PolicyDecision},
};
pub(super) use approval::{Admission, Challenge, Manager, Review};
pub(super) use approval::{LookupAdmission, LookupResult, PreparedLookup, RepositoryName};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
pub(super) use migration::{Migration, MigrationSource};
use qm_providers::{AccountBinding, ProviderBinding};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub(super) use store::Store;
#[cfg(test)]
pub(in crate::owner) use store::tests::use_legacy_format;

pub(super) const RECORD_LIMIT: usize = 96 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum ProviderChoice {
    Keep,
    Forget,
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
    pub(super) migration: Option<Migration>,
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
    #[serde(
        default,
        rename = "githubCredential",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "decode_github_credential"
    )]
    github_credential: Option<GitHubCredential>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "decode_restic"
    )]
    restic: Option<ResticConfig>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::owner) struct GitHubCredential {
    item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    item_name: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::owner) struct ResticConfig {
    pub(in crate::owner) enabled: bool,
    pub(in crate::owner) executable: String,
    pub(in crate::owner) item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::owner) item_name: Option<String>,
}

fn decode_github_credential<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<GitHubCredential>, D::Error> {
    Option::<GitHubCredential>::deserialize(deserializer)?
        .map(|mut credential| {
            credential.item_id = ProviderBinding::canonical_item_id(&credential.item_id)
                .map_err(|_| serde::de::Error::custom("invalid GitHub item identity"))?;
            if credential
                .item_name
                .as_ref()
                .is_some_and(|name| name.len() > 1024)
            {
                return Err(serde::de::Error::custom("GitHub item name is too long"));
            }
            Ok(credential)
        })
        .transpose()
}

fn decode_restic<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ResticConfig>, D::Error> {
    Option::<ResticConfig>::deserialize(deserializer)?
        .map(|mut config| {
            let path = Path::new(&config.executable);
            if !path.is_absolute()
                || path.file_name().is_none()
                || config.executable.ends_with('/')
                || config.executable.len() > 4096
                || config.executable.contains('\0')
            {
                return Err(serde::de::Error::custom("invalid Restic executable path"));
            }
            if config
                .item_name
                .as_ref()
                .is_some_and(|name| name.len() > 1024)
            {
                return Err(serde::de::Error::custom("Restic item name is too long"));
            }
            config.item_id = ProviderBinding::canonical_item_id(&config.item_id)
                .map_err(|_| serde::de::Error::custom("invalid Restic item identity"))?;
            Ok(config)
        })
        .transpose()
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
    pub(in crate::owner) fn github_binding(
        &self,
        account: &AccountBinding,
    ) -> Result<ProviderBinding, Error> {
        let credential = self.github_credential.as_ref().ok_or(Error::Invalid)?;
        if credential
            .item_name
            .as_ref()
            .is_some_and(|name| name.len() > 1024)
        {
            return Err(Error::Invalid);
        }
        ProviderBinding::new(
            account.server(),
            account.account_id(),
            account.email(),
            &credential.item_id,
            qm_providers::CredentialField::LoginPassword,
            "github-write",
        )
        .map_err(|_| Error::Invalid)
    }

    pub(in crate::owner) fn restic_binding(
        &self,
        account: &AccountBinding,
    ) -> Result<ProviderBinding, Error> {
        let config = self
            .restic
            .as_ref()
            .filter(|config| config.enabled)
            .ok_or(Error::Invalid)?;
        ProviderBinding::new(
            account.server(),
            account.account_id(),
            account.email(),
            &config.item_id,
            qm_providers::CredentialField::LoginPassword,
            "restic-password",
        )
        .map_err(|_| Error::Invalid)
    }

    pub(in crate::owner) fn restic(&self) -> Option<&ResticConfig> {
        self.restic.as_ref()
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 65536 {
            return Err(Error::Invalid);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }

    pub(super) fn policy(&self) -> Result<Policy, AuthorizationError> {
        if let Some(config) = self.github.clone().filter(GitHubConfig::enabled) {
            return Ok(Policy::default().with_github(config).with_mutation_rule(
                match self.mutations {
                    MutationRule::RequireApproval => PolicyDecision::RequireApproval,
                    MutationRule::Deny => PolicyDecision::Deny,
                },
            ));
        }
        if self.restic().is_some_and(|restic| restic.enabled) {
            return Ok(Policy::default().with_mutation_rule(PolicyDecision::Deny));
        }
        Err(AuthorizationError::Denied)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProviderPin {
    pub(super) slot: String,
    pub(super) binding: AccountBinding,
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
        if !Self::valid_slot(&self.slot) || !hex(&self.scope) || self.device_key == [0; 32] {
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
            state: if manager
                .as_ref()
                .is_some_and(|manager| manager.migration().is_some())
            {
                crate::VaultState::SettingsImportRequired
            } else {
                crate::VaultState::Unenrolled
            },
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

    pub(super) fn rules() -> Settings {
        Settings::decode(br#"{"github":{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}],"approveUnverifiedRequests":false},"githubCredential":{"itemId":"22222222-2222-4222-8222-222222222222"},"mutations":"requireApproval"}"#).unwrap()
    }

    pub(super) fn fixture() -> (EcdsaKeyPair, Manager) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let manager = Manager::new(Record::unconfigured(key.public_key().as_ref()).unwrap());
        (key, manager)
    }

    pub(super) fn pin() -> ProviderPin {
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
    fn disabling_github_retains_configuration_but_cannot_create_policy() {
        let original = rules();
        let encoded = serde_json::to_value(&original).unwrap();
        assert!(encoded["github"].get("enabled").is_none());
        let mut disabled = encoded.clone();
        disabled["github"]["enabled"] = serde_json::json!(false);
        let settings = Settings::decode(&serde_json::to_vec(&disabled).unwrap()).unwrap();
        assert!(settings.policy().is_err());
        let persisted = serde_json::to_vec(&settings).unwrap();
        let restored = Settings::decode(&persisted).unwrap();
        assert!(restored.policy().is_err());
        assert_eq!(serde_json::to_value(&restored).unwrap(), disabled);
        disabled["github"]["enabled"] = serde_json::json!(true);
        let enabled = Settings::decode(&serde_json::to_vec(&disabled).unwrap()).unwrap();
        assert!(enabled == original);
        assert!(enabled.policy().is_ok());
        assert_eq!(serde_json::to_value(&enabled).unwrap(), encoded);
    }

    fn restic_settings(enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "github": null,
            "mutations": "requireApproval",
            "restic": {
                "enabled": enabled,
                "executable": "/nix/store/example/bin/.restic-wrapped",
                "itemId": "22222222-2222-4222-8222-222222222222",
            }
        })
    }

    #[test]
    fn absent_restic_preserves_legacy_settings_bytes() {
        let original = br#"{"github":{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one","writes":false}],"approveUnverifiedRequests":false},"mutations":"requireApproval"}"#;
        let settings = Settings::decode(original).unwrap();
        assert!(settings.restic().is_none());
        assert_eq!(serde_json::to_vec(&settings).unwrap(), original);
        let mut explicit_null: serde_json::Value = serde_json::from_slice(original).unwrap();
        explicit_null["restic"] = serde_json::Value::Null;
        let settings: Settings = serde_json::from_value(explicit_null).unwrap();
        assert_eq!(serde_json::to_vec(&settings).unwrap(), original);
    }

    #[test]
    fn disabled_restic_retains_its_selection_without_enabling_policy() {
        for enabled in [false, true] {
            let encoded = restic_settings(enabled);
            let settings = Settings::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(&settings).unwrap(), encoded);
            let config = settings.restic().unwrap();
            assert_eq!(config.enabled, enabled);
            assert_eq!(config.executable, "/nix/store/example/bin/.restic-wrapped");
            assert_eq!(config.item_id, "22222222-2222-4222-8222-222222222222");
            if enabled {
                assert_eq!(
                    settings.policy().unwrap().digest(),
                    Policy::default()
                        .with_mutation_rule(PolicyDecision::Deny)
                        .digest()
                );
            } else {
                assert!(matches!(settings.policy(), Err(AuthorizationError::Denied)));
            }
        }
    }

    #[test]
    fn restic_preserves_enabled_github_policy_and_allows_disabled_github_configuration() {
        let github_settings = rules();
        let mut encoded = serde_json::to_value(&github_settings).unwrap();
        encoded["restic"] = restic_settings(true)["restic"].clone();
        let combined: Settings = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            combined.policy().unwrap().digest(),
            github_settings.policy().unwrap().digest()
        );
        encoded["github"]["enabled"] = false.into();
        let restic_only: Settings = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            restic_only.policy().unwrap().digest(),
            Policy::default()
                .with_mutation_rule(PolicyDecision::Deny)
                .digest()
        );
        assert_eq!(serde_json::to_value(restic_only).unwrap(), encoded);
    }

    #[test]
    fn invalid_restic_paths_and_items_are_rejected_in_settings_and_nested_commands() {
        let invalid = [
            ("executable", ""),
            ("executable", "restic"),
            ("executable", "./restic"),
            ("executable", "~/bin/restic"),
            ("executable", "/"),
            ("executable", "/bin/restic/"),
            ("executable", "/bin/restic\0"),
            ("itemId", ""),
            ("itemId", "not-an-item"),
            ("itemId", "00000000-0000-0000-0000-000000000000"),
        ];
        for enabled in [false, true] {
            for (field, value) in invalid {
                let mut settings = restic_settings(enabled);
                settings["restic"][field] = value.into();
                assert!(
                    Settings::decode(&serde_json::to_vec(&settings).unwrap()).is_err(),
                    "{field}: {value:?}"
                );
                let command = serde_json::json!({
                    "kind": "prepareSettings", "revision": 1,
                    "settings": settings, "provider": {"kind": "keep"},
                });
                assert!(
                    crate::owner::protocol::decode_client(&serde_json::to_vec(&command).unwrap())
                        .is_err(),
                    "{field}: {value:?}"
                );
            }
        }
        let mut oversized = restic_settings(true);
        oversized["restic"]["executable"] = format!("/{}", "x".repeat(4096)).into();
        assert!(Settings::decode(&serde_json::to_vec(&oversized).unwrap()).is_err());
    }

    #[test]
    fn restic_requires_complete_configuration_and_canonicalises_item_identity() {
        for field in ["enabled", "executable", "itemId"] {
            let mut settings = restic_settings(true);
            settings["restic"].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<Settings>(settings).is_err(),
                "{field}"
            );
        }
        let mut settings = restic_settings(true);
        settings["restic"]["executable"] = "/Applications/Backup Tools/restic".into();
        settings["restic"]["itemId"] = "AABBCCDD-2222-4222-8222-222222222222".into();
        let decoded: Settings = serde_json::from_value(settings).unwrap();
        assert_eq!(
            decoded.restic().unwrap().item_id,
            "aabbccdd-2222-4222-8222-222222222222"
        );
    }

    #[test]
    fn optional_restic_item_name_preserves_legacy_encoding_and_is_bounded() {
        let original = restic_settings(true);
        let settings: Settings = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(&settings).unwrap(), original);
        let mut named = original.clone();
        named["restic"]["itemName"] = "Restic backup".into();
        let settings: Settings = serde_json::from_value(named.clone()).unwrap();
        assert_eq!(serde_json::to_value(&settings).unwrap(), named);
        named["restic"]["itemName"] = "x".repeat(1025).into();
        assert!(serde_json::from_value::<Settings>(named).is_err());
    }

    #[test]
    fn signed_restic_selection_survives_protected_store_reload() {
        let (key, _) = fixture();
        let store = Store::memory();
        let mut manager: Manager = store.register(key.public_key().as_ref()).unwrap();
        let settings: Settings = serde_json::from_value(restic_settings(true)).unwrap();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: settings.clone(),
                    provider: Some(pin()),
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
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1_003.into())
            .unwrap();
        let admission = manager.admit(verified, 1_004.into()).unwrap();
        manager.finish(store.publish(admission)).unwrap();
        let restarted: Manager = store.load().unwrap().unwrap();
        assert!(restarted.record().settings() == Some(&settings));
        assert!(restarted.record().provider() == Some(&pin()));
        assert_eq!(
            restarted.policy().unwrap().digest(),
            Policy::default()
                .with_mutation_rule(PolicyDecision::Deny)
                .digest()
        );
    }

    #[test]
    fn settings_review_revalidates_directly_constructed_restic_configuration() {
        for invalid_item in [false, true] {
            let (_, mut manager) = fixture();
            let mut settings: Settings = serde_json::from_value(restic_settings(false)).unwrap();
            let config = settings.restic.as_mut().unwrap();
            if invalid_item {
                config.item_id = "not-an-item".into();
            } else {
                config.executable = "restic".into();
            }
            let review = manager.prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings,
                    provider: Some(pin()),
                },
                1_000.into(),
                (),
            );
            assert!(matches!(review, Err(Error::Invalid)));
            assert!(manager.idle());
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
    fn the_swift_import_command_selects_only_a_frozen_migration_source() {
        let command = crate::owner::protocol::decode_client(include_bytes!("../../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/settings-import-command.json")).unwrap();
        let crate::owner::protocol::Client::PrepareSettingsImport { id } = command else {
            panic!("wrong command")
        };
        assert_eq!(id, BASE64.encode([1; 32]));
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

    #[test]
    fn github_credential_selection_validates_identity_name_and_authority_fields() {
        let base = serde_json::json!({"github":null,"mutations":"requireApproval", "githubCredential":{"itemId":"22222222-2222-4222-8222-222222222222","itemName":"GitHub"}});
        assert!(Settings::decode(&serde_json::to_vec(&base).unwrap()).is_ok());
        for credential in [
            serde_json::json!({"itemId":"invalid"}),
            serde_json::json!({"itemId":"22222222-2222-4222-8222-222222222222","itemName":"x".repeat(1025)}),
            serde_json::json!({"itemId":"22222222-2222-4222-8222-222222222222","role":"restic-password"}),
        ] {
            let mut invalid = base.clone();
            invalid["githubCredential"] = credential;
            assert!(Settings::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn legacy_credential_binding_cannot_be_decoded_as_an_account_provider_pin() {
        let mut pin = serde_json::to_value(pin()).unwrap();
        pin["binding"]["item_id"] = serde_json::json!("22222222-2222-4222-8222-222222222222");
        pin["binding"]["field"] = serde_json::json!("LoginPassword");
        pin["binding"]["role"] = serde_json::json!("github-write");
        assert!(serde_json::from_value::<ProviderPin>(pin).is_err());
    }
}
