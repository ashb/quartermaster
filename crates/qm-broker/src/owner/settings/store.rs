use super::approval::SignedChange;
use super::{Admission, Error, Manager, Record};

trait Storage: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, Error>;
    fn create(&self, bytes: &[u8]) -> Result<(), Error>;
    fn replace(&self, bytes: &[u8]) -> Result<(), Error>;
}

pub(in crate::owner) struct Store {
    storage: Box<dyn Storage>,
    anchor: Box<dyn Storage>,
}

impl Store {
    #[cfg(target_os = "macos")]
    pub(in crate::owner) fn native() -> Result<Self, Error> {
        use qm_macos::protected_record::ProtectedRecord;
        Ok(Self {
            storage: Box::new(
                ProtectedRecord::open("dev.quartermaster.settings.development.v1")
                    .map_err(|_| Error::Storage)?,
            ),
            anchor: Box::new(
                ProtectedRecord::open("dev.quartermaster.settings-key.development.v1")
                    .map_err(|_| Error::Storage)?,
            ),
        })
    }

    pub(in crate::owner) fn load<C>(&self) -> Result<Option<Manager<C>>, Error> {
        let Some(bytes) = self.storage.load()? else {
            return Ok(None);
        };
        if bytes.len() > qm_types::PROTECTED_RECORD_BYTES {
            return Err(Error::Invalid);
        }
        if let Ok(signed) = serde_json::from_slice::<SignedChange>(&bytes) {
            let key = self.anchor.load()?.ok_or(Error::Storage)?;
            return signed.record(&key).map(Manager::new).map(Some);
        }
        let legacy = Record::decode(&bytes)?;
        self.pin(legacy.public_key())?;
        Manager::from_legacy(legacy, &bytes).map(Some)
    }

    fn pin(&self, key: &[u8]) -> Result<(), Error> {
        Record::unconfigured(key)?;
        if self.anchor.load()?.is_none() {
            self.anchor.create(key)?;
        }
        if self.anchor.load()?.as_deref() != Some(key) {
            return Err(Error::Stale);
        }
        Ok(())
    }

    pub(in crate::owner) fn register<C>(&self, key: &[u8]) -> Result<Manager<C>, Error> {
        if let Some(manager) = self.load()? {
            if manager.record().public_key() != key {
                return Err(Error::Stale);
            }
            return Ok(manager);
        }
        let record = Record::unconfigured(key)?;
        self.pin(key)?;
        self.storage
            .create(&serde_json::to_vec(&record).map_err(|_| Error::Invalid)?)?;
        let retained = self.load()?.ok_or(Error::Storage)?;
        if retained.record().public_key() != key {
            return Err(Error::Stale);
        }
        Ok(retained)
    }

    pub(in crate::owner) fn publish<C>(&self, admission: Admission<C>) -> Publication<C> {
        let result = self
            .anchor
            .load()
            .and_then(|key| {
                let key = key.ok_or(Error::Storage)?;
                if admission.signed.record(&key)? != *admission.record() {
                    return Err(Error::Invalid);
                }
                if let Some(source) = admission.signed.migration_source()? {
                    source.check_current(&self.storage.load()?.ok_or(Error::Storage)?)?;
                }
                admission.signed.encoded()
            })
            .and_then(|bytes| self.storage.replace(&bytes));
        Publication { admission, result }
    }

    #[cfg(test)]
    pub(in crate::owner) fn memory() -> Self {
        Self {
            storage: Box::<tests::Memory>::default(),
            anchor: Box::<tests::Memory>::default(),
        }
    }

    #[cfg(test)]
    pub(in crate::owner) fn paused() -> (
        Self,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, observing) = std::sync::mpsc::sync_channel(1);
        let (release, waiting) = std::sync::mpsc::sync_channel(1);
        (
            Self {
                anchor: Box::<tests::Memory>::default(),
                storage: Box::new(tests::Paused {
                    memory: tests::Memory::default(),
                    entered,
                    waiting: std::sync::Mutex::new(waiting),
                }),
            },
            observing,
            release,
        )
    }
}

pub(in crate::owner) struct Publication<C> {
    pub(super) admission: Admission<C>,
    pub(super) result: Result<(), Error>,
}

#[cfg(target_os = "macos")]
impl Storage for qm_macos::protected_record::ProtectedRecord {
    fn load(&self) -> Result<Option<Vec<u8>>, Error> {
        self.load().map_err(|_| Error::Storage)
    }
    fn create(&self, bytes: &[u8]) -> Result<(), Error> {
        self.create(bytes).map_err(|_| Error::Storage)
    }
    fn replace(&self, bytes: &[u8]) -> Result<(), Error> {
        self.replace(bytes).map_err(|_| Error::Storage)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::owner::settings::{BASE64, Engine, Proposal, Revision, Settings};
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };
    use std::sync::Mutex;

    #[derive(Default)]
    pub(super) struct Memory(Mutex<Option<Vec<u8>>>);
    pub(super) struct Paused {
        pub(super) memory: Memory,
        pub(super) entered: std::sync::mpsc::SyncSender<()>,
        pub(super) waiting: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Storage for Paused {
        fn load(&self) -> Result<Option<Vec<u8>>, Error> {
            self.memory.load()
        }
        fn create(&self, bytes: &[u8]) -> Result<(), Error> {
            self.memory.create(bytes)
        }
        fn replace(&self, bytes: &[u8]) -> Result<(), Error> {
            self.entered.send(()).map_err(|_| Error::Storage)?;
            self.waiting
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| Error::Storage)?;
            self.memory.replace(bytes)
        }
    }
    impl Storage for Memory {
        fn load(&self) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn create(&self, bytes: &[u8]) -> Result<(), Error> {
            let mut value = self.0.lock().unwrap();
            if value.is_some() {
                return Err(Error::Storage);
            }
            *value = Some(bytes.to_vec());
            Ok(())
        }
        fn replace(&self, bytes: &[u8]) -> Result<(), Error> {
            let mut value = self.0.lock().unwrap();
            if value.is_none() {
                return Err(Error::Storage);
            }
            *value = Some(bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn registration_pins_only_an_unconfigured_record_and_cannot_replace_its_key() {
        let store = Store {
            storage: Box::<Memory>::default(),
            anchor: Box::<Memory>::default(),
        };
        let mut first = vec![1; 65];
        first[0] = 4;
        let mut other = first.clone();
        other[1] ^= 1;
        let manager = store.register::<()>(&first).unwrap();
        let record = manager.record();
        assert!(record.settings.is_none());
        assert!(record.provider.is_none());
        assert!(store.register::<()>(&other).is_err());
        assert_eq!(
            store.load::<()>().unwrap().unwrap().record().public_key(),
            first
        );
    }

    #[test]
    fn corrupt_protected_state_is_not_replaced_by_registration() {
        let store = Store {
            storage: Box::new(Memory(Mutex::new(Some(b"corrupted".to_vec())))),
            anchor: Box::<Memory>::default(),
        };
        let mut key = vec![1; 65];
        key[0] = 4;
        assert!(store.load::<()>().is_err());
        assert!(store.register::<()>(&key).is_err());
    }

    pub(in crate::owner) fn use_legacy_format(store: &Store) {
        let record = store.load::<()>().unwrap().unwrap().record().clone();
        store
            .storage
            .replace(&serde_json::to_vec(&record).unwrap())
            .unwrap();
    }

    fn signed_store() -> (Store, Record, EcdsaKeyPair) {
        let random = SystemRandom::new();
        let bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes.as_ref(), &random)
                .unwrap();
        let store = Store::memory();
        let mut manager: Manager = store.register(key.public_key().as_ref()).unwrap();
        let review = manager
            .prepare(
                7,
                [1; 16],
                Proposal {
                    revision: Revision(0),
                    settings: Settings::decode(br#"{"github":null,"mutations":"deny"}"#).unwrap(),
                    provider: Some(super::super::ProviderPin {
                        slot: "legacy".into(),
                        binding: crate::owner::test_support::vault::snapshot("github-write")
                            .binding()
                            .clone(),
                        scope: "0".repeat(32),
                        device_key: [7; 32],
                    }),
                },
                1000.into(),
                (),
            )
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 1001.into(), 1002.into())
            .unwrap();
        let signature = key
            .sign(&random, &BASE64.decode(challenge.bytes).unwrap())
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 1003.into())
            .unwrap();
        let admission = manager.admit(verified, 1004.into()).unwrap();
        manager.finish(store.publish(admission)).unwrap();
        (store, manager.record().clone(), key)
    }

    #[test]
    fn stored_settings_retain_the_signature_and_verify_without_a_live_authentication_context() {
        let (store, expected, _) = signed_store();
        let bytes = store.storage.load().unwrap().unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            document["signature"]
                .as_str()
                .is_some_and(|signature| !signature.is_empty())
        );
        assert!(document["review"]["document"].is_string());
        assert!(store.load::<()>().unwrap().unwrap().record() == &expected);
        assert!(store.load::<()>().unwrap().unwrap().migration().is_none());
    }

    #[test]
    fn stored_settings_reject_tampered_documents_timestamps_signatures_and_a_replaced_signer() {
        for field in ["signature", "authenticated", "document", "digest", "signer"] {
            let (store, _, _) = signed_store();
            let mut value: serde_json::Value =
                serde_json::from_slice(&store.storage.load().unwrap().unwrap()).unwrap();
            match field {
                "signature" => value["signature"] = BASE64.encode([0; 70]).into(),
                "authenticated" => value["authenticated"] = 1002.into(),
                "signer" => {
                    let (other, _, _) = signed_store();
                    value =
                        serde_json::from_slice(&other.storage.load().unwrap().unwrap()).unwrap();
                }
                _ => value["review"][field] = BASE64.encode(b"altered").into(),
            }
            store
                .storage
                .replace(&serde_json::to_vec(&value).unwrap())
                .unwrap();
            assert!(store.load::<()>().is_err(), "{field}");
        }
    }

    #[test]
    fn legacy_settings_preserve_the_source_revision_without_policy_or_provider_authority() {
        let (store, record, _) = signed_store();
        store
            .storage
            .replace(&serde_json::to_vec(&record).unwrap())
            .unwrap();
        let manager = store.load::<()>().unwrap().unwrap();
        assert_eq!(manager.record().public_key(), record.public_key());
        assert_eq!(manager.record().revision(), record.revision());
        assert!(manager.record().settings().is_none());
        assert!(manager.record().provider().is_none());
        assert!(manager.policy().is_err());
        assert_eq!(
            store.storage.load().unwrap().unwrap(),
            serde_json::to_vec(&record).unwrap()
        );
        let migration = manager.migration().unwrap();
        assert!(Some(&migration.settings) == record.settings());
        assert!(migration.provider == record.provider);
        assert_eq!(migration.revision, record.revision());
    }

    #[test]
    fn import_requires_fresh_proof_and_canceling_preserves_the_complete_source() {
        let (store, _, _) = signed_store();
        use_legacy_format(&store);
        let original = store.storage.load().unwrap().unwrap();
        let mut manager = store.load::<()>().unwrap().unwrap();
        let source = manager.migration().unwrap().source.clone();
        assert!(
            manager
                .prepare_import("another source", 7, [1; 16], 1000.into(), ())
                .is_err()
        );
        let review = manager
            .prepare_import(&source.id, 7, [1; 16], 1000.into(), ())
            .unwrap();
        assert!(
            manager
                .approve(&review.id, 7, b"unsigned", 1001.into())
                .is_err()
        );
        let review = manager
            .prepare_import(&source.id, 7, [1; 16], 1002.into(), ())
            .unwrap();
        assert!(manager.cancel(&review.id, 7).unwrap());
        assert!(manager.migration().unwrap().source == source);
        assert!(manager.policy().is_err());
        assert_eq!(store.storage.load().unwrap().unwrap(), original);
        assert!(store.load::<()>().unwrap().unwrap().migration().is_some());
    }

    #[test]
    fn importing_publishes_the_full_signed_settings_once_and_reloads_without_migration() {
        let (store, previous, key) = signed_store();
        use_legacy_format(&store);
        let mut manager = store.load::<()>().unwrap().unwrap();
        let source = manager.migration().unwrap().source.clone();
        let review = manager
            .prepare_import(&source.id, 7, [1; 16], 2000.into(), ())
            .unwrap();
        let encoded = serde_json::to_value(&review).unwrap();
        let document: serde_json::Value = serde_json::from_slice(
            &BASE64
                .decode(encoded["document"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(document["migration"]["id"], source.id);
        let challenge = manager
            .authenticate(&review.id, 7, 2001.into(), 2002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 2003.into())
            .unwrap();
        let admission = manager.admit(verified, 2004.into()).unwrap();
        manager.finish(store.publish(admission)).unwrap();
        assert!(manager.migration().is_none());
        assert!(manager.record().settings() == previous.settings());
        assert!(manager.record().provider() == previous.provider());
        assert_eq!(
            manager.record().revision(),
            previous.revision().next().unwrap()
        );
        let loaded = store.load::<()>().unwrap().unwrap();
        assert!(loaded.migration().is_none());
        assert!(loaded.record() == manager.record());
        assert!(
            manager
                .prepare_import(&source.id, 7, [1; 16], 2005.into(), ())
                .is_err()
        );
        let mut changed: serde_json::Value =
            serde_json::from_slice(&store.storage.load().unwrap().unwrap()).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(
            &BASE64
                .decode(changed["review"]["document"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        document["migration"]["id"] = BASE64.encode([7; 32]).into();
        let bytes = serde_json::to_vec(&document).unwrap();
        changed["review"]["document"] = BASE64.encode(&bytes).into();
        changed["review"]["digest"] = BASE64
            .encode(ring::digest::digest(&ring::digest::SHA256, &bytes))
            .into();
        store
            .storage
            .replace(&serde_json::to_vec(&changed).unwrap())
            .unwrap();
        assert!(store.load::<()>().is_err());
    }

    #[test]
    fn discarding_legacy_settings_preserves_the_key_pin_and_advances_the_signed_revision() {
        let (store, mut previous, key) = signed_store();
        previous.revision = Revision(4);
        store
            .storage
            .replace(&serde_json::to_vec(&previous).unwrap())
            .unwrap();
        let anchor = store.anchor.load().unwrap();
        let mut manager = store.load::<()>().unwrap().unwrap();
        let source = manager.migration().unwrap().source.clone();
        let review = manager
            .prepare_discard(&source.id, 7, [1; 16], 2000.into(), ())
            .unwrap();
        let challenge = manager
            .authenticate(&review.id, 7, 2001.into(), 2002.into())
            .unwrap();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &BASE64.decode(&challenge.bytes).unwrap(),
            )
            .unwrap();
        let verified = manager
            .approve(&review.id, 7, signature.as_ref(), 2003.into())
            .unwrap();
        let admission = manager.admit(verified, 2004.into()).unwrap();
        manager.finish(store.publish(admission)).unwrap();
        let loaded = store.load::<()>().unwrap().unwrap();
        assert!(loaded.migration().is_none());
        assert_eq!(loaded.record().revision(), Revision(5));
        assert!(loaded.record().provider().is_none());
        let disabled =
            Settings::decode(br#"{"github":null,"mutations":"requireApproval"}"#).unwrap();
        assert!(loaded.record().settings() == Some(&disabled));
        assert!(loaded.policy().is_err());
        assert_eq!(store.anchor.load().unwrap(), anchor);
        assert_eq!(loaded.record().public_key(), previous.public_key());
        assert!(
            manager
                .prepare_discard(&source.id, 7, [1; 16], 2005.into(), ())
                .is_err()
        );
    }

    #[test]
    fn changing_the_source_during_migration_cannot_overwrite_it() {
        for discard in [false, true] {
            let (store, _, key) = signed_store();
            use_legacy_format(&store);
            let mut manager = store.load::<()>().unwrap().unwrap();
            let source = manager.migration().unwrap().source.clone();
            let review = if discard {
                manager.prepare_discard(&source.id, 7, [1; 16], 2000.into(), ())
            } else {
                manager.prepare_import(&source.id, 7, [1; 16], 2000.into(), ())
            }
            .unwrap();
            let challenge = manager
                .authenticate(&review.id, 7, 2001.into(), 2002.into())
                .unwrap();
            let signature = key
                .sign(
                    &SystemRandom::new(),
                    &BASE64.decode(&challenge.bytes).unwrap(),
                )
                .unwrap();
            let verified = manager
                .approve(&review.id, 7, signature.as_ref(), 2003.into())
                .unwrap();
            let admission = manager.admit(verified, 2004.into()).unwrap();
            let changed = b"changed source";
            store.storage.replace(changed).unwrap();
            assert!(manager.finish(store.publish(admission)).is_err());
            assert_eq!(store.storage.load().unwrap().unwrap(), changed);
            assert!(manager.failed());
            assert!(manager.policy().is_err());
        }
    }

    #[test]
    fn unsupported_or_corrupt_formats_cannot_become_import_candidates() {
        for bytes in [
            br#"{"version":999}"#.as_slice(),
            br#"{"review":{},"signature":"invalid"}"#,
        ] {
            let store = Store {
                storage: Box::new(Memory(Mutex::new(Some(bytes.to_vec())))),
                anchor: Box::<Memory>::default(),
            };
            assert!(store.load::<()>().is_err());
            assert_eq!(store.storage.load().unwrap().unwrap(), bytes);
        }
    }
}
