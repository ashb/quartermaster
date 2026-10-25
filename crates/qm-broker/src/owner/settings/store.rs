use super::{Admission, Error, Manager, Record};

trait Storage: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>, Error>;
    fn create(&self, bytes: &[u8]) -> Result<(), Error>;
    fn replace(&self, bytes: &[u8]) -> Result<(), Error>;
}

pub(in crate::owner) struct Store {
    storage: Box<dyn Storage>,
}

impl Store {
    #[cfg(target_os = "macos")]
    pub(in crate::owner) fn native() -> Result<Self, Error> {
        qm_macos::protected_record::ProtectedRecord::open(
            "dev.quartermaster.settings.development.v1",
        )
        .map(|storage| Self {
            storage: Box::new(storage),
        })
        .map_err(|_| Error::Storage)
    }

    pub(in crate::owner) fn load<C>(&self) -> Result<Option<Manager<C>>, Error> {
        self.storage
            .load()?
            .map(|bytes| Record::decode(&bytes).map(Manager::new))
            .transpose()
    }

    pub(in crate::owner) fn register<C>(&self, key: &[u8]) -> Result<Manager<C>, Error> {
        if let Some(manager) = self.load()? {
            if manager.record().public_key() != key {
                return Err(Error::Stale);
            }
            return Ok(manager);
        }
        let record = Record::unconfigured(key)?;
        self.storage
            .create(&serde_json::to_vec(&record).map_err(|_| Error::Invalid)?)?;
        let retained = self.load()?.ok_or(Error::Storage)?;
        if retained.record().public_key() != key {
            return Err(Error::Stale);
        }
        Ok(retained)
    }

    pub(in crate::owner) fn publish<C>(&self, admission: Admission<C>) -> Publication<C> {
        let result = serde_json::to_vec(admission.record())
            .map_err(|_| Error::Invalid)
            .and_then(|bytes| self.storage.replace(&bytes));
        Publication { admission, result }
    }

    #[cfg(test)]
    pub(in crate::owner) fn memory() -> Self {
        Self {
            storage: Box::<tests::Memory>::default(),
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
mod tests {
    use super::*;
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
        };
        let mut key = vec![1; 65];
        key[0] = 4;
        assert!(store.load::<()>().is_err());
        assert!(store.register::<()>(&key).is_err());
    }
}
