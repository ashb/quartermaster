use super::persistence::{enrollment, store};
use super::provider_lifecycle::{
    self, CacheIdentity, PersistedRevision, ProviderOperation, ProviderState,
};
use crate::{CacheStatus, StatusKind, VaultState};
use qm_macos::cache_key::{
    CacheKeyError, CacheKeyScope, DeviceCacheKey, NativeAuthenticationContext, WrappedCacheKey,
};
use qm_providers::{
    CacheError, EnrollmentPhase, KdfLimits, ProviderError, SealedSnapshot, VaultEnrollment,
    VaultSnapshot,
};
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(test)]
use serde_json::{Value, json};
use std::{io, path::Path};
use time::OffsetDateTime;

pub const LIMITS: KdfLimits = KdfLimits {
    pbkdf2_iterations: 2_000_000,
    argon2_iterations: 10,
    argon2_memory_mib: 256,
    argon2_parallelism: 16,
};

#[derive(Debug)]
pub enum Error {
    Storage,
    StorageBusy,
    Provider(ProviderError),
    Cache(CacheError),
    Key(CacheKeyError),
    Incomplete,
    Lifecycle(provider_lifecycle::Error),
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock => Self::StorageBusy,
            _ => Self::Storage,
        }
    }
}
impl From<ProviderError> for Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}
impl From<CacheError> for Error {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}
impl From<CacheKeyError> for Error {
    fn from(error: CacheKeyError) -> Self {
        Self::Key(error)
    }
}
impl From<provider_lifecycle::Error> for Error {
    fn from(error: provider_lifecycle::Error) -> Self {
        Self::Lifecycle(error)
    }
}

pub(super) struct Source {
    manifest: Option<VaultEnrollment>,
    cache: Option<Vec<u8>>,
    pub(super) revision: PersistedRevision,
}

impl Source {
    pub(super) fn capture(root: &Path) -> Result<Self, Error> {
        let store = store(root)?;
        let encoded = store.load_enrollment()?;
        let cache = store.load()?;
        let mut hash = Context::new(&SHA256);
        for entry in [encoded.as_deref(), cache.as_deref()] {
            hash.update(&(entry.map_or(0, |bytes| bytes.len()) as u64).to_le_bytes());
            hash.update(entry.unwrap_or_default());
        }
        let manifest = encoded
            .map(|bytes| VaultEnrollment::decode(&bytes))
            .transpose()?;
        Ok(Self {
            manifest,
            cache,
            revision: PersistedRevision(hash.finish().as_ref().try_into().unwrap()),
        })
    }

    pub(super) fn binding(&self) -> Option<qm_providers::ProviderBinding> {
        self.manifest
            .as_ref()
            .map(|manifest| manifest.binding().clone())
    }

    pub(super) fn minimum_sync(&self) -> OffsetDateTime {
        self.manifest
            .as_ref()
            .map_or(OffsetDateTime::UNIX_EPOCH, VaultEnrollment::minimum_sync)
    }

    pub(super) fn identity(&self) -> Result<CacheIdentity, Error> {
        let manifest = self.manifest.as_ref().ok_or(Error::Incomplete)?;
        if manifest.phase() != EnrollmentPhase::Ready {
            return Err(Error::Incomplete);
        }
        let device_key = manifest.identity().ok_or(Error::Incomplete)?;
        let sealed = SealedSnapshot::decode(
            self.cache.as_deref().ok_or(CacheError::InvalidFormat)?,
            manifest.binding(),
            &device_key,
        )?;
        if sealed.synchronized_at() < manifest.minimum_sync() {
            return Err(CacheError::Stale.into());
        }
        Ok(CacheIdentity {
            binding: manifest.binding().clone(),
            scope: manifest.scope().into(),
            device_key,
            checkpoint: sealed.checkpoint(),
            synchronized_at: sealed.synchronized_at(),
            revision: self.revision,
        })
    }

    pub(super) fn unlock(self) -> Result<VaultSnapshot, Error> {
        self.open(None)
    }

    pub(super) fn unlock_authenticated(
        self,
        context: &NativeAuthenticationContext<'_>,
    ) -> Result<VaultSnapshot, Error> {
        self.open(Some(context))
    }

    fn open(
        self,
        context: Option<&NativeAuthenticationContext<'_>>,
    ) -> Result<VaultSnapshot, Error> {
        let identity = self.identity()?;
        let sealed = SealedSnapshot::decode(
            self.cache.as_deref().unwrap(),
            &identity.binding,
            &identity.device_key,
        )?;
        let wrapped =
            WrappedCacheKey::from_parts(identity.device_key, sealed.wrapped_key().to_vec())?;
        let device =
            DeviceCacheKey::load(CacheKeyScope::new(&identity.scope)?, identity.device_key)?;
        let key = match context {
            Some(context) => device.unwrap_authenticated(&wrapped, context)?,
            None => device.unwrap(&wrapped)?,
        };
        Ok(key.with_bytes(|key| sealed.open(key, self.minimum_sync()))?)
    }

    pub(super) fn delete_device(&self) -> Result<(), Error> {
        if let Some(manifest) = &self.manifest {
            DeviceCacheKey::discard_for_reenrollment(CacheKeyScope::new(manifest.scope())?)?;
        }
        Ok(())
    }
}

pub fn status(root: &Path, snapshot: Option<&VaultSnapshot>) -> CacheStatus {
    match status_inner(root, snapshot) {
        Ok(value) => value,
        Err(error) => error_reply(error),
    }
}

fn status_inner(root: &Path, snapshot: Option<&VaultSnapshot>) -> Result<CacheStatus, Error> {
    let enrollment = enrollment(&store(root)?)?;
    let state = match (&enrollment, snapshot) {
        (_, Some(_)) => VaultState::OnlineUnlocked,
        (None, None) => VaultState::Unenrolled,
        (Some(enrollment), None) if enrollment.phase() == EnrollmentPhase::Ready => {
            VaultState::Locked
        }
        _ => VaultState::IncompleteEnrollment,
    };
    Ok(CacheStatus {
        kind: StatusKind::VaultStatus,
        state,
        binding: enrollment
            .as_ref()
            .map(|enrollment| enrollment.binding().clone()),
        last_sync: enrollment.as_ref().map(VaultEnrollment::minimum_sync),
        error: None,
        observation: None,
    })
}

pub fn error_reply(error: Error) -> CacheStatus {
    let detail = match &error {
        Error::Cache(cause) => format!("Cache({cause:?})"),
        _ => format!("{error:?}"),
    };
    let state = match &error {
        Error::StorageBusy | Error::Lifecycle(provider_lifecycle::Error::Busy) => VaultState::Busy,
        Error::Lifecycle(
            provider_lifecycle::Error::Superseded | provider_lifecycle::Error::Locked,
        ) => VaultState::Locked,
        Error::Key(CacheKeyError::UserCancelled) => VaultState::Locked,
        Error::Key(CacheKeyError::KeyMissing | CacheKeyError::KeyChanged) => {
            VaultState::KeyInvalidated
        }
        Error::Key(_) => VaultState::KeychainIssue,
        Error::Incomplete => VaultState::IncompleteEnrollment,
        Error::Provider(
            ProviderError::InvalidCredentials
            | ProviderError::ReauthRequired
            | ProviderError::MfaUnsupported,
        ) => VaultState::ReauthRequired,
        Error::Provider(ProviderError::ServerUnavailable) => VaultState::ServerUnavailable,
        Error::Provider(ProviderError::AmbiguousItem) => VaultState::AmbiguousItem,
        Error::Provider(ProviderError::ItemNotFound) => VaultState::ItemNotFound,
        _ => VaultState::IncompatibleCache,
    };
    CacheStatus {
        kind: StatusKind::VaultStatus,
        state,
        binding: None,
        last_sync: None,
        error: Some(detail),
        observation: None,
    }
}

pub(super) struct SealIntent {
    manifest: VaultEnrollment,
}

pub(super) fn begin_persistence(
    root: &Path,
    provider: &ProviderState,
    operation: &mut ProviderOperation,
    snapshot: &VaultSnapshot,
) -> Result<SealIntent, Error> {
    let source = Source::capture(root)?;
    provider.check(operation, source.revision)?;
    let manifest = match source.manifest {
        Some(manifest) => {
            if manifest.binding() != snapshot.binding() {
                return Err(ProviderError::AccountMismatch.into());
            }
            if manifest.phase() == EnrollmentPhase::Intent {
                return Err(Error::Incomplete);
            }
            if snapshot.synchronized_at() < manifest.minimum_sync() {
                return Err(CacheError::Stale.into());
            }
            manifest
        }
        None => {
            let mut bytes = [0; 16];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| Error::Storage)?;
            let scope = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let manifest = VaultEnrollment::begin(snapshot.binding().clone(), scope)?;
            store(root)?.save_enrollment(&manifest.encode()?)?;
            provider.revise_source(operation, Source::capture(root)?.revision)?;
            manifest
        }
    };
    Ok(SealIntent { manifest })
}

struct KeyLease {
    key: Option<DeviceCacheKey>,
    created: bool,
}

impl Drop for KeyLease {
    fn drop(&mut self) {
        if self.created
            && let Some(key) = self.key.take()
        {
            let _ = key.delete();
        }
    }
}

pub(super) struct PreparedCache {
    snapshot: Option<VaultSnapshot>,
    key: KeyLease,
    manifest: VaultEnrollment,
    sealed: SealedSnapshot,
}

impl SealIntent {
    pub(super) fn seal(mut self, snapshot: VaultSnapshot) -> Result<PreparedCache, Error> {
        if self.manifest.binding() != snapshot.binding() {
            return Err(ProviderError::AccountMismatch.into());
        }
        if snapshot.synchronized_at() < self.manifest.minimum_sync() {
            return Err(CacheError::Stale.into());
        }
        let scope = CacheKeyScope::new(self.manifest.scope())?;
        let created = self.manifest.identity().is_none();
        let key = KeyLease {
            key: Some(match self.manifest.identity() {
                Some(pin) => DeviceCacheKey::load(scope, pin)?,
                None => DeviceCacheKey::enroll(scope)?,
            }),
            created,
        };
        let device = key.key.as_ref().unwrap();
        if created {
            self.manifest.record_key(*device.identity())?;
        }
        let (encryption, wrapped) = device.wrap_new_snapshot_key()?;
        let sealed = encryption.with_bytes(|bytes| {
            SealedSnapshot::seal(&snapshot, bytes, *wrapped.identity(), wrapped.ciphertext())
        })?;
        Ok(PreparedCache {
            snapshot: Some(snapshot),
            key,
            manifest: self.manifest,
            sealed,
        })
    }
}

pub(super) fn publish_update(
    root: &Path,
    provider: &mut ProviderState,
    operation: ProviderOperation,
    prepared: &mut PreparedCache,
) -> Result<(), Error> {
    let source = match Source::capture(root) {
        Ok(source) => source,
        Err(error) => {
            provider.release(&operation);
            return Err(error);
        }
    };
    let snapshot = prepared.snapshot.take().unwrap();
    let synchronized_at = snapshot.synchronized_at();
    let update = provider.prepare_update(operation, source.revision, snapshot)?;
    let cache = store(root)?;
    if prepared.key.created {
        cache.save_enrollment(&prepared.manifest.encode()?)?;
        prepared.key.created = false;
    }
    let mut ready = prepared.manifest.clone();
    ready.record_ready(synchronized_at)?;
    cache.save(prepared.sealed.as_bytes())?;
    cache.save_enrollment(&ready.encode()?)?;
    update.install(Source::capture(root)?.identity()?)?;
    Ok(())
}

pub(super) fn finish_unlock(
    root: &Path,
    provider: &mut ProviderState,
    operation: ProviderOperation,
    snapshot: VaultSnapshot,
) -> Result<(), Error> {
    let identity = match Source::capture(root).and_then(|source| source.identity()) {
        Ok(identity) => identity,
        Err(error) => {
            provider.release(&operation);
            return Err(error);
        }
    };
    Ok(provider.finish_unlock(operation, &identity, snapshot)?)
}

pub(super) fn finish_discard(
    root: &Path,
    provider: &mut ProviderState,
    operation: ProviderOperation,
) -> Result<(), Error> {
    let result = (|| {
        provider.check_discard(&operation, Source::capture(root)?.revision)?;
        let cache = store(root)?;
        cache.discard()?;
        cache.discard_enrollment()?;
        Ok(())
    })();
    provider.release(&operation);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use qm_providers::{CredentialField, ProviderBinding};

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
    fn item_selection_errors_do_not_claim_the_cache_is_incompatible() {
        for (error, expected) in [
            (ProviderError::AmbiguousItem, "ambiguous_item"),
            (ProviderError::ItemNotFound, "item_not_found"),
        ] {
            let reply = error_reply(Error::Provider(error));
            assert_eq!(serde_json::to_value(&reply).unwrap()["state"], expected);
            assert_eq!(reply.error.unwrap(), format!("Provider({error:?})"));
        }
    }

    #[test]
    fn status_reports_interrupted_and_ready_enrollments_without_authenticating() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let store = store(&root).unwrap();
        let mut manifest =
            VaultEnrollment::begin(binding(), "0123456789abcdef0123456789abcdef".into()).unwrap();
        store.save_enrollment(&manifest.encode().unwrap()).unwrap();
        assert_eq!(status(&root, None).state, VaultState::IncompleteEnrollment);
        assert!(matches!(
            Source::capture(&root).and_then(Source::unlock),
            Err(Error::Incomplete)
        ));

        manifest.record_key([7; 32]).unwrap();
        manifest
            .record_ready(crate::owner::test_support::wall(10))
            .unwrap();
        store.save_enrollment(&manifest.encode().unwrap()).unwrap();
        store.save(b"invalid dummy encrypted cache").unwrap();
        let before = store.load().unwrap().unwrap();

        assert_eq!(status(&root, None).state, VaultState::Locked);
        assert!(matches!(
            Source::capture(&root).and_then(Source::unlock),
            Err(Error::Cache(CacheError::InvalidFormat))
        ));
        assert_eq!(store.load().unwrap().unwrap(), before);
    }

    #[test]
    fn unentitled_reset_cannot_delete_an_enrollment_or_its_cache() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let store = store(&root).unwrap();
        let manifest =
            VaultEnrollment::begin(binding(), "0123456789abcdef0123456789abcdef".into()).unwrap();
        store.save_enrollment(&manifest.encode().unwrap()).unwrap();
        store.save(b"preserve dummy encrypted cache").unwrap();

        assert!(matches!(
            discard(&root),
            Err(Error::Key(CacheKeyError::InvalidEntitlements))
        ));

        assert!(store.load_enrollment().unwrap().is_some());
        assert_eq!(
            store.load().unwrap().unwrap(),
            b"preserve dummy encrypted cache"
        );
    }

    #[test]
    fn explicit_discard_removes_unenrolled_cache_data_without_key_queries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let store = store(&root).unwrap();
        store.save(b"discard dummy encrypted cache").unwrap();

        discard(&root).unwrap();

        assert_eq!(store.load().unwrap(), None);
        assert_eq!(status(&root, None).state, VaultState::Unenrolled);
    }

    #[test]
    fn persist_rejects_a_backward_sync_before_key_access_or_cache_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let cache = store(&root).unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let mut manifest = VaultEnrollment::begin(
            snapshot.binding().clone(),
            "0123456789abcdef0123456789abcdef".into(),
        )
        .unwrap();
        manifest.record_key([7; 32]).unwrap();
        manifest
            .record_ready(snapshot.synchronized_at() + std::time::Duration::from_secs(1))
            .unwrap();
        cache.save_enrollment(&manifest.encode().unwrap()).unwrap();
        cache
            .save(b"preserve the previous authenticated cache")
            .unwrap();
        let before_enrollment = cache.load_enrollment().unwrap();
        let before_cache = cache.load().unwrap();

        let source = Source::capture(&root).unwrap();
        let mut provider = ProviderState::default();
        let mut operation = provider
            .begin_login(source.binding(), source.minimum_sync(), source.revision)
            .unwrap();
        let result = begin_persistence(&root, &provider, &mut operation, &snapshot);

        assert!(matches!(result, Err(Error::Cache(CacheError::Stale))));
        assert_eq!(cache.load_enrollment().unwrap(), before_enrollment);
        assert_eq!(cache.load().unwrap(), before_cache);
    }

    fn discard(root: &Path) -> Result<(), Error> {
        let source = Source::capture(root)?;
        let mut provider = ProviderState::default();
        let operation = provider.begin_discard(source.revision)?;
        source.delete_device()?;
        finish_discard(root, &mut provider, operation)
    }

    #[test]
    fn a_late_unlock_after_lock_cannot_install_or_change_persisted_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let source = fixture::put(&root, &snapshot);
        let cache = store(&root).unwrap();
        let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());
        let mut provider = ProviderState::default();
        let operation = provider.begin_unlock(source.identity().unwrap()).unwrap();
        provider.lock().unwrap();

        assert!(matches!(
            finish_unlock(&root, &mut provider, operation, snapshot),
            Err(Error::Lifecycle(provider_lifecycle::Error::Superseded))
        ));
        assert!(provider.snapshot().is_none());
        assert_eq!(
            (cache.load().unwrap(), cache.load_enrollment().unwrap()),
            before
        );
    }

    #[test]
    fn late_refresh_after_lock_discard_or_replacement_cannot_publish_any_files() {
        for event in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let snapshot = crate::owner::test_support::vault::snapshot("github-write");
            let source = fixture::put(&root, &snapshot);
            let mut provider = ProviderState::default();
            let identity = source.identity().unwrap();
            let unlock = provider.begin_unlock(identity.clone()).unwrap();
            provider.finish_unlock(unlock, &identity, snapshot).unwrap();
            let (refresh, _) = provider.begin_refresh(&identity).unwrap();
            let refreshed = crate::owner::test_support::vault::snapshot_at(
                "github-write",
                identity.binding.item_id(),
                [9; 16],
                identity.synchronized_at + std::time::Duration::from_secs(1),
            );
            let mut prepared = fixture::prepared(&root, refreshed);
            let cache = store(&root).unwrap();
            let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());
            match event {
                0 => provider.lock().unwrap(),
                1 => assert!(matches!(
                    provider.begin_discard(source.revision),
                    Err(provider_lifecycle::Error::Busy)
                )),
                2 => assert!(matches!(
                    provider.begin_login(source.binding(), source.minimum_sync(), source.revision),
                    Err(provider_lifecycle::Error::Busy)
                )),
                _ => unreachable!(),
            }

            assert!(matches!(
                publish_update(&root, &mut provider, refresh, &mut prepared),
                Err(Error::Lifecycle(provider_lifecycle::Error::Superseded))
            ));
            assert!(provider.snapshot().is_none());
            assert_eq!(
                (cache.load().unwrap(), cache.load_enrollment().unwrap()),
                before
            );
        }
    }

    #[test]
    fn valid_refresh_publishes_a_new_checkpoint_and_preserves_the_selected_binding() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let source = fixture::put(&root, &snapshot);
        let identity = source.identity().unwrap();
        let mut provider = ProviderState::default();
        let unlock = provider.begin_unlock(identity.clone()).unwrap();
        provider.finish_unlock(unlock, &identity, snapshot).unwrap();
        let (refresh, _) = provider.begin_refresh(&identity).unwrap();
        let refreshed = crate::owner::test_support::vault::snapshot_at(
            "github-write",
            identity.binding.item_id(),
            [9; 16],
            identity.synchronized_at + std::time::Duration::from_secs(1),
        );
        let mut prepared = fixture::prepared(&root, refreshed);

        publish_update(&root, &mut provider, refresh, &mut prepared).unwrap();

        let persisted = Source::capture(&root).unwrap();
        let opened = SealedSnapshot::decode(
            persisted.cache.as_deref().unwrap(),
            &identity.binding,
            &identity.device_key,
        )
        .unwrap()
        .open(&[6; 32], identity.synchronized_at)
        .unwrap();
        assert_eq!(opened.checkpoint(), [9; 16]);
        assert_eq!(opened.binding(), &identity.binding);
        assert_eq!(provider.snapshot().unwrap().checkpoint(), [9; 16]);
        assert_eq!(
            persisted.manifest.as_ref().unwrap().identity(),
            Some([7; 32])
        );
        assert_ne!(persisted.revision.0, source.revision.0);
    }

    #[test]
    fn a_changed_device_key_during_refresh_is_rejected_before_cache_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        let source = fixture::put(&root, &snapshot);
        let identity = source.identity().unwrap();
        let mut provider = ProviderState::default();
        let unlock = provider.begin_unlock(identity.clone()).unwrap();
        provider.finish_unlock(unlock, &identity, snapshot).unwrap();
        let (refresh, _) = provider.begin_refresh(&identity).unwrap();
        let refreshed = crate::owner::test_support::vault::snapshot_at(
            "github-write",
            identity.binding.item_id(),
            [9; 16],
            identity.synchronized_at + std::time::Duration::from_secs(1),
        );
        let mut prepared = fixture::prepared(&root, refreshed);
        let cache = store(&root).unwrap();
        let mut enrollment: Value =
            serde_json::from_slice(&cache.load_enrollment().unwrap().unwrap()).unwrap();
        enrollment["identity"] = json!(([8; 32]));
        cache
            .save_enrollment(&serde_json::to_vec(&enrollment).unwrap())
            .unwrap();
        let before = (cache.load().unwrap(), cache.load_enrollment().unwrap());

        assert!(matches!(
            publish_update(&root, &mut provider, refresh, &mut prepared),
            Err(Error::Lifecycle(provider_lifecycle::Error::Changed))
        ));
        assert_eq!(
            (cache.load().unwrap(), cache.load_enrollment().unwrap()),
            before
        );
    }
}

#[cfg(test)]
pub(in crate::owner) mod fixture {
    use super::*;

    pub(in crate::owner) fn open(source: Source) -> VaultSnapshot {
        let identity = source.identity().unwrap();
        SealedSnapshot::decode(
            source.cache.as_deref().unwrap(),
            &identity.binding,
            &identity.device_key,
        )
        .unwrap()
        .open(&[6; 32], source.minimum_sync())
        .unwrap()
    }

    pub(in crate::owner) fn put(root: &Path, snapshot: &VaultSnapshot) -> Source {
        let mut manifest = VaultEnrollment::begin(
            snapshot.binding().clone(),
            "0123456789abcdef0123456789abcdef".into(),
        )
        .unwrap();
        manifest.record_key([7; 32]).unwrap();
        manifest.record_ready(snapshot.synchronized_at()).unwrap();
        let sealed = SealedSnapshot::seal(snapshot, &[6; 32], [7; 32], &[8; 113]).unwrap();
        let cache = store(root).unwrap();
        cache.save_enrollment(&manifest.encode().unwrap()).unwrap();
        cache.save(sealed.as_bytes()).unwrap();
        Source::capture(root).unwrap()
    }

    pub(in crate::owner) fn prepared(root: &Path, snapshot: VaultSnapshot) -> PreparedCache {
        PreparedCache {
            manifest: Source::capture(root).unwrap().manifest.unwrap(),
            sealed: SealedSnapshot::seal(&snapshot, &[6; 32], [7; 32], &[8; 113]).unwrap(),
            snapshot: Some(snapshot),
            key: KeyLease {
                key: None,
                created: false,
            },
        }
    }
}
