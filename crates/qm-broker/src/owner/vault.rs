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
    Provider(ProviderError),
    Cache(CacheError),
    Key(CacheKeyError),
    Incomplete,
    Lifecycle(provider_lifecycle::Error),
}
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Storage
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
        Error::Lifecycle(provider_lifecycle::Error::Busy) => VaultState::Busy,
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
#[path = "../../tests/unit/vault.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/support/persisted_vault.rs"]
pub(in crate::owner) mod fixture;
