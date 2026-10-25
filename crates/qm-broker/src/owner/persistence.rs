use super::vault::Error;
use qm_macos::cache_store::{CacheStore, TimeMachineExclusion};
use qm_providers::VaultEnrollment;
use std::path::Path;

pub(super) fn store(root: &Path) -> Result<CacheStore<TimeMachineExclusion>, Error> {
    Ok(CacheStore::open(&root.join("vault"), TimeMachineExclusion)?)
}

pub(super) fn enrollment(
    store: &CacheStore<TimeMachineExclusion>,
) -> Result<Option<VaultEnrollment>, Error> {
    store
        .load_enrollment()?
        .map(|bytes| VaultEnrollment::decode(&bytes).map_err(Error::from))
        .transpose()
}
