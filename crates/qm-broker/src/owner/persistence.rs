use super::policy::{AuthorizationError, Policy};
use super::vault::Error;
use qm_macos::cache_store::{CacheStore, TimeMachineExclusion};
use qm_providers::VaultEnrollment;
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(super) fn policy(root: &Path) -> Result<Policy, AuthorizationError> {
    let policy = Policy::default();
    match private_configuration(root, "github.json")? {
        Some(bytes) => {
            let config = super::github::configuration::GitHubConfig::decode(&bytes)
                .map_err(|_| AuthorizationError::InvalidPolicy)?;
            Ok(policy.with_github(config))
        }
        None => Ok(policy),
    }
}

fn private_configuration(root: &Path, name: &str) -> Result<Option<Vec<u8>>, AuthorizationError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root.join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AuthorizationError::InvalidPolicy),
    };
    let metadata = file
        .metadata()
        .map_err(|_| AuthorizationError::InvalidPolicy)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 65536
    {
        return Err(AuthorizationError::InvalidPolicy);
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorizationError::InvalidPolicy)?;
    if bytes.len() > 65536 {
        return Err(AuthorizationError::InvalidPolicy);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
#[path = "../../tests/unit/persistence.rs"]
mod tests;

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
