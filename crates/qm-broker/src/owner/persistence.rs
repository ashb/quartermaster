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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn github_configuration_loading_rejects_unsafe_files_instead_of_ignoring_them() {
        for case in 0..6 {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("github.json");
            let bytes = match case {
                2 => b"{\"mode\":\"automatic\"}".to_vec(),
                3 => vec![b' '; 65537],
                _ => br#"{"version":1,"mode":"github","repositories":[]}"#.to_vec(),
            };
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            match case {
                0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                1 => {
                    let target = root.path().join("target");
                    fs::rename(&path, &target).unwrap();
                    std::os::unix::fs::symlink(target, &path).unwrap();
                }
                4 => fs::hard_link(&path, root.path().join("other-link")).unwrap(),
                5 => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => {}
            }
            assert!(policy(root.path()).is_err(), "case {case}");
        }
    }
}
