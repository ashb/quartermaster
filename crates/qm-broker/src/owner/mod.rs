#[cfg(target_os = "macos")]
mod persistence;
#[cfg(any(target_os = "macos", test))]
mod request;
#[cfg(any(target_os = "macos", test))]
mod review;
#[cfg(target_os = "macos")]
mod runtime;
#[cfg(target_os = "macos")]
mod vault;

use crate::{CacheStatus, ServiceError, ServiceOptions};

#[cfg(any(target_os = "macos", test))]
mod github;

#[cfg(target_os = "macos")]
fn validate(options: &ServiceOptions) -> Result<(), ServiceError> {
    use std::{fs, os::unix::fs::MetadataExt};

    if !cfg!(debug_assertions) {
        return Err(ServiceError::Runtime(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "only the development service is implemented",
        )));
    }
    let storage =
        fs::symlink_metadata(&options.storage_root).map_err(|_| ServiceError::UnsafeStorage)?;
    if !storage.is_dir()
        || storage.uid() != unsafe { libc::geteuid() }
        || storage.mode() & 0o077 != 0
    {
        return Err(ServiceError::UnsafeStorage);
    }
    let executable = fs::canonicalize(std::env::current_exe().map_err(ServiceError::Runtime)?)
        .map_err(ServiceError::Runtime)?;
    let bundle = fs::canonicalize(&options.bundle_root).map_err(|_| ServiceError::InvalidBundle)?;
    let expected =
        bundle.join("Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd");
    if bundle.extension().is_none_or(|value| value != "app") || executable != expected {
        return Err(ServiceError::InvalidBundle);
    }
    Ok(())
}

pub(super) fn serve(options: ServiceOptions) -> Result<(), ServiceError> {
    #[cfg(target_os = "macos")]
    {
        validate(&options)?;
        runtime::serve(options).map_err(ServiceError::Runtime)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = options;
        Err(ServiceError::UnsupportedPlatform)
    }
}

pub(super) fn persisted_status(options: ServiceOptions) -> Result<CacheStatus, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        validate(&options)?;
        let mut status = vault::status(&options.storage_root, None);
        status.observation = Some(crate::StatusObservation::PersistedCache);
        Ok(status)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = options;
        Err(ServiceError::UnsupportedPlatform)
    }
}
#[cfg(any(target_os = "macos", test))]
mod deadline;
#[cfg(any(target_os = "macos", test))]
mod dispatch;
#[cfg(any(target_os = "macos", test))]
mod execution;
#[cfg(any(target_os = "macos", test))]
mod grant;
#[cfg(any(target_os = "macos", test))]
mod identity;
#[cfg(any(target_os = "macos", test))]
mod operation;
#[cfg(any(target_os = "macos", test))]
mod policy;
#[cfg(any(target_os = "macos", test))]
mod provider_lifecycle;
#[cfg(test)]
#[path = "../../tests/support/mod.rs"]
mod test_support;
#[cfg(all(unix, any(target_os = "macos", test)))]
mod transport;
