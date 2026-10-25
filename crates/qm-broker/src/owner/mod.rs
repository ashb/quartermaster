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
        runtime::serve(options).map_err(|error| ServiceError::Runtime(std::io::Error::other(error)))
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
mod protocol;
#[cfg(any(target_os = "macos", test))]
mod provider_lifecycle;
#[cfg(test)]
mod test_support {
    use crate::owner::request;
    use std::io::Cursor;

    pub(crate) mod approval;
    #[cfg(unix)]
    pub(crate) mod github;
    pub(crate) mod vault;

    pub(crate) fn policy_bytes(expires: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "writes": "allow",
            "grants": [{
                "id": "0123456789abcdef0123456789abcdef",
                "uid": 501,
                "codeHash": "11".repeat(20),
                "action": "readIssue",
                "repository": "quartermaster/demo",
                "role": "github-read",
                "expiresUnix": expires
            }]
        }))
        .unwrap()
    }

    pub(crate) fn read_request() -> request::FrozenOperation {
        request::read(&mut Cursor::new(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n")).unwrap()
    }

    pub(crate) fn close_request() -> request::FrozenOperation {
        request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap()
    }

    pub(crate) fn wall(seconds: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    pub(crate) fn principal(session: [u8; 16]) -> crate::owner::identity::VerifiedPrincipal {
        crate::owner::identity::VerifiedPrincipal::fixture(501, "11".repeat(20), session)
    }
}
#[cfg(all(unix, any(target_os = "macos", test)))]
mod transport;
