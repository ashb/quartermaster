//! Credential use is private to the service owner.
//!
//! ```no_run
//! let options = qm_broker::ServiceOptions {
//!     storage_root: "/private/user-state".into(),
//!     bundle_root: "/Applications/Quartermaster.app".into(),
//! };
//! qm_broker::serve(options)?;
//! # Ok::<(), qm_broker::ServiceError>(())
//! ```
//!
//! ```compile_fail
//! use qm_broker::owner;
//! ```
//!
//! ```compile_fail
//! use qm_broker::{ApprovalSession, VaultSnapshot, VaultKeys, SealedSnapshot};
//! ```
//!
//! ```compile_fail
//! let options = qm_broker::ServiceOptions {
//!     storage_root: "/private/user-state".into(),
//!     bundle_root: "/Applications/Quartermaster.app".into(),
//!     approval_key: vec![4; 65],
//! };
//! ```
//!
//! ```compile_fail
//! qm_broker::serve(|plaintext: &[u8]| plaintext.to_vec());
//! ```

use std::{fmt, io, path::PathBuf};

mod owner;
mod platform;
mod wire_limits;

pub struct ServiceOptions {
    pub storage_root: PathBuf,
    pub bundle_root: PathBuf,
}

#[derive(Debug)]
pub enum ServiceError {
    UnsafeStorage,
    InvalidBundle,
    UnsupportedPlatform,
    Runtime(io::Error),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeStorage => formatter.write_str("unsafe service storage"),
            Self::InvalidBundle => {
                formatter.write_str("bundle does not contain the running backend")
            }
            Self::UnsupportedPlatform => formatter.write_str("service requires macOS"),
            Self::Runtime(error) => write!(formatter, "backend service failed: {error}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    Unenrolled,
    SettingsImportRequired,
    IncompleteEnrollment,
    Locked,
    OnlineUnlocked,
    Busy,
    ReauthRequired,
    IncompatibleCache,
    KeyInvalidated,
    KeychainIssue,
    ServerUnavailable,
    AmbiguousItem,
    ItemNotFound,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
enum StatusKind {
    VaultStatus,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum StatusObservation {
    PersistedCache,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStatus {
    kind: StatusKind,
    state: VaultState,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<qm_providers::ProviderBinding>,
    #[serde(
        with = "time::serde::timestamp::option",
        skip_serializing_if = "Option::is_none"
    )]
    last_sync: Option<time::OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<StatusObservation>,
}

pub fn serve(options: ServiceOptions) -> Result<(), ServiceError> {
    owner::serve(options)
}

pub fn persisted_status(options: ServiceOptions) -> Result<CacheStatus, ServiceError> {
    owner::persisted_status(options)
}
