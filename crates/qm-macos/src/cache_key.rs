use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CacheKeyError {
    InvalidScope,
    InvalidWrappedKey,
    InvalidKey,
    AlreadyEnrolled,
    KeyMissing,
    KeyChanged,
    AmbiguousKey,
    UserCancelled,
    InteractionUnavailable,
    InvalidEntitlements,
    RandomnessUnavailable,
    Storage {
        operation: &'static str,
        code: Option<i32>,
    },
    Security {
        operation: &'static str,
        code: i64,
    },
}

impl fmt::Display for CacheKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CacheKeyError {}

pub struct CacheKeyScope {
    enrollment: String,
}

impl CacheKeyScope {
    pub fn new(enrollment_id: &str) -> Result<Self, CacheKeyError> {
        if enrollment_id.len() != 32
            || !enrollment_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CacheKeyError::InvalidScope);
        }
        Ok(Self {
            enrollment: enrollment_id.into(),
        })
    }

    pub fn label(&self) -> String {
        format!("Quartermaster development cache {}", self.enrollment)
    }
}

pub struct WrappedCacheKey {
    identity: [u8; 32],
    ciphertext: Vec<u8>,
}

#[cfg(unix)]
mod lock;

impl WrappedCacheKey {
    pub fn from_parts(identity: [u8; 32], ciphertext: Vec<u8>) -> Result<Self, CacheKeyError> {
        if ciphertext.len() != 113 {
            return Err(CacheKeyError::InvalidWrappedKey);
        }
        Ok(Self {
            identity,
            ciphertext,
        })
    }

    pub fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[cfg(target_os = "macos")]
mod native;
#[cfg(target_os = "macos")]
pub use native::{DeviceCacheKey, NativeAuthenticationContext, SnapshotKey};

#[cfg(test)]
#[path = "../tests/unit/cache_key.rs"]
mod tests;
