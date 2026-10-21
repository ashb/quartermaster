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
mod tests {
    use super::*;

    #[test]
    fn enrollment_scope_rejects_tags_that_could_select_another_key() {
        for invalid in [
            "",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdefx",
            "dev.quartermaster.approval.debug.v1",
            "../../approval-key",
        ] {
            assert!(matches!(
                CacheKeyScope::new(invalid),
                Err(CacheKeyError::InvalidScope)
            ));
        }
        let scope = CacheKeyScope::new("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            scope.label(),
            "Quartermaster development cache 0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn wrapped_snapshot_key_requires_the_fixed_ecies_envelope_length() {
        for length in [0, 32, 65, 112, 114, 8192] {
            assert!(matches!(
                WrappedCacheKey::from_parts([1; 32], vec![0; length]),
                Err(CacheKeyError::InvalidWrappedKey)
            ));
        }
        let wrapped = WrappedCacheKey::from_parts([1; 32], vec![0x42; 113]).unwrap();
        assert_eq!(wrapped.identity(), &[1; 32]);
        assert_eq!(wrapped.ciphertext(), &[0x42; 113]);
    }
}
