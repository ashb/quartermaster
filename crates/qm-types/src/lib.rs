pub const PROTECTED_RECORD_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    InvalidKeyLength,
    InvalidCiphertext,
    UnsupportedCipherType,
    UnauthenticatedCiphertext,
    DecryptionFailed,
    InvalidKdfParameters,
    KeyDerivationFailed,
    InvalidApprovalKey,
    InvalidApprovalSignature,
    MissingPresence,
    AlreadyAuthenticated,
    PendingExpired,
    DispatchExpired,
    BindingMismatch,
    SessionRevoked,
    PolicyChanged,
    StateUnavailable,
    RandomnessUnavailable,
}

mod timestamp;
pub use timestamp::MonotonicTimestamp;
