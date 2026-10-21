//! Low-level provider and cryptographic primitives for the trusted credential owner.
//! Application authorization lives in qm-broker; these APIs do not authenticate
//! enrolment, native presence, caller identity or policy on their own.
#![forbid(unsafe_code)]

mod approval;
mod credential;
mod kdf;
mod vault;

pub use approval::{
    ApprovalSession, ApprovedRequest, AuthenticatedIntent, PendingApproval, PendingIntent,
    RequestBinding,
};
pub use credential::EncryptedCredential;
pub use kdf::{KdfAlgorithm, KdfLimits, KdfParameters, ValidatedKdfParameters, VaultIdentity};
pub use vault::{
    CacheError, CredentialField, EnrollmentPhase, ProviderBinding, ProviderError, RbwProvider,
    SealedSnapshot, VaultEnrollment, VaultProvider, VaultSnapshot,
};
