//! Credential boundaries for the prototype broker. Native presence and IPC integration
//! are still pending; callers of the host APIs must already be trusted broker code.
#![forbid(unsafe_code)]

mod approval;
mod credential;
mod kdf;

pub use approval::{ApprovalSession, ApprovedRequest, PendingApproval, RequestBinding};
pub use credential::{ApprovedCredentialData, EncryptedCredential, VaultKeys};
pub use kdf::{KdfAlgorithm, KdfLimits, KdfParameters, ValidatedKdfParameters, VaultIdentity};
