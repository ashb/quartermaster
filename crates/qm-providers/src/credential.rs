use crate::approval::Authority;
use crate::{ApprovalSession, ApprovedRequest, RequestBinding};
use qm_types::CredentialError;
use rbw::cipherstring::CipherString;
use ring::digest::{SHA256, digest};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

/// Structurally validated ciphertext; authentication happens during decryption.
pub struct EncryptedCredential {
    cipher: CipherString,
    digest: [u8; 32],
}

impl EncryptedCredential {
    pub fn parse(encoded: &str) -> Result<Self, CredentialError> {
        if encoded.len() > 8192 {
            return Err(CredentialError::InvalidCiphertext);
        }
        if !encoded.starts_with("2.") {
            return Err(CredentialError::UnsupportedCipherType);
        }
        let cipher = CipherString::new(encoded).map_err(|_| CredentialError::InvalidCiphertext)?;
        let CipherString::Symmetric {
            iv,
            ciphertext,
            mac,
        } = &cipher
        else {
            return Err(CredentialError::UnsupportedCipherType);
        };
        let Some(mac) = mac else {
            return Err(CredentialError::UnauthenticatedCiphertext);
        };
        if iv.len() != 16
            || mac.len() != 32
            || ciphertext.is_empty()
            || ciphertext.len() > 4096
            || !ciphertext.len().is_multiple_of(16)
        {
            return Err(CredentialError::InvalidCiphertext);
        }
        Ok(Self {
            cipher,
            digest: digest(&SHA256, encoded.as_bytes())
                .as_ref()
                .try_into()
                .unwrap(),
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub struct VaultKeys {
    keys: rbw::locked::Keys,
    authority: Arc<Authority>,
}

impl VaultKeys {
    pub fn restore(session: &ApprovalSession, bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != 64 {
            return Err(CredentialError::InvalidKeyLength);
        }
        let mut locked = rbw::locked::Vec::new();
        locked.extend(bytes.iter().copied());
        Ok(Self {
            keys: rbw::locked::Keys::new(locked),
            authority: session.authority(),
        })
    }

    pub fn decrypt(
        &self,
        approval: ApprovedRequest,
        encrypted: &EncryptedCredential,
    ) -> Result<ApprovedCredentialData, CredentialError> {
        approval.check()?;
        if !approval.belongs_to(&self.authority)
            || approval.binding().credential_digest != encrypted.digest
        {
            return Err(CredentialError::BindingMismatch);
        }
        let plaintext = Zeroizing::new(
            encrypted
                .cipher
                .decrypt_symmetric(&self.keys, None)
                .map_err(|_| CredentialError::DecryptionFailed)?,
        );
        Ok(ApprovedCredentialData {
            approval,
            plaintext,
        })
    }
}

/// Plaintext is private, zeroized on drop, and accessible only through consuming
/// dispatch. Dispatch is the revocation admission point; a later revocation cannot
/// retract a request already admitted to the trusted sink.
///
/// ```compile_fail
/// fn send_twice(data: qm_providers::ApprovedCredentialData) {
///     data.dispatch(|_, _| ()).unwrap();
///     data.dispatch(|_, _| ()).unwrap();
/// }
/// ```
pub struct ApprovedCredentialData {
    approval: ApprovedRequest,
    plaintext: Zeroizing<Vec<u8>>,
}

impl ApprovedCredentialData {
    /// The trusted sink must dispatch the bound request to its verified recipient.
    /// Rust cannot prevent that sink from copying or leaking the supplied bytes.
    pub fn dispatch<R>(
        self,
        send: impl FnOnce(&RequestBinding, &[u8]) -> R,
    ) -> Result<R, CredentialError> {
        self.dispatch_at(Instant::now, send)
    }

    fn dispatch_at<R>(
        self,
        clock: impl FnOnce() -> Instant,
        send: impl FnOnce(&RequestBinding, &[u8]) -> R,
    ) -> Result<R, CredentialError> {
        self.approval.check_at(clock)?;
        Ok(send(self.approval.binding(), &self.plaintext))
    }
}

#[cfg(test)]
#[path = "../tests/unit/credential.rs"]
mod tests;
