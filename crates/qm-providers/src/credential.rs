use qm_types::CredentialError;
use rbw::cipherstring::CipherString;
use ring::digest::{SHA256, digest};

/// Structurally validated ciphertext; authentication happens during decryption.
pub struct EncryptedCredential {
    cipher: CipherString,
    encoded: String,
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
            encoded: encoded.to_owned(),
            digest: digest(&SHA256, encoded.as_bytes())
                .as_ref()
                .try_into()
                .unwrap(),
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn encoded(&self) -> &str {
        &self.encoded
    }

    pub(crate) fn authenticate(&self, keys: &rbw::locked::Keys) -> Result<(), CredentialError> {
        let CipherString::Symmetric {
            iv,
            ciphertext,
            mac: Some(mac),
        } = &self.cipher
        else {
            return Err(CredentialError::InvalidCiphertext);
        };
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, keys.mac_key());
        let mut authenticated = Vec::with_capacity(iv.len() + ciphertext.len());
        authenticated.extend_from_slice(iv);
        authenticated.extend_from_slice(ciphertext);
        ring::hmac::verify(&key, &authenticated, mac).map_err(|_| CredentialError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CIPHER: &str = include_str!("../tests/fixtures/dummy.type2");

    #[test]
    fn malformed_ciphertexts_and_missing_macs_are_rejected_before_decryption() {
        for input in ["", "!.bad", "2.bad", "7.bad", "4.AAAA", "2.!!!|!!!|!!!"] {
            assert!(EncryptedCredential::parse(input).is_err());
        }
        assert!(matches!(
            EncryptedCredential::parse(&"2".repeat(8193)),
            Err(CredentialError::InvalidCiphertext)
        ));
        let without_mac = CIPHER.trim().rsplit_once('|').unwrap().0;
        assert!(matches!(
            EncryptedCredential::parse(without_mac),
            Err(CredentialError::UnauthenticatedCiphertext)
        ));
    }
}
