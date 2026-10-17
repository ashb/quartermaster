use qm_types::CredentialError;
use rbw::api::KdfType;
use rbw::identity::Identity;
use rbw::locked::Password;

#[derive(Debug, Clone, Copy)]
pub enum KdfAlgorithm {
    Pbkdf2,
    Argon2id,
}

#[derive(Debug, Clone, Copy)]
pub struct KdfLimits {
    pub pbkdf2_iterations: u32,
    pub argon2_iterations: u32,
    pub argon2_memory_mib: u32,
    pub argon2_parallelism: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct KdfParameters {
    pub algorithm: KdfAlgorithm,
    pub iterations: u32,
    pub memory_mib: Option<u32>,
    pub parallelism: Option<u32>,
}

/// Parameters admitted under broker-owned resource limits. Fields and construction
/// are private so later derivation cannot mutate or bypass the validation.
///
/// ```compile_fail
/// fn forge(parameters: qm_providers::KdfParameters) {
///     let checked = qm_providers::ValidatedKdfParameters { parameters };
/// }
/// ```
pub struct ValidatedKdfParameters {
    parameters: KdfParameters,
}

impl KdfParameters {
    pub fn validate(self, limits: &KdfLimits) -> Result<ValidatedKdfParameters, CredentialError> {
        let max_iterations = match self.algorithm {
            KdfAlgorithm::Pbkdf2 => limits.pbkdf2_iterations,
            KdfAlgorithm::Argon2id => limits.argon2_iterations,
        };
        if self.iterations == 0 || self.iterations > max_iterations {
            return Err(CredentialError::InvalidKdfParameters);
        }
        match self.algorithm {
            KdfAlgorithm::Pbkdf2 => {
                if self.memory_mib.is_some() || self.parallelism.is_some() {
                    return Err(CredentialError::InvalidKdfParameters);
                }
            }
            KdfAlgorithm::Argon2id => {
                let (Some(memory), Some(parallelism)) = (self.memory_mib, self.parallelism) else {
                    return Err(CredentialError::InvalidKdfParameters);
                };
                let memory_kib = memory
                    .checked_mul(1024)
                    .ok_or(CredentialError::InvalidKdfParameters)?;
                let minimum_memory = parallelism
                    .checked_mul(8)
                    .ok_or(CredentialError::InvalidKdfParameters)?;
                if memory == 0
                    || parallelism == 0
                    || parallelism > 0x00ff_ffff
                    || memory_kib < minimum_memory
                    || memory > limits.argon2_memory_mib
                    || parallelism > limits.argon2_parallelism
                {
                    return Err(CredentialError::InvalidKdfParameters);
                }
            }
        }
        Ok(ValidatedKdfParameters { parameters: self })
    }
}

pub struct VaultIdentity {
    identity: Identity,
}

impl VaultIdentity {
    pub fn email(&self) -> &str {
        &self.identity.email
    }
}

impl ValidatedKdfParameters {
    pub fn derive(&self, email: &str, password: &[u8]) -> Result<VaultIdentity, CredentialError> {
        let mut locked = rbw::locked::Vec::new();
        locked.extend(password.iter().copied());
        let password = Password::new(locked);
        let parameters = self.parameters;
        let algorithm = match parameters.algorithm {
            KdfAlgorithm::Pbkdf2 => KdfType::Pbkdf2,
            KdfAlgorithm::Argon2id => KdfType::Argon2id,
        };
        let identity = Identity::new(
            email,
            &password,
            algorithm,
            parameters.iterations,
            parameters.memory_mib,
            parameters.parallelism,
        )
        .map_err(|_| CredentialError::KeyDerivationFailed)?;
        Ok(VaultIdentity { identity })
    }
}

#[cfg(test)]
#[path = "../tests/unit/kdf.rs"]
mod tests;
