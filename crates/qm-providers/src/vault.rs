use crate::{EncryptedCredential, KdfAlgorithm, KdfLimits, KdfParameters};
use rbw::cipherstring::CipherString;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use time::OffsetDateTime;
use zeroize::Zeroizing;

mod cache;
pub use cache::{CacheError, SealedSnapshot};
mod lifecycle;
pub use lifecycle::{EnrollmentPhase, VaultEnrollment};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    InvalidBinding,
    ServerUnavailable,
    InvalidCredentials,
    ReauthRequired,
    MfaUnsupported,
    OrganizationUnsupported,
    CipherUnsupported,
    ItemNotFound,
    AmbiguousItem,
    AccountMismatch,
    MasterPasswordRepromptRequired,
    CacheIncompatible,
    InvalidKdf,
    InvalidResponse,
    KeyChanged,
    UserCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialField {
    LoginPassword,
    HiddenField(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderBinding {
    server: String,
    account_id: String,
    email: String,
    item_id: String,
    field: CredentialField,
    role: String,
}

impl<'de> Deserialize<'de> for ProviderBinding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            server: String,
            account_id: String,
            email: String,
            item_id: String,
            field: CredentialField,
            role: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            &fields.server,
            &fields.account_id,
            &fields.email,
            &fields.item_id,
            fields.field,
            &fields.role,
        )
        .map_err(|_| serde::de::Error::custom("invalid_provider_binding"))
    }
}

impl ProviderBinding {
    pub fn new(
        server: &str,
        account_id: &str,
        email: &str,
        item_id: &str,
        field: CredentialField,
        role: &str,
    ) -> Result<Self, ProviderError> {
        let url = reqwest::Url::parse(server).map_err(|_| ProviderError::InvalidBinding)?;
        let email = email.trim().to_lowercase();
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || email.len() > 254
            || !email.contains('@')
            || email.chars().any(char::is_whitespace)
            || role.is_empty()
            || role.len() > 64
            || !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || matches!(&field, CredentialField::HiddenField(name) if name.is_empty() || name.len() > 256 || name.contains('\0'))
        {
            return Err(ProviderError::InvalidBinding);
        }
        let uuid = |id: &str| {
            uuid::Uuid::parse_str(id)
                .map(|id| id.hyphenated().to_string())
                .map_err(|_| ProviderError::InvalidBinding)
        };
        Ok(Self {
            server: url.as_str().trim_end_matches('/').to_owned(),
            account_id: uuid(account_id)?,
            email,
            item_id: uuid(item_id)?,
            field,
            role: role.to_owned(),
        })
    }

    pub fn server(&self) -> &str {
        &self.server
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn item_id(&self) -> &str {
        &self.item_id
    }
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn field(&self) -> &CredentialField {
        &self.field
    }
}

/// Trusted broker interface. Unlocking a snapshot grants no operation authority.
pub trait VaultProvider {
    fn login(
        &self,
        password: &[u8],
    ) -> impl std::future::Future<Output = Result<VaultSnapshot, ProviderError>>;
    fn sync(
        &self,
        snapshot: &VaultSnapshot,
    ) -> impl std::future::Future<Output = Result<VaultSnapshot, ProviderError>>;
}

pub struct RbwProvider {
    binding: ProviderBinding,
    limits: KdfLimits,
    client: rbw::api::Client,
    http: reqwest::Client,
}

#[derive(Clone, Copy)]
enum Selection {
    Pinned,
    DiscoverAccount,
    DiscoverSoleLogin,
}

/// Selected ciphertext and private provider state. Persist only through `SealedSnapshot`.
pub struct VaultSnapshot {
    binding: ProviderBinding,
    credential: EncryptedCredential,
    selected_key: Zeroizing<Vec<u8>>,
    vault_key: Zeroizing<Vec<u8>>,
    protected_key: String,
    kdf: KdfParameters,
    refresh_token: Zeroizing<String>,
    checkpoint: [u8; 16],
    synchronized_at: OffsetDateTime,
}

impl VaultSnapshot {
    pub fn credential_digest(&self) -> [u8; 32] {
        self.credential.digest()
    }

    pub fn synchronized_at(&self) -> OffsetDateTime {
        self.synchronized_at
    }

    pub fn binding(&self) -> &ProviderBinding {
        &self.binding
    }
    pub fn checkpoint(&self) -> [u8; 16] {
        self.checkpoint
    }

    /// Trusted credential-owner primitive. The owner must authorize this exact
    /// credential before acquisition and recheck authority at final admission.
    /// The returned buffer must stay inside its concrete credential-use adapter.
    pub fn decrypt_selected_for_owner(&self) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        decrypt_value(self.credential.encoded(), &locked_keys(&self.selected_key)?)
    }
}

impl RbwProvider {
    pub async fn enroll_sole_login(
        server: &str,
        email: &str,
        password: &[u8],
        limits: KdfLimits,
        role: &str,
    ) -> Result<VaultSnapshot, ProviderError> {
        let unknown = uuid::Uuid::nil().to_string();
        let binding = ProviderBinding::new(
            server,
            &unknown,
            email,
            &unknown,
            CredentialField::LoginPassword,
            role,
        )?;
        Self::new(binding, limits)?.discover(password).await
    }

    async fn discover(&self, password: &[u8]) -> Result<VaultSnapshot, ProviderError> {
        self.login_selected(password, Selection::DiscoverSoleLogin)
            .await
    }

    pub async fn enroll_selected_login(
        server: &str,
        email: &str,
        item_id: &str,
        password: &[u8],
        limits: KdfLimits,
        role: &str,
    ) -> Result<VaultSnapshot, ProviderError> {
        let binding = ProviderBinding::new(
            server,
            &uuid::Uuid::nil().to_string(),
            email,
            item_id,
            CredentialField::LoginPassword,
            role,
        )?;
        Self::new(binding, limits)?
            .login_selected(password, Selection::DiscoverAccount)
            .await
    }

    pub fn new(binding: ProviderBinding, limits: KdfLimits) -> Result<Self, ProviderError> {
        let client = rbw::api::Client::new(
            &format!("{}/api", binding.server),
            &format!("{}/identity", binding.server),
            &binding.server,
            None,
        );
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ProviderError::ServerUnavailable)?;
        Ok(Self {
            binding,
            limits,
            client,
            http,
        })
    }

    async fn prelogin(&self) -> Result<KdfParameters, ProviderError> {
        #[derive(Deserialize)]
        struct Prelogin {
            #[serde(alias = "Kdf")]
            kdf: rbw::api::KdfType,
            #[serde(rename = "kdfIterations", alias = "KdfIterations")]
            iterations: u32,
            #[serde(rename = "kdfMemory", alias = "KdfMemory")]
            memory_mib: Option<u32>,
            #[serde(rename = "kdfParallelism", alias = "KdfParallelism")]
            parallelism: Option<u32>,
        }
        let response = self
            .http
            .post(format!(
                "{}/identity/accounts/prelogin",
                self.binding.server
            ))
            .json(&serde_json::json!({"email": self.binding.email}))
            .send()
            .await
            .map_err(|_| ProviderError::ServerUnavailable)?;
        check_status(response.status(), false)?;
        let prelogin: Prelogin = bounded_json(response).await?;
        Ok(KdfParameters {
            algorithm: match prelogin.kdf {
                rbw::api::KdfType::Pbkdf2 => KdfAlgorithm::Pbkdf2,
                rbw::api::KdfType::Argon2id => KdfAlgorithm::Argon2id,
            },
            iterations: prelogin.iterations,
            memory_mib: prelogin.memory_mib,
            parallelism: prelogin.parallelism,
        })
    }

    async fn snapshot(
        &self,
        access: &str,
        refresh_token: Zeroizing<String>,
        protected_key: String,
        vault_key: Zeroizing<Vec<u8>>,
        kdf: KdfParameters,
        selection: Selection,
    ) -> Result<VaultSnapshot, ProviderError> {
        #[derive(Deserialize)]
        struct Profile {
            #[serde(alias = "Id")]
            id: String,
            #[serde(alias = "Email")]
            email: String,
        }
        let response = self
            .http
            .get(format!("{}/api/accounts/profile", self.binding.server))
            .bearer_auth(access)
            .send()
            .await
            .map_err(|_| ProviderError::ServerUnavailable)?;
        check_status(response.status(), false)?;
        let profile: Profile = bounded_json(response).await?;
        if (matches!(selection, Selection::Pinned) && profile.id != self.binding.account_id)
            || profile.email.trim().to_lowercase() != self.binding.email
        {
            return Err(ProviderError::AccountMismatch);
        }
        let (sync_key, _, _, entries) = self
            .client
            .sync(access)
            .await
            .map_err(|error| map_rbw(error, false))?;
        if sync_key != protected_key {
            return Err(ProviderError::KeyChanged);
        }
        let mut binding = self.binding.clone();
        if !matches!(selection, Selection::Pinned) {
            binding.account_id = uuid::Uuid::parse_str(&profile.id)
                .map_err(|_| ProviderError::InvalidResponse)?
                .to_string();
        }
        if matches!(selection, Selection::DiscoverSoleLogin) {
            let sole = match entries.as_slice() {
                [] => return Err(ProviderError::ItemNotFound),
                [entry] => entry,
                _ => return Err(ProviderError::AmbiguousItem),
            };
            binding.item_id = uuid::Uuid::parse_str(&sole.id)
                .map_err(|_| ProviderError::InvalidResponse)?
                .to_string();
        }
        let mut selected = entries
            .into_iter()
            .filter(|entry| entry.id == binding.item_id);
        let entry = selected.next().ok_or(ProviderError::ItemNotFound)?;
        if selected.next().is_some() {
            return Err(ProviderError::AmbiguousItem);
        }
        if entry.org_id.is_some() {
            return Err(ProviderError::OrganizationUnsupported);
        }
        if entry.master_password_reprompt() {
            return Err(ProviderError::MasterPasswordRepromptRequired);
        }
        let vault_keys = locked_keys(&vault_key)?;
        let selected_key = match &entry.key {
            Some(key) => decrypt_key(key, &vault_keys)?,
            None => Zeroizing::new(vault_key.to_vec()),
        };
        let item_keys = locked_keys(&selected_key)?;
        let cipher = match &self.binding.field {
            CredentialField::LoginPassword => match entry.data {
                rbw::db::EntryData::Login {
                    password: Some(password),
                    ..
                } => password,
                _ => return Err(ProviderError::ItemNotFound),
            },
            CredentialField::HiddenField(name) => {
                let mut value = None;
                for field in entry.fields {
                    let Some(encoded_name) = field.name else {
                        continue;
                    };
                    let decoded = decrypt_value(&encoded_name, &item_keys)?;
                    if decoded.as_slice() != name.as_bytes() {
                        continue;
                    }
                    if value.is_some() {
                        return Err(ProviderError::AmbiguousItem);
                    }
                    if field.ty != Some(rbw::api::FieldType::Hidden) || field.linked_id.is_some() {
                        return Err(ProviderError::CipherUnsupported);
                    }
                    value = Some(field.value.ok_or(ProviderError::ItemNotFound)?);
                }
                value.ok_or(ProviderError::ItemNotFound)?
            }
        };
        let credential =
            EncryptedCredential::parse(&cipher).map_err(|_| ProviderError::CipherUnsupported)?;
        credential
            .authenticate(&item_keys)
            .map_err(|_| ProviderError::InvalidResponse)?;
        let mut checkpoint = [0; 16];
        SystemRandom::new()
            .fill(&mut checkpoint)
            .map_err(|_| ProviderError::InvalidResponse)?;
        let synchronized_at = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| ProviderError::InvalidResponse)?;
        Ok(VaultSnapshot {
            binding,
            credential,
            selected_key,
            vault_key,
            protected_key,
            kdf,
            refresh_token,
            checkpoint,
            synchronized_at,
        })
    }
    async fn login_selected(
        &self,
        password: &[u8],
        selection: Selection,
    ) -> Result<VaultSnapshot, ProviderError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let parameters = self.prelogin().await?;
            let checked = parameters
                .validate(&self.limits)
                .map_err(|_| ProviderError::InvalidKdf)?;
            let identity = checked
                .derive(&self.binding.email, password)
                .map_err(|_| ProviderError::InvalidKdf)?;
            let mut device_id = [0; 16];
            SystemRandom::new()
                .fill(&mut device_id)
                .map_err(|_| ProviderError::InvalidResponse)?;
            let (access, refresh, protected_key) = self
                .client
                .login(
                    &self.binding.email,
                    None,
                    &uuid::Uuid::from_bytes(device_id).to_string(),
                    identity.password_hash(),
                    None,
                    None,
                )
                .await
                .map_err(|error| map_rbw(error, true))?;
            let access = Zeroizing::new(access);
            let refresh = Zeroizing::new(refresh);
            if access.is_empty()
                || refresh.is_empty()
                || access.len() > 16384
                || refresh.len() > 16384
            {
                return Err(ProviderError::InvalidResponse);
            }
            let vault_key = decrypt_key(&protected_key, identity.keys())?;
            self.snapshot(
                &access,
                refresh,
                protected_key,
                vault_key,
                parameters,
                selection,
            )
            .await
        })
        .await
        .map_err(|_| ProviderError::ServerUnavailable)?
    }
}

impl VaultProvider for RbwProvider {
    async fn login(&self, password: &[u8]) -> Result<VaultSnapshot, ProviderError> {
        self.login_selected(password, Selection::Pinned).await
    }

    async fn sync(&self, snapshot: &VaultSnapshot) -> Result<VaultSnapshot, ProviderError> {
        if self.binding != snapshot.binding {
            return Err(ProviderError::AccountMismatch);
        }
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            #[derive(Deserialize)]
            struct Refreshed {
                access_token: String,
                refresh_token: Option<String>,
            }
            let response = self
                .http
                .post(format!("{}/identity/connect/token", self.binding.server))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", "cli"),
                    ("refresh_token", &snapshot.refresh_token),
                ])
                .send()
                .await
                .map_err(|_| ProviderError::ServerUnavailable)?;
            check_status(response.status(), true)?;
            let refreshed: Refreshed = bounded_json(response).await?;
            let access = Zeroizing::new(refreshed.access_token);
            let refresh = Zeroizing::new(
                refreshed
                    .refresh_token
                    .unwrap_or_else(|| snapshot.refresh_token.to_string()),
            );
            if access.is_empty()
                || refresh.is_empty()
                || access.len() > 16384
                || refresh.len() > 16384
            {
                return Err(ProviderError::InvalidResponse);
            }
            self.snapshot(
                &access,
                refresh,
                snapshot.protected_key.clone(),
                Zeroizing::new(snapshot.vault_key.to_vec()),
                snapshot.kdf,
                Selection::Pinned,
            )
            .await
        })
        .await
        .map_err(|_| ProviderError::ServerUnavailable)?
    }
}

fn locked_keys(bytes: &[u8]) -> Result<rbw::locked::Keys, ProviderError> {
    if bytes.len() != 64 {
        return Err(ProviderError::CacheIncompatible);
    }
    let mut locked = rbw::locked::Vec::new();
    locked.extend(bytes.iter().copied());
    Ok(rbw::locked::Keys::new(locked))
}

fn decrypt_value(
    encoded: &str,
    keys: &rbw::locked::Keys,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    EncryptedCredential::parse(encoded).map_err(|_| ProviderError::CipherUnsupported)?;
    CipherString::new(encoded)
        .map_err(|_| ProviderError::CipherUnsupported)?
        .decrypt_symmetric(keys, None)
        .map(Zeroizing::new)
        .map_err(|_| ProviderError::InvalidResponse)
}

fn decrypt_key(
    encoded: &str,
    keys: &rbw::locked::Keys,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let bytes = decrypt_value(encoded, keys)?;
    if bytes.len() != 64 {
        return Err(ProviderError::CacheIncompatible);
    }
    Ok(bytes)
}

fn map_rbw(error: rbw::error::Error, login: bool) -> ProviderError {
    match error {
        rbw::error::Error::IncorrectPassword { .. } | rbw::error::Error::IncorrectApiKey => {
            ProviderError::InvalidCredentials
        }
        rbw::error::Error::TwoFactorRequired { .. } | rbw::error::Error::RegistrationRequired => {
            ProviderError::MfaUnsupported
        }
        rbw::error::Error::RequestUnauthorized => {
            if login {
                ProviderError::InvalidCredentials
            } else {
                ProviderError::ReauthRequired
            }
        }
        rbw::error::Error::Reqwest { .. } | rbw::error::Error::CreateReqwestClient { .. } => {
            ProviderError::ServerUnavailable
        }
        rbw::error::Error::RequestFailed { status } if status >= 500 || status == 429 => {
            ProviderError::ServerUnavailable
        }
        rbw::error::Error::RequestFailed {
            status: 400 | 401 | 403,
        } => {
            if login {
                ProviderError::InvalidCredentials
            } else {
                ProviderError::ReauthRequired
            }
        }
        rbw::error::Error::InvalidKdfType { .. } => ProviderError::InvalidKdf,
        _ => ProviderError::InvalidResponse,
    }
}

fn check_status(status: reqwest::StatusCode, refresh: bool) -> Result<(), ProviderError> {
    match status.as_u16() {
        200 => Ok(()),
        401 | 403 => Err(ProviderError::ReauthRequired),
        400 if refresh => Err(ProviderError::ReauthRequired),
        429 | 500..=599 => Err(ProviderError::ServerUnavailable),
        _ => Err(ProviderError::InvalidResponse),
    }
}

async fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, ProviderError> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ProviderError::ServerUnavailable)?
    {
        if bytes.len() + chunk.len() > 65536 {
            return Err(ProviderError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::InvalidResponse)
}

#[cfg(test)]
#[path = "../tests/unit/vault.rs"]
mod tests;
