use crate::owner::provider_lifecycle::{CacheIdentity, PersistedRevision};
use crate::owner::settings::{Manager, Proposal, ProviderPin, Revision, Store};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_providers::{CredentialField, ProviderBinding, SealedSnapshot, VaultSnapshot};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde_json::json;

pub(crate) fn snapshot(role: &str) -> CredentialFixture {
    snapshot_with(role, "22222222-2222-4222-8222-222222222222", [3; 16])
}

pub(crate) fn snapshot_with(role: &str, item: &str, checkpoint: [u8; 16]) -> CredentialFixture {
    snapshot_at(role, item, checkpoint, super::wall(1_792_483_200))
}

pub(crate) fn snapshot_at(
    role: &str,
    item: &str,
    checkpoint: [u8; 16],
    synchronized_at: time::OffsetDateTime,
) -> CredentialFixture {
    snapshot_for_account(
        role,
        item,
        checkpoint,
        synchronized_at,
        "11111111-1111-4111-8111-111111111111",
    )
}

pub(crate) fn snapshot_for_account(
    role: &str,
    item: &str,
    checkpoint: [u8; 16],
    synchronized_at: time::OffsetDateTime,
    account: &str,
) -> CredentialFixture {
    let credential = ProviderBinding::new(
        "https://vault.example.invalid",
        account,
        "dummy@example.invalid",
        item,
        CredentialField::LoginPassword,
        role,
    )
    .unwrap();
    catalogue_at(credential, &[item], checkpoint, synchronized_at)
}

pub(crate) fn catalogue(credential: ProviderBinding, items: &[&str]) -> CredentialFixture {
    catalogue_at(credential, items, [3; 16], super::wall(1_792_483_200))
}

fn catalogue_at(
    credential: ProviderBinding,
    items: &[&str],
    checkpoint: [u8; 16],
    synchronized_at: time::OffsetDateTime,
) -> CredentialFixture {
    let binding = credential.account();
    let header = serde_json::to_vec(&json!({
        "schema": 2, "rbw_version": "1.15.0", "binding": binding,
        "device_key": ([7; 32]), "wrapped_key": vec![8; 113],
        "checkpoint": checkpoint, "synchronized_at": synchronized_at.unix_timestamp(),
        "kdf": {"algorithm":"Pbkdf2", "iterations":1, "memory_mib":null, "parallelism":null}
    }))
    .unwrap();
    let cipher = include_str!("../../../../qm-providers/tests/fixtures/dummy.type2").trim();
    let entries: Vec<_> = items
        .iter()
        .map(|item| {
            json!({"id":item,"org_id":null,"folder":null,"folder_id":null,"name":cipher,
            "data":{"Login":{"username":null,"password":cipher,"totp":null,"uris":[]}},
            "fields":[],"notes":null,"history":[],"key":null,"master_password_reprompt":0})
        })
        .collect();
    let mut payload = serde_json::to_vec(&json!({
        "entries": entries,
        "vault_key": (0..64).collect::<Vec<u8>>(), "protected_key": cipher,
        "refresh_token": "dummy-refresh"
    }))
    .unwrap();
    let mut bytes = b"QMVCACHE".to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&header);
    let mut nonce = [0; 12];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let encryption = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[6; 32]).unwrap());
    encryption
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&bytes),
            &mut payload,
        )
        .unwrap();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&payload);
    let snapshot = SealedSnapshot::decode(&bytes, &binding, &[7; 32])
        .unwrap()
        .open(&[6; 32], time::OffsetDateTime::UNIX_EPOCH)
        .unwrap();
    CredentialFixture {
        snapshot,
        credential,
    }
}

pub(crate) fn install(
    provider: &mut crate::owner::provider_lifecycle::ProviderState,
    snapshot: impl Into<VaultSnapshot>,
) {
    let snapshot = snapshot.into();
    let identity = CacheIdentity {
        binding: snapshot.binding().clone(),
        scope: "0123456789abcdef0123456789abcdef".into(),
        device_key: [7; 32],
        checkpoint: snapshot.checkpoint(),
        synchronized_at: snapshot.synchronized_at(),
        revision: PersistedRevision([8; 32]),
    };
    let operation = provider.begin_unlock(identity.clone()).unwrap();
    provider
        .finish_unlock(operation, &identity, snapshot)
        .unwrap();
}

pub(crate) fn selection(
    snapshot: &CredentialFixture,
) -> crate::owner::dispatch::CredentialSelection {
    crate::owner::dispatch::CredentialSelection::at_generation(
        snapshot,
        &snapshot.credential,
        Default::default(),
    )
    .unwrap()
}

pub(crate) fn binding(role: &str, item: &str) -> ProviderBinding {
    ProviderBinding::new(
        "https://vault.example.invalid",
        "11111111-1111-4111-8111-111111111111",
        "dummy@example.invalid",
        item,
        CredentialField::LoginPassword,
        role,
    )
    .unwrap()
}

pub(crate) fn manager<C>() -> crate::owner::settings::Manager<C> {
    manager_with_settings(crate::owner::settings::Settings::decode(br#"{"github":null,"githubCredential":{"itemId":"22222222-2222-4222-8222-222222222222"},"mutations":"requireApproval"}"#).unwrap())
}

pub(crate) fn manager_with_settings<C>(
    settings: crate::owner::settings::Settings,
) -> crate::owner::settings::Manager<C> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let store = Store::memory();
    let mut manager: Manager = store.register(key.public_key().as_ref()).unwrap();
    let review = manager
        .prepare(
            7,
            [1; 16],
            Proposal {
                revision: Revision(0),
                settings,
                provider: Some(ProviderPin {
                    slot: "legacy".into(),
                    binding: binding("github-write", "22222222-2222-4222-8222-222222222222")
                        .account(),
                    scope: "0123456789abcdef0123456789abcdef".into(),
                    device_key: [7; 32],
                }),
            },
            1000.into(),
            (),
        )
        .unwrap();
    let challenge = manager
        .authenticate(&review.id, 7, 1001.into(), 1002.into())
        .unwrap();
    let signature = key
        .sign(&rng, &BASE64.decode(challenge.bytes).unwrap())
        .unwrap();
    let verified = manager
        .approve(&review.id, 7, signature.as_ref(), 1003.into())
        .unwrap();
    let admission = manager.admit(verified, 1004.into()).unwrap();
    manager.finish(store.publish(admission)).unwrap();
    store.load().unwrap().unwrap()
}

pub(crate) struct CredentialFixture {
    pub(crate) snapshot: VaultSnapshot,
    pub(crate) credential: ProviderBinding,
}

impl std::ops::Deref for CredentialFixture {
    type Target = VaultSnapshot;
    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl From<CredentialFixture> for VaultSnapshot {
    fn from(fixture: CredentialFixture) -> Self {
        fixture.snapshot
    }
}

pub(crate) fn write_policy_bytes(expires: u64) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&super::policy_bytes(expires)).unwrap();
    value["grants"][0]["role"] = "github-write".into();
    serde_json::to_vec(&value).unwrap()
}
