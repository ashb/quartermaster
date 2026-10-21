use qm_providers::{CredentialField, ProviderBinding, SealedSnapshot, VaultSnapshot};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde_json::json;

pub(crate) fn snapshot(role: &str) -> VaultSnapshot {
    snapshot_with(role, "22222222-2222-4222-8222-222222222222", [3; 16])
}

pub(crate) fn snapshot_with(role: &str, item: &str, checkpoint: [u8; 16]) -> VaultSnapshot {
    snapshot_at(role, item, checkpoint, super::wall(1_792_483_200))
}

pub(crate) fn snapshot_at(
    role: &str,
    item: &str,
    checkpoint: [u8; 16],
    synchronized_at: time::OffsetDateTime,
) -> VaultSnapshot {
    let binding = ProviderBinding::new(
        "https://vault.example.invalid",
        "11111111-1111-4111-8111-111111111111",
        "dummy@example.invalid",
        item,
        CredentialField::LoginPassword,
        role,
    )
    .unwrap();
    let header = serde_json::to_vec(&json!({
        "schema": 1, "rbw_version": "1.15.0", "binding": binding,
        "device_key": ([7; 32]), "wrapped_key": vec![8; 113],
        "checkpoint": checkpoint, "synchronized_at": synchronized_at.unix_timestamp(),
        "kdf": {"algorithm":"Pbkdf2", "iterations":1, "memory_mib":null, "parallelism":null}
    }))
    .unwrap();
    let cipher = include_str!("../../../../qm-providers/tests/fixtures/dummy.type2").trim();
    let mut payload = serde_json::to_vec(&json!({
        "cipher": cipher, "selected_key": (0..64).collect::<Vec<u8>>(),
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
    SealedSnapshot::decode(&bytes, &binding, &[7; 32])
        .unwrap()
        .open(&[6; 32], time::OffsetDateTime::UNIX_EPOCH)
        .unwrap()
}

pub(crate) fn install(
    provider: &mut crate::owner::provider_lifecycle::ProviderState,
    snapshot: VaultSnapshot,
) {
    use crate::owner::provider_lifecycle::{CacheIdentity, PersistedRevision};
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

pub(crate) fn selection(snapshot: &VaultSnapshot) -> crate::owner::dispatch::CredentialSelection {
    crate::owner::dispatch::CredentialSelection::at_generation(snapshot, Default::default())
}
