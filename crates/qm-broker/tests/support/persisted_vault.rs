use super::*;

pub(in crate::owner) fn open(source: Source) -> VaultSnapshot {
    let identity = source.identity().unwrap();
    SealedSnapshot::decode(
        source.cache.as_deref().unwrap(),
        &identity.binding,
        &identity.device_key,
    )
    .unwrap()
    .open(&[6; 32], source.minimum_sync())
    .unwrap()
}

pub(in crate::owner) fn put(root: &Path, snapshot: &VaultSnapshot) -> Source {
    let mut manifest = VaultEnrollment::begin(
        snapshot.binding().clone(),
        "0123456789abcdef0123456789abcdef".into(),
    )
    .unwrap();
    manifest.record_key([7; 32]).unwrap();
    manifest.record_ready(snapshot.synchronized_at()).unwrap();
    let sealed = SealedSnapshot::seal(snapshot, &[6; 32], [7; 32], &[8; 113]).unwrap();
    let cache = store(root).unwrap();
    cache.save_enrollment(&manifest.encode().unwrap()).unwrap();
    cache.save(sealed.as_bytes()).unwrap();
    Source::capture(root).unwrap()
}

pub(in crate::owner) fn prepared(root: &Path, snapshot: VaultSnapshot) -> PreparedCache {
    PreparedCache {
        manifest: Source::capture(root).unwrap().manifest.unwrap(),
        sealed: SealedSnapshot::seal(&snapshot, &[6; 32], [7; 32], &[8; 113]).unwrap(),
        snapshot: Some(snapshot),
        key: KeyLease {
            key: None,
            created: false,
        },
    }
}
