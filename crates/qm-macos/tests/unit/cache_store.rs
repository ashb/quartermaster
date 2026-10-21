use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct BackupFixture {
    calls: AtomicUsize,
    fail_on: AtomicUsize,
}

impl BackupExclusion for BackupFixture {
    fn exclude_and_verify(&self, _file: &File) -> io::Result<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_on.load(Ordering::SeqCst) {
            return Err(io::Error::other("dummy backup exclusion failed"));
        }
        Ok(())
    }
}

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn replacement_is_private_complete_and_reapplies_backup_exclusion() {
    let directory = directory();
    let store = CacheStore::open(
        &directory.path().canonicalize().unwrap(),
        BackupFixture::default(),
    )
    .unwrap();
    assert_eq!(store.load().unwrap(), None);

    store.save(b"dummy encrypted snapshot one").unwrap();
    store.save(b"dummy encrypted snapshot two").unwrap();

    assert_eq!(
        store.load().unwrap().unwrap(),
        b"dummy encrypted snapshot two"
    );
    assert_eq!(
        fs::metadata(directory.path().join("vault.cache"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(store.backup.calls.load(Ordering::SeqCst), 6);
    fs::write(directory.path().join("unrelated"), b"preserve").unwrap();
    store.discard().unwrap();
    assert_eq!(store.load().unwrap(), None);
    assert_eq!(
        fs::read(directory.path().join("unrelated")).unwrap(),
        b"preserve"
    );
}

#[test]
fn backup_failure_before_or_after_publish_leaves_a_complete_snapshot() {
    for after_publish in [false, true] {
        let directory = directory();
        let store = CacheStore::open(
            &directory.path().canonicalize().unwrap(),
            BackupFixture::default(),
        )
        .unwrap();
        store.save(b"old complete encrypted snapshot").unwrap();
        store
            .backup
            .fail_on
            .store(if after_publish { 6 } else { 4 }, Ordering::SeqCst);

        assert!(store.save(b"new complete encrypted snapshot").is_err());

        let expected = if after_publish {
            b"new complete encrypted snapshot"
        } else {
            b"old complete encrypted snapshot"
        };
        assert_eq!(store.load().unwrap().unwrap(), expected);
        assert!(!directory.path().join(".vault.pending").exists());
    }
}

#[test]
fn symlinks_hardlinks_permissions_and_oversized_files_are_rejected() {
    let directory = directory();
    let root = directory.path().canonicalize().unwrap();
    let store = CacheStore::open(&root, BackupFixture::default()).unwrap();
    let outside = root.join("outside");
    fs::write(&outside, b"preserve").unwrap();
    symlink(&outside, root.join("vault.cache")).unwrap();
    assert!(store.load().is_err());
    assert!(store.save(b"must not overwrite").is_err());
    assert!(store.discard().is_err());
    fs::remove_file(root.join("vault.cache")).unwrap();
    fs::hard_link(&outside, root.join("vault.cache")).unwrap();
    assert!(store.load().is_err());
    fs::remove_file(root.join("vault.cache")).unwrap();
    fs::write(root.join("vault.cache"), b"not private").unwrap();
    fs::set_permissions(root.join("vault.cache"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load().is_err());
    fs::set_permissions(root.join("vault.cache"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.join("vault.cache"), vec![0; 262145]).unwrap();
    assert!(store.load().is_err());
    assert!(store.save(&[]).is_err());
    assert!(store.save(&vec![0; 262145]).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"preserve");
    symlink(&root, root.join("alias")).unwrap();
    assert!(CacheStore::open(&root.join("alias"), BackupFixture::default()).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(CacheStore::open(&root, BackupFixture::default()).is_err());
}

#[test]
fn interrupted_staging_is_replaced_and_staging_symlinks_are_preserved_and_rejected() {
    let directory = directory();
    let root = directory.path().canonicalize().unwrap();
    let store = CacheStore::open(&root, BackupFixture::default()).unwrap();
    store.save(b"old complete snapshot").unwrap();
    let staging = root.join(".vault.pending");
    fs::write(&staging, b"incomplete encrypted staging").unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
    store.save(b"new complete snapshot").unwrap();
    assert_eq!(store.load().unwrap().unwrap(), b"new complete snapshot");

    let outside = root.join("unrelated");
    fs::write(&outside, b"preserve").unwrap();
    symlink(&outside, &staging).unwrap();
    assert!(store.save(b"must not publish").is_err());
    assert_eq!(store.load().unwrap().unwrap(), b"new complete snapshot");
    assert!(
        fs::symlink_metadata(&staging)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"preserve");
}

#[test]
fn concurrent_writers_publish_complete_snapshots_under_the_same_lock() {
    let directory = directory();
    let root = directory.path().canonicalize().unwrap();
    let first = CacheStore::open(&root, BackupFixture::default()).unwrap();
    let second = CacheStore::open(&root, BackupFixture::default()).unwrap();
    let reader = CacheStore::open(&root, BackupFixture::default()).unwrap();
    let writer = |store: CacheStore<BackupFixture>, byte: u8| {
        std::thread::spawn(move || {
            for _ in 0..10 {
                store.save(&vec![byte; 8192]).unwrap();
            }
        })
    };
    let first = writer(first, 1);
    let second = writer(second, 2);
    for _ in 0..10 {
        if let Some(bytes) = reader.load().unwrap() {
            assert_eq!(bytes.len(), 8192);
            assert!(bytes.iter().all(|byte| *byte == bytes[0]));
            assert!([1, 2].contains(&bytes[0]));
        }
    }
    first.join().unwrap();
    second.join().unwrap();
}

#[test]
fn enrollment_manifest_is_private_atomic_and_separate_from_the_encrypted_snapshot() {
    let directory = directory();
    let root = directory.path().canonicalize().unwrap();
    let store = CacheStore::open(&root, BackupFixture::default()).unwrap();
    store.save(b"dummy encrypted snapshot").unwrap();
    assert_eq!(store.load_enrollment().unwrap(), None);

    store.save_enrollment(br#"{"phase":"intent"}"#).unwrap();
    store.save_enrollment(br#"{"phase":"ready"}"#).unwrap();

    assert_eq!(
        store.load_enrollment().unwrap().unwrap(),
        br#"{"phase":"ready"}"#
    );
    assert_eq!(
        fs::metadata(root.join("enrollment.json")).unwrap().mode() & 0o777,
        0o600
    );
    store.discard_enrollment().unwrap();
    assert_eq!(store.load_enrollment().unwrap(), None);
    assert_eq!(store.load().unwrap().unwrap(), b"dummy encrypted snapshot");
}
