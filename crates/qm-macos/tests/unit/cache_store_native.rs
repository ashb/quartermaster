use super::*;
use crate::cache_store::CacheStore;
use core_foundation::base::TCFType;
use core_foundation::url::CFURL;
use std::os::unix::fs::PermissionsExt;

#[test]
fn actual_cache_replacements_remain_excluded_from_time_machine() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().canonicalize().unwrap();
    let store = CacheStore::open(&path, TimeMachineExclusion).unwrap();

    for bytes in [
        b"first dummy encrypted snapshot".as_slice(),
        b"second dummy encrypted snapshot".as_slice(),
    ] {
        store.save(bytes).unwrap();
        for (path, is_directory) in [(&path, true), (&path.join("vault.cache"), false)] {
            let url = CFURL::from_path(path, is_directory).unwrap();
            assert_ne!(
                unsafe { CSBackupIsItemExcluded(url.as_concrete_TypeRef(), std::ptr::null_mut()) },
                0
            );
        }
    }
}
