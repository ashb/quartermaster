use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const MAX_CACHE: usize = 262144;
const CACHE: &CStr = c"vault.cache";
const PENDING: &CStr = c".vault.pending";
const ENROLLMENT: &CStr = c"enrollment.json";
const ENROLLMENT_PENDING: &CStr = c".enrollment.pending";

pub trait BackupExclusion {
    fn exclude_and_verify(&self, file: &File) -> io::Result<()>;
}

pub struct CacheStore<B> {
    directory: File,
    backup: B,
}

impl<B: BackupExclusion> CacheStore<B> {
    pub fn save_enrollment(&self, bytes: &[u8]) -> io::Result<()> {
        self.save_entry(ENROLLMENT, ENROLLMENT_PENDING, bytes, 16384)
    }

    pub fn load_enrollment(&self) -> io::Result<Option<Vec<u8>>> {
        self.load_entry(ENROLLMENT, 16384)
    }
    pub fn discard_enrollment(&self) -> io::Result<()> {
        let _lock = self.lock()?;
        self.remove(ENROLLMENT)?;
        self.remove(ENROLLMENT_PENDING)?;
        self.directory.sync_all()
    }

    pub fn open(directory: &Path, backup: B) -> io::Result<Self> {
        let directory = open_directory(directory)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other("unsafe cache directory"));
        }
        Ok(Self { directory, backup })
    }

    pub fn save(&self, bytes: &[u8]) -> io::Result<()> {
        self.save_entry(CACHE, PENDING, bytes, MAX_CACHE)
    }

    fn save_entry(
        &self,
        target: &CStr,
        staging: &CStr,
        bytes: &[u8],
        limit: usize,
    ) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > limit {
            return Err(io::Error::other("invalid cache size"));
        }
        let _lock = self.lock()?;
        self.open_file(target, libc::O_RDONLY)?;
        self.remove(staging)?;
        let mut file = self
            .open_file(staging, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?
            .ok_or_else(|| io::Error::other("missing cache staging file"))?;
        let mut cleanup = PendingFile {
            directory: &self.directory,
            name: staging,
            published: false,
        };
        file.write_all(bytes)?;
        file.sync_all()?;
        self.backup.exclude_and_verify(&self.directory)?;
        self.backup.exclude_and_verify(&file)?;
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                staging.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        cleanup.published = true;
        self.backup.exclude_and_verify(&file)?;
        file.sync_all()?;
        self.directory.sync_all()
    }

    pub fn load(&self) -> io::Result<Option<Vec<u8>>> {
        self.load_entry(CACHE, MAX_CACHE)
    }

    fn load_entry(&self, name: &CStr, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let _lock = self.lock()?;
        let Some(file) = self.open_file(name, libc::O_RDONLY)? else {
            return Ok(None);
        };
        if file.metadata()?.len() > limit as u64 {
            return Err(io::Error::other("invalid cache size"));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > limit {
            return Err(io::Error::other("invalid cache size"));
        }
        Ok(Some(bytes))
    }

    pub fn discard(&self) -> io::Result<()> {
        let _lock = self.lock()?;
        self.remove(CACHE)?;
        self.remove(PENDING)?;
        self.directory.sync_all()
    }

    fn lock(&self) -> io::Result<File> {
        let file = self
            .open_file(c"vault.lock", libc::O_RDWR | libc::O_CREAT)?
            .ok_or_else(|| io::Error::other("missing cache lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    fn open_file(&self, name: &CStr, flags: i32) -> io::Result<Option<File>> {
        let file = match crate::unix_file::open_at(&self.directory, name, flags) {
            Ok(file) => file,
            Err(error) if flags & libc::O_CREAT == 0 && error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::other("unsafe cache file"));
        }
        Ok(Some(file))
    }

    fn remove(&self, name: &CStr) -> io::Result<()> {
        if self.open_file(name, libc::O_RDONLY)?.is_some()
            && unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

struct PendingFile<'a> {
    directory: &'a File,
    name: &'a CStr,
    published: bool,
}

impl Drop for PendingFile<'_> {
    fn drop(&mut self) {
        if !self.published {
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("cache directory must be absolute"));
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| io::Error::other("invalid cache path"))?
            }
            _ => return Err(io::Error::other("invalid cache path")),
        };
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(io::Error::last_os_error());
            }
            descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(directory)
}

#[cfg(target_os = "macos")]
mod backup;
#[cfg(target_os = "macos")]
pub use backup::TimeMachineExclusion;

#[cfg(test)]
mod tests {
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
}
