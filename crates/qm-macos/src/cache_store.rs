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
#[path = "../tests/unit/cache_store.rs"]
mod tests;
