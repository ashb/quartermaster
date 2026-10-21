use std::ffi::CString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::CacheKeyScope;

pub(super) struct EnrollmentLock {
    _file: File,
}

impl EnrollmentLock {
    // Retain the lock file after closing it so concurrent processes always lock the same inode.
    pub(super) fn acquire(directory: &Path, scope: &CacheKeyScope) -> io::Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let metadata = directory.metadata()?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other("unsafe enrolment lock directory"));
        }
        let name = CString::new(format!("cache-key.{}.lock", scope.enrollment)).unwrap();
        let file = crate::unix_file::open_at(&directory, &name, libc::O_CREAT | libc::O_RDWR)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::other("unsafe enrolment lock file"));
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/cache_key_lock.rs"]
mod tests;
