use super::BackupExclusion;
use core_foundation::base::TCFType;
use core_foundation::url::{CFURL, CFURLRef};
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub struct TimeMachineExclusion;

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn CSBackupSetItemExcluded(item: CFURLRef, exclude: u8, by_path: u8) -> i32;
    fn CSBackupIsItemExcluded(item: CFURLRef, by_path: *mut u8) -> u8;
}

impl BackupExclusion for TimeMachineExclusion {
    fn exclude_and_verify(&self, file: &File) -> io::Result<()> {
        let mut path = [0u8; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let path = CStr::from_bytes_until_nul(&path)
            .map_err(|_| io::Error::other("invalid cache path"))?;
        let path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
        let url = CFURL::from_path(path, file.metadata()?.is_dir())
            .ok_or_else(|| io::Error::other("invalid backup URL"))?;
        let status = unsafe { CSBackupSetItemExcluded(url.as_concrete_TypeRef(), 1, 0) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if unsafe { CSBackupIsItemExcluded(url.as_concrete_TypeRef(), std::ptr::null_mut()) } == 0 {
            return Err(io::Error::other("backup exclusion verification failed"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/cache_store_native.rs"]
mod tests;
