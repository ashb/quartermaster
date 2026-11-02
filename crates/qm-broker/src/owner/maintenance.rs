use super::settings;
use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

pub(super) fn reset_settings(root: &Path) -> io::Result<()> {
    let _lock = backend_lock(root)?;
    let store = settings::Store::native()
        .map_err(|_| io::Error::other("protected settings unavailable"))?;
    store
        .reset()
        .map_err(|_| io::Error::other("could not clear protected settings"))
}

fn backend_lock(root: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("backend.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_cannot_run_while_the_backend_holds_its_lock() {
        let root = tempfile::tempdir().unwrap();
        let backend = backend_lock(root.path()).unwrap();
        assert_eq!(
            backend_lock(root.path()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(backend);
        assert!(backend_lock(root.path()).is_ok());
    }

    #[test]
    fn reset_does_not_follow_a_symlinked_backend_lock() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("backend.lock")).unwrap();
        assert!(backend_lock(root.path()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
    }
}
