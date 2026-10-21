use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};

pub(crate) fn open_at(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let create_or_open = flags & libc::O_CREAT != 0 && flags & libc::O_EXCL == 0;
    // Darwin's combined openat(O_CREAT) can return ENOENT during concurrent first creation.
    let first_flags = if create_or_open {
        flags | libc::O_EXCL
    } else {
        flags
    };
    let mut descriptor =
        unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), first_flags, 0o600) };
    if descriptor < 0
        && create_or_open
        && io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists
    {
        descriptor =
            unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags & !libc::O_CREAT) };
    }
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
