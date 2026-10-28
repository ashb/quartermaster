use std::{
    ffi::{CStr, OsString},
    fs, io,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

pub(super) struct Paths {
    pub(super) backend: PathBuf,
    pub(super) socket: PathBuf,
}

impl Paths {
    pub(super) fn discover() -> io::Result<Self> {
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        let app = app_for_executable(&executable)?;
        let home = unsafe {
            let user = libc::getpwuid(libc::geteuid());
            if user.is_null() {
                return Err(io::Error::other("user home unavailable"));
            }
            OsString::from_vec(CStr::from_ptr((*user).pw_dir).to_bytes().to_vec())
        };
        Ok(Self {
            backend: app
                .join("Contents/Helpers/QuartermasterBackend.app/Contents/MacOS/quartermasterd"),
            socket: PathBuf::from(home)
                .join("Library/Application Support/Quartermaster/Development/github.sock"),
        })
    }
}

fn app_for_executable(executable: &Path) -> io::Result<&Path> {
    let app = executable
        .ancestors()
        .nth(3)
        .filter(|p| p.extension().is_some_and(|s| s == "app"))
        .filter(|p| p.join("Contents/MacOS/qm") == executable)
        .ok_or_else(|| {
            io::Error::other("run qm from Quartermaster.app/Contents/MacOS (a symlink is fine)")
        })?;
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_cli_in_the_outer_app_selects_the_bundled_backend() {
        assert_eq!(
            app_for_executable(Path::new(
                "/Applications/Quartermaster.app/Contents/MacOS/qm"
            ))
            .unwrap(),
            Path::new("/Applications/Quartermaster.app")
        );
        for path in [
            "/usr/local/bin/qm",
            "/Applications/Quartermaster.app/Other/qm",
            "/Applications/Quartermaster.app/Contents/MacOS/other",
        ] {
            assert!(app_for_executable(Path::new(path)).is_err());
        }
    }
}
