use serde_json::json;
use std::{
    ffi::CStr,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
};

const SERVICE: &str = "dev.quartermaster.debug.backend";

fn failure(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

struct Paths {
    app: PathBuf,
    root: PathBuf,
    executable: PathBuf,
}
impl Paths {
    fn options(&self) -> qm_broker::ServiceOptions {
        qm_broker::ServiceOptions {
            storage_root: self.root.clone(),
            bundle_root: self.app.clone(),
        }
    }

    fn discover() -> io::Result<Self> {
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        let app = executable
            .ancestors()
            .nth(6)
            .filter(|p| p.extension().is_some_and(|s| s == "app"))
            .ok_or_else(|| failure("run the backend embedded in Quartermaster.app"))?
            .to_owned();
        let home = unsafe {
            let user = libc::getpwuid(libc::geteuid());
            if user.is_null() {
                return Err(failure("user home unavailable"));
            }
            CStr::from_ptr((*user).pw_dir)
                .to_string_lossy()
                .into_owned()
        };
        let root =
            PathBuf::from(home).join("Library/Application Support/Quartermaster/Development");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)?;
        let metadata = fs::symlink_metadata(&root)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(failure("unsafe development directory"));
        }
        Ok(Self {
            app,
            root,
            executable,
        })
    }

    fn destination(&self) -> String {
        format!("gui/{}/{SERVICE}", unsafe { libc::geteuid() })
    }

    fn stop(&self) -> io::Result<()> {
        let _lock = exclusive_lock(&self.root.join("startup.lock"))?;
        Command::new("/bin/launchctl")
            .args(["bootout", &self.destination()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(())
    }

    fn start(&self) -> io::Result<()> {
        let _lock = exclusive_lock(&self.root.join("startup.lock"))?;
        if Command::new("/bin/launchctl")
            .args(["print", &self.destination()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            return Ok(());
        }
        let gh = self.root.join("gh");
        DirBuilder::new().recursive(true).mode(0o700).create(&gh)?;
        private_write(
            &gh.join("config.yml"),
            format!(
                "http_unix_socket: {}\n",
                json!(self.root.join("github.sock"))
            )
            .as_bytes(),
        )?;
        let description = json!({"Label": SERVICE, "ProgramArguments": [self.executable, "serve"],
            "MachServices": {(SERVICE): true}, "RunAtLoad": true, "ProcessType": "Interactive",
            "StandardOutPath": self.root.join("backend.log"), "StandardErrorPath": self.root.join("backend.log")});
        let input = self.root.join("agent.json");
        let plist = self.root.join("agent.plist");
        private_write(&input, &serde_json::to_vec(&description)?)?;
        if !Command::new("/usr/bin/plutil")
            .args(["-convert", "xml1", "-o"])
            .arg(&plist)
            .arg(&input)
            .status()?
            .success()
        {
            return Err(failure("cannot prepare development agent"));
        }
        fs::set_permissions(&plist, fs::Permissions::from_mode(0o600))?;
        private_write(&self.root.join("backend.log"), b"")?;
        if !Command::new("/bin/launchctl")
            .arg("bootstrap")
            .arg(format!("gui/{}", unsafe { libc::geteuid() }))
            .arg(&plist)
            .status()?
            .success()
        {
            return Err(failure("cannot start development agent"));
        }
        println!(
            "Development backend started.\nGH_CONFIG_DIR={}\nLog: {}",
            gh.display(),
            self.root.join("backend.log").display()
        );
        Ok(())
    }
}

fn private_file(path: &std::path::Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(failure("unsafe development file"));
    }
    Ok(file)
}

fn exclusive_lock(path: &std::path::Path) -> io::Result<File> {
    let file = private_file(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn private_write(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_file(path)?;
    file.set_len(0)?;
    file.write_all(bytes)
}

pub fn run() -> io::Result<()> {
    if !cfg!(debug_assertions) {
        return Err(failure("only the development runtime is implemented"));
    }
    let paths = Paths::discover()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "start" => paths.start(),
        [mode] if mode == "restart" => {
            paths.stop()?;
            paths.start()
        }
        [mode] if mode == "stop" => paths.stop(),
        [mode] if mode == "cache-status" => {
            let status = qm_broker::persisted_status(paths.options()).map_err(io::Error::other)?;
            println!("{}", serde_json::to_string(&status)?);
            Ok(())
        }
        [mode] if mode == "serve" => qm_broker::serve(paths.options()).map_err(io::Error::other),
        _ => Err(failure(
            "usage: quartermasterd start|restart|stop|serve|cache-status",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn concurrent_starters_recheck_state_under_one_exclusive_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("startup.lock");
        let starters = Arc::new(Barrier::new(2));
        let registrations = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let starters = Arc::clone(&starters);
                let registrations = Arc::clone(&registrations);
                let path = &path;
                scope.spawn(move || {
                    starters.wait();
                    let _lock = exclusive_lock(path).unwrap();
                    if registrations.load(Ordering::SeqCst) == 0 {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        registrations.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(registrations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn startup_lock_rejects_symlinks_and_public_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lock");
        let target = directory.path().join("target");
        fs::write(&target, b"retain").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(exclusive_lock(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(exclusive_lock(&path).is_err());
        assert_eq!(fs::read(target).unwrap(), b"retain");
    }
}
