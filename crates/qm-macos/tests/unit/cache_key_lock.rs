use super::*;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::process::Command;

const ENROLLMENT: &str = "0123456789abcdef0123456789abcdef";

fn scope() -> CacheKeyScope {
    CacheKeyScope::new(ENROLLMENT).unwrap()
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn enrollment_lock_excludes_another_process_and_keeps_the_same_inode() {
    if let Some(path) = std::env::var_os("QM_ENROLLMENT_LOCK_CHILD") {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if std::env::var_os("QM_ENROLLMENT_LOCK_EXPECT_BLOCKED").is_some() {
            assert_eq!(result, -1);
            assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        } else {
            assert_eq!(result, 0);
        }
        return;
    }
    let directory = private_directory();
    let guard = EnrollmentLock::acquire(directory.path(), &scope()).unwrap();
    let path = directory
        .path()
        .join(format!("cache-key.{ENROLLMENT}.lock"));
    let inode = fs::metadata(&path).unwrap().ino();
    let child = |blocked: bool| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "cache_key::lock::tests::enrollment_lock_excludes_another_process_and_keeps_the_same_inode"]);
        command.env("QM_ENROLLMENT_LOCK_CHILD", &path);
        command.env_remove("QM_ENROLLMENT_LOCK_EXPECT_BLOCKED");
        if blocked {
            command.env("QM_ENROLLMENT_LOCK_EXPECT_BLOCKED", "1");
        }
        assert!(command.output().unwrap().status.success());
    };
    child(true);
    drop(guard);
    child(false);
    let _next = EnrollmentLock::acquire(directory.path(), &scope()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
}

#[test]
fn enrollment_lock_rejects_symlinks_and_shared_permissions_without_touching_targets() {
    let directory = private_directory();
    let target = tempfile::NamedTempFile::new().unwrap();
    fs::write(target.path(), b"preserve").unwrap();
    let path = directory
        .path()
        .join(format!("cache-key.{ENROLLMENT}.lock"));
    symlink(target.path(), &path).unwrap();
    assert!(EnrollmentLock::acquire(directory.path(), &scope()).is_err());
    assert_eq!(fs::read(target.path()).unwrap(), b"preserve");
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"preserve").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(EnrollmentLock::acquire(directory.path(), &scope()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(EnrollmentLock::acquire(directory.path(), &scope()).is_err());
}

#[test]
fn enrollment_lock_rejects_a_hardlinked_file() {
    let directory = private_directory();
    let target = directory.path().join("original");
    fs::write(&target, b"preserve").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &target,
        directory
            .path()
            .join(format!("cache-key.{ENROLLMENT}.lock")),
    )
    .unwrap();
    assert!(EnrollmentLock::acquire(directory.path(), &scope()).is_err());
}

#[test]
fn process_exit_releases_an_enrollment_lock_without_unlinking_it() {
    if let Some(path) = std::env::var_os("QM_ENROLLMENT_LOCK_EXIT_CHILD") {
        let _guard = EnrollmentLock::acquire(Path::new(&path), &scope()).unwrap();
        std::process::exit(0);
    }
    let directory = private_directory();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cache_key::lock::tests::process_exit_releases_an_enrollment_lock_without_unlinking_it",
        ])
        .env("QM_ENROLLMENT_LOCK_EXIT_CHILD", directory.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            directory
                .path()
                .join(format!("cache-key.{ENROLLMENT}.lock")),
        )
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}

#[test]
fn concurrent_first_enrollment_lock_creation_admits_every_cooperating_caller() {
    for _ in 0..8 {
        let directory = private_directory();
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|threads| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    threads.spawn(|| {
                        barrier.wait();
                        EnrollmentLock::acquire(directory.path(), &scope()).unwrap();
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        });
    }
}
