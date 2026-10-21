mod approval;
mod control;
mod dispatch;
mod http;
mod state;
mod vault_workflow;

use crate::owner::transport::OperationResponse;
use ring::rand::{SecureRandom, SystemRandom};
use state::OwnerState;
use std::{
    fs::{self, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
};

const SERVICE: &str = "dev.quartermaster.debug.backend";
const PROFILE: &str = "development";

fn failure(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> io::Result<T> {
    result.map_err(|e| failure(format!("{e:?}")))
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    checked(SystemRandom::new().fill(&mut bytes))?;
    Ok(bytes)
}

#[derive(Clone)]
struct ServicePaths {
    app: PathBuf,
    root: PathBuf,
}

type Shared = Arc<(Mutex<OwnerState>, Condvar)>;

fn serve_connections(
    incoming: impl Iterator<Item = io::Result<UnixStream>>,
    shared: Shared,
    paths: ServicePaths,
) -> io::Result<()> {
    thread::scope(|scope| {
        let (send, receive) = mpsc::sync_channel::<UnixStream>(8);
        let receive = Arc::new(Mutex::new(receive));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let receive = Arc::clone(&receive);
            let shared = Arc::clone(&shared);
            let paths = paths.clone();
            workers.push(scope.spawn(move || -> io::Result<()> {
                loop {
                    let next = receive
                        .lock()
                        .map_err(|_| failure("ingress unavailable"))?
                        .recv();
                    let Ok(mut stream) = next else {
                        return Ok(());
                    };
                    if let Err(error) = http::handle_http(&mut stream, &shared, &paths) {
                        eprintln!("Request denied: {error}");
                        let _ = http::response(&mut stream, OperationResponse::Denied);
                    }
                }
            }));
        }
        for stream in incoming {
            send.send(stream?)
                .map_err(|_| failure("ingress workers stopped"))?;
        }
        drop(send);
        for worker in workers {
            worker
                .join()
                .map_err(|_| failure("ingress worker stopped"))??;
        }
        Ok(())
    })
}

pub(super) fn serve(options: crate::ServiceOptions) -> io::Result<()> {
    let paths = ServicePaths {
        app: options.bundle_root,
        root: options.storage_root,
    };
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.root.join("backend.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(failure("backend already running"));
    }
    let socket = paths.root.join("github.sock");
    if let Ok(metadata) = fs::symlink_metadata(&socket) {
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(failure("unsafe socket path"));
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let shared = Arc::new((Mutex::new(OwnerState::new()?), Condvar::new()));
    let xpc_shared = Arc::clone(&shared);
    let xpc_paths = paths.clone();
    thread::spawn(move || {
        let result = control::serve_xpc(xpc_shared, xpc_paths);
        if let Err(error) = result {
            eprintln!("XPC unavailable: {error}");
            std::process::exit(1);
        }
    });
    println!("Quartermaster listening at {}.", socket.display());
    serve_connections(listener.incoming(), shared, paths)
}

#[cfg(test)]
use {
    self::{
        approval::{
            ApprovalCompletion, ApprovalDelivery, FrozenProvider, ProviderPresentation,
            ReviewContext, begin_native_presence, complete_native_presence,
        },
        control::{Client, handle, pack, unpack},
        http::{handle_http, response_until},
    },
    crate::owner::{
        deadline::Deadline,
        dispatch::{CredentialSelection, PreparedOperation},
        identity::VerifiedPrincipal,
        operation::{CancellationResult, OperationId},
        policy::AuthorizationOutcome,
        request as http_request,
    },
    base64::{Engine, engine::general_purpose::STANDARD as BASE64},
    qm_macos::{
        peer_identity::PeerIdentity,
        presence_clock::{MonotonicTimestamp, monotonic_raw as presence_now},
    },
    rama_net_apple_xpc::XpcMessage,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        io::{Read, Write},
        time::{Duration, Instant},
    },
    time::OffsetDateTime,
};

#[cfg(test)]
#[path = "../../tests/unit/authentication.rs"]
mod authentication_tests;
#[cfg(test)]
#[path = "../../tests/unit/github_runtime.rs"]
mod github_tests;
#[cfg(test)]
#[path = "../../tests/unit/runtime.rs"]
mod tests;
