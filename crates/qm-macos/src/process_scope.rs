use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod native;
pub(crate) use native::peer_token;

const MAX_PROCESSES: usize = 32;
const VALIDATION_BUDGET: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pid: u32,
    uid: u32,
    unique_id: u64,
    generation: u32,
}

pub struct ProcessPeer {
    identity: ExecutionIdentity,
    token: [u32; 8],
    stream: UnixStream,
    watch: Mutex<Option<native::Watch>>,
}

pub struct ProcessRoot {
    identity: ExecutionIdentity,
    executable: String,
    watch: Mutex<Option<native::Watch>>,
}

impl ProcessPeer {
    pub(crate) fn capture(stream: &UnixStream, token: [u32; 8]) -> io::Result<Self> {
        let started = Instant::now();
        let identity = native::observe(token[5])?.identity;
        if identity.uid != unsafe { libc::geteuid() }
            || identity.uid != token[1]
            || identity.generation != token[7]
        {
            return Err(unavailable());
        }
        let watch = native::Watch::new()?;
        watch.register(identity.pid)?;
        let peer = Self {
            identity,
            token,
            stream: stream.try_clone()?,
            watch: Mutex::new(Some(watch)),
        };
        peer.revalidate()?;
        within_budget(started)?;
        Ok(peer)
    }

    pub fn revalidate(&self) -> io::Result<()> {
        check_lifetime(&self.watch, self.identity, || {
            if native::peer_token(&self.stream)? != self.token {
                return Err(unavailable());
            }
            Ok(())
        })
    }

    pub fn root(&self, pid: u32) -> io::Result<ProcessRoot> {
        let started = Instant::now();
        let identity = native::observe(pid)?.identity;
        if identity.uid != self.identity.uid {
            return Err(unavailable());
        }
        let watch = native::Watch::new()?;
        watch.register(pid)?;
        let root = ProcessRoot {
            identity,
            executable: native::executable(pid)?,
            watch: Mutex::new(Some(watch)),
        };
        root.verify_descendant(self)?;
        within_budget(started)?;
        Ok(root)
    }

    pub fn ancestor_roots(&self) -> io::Result<Vec<ProcessRoot>> {
        let started = Instant::now();
        self.revalidate()?;
        let mut roots = Vec::new();
        let mut current = native::observe(self.identity.pid)?;
        for _ in 1..MAX_PROCESSES {
            within_budget(started)?;
            if current.parent_pid <= 1 {
                break;
            }
            let Ok(parent) = native::observe(current.parent_pid) else {
                break;
            };
            if parent.identity.uid != self.identity.uid
                || current.parent_unique_id != parent.identity.unique_id
                || current.parent_generation != parent.identity.generation
                || roots
                    .iter()
                    .any(|root: &ProcessRoot| root.identity == parent.identity)
            {
                break;
            }
            let Ok(root) = self.root(parent.identity.pid) else {
                break;
            };
            if root.identity != parent.identity {
                break;
            }
            roots.push(root);
            current = parent;
        }
        self.revalidate()?;
        within_budget(started)?;
        Ok(roots)
    }
}

impl ProcessRoot {
    pub fn identity(&self) -> ExecutionIdentity {
        self.identity
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn revalidate(&self) -> io::Result<()> {
        check_lifetime(&self.watch, self.identity, || Ok(()))
    }

    pub fn verify_descendant(&self, peer: &ProcessPeer) -> io::Result<()> {
        let started = Instant::now();
        self.revalidate()?;
        peer.revalidate()?;
        let watch = native::Watch::new()?;
        let verified = verify_chain_with(
            peer.identity,
            self.identity,
            native::observe,
            |chain| {
                for process in chain {
                    watch.register(process.identity.pid)?;
                }
                Ok(())
            },
            || watch.unchanged(),
            || started.elapsed(),
        );
        let root_current = self.revalidate();
        verified?;
        root_current?;
        peer.revalidate()?;
        within_budget(started)
    }

    pub fn invalidate(&self) {
        if let Ok(mut watch) = self.watch.lock() {
            *watch = None;
        }
    }
}

impl ExecutionIdentity {
    pub fn pid(self) -> u32 {
        self.pid
    }

    pub fn uid(self) -> u32 {
        self.uid
    }

    pub fn binding(self) -> String {
        format!(
            "{}:{:016x}:{:08x}",
            self.pid, self.unique_id, self.generation
        )
    }
}

fn within_budget(started: Instant) -> io::Result<()> {
    if started.elapsed() >= VALIDATION_BUDGET {
        Err(unavailable())
    } else {
        Ok(())
    }
}

fn check_lifetime(
    watch: &Mutex<Option<native::Watch>>,
    identity: ExecutionIdentity,
    check_peer: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let started = Instant::now();
    let mut watch = watch.lock().map_err(|_| unavailable())?;
    let result = (|| {
        let watch = watch.as_ref().ok_or_else(unavailable)?;
        check_peer()?;
        if native::observe(identity.pid)?.identity != identity {
            return Err(unavailable());
        }
        watch.unchanged()?;
        within_budget(started)
    })();
    if result.is_err() {
        *watch = None;
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    identity: ExecutionIdentity,
    parent_pid: u32,
    parent_unique_id: u64,
    parent_generation: u32,
}

fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "process scope unavailable")
}

fn verify_chain_with(
    peer: ExecutionIdentity,
    root: ExecutionIdentity,
    mut observe: impl FnMut(u32) -> io::Result<Observation>,
    register: impl FnOnce(&[Observation]) -> io::Result<()>,
    check_events: impl FnOnce() -> io::Result<()>,
    elapsed: impl Fn() -> Duration,
) -> io::Result<()> {
    let before = collect_chain(peer, root, &mut observe, &elapsed)?;
    register(&before)?;
    let after = collect_chain(peer, root, &mut observe, &elapsed)?;
    if before != after {
        return Err(unavailable());
    }
    check_events()?;
    if elapsed() >= VALIDATION_BUDGET {
        return Err(unavailable());
    }
    Ok(())
}

fn collect_chain(
    peer: ExecutionIdentity,
    root: ExecutionIdentity,
    observe: &mut impl FnMut(u32) -> io::Result<Observation>,
    elapsed: &impl Fn() -> Duration,
) -> io::Result<Vec<Observation>> {
    let mut chain: Vec<Observation> = Vec::new();
    let mut pid = peer.pid;
    for _ in 0..MAX_PROCESSES {
        if elapsed() >= VALIDATION_BUDGET || chain.iter().any(|p| p.identity.pid == pid) {
            return Err(unavailable());
        }
        let current = observe(pid)?;
        if current.identity.pid != pid || current.identity.uid != peer.uid {
            return Err(unavailable());
        }
        if let Some(child) = chain.last() {
            if child.parent_unique_id != current.identity.unique_id
                || child.parent_generation != current.identity.generation
            {
                return Err(unavailable());
            }
        } else if current.identity != peer {
            return Err(unavailable());
        }
        chain.push(current);
        if pid == root.pid {
            return if current.identity == root {
                Ok(chain)
            } else {
                Err(unavailable())
            };
        }
        if current.parent_pid <= 1 {
            return Err(unavailable());
        }
        pid = current.parent_pid;
    }
    Err(unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    fn local_peer() -> (ProcessPeer, UnixStream, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(directory.path().join("peer")).unwrap();
        let client = UnixStream::connect(directory.path().join("peer")).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut token = [0u32; 8];
        let mut length = size_of_val(&token) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    server.as_raw_fd(),
                    libc::SOL_LOCAL,
                    libc::LOCAL_PEERTOKEN,
                    token.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            0
        );
        assert_eq!(length as usize, size_of_val(&token));
        (
            ProcessPeer::capture(&server, token).unwrap(),
            client,
            directory,
        )
    }

    #[test]
    fn verified_root_membership_ends_permanently_when_monitor_is_lost() {
        let (peer, _client, _directory) = local_peer();
        let root = peer.root(std::process::id()).unwrap();
        assert!(root.verify_descendant(&peer).is_ok());
        root.invalidate();
        assert!(root.verify_descendant(&peer).is_err());
        assert!(root.verify_descendant(&peer).is_err());
    }

    #[test]
    fn native_peer_capture_rejects_a_different_saved_audit_generation() {
        let (peer, _client, _directory) = local_peer();
        let mut token = peer.token;
        token[7] = token[7].wrapping_add(1);
        assert!(ProcessPeer::capture(&peer.stream, token).is_err());
        assert!(peer.revalidate().is_ok());
    }

    fn process(pid: u32, parent: u32) -> Observation {
        Observation {
            identity: ExecutionIdentity {
                pid,
                uid: 501,
                unique_id: u64::from(pid) * 10,
                generation: pid,
            },
            parent_pid: parent,
            parent_unique_id: u64::from(parent) * 10,
            parent_generation: parent,
        }
    }

    fn tree(pid: u32) -> io::Result<Observation> {
        match pid {
            30 => Ok(process(30, 20)),
            20 => Ok(process(20, 10)),
            10 => Ok(process(10, 1)),
            _ => Err(io::Error::from_raw_os_error(libc::EPERM)),
        }
    }

    fn verify(observe: impl FnMut(u32) -> io::Result<Observation>) -> io::Result<()> {
        verify_chain_with(
            process(30, 20).identity,
            process(10, 1).identity,
            observe,
            |_| Ok(()),
            || Ok(()),
            || Duration::ZERO,
        )
    }

    #[test]
    fn indirect_descent_stops_at_root_before_unreadable_login() {
        assert!(verify(tree).is_ok());
    }

    #[test]
    fn every_parent_edge_requires_its_original_execution() {
        for mutation in 0..5 {
            let result = verify(|pid| {
                let mut observed = tree(pid)?;
                if pid == 20 {
                    match mutation {
                        0 => observed.parent_pid = 1,
                        1 => observed.parent_unique_id += 1,
                        2 => observed.parent_generation += 1,
                        3 => observed.identity.unique_id += 1,
                        _ => observed.identity.uid += 1,
                    }
                }
                Ok(observed)
            });
            assert!(result.is_err(), "accepted changed edge {mutation}");
        }
    }

    #[test]
    fn peer_or_root_replacement_cannot_adopt_the_same_pid() {
        for pid in [10, 30] {
            for reuse in [false, true] {
                assert!(
                    verify(|queried| {
                        let mut observed = tree(queried)?;
                        if queried == pid {
                            if reuse {
                                observed.identity.unique_id += 1;
                            } else {
                                observed.identity.generation += 1;
                            }
                        }
                        Ok(observed)
                    })
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn a_change_between_capture_and_admission_rejects_without_events() {
        let changed = Cell::new(false);
        let result = verify_chain_with(
            process(30, 20).identity,
            process(10, 1).identity,
            |pid| {
                let mut observed = tree(pid)?;
                if changed.get() && pid == 10 {
                    observed.identity.generation += 1;
                }
                Ok(observed)
            },
            |_| {
                changed.set(true);
                Ok(())
            },
            || Ok(()),
            || Duration::ZERO,
        );
        assert!(result.is_err());
    }

    #[test]
    fn missing_queries_watch_failure_events_and_late_results_prevent_admission() {
        for failure in 0..4 {
            let result = verify_chain_with(
                process(30, 20).identity,
                process(10, 1).identity,
                |pid| {
                    if failure == 0 {
                        Err(unavailable())
                    } else {
                        tree(pid)
                    }
                },
                |_| {
                    if failure == 1 {
                        Err(unavailable())
                    } else {
                        Ok(())
                    }
                },
                || {
                    if failure == 2 {
                        Err(unavailable())
                    } else {
                        Ok(())
                    }
                },
                || {
                    if failure == 3 {
                        VALIDATION_BUDGET
                    } else {
                        Duration::ZERO
                    }
                },
            );
            assert!(result.is_err(), "accepted failure {failure}");
        }
    }

    #[test]
    fn authority_walk_is_independent_of_display_but_bounded() {
        for (depth, accepted) in [(9, true), (32, true), (33, false)] {
            let leaf = depth + 1;
            let result = verify_chain_with(
                process(leaf, leaf - 1).identity,
                process(2, 1).identity,
                |pid| Ok(process(pid, pid - 1)),
                |_| Ok(()),
                || Ok(()),
                || Duration::ZERO,
            );
            assert_eq!(result.is_ok(), accepted, "depth {depth}");
        }
    }

    #[test]
    fn cycles_cannot_extend_a_partial_chain() {
        assert!(verify(|pid| Ok(process(pid, if pid == 30 { 20 } else { 30 }))).is_err());
    }
}
