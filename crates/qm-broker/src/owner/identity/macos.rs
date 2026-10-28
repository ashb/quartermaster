use super::{PrincipalBinding, RootDescription, RootEvidence, VerifiedPrincipal, VerifiedRoot};
use qm_macos::peer_identity::PeerIdentity;
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;
use std::{
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

impl VerifiedPrincipal {
    pub(in crate::owner) fn capture(
        stream: &UnixStream,
        session: [u8; 16],
    ) -> io::Result<(Self, PeerIdentity)> {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if uid != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong socket user",
            ));
        }
        let peer = PeerIdentity::capture(stream)?;
        let socket = Some(peer.socket_peer(stream)?);
        let process = peer.process_peer(stream).ok();
        let mut connection = [0; 16];
        SystemRandom::new()
            .fill(&mut connection)
            .map_err(|_| io::Error::other("identity nonce unavailable"))?;
        Ok((
            Self {
                binding: PrincipalBinding {
                    uid,
                    code_hash: peer.code_hash().into(),
                    session,
                    connection,
                },
                process,
                socket,
                #[cfg(test)]
                fixture_root: None,
            },
            peer,
        ))
    }

    pub(super) fn native_roots(&self) -> io::Result<Vec<Arc<VerifiedRoot>>> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| io::Error::other("process scope unavailable"))?;
        Ok(process
            .ancestor_roots()?
            .into_iter()
            .filter(|root| {
                matches!(
                    std::path::Path::new(root.executable())
                        .file_name()
                        .and_then(|s| s.to_str()),
                    Some("zsh" | "bash" | "sh" | "fish" | "dash" | "ksh" | "csh" | "tcsh" | "nu")
                )
            })
            .map(|process| {
                Arc::new(VerifiedRoot {
                    session: self.binding.session,
                    description: RootDescription {
                        id: process.identity().binding(),
                        pid: process.identity().pid(),
                        executable: process.executable().into(),
                    },
                    evidence: RootEvidence::Native(process),
                })
            })
            .collect())
    }
}

#[cfg(test)]
impl VerifiedRoot {
    pub(in crate::owner) fn native_fixture(session: [u8; 16]) -> Arc<Self> {
        let (stream, _client) = UnixStream::pair().unwrap();
        let (principal, _) = VerifiedPrincipal::capture(&stream, session).unwrap();
        let process = principal
            .process
            .as_ref()
            .unwrap()
            .root(std::process::id())
            .unwrap();
        Arc::new(Self {
            session,
            description: RootDescription {
                id: process.identity().binding(),
                pid: process.identity().pid(),
                executable: process.executable().into(),
            },
            evidence: RootEvidence::Native(process),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_root_membership_cannot_cross_backend_sessions_or_invalidation() {
        let (stream, _client) = UnixStream::pair().unwrap();
        let (principal, _) = VerifiedPrincipal::capture(&stream, [1; 16]).unwrap();
        let process = principal
            .process
            .as_ref()
            .unwrap()
            .root(std::process::id())
            .unwrap();
        let root = VerifiedRoot {
            session: [1; 16],
            description: RootDescription {
                id: process.identity().binding(),
                pid: process.identity().pid(),
                executable: process.executable().into(),
            },
            evidence: RootEvidence::Native(process),
        };
        assert!(root.verify(&principal).is_ok());
        let (replacement, _) = VerifiedPrincipal::capture(&stream, [2; 16]).unwrap();
        assert!(root.verify(&replacement).is_err());
        root.invalidate();
        assert!(root.verify(&principal).is_err());
        assert!(root.verify(&principal).is_err());
    }

    #[test]
    fn missing_native_evidence_does_not_create_a_root_candidate() {
        let mut principal = VerifiedPrincipal::fixture(501, "a".repeat(40), [1; 16]);
        principal.fixture_root = None;
        assert!(principal.roots().is_err());
    }
}
