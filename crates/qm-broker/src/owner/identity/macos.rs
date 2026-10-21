use super::{PrincipalBinding, VerifiedPrincipal};
use qm_macos::peer_identity::PeerIdentity;
use ring::rand::{SecureRandom, SystemRandom};
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
        let mut connection = [0; 16];
        SystemRandom::new()
            .fill(&mut connection)
            .map_err(|_| io::Error::other("identity nonce unavailable"))?;
        Ok((
            Self(PrincipalBinding {
                uid,
                code_hash: peer.code_hash().into(),
                session,
                connection,
            }),
            peer,
        ))
    }
}
