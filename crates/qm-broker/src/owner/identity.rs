#[cfg(target_os = "macos")]
mod macos;

use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrincipalBinding {
    uid: u32,
    code_hash: String,
    session: [u8; 16],
    connection: [u8; 16],
}

pub(super) struct VerifiedPrincipal {
    binding: PrincipalBinding,
    #[cfg(test)]
    fixture_root: Option<String>,
    #[cfg(target_os = "macos")]
    process: Option<qm_macos::process_scope::ProcessPeer>,
    #[cfg(target_os = "macos")]
    socket: Option<qm_macos::peer_identity::SocketPeer>,
}

impl PrincipalBinding {
    pub(super) fn in_session(&self, session: [u8; 16]) -> bool {
        self.session == session
    }
}

impl VerifiedPrincipal {
    pub(super) fn revalidate(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if let Some(process) = &self.process {
            return process.revalidate();
        }
        #[cfg(target_os = "macos")]
        if let Some(socket) = &self.socket {
            return socket.revalidate();
        }
        #[cfg(test)]
        return Ok(());
        #[cfg(not(test))]
        Err(io::Error::other("peer evidence unavailable"))
    }

    #[cfg(test)]
    pub(super) fn without_fixture_root(mut self) -> Self {
        self.fixture_root = None;
        self
    }

    pub(super) fn uid(&self) -> u32 {
        self.binding.uid
    }

    pub(super) fn code_hash(&self) -> &str {
        &self.binding.code_hash
    }

    pub(super) fn matches(&self, uid: u32, code_hash: &str, session: [u8; 16]) -> bool {
        self.binding.uid == uid
            && self.binding.code_hash == code_hash
            && self.binding.session == session
    }

    pub(super) fn binding(&self) -> PrincipalBinding {
        self.binding.clone()
    }

    pub(super) fn in_session(&self, session: [u8; 16]) -> bool {
        self.binding.session == session
    }

    #[cfg(test)]
    pub(super) fn fixture(uid: u32, code_hash: String, session: [u8; 16]) -> Self {
        Self::fixture_with_connection(uid, code_hash, session, [3; 16])
    }

    #[cfg(test)]
    pub(super) fn fixture_with_connection(
        uid: u32,
        code_hash: String,
        session: [u8; 16],
        connection: [u8; 16],
    ) -> Self {
        Self {
            fixture_root: Some("fixture-root".into()),
            binding: PrincipalBinding {
                uid,
                code_hash,
                session,
                connection,
            },
            #[cfg(target_os = "macos")]
            process: None,
            #[cfg(target_os = "macos")]
            socket: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RootDescription {
    pub(super) id: String,
    pub(super) pid: u32,
    pub(super) executable: String,
}

pub(super) struct VerifiedRoot {
    session: [u8; 16],
    description: RootDescription,
    evidence: RootEvidence,
}

enum RootEvidence {
    #[cfg(target_os = "macos")]
    Native(qm_macos::process_scope::ProcessRoot),
    #[cfg(test)]
    Fixture(std::sync::atomic::AtomicBool),
}

impl VerifiedRoot {
    pub(super) fn description(&self) -> &RootDescription {
        &self.description
    }

    pub(super) fn live(&self) -> io::Result<()> {
        match &self.evidence {
            #[cfg(target_os = "macos")]
            RootEvidence::Native(root) => root.revalidate(),
            #[cfg(test)]
            RootEvidence::Fixture(live) if live.load(std::sync::atomic::Ordering::SeqCst) => Ok(()),
            #[cfg(test)]
            _ => Err(io::Error::other("root lifetime ended")),
        }
    }

    pub(super) fn verify(&self, principal: &VerifiedPrincipal) -> io::Result<()> {
        if !principal.in_session(self.session) {
            return Err(io::Error::other("root session ended"));
        }
        self.live()?;
        match &self.evidence {
            #[cfg(target_os = "macos")]
            RootEvidence::Native(root) => root.verify_descendant(
                principal
                    .process
                    .as_ref()
                    .ok_or_else(|| io::Error::other("process scope unavailable"))?,
            ),
            #[cfg(test)]
            RootEvidence::Fixture(_)
                if principal.fixture_root.as_deref() == Some(&self.description.id) =>
            {
                Ok(())
            }
            #[cfg(test)]
            _ => Err(io::Error::other("unrelated root")),
        }
    }

    #[cfg(test)]
    pub(super) fn fixture(id: &str, session: [u8; 16]) -> Arc<Self> {
        Arc::new(Self {
            session,
            description: RootDescription {
                id: id.into(),
                pid: 123,
                executable: "/bin/zsh".into(),
            },
            evidence: RootEvidence::Fixture(std::sync::atomic::AtomicBool::new(true)),
        })
    }

    #[cfg(test)]
    pub(super) fn invalidate(&self) {
        match &self.evidence {
            #[cfg(target_os = "macos")]
            RootEvidence::Native(root) => root.invalidate(),
            RootEvidence::Fixture(live) => live.store(false, std::sync::atomic::Ordering::SeqCst),
        }
    }
}

impl VerifiedPrincipal {
    pub(super) fn roots(&self) -> io::Result<Vec<Arc<VerifiedRoot>>> {
        #[cfg(test)]
        if let Some(id) = &self.fixture_root {
            return Ok(vec![VerifiedRoot::fixture(id, self.binding.session)]);
        }
        #[cfg(target_os = "macos")]
        {
            self.native_roots()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(io::Error::other("process scope unavailable"))
        }
    }

    #[cfg(test)]
    pub(super) fn with_fixture_root(mut self, id: &str) -> Self {
        self.fixture_root = Some(id.into());
        self
    }
}
