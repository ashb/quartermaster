#[cfg(target_os = "macos")]
mod macos;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrincipalBinding {
    uid: u32,
    code_hash: String,
    session: [u8; 16],
    connection: [u8; 16],
}

pub(super) struct VerifiedPrincipal(PrincipalBinding);

impl PrincipalBinding {
    pub(super) fn in_session(&self, session: [u8; 16]) -> bool {
        self.session == session
    }
}

impl VerifiedPrincipal {
    pub(super) fn uid(&self) -> u32 {
        self.0.uid
    }

    pub(super) fn code_hash(&self) -> &str {
        &self.0.code_hash
    }

    pub(super) fn matches(&self, uid: u32, code_hash: &str, session: [u8; 16]) -> bool {
        self.0.uid == uid && self.0.code_hash == code_hash && self.0.session == session
    }

    pub(super) fn binding(&self) -> PrincipalBinding {
        self.0.clone()
    }

    pub(super) fn in_session(&self, session: [u8; 16]) -> bool {
        self.0.session == session
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
        Self(PrincipalBinding {
            uid,
            code_hash,
            session,
            connection,
        })
    }
}
