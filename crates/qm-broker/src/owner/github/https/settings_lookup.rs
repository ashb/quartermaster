use super::{DeadlineSocket, ReadyGitHub, Records, remaining, response, unavailable};
use crate::owner::{
    github::response::MetadataFailure,
    settings::{LookupAdmission, LookupResult, PreparedLookup},
};
use qm_macos::presence_clock::monotonic_raw;
use std::io;
use zeroize::Zeroizing;

pub(in crate::owner) struct AuthenticatedLookup {
    request: PreparedLookup,
    body: Zeroizing<Vec<u8>>,
}

impl AuthenticatedLookup {
    pub(in crate::owner) fn into_parts(self) -> (PreparedLookup, Zeroizing<Vec<u8>>) {
        (self.request, self.body)
    }
}

pub(in crate::owner) struct PreparedLookupTransport {
    ready: ReadyGitHub,
    request: PreparedLookup,
    records: Records,
}

pub(in crate::owner) struct InFlightLookup {
    ready: ReadyGitHub,
    request: PreparedLookup,
}

impl ReadyGitHub {
    pub(in crate::owner) fn stage_lookup(
        mut self,
        request: PreparedLookup,
    ) -> io::Result<PreparedLookupTransport> {
        let records = self.encrypt(request.bytes())?;
        Ok(PreparedLookupTransport {
            ready: self,
            request,
            records,
        })
    }
}

impl PreparedLookupTransport {
    pub(in crate::owner) fn request(&self) -> &PreparedLookup {
        &self.request
    }

    pub(in crate::owner) fn validate(&self) -> io::Result<()> {
        if !self.request.intact() || !self.records.intact() {
            return Err(unavailable());
        }
        remaining(self.ready.deadline).map(|_| ())
    }

    pub(in crate::owner) fn handoff(
        mut self,
        admission: LookupAdmission<'_>,
    ) -> io::Result<InFlightLookup> {
        self.validate()?;
        if !admission.accepts(&self.request, monotonic_raw()?) {
            return Err(unavailable());
        }
        self.ready.submit(self.records)?;
        Ok(InFlightLookup {
            ready: self.ready,
            request: self.request,
        })
    }
}

impl InFlightLookup {
    pub(in crate::owner) fn response(mut self) -> Result<LookupResult, MetadataFailure> {
        self.ready
            .socket
            .set_nonblocking(false)
            .map_err(|_| MetadataFailure::Invalid)?;
        let mut connection = DeadlineSocket {
            socket: &mut self.ready.socket,
            deadline: self.ready.deadline,
        };
        let mut stream = rustls::Stream::new(&mut self.ready.tls, &mut connection);
        let wire = response::read(&mut stream, "GET").map_err(|_| MetadataFailure::Invalid)?;
        remaining(self.ready.deadline).map_err(|_| MetadataFailure::Invalid)?;
        let body = Zeroizing::new(wire.metadata_bytes(self.request.credential())?.to_vec());
        LookupResult::from_authenticated(AuthenticatedLookup {
            request: self.request,
            body,
        })
    }
}
