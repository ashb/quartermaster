use super::repository::{PreparedMetadata, RepositoryBinding};
use super::response::{self, MetadataFailure, Outcome};
use crate::owner::{
    deadline::Deadline,
    dispatch::{PreparedGitHubRequest, PreparedRequest},
    operation::{Admission, MetadataAdmission},
    transport::{OperationResponse, ReadRedirect, reserve_socket},
};
use ring::digest::{SHA256, digest};
#[cfg(test)]
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

const FRAME_LIMIT: usize = 32768;
static RESOLVING: AtomicUsize = AtomicUsize::new(0);

fn unavailable() -> io::Error {
    io::Error::other("GitHub transport unavailable")
}

fn remaining(deadline: Deadline) -> io::Result<Duration> {
    deadline.remaining()
}

fn configuration(roots: RootCertStore) -> io::Result<Arc<ClientConfig>> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| unavailable())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn resolve_with(
    deadline: Deadline,
    lookup: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    remaining(deadline)?;
    struct Reservation;
    impl Drop for Reservation {
        fn drop(&mut self) {
            RESOLVING.fetch_sub(1, Ordering::AcqRel);
        }
    }
    RESOLVING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < 4).then_some(active + 1)
        })
        .map_err(|_| unavailable())?;
    let reservation = Reservation;
    let (send, receive) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("github-resolver".into())
        .spawn(move || {
            let _reservation = reservation;
            let _ = send.send(lookup());
        })?;
    receive
        .recv_timeout(remaining(deadline)?)
        .map_err(|_| unavailable())?
}

pub(in crate::owner) struct ReadyGitHub {
    socket: TcpStream,
    tls: ClientConnection,
    deadline: Deadline,
}

#[derive(Clone, Default)]
pub(in crate::owner) enum Connector {
    #[default]
    Github,
    #[cfg(test)]
    Fixture(SocketAddr),
}

impl Connector {
    #[cfg(test)]
    pub(in crate::owner) fn fixture(address: SocketAddr) -> Self {
        assert!(address.ip().is_loopback());
        Self::Fixture(address)
    }

    pub(in crate::owner) fn connect(&self, deadline: Deadline) -> io::Result<ReadyGitHub> {
        match self {
            Self::Github => ReadyGitHub::connect(deadline),
            #[cfg(test)]
            Self::Fixture(address) => {
                let mut roots = RootCertStore::empty();
                roots
                    .add(CertificateDer::from(
                        include_bytes!("../../../tests/fixtures/tls/dummy-ca.der").to_vec(),
                    ))
                    .map_err(|_| unavailable())?;
                let ready = ReadyGitHub::connect_to(
                    *address,
                    configuration(roots)?,
                    deadline.cap(Duration::from_secs(10))?,
                )?;
                Ok(ReadyGitHub { deadline, ..ready })
            }
        }
    }
}

pub(in crate::owner) struct PreparedGitHub {
    ready: ReadyGitHub,
    request: PreparedGitHubRequest,
    records: Records,
}

struct Records {
    bytes: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
}

impl Records {
    fn intact(&self) -> bool {
        !self.bytes.is_empty()
            && self.bytes.len() <= FRAME_LIMIT
            && digest(&SHA256, &self.bytes).as_ref() == self.digest
    }
}

pub(in crate::owner) struct PreparedMetadataTransport {
    ready: ReadyGitHub,
    request: PreparedMetadata,
    records: Records,
}
pub(in crate::owner) struct InFlightMetadata {
    ready: ReadyGitHub,
    request: PreparedMetadata,
}

pub(super) struct AuthenticatedMetadata {
    request: PreparedMetadata,
    wire: response::WireResponse,
}

impl AuthenticatedMetadata {
    pub(super) fn into_parts(self) -> (PreparedMetadata, response::WireResponse) {
        (self.request, self.wire)
    }
}

pub(in crate::owner) struct InFlightGitHub {
    ready: ReadyGitHub,
    prepared: PreparedGitHubRequest,
    request: crate::owner::request::FrozenOperation,
}

impl ReadyGitHub {
    pub(in crate::owner) fn connect(deadline: Deadline) -> io::Result<Self> {
        let preparation = deadline.cap(Duration::from_secs(10))?;
        let certificates = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (valid, _) = roots.add_parsable_certificates(certificates.certs);
        if valid == 0 {
            return Err(unavailable());
        }
        let config = configuration(roots)?;
        let addresses = resolve_with(preparation, || {
            ("api.github.com", 443)
                .to_socket_addrs()
                .map(|addresses| addresses.take(32).collect())
        })?;
        for address in addresses {
            if let Ok(ready) = Self::connect_to(address, Arc::clone(&config), preparation) {
                return Ok(Self { deadline, ..ready });
            }
            remaining(preparation)?;
        }
        Err(unavailable())
    }

    fn connect_to(
        address: SocketAddr,
        config: Arc<ClientConfig>,
        deadline: Deadline,
    ) -> io::Result<Self> {
        let mut socket = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
        socket.set_nodelay(true)?;
        let mut tls = ClientConnection::new(
            config,
            ServerName::try_from("api.github.com").map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        tls.set_buffer_limit(Some(FRAME_LIMIT));
        {
            let mut connection = DeadlineSocket {
                socket: &mut socket,
                deadline,
            };
            while tls.is_handshaking() {
                tls.complete_io(&mut connection)?;
            }
            while tls.wants_write() {
                tls.write_tls(&mut connection)?;
            }
        }
        if tls
            .alpn_protocol()
            .is_some_and(|protocol| protocol != b"http/1.1")
        {
            return Err(unavailable());
        }
        socket.set_nonblocking(true)?;
        reserve_socket(&socket, FRAME_LIMIT)?;
        remaining(deadline)?;
        Ok(Self {
            socket,
            tls,
            deadline,
        })
    }

    fn encrypt(&mut self, bytes: &[u8]) -> io::Result<Records> {
        if bytes.len() > 8192 {
            return Err(unavailable());
        }
        remaining(self.deadline)?;
        self.tls.writer().write_all(bytes)?;
        let mut records = Zeroizing::new(Vec::new());
        while self.tls.wants_write() {
            self.tls.write_tls(&mut *records)?;
            if records.len() > FRAME_LIMIT {
                return Err(unavailable());
            }
        }
        if records.is_empty() {
            return Err(unavailable());
        }
        let digest = digest(&SHA256, &records).as_ref().try_into().unwrap();
        Ok(Records {
            bytes: records,
            digest,
        })
    }

    fn submit(&mut self, records: Records) -> io::Result<()> {
        if !records.intact() {
            return Err(unavailable());
        }
        remaining(self.deadline)?;
        let count = self.socket.write(&records.bytes)?;
        if count != records.bytes.len() {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(in crate::owner) fn stage(
        mut self,
        request: PreparedGitHubRequest,
    ) -> io::Result<PreparedGitHub> {
        let records = self.encrypt(request.bytes())?;
        Ok(PreparedGitHub {
            ready: self,
            request,
            records,
        })
    }

    pub(in crate::owner) fn stage_metadata(
        mut self,
        request: PreparedMetadata,
    ) -> io::Result<PreparedMetadataTransport> {
        let records = self.encrypt(request.bytes())?;
        Ok(PreparedMetadataTransport {
            ready: self,
            request,
            records,
        })
    }
}

impl PreparedGitHub {
    pub(in crate::owner) fn request(&self) -> &PreparedRequest {
        &self.request
    }
    pub(in crate::owner) fn validate(&self) -> io::Result<()> {
        if !self.records.intact() {
            return Err(unavailable());
        }
        remaining(self.ready.deadline).map(|_| ())
    }

    pub(in crate::owner) fn handoff(mut self, admission: Admission) -> io::Result<InFlightGitHub> {
        if !admission.accepts(&self.request) {
            return Err(unavailable());
        }
        self.ready.submit(self.records)?;
        Ok(InFlightGitHub {
            ready: self.ready,
            prepared: self.request,
            request: admission.into_request(),
        })
    }
}

impl PreparedMetadataTransport {
    pub(in crate::owner) fn request(&self) -> &PreparedMetadata {
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
        admission: MetadataAdmission,
    ) -> io::Result<InFlightMetadata> {
        if !admission.accepts(&self.request) {
            return Err(unavailable());
        }
        self.ready.submit(self.records)?;
        Ok(InFlightMetadata {
            ready: self.ready,
            request: self.request,
        })
    }
}

impl InFlightMetadata {
    pub(in crate::owner) fn response(mut self) -> Result<RepositoryBinding, MetadataFailure> {
        self.ready
            .socket
            .set_nonblocking(false)
            .map_err(|_| MetadataFailure::Invalid)?;
        let mut connection = DeadlineSocket {
            socket: &mut self.ready.socket,
            deadline: self.ready.deadline,
        };
        let mut stream = rustls::Stream::new(&mut self.ready.tls, &mut connection);
        let wire = response::read(&mut stream).map_err(|_| MetadataFailure::Invalid)?;
        remaining(self.ready.deadline).map_err(|_| MetadataFailure::Invalid)?;
        let result = RepositoryBinding::from_authenticated(AuthenticatedMetadata {
            request: self.request,
            wire,
        });
        remaining(self.ready.deadline).map_err(|_| MetadataFailure::Invalid)?;
        result
    }
}

impl InFlightGitHub {
    pub(in crate::owner) fn response(mut self) -> OperationResponse {
        let response = (|| {
            self.ready.socket.set_nonblocking(false)?;
            let mut connection = DeadlineSocket {
                socket: &mut self.ready.socket,
                deadline: self.ready.deadline,
            };
            let mut stream = rustls::Stream::new(&mut self.ready.tls, &mut connection);
            let wire = response::read(&mut stream).map_err(|_| unavailable())?;
            remaining(self.ready.deadline)?;
            let response = wire
                .issues(
                    &self.request,
                    self.prepared.repository(),
                    self.prepared.credential(),
                )
                .map_err(|_| unavailable())?;
            remaining(self.ready.deadline)?;
            Ok::<_, io::Error>(response)
        })();
        match response {
            Ok(Outcome::Response(response)) => OperationResponse::Github(response),
            Ok(Outcome::Redirect(target)) => OperationResponse::Redirect(Box::new(ReadRedirect {
                target,
                selection: self.prepared.selection().clone(),
            })),
            Err(_) => OperationResponse::Uncertain,
        }
    }
}

struct DeadlineSocket<'a> {
    socket: &'a mut TcpStream,
    deadline: Deadline,
}

impl Read for DeadlineSocket<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineSocket<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.socket.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/github_https.rs"]
mod tests;
