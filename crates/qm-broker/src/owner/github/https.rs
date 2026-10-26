use super::repository::{PreparedMetadata, RepositoryBinding};
#[cfg(target_os = "macos")]
mod settings_lookup;
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
#[cfg(target_os = "macos")]
pub(in crate::owner) use settings_lookup::AuthenticatedLookup;
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

const APPLICATION_LIMIT: usize = 256 * 1024;
const FRAME_LIMIT: usize = APPLICATION_LIMIT + 16 * 1024;
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
        reserve_socket(&socket, 32 * 1024)?;
        remaining(deadline)?;
        Ok(Self {
            socket,
            tls,
            deadline,
        })
    }

    fn encrypt(&mut self, bytes: &[u8]) -> io::Result<Records> {
        if bytes.len() > APPLICATION_LIMIT {
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
        reserve_socket(&self.socket, records.len())?;
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
        let wire = response::read(&mut stream, "GET").map_err(|_| MetadataFailure::Invalid)?;
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
            let wire =
                response::read(&mut stream, self.request.method()).map_err(|_| unavailable())?;
            remaining(self.ready.deadline)?;
            let response = match self.prepared.repository() {
                Some(repository) => {
                    wire.issues(&self.request, repository, self.prepared.credential())
                }
                None => wire.application(self.prepared.credential()),
            }
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
mod tests {
    use super::*;
    use crate::owner::policy::fixture::FixturePolicy;
    use crate::owner::{
        dispatch::PreparedOperation,
        github::{configuration::GitHubConfig, repository::RepositoryLookup},
        identity::VerifiedPrincipal,
        operation::{CancellationResult, OperationRegistry},
        policy::Authorizer,
        request,
        test_support::{self, vault},
        transport::OperationResponse,
    };
    use rustls::{
        ServerConfig, ServerConnection,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use std::{
        io::{Cursor, Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Instant,
    };

    fn client_config(trusted: bool) -> Arc<ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            roots
                .add(CertificateDer::from(
                    include_bytes!("../../../tests/fixtures/tls/dummy-ca.der").to_vec(),
                ))
                .unwrap();
        }
        configuration(roots).unwrap()
    }

    fn peer(
        stall: bool,
    ) -> (
        std::net::SocketAddr,
        mpsc::Sender<()>,
        thread::JoinHandle<Vec<u8>>,
    ) {
        peer_response(stall, None)
    }

    fn peer_response(
        stall: bool,
        metadata_id: Option<u64>,
    ) -> (
        std::net::SocketAddr,
        mpsc::Sender<()>,
        thread::JoinHandle<Vec<u8>>,
    ) {
        let body = metadata_id.map(|id| format!("{{\"id\":{id},\"full_name\":\"example/one\"}}")).unwrap_or_else(|| r#"{"number":42,"state":"open","url":"https://api.github.com/repos/example/one/issues/42","repository_url":"https://api.github.com/repos/example/one","title":"Actual fixture response"}"#.to_owned());
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body.as_bytes());
        peer_reply(stall, response)
    }

    fn peer_reply(
        stall: bool,
        response: Vec<u8>,
    ) -> (
        std::net::SocketAddr,
        mpsc::Sender<()>,
        thread::JoinHandle<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (resume, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            if stall {
                receive.recv().unwrap();
            }
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    include_bytes!("../../../tests/fixtures/tls/dummy-cert.der").to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    include_bytes!("../../../tests/fixtures/tls/dummy-key.der").to_vec(),
                )),
            )
            .unwrap();
            let mut tls = ServerConnection::new(Arc::new(config)).unwrap();
            let mut input = Vec::new();
            {
                let mut stream = rustls::Stream::new(&mut tls, &mut socket);
                while !input.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    match stream.read(&mut byte) {
                        Ok(1) => input.push(byte[0]),
                        _ => return input,
                    }
                }
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut head = httparse::Request::new(&mut headers);
                head.parse(&input).unwrap();
                let count = head
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |header| {
                        std::str::from_utf8(header.value)
                            .unwrap()
                            .parse::<usize>()
                            .unwrap()
                    });
                let offset = input.len();
                input.resize(offset + count, 0);
                stream.read_exact(&mut input[offset..]).unwrap();
                stream.write_all(&response).unwrap();
            }
            tls.send_close_notify();
            while tls.wants_write() {
                if tls.write_tls(&mut socket).is_err() {
                    break;
                }
            }
            input
        });
        (address, resume, worker)
    }

    fn prepared(
        expired: bool,
    ) -> (
        Authorizer,
        VerifiedPrincipal,
        OperationRegistry,
        crate::owner::operation::OperationId,
        qm_providers::VaultSnapshot,
        crate::owner::dispatch::PreparedGitHubRequest,
    ) {
        let now = Instant::now()
            - if expired {
                Duration::from_secs(20)
            } else {
                Duration::ZERO
            };
        let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}]}"#).unwrap();
        let request = request::read_configured(&mut Cursor::new("GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nAuthorization: Bearer untrusted-caller-token\r\n\r\n"), Some(&config)).unwrap();
        let mut document: serde_json::Value =
            serde_json::from_slice(&test_support::policy_bytes(1010)).unwrap();
        document["grants"][0]["repository"] = "example/one".into();
        let mut authorizer = Authorizer::new([1; 16]);
        authorizer
            .install(
                Ok(
                    FixturePolicy::decode(&serde_json::to_vec(&document).unwrap())
                        .unwrap()
                        .with_github(config.clone()),
                ),
                test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let snapshot = vault::snapshot("github-read");
        let selection = vault::selection(&snapshot);
        let binding = RepositoryLookup::new(
            &config,
            &request,
            selection.clone(),
            authorizer.policy_generation(),
        )
        .unwrap()
        .verify_fixture(br#"{"id":123,"full_name":"example/one"}"#)
        .unwrap();
        let mut registry = OperationRegistry::default();
        let id = registry
            .register(authorizer.authorize(&principal, request, now).unwrap(), now)
            .unwrap();
        registry
            .select_credential(id, &principal, selection)
            .unwrap();
        let request = crate::owner::execution::prepare_github(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            binding,
            now,
        )
        .unwrap();
        (authorizer, principal, registry, id, snapshot, request)
    }

    #[test]
    fn cookie_bearing_requests_cannot_reuse_the_scoped_read_grant() {
        let (authorizer, principal, _registry, _id, _snapshot, _prepared) = prepared(false);
        let config = authorizer.github_configuration().unwrap();
        let request = request::read_configured(&mut Cursor::new(
            "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nCookie: forbidden\r\n\r\n"
        ), Some(config)).unwrap();
        assert_eq!(request.action(), request::Action::Api);
        assert!(matches!(
            authorizer.authorize(&principal, request, Instant::now()),
            Err(crate::owner::policy::AuthorizationError::Denied)
        ));
    }

    struct ApprovedApi {
        authorizer: Authorizer,
        principal: VerifiedPrincipal,
        registry: OperationRegistry,
        id: crate::owner::operation::OperationId,
        snapshot: qm_providers::VaultSnapshot,
        prepared: crate::owner::dispatch::PreparedGitHubRequest,
        session: qm_providers::ApprovalSession,
        original: crate::owner::request::FrozenOperation,
    }

    impl ApprovedApi {
        fn new(raw: &str) -> Self {
            Self::with_role(raw, "github-write")
        }

        fn with_role(raw: &str, role: &str) -> Self {
            let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[],"approveUnverifiedRequests":true}"#).unwrap();
            let request = request::read_configured(&mut Cursor::new(raw), Some(&config)).unwrap();
            let mut authorizer = Authorizer::new([1; 16]);
            authorizer
                .install(
                    Ok(FixturePolicy::default().with_github(config)),
                    test_support::wall(1000),
                    Instant::now(),
                )
                .unwrap();
            let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
            let snapshot = vault::snapshot(role);
            let crate::owner::policy::AuthorizationOutcome::RequireApproval(requirement) =
                authorizer
                    .authorize(&principal, request.clone(), Instant::now())
                    .unwrap()
            else {
                panic!()
            };
            assert!(requirement.grant_claims().is_none());
            let mut registry = OperationRegistry::default();
            let (id, session, _key, _digest) = test_support::approval::sign(
                &mut registry,
                &authorizer,
                &principal,
                &snapshot,
                requirement,
                Instant::now(),
                Duration::ZERO,
            );
            let prepared = crate::owner::execution::prepare_unscoped_github(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                Instant::now(),
            )
            .unwrap();
            Self {
                authorizer,
                principal,
                registry,
                id,
                snapshot,
                prepared,
                session,
                original: request,
            }
        }
    }

    #[test]
    fn one_use_api_approval_uses_the_host_selected_read_or_write_credential_role() {
        for role in ["github-read", "github-write"] {
            let mut fixture = ApprovedApi::with_role(
                "GET /future-api HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
                role,
            );
            assert_eq!(fixture.prepared.selection().role(), role);
            let (address, _, worker) = peer(false);
            let transport = ReadyGitHub::connect_to(
                address,
                client_config(true),
                Deadline::after(Duration::from_secs(3)).unwrap(),
            )
            .unwrap();
            let operation = PreparedOperation::github(fixture.prepared, transport).unwrap();
            assert!(matches!(
                operation
                    .handoff(
                        &mut fixture.registry,
                        &mut fixture.authorizer,
                        &fixture.principal,
                        &fixture.snapshot
                    )
                    .unwrap()
                    .response(),
                OperationResponse::Github(_)
            ));
            assert!(
                worker
                    .join()
                    .unwrap()
                    .starts_with(b"GET /future-api HTTP/1.1\r\n")
            );
        }
    }

    #[test]
    fn one_use_api_responses_preserve_bodyless_text_and_binary_http_semantics_over_tls() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"\x00\xff\r\n").unwrap();
        let compressed = encoder.finish().unwrap();
        let mut gzip_reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", compressed.len()).into_bytes();
        gzip_reply.extend_from_slice(&compressed);
        for (method, upstream, framing, expected) in [
            ("HEAD", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 41\r\n\r\n".as_slice(), Some("Content-Length: 41\r\n"), b"".as_slice()),
            ("DELETE", b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(), None, b"".as_slice()),
            ("GET", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 41\r\n\r\n".as_slice(), Some("Content-Length: 41\r\n"), b"".as_slice()),
            ("GET", b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nhi!".as_slice(), Some("Content-Type: text/plain\r\n"), b"hi!".as_slice()),
            ("GET", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n\x00\xff\r\n".as_slice(), Some("Content-Type: application/octet-stream\r\n"), b"\x00\xff\r\n".as_slice()),
            ("GET", gzip_reply.as_slice(), Some("Content-Type: application/octet-stream\r\n"), b"\x00\xff\r\n".as_slice()),
            ("GET", b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nuntil-close".as_slice(), Some("Content-Type: text/plain\r\n"), b"until-close".as_slice()),
            ("HEAD", b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: 4194304\r\n\r\n".as_slice(), Some("Content-Length: 4194304\r\n"), b"".as_slice()),
        ] {
            let mut fixture = ApprovedApi::with_role(&format!("{method} /future-api HTTP/1.1\r\nHost: api.github.com\r\n\r\n"), "github-read");
            let (address, _, worker) = peer_reply(false, upstream.to_vec());
            let transport = ReadyGitHub::connect_to(address, client_config(true), Deadline::after(Duration::from_secs(3)).unwrap()).unwrap();
            let outcome = PreparedOperation::github(fixture.prepared, transport).unwrap().handoff(&mut fixture.registry, &mut fixture.authorizer, &fixture.principal, &fixture.snapshot).unwrap().response();
            let OperationResponse::Github(response) = outcome else { panic!("{method}: valid response became uncertain") };
            let mut forwarded = Vec::new();
            response.write(&mut forwarded).unwrap();
            let boundary = forwarded.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(&forwarded[boundary..], expected);
            let head = std::str::from_utf8(&forwarded[..boundary]).unwrap();
            if let Some(framing) = framing { assert!(head.contains(framing), "{head}"); }
            else { assert!(!head.contains("Content-Length:"), "{head}"); }
            assert!(worker.join().unwrap().starts_with(format!("{method} /future-api HTTP/1.1\r\n").as_bytes()));
        }
    }

    #[test]
    fn one_use_approval_forwards_original_rest_and_graphql_bodies_and_cookie_headers_over_tls() {
        for target in ["/graphql", "/an-unfamiliar-endpoint?x=%2f&x=2"] {
            let body = r#"{ "query": "query { viewer { login } }", "variables": {} }"#;
            let raw = format!(
                "POST {target} HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: caller-placeholder\r\nCookie: explicitly-reviewed\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let mut fixture = ApprovedApi::new(&raw);
            let (address, _, worker) = peer(false);
            let transport = ReadyGitHub::connect_to(
                address,
                client_config(true),
                Deadline::after(Duration::from_secs(3)).unwrap(),
            )
            .unwrap();
            let receipt = PreparedOperation::github(fixture.prepared, transport)
                .unwrap()
                .handoff(
                    &mut fixture.registry,
                    &mut fixture.authorizer,
                    &fixture.principal,
                    &fixture.snapshot,
                )
                .unwrap();
            assert!(matches!(receipt.response(), OperationResponse::Github(_)));
            let actual = worker.join().unwrap();
            let expected = raw
                .replace(
                    "Authorization: caller-placeholder",
                    "Authorization: Bearer quartermaster-dummy-canary",
                )
                .replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n");
            assert_eq!(actual, expected.as_bytes());
            assert!(
                crate::owner::execution::prepare_unscoped_github(
                    &fixture.registry,
                    fixture.id,
                    &fixture.principal,
                    &fixture.authorizer,
                    &fixture.snapshot,
                    Instant::now()
                )
                .is_err()
            );
            assert!(matches!(
                fixture
                    .authorizer
                    .authorize(&fixture.principal, fixture.original, Instant::now())
                    .unwrap(),
                crate::owner::policy::AuthorizationOutcome::RequireApproval(_)
            ));
        }
    }

    #[test]
    fn canceled_or_stale_one_use_approvals_send_zero_application_bytes_over_tls() {
        for failure in [
            "cancel",
            "ui-loss",
            "policy-reversion",
            "credential-replacement",
        ] {
            let mut fixture =
                ApprovedApi::new("GET /future-api HTTP/1.1\r\nHost: api.github.com\r\n\r\n");
            let (address, _, worker) = peer(false);
            let transport = ReadyGitHub::connect_to(
                address,
                client_config(true),
                Deadline::after(Duration::from_secs(3)).unwrap(),
            )
            .unwrap();
            let prepared = PreparedOperation::github(fixture.prepared, transport).unwrap();
            match failure {
                "cancel" => {
                    assert_eq!(
                        fixture.registry.cancel(fixture.id, &fixture.principal),
                        CancellationResult::Canceled
                    );
                }
                "ui-loss" => fixture
                    .registry
                    .cancel_interactive_session(fixture.session.id()),
                "policy-reversion" => {
                    let config = fixture.authorizer.github_configuration().unwrap().clone();
                    fixture.authorizer.invalidate_policy().unwrap();
                    fixture
                        .authorizer
                        .install(
                            Ok(FixturePolicy::default().with_github(config)),
                            test_support::wall(1000),
                            Instant::now(),
                        )
                        .unwrap();
                }
                _ => {
                    fixture.snapshot = vault::snapshot_with(
                        "github-write",
                        "33333333-3333-4333-8333-333333333333",
                        [4; 16],
                    )
                }
            }
            assert!(
                prepared
                    .handoff(
                        &mut fixture.registry,
                        &mut fixture.authorizer,
                        &fixture.principal,
                        &fixture.snapshot
                    )
                    .is_err(),
                "{failure}"
            );
            assert!(worker.join().unwrap().is_empty(), "{failure}");
        }
    }

    #[test]
    fn a_large_graphql_request_is_reviewed_and_forwarded_without_truncation() {
        let body = serde_json::json!({"query":"query { viewer { login } }", "variables":{"padding":"x".repeat(100_000)}}).to_string();
        let raw = format!(
            "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: caller-placeholder\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut fixture = ApprovedApi::new(&raw);
        let (address, _, worker) = peer(false);
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(3)).unwrap(),
        )
        .unwrap();
        let operation = PreparedOperation::github(fixture.prepared, transport).unwrap();
        assert!(matches!(
            operation
                .handoff(
                    &mut fixture.registry,
                    &mut fixture.authorizer,
                    &fixture.principal,
                    &fixture.snapshot
                )
                .unwrap()
                .response(),
            OperationResponse::Github(_)
        ));
        let expected = raw
            .replace(
                "Authorization: caller-placeholder",
                "Authorization: Bearer quartermaster-dummy-canary",
            )
            .replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n");
        assert_eq!(worker.join().unwrap(), expected.as_bytes());
    }

    #[test]
    fn github_https_stages_an_immutable_encrypted_request_and_sends_once_only_after_admission() {
        let (mut authorizer, principal, mut registry, _id, snapshot, request) = prepared(false);
        let (address, _, worker) = peer(false);
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let operation = PreparedOperation::github(request, transport).unwrap();
        let receipt = operation
            .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
            .unwrap();
        assert!(matches!(receipt.response(), OperationResponse::Github(_)));
        let input = String::from_utf8(worker.join().unwrap()).unwrap();
        assert!(
            input.starts_with(
                "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n"
            )
        );
        assert_eq!(
            input
                .matches("Authorization: Bearer quartermaster-dummy-canary")
                .count(),
            1
        );
        assert!(input.contains("X-GitHub-Api-Version: 2022-11-28\r\n"));
        assert!(!input.contains("untrusted-caller-token"));
        assert!(!input.contains("Cookie:"));
        let config = authorizer.github_configuration().unwrap();
        let request = request::read_configured(
            &mut Cursor::new(
                "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n",
            ),
            Some(config),
        )
        .unwrap();
        assert!(
            authorizer
                .authorize(&principal, request, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn github_https_cancel_expiry_policy_session_and_credential_changes_send_zero_application_bytes()
     {
        for change in ["cancel", "expiry", "policy", "session", "credential"] {
            let (mut authorizer, principal, mut registry, id, snapshot, request) =
                prepared(change == "expiry");
            let (address, resume, worker) = peer(true);
            let connection = thread::spawn(move || {
                ReadyGitHub::connect_to(
                    address,
                    client_config(true),
                    Deadline::after(Duration::from_secs(2)).unwrap(),
                )
            });
            match change {
                "cancel" => assert_eq!(
                    registry.cancel(id, &principal),
                    CancellationResult::Canceled
                ),
                "policy" => {
                    authorizer
                        .install(
                            Ok(FixturePolicy::default()),
                            test_support::wall(1000),
                            Instant::now(),
                        )
                        .unwrap();
                }
                "session" => authorizer.revoke_session(),
                _ => {}
            }
            resume.send(()).unwrap();
            let transport = connection.join().unwrap().unwrap();
            let operation = PreparedOperation::github(request, transport).unwrap();
            let replacement = vault::snapshot_with(
                "github-read",
                "33333333-3333-4333-8333-333333333333",
                [9; 16],
            );
            assert!(
                operation
                    .handoff(
                        &mut registry,
                        &mut authorizer,
                        &principal,
                        if change == "credential" {
                            &replacement
                        } else {
                            &snapshot
                        }
                    )
                    .is_err()
            );
            assert!(
                worker.join().unwrap().is_empty(),
                "sent application bytes after {change}"
            );
        }
    }

    #[test]
    fn github_https_tampered_encrypted_records_send_nothing_and_preserve_read_access() {
        let (mut authorizer, principal, mut registry, id, snapshot, request) = prepared(false);
        let (address, _, worker) = peer(false);
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let mut prepared = transport.stage(request).unwrap();
        prepared.records.bytes[0] ^= 1;
        let operation = PreparedOperation::Github(Box::new(prepared));
        assert!(
            operation
                .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
                .is_err()
        );
        assert!(worker.join().unwrap().is_empty());
        assert_eq!(
            registry.cancel(id, &principal),
            CancellationResult::Canceled
        );
        let request = request::read_configured(
            &mut Cursor::new(
                "GET /repos/example/one/issues/42 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n",
            ),
            authorizer.github_configuration(),
        )
        .unwrap();
        assert!(
            authorizer
                .authorize(&principal, request, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn github_https_handshake_timeout_and_untrusted_certificate_never_send_http() {
        for trusted in [false, true] {
            let (address, resume, worker) = peer(trusted);
            let result = ReadyGitHub::connect_to(
                address,
                client_config(trusted),
                Deadline::after(Duration::from_millis(50)).unwrap(),
            );
            assert!(result.is_err());
            if trusted {
                resume.send(()).unwrap();
            }
            assert!(worker.join().unwrap().is_empty());
        }
    }

    #[test]
    fn github_https_metadata_authority_can_only_lookup_the_pinned_repository_and_preserves_issue_access()
     {
        let (mut authorizer, principal, mut registry, id, snapshot, _) = prepared(false);
        let request = crate::owner::execution::prepare_metadata(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        let (address, _, worker) = peer_response(false, Some(123));
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let prepared = transport.stage_metadata(request).unwrap();
        let admission = registry
            .admit_metadata(
                prepared.request(),
                &principal,
                &authorizer,
                &snapshot,
                Instant::now(),
            )
            .unwrap();
        let binding = prepared.handoff(admission).unwrap().response().unwrap();
        let input = String::from_utf8(worker.join().unwrap()).unwrap();
        assert!(input.starts_with("GET /repos/example/one HTTP/1.1\r\n"));
        assert!(!input.contains("/issues/"));
        let request = crate::owner::execution::prepare_github(
            &registry,
            id,
            &principal,
            &authorizer,
            &snapshot,
            binding,
            Instant::now(),
        )
        .unwrap();
        let (address, _, worker) = peer(false);
        let transport = ReadyGitHub::connect_to(
            address,
            client_config(true),
            Deadline::after(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        let prepared = PreparedOperation::github(request, transport).unwrap();
        assert!(matches!(
            prepared
                .handoff(&mut registry, &mut authorizer, &principal, &snapshot)
                .unwrap()
                .response(),
            OperationResponse::Github(_)
        ));
        assert!(!worker.join().unwrap().is_empty());
    }

    #[test]
    fn github_https_metadata_cancellation_and_policy_change_send_zero_application_bytes() {
        for cancel in [true, false] {
            let (mut authorizer, principal, mut registry, id, snapshot, _) = prepared(false);
            let request = crate::owner::execution::prepare_metadata(
                &registry,
                id,
                &principal,
                &authorizer,
                &snapshot,
                Instant::now(),
            )
            .unwrap();
            let (address, _, worker) = peer_response(false, Some(123));
            let transport = ReadyGitHub::connect_to(
                address,
                client_config(true),
                Deadline::after(Duration::from_secs(2)).unwrap(),
            )
            .unwrap();
            let prepared = transport.stage_metadata(request).unwrap();
            if cancel {
                assert_eq!(
                    registry.cancel(id, &principal),
                    CancellationResult::Canceled
                );
            } else {
                authorizer
                    .install(
                        Ok(FixturePolicy::default()),
                        test_support::wall(1000),
                        Instant::now(),
                    )
                    .unwrap();
            }
            assert!(
                registry
                    .admit_metadata(
                        prepared.request(),
                        &principal,
                        &authorizer,
                        &snapshot,
                        Instant::now()
                    )
                    .is_err()
            );
            drop(prepared);
            assert!(worker.join().unwrap().is_empty());
        }
    }

    #[test]
    fn github_https_expired_preparation_does_not_start_dns() {
        let (started, receive) = mpsc::channel();
        assert!(
            resolve_with(Deadline::after(Duration::ZERO).unwrap(), move || {
                started.send(()).unwrap();
                Ok(Vec::new())
            })
            .is_err()
        );
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }

    #[test]
    fn github_https_stalled_dns_keeps_its_worker_reservation_until_lookup_finishes() {
        let mut releases = Vec::new();
        let mut completions = Vec::new();
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let (started, received) = mpsc::sync_channel(0);
            let (release, resume) = mpsc::sync_channel(0);
            let (complete, completed) = mpsc::sync_channel(0);
            waiters.push(thread::spawn(move || {
                resolve_with(
                    Deadline::after(Duration::from_millis(50)).unwrap(),
                    move || {
                        started.send(()).unwrap();
                        resume.recv().unwrap();
                        complete.send(()).unwrap();
                        Ok(vec!["127.0.0.1:443".parse().unwrap()])
                    },
                )
            }));
            received.recv_timeout(Duration::from_secs(1)).unwrap();
            releases.push(release);
            completions.push(completed);
        }
        for waiter in waiters {
            assert!(waiter.join().unwrap().is_err());
        }
        let (started, receive) = mpsc::channel();
        let refused = resolve_with(
            Deadline::after(Duration::from_secs(1)).unwrap(),
            move || {
                started.send(()).unwrap();
                Ok(Vec::new())
            },
        );
        for (release, completed) in releases.into_iter().zip(completions) {
            release.send(()).unwrap();
            completed.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        assert!(refused.is_err());
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        );
    }
}
