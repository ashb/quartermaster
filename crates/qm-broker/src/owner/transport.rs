use super::{
    dispatch::PreparedSimulationRequest,
    operation::{Admission, Completion},
    request::{self, Action},
};
use serde::Deserialize;
use std::{
    io::{self, Cursor, Read, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum OperationResponse {
    IssueOpen,
    IssueClosed,
    Denied,
    Uncertain,
    Github(super::github::response::PublicResponse),
    Redirect(Box<ReadRedirect>),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReadRedirect {
    pub(super) target: request::FrozenOperation,
    pub(super) selection: super::dispatch::CredentialSelection,
}

impl OperationResponse {
    pub(super) fn public_parts(&self) -> (String, &[u8]) {
        match self {
            Self::IssueOpen => (
                "200 OK".into(),
                b"{\"number\":42,\"state\":\"open\",\"quartermaster_local_simulation\":true}",
            ),
            Self::IssueClosed => (
                "200 OK".into(),
                b"{\"number\":42,\"state\":\"closed\",\"quartermaster_local_simulation\":true}",
            ),
            Self::Denied => (
                "403 Forbidden".into(),
                b"{\"message\":\"Quartermaster denied this operation\"}",
            ),
            Self::Uncertain => (
                "502 Bad Gateway".into(),
                b"{\"message\":\"The operation's result could not be confirmed\"}",
            ),
            Self::Github(response) => response.public_parts(),
            Self::Redirect(_) => (
                "502 Bad Gateway".into(),
                b"{\"message\":\"Unresolved redirect\"}",
            ),
        }
    }

    pub(super) fn completion(&self) -> Completion {
        if self == &Self::Uncertain {
            Completion::Uncertain
        } else {
            Completion::Completed
        }
    }
}

#[derive(Default)]
struct DummyState {
    closed: bool,
    requests: usize,
    bytes: usize,
}

#[derive(Clone, Default)]
pub(super) struct DummyUpstream(Arc<Mutex<DummyState>>);

impl DummyUpstream {
    pub(super) fn connect(&self) -> io::Result<ReadyHttp> {
        let (client, mut server) = UnixStream::pair()?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        server.set_write_timeout(Some(Duration::from_secs(5)))?;
        let state = Arc::clone(&self.0);
        let worker = thread::spawn(move || {
            let _ = serve_dummy(&mut server, &state);
        });
        ReadyHttp::from_stream(client, worker)
    }
}

pub(super) struct ReadyHttp {
    stream: Option<UnixStream>,
    worker: Option<JoinHandle<()>>,
}

impl ReadyHttp {
    fn from_stream(stream: UnixStream, worker: JoinHandle<()>) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        reserve_socket(&stream, MAX_FRAME)?;
        Ok(Self {
            stream: Some(stream),
            worker: Some(worker),
        })
    }

    /// The exclusive fresh socket holds one bounded frame; no queue or future delays submission.
    pub(super) fn handoff(
        self,
        admission: Admission,
        request: PreparedSimulationRequest,
    ) -> io::Result<InFlightHttp> {
        if request.bytes().len() > MAX_FRAME || !admission.accepts(&request) {
            return Err(io::Error::other("prepared request changed"));
        }
        let bytes = request.bytes();
        let written = unsafe {
            libc::send(
                self.stream.as_ref().unwrap().as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if written < 0 || written as usize != bytes.len() {
            return Err(io::Error::other("uncertain local handoff"));
        }
        Ok(InFlightHttp {
            connection: self,
            action: admission.request().action(),
        })
    }
}

pub(super) fn reserve_socket(socket: &impl AsRawFd, maximum: usize) -> io::Result<()> {
    let capacity: libc::c_int = maximum.max(65536).try_into().map_err(|_| failure())?;
    let mut actual: libc::c_int = 0;
    let mut length = size_of_val(&actual) as libc::socklen_t;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&capacity as *const libc::c_int).cast(),
            size_of_val(&capacity) as libc::socklen_t,
        )
    } != 0
        || unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&mut actual as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut socket = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    if actual < libc::c_int::try_from(maximum).map_err(|_| failure())?
        || length as usize != size_of_val(&actual)
        || unsafe { libc::poll(&mut socket, 1, 0) } != 1
        || socket.revents != libc::POLLOUT
    {
        return Err(io::Error::other("local transport is not ready"));
    }
    Ok(())
}

impl Drop for ReadyHttp {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) struct InFlightHttp {
    connection: ReadyHttp,
    action: Action,
}

impl InFlightHttp {
    pub(super) fn response(mut self) -> OperationResponse {
        let stream = self.connection.stream.as_mut().unwrap();
        if stream.set_nonblocking(false).is_err() {
            return OperationResponse::Uncertain;
        }
        read_response(stream, self.action).unwrap_or(OperationResponse::Uncertain)
    }
}

fn failure() -> io::Error {
    io::Error::other("unsupported local HTTP response")
}

fn content_length(headers: &[httparse::Header<'_>]) -> io::Result<usize> {
    let mut length = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(failure());
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(failure());
            }
            length = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| failure())?
                    .parse::<usize>()
                    .map_err(|_| failure())?,
            );
        }
    }
    length.filter(|length| *length <= 1024).ok_or_else(failure)
}

fn read_frame(stream: &mut UnixStream, bytes: &mut Vec<u8>, request: bool) -> io::Result<usize> {
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= MAX_FRAME {
            return Err(failure());
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    let header_length = bytes.len();
    let length = {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        if request {
            let mut parsed = httparse::Request::new(&mut headers);
            if !parsed.parse(bytes).map_err(|_| failure())?.is_complete()
                || parsed.version != Some(1)
            {
                return Err(failure());
            }
            content_length(parsed.headers)?
        } else {
            let mut parsed = httparse::Response::new(&mut headers);
            if !parsed.parse(bytes).map_err(|_| failure())?.is_complete()
                || parsed.version != Some(1)
            {
                return Err(failure());
            }
            content_length(parsed.headers)?
        }
    };
    let mut buffer = Zeroizing::new([0; 1024]);
    while bytes.len() < header_length + length {
        let remaining = header_length + length - bytes.len();
        let count = stream.read(&mut buffer[..remaining])?;
        if count == 0 {
            return Err(failure());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(header_length)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueResponse {
    number: u32,
    state: IssueState,
    quartermaster_local_simulation: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum IssueState {
    Open,
    Closed,
}

fn read_response(stream: &mut UnixStream, action: Action) -> io::Result<OperationResponse> {
    let mut bytes = Zeroizing::new(Vec::new());
    let header_length = read_frame(stream, &mut bytes, false)?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    parsed
        .parse(&bytes[..header_length])
        .map_err(|_| failure())?;
    match parsed.code {
        Some(401 | 403) => Ok(OperationResponse::Denied),
        Some(200) => {
            let body: IssueResponse =
                serde_json::from_slice(&bytes[header_length..]).map_err(|_| failure())?;
            if body.number != 42 || !body.quartermaster_local_simulation {
                return Err(failure());
            }
            match (action, body.state) {
                (_, IssueState::Closed) => Ok(OperationResponse::IssueClosed),
                (Action::ReadIssue, IssueState::Open) => Ok(OperationResponse::IssueOpen),
                _ => Err(failure()),
            }
        }
        _ => Err(failure()),
    }
}

fn serve_dummy(stream: &mut UnixStream, state: &Mutex<DummyState>) -> io::Result<()> {
    let mut bytes = Zeroizing::new(Vec::new());
    let read = read_frame(stream, &mut bytes, true);
    {
        let mut state = state.lock().map_err(|_| failure())?;
        state.bytes += bytes.len();
        if read.is_ok() {
            state.requests += 1;
        }
    }
    let header_length = read?;
    let operation = request::read(&mut Cursor::new(&bytes[..]))?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed
        .parse(&bytes[..header_length])
        .map_err(|_| failure())?;
    let authorization: Vec<_> = parsed
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("authorization"))
        .collect();
    let response = if authorization.len() != 1
        || authorization[0].value != b"Bearer quartermaster-dummy-canary"
    {
        OperationResponse::Denied
    } else {
        let mut state = state.lock().map_err(|_| failure())?;
        if operation.action() == Action::CloseIssue {
            state.closed = true;
        }
        if state.closed {
            OperationResponse::IssueClosed
        } else {
            OperationResponse::IssueOpen
        }
    };
    let (status, body) = response.public_parts();
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    pub(in crate::owner) enum Reply {
        Lost,
        Redirect,
        Echo,
    }

    pub(in crate::owner) struct Probe {
        requests: Arc<AtomicUsize>,
        bytes: Arc<AtomicUsize>,
    }

    pub(in crate::owner) fn counts(probe: &Probe) -> (usize, usize) {
        (
            probe.requests.load(Ordering::SeqCst),
            probe.bytes.load(Ordering::SeqCst),
        )
    }

    pub(in crate::owner) fn observe(upstream: &DummyUpstream) -> (usize, usize) {
        let state = upstream.0.lock().unwrap();
        (state.requests, state.bytes)
    }

    pub(in crate::owner) fn fault(reply: Reply) -> (ReadyHttp, Probe) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(AtomicUsize::new(0));
        let probe = Probe {
            requests: Arc::clone(&requests),
            bytes: Arc::clone(&bytes),
        };
        let worker = thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Zeroizing::new(Vec::new());
            let received = read_frame(&mut server, &mut request, true);
            bytes.fetch_add(request.len(), Ordering::SeqCst);
            if received.is_err() {
                return;
            }
            requests.fetch_add(1, Ordering::SeqCst);
            let body = match reply {
                Reply::Lost => return,
                Reply::Redirect => {
                    let _ = server.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://github.example.invalid/other\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
                Reply::Echo => b"{\"token\":\"quartermaster-dummy-canary\"}".as_slice(),
            };
            let _ = write!(
                server,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = server.write_all(body);
        });
        (ReadyHttp::from_stream(client, worker).unwrap(), probe)
    }
}
