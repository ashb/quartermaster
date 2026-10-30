use rustls::{
    ServerConfig, ServerConnection,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(crate) struct Server {
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<Vec<String>>>,
}

impl Server {
    pub(crate) fn join(mut self) -> thread::Result<Vec<String>> {
        self.stopped.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) struct Reply {
    status: u16,
    content_type: &'static str,
    headers: String,
    body: Vec<u8>,
    id_bound_body: Option<Vec<u8>>,
    gate: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
}

pub(crate) fn repository(id: u64) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        headers: String::new(),
        body: serde_json::to_vec(&serde_json::json!({"id":id,"full_name":"example/one"})).unwrap(),
        id_bound_body: None,
        gate: None,
    }
}

pub(crate) fn text(body: &str) -> Reply {
    Reply {
        content_type: "application/json",
        ..binary(body.as_bytes().to_vec())
    }
}

pub(crate) fn binary(body: Vec<u8>) -> Reply {
    Reply {
        status: 200,
        content_type: "application/octet-stream",
        headers: String::new(),
        body,
        id_bound_body: None,
        gate: None,
    }
}

pub(crate) fn issue(number: u64) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        headers: String::new(),
        body: serde_json::json!({
            "number":number,"state":"open","title":format!("Actual fixture issue {number}"),
            "url":format!("https://api.github.com/repos/example/one/issues/{number}"),
            "repository_url":"https://api.github.com/repos/example/one"
        })
        .to_string()
        .into_bytes(),
        id_bound_body: None,
        gate: None,
    }
}

pub(crate) fn list() -> Reply {
    list_page(123456, None)
}

pub(crate) fn list_page(number: u64, next: Option<&str>) -> Reply {
    let mut reply = issue(number);
    reply.body = format!("[{}]", String::from_utf8(reply.body).unwrap()).into_bytes();
    if let Some(next) = next {
        reply.headers = format!("Link: <{next}>; rel=\"next\"\r\n");
    }
    reply
}

pub(crate) fn large_issue(number: u64) -> Reply {
    let mut reply = issue(number);
    let mut document: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    document["body"] = "x".repeat(1536 * 1024).into();
    reply.body = serde_json::to_vec(&document).unwrap();
    reply
}
pub(crate) fn redirect(url: &str) -> Reply {
    Reply {
        status: 307,
        content_type: "application/json",
        headers: format!("Location: {url}\r\n"),
        body: Vec::new(),
        id_bound_body: None,
        gate: None,
    }
}
pub(crate) fn unauthorized() -> Reply {
    Reply {
        status: 401,
        content_type: "application/json",
        headers: "X-RateLimit-Remaining: 17\r\n".into(),
        body: b"private upstream authentication detail".to_vec(),
        id_bound_body: None,
        gate: None,
    }
}

pub(crate) fn replaced_repository_issue(number: u64) -> Reply {
    let original = String::from_utf8(issue(number).body)
        .unwrap()
        .replace("Actual fixture issue", "Original repository issue")
        .into_bytes();
    let mut replacement = issue(number);
    replacement.body = String::from_utf8(replacement.body)
        .unwrap()
        .replace("Actual fixture issue", "Recreated repository issue")
        .into_bytes();
    replacement.id_bound_body = Some(original);
    replacement
}

pub(crate) fn serve(replies: Vec<Reply>) -> (SocketAddr, Server) {
    let limit = replies.len();
    let mut replies = replies.into_iter();
    serve_with(false, limit, move |_| replies.next())
}

pub(crate) fn serve_routes(
    storage: bool,
    mut reply: impl FnMut(&str) -> Reply + Send + 'static,
) -> (SocketAddr, Server) {
    serve_with(storage, 128, move |request| Some(reply(request)))
}

fn serve_with(
    storage: bool,
    limit: usize,
    mut reply: impl FnMut(&str) -> Option<Reply> + Send + 'static,
) -> (SocketAddr, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = Arc::clone(&stopped);
    let worker = thread::spawn(move || {
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        if storage {
                            include_bytes!("../../../tests/fixtures/tls/log-storage-cert.der")
                                .as_slice()
                        } else {
                            include_bytes!("../../../tests/fixtures/tls/dummy-cert.der").as_slice()
                        }
                        .to_vec(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        if storage {
                            include_bytes!("../../../tests/fixtures/tls/log-storage-key.der")
                                .as_slice()
                        } else {
                            include_bytes!("../../../tests/fixtures/tls/dummy-key.der").as_slice()
                        }
                        .to_vec(),
                    )),
                )
                .unwrap();
        let config = Arc::new(config);
        let mut requests = Vec::new();
        while requests.len() < limit {
            let (mut socket, _) = loop {
                if worker_stopped.load(Ordering::Relaxed) {
                    return requests;
                }
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    _ => return requests,
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut tls = ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut stream = rustls::Stream::new(&mut tls, &mut socket);
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) if bytes.len() < 8192 => bytes.push(byte[0]),
                    Ok(_) => return requests,
                    Err(error) => panic!("dummy TLS peer read failed: {error}"),
                }
            }
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut parsed = httparse::Request::new(&mut headers);
            parsed.parse(&bytes).unwrap();
            let length = parsed
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |header| {
                    std::str::from_utf8(header.value)
                        .unwrap()
                        .parse::<usize>()
                        .unwrap()
                });
            assert!(length <= 256 * 1024);
            let offset = bytes.len();
            bytes.resize(offset + length, 0);
            stream.read_exact(&mut bytes[offset..]).unwrap();
            let request = String::from_utf8(bytes).unwrap();
            let Some(reply) = reply(&request) else {
                panic!(
                    "unexpected fixture request: {}",
                    request.lines().next().unwrap()
                );
            };
            if let Some((entered, release)) = reply.gate {
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            let body = if request.starts_with("GET /repositories/123/issues/") {
                reply.id_bound_body.as_deref().unwrap_or(&reply.body)
            } else {
                &reply.body
            };
            let head = format!(
                "HTTP/1.1 {} Test\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n",
                reply.status,
                reply.content_type,
                body.len(),
                reply.headers
            );
            let sent = (|| {
                stream.write_all(head.as_bytes())?;
                stream.write_all(body)
            })();
            tls.send_close_notify();
            let _ = tls.write_tls(&mut socket);
            requests.push(request);
            if sent.is_err() {
                return requests;
            }
        }
        requests
    });
    (
        address,
        Server {
            stopped,
            worker: Some(worker),
        },
    )
}

pub(crate) fn gated(mut reply: Reply) -> (Reply, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, proceed) = mpsc::sync_channel(1);
    reply.gate = Some((entered, proceed));
    (reply, waiting, release)
}
