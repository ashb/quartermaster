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
    headers: String,
    body: String,
    id_bound_body: Option<String>,
}

pub(crate) fn repository(id: u64) -> Reply {
    Reply {
        status: 200,
        headers: String::new(),
        body: serde_json::json!({"id":id,"full_name":"example/one"}).to_string(),
        id_bound_body: None,
    }
}

pub(crate) fn issue(number: u64) -> Reply {
    Reply {
        status: 200,
        headers: String::new(),
        body: serde_json::json!({
            "number":number,"state":"open","title":format!("Actual fixture issue {number}"),
            "url":format!("https://api.github.com/repos/example/one/issues/{number}"),
            "repository_url":"https://api.github.com/repos/example/one"
        })
        .to_string(),
        id_bound_body: None,
    }
}

pub(crate) fn list() -> Reply {
    list_page(123456, None)
}

pub(crate) fn list_page(number: u64, next: Option<&str>) -> Reply {
    let mut reply = issue(number);
    reply.body = format!("[{}]", reply.body);
    if let Some(next) = next {
        reply.headers = format!("Link: <{next}>; rel=\"next\"\r\n");
    }
    reply
}

pub(crate) fn large_issue(number: u64) -> Reply {
    let mut reply = issue(number);
    let mut document: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    document["body"] = "x".repeat(1536 * 1024).into();
    reply.body = document.to_string();
    reply
}
pub(crate) fn redirect(url: &str) -> Reply {
    Reply {
        status: 307,
        headers: format!("Location: {url}\r\n"),
        body: String::new(),
        id_bound_body: None,
    }
}
pub(crate) fn unauthorized() -> Reply {
    Reply {
        status: 401,
        headers: "X-RateLimit-Remaining: 17\r\n".into(),
        body: "private upstream authentication detail".into(),
        id_bound_body: None,
    }
}

pub(crate) fn replaced_repository_issue(number: u64) -> Reply {
    let original = issue(number)
        .body
        .replace("Actual fixture issue", "Original repository issue");
    let mut replacement = issue(number);
    replacement.body = replacement
        .body
        .replace("Actual fixture issue", "Recreated repository issue");
    replacement.id_bound_body = Some(original);
    replacement
}

pub(crate) fn serve(replies: Vec<Reply>) -> (SocketAddr, Server) {
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
                        include_bytes!("../fixtures/tls/dummy-cert.der").to_vec(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        include_bytes!("../fixtures/tls/dummy-key.der").to_vec(),
                    )),
                )
                .unwrap();
        let config = Arc::new(config);
        let mut requests = Vec::new();
        for reply in replies {
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
            let request = String::from_utf8(bytes).unwrap();
            let body = if request.starts_with("GET /repositories/123/issues/") {
                reply.id_bound_body.as_deref().unwrap_or(&reply.body)
            } else {
                &reply.body
            };
            write!(stream, "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{}", reply.status, body.len(), reply.headers, body).unwrap();
            requests.push(request);
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
