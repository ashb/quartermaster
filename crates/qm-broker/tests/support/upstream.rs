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
