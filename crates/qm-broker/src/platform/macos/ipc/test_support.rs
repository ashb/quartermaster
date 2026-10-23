use super::{
    Event, Response,
    listener::{Delegate, Server},
    protocol::{self, QuartermasterContextProtocol},
};
use crate::platform::lifecycle::HostEvents;
use block2::{ManualBlockEncoding, RcBlock};
use objc2::{AnyThread, rc::Retained, runtime::ProtocolObject};
use objc2_foundation::{NSData, NSString, NSXPCConnection, NSXPCListener};
use objc2_local_authentication::LAContext;
use std::{
    io,
    sync::{Arc, mpsc},
    time::Duration,
};

pub(crate) struct Fixture {
    listener: Retained<NSXPCListener>,
    _delegate: Retained<Delegate>,
    pub(super) server: Arc<Server>,
}

impl Fixture {
    pub(crate) fn new<R: Into<Response> + 'static>(
        handler: impl for<'a> Fn(Event<'a>) -> io::Result<R> + Send + Sync + 'static,
    ) -> Self {
        let requirement =
            qm_macos::peer_identity::requirement_for_path(&std::env::current_exe().unwrap())
                .unwrap();
        Self::with_requirement(handler, &requirement)
    }

    pub(super) fn with_requirement<R: Into<Response> + 'static>(
        handler: impl for<'a> Fn(Event<'a>) -> io::Result<R> + Send + Sync + 'static,
        requirement: &str,
    ) -> Self {
        let listener = NSXPCListener::anonymousListener();
        listener.setConnectionCodeSigningRequirement(&NSString::from_str(requirement));
        let server = Server::new(
            HostEvents::default(),
            Arc::new(move |event| handler(event).map(Into::into)),
        );
        let delegate = Delegate::new(Arc::clone(&server));
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        listener.resume();
        Self {
            listener,
            _delegate: delegate,
            server,
        }
    }

    pub(crate) fn client(&self) -> Retained<NSXPCConnection> {
        let client = NSXPCConnection::initWithListenerEndpoint(
            NSXPCConnection::alloc(),
            &self.listener.endpoint(),
        );
        client.setRemoteObjectInterface(Some(&protocol::interface()));
        client.resume();
        client
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.close();
        self.listener.invalidate();
    }
}

pub(super) struct DataReplyEncoding;

// XPC requires the concrete object class in the reply block's argument metadata.
unsafe impl ManualBlockEncoding for DataReplyEncoding {
    type Arguments = (std::ptr::NonNull<NSData>,);
    type Return = ();
    const ENCODING_CSTR: &'static std::ffi::CStr = cr#"v16@?0@"NSData"8"#;
}

pub(crate) fn start_send(
    client: &NSXPCConnection,
    bytes: &[u8],
    context: Option<&LAContext>,
) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (send, receive) = mpsc::sync_channel(1);
    let failed = send.clone();
    let error = RcBlock::new(move |_: std::ptr::NonNull<objc2_foundation::NSError>| {
        let _ = failed.send(Err(io::Error::other("native XPC request failed")));
    });
    let reply = RcBlock::with_encoding::<_, _, _, DataReplyEncoding>(
        move |data: std::ptr::NonNull<NSData>| {
            let _ = send.send(Ok(unsafe { data.as_ref() }.to_vec()));
        },
    );
    let proxy: Retained<ProtocolObject<dyn QuartermasterContextProtocol>> =
        unsafe { Retained::cast_unchecked(client.remoteObjectProxyWithErrorHandler(&error)) };
    let message = NSData::with_bytes(bytes);
    match context {
        Some(context) => proxy.authenticate(Some(&message), Some(context), Some(&reply)),
        None => proxy.send(Some(&message), Some(&reply)),
    }
    receive
}

pub(crate) fn send(client: &NSXPCConnection, bytes: &[u8], context: Option<&LAContext>) -> Vec<u8> {
    start_send(client, bytes, context)
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap()
}
