use super::{
    ConnectionId, Event, Handler,
    peer::{Peer, PeerState},
    protocol,
};
use crate::platform::HostSessionEvent;
use block2::RcBlock;
use objc2::{
    AnyThread, DefinedClass, define_class, msg_send,
    rc::Retained,
    runtime::{NSObject, ProtocolObject},
    sel,
};
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceDidWakeNotification, NSWorkspaceSessionDidResignActiveNotification,
    NSWorkspaceWillPowerOffNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSDistributedNotificationCenter, NSNotification, NSNotificationCenter,
    NSNotificationSuspensionBehavior, NSObjectProtocol, NSString, NSXPCConnection, NSXPCListener,
    NSXPCListenerDelegate,
};
use std::{
    collections::BTreeMap,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);
static SERVING: AtomicBool = AtomicBool::new(false);

pub(super) struct Server {
    pub(super) handler: Arc<Handler>,
    peers: Mutex<BTreeMap<ConnectionId, Arc<PeerState>>>,
    closed: AtomicBool,
}

impl Server {
    pub(super) fn new(handler: Arc<Handler>) -> Arc<Self> {
        Arc::new(Self {
            handler,
            peers: Mutex::default(),
            closed: AtomicBool::new(false),
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let peers = std::mem::take(&mut *self.peers.lock().unwrap());
        for peer in peers.into_values() {
            peer.disconnect();
            peer.invalidate();
        }
    }

    fn host_event(&self, event: HostSessionEvent) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            (self.handler)(Event::HostSession(event))
        }));
        let peers: Vec<_> = self.peers.lock().unwrap().values().cloned().collect();
        for peer in peers {
            peer.disconnect();
            peer.invalidate();
        }
    }

    fn accept(self: &Arc<Self>, connection: &NSXPCConnection) -> bool {
        if connection.effectiveUserIdentifier() != unsafe { libc::geteuid() } {
            return false;
        }
        let mut peers = self.peers.lock().unwrap();
        if self.closed.load(Ordering::Acquire) || peers.len() >= 4 {
            return false;
        }
        let Ok(identifier) =
            NEXT_CONNECTION.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
        else {
            return false;
        };
        let interface = protocol::interface();
        let state = PeerState::new(ConnectionId(identifier), connection, self);
        let peer = Peer::new(Arc::clone(&state));
        peers.insert(state.id, Arc::clone(&state));
        drop(peers);
        let weak = Arc::downgrade(&state);
        let interrupted = RcBlock::new(move || {
            if let Some(state) = weak.upgrade() {
                state.disconnect();
                state.invalidate();
            }
        });
        let weak = Arc::downgrade(&state);
        let invalidated = RcBlock::new(move || {
            if let Some(state) = weak.upgrade() {
                state.disconnect();
                if let Some(server) = state.server.upgrade() {
                    server.peers.lock().unwrap().remove(&state.id);
                }
                let connection = state.connection.lock().unwrap().take();
                drop(connection);
            }
        });
        connection.setInterruptionHandler(Some(&interrupted));
        connection.setInvalidationHandler(Some(&invalidated));
        connection.setExportedInterface(Some(&interface));
        unsafe {
            connection.setExportedObject(Some(&peer));
        }
        connection.resume();
        true
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[name = "QuartermasterRustListener"]
    #[ivars = Arc<Server>]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl NSXPCListenerDelegate for Delegate {
        #[allow(non_snake_case)]
        #[unsafe(method(listener:shouldAcceptNewConnection:))]
        fn listener_shouldAcceptNewConnection(&self, _listener: &NSXPCListener, connection: &NSXPCConnection) -> bool {
            self.ivars().accept(connection)
        }
    }

    impl Delegate {
        #[unsafe(method(workspaceEvent:))]
        fn workspace_event(&self, notification: &NSNotification) {
            let name = notification.name();
            let event = unsafe {
                if &*name == NSWorkspaceWillSleepNotification { HostSessionEvent::Sleep }
                else if &*name == NSWorkspaceDidWakeNotification { HostSessionEvent::Wake }
                else if &*name == NSWorkspaceSessionDidResignActiveNotification { HostSessionEvent::Inactive }
                else if &*name == NSWorkspaceWillPowerOffNotification { HostSessionEvent::Logout }
                else { return; }
            };
            self.ivars().host_event(event);
        }

        #[unsafe(method(screenLocked:))]
        fn screen_locked(&self, _notification: &NSNotification) {
            self.ivars().host_event(HostSessionEvent::ScreenLock);
        }
    }
);

impl Delegate {
    fn new(state: Arc<Server>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(state);
        unsafe { msg_send![super(this), init] }
    }
}

pub(super) struct Listener {
    listener: Retained<NSXPCListener>,
    delegate: Retained<Delegate>,
    workspace: Retained<NSNotificationCenter>,
    distributed: Retained<NSDistributedNotificationCenter>,
}

impl Listener {
    pub(super) fn new(service: &str, requirement: &str, handler: Arc<Handler>) -> io::Result<Self> {
        if service.contains('\0') || requirement.contains('\0') {
            return Err(io::Error::other("invalid native listener configuration"));
        }
        if SERVING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::other("native listener already running"));
        }
        let listener = NSXPCListener::initWithMachServiceName(
            NSXPCListener::alloc(),
            &NSString::from_str(service),
        );
        listener.setConnectionCodeSigningRequirement(&NSString::from_str(requirement));
        let delegate = Delegate::new(Server::new(handler));
        let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        unsafe {
            for name in [
                NSWorkspaceWillSleepNotification,
                NSWorkspaceDidWakeNotification,
                NSWorkspaceSessionDidResignActiveNotification,
                NSWorkspaceWillPowerOffNotification,
            ] {
                workspace.addObserver_selector_name_object(
                    &delegate,
                    sel!(workspaceEvent:),
                    Some(name),
                    None,
                );
            }
            distributed.addObserver_selector_name_object_suspensionBehavior(
                &delegate,
                sel!(screenLocked:),
                Some(&NSString::from_str("com.apple.screenIsLocked")),
                None,
                NSNotificationSuspensionBehavior::DeliverImmediately,
            );
        }
        listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        listener.resume();
        Ok(Self {
            listener,
            delegate,
            workspace,
            distributed,
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let server = self.delegate.ivars();
        server.close();
        self.listener.invalidate();
        unsafe {
            self.workspace.removeObserver(&self.delegate);
            self.distributed.removeObserver(&self.delegate);
        }
        SERVING.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ContextLease, MESSAGE_LIMIT, REJECTED, protocol::QuartermasterContextProtocol,
    };
    use super::*;
    use block2::ManualBlockEncoding;
    use objc2::{rc::Retained, runtime::ProtocolObject};
    use objc2_foundation::NSData;
    use objc2_local_authentication::LAContext;
    use std::{
        sync::{atomic::AtomicUsize, mpsc},
        time::{Duration, Instant},
    };

    struct Fixture {
        listener: Retained<NSXPCListener>,
        _delegate: Retained<Delegate>,
        server: Arc<Server>,
    }

    impl Fixture {
        fn new(
            handler: impl for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
        ) -> Self {
            let requirement =
                qm_macos::peer_identity::requirement_for_path(&std::env::current_exe().unwrap())
                    .unwrap();
            Self::with_requirement(handler, &requirement)
        }

        fn with_requirement(
            handler: impl for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
            requirement: &str,
        ) -> Self {
            let listener = NSXPCListener::anonymousListener();
            listener.setConnectionCodeSigningRequirement(&NSString::from_str(requirement));
            let server = Server::new(Arc::new(handler));
            let delegate = Delegate::new(Arc::clone(&server));
            listener.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            listener.resume();
            Self {
                listener,
                _delegate: delegate,
                server,
            }
        }

        fn client(&self) -> Retained<NSXPCConnection> {
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

    struct DataReplyEncoding;

    // XPC requires the concrete object class in the reply block's argument metadata.
    unsafe impl ManualBlockEncoding for DataReplyEncoding {
        type Arguments = (std::ptr::NonNull<NSData>,);
        type Return = ();
        const ENCODING_CSTR: &'static std::ffi::CStr = cr#"v16@?0@"NSData"8"#;
    }

    fn start_send(
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

    fn send(client: &NSXPCConnection, bytes: &[u8], context: Option<&LAContext>) -> Vec<u8> {
        start_send(client, bytes, context)
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn missing_native_arguments_cannot_reach_the_handler() {
        let called = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&called);
        let fixture = Fixture::new(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        });
        let client = fixture.client();
        let peer = Peer::new(PeerState::new(ConnectionId(0), &client, &fixture.server));
        let (send, receive) = mpsc::sync_channel(2);
        let reply = RcBlock::with_encoding::<_, _, _, DataReplyEncoding>(
            move |data: std::ptr::NonNull<NSData>| {
                send.send(unsafe { data.as_ref() }.to_vec()).unwrap();
            },
        );
        let message = NSData::with_bytes(b"missing argument");
        peer.send(None, Some(&reply));
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            REJECTED
        );
        peer.authenticate(Some(&message), None, Some(&reply));
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            REJECTED
        );
        peer.send(Some(&message), None);
        let context = unsafe { LAContext::new() };
        peer.authenticate(Some(&message), Some(&context), None);
        assert_eq!(called.load(Ordering::Relaxed), 0);
        client.invalidate();
    }

    #[test]
    fn native_xpc_roundtrip_carries_data_and_one_queue_confined_context_without_authentication() {
        let lease: Arc<Mutex<Option<ContextLease>>> = Arc::default();
        let retained = Arc::clone(&lease);
        let fixture = Fixture::new(move |event| {
            let Event::Message {
                connection,
                context,
                payload,
            } = event
            else {
                return Ok(Vec::new());
            };
            if payload == b"release" {
                retained.lock().unwrap().take();
            }
            if context.is_some() {
                *retained.lock().unwrap() = Some(
                    connection.context_lease(
                        qm_macos::presence_clock::monotonic_raw()?
                            .checked_add(Duration::from_secs(5))
                            .unwrap(),
                    )?,
                );
            }
            Ok(if context.is_some() {
                b"context".to_vec()
            } else {
                payload.to_vec()
            })
        });
        let client = fixture.client();
        assert_eq!(send(&client, b"plain", None), b"plain");
        let context = unsafe { LAContext::new() };
        assert_eq!(send(&client, b"first", Some(&context)), b"context");
        assert_eq!(send(&client, b"duplicate", Some(&context)), REJECTED);
        assert_eq!(send(&client, b"release", None), b"release");
        let second = unsafe { LAContext::new() };
        assert_eq!(send(&client, b"second", Some(&second)), b"context");
        client.invalidate();
    }

    #[test]
    fn oversized_xpc_requests_and_replies_are_rejected_without_exposing_handler_data() {
        let called = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&called);
        let fixture = Fixture::new(move |event| {
            if matches!(event, Event::Message { .. }) {
                observed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(vec![b'x'; MESSAGE_LIMIT + 1])
        });
        let client = fixture.client();
        assert_eq!(
            send(&client, &vec![b'x'; MESSAGE_LIMIT + 1], None),
            REJECTED
        );
        assert_eq!(called.load(Ordering::Relaxed), 0);
        assert_eq!(send(&client, b"allowed input", None), REJECTED);
        assert_eq!(called.load(Ordering::Relaxed), 1);
        client.invalidate();
    }

    #[test]
    fn invalidation_notifies_once_and_releases_the_peer_slot() {
        let disconnected = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&disconnected);
        let fixture = Fixture::new(move |event| {
            if matches!(event, Event::Disconnected(_)) {
                observed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Vec::new())
        });
        let client = fixture.client();
        send(&client, b"connected", None);
        assert_eq!(fixture.server.peers.lock().unwrap().len(), 1);
        client.invalidate();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.server.peers.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(fixture.server.peers.lock().unwrap().is_empty());
        assert_eq!(disconnected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn code_requirement_and_connection_limit_are_enforced_before_message_delivery() {
        let denied = Fixture::with_requirement(
            |_| panic!("rejected peer reached handler"),
            "identifier \"quartermaster.no-such-client\"",
        );
        let client = denied.client();
        assert!(
            start_send(&client, b"denied", None)
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_err()
        );
        assert!(denied.server.peers.lock().unwrap().is_empty());
        client.invalidate();

        let fixture = Fixture::new(|_| Ok(Vec::new()));
        let mut clients = Vec::new();
        for _ in 0..4 {
            let client = fixture.client();
            send(&client, b"admitted", None);
            clients.push(client);
        }
        let rejected = fixture.client();
        assert!(
            start_send(&rejected, b"over limit", None)
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.server.peers.lock().unwrap().len(), 4);
        rejected.invalidate();
        for client in clients {
            client.invalidate();
        }
    }

    #[test]
    fn a_stalled_control_message_keeps_at_most_four_requests_in_flight_and_releases_capacity() {
        let (entered, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let wait = Mutex::new(wait);
        let fixture = Fixture::new(move |event| {
            let Event::Message { payload, .. } = event else {
                return Ok(Vec::new());
            };
            if payload == b"blocked" {
                entered.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(payload.to_vec())
        });
        let client = fixture.client();
        let mut pending = vec![start_send(&client, b"blocked", None)];
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        for _ in 0..3 {
            pending.push(start_send(&client, b"queued", None));
        }
        let excess = start_send(&client, b"excess", None).recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        assert_eq!(excess.unwrap().unwrap(), REJECTED);
        for reply in pending {
            assert_ne!(
                reply.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
                REJECTED
            );
        }
        assert_eq!(send(&client, b"available", None), b"available");
        client.invalidate();
    }

    #[test]
    fn failed_or_panicking_context_handlers_reject_the_request_and_release_the_context() {
        for panic in [false, true] {
            let called = AtomicUsize::new(0);
            let fixture = Fixture::new(move |event| {
                if !matches!(event, Event::Message { .. }) {
                    return Ok(Vec::new());
                }
                if called.fetch_add(1, Ordering::Relaxed) == 0 {
                    assert!(!panic, "dummy handler failure");
                    return Err(io::Error::other("dummy handler failure"));
                }
                Ok(b"accepted".to_vec())
            });
            let client = fixture.client();
            let first = unsafe { LAContext::new() };
            assert_eq!(send(&client, b"fail", Some(&first)), REJECTED);
            let second = unsafe { LAContext::new() };
            assert_eq!(send(&client, b"retry", Some(&second)), b"accepted");
            client.invalidate();
        }
    }
}
