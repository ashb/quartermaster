use super::{
    Connection, ConnectionId, Event, Handler, MESSAGE_LIMIT, REJECTED,
    context::{ContextQueue, Generation, IncomingContext},
    listener::Server,
    protocol::{QuartermasterContextProtocol, ReplyBlock},
};
use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::{AnyThread, DefinedClass, define_class, msg_send, rc::Retained, runtime::NSObject};
use objc2_foundation::{NSData, NSObjectProtocol, NSXPCConnection};
use objc2_local_authentication::LAContext;
use qm_macos::cache_key::NativeAuthenticationContext;
use std::{
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, Weak},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(super) struct XpcConnection(Retained<NSXPCConnection>);

// NSXPCConnection supports concurrent calls; mutable peer bookkeeping has its own mutex.
unsafe impl Send for XpcConnection {}
unsafe impl Sync for XpcConnection {}

impl XpcConnection {
    pub(super) fn retain(connection: &NSXPCConnection) -> Self {
        Self(
            unsafe { Retained::retain((connection as *const NSXPCConnection).cast_mut()) }.unwrap(),
        )
    }
    pub(super) fn invalidate(&self) {
        self.0.invalidate();
    }
}

struct NativeReply(RcBlock<dyn Fn(std::ptr::NonNull<NSData>)>);

// NSXPC reply blocks may be invoked from another queue; this wrapper is private to native dispatch.
unsafe impl Send for NativeReply {}

impl NativeReply {
    fn send(self, bytes: &[u8]) {
        let data = NSData::with_bytes(if bytes.len() <= MESSAGE_LIMIT {
            bytes
        } else {
            REJECTED
        });
        self.0.call((std::ptr::NonNull::from(&*data),));
    }
}

#[derive(Default)]
struct Admission {
    closed: bool,
    in_flight: usize,
}

pub(super) struct PeerState {
    pub(super) id: ConnectionId,
    pub(super) contexts: ContextQueue,
    pub(super) connection: Mutex<Option<XpcConnection>>,
    pub(super) server: Weak<Server>,
    handler: Arc<Handler>,
    admission: Mutex<Admission>,
    control: DispatchRetained<DispatchQueue>,
}

struct RequestSlot(Arc<PeerState>);

impl Drop for RequestSlot {
    fn drop(&mut self) {
        self.0.admission.lock().unwrap().in_flight -= 1;
    }
}

impl PeerState {
    pub(super) fn new(
        id: ConnectionId,
        connection: &NSXPCConnection,
        server: &Arc<Server>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            contexts: ContextQueue::new(),
            connection: Mutex::new(Some(XpcConnection::retain(connection))),
            server: Arc::downgrade(server),
            handler: Arc::clone(&server.handler),
            admission: Mutex::default(),
            control: DispatchQueue::new("dev.quartermaster.control", None),
        })
    }

    pub(super) fn is_connected(&self) -> bool {
        !self.admission.lock().unwrap().closed
    }

    fn reserve(self: &Arc<Self>) -> Option<RequestSlot> {
        let mut state = self.admission.lock().unwrap();
        if state.closed || state.in_flight >= 4 {
            return None;
        }
        state.in_flight += 1;
        Some(RequestSlot(Arc::clone(self)))
    }

    pub(super) fn disconnect(&self) {
        {
            let mut state = self.admission.lock().unwrap();
            if state.closed {
                return;
            }
            state.closed = true;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            (self.handler)(Event::Disconnected(self.id))
        }));
        self.contexts.clear();
    }

    pub(super) fn invalidate(&self) {
        let connection = self.connection.lock().unwrap().clone();
        if let Some(connection) = connection.as_ref() {
            connection.invalidate();
        }
    }

    fn invoke(
        self: &Arc<Self>,
        payload: &[u8],
        authenticated: Option<(Generation, &LAContext)>,
        reply: NativeReply,
    ) {
        if !self.is_connected() {
            if let Some((generation, _)) = authenticated {
                self.contexts.release(generation);
            }
            reply.send(REJECTED);
            return;
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            let context = authenticated.map(|(_, context)| {
                // The context stays borrowed on this peer's serial context queue.
                unsafe {
                    NativeAuthenticationContext::from_borrowed((context as *const LAContext).cast())
                }
            });
            (self.handler)(Event::Message {
                connection: Connection {
                    peer: self,
                    generation: authenticated.map(|(generation, _)| generation),
                    _queue: PhantomData,
                },
                context,
                payload,
            })
        }));
        let response = match result {
            Ok(Ok(response)) if response.len() <= MESSAGE_LIMIT => response,
            _ => {
                if let Some((generation, _)) = authenticated {
                    self.contexts.release(generation);
                }
                REJECTED.to_vec()
            }
        };
        reply.send(&response);
    }

    fn submit(
        self: &Arc<Self>,
        message: Option<&NSData>,
        context: Option<IncomingContext>,
        reply: &ReplyBlock,
    ) {
        let reply = NativeReply(reply.copy());
        let Some(message) = message.filter(|message| message.len() <= MESSAGE_LIMIT) else {
            reply.send(REJECTED);
            return;
        };
        let Some(slot) = self.reserve() else {
            reply.send(REJECTED);
            return;
        };
        let payload = Zeroizing::new(message.to_vec());
        match context {
            Some(context) => {
                self.contexts
                    .authenticate(context, move |authenticated| match authenticated {
                        Some(authenticated) => slot.0.invoke(&payload, Some(authenticated), reply),
                        None => reply.send(REJECTED),
                    })
            }
            None => self.control.exec_async(move || {
                objc2::rc::autoreleasepool(|_| {
                    slot.0.invoke(&payload, None, reply);
                });
            }),
        }
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[name = "QuartermasterRustPeer"]
    #[ivars = Arc<PeerState>]
    pub(super) struct Peer;

    unsafe impl NSObjectProtocol for Peer {}

    unsafe impl QuartermasterContextProtocol for Peer {
        #[unsafe(method(send:reply:))]
        fn send(&self, message: Option<&NSData>, reply: Option<&ReplyBlock>) {
            if let Some(reply) = reply { self.ivars().submit(message, None, reply); }
        }

        #[unsafe(method(authenticate:context:reply:))]
        fn authenticate(&self, message: Option<&NSData>, context: Option<&LAContext>, reply: Option<&ReplyBlock>) {
            let Some(reply) = reply else { return; };
            match context {
                Some(context) => self.ivars().submit(message, Some(IncomingContext::retain(context)), reply),
                None => NativeReply(reply.copy()).send(REJECTED),
            }
        }
    }
);

impl Peer {
    pub(super) fn new(state: Arc<PeerState>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(state);
        unsafe { msg_send![super(this), init] }
    }
}
