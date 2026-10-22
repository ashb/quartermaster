mod context;
mod listener;
mod peer;
mod protocol;

use crate::platform::HostSessionEvent;
use context::Generation;
use peer::PeerState;
use qm_macos::{cache_key::NativeAuthenticationContext, presence_clock::MonotonicTimestamp};
use std::{
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Weak},
};

const MESSAGE_LIMIT: usize = 16_384;
const REJECTED: &[u8] = br#"{"kind":"error"}"#;
type Handler = dyn for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConnectionId(u64);

pub(crate) struct Connection<'a> {
    peer: &'a Arc<PeerState>,
    generation: Option<Generation>,
    _queue: PhantomData<Rc<()>>,
}

impl Connection<'_> {
    pub(crate) fn id(&self) -> ConnectionId {
        self.peer.id
    }

    pub(crate) fn release_context(&self) {
        if let Some(generation) = self.generation {
            self.peer.contexts.release(generation);
        }
    }

    pub(crate) fn context_lease(&self, deadline: MonotonicTimestamp) -> io::Result<ContextLease> {
        let generation = self
            .generation
            .ok_or_else(|| io::Error::other("missing native context lease"))?;
        self.peer.contexts.shorten(generation, deadline);
        Ok(ContextLease {
            peer: Arc::downgrade(self.peer),
            generation,
        })
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.peer.is_connected()
    }
}

pub(crate) struct ContextLease {
    peer: Weak<PeerState>,
    generation: Generation,
}

impl Drop for ContextLease {
    fn drop(&mut self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.contexts.release(self.generation);
        }
    }
}

pub(crate) enum Event<'a> {
    Message {
        connection: Connection<'a>,
        context: Option<NativeAuthenticationContext<'a>>,
        payload: &'a [u8],
    },
    Disconnected(ConnectionId),
    HostSession(HostSessionEvent),
}

pub(crate) fn serve(
    service: &str,
    requirement: &str,
    handler: impl for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
) -> io::Result<()> {
    let _listener = listener::Listener::new(service, requirement, Arc::new(handler))?;
    loop {
        objc2::rc::autoreleasepool(|_| {
            let until = objc2_foundation::NSDate::dateWithTimeIntervalSinceNow(60.0);
            objc2_foundation::NSRunLoop::currentRunLoop().runUntilDate(&until);
        });
    }
}
