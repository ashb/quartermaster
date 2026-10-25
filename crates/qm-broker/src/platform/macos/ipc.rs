mod context;
mod listener;
mod peer;
mod protocol;
#[cfg(test)]
pub(crate) mod test_support;

use crate::platform::HostSessionEvent;
use context::Generation;
use peer::PeerState;
use qm_macos::{cache_key::NativeAuthenticationContext, presence_clock::MonotonicTimestamp};
use std::{
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Weak, mpsc},
};

const MESSAGE_LIMIT: usize = crate::wire_limits::IPC_PAYLOAD_BYTES;
const REJECTED: &[u8] = br#"{"kind":"error","code":"unavailable"}"#;
type Handler = dyn for<'a> Fn(Event<'a>) -> io::Result<Response> + Send + Sync;

pub(crate) enum Response {
    Immediate(Vec<u8>),
    Deferred(mpsc::Receiver<Vec<u8>>),
}

impl From<Vec<u8>> for Response {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Immediate(bytes)
    }
}

#[derive(Clone)]
pub(crate) struct PeerHandle {
    peer: Weak<PeerState>,
    id: ConnectionId,
}

impl PeerHandle {
    pub(crate) fn id(&self) -> ConnectionId {
        self.id
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.peer.upgrade().is_some_and(|peer| peer.is_connected())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConnectionId(u64);

impl ConnectionId {
    pub(crate) fn value(self) -> u64 {
        self.0
    }
}

pub(crate) struct Connection<'a> {
    peer: &'a Arc<PeerState>,
    generation: Option<Generation>,
    _queue: PhantomData<Rc<()>>,
}

impl Connection<'_> {
    pub(crate) fn id(&self) -> ConnectionId {
        self.peer.id
    }

    pub(crate) fn handle(&self) -> PeerHandle {
        PeerHandle {
            peer: Arc::downgrade(self.peer),
            id: self.id(),
        }
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

pub(crate) fn listen(
    service: &str,
    requirement: &str,
    events: crate::platform::lifecycle::HostEvents,
    handler: impl for<'a> Fn(Event<'a>) -> io::Result<Response> + Send + Sync + 'static,
) -> io::Result<listener::Listener> {
    listener::Listener::new(service, requirement, events, Arc::new(handler))
}
