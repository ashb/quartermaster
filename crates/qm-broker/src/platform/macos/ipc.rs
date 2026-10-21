use crate::platform::HostSessionEvent;
use qm_macos::cache_key::NativeAuthenticationContext;
use qm_macos::presence_clock::MonotonicTimestamp;
use std::{
    ffi::{CString, c_char, c_void},
    io,
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectionId(u64);

pub(crate) struct Connection<'a> {
    id: ConnectionId,
    raw: *mut c_void,
    context_generation: u64,
    _queue: PhantomData<(&'a (), Rc<()>)>,
}

impl Connection<'_> {
    pub(crate) fn id(&self) -> ConnectionId {
        self.id
    }

    pub(crate) fn release_context(&self) {
        if self.context_generation != 0 {
            unsafe { qm_context_release_lease(self.id.0, self.context_generation) };
        }
    }

    pub(crate) fn context_lease(&self, deadline: MonotonicTimestamp) -> io::Result<ContextLease> {
        if self.context_generation == 0 {
            return Err(io::Error::other("missing native context lease"));
        }
        unsafe { qm_context_expire(self.raw, self.context_generation, deadline.into()) };
        Ok(ContextLease {
            connection: self.id,
            generation: self.context_generation,
        })
    }

    pub(crate) fn is_connected(&self) -> bool {
        unsafe { qm_context_connected(self.raw) }
    }
}

pub(crate) struct ContextLease {
    connection: ConnectionId,
    generation: u64,
}

impl Drop for ContextLease {
    fn drop(&mut self) {
        unsafe { qm_context_release_lease(self.connection.0, self.generation) };
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

type Handler = dyn for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync;
type Callback = unsafe extern "C" fn(
    *mut c_void,
    u64,
    u32,
    *const u8,
    usize,
    u64,
    *mut c_void,
    *mut c_void,
    *mut c_void,
);

unsafe extern "C" {
    fn qm_context_serve(
        service: *const c_char,
        requirement: *const c_char,
        owner: *mut c_void,
        handler: Callback,
    ) -> i32;
    fn qm_context_reply(reply: *mut c_void, bytes: *const u8, length: usize);
    fn qm_context_expire(connection: *mut c_void, generation: u64, deadline: u64);
    fn qm_context_release_lease(connection: u64, generation: u64);
    fn qm_context_connected(connection: *mut c_void) -> bool;
}

unsafe extern "C" fn receive(
    owner: *mut c_void,
    identifier: u64,
    kind: u32,
    bytes: *const u8,
    length: usize,
    context_generation: u64,
    context: *mut c_void,
    peer: *mut c_void,
    reply: *mut c_void,
) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handler = unsafe { &*owner.cast::<Box<Handler>>() };
        if kind == 1 {
            return handler(Event::Disconnected(ConnectionId(identifier)));
        }
        if kind == 2 {
            if bytes.is_null() || length != 1 || !context.is_null() || !peer.is_null() {
                return Err(io::Error::other("invalid host-session event"));
            }
            let event = match unsafe { *bytes } {
                1 => HostSessionEvent::Sleep,
                2 => HostSessionEvent::Wake,
                3 => HostSessionEvent::ScreenLock,
                4 => HostSessionEvent::Inactive,
                5 => HostSessionEvent::Logout,
                _ => return Err(io::Error::other("invalid host-session event")),
            };
            return handler(Event::HostSession(event));
        }
        if kind != 0 || bytes.is_null() || length > 16384 {
            return Err(io::Error::other("invalid native message"));
        }
        let context = if context.is_null() {
            None
        } else {
            // NSXPC decodes only LAContext; this callback borrows it on its serial queue.
            Some(unsafe { NativeAuthenticationContext::from_borrowed(context.cast_const()) })
        };
        handler(Event::Message {
            connection: Connection {
                id: ConnectionId(identifier),
                raw: peer,
                context_generation,
                _queue: PhantomData,
            },
            context,
            payload: unsafe { std::slice::from_raw_parts(bytes, length) },
        })
    }));
    if reply.is_null() {
        return;
    }
    let response = match result {
        Ok(Ok(response)) if response.len() <= 16384 => response,
        _ => {
            if !context.is_null() {
                unsafe { qm_context_release_lease(identifier, context_generation) };
            }
            br#"{"kind":"error"}"#.to_vec()
        }
    };
    unsafe { qm_context_reply(reply, response.as_ptr(), response.len()) };
}

pub(crate) fn serve(
    service: &str,
    requirement: &str,
    handler: impl for<'a> Fn(Event<'a>) -> io::Result<Vec<u8>> + Send + Sync + 'static,
) -> io::Result<()> {
    let service = CString::new(service).map_err(io::Error::other)?;
    let requirement = CString::new(requirement).map_err(io::Error::other)?;
    let mut handler: Box<Handler> = Box::new(handler);
    let code = unsafe {
        qm_context_serve(
            service.as_ptr(),
            requirement.as_ptr(),
            (&raw mut handler).cast(),
            receive,
        )
    };
    Err(io::Error::other(format!(
        "native IPC listener stopped ({code})"
    )))
}
