use core_foundation::{
    base::TCFType,
    runloop::{
        CFRunLoop, CFRunLoopSource, CFRunLoopSourceContext, CFRunLoopSourceCreate,
        CFRunLoopSourceInvalidate, CFRunLoopSourceSignal, CFRunLoopWakeUp, kCFRunLoopDefaultMode,
    },
};
use std::{
    ffi::c_void,
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct State {
    run_loop: CFRunLoop,
    stopped: AtomicBool,
}

pub(crate) struct EventLoop {
    wake: Arc<Wake>,
    _thread: PhantomData<Rc<()>>,
}

#[derive(Clone)]
pub(crate) struct Stop(Arc<Wake>);

struct Wake {
    source: CFRunLoopSource,
    state: Arc<State>,
}

// A version-zero source can be signalled from any thread. Its callback uses only
// the atomic stop flag and the thread-safe CFRunLoop handle.
unsafe impl Send for Wake {}
unsafe impl Sync for Wake {}

extern "C" fn retain_state(info: *const c_void) -> *const c_void {
    unsafe { Arc::increment_strong_count(info.cast::<State>()) };
    info
}

extern "C" fn release_state(info: *const c_void) {
    unsafe { Arc::decrement_strong_count(info.cast::<State>()) };
}

extern "C" fn perform(info: *const c_void) {
    let state = unsafe { &*info.cast::<State>() };
    if state.stopped.load(Ordering::Acquire) {
        state.run_loop.stop();
    }
}

impl EventLoop {
    pub(crate) fn new() -> io::Result<Self> {
        let state = Arc::new(State {
            run_loop: CFRunLoop::get_current(),
            stopped: AtomicBool::new(false),
        });
        let mut context = CFRunLoopSourceContext {
            version: 0,
            info: Arc::as_ptr(&state).cast_mut().cast(),
            retain: Some(retain_state),
            release: Some(release_state),
            copyDescription: None,
            equal: None,
            hash: None,
            schedule: None,
            cancel: None,
            perform,
        };
        let source = unsafe { CFRunLoopSourceCreate(std::ptr::null(), 0, &mut context) };
        if source.is_null() {
            return Err(io::Error::other("native event source unavailable"));
        }
        let source = unsafe { CFRunLoopSource::wrap_under_create_rule(source) };
        state
            .run_loop
            .add_source(&source, unsafe { kCFRunLoopDefaultMode });
        Ok(Self {
            wake: Arc::new(Wake { source, state }),
            _thread: PhantomData,
        })
    }

    pub(crate) fn stop_handle(&self) -> Stop {
        Stop(Arc::clone(&self.wake))
    }

    pub(crate) fn run(&self) -> io::Result<()> {
        if self.wake.state.stopped.load(Ordering::Acquire) {
            return Ok(());
        }
        objc2::rc::autoreleasepool(|_| CFRunLoop::run_current());
        if self.wake.state.stopped.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::other("native event loop stopped unexpectedly"))
        }
    }
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        unsafe { CFRunLoopSourceInvalidate(self.wake.source.as_concrete_TypeRef()) };
    }
}

impl Stop {
    pub(crate) fn stop(&self) {
        self.0.state.stopped.store(true, Ordering::Release);
        unsafe {
            CFRunLoopSourceSignal(self.0.source.as_concrete_TypeRef());
            CFRunLoopWakeUp(self.0.state.run_loop.as_concrete_TypeRef());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::{base::TCFType, runloop::CFRunLoopIsWaiting};
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn idle_native_loop_waits_for_a_source_and_stops_promptly() {
        let (send, receive) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let event_loop = EventLoop::new().unwrap();
            send.send(event_loop.stop_handle()).unwrap();
            event_loop.run().unwrap();
        });
        let stop = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        let waiting = loop {
            if unsafe { CFRunLoopIsWaiting(stop.0.state.run_loop.as_concrete_TypeRef()) } != 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(1));
        };
        let stopped = Instant::now();
        stop.stop();
        worker.join().unwrap();
        assert!(waiting, "native loop never blocked waiting for an event");
        assert!(stopped.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stopping_before_the_loop_starts_does_not_get_lost() {
        let event_loop = EventLoop::new().unwrap();
        event_loop.stop_handle().stop();
        event_loop.run().unwrap();
    }

    #[test]
    fn source_loss_is_an_error_instead_of_an_empty_loop_spin() {
        let event_loop = EventLoop::new().unwrap();
        unsafe { CFRunLoopSourceInvalidate(event_loop.wake.source.as_concrete_TypeRef()) };
        assert!(event_loop.run().is_err());
    }
}
