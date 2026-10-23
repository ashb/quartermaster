use dispatch2::{DispatchQueue, DispatchRetained, DispatchTime};
use objc2::rc::Retained;
use objc2_local_authentication::LAContext;
use qm_macos::presence_clock::{MonotonicTimestamp, monotonic_raw};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

const CONTEXT_LIFETIME: Duration = Duration::from_secs(30);

pub(super) struct IncomingContext(Retained<LAContext>);

// XPC hands ownership to the serial context queue; no subsequent shared access is exposed.
unsafe impl Send for IncomingContext {}

impl IncomingContext {
    pub(super) fn retain(context: &LAContext) -> Self {
        Self(unsafe { Retained::retain((context as *const LAContext).cast_mut()) }.unwrap())
    }
    fn into_inner(self) -> Retained<LAContext> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Generation(u64);

struct Lease {
    context: Retained<LAContext>,
    deadline: MonotonicTimestamp,
}

impl Drop for Lease {
    fn drop(&mut self) {
        unsafe {
            self.context.invalidate();
        }
    }
}

#[derive(Default)]
struct Slot {
    generation: u64,
    lease: Option<Lease>,
}

// Slot access and final context invalidation are confined to the owning serial queue.
unsafe impl Send for Slot {}

impl Slot {
    fn install(
        &mut self,
        context: Retained<LAContext>,
        now: MonotonicTimestamp,
    ) -> Option<Generation> {
        if self
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.deadline)
        {
            self.lease.take();
        }
        if self.lease.is_some() {
            return None;
        }
        let generation = self.generation.checked_add(1)?;
        let deadline = now.checked_add(CONTEXT_LIFETIME)?;
        unsafe {
            context.setInteractionNotAllowed(true);
        }
        self.generation = generation;
        self.lease = Some(Lease { context, deadline });
        Some(Generation(generation))
    }

    fn expire(
        &mut self,
        generation: Generation,
        deadline: MonotonicTimestamp,
        now: MonotonicTimestamp,
    ) -> Option<Duration> {
        if self.generation != generation.0 {
            return None;
        }
        let lease = self.lease.as_mut()?;
        lease.deadline = lease.deadline.min(deadline);
        let remaining = lease
            .deadline
            .checked_duration_since(now)
            .filter(|time| !time.is_zero());
        if remaining.is_none() {
            self.lease.take();
        }
        remaining
    }

    fn release(&mut self, generation: Generation) {
        if self.generation == generation.0 {
            self.lease.take();
        }
    }
}

pub(super) struct ContextQueue {
    queue: DispatchRetained<DispatchQueue>,
    slot: Arc<Mutex<Slot>>,
}

impl ContextQueue {
    pub(super) fn new() -> Self {
        Self {
            queue: DispatchQueue::new("dev.quartermaster.context", None),
            slot: Arc::default(),
        }
    }

    pub(super) fn authenticate(
        &self,
        incoming: IncomingContext,
        work: impl FnOnce(Option<(Generation, &LAContext)>) + Send + 'static,
    ) {
        let state = Arc::clone(&self.slot);
        let queue = self.queue.clone();
        self.queue.exec_async(move || {
            objc2::rc::autoreleasepool(|_| {
                let mut slot = state.lock().unwrap();
                let generation = monotonic_raw()
                    .ok()
                    .and_then(|now| slot.install(incoming.into_inner(), now));
                match generation {
                    Some(generation) => {
                        let lease = slot.lease.as_ref().unwrap();
                        schedule_expiry(
                            &queue,
                            &state,
                            generation,
                            lease.deadline,
                            CONTEXT_LIFETIME,
                        );
                        work(Some((generation, &lease.context)));
                    }
                    None => work(None),
                }
            });
        });
    }

    pub(super) fn shorten(&self, generation: Generation, deadline: MonotonicTimestamp) {
        let state = Arc::clone(&self.slot);
        let queue = self.queue.clone();
        self.queue
            .exec_async(move || expire(&queue, &state, generation, deadline));
    }

    pub(super) fn release(&self, generation: Generation) {
        let state = Arc::clone(&self.slot);
        self.queue.exec_async(move || {
            state.lock().unwrap().release(generation);
        });
    }

    pub(super) fn clear(&self) {
        let state = Arc::clone(&self.slot);
        self.queue.exec_async(move || {
            state.lock().unwrap().lease.take();
        });
    }
}

impl Drop for ContextQueue {
    fn drop(&mut self) {
        self.clear();
    }
}

fn expire(
    queue: &DispatchRetained<DispatchQueue>,
    state: &Arc<Mutex<Slot>>,
    generation: Generation,
    deadline: MonotonicTimestamp,
) {
    let mut slot = state.lock().unwrap();
    match monotonic_raw() {
        Ok(now) => {
            if let Some(remaining) = slot.expire(generation, deadline, now) {
                schedule_expiry(queue, state, generation, deadline, remaining);
            }
        }
        Err(_) => {
            slot.lease.take();
        }
    }
}

fn schedule_expiry(
    queue: &DispatchRetained<DispatchQueue>,
    state: &Arc<Mutex<Slot>>,
    generation: Generation,
    deadline: MonotonicTimestamp,
    remaining: Duration,
) {
    let weak: Weak<Mutex<Slot>> = Arc::downgrade(state);
    let queued = queue.clone();
    let when = unsafe {
        DispatchTime::walltime(std::ptr::null(), remaining.as_nanos().try_into().unwrap())
    };
    queue
        .after(when, move || {
            if let Some(state) = weak.upgrade() {
                expire(&queued, &state, generation, deadline);
            }
        })
        .expect("context expiry within dispatch time range");
}

#[cfg(test)]
mod tests {
    use super::super::{ContextLease, Event, listener::Listener};
    use super::*;
    use qm_macos::cache_key::{
        CacheKeyScope, DeviceCacheKey, NativeAuthenticationContext, SnapshotKey, WrappedCacheKey,
    };
    use serde::Deserialize;
    use std::{path::PathBuf, sync::mpsc, time::Instant};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureConfig {
        service: String,
        client_requirement: String,
        scope: String,
        approval_group: String,
        case: String,
        result_path: PathBuf,
    }

    struct HardwareCache {
        scope: String,
        identity: [u8; 32],
        expected: SnapshotKey,
        wrapped: WrappedCacheKey,
    }

    struct ObservedContext {
        queue: DispatchRetained<DispatchQueue>,
        slot: Arc<Mutex<Slot>>,
    }

    impl HardwareCache {
        fn new(scope: &str) -> Self {
            let key = DeviceCacheKey::enroll(CacheKeyScope::new(scope).unwrap()).unwrap();
            let (expected, wrapped) = key.wrap_new_snapshot_key().unwrap();
            Self {
                scope: scope.into(),
                identity: *key.identity(),
                expected,
                wrapped,
            }
        }

        fn unwrap(&self, context: &NativeAuthenticationContext<'_>) -> bool {
            let key = DeviceCacheKey::load(CacheKeyScope::new(&self.scope).unwrap(), self.identity)
                .unwrap();
            key.unwrap_authenticated(&self.wrapped, context)
                .is_ok_and(|opened| self.expected.with_bytes(|a| opened.with_bytes(|b| a == b)))
        }
    }

    fn wrong_group_is_denied(group: &str, tag: &[u8]) -> bool {
        use core_foundation::{
            base::TCFType, boolean::CFBoolean, data::CFData, dictionary::CFDictionary,
            string::CFString,
        };
        use security_framework_sys::{item::*, keychain_item::SecItemCopyMatching};
        unsafe extern "C" {
            static kSecAttrApplicationTag: core_foundation::string::CFStringRef;
            static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
        }
        let query = unsafe {
            CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassKey).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                    CFString::new(group).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                    CFData::from_buffer(tag).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                    CFBoolean::true_value().into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUI),
                    CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail).into_CFType(),
                ),
            ])
        };
        unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), std::ptr::null_mut()) == -34018 }
    }

    fn fixture_config() -> FixtureConfig {
        let path =
            std::env::var_os("QM_NATIVE_IPC_TEST_CONFIG").expect("run with just test-integration");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    #[ignore = "separate-process Swift fixture; run just test-integration"]
    fn swift_client_fixture() {
        let config = fixture_config();
        let result_path = config.result_path.clone();
        let hardware = matches!(config.case.as_str(), "hardware" | "frontend-exit");
        let cache = hardware.then(|| Arc::new(Mutex::new(HardwareCache::new(&config.scope))));
        let lease: Arc<Mutex<Option<ContextLease>>> = Arc::default();
        let observed: Arc<Mutex<Option<ObservedContext>>> = Arc::default();
        let (finished, receive) = mpsc::sync_channel(1);
        let held = Arc::clone(&lease);
        let seen = Arc::clone(&observed);
        let used_cache = cache.clone();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let successful = Arc::clone(&completed);
        let listener = Listener::new(
            &config.service,
            &config.client_requirement,
            crate::platform::lifecycle::HostEvents::default(),
            Arc::new(move |event: Event<'_>| {
                let Event::Message {
                    connection,
                    context,
                    payload,
                } = event
                else {
                    if matches!(event, Event::Disconnected(_)) {
                        let _ = finished.try_send(());
                    }
                    return Ok(Vec::new());
                };
                seen.lock().unwrap().get_or_insert_with(|| ObservedContext {
                    queue: connection.peer.contexts.queue.clone(),
                    slot: Arc::clone(&connection.peer.contexts.slot),
                });
                match payload {
                    b"release" => {
                        held.lock().unwrap().take();
                        Ok(b"released".to_vec())
                    }
                    b"finish" => {
                        successful.store(true, std::sync::atomic::Ordering::Release);
                        Ok(b"finished".to_vec())
                    }
                    b"isolation" => {
                        assert!(wrong_group_is_denied(
                            &config.approval_group,
                            format!("dev.quartermaster.test.approval.{}", config.scope).as_bytes()
                        ));
                        Ok(b"isolated".to_vec())
                    }
                    b"reuse" | b"invalidate" => {
                        let contexts = &connection.peer.contexts;
                        let cache = used_cache.as_ref().unwrap();
                        contexts.queue.exec_sync(|| {
                            let mut slot = contexts.slot.lock().unwrap();
                            let imported = slot.lease.as_ref().unwrap().context.clone();
                            if payload == b"invalidate" {
                                slot.lease.take();
                            }
                            let borrowed = unsafe {
                                NativeAuthenticationContext::from_borrowed(
                                    (&*imported as *const LAContext).cast(),
                                )
                            };
                            assert_eq!(
                                cache.lock().unwrap().unwrap(&borrowed),
                                payload == b"reuse",
                                "receiver context validity did not match its lifecycle"
                            );
                        });
                        Ok(if payload == b"reuse" {
                            b"reused".to_vec()
                        } else {
                            b"invalidated".to_vec()
                        })
                    }
                    b"unauthenticated" | b"unwrap" => {
                        let opened = used_cache
                            .as_ref()
                            .unwrap()
                            .lock()
                            .unwrap()
                            .unwrap(context.as_ref().unwrap());
                        if payload == b"unauthenticated" {
                            assert!(!opened);
                        } else {
                            assert!(
                                opened,
                                "transferred authentication did not unwrap dummy key"
                            );
                        }
                        if opened {
                            let deadline = monotonic_raw()?.checked_add(CONTEXT_LIFETIME).unwrap();
                            *held.lock().unwrap() = Some(connection.context_lease(deadline)?);
                        } else {
                            connection.release_context();
                        }
                        Ok(if opened {
                            b"unwrapped".to_vec()
                        } else {
                            b"denied".to_vec()
                        })
                    }
                    _ if context.is_some() => {
                        let deadline = monotonic_raw()?.checked_add(CONTEXT_LIFETIME).unwrap();
                        *held.lock().unwrap() = Some(connection.context_lease(deadline)?);
                        Ok(b"context".to_vec())
                    }
                    _ => Ok(payload.to_vec()),
                }
            }),
        )
        .unwrap();
        let result = receive.recv_timeout(Duration::from_secs(if hardware { 150 } else { 20 }));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut cleared = false;
        while Instant::now() < deadline {
            if let Some(observed) = observed.lock().unwrap().as_ref() {
                observed.queue.exec_sync(|| {
                    cleared = observed.slot.lock().unwrap().lease.is_none();
                });
            }
            if cleared {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(listener);
        drop(lease.lock().unwrap().take());
        drop(cache);
        result.unwrap();
        assert!(
            completed.load(std::sync::atomic::Ordering::Acquire),
            "Swift client did not complete assertions"
        );
        assert!(cleared, "disconnection retained its authentication context");
        std::fs::write(result_path, "passed\n").unwrap();
    }

    #[test]
    #[ignore = "dummy key cleanup for just test-integration hardware"]
    fn cleanup_swift_client_fixture() {
        let config = fixture_config();
        let scope = || CacheKeyScope::new(&config.scope).unwrap();
        DeviceCacheKey::discard_for_reenrollment(scope()).unwrap();
        assert!(matches!(
            DeviceCacheKey::load(scope(), [0; 32]),
            Err(qm_macos::cache_key::CacheKeyError::KeyMissing)
        ));
    }

    fn now(seconds: u64) -> MonotonicTimestamp {
        (seconds * 1_000_000_000).into()
    }

    fn native_context() -> Retained<LAContext> {
        unsafe { LAContext::new() }
    }

    #[test]
    fn context_deadlines_can_only_shorten_and_stale_cleanup_cannot_release_a_new_context() {
        let mut slot = Slot::default();
        let first = slot.install(native_context(), now(1)).unwrap();
        assert!(slot.install(native_context(), now(2)).is_none());
        assert_eq!(
            slot.expire(first, now(10), now(3)),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            slot.expire(first, now(50), now(4)),
            Some(Duration::from_secs(6))
        );
        assert_eq!(slot.expire(first, now(50), now(10)), None);
        let second = slot.install(native_context(), now(11)).unwrap();
        slot.release(first);
        assert!(slot.lease.is_some());
        assert_eq!(slot.expire(first, now(12), now(50)), None);
        assert!(slot.lease.is_some());
        slot.release(second);
        assert!(slot.lease.is_none());
    }

    #[test]
    fn expired_context_can_be_replaced_but_generation_or_clock_overflow_cannot_install_one() {
        let mut slot = Slot::default();
        let first = slot.install(native_context(), now(1)).unwrap();
        let second = slot.install(native_context(), now(31)).unwrap();
        assert_ne!(first, second);
        slot.lease.take();
        slot.generation = u64::MAX;
        assert!(slot.install(native_context(), now(32)).is_none());
        slot.generation = 0;
        assert!(slot.install(native_context(), u64::MAX.into()).is_none());
        assert!(slot.lease.is_none());
    }
}
