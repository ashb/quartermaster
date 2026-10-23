use super::HostSessionEvent;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const EVENTS: [HostSessionEvent; 6] = [
    HostSessionEvent::Sleep,
    HostSessionEvent::Wake,
    HostSessionEvent::ScreenLock,
    HostSessionEvent::Inactive,
    HostSessionEvent::Logout,
    HostSessionEvent::ConsoleChange,
];

#[derive(Clone, Copy, Default)]
pub(crate) struct Observation([u64; EVENTS.len()]);

#[derive(Default)]
struct State {
    generations: [AtomicU64; EVENTS.len()],
    failed: AtomicBool,
}

/// Records delivered native events without waiting for the authority mutex.
/// It cannot establish that macOS delivered every transition.
#[derive(Clone, Default)]
pub(crate) struct HostEvents(Arc<State>);

impl HostEvents {
    pub(crate) fn record(&self, event: HostSessionEvent) {
        let index = EVENTS
            .iter()
            .position(|candidate| *candidate == event)
            .unwrap();
        if self.0.generations[index]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            self.fail();
        }
    }

    pub(crate) fn fail(&self) {
        self.0.failed.store(true, Ordering::Release);
    }

    pub(crate) fn observe(
        &self,
        prior: Observation,
    ) -> Result<(Observation, Vec<HostSessionEvent>), ()> {
        if self.0.failed.load(Ordering::Acquire) {
            return Err(());
        }
        let current = Observation(std::array::from_fn(|index| {
            self.0.generations[index].load(Ordering::Acquire)
        }));
        let changed = EVENTS
            .into_iter()
            .enumerate()
            .filter_map(|(index, event)| (current.0[index] != prior.0[index]).then_some(event))
            .collect();
        Ok((current, changed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_and_reordered_events_revoke_without_a_delivery_queue() {
        let events = HostEvents::default();
        events.record(HostSessionEvent::Wake);
        events.record(HostSessionEvent::ScreenLock);
        events.record(HostSessionEvent::ScreenLock);
        let (first, changed) = events.observe(Observation::default()).unwrap();
        assert_eq!(
            changed,
            [HostSessionEvent::Wake, HostSessionEvent::ScreenLock]
        );
        assert!(events.observe(first).unwrap().1.is_empty());
        events.record(HostSessionEvent::ScreenLock);
        assert_eq!(
            events.observe(first).unwrap().1,
            [HostSessionEvent::ScreenLock]
        );
    }

    #[test]
    fn source_failure_and_generation_exhaustion_are_permanent() {
        for exhausted in [false, true] {
            let events = HostEvents::default();
            if exhausted {
                events.0.generations[0].store(u64::MAX, Ordering::Release);
                events.record(HostSessionEvent::Sleep);
            } else {
                events.fail();
            }
            events.record(HostSessionEvent::Wake);
            assert!(events.observe(Observation::default()).is_err());
        }
    }
}
