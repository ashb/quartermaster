use std::{
    io,
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
pub(in crate::owner) use qm_macos::presence_clock::{
    MonotonicTimestamp as Sample, monotonic_raw as continuous_now,
};

#[cfg(not(target_os = "macos"))]
pub(in crate::owner) type Sample = Instant;

#[cfg(not(target_os = "macos"))]
pub(in crate::owner) fn continuous_now() -> io::Result<Sample> {
    Ok(Instant::now())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::owner) struct Deadline {
    at: Sample,
}

impl Deadline {
    pub(in crate::owner) fn after(duration: Duration) -> io::Result<Self> {
        Self::at(continuous_now()?, duration)
    }

    pub(in crate::owner) fn at(anchor: Sample, duration: Duration) -> io::Result<Self> {
        anchor
            .checked_add(duration)
            .map(|at| Self { at })
            .ok_or_else(|| io::Error::other("deadline overflow"))
    }

    pub(in crate::owner) fn from_instant(deadline: Instant) -> io::Result<Self> {
        let anchor = continuous_now()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        anchor
            .checked_add(remaining)
            .map(|at| Self { at })
            .ok_or_else(|| io::Error::other("deadline overflow"))
    }

    pub(in crate::owner) fn earliest(self, other: Self) -> Self {
        Self {
            at: self.at.min(other.at),
        }
    }

    pub(in crate::owner) fn cap(self, duration: Duration) -> io::Result<Self> {
        Ok(self.earliest(Self::after(duration)?))
    }

    pub(in crate::owner) fn remaining(self) -> io::Result<Duration> {
        self.remaining_at(continuous_now()?)
    }

    pub(in crate::owner) fn remaining_at(self, now: Sample) -> io::Result<Duration> {
        self.at
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "operation deadline expired"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_expiry_uses_continuous_samples_and_cannot_be_extended_by_a_later_cap() {
        let start = continuous_now().unwrap();
        let at = start.checked_add(Duration::from_secs(10)).unwrap();
        let deadline = Deadline { at };
        assert_eq!(
            deadline.remaining_at(start).unwrap(),
            Duration::from_secs(10)
        );
        assert!(deadline.remaining_at(at).is_err());
        assert!(
            deadline
                .remaining_at(at.checked_add(Duration::from_secs(100)).unwrap())
                .is_err()
        );
        assert_eq!(
            deadline
                .earliest(Deadline {
                    at: at.checked_add(Duration::from_secs(20)).unwrap()
                })
                .remaining_at(start)
                .unwrap(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn expired_or_overflowing_deadlines_cannot_produce_a_positive_timeout() {
        assert!(
            Deadline::after(Duration::ZERO)
                .unwrap()
                .remaining()
                .is_err()
        );
        assert!(
            Deadline::from_instant(Instant::now() - Duration::from_secs(1))
                .unwrap()
                .remaining()
                .is_err()
        );
        assert!(Deadline::after(Duration::MAX).is_err());
    }
}
