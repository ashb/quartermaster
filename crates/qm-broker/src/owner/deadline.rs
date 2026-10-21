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
#[path = "../../tests/unit/deadline.rs"]
mod tests;
