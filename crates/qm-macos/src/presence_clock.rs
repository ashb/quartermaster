use serde::{Deserialize, Serialize};
use std::{io, mem::MaybeUninit, time::Duration};

/// A CLOCK_MONOTONIC_RAW sample shared by authenticated same-boot macOS peers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(from = "u64", into = "u64")]
pub struct MonotonicTimestamp(Duration);

impl From<u64> for MonotonicTimestamp {
    fn from(nanoseconds: u64) -> Self {
        Self(Duration::from_nanos(nanoseconds))
    }
}

impl From<MonotonicTimestamp> for u64 {
    fn from(sample: MonotonicTimestamp) -> Self {
        sample.0.as_nanos().try_into().unwrap()
    }
}

impl MonotonicTimestamp {
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let duration: u64 = duration.as_nanos().try_into().ok()?;
        u64::from(self).checked_add(duration).map(Self::from)
    }
}

/// Matches the Swift authentication callback's clock; std::time::Instant is opaque across IPC.
pub fn monotonic_raw() -> io::Result<MonotonicTimestamp> {
    let mut time = MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, time.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec).map_err(io::Error::other)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(io::Error::other)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .map(MonotonicTimestamp::from)
        .ok_or_else(|| io::Error::other("presence clock overflow"))
}

#[cfg(test)]
#[path = "../tests/unit/presence_clock.rs"]
mod tests;
