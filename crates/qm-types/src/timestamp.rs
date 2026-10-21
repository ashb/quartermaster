use serde::{Deserialize, Serialize};
use std::time::Duration;

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
