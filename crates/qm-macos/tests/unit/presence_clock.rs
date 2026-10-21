use super::*;
use std::time::Duration;

#[test]
fn monotonic_timestamps_roundtrip_as_the_original_nanosecond_wire_values() {
    let sample: MonotonicTimestamp = serde_json::from_str("120000000001").unwrap();

    assert_eq!(serde_json::to_string(&sample).unwrap(), "120000000001");
    let earlier: MonotonicTimestamp = serde_json::from_str("100000000000").unwrap();
    assert_eq!(
        sample.checked_duration_since(earlier),
        Some(Duration::new(20, 1))
    );
    assert_eq!(earlier.checked_duration_since(sample), None);
}

#[test]
fn monotonic_timestamp_deadlines_reject_wire_range_overflow() {
    let sample: MonotonicTimestamp = serde_json::from_str("18446744073709551615").unwrap();

    assert!(sample.checked_add(Duration::from_nanos(1)).is_none());
    assert!(serde_json::from_str::<MonotonicTimestamp>("-1").is_err());
    assert!(serde_json::from_str::<MonotonicTimestamp>("0.5").is_err());
}
