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
