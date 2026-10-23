use super::Error;
use std::{
    ffi::CStr,
    mem::{MaybeUninit, size_of},
};

// Mach absolute ticks are opaque transition witnesses, never deadline values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AbsoluteTime(u64);

impl AbsoluteTime {
    fn read(name: &CStr) -> Result<Self, Error> {
        let mut value = MaybeUninit::<u64>::uninit();
        let mut length = size_of::<u64>();
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || length != size_of::<u64>() {
            return Err(Error::Unavailable);
        }
        Ok(Self(unsafe { value.assume_init() }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PowerTransitions {
    slept: AbsoluteTime,
    woke: AbsoluteTime,
}

impl PowerTransitions {
    pub(super) fn capture() -> Result<Self, Error> {
        Ok(Self {
            slept: AbsoluteTime::read(c"kern.sleep_abs_time")?,
            woke: AbsoluteTime::read(c"kern.wake_abs_time")?,
        })
    }

    pub(super) fn regressed_from(self, previous: Self) -> bool {
        self.slept < previous.slept || self.woke < previous.woke
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PowerTransitions {
        pub(in crate::console_session) fn fixture(slept: u64, woke: u64) -> Self {
            Self {
                slept: AbsoluteTime(slept),
                woke: AbsoluteTime(woke),
            }
        }
    }

    #[test]
    fn missing_kernel_properties_fail_closed() {
        assert_eq!(
            AbsoluteTime::read(c"kern.quartermaster_missing_property"),
            Err(Error::Unavailable)
        );
    }

    #[test]
    fn both_sleep_and_wake_are_required_to_advance_monotonically() {
        let old = PowerTransitions::fixture(10, 20);
        for current in [
            PowerTransitions::fixture(11, 20),
            PowerTransitions::fixture(30, 40),
        ] {
            assert_ne!(old, current);
            assert!(!current.regressed_from(old));
            assert!(old.regressed_from(current));
        }
    }
}
