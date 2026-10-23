mod power;

use objc2_core_foundation::{
    CFArray, CFBoolean, CFData, CFDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_io_kit::{
    IOObjectRelease, IORegistryEntryCreateCFProperty, IORegistryGetRootEntry,
    IOServiceGetMatchingService, IOServiceMatching,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsoleGeneration(u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleSession {
    generation: ConsoleGeneration,
    session: String,
    interactive: bool,
    power: power::PowerTransitions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Unchanged,
    ConsoleChanged,
    PowerChanged,
    LoginChanged,
    InvalidGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidProperty,
    NoSession,
    Transition,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "console registry unavailable",
            Self::InvalidProperty => "invalid console property",
            Self::NoSession => "console login unavailable",
            Self::Transition => "console changed while sampling",
        })
    }
}

impl std::error::Error for Error {}

struct RegistryEntry(u32);

impl Drop for RegistryEntry {
    fn drop(&mut self) {
        IOObjectRelease(self.0);
    }
}

impl RegistryEntry {
    fn new(value: u32) -> Result<Self, Error> {
        if value == 0 {
            Err(Error::Unavailable)
        } else {
            Ok(Self(value))
        }
    }

    fn property(&self, name: &str) -> Result<CFRetained<CFType>, Error> {
        unsafe { IORegistryEntryCreateCFProperty(self.0, Some(&CFString::from_str(name)), None, 0) }
            .ok_or(Error::Unavailable)
    }

    fn generation(&self) -> Result<ConsoleGeneration, Error> {
        let value = self.property("IOConsoleUsersSeed")?;
        let data = value
            .downcast_ref::<CFData>()
            .ok_or(Error::InvalidProperty)?;
        let bytes = data.to_vec();
        let bytes = bytes.try_into().map_err(|_| Error::InvalidProperty)?;
        let generation = u32::from_ne_bytes(bytes);
        if generation == u32::MAX {
            return Err(Error::InvalidProperty);
        }
        Ok(ConsoleGeneration(generation))
    }
}

fn user_session(users: &CFType, uid: u32) -> Result<(String, bool), Error> {
    let users = users
        .downcast_ref::<CFArray>()
        .ok_or(Error::InvalidProperty)?;
    // IOKit serializes registry collections as Core Foundation objects.
    let users = unsafe { users.cast_unchecked::<CFType>() };
    let mut found = None;
    for user in users.iter() {
        let user = user
            .downcast_ref::<CFDictionary>()
            .ok_or(Error::InvalidProperty)?;
        let user = unsafe { user.cast_unchecked::<CFType, CFType>() };
        let id = user
            .get(&CFString::from_str("kCGSSessionUserIDKey"))
            .ok_or(Error::InvalidProperty)?;
        let id = id
            .downcast_ref::<CFNumber>()
            .and_then(CFNumber::as_i64)
            .ok_or(Error::InvalidProperty)?;
        if id != i64::from(uid) {
            continue;
        }
        if found.is_some() {
            return Err(Error::InvalidProperty);
        }
        let session = user
            .get(&CFString::from_str("CGSSessionUniqueSessionUUID"))
            .ok_or(Error::InvalidProperty)?;
        let session = session
            .downcast_ref::<CFString>()
            .ok_or(Error::InvalidProperty)?
            .to_string();
        if session.is_empty() || session.len() > 128 {
            return Err(Error::InvalidProperty);
        }
        let on_console = user
            .get(&CFString::from_str("kCGSSessionOnConsoleKey"))
            .ok_or(Error::InvalidProperty)?;
        let on_console = on_console
            .downcast_ref::<CFBoolean>()
            .ok_or(Error::InvalidProperty)?
            .as_bool();
        let logged_in = user
            .get(&CFString::from_str("kCGSessionLoginDoneKey"))
            .ok_or(Error::InvalidProperty)?;
        let logged_in = logged_in
            .downcast_ref::<CFBoolean>()
            .ok_or(Error::InvalidProperty)?
            .as_bool();
        found = Some((session, on_console && logged_in));
    }
    found.ok_or(Error::NoSession)
}

impl ConsoleSession {
    /// Samples the kernel's console generation around the session properties.
    /// Console changes must invalidate pending authority even if notifications
    /// were lost. The property names are private and absence fails closed.
    pub fn capture() -> Result<Self, Error> {
        let power = power::PowerTransitions::capture()?;
        let resources = RegistryEntry::new(unsafe {
            IOServiceGetMatchingService(
                0,
                IOServiceMatching(c"IOResources".as_ptr())
                    .map(|matching| CFRetained::from(&*matching)),
            )
        })?;
        let root = RegistryEntry::new(IORegistryGetRootEntry(0))?;
        let generation = resources.generation()?;
        let users = root.property("IOConsoleUsers")?;
        let (session, on_console) = user_session(&users, unsafe { libc::geteuid() })?;
        let locked = root.property("IOConsoleLocked")?;
        let locked = locked
            .downcast_ref::<CFBoolean>()
            .ok_or(Error::InvalidProperty)?
            .as_bool();
        if resources.generation()? != generation || power::PowerTransitions::capture()? != power {
            return Err(Error::Transition);
        }
        Ok(Self {
            generation,
            session,
            interactive: on_console && !locked,
            power,
        })
    }

    pub fn transition_to(&self, next: &Self) -> Transition {
        if self.session != next.session {
            Transition::LoginChanged
        } else if next.generation < self.generation
            || next.power.regressed_from(self.power)
            || (next.generation == self.generation && next.interactive != self.interactive)
        {
            Transition::InvalidGeneration
        } else if next.power != self.power {
            Transition::PowerChanged
        } else if next.generation != self.generation {
            Transition::ConsoleChanged
        } else {
            Transition::Unchanged
        }
    }
    pub fn interactive(&self) -> bool {
        self.interactive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_changes_cannot_be_hidden_by_returning_to_an_interactive_state() {
        let before = ConsoleSession {
            generation: ConsoleGeneration(10),
            session: "session".into(),
            interactive: true,
            power: power::PowerTransitions::fixture(10, 20),
        };
        let after = ConsoleSession {
            generation: ConsoleGeneration(12),
            ..before.clone()
        };
        assert!(after.interactive());
        assert_eq!(before.transition_to(&after), Transition::ConsoleChanged);
        assert_eq!(after.transition_to(&before), Transition::InvalidGeneration);
        let replaced = ConsoleSession {
            session: "replacement".into(),
            ..after.clone()
        };
        assert_eq!(before.transition_to(&replaced), Transition::LoginChanged);
        let inconsistent = ConsoleSession {
            interactive: false,
            ..before.clone()
        };
        assert_eq!(
            before.transition_to(&inconsistent),
            Transition::InvalidGeneration
        );
    }

    #[test]
    fn absent_or_malformed_session_properties_do_not_produce_a_witness() {
        let empty = CFArray::<CFType>::empty();
        assert_eq!(user_session(&empty, 501), Err(Error::NoSession));
        let invalid = CFArray::<CFType>::from_objects(&[&CFString::from_str("invalid")]);
        assert_eq!(user_session(&invalid, 501), Err(Error::InvalidProperty));
    }

    #[test]
    fn sleep_and_wake_are_detected_without_a_console_change() {
        let before = ConsoleSession {
            generation: ConsoleGeneration(10),
            session: "session".into(),
            interactive: true,
            power: power::PowerTransitions::fixture(10, 20),
        };
        let after = ConsoleSession {
            power: power::PowerTransitions::fixture(30, 40),
            ..before.clone()
        };
        assert_eq!(before.transition_to(&after), Transition::PowerChanged);
        assert_eq!(after.transition_to(&before), Transition::InvalidGeneration);
    }
}
