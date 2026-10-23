#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(any(target_os = "macos", test))]
pub(crate) mod lifecycle;

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostSessionEvent {
    Sleep,
    Wake,
    ScreenLock,
    Inactive,
    Logout,
    ConsoleChange,
}
