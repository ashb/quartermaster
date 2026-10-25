use crate::owner::{
    dispatch, operation::OperationError, policy::AuthorizationError, protocol::ControlError,
    provider_lifecycle, settings::Error as SettingsError, vault,
};
use std::{fmt, io};

pub(super) type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub(in crate::owner) enum Error {
    Authorization(AuthorizationError),
    Operation(OperationError),
    Provider(provider_lifecycle::Error),
    Vault(vault::Error),
    Dispatch(dispatch::Error),
    Protocol(ControlError),
    Credential(qm_types::CredentialError),
    Task(tokio::task::JoinError),
    Console(qm_macos::console_session::Error),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    State(Fault),
}

#[derive(Debug, Clone, Copy)]
pub(in crate::owner) enum Fault {
    StateUnavailable,
    AlreadyRunning,
    InvalidSocket,
    MainThreadRequired,
    IngressUnavailable,
    UiDisconnected,
    UiNotEnrolled,
    ApprovalKeyChanged,
    PendingMissing,
    ReviewNotPresented,
    NativeContextRequired,
    UnexpectedContext,
    InvalidClock,
    ApprovalExpired,
    Canceled,
    ApprovalPending,
    ProviderChanged,
    VaultLocked,
    CacheOpening,
    UnsupportedField,
    UnsupportedVaultCommand,
    InvalidOperation,
    RepositoryMismatch,
    RedirectDenied,
    RedirectRequiresApproval,
    RedirectLoop,
    RedirectLimit,
    LaunchFailed,
    SessionEnded,
}

impl Error {
    pub(super) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::State(fault)
    }
}
impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self::io("OS operation", source)
    }
}
impl From<tokio::task::JoinError> for Error {
    fn from(error: tokio::task::JoinError) -> Self {
        Self::Task(error)
    }
}
impl From<qm_macos::console_session::Error> for Error {
    fn from(error: qm_macos::console_session::Error) -> Self {
        Self::Console(error)
    }
}
impl From<AuthorizationError> for Error {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}
impl From<OperationError> for Error {
    fn from(error: OperationError) -> Self {
        Self::Operation(error)
    }
}
impl From<provider_lifecycle::Error> for Error {
    fn from(error: provider_lifecycle::Error) -> Self {
        Self::Provider(error)
    }
}
impl From<vault::Error> for Error {
    fn from(error: vault::Error) -> Self {
        Self::Vault(error)
    }
}
impl From<dispatch::Error> for Error {
    fn from(error: dispatch::Error) -> Self {
        Self::Dispatch(error)
    }
}
impl From<ControlError> for Error {
    fn from(error: ControlError) -> Self {
        Self::Protocol(error)
    }
}
impl From<qm_types::CredentialError> for Error {
    fn from(error: qm_types::CredentialError) -> Self {
        Self::Credential(error)
    }
}
impl From<base64::DecodeError> for Error {
    fn from(_: base64::DecodeError) -> Self {
        Self::Protocol(ControlError::InvalidMessage)
    }
}
impl From<crate::owner::settings::Error> for Error {
    fn from(error: crate::owner::settings::Error) -> Self {
        Self::Protocol(match error {
            SettingsError::Busy => ControlError::Busy,
            SettingsError::Expired => ControlError::Expired,
            SettingsError::Storage => ControlError::Unavailable,
            SettingsError::Invalid | SettingsError::Stale => ControlError::Denied,
        })
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Protocol(ControlError::InvalidMessage)
    }
}
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Protocol(ControlError::Unavailable)
    }
}

impl From<Error> for ControlError {
    fn from(error: Error) -> Self {
        match error {
            Error::Authorization(error) => error.into(),
            Error::Operation(error) => error.into(),
            Error::Provider(error) => error.into(),
            Error::Dispatch(error) => error.into(),
            Error::Protocol(code) => code,
            Error::Credential(error) => error.into(),
            Error::Vault(vault::Error::Lifecycle(error)) => error.into(),
            Error::Vault(vault::Error::StorageBusy) => Self::Busy,
            Error::State(Fault::ApprovalExpired) => Self::Expired,
            Error::State(Fault::ProviderChanged | Fault::ApprovalKeyChanged) => {
                Self::ProviderChanged
            }
            Error::State(Fault::SessionEnded) => Self::SessionEnded,
            Error::State(Fault::ApprovalPending | Fault::CacheOpening) => Self::Busy,
            Error::State(
                Fault::UiDisconnected
                | Fault::UiNotEnrolled
                | Fault::PendingMissing
                | Fault::ReviewNotPresented
                | Fault::NativeContextRequired
                | Fault::UnexpectedContext
                | Fault::Canceled
                | Fault::VaultLocked
                | Fault::UnsupportedField
                | Fault::UnsupportedVaultCommand
                | Fault::RepositoryMismatch
                | Fault::RedirectDenied
                | Fault::RedirectRequiresApproval
                | Fault::RedirectLoop
                | Fault::RedirectLimit,
            ) => Self::Denied,
            _ => Self::Unavailable,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(_) => f.write_str("authorization failed"),
            Self::Operation(_) => f.write_str("operation failed"),
            Self::Provider(_) | Self::Vault(_) => f.write_str("provider failed"),
            Self::Dispatch(_) => f.write_str("dispatch failed"),
            Self::Protocol(code) => code.fmt(f),
            Self::Credential(_) => f.write_str("credential authorization failed"),
            Self::Task(_) => f.write_str("runtime task failed"),
            Self::Console(_) => f.write_str("console session unavailable"),
            Self::Io { operation, .. } => write!(f, "{operation} failed"),
            Self::State(fault) => write!(f, "runtime state: {fault:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Task(source) => Some(source),
            Self::Console(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::protocol::{Reply, encode_reply};

    #[test]
    fn structured_failures_retain_their_wire_categories() {
        for (error, expected) in [
            (
                Error::Provider(provider_lifecycle::Error::Busy),
                ControlError::Busy,
            ),
            (
                Error::Provider(provider_lifecycle::Error::Superseded),
                ControlError::ProviderChanged,
            ),
            (
                Error::Authorization(AuthorizationError::Expired),
                ControlError::Expired,
            ),
            (
                Error::Authorization(AuthorizationError::SessionRevoked),
                ControlError::SessionEnded,
            ),
            (Error::State(Fault::Canceled), ControlError::Denied),
            (
                Error::Dispatch(dispatch::Error::Uncertain),
                ControlError::Unavailable,
            ),
        ] {
            assert_eq!(ControlError::from(error), expected);
        }
    }

    #[test]
    fn io_sources_are_retained_without_exposing_their_contents() {
        let error = Error::io("cache publication", io::Error::other("SECRET_CANARY"));
        assert_eq!(error.to_string(), "cache publication failed");
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "SECRET_CANARY"
        );
        let reply = encode_reply(&Reply::Error { code: error.into() }).unwrap();
        assert_eq!(reply, br#"{"kind":"error","code":"unavailable"}"#);
    }
}
