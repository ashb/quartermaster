use super::{dispatch, operation::OperationError, policy::AuthorizationError, provider_lifecycle};
use crate::CacheStatus;
use qm_types::{CredentialError, MonotonicTimestamp};
use serde::{Deserialize, Serialize};
use std::{fmt, io};
use zeroize::Zeroizing;

pub(super) const MAX_PAYLOAD: usize = crate::wire_limits::IPC_PAYLOAD_BYTES;

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Client {
    Hello {},
    Enroll {
        #[serde(rename = "publicKey")]
        public_key: String,
    },
    Next {},
    Presence {
        id: String,
        authenticated: MonotonicTimestamp,
    },
    Proof {
        id: String,
        signature: String,
    },
    Cancel {
        id: String,
    },
    VaultStatus {},
    VaultLogin {
        server: String,
        email: String,
        password: Zeroizing<String>,
        #[serde(rename = "itemId")]
        item_id: Option<String>,
    },
    VaultLock {},
    VaultUnlock {},
    VaultSync {},
    VaultDiscard {},
    RevokeReadGrants {},
    SettingsRegister {
        #[serde(rename = "publicKey")]
        public_key: String,
    },
    SettingsStatus {},
    PrepareSettingsImport {
        id: String,
    },
    PrepareSettingsDiscard {
        id: String,
    },
    StageEnrollment {
        server: String,
        email: String,
        password: Zeroizing<String>,
        #[serde(rename = "itemId")]
        item_id: Option<String>,
    },
    PrepareSettings {
        revision: super::settings::Revision,
        settings: super::settings::Settings,
        provider: super::settings::ProviderChoice,
        #[serde(default)]
        additions: Vec<super::settings::RepositoryName>,
    },
    SettingsPresence {
        id: String,
        authenticated: MonotonicTimestamp,
    },
    SettingsProof {
        id: String,
        signature: String,
    },
    SettingsCancel {
        id: Option<String>,
    },
}

impl Client {
    pub(super) fn is_settings(&self) -> bool {
        matches!(
            self,
            Self::SettingsRegister { .. }
                | Self::SettingsStatus {}
                | Self::PrepareSettingsImport { .. }
                | Self::PrepareSettingsDiscard { .. }
                | Self::StageEnrollment { .. }
                | Self::PrepareSettings { .. }
                | Self::SettingsPresence { .. }
                | Self::SettingsProof { .. }
                | Self::SettingsCancel { .. }
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProviderPresentation {
    pub(super) server: String,
    pub(super) account: String,
    pub(super) email: String,
    pub(super) item: String,
    pub(super) field: String,
    pub(super) role: String,
    pub(super) enrollment: String,
    pub(super) generation: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApprovalReview {
    pub(super) id: String,
    pub(super) created: MonotonicTimestamp,
    pub(super) session: String,
    pub(super) policy: String,
    pub(super) nonce: String,
    pub(super) request: String,
    pub(super) request_digest: String,
    pub(super) provider: ProviderPresentation,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApprovalChallenge {
    pub(super) review: ApprovalReview,
    pub(super) credential_digest: String,
    pub(super) authenticated: MonotonicTimestamp,
    pub(super) expires: MonotonicTimestamp,
    pub(super) bytes: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(super) enum Reply {
    Hello {
        profile: &'static str,
    },
    Enrolled,
    Idle,
    Review {
        approval: ApprovalReview,
    },
    Challenge {
        authorization: ApprovalChallenge,
    },
    Accepted,
    Canceled,
    AlreadyAdmitted,
    UnknownOperation,
    ReadGrantsRevoked,
    SettingsStatus {
        settings: super::settings::Snapshot,
    },
    SettingsReview {
        review: super::settings::Review,
    },
    SettingsChallenge {
        authorization: super::settings::Challenge,
    },
    EnrollmentStaged {
        ticket: String,
        provider: super::settings::ProviderPin,
    },
    SettingsApplied {
        revision: super::settings::Revision,
    },
    Error {
        code: ControlError,
    },
    #[serde(untagged)]
    VaultStatus(CacheStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ControlError {
    InvalidMessage,
    Denied,
    Expired,
    Busy,
    ProviderChanged,
    SessionEnded,
    Unavailable,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMessage => "invalid control message",
            Self::Denied => "request denied",
            Self::Expired => "approval expired",
            Self::Busy => "operation already pending",
            Self::ProviderChanged => "provider selection changed",
            Self::SessionEnded => "authorization session ended",
            Self::Unavailable => "service unavailable",
        })
    }
}
impl std::error::Error for ControlError {}

impl From<AuthorizationError> for ControlError {
    fn from(error: AuthorizationError) -> Self {
        match error {
            AuthorizationError::Expired => Self::Expired,
            AuthorizationError::SessionRevoked => Self::SessionEnded,
            AuthorizationError::CredentialMismatch => Self::ProviderChanged,
            _ => Self::Denied,
        }
    }
}
impl From<OperationError> for ControlError {
    fn from(error: OperationError) -> Self {
        match error {
            OperationError::Authorization(error) => error.into(),
            OperationError::Capacity => Self::Busy,
            OperationError::CredentialMismatch => Self::ProviderChanged,
            OperationError::NotReady | OperationError::UnknownOperation => Self::Denied,
            OperationError::Unavailable => Self::Unavailable,
        }
    }
}
impl From<provider_lifecycle::Error> for ControlError {
    fn from(error: provider_lifecycle::Error) -> Self {
        match error {
            provider_lifecycle::Error::Busy => Self::Busy,
            provider_lifecycle::Error::Changed | provider_lifecycle::Error::Superseded => {
                Self::ProviderChanged
            }
            _ => Self::Unavailable,
        }
    }
}
impl From<CredentialError> for ControlError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::PendingExpired | CredentialError::DispatchExpired => Self::Expired,
            CredentialError::SessionRevoked => Self::SessionEnded,
            CredentialError::StateUnavailable | CredentialError::RandomnessUnavailable => {
                Self::Unavailable
            }
            _ => Self::Denied,
        }
    }
}
impl From<dispatch::Error> for ControlError {
    fn from(error: dispatch::Error) -> Self {
        match error {
            dispatch::Error::Operation(error) => error.into(),
            dispatch::Error::Authorization(error) => error.into(),
            dispatch::Error::CredentialMismatch => Self::ProviderChanged,
            _ => Self::Unavailable,
        }
    }
}
impl From<serde_json::Error> for ControlError {
    fn from(_: serde_json::Error) -> Self {
        Self::InvalidMessage
    }
}
impl From<ring::error::Unspecified> for ControlError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unavailable
    }
}
impl From<io::Error> for ControlError {
    fn from(error: io::Error) -> Self {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<Self>())
            .copied()
            .unwrap_or(Self::Unavailable)
    }
}

pub(super) fn decode_client(payload: &[u8]) -> Result<Client, ControlError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(ControlError::InvalidMessage);
    }
    serde_json::from_slice(payload).map_err(Into::into)
}

pub(super) fn encode_reply(reply: &Reply) -> Result<Vec<u8>, ControlError> {
    let bytes = serde_json::to_vec(reply)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(ControlError::InvalidMessage);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_fixtures() -> serde_json::Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/broker-protocol.json"
        )))
        .unwrap()
    }

    #[test]
    fn swift_command_fixtures_preserve_fields_and_require_each_mandatory_payload() {
        for fixture in wire_fixtures()["commands"].as_array().unwrap() {
            let command = decode_client(&serde_json::to_vec(fixture).unwrap()).unwrap();
            let decoded = serde_json::to_value(command).unwrap();
            for (key, expected) in fixture.as_object().unwrap() {
                assert_eq!(decoded.get(key), Some(expected), "field {key}");
                if key != "itemId" {
                    let mut missing = fixture.clone();
                    missing.as_object_mut().unwrap().remove(key);
                    assert!(matches!(
                        decode_client(&serde_json::to_vec(&missing).unwrap()),
                        Err(ControlError::InvalidMessage)
                    ));
                }
            }
        }
    }

    #[test]
    fn rust_reply_encoding_matches_the_shared_swift_wire_fixtures() {
        for fixture in wire_fixtures()["replies"].as_array().unwrap() {
            let reply = match fixture["kind"].as_str().unwrap() {
                "hello" => Reply::Hello {
                    profile: "development",
                },
                "enrolled" => Reply::Enrolled,
                "idle" => Reply::Idle,
                "review" => Reply::Review {
                    approval: serde_json::from_value(fixture["approval"].clone()).unwrap(),
                },
                "challenge" => Reply::Challenge {
                    authorization: serde_json::from_value(fixture["authorization"].clone())
                        .unwrap(),
                },
                "accepted" => Reply::Accepted,
                "canceled" => Reply::Canceled,
                "alreadyAdmitted" => Reply::AlreadyAdmitted,
                "unknownOperation" => Reply::UnknownOperation,
                "readGrantsRevoked" => Reply::ReadGrantsRevoked,
                "error" => Reply::Error {
                    code: serde_json::from_value(fixture["code"].clone()).unwrap(),
                },
                "vaultStatus" => Reply::VaultStatus(crate::CacheStatus {
                    kind: crate::StatusKind::VaultStatus,
                    state: match fixture["state"].as_str().unwrap() {
                        "locked" => crate::VaultState::Locked,
                        "busy" => crate::VaultState::Busy,
                        other => panic!("unexpected fixture vault state {other}"),
                    },
                    binding: fixture
                        .get("binding")
                        .map(|binding| serde_json::from_value(binding.clone()).unwrap()),
                    last_sync: fixture.get("lastSync").map(|value| {
                        time::OffsetDateTime::from_unix_timestamp(value.as_i64().unwrap()).unwrap()
                    }),
                    error: fixture
                        .get("error")
                        .map(|value| value.as_str().unwrap().to_owned()),
                    observation: fixture.get("observation").map(|value| {
                        assert_eq!(value, "persisted_cache");
                        crate::StatusObservation::PersistedCache
                    }),
                }),
                other => panic!("unexpected fixture reply {other}"),
            };
            let encoded: serde_json::Value =
                serde_json::from_slice(&encode_reply(&reply).unwrap()).unwrap();
            assert_eq!(&encoded, fixture);
        }
    }

    #[test]
    fn active_payload_codec_accepts_commands_and_rejects_missing_forged_or_oversized_payloads() {
        assert!(matches!(
            decode_client(br#"{"kind":"vaultSync"}"#),
            Ok(Client::VaultSync {})
        ));
        for payload in [
            br#"{"kind":"proof","id":"request"}"#.as_slice(),
            br#"{"kind":"vaultSync","approved":true}"#,
            br#"{"kind":"allow"}"#,
            br#"{"version":1,"payload":{}}"#,
        ] {
            assert!(matches!(
                decode_client(payload),
                Err(ControlError::InvalidMessage)
            ));
        }
        assert!(matches!(
            decode_client(&vec![b' '; MAX_PAYLOAD + 1]),
            Err(ControlError::InvalidMessage)
        ));
    }

    #[test]
    fn control_failures_preserve_sanitized_categories_without_debug_or_upstream_text() {
        assert_eq!(
            ControlError::from(crate::owner::policy::AuthorizationError::Expired),
            ControlError::Expired
        );
        assert_eq!(
            ControlError::from(crate::owner::provider_lifecycle::Error::Busy),
            ControlError::Busy
        );
        let error = std::io::Error::other("upstream SECRET_CANARY response");
        let encoded = encode_reply(&Reply::Error {
            code: ControlError::from(error),
        })
        .unwrap();
        assert_eq!(encoded, br#"{"kind":"error","code":"unavailable"}"#);
    }
}
