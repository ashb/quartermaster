use super::{
    deadline::{Deadline, Sample},
    dispatch::CredentialSelection,
    identity::VerifiedPrincipal,
    policy::AuthorizationError,
    request::{Action, FrozenOperation},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
struct GrantId(String);

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum GrantAction {
    ListIssues,
    ReadIssue,
    IssueReads,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GrantRule {
    id: GrantId,
    uid: u32,
    code_hash: String,
    action: GrantAction,
    repository: String,
    role: String,
    #[serde(with = "time::serde::timestamp")]
    expires_unix: OffsetDateTime,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub(super) struct ReadGrantClaims {
    purpose: &'static str,
    grant: GrantRule,
}

impl ReadGrantClaims {
    #[cfg(test)]
    pub(super) fn role(&self) -> &str {
        &self.grant.role
    }
}

impl GrantRule {
    #[cfg(test)]
    pub(super) fn validate(&self) -> Result<(), AuthorizationError> {
        let hex = |s: &str| {
            s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.id.0.len() != 32
            || !hex(&self.id.0)
            || !matches!(self.code_hash.len(), 40 | 64)
            || !hex(&self.code_hash)
            || !super::github::configuration::valid_repository_name(&self.repository)
            || !matches!(self.role.as_str(), "github-read" | "github-write")
            || self.expires_unix <= OffsetDateTime::UNIX_EPOCH
        {
            return Err(AuthorizationError::InvalidPolicy);
        }
        Ok(())
    }

    fn matches(
        &self,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
    ) -> bool {
        principal.matches(self.uid, &self.code_hash, session)
            && matches!(
                (self.action, operation.action()),
                (GrantAction::ReadIssue, Action::ReadIssue)
                    | (GrantAction::ListIssues, Action::ListIssues)
                    | (
                        GrantAction::IssueReads,
                        Action::ListIssues | Action::ReadIssue
                    )
            )
            && operation.repository() == self.repository
    }
}

struct Grant {
    rule: GrantRule,
    expires: Instant,
    continuous_expiry: Deadline,
    credential: CredentialSelection,
}

pub(super) struct ReadGrantProposal {
    rule: GrantRule,
    expires: Instant,
    continuous_expiry: Deadline,
}

impl ReadGrantProposal {
    pub(super) fn new(
        principal: &VerifiedPrincipal,
        request: &FrozenOperation,
        role: &str,
    ) -> Result<Self, AuthorizationError> {
        if !matches!(request.action(), Action::ListIssues | Action::ReadIssue)
            || !matches!(role, "github-read" | "github-write")
        {
            return Err(AuthorizationError::Denied);
        }
        let anchor =
            super::deadline::continuous_now().map_err(|_| AuthorizationError::InvalidPolicy)?;
        let now = Instant::now();
        let lifetime = Duration::from_secs(3600);
        let mut id = [0; 16];
        SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| AuthorizationError::InvalidPolicy)?;
        Ok(Self {
            rule: GrantRule {
                id: GrantId(id.iter().map(|byte| format!("{byte:02x}")).collect()),
                uid: principal.uid(),
                code_hash: principal.code_hash().to_owned(),
                action: GrantAction::IssueReads,
                repository: request.repository().to_owned(),
                role: role.to_owned(),
                expires_unix: OffsetDateTime::now_utc() + lifetime,
            },
            expires: now
                .checked_add(lifetime)
                .ok_or(AuthorizationError::InvalidPolicy)?,
            continuous_expiry: Deadline::at(anchor, lifetime)
                .map_err(|_| AuthorizationError::InvalidPolicy)?,
        })
    }

    pub(super) fn claims(&self) -> ReadGrantClaims {
        ReadGrantClaims {
            purpose: "quartermaster.issue-read-grant.v1",
            grant: self.rule.clone(),
        }
    }

    pub(super) fn role(&self) -> &str {
        &self.rule.role
    }

    pub(super) fn check(&self, now: Instant) -> Result<(), AuthorizationError> {
        if now >= self.expires {
            return Err(AuthorizationError::Expired);
        }
        self.continuous_expiry
            .remaining()
            .map_err(|_| AuthorizationError::Expired)?;
        Ok(())
    }
}

impl Grant {
    fn check(&self, now: Instant) -> Result<(), AuthorizationError> {
        if now >= self.expires {
            return Err(AuthorizationError::Expired);
        }
        self.continuous_expiry
            .remaining()
            .map_err(|_| AuthorizationError::Expired)?;
        Ok(())
    }
}

pub(super) struct GrantUse {
    id: GrantId,
    role: String,
}

impl GrantUse {
    pub(super) fn role(&self) -> &str {
        &self.role
    }
}

#[derive(Default)]
pub(super) struct GrantTable {
    grants: Vec<Grant>,
}

impl GrantTable {
    pub(super) fn clamp_expiry(&mut self, wall_now: OffsetDateTime, now: Instant, anchor: Sample) {
        for grant in &mut self.grants {
            let remaining =
                Duration::try_from(grant.rule.expires_unix - wall_now).unwrap_or_default();
            if remaining < grant.expires.saturating_duration_since(now) {
                grant.expires = now.checked_add(remaining).unwrap_or(now);
            }
            match Deadline::at(anchor, remaining) {
                Ok(deadline) => {
                    grant.continuous_expiry = grant.continuous_expiry.earliest(deadline)
                }
                Err(_) => grant.expires = now,
            }
        }
    }

    #[cfg(test)]
    pub(super) fn new(
        rules: &[GrantRule],
        wall_now: OffsetDateTime,
        now: Instant,
        anchor: Sample,
    ) -> Result<Self, AuthorizationError> {
        let grants = rules
            .iter()
            .map(|rule| {
                let remaining =
                    Duration::try_from(rule.expires_unix - wall_now).unwrap_or_default();
                let expires = now
                    .checked_add(remaining)
                    .ok_or(AuthorizationError::InvalidPolicy)?;
                let rule = rule.clone();
                Ok(Grant {
                    credential: crate::owner::test_support::vault::selection(
                        &crate::owner::test_support::vault::snapshot(&rule.role),
                    ),
                    rule,
                    expires,
                    continuous_expiry: Deadline::at(anchor, remaining)
                        .map_err(|_| AuthorizationError::InvalidPolicy)?,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { grants })
    }

    pub(super) fn issue(
        &mut self,
        proposal: ReadGrantProposal,
        selection: CredentialSelection,
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        self.grants.retain(|grant| grant.check(now).is_ok());
        if self.grants.len() >= 64
            || proposal.rule.role != selection.role()
            || self
                .grants
                .iter()
                .any(|grant| grant.rule.id == proposal.rule.id)
        {
            return Err(AuthorizationError::Denied);
        }
        let grant = Grant {
            rule: proposal.rule,
            expires: proposal.expires,
            continuous_expiry: proposal.continuous_expiry,
            credential: selection,
        };
        grant.check(now)?;
        self.grants.push(grant);
        Ok(())
    }

    pub(super) fn authorize(
        &self,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
        now: Instant,
    ) -> Result<GrantUse, AuthorizationError> {
        let grant = self
            .grants
            .iter()
            .rev()
            .find(|grant| grant.rule.matches(principal, operation, session))
            .ok_or(AuthorizationError::Denied)?;
        grant.check(now)?;
        Ok(GrantUse {
            id: GrantId(grant.rule.id.0.clone()),
            role: grant.rule.role.clone(),
        })
    }

    pub(super) fn accepts(&self, use_: &GrantUse, selection: &CredentialSelection) -> bool {
        self.grants
            .iter()
            .find(|grant| grant.rule.id == use_.id && grant.rule.role == selection.role())
            .is_some_and(|grant| grant.credential.same_credential(selection))
    }

    pub(super) fn check(
        &self,
        use_: &GrantUse,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        let grant = self
            .grants
            .iter()
            .find(|grant| {
                grant.rule.id == use_.id
                    && grant.rule.role == use_.role
                    && grant.rule.matches(principal, operation, session)
            })
            .ok_or(AuthorizationError::Denied)?;
        grant.check(now)
    }

    pub(super) fn consume(
        &self,
        use_: GrantUse,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        self.check(&use_, principal, operation, session, now)
    }

    pub(super) fn deadline(
        &self,
        use_: &GrantUse,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
        now: Instant,
    ) -> Result<Deadline, AuthorizationError> {
        self.check(use_, principal, operation, session, now)?;
        self.grants
            .iter()
            .find(|grant| grant.rule.id == use_.id)
            .ok_or(AuthorizationError::Denied)
            .and_then(|grant| {
                let uptime = Deadline::from_instant(grant.expires)
                    .map_err(|_| AuthorizationError::Expired)?;
                Ok(grant.continuous_expiry.earliest(uptime))
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::owner::policy::fixture::FixturePolicy;
    use crate::owner::{
        identity::VerifiedPrincipal,
        policy::*,
        test_support::{policy_bytes, read_request},
    };
    use std::time::{Duration, Instant};

    fn setup() -> (Authorizer, Instant) {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        (owner, now)
    }

    #[test]
    fn issuance_capacity_counts_only_usable_grants() {
        let principal = crate::owner::test_support::principal([1; 16]);
        let snapshot = crate::owner::test_support::vault::snapshot("github-read");
        for expired_uptime in [false, true] {
            let mut grants = super::GrantTable::default();
            for _ in 0..65 {
                let proposal =
                    super::ReadGrantProposal::new(&principal, &read_request(), "github-read")
                        .unwrap();
                grants
                    .issue(
                        proposal,
                        crate::owner::test_support::vault::selection(&snapshot),
                        Instant::now(),
                    )
                    .unwrap();
                let latest = grants.grants.last_mut().unwrap();
                if expired_uptime {
                    latest.expires = Instant::now();
                } else {
                    latest.continuous_expiry =
                        crate::owner::deadline::Deadline::after(Duration::ZERO).unwrap();
                }
            }
            assert_eq!(grants.grants.len(), 1);
        }
    }

    #[test]
    fn issuance_rejects_overflow_without_removing_live_grants() {
        let principal = crate::owner::test_support::principal([1; 16]);
        let snapshot = crate::owner::test_support::vault::snapshot("github-read");
        let mut grants = super::GrantTable::default();
        for _ in 0..64 {
            grants
                .issue(
                    super::ReadGrantProposal::new(&principal, &read_request(), "github-read")
                        .unwrap(),
                    crate::owner::test_support::vault::selection(&snapshot),
                    Instant::now(),
                )
                .unwrap();
        }
        assert!(
            grants
                .issue(
                    super::ReadGrantProposal::new(&principal, &read_request(), "github-read")
                        .unwrap(),
                    crate::owner::test_support::vault::selection(&snapshot),
                    Instant::now(),
                )
                .is_err()
        );
        assert_eq!(grants.grants.len(), 64);
    }

    #[test]
    fn grant_binds_the_verified_user_code_and_session() {
        let (owner, now) = setup();
        for principal in [
            VerifiedPrincipal::fixture(502, "11".repeat(20), [1; 16]),
            VerifiedPrincipal::fixture(501, "22".repeat(20), [1; 16]),
            VerifiedPrincipal::fixture(501, "11".repeat(20), [2; 16]),
        ] {
            assert!(owner.authorize(&principal, read_request(), now).is_err());
        }
    }

    #[test]
    fn activity_and_unchanged_policy_reload_do_not_extend_grant_expiry() {
        let (mut owner, now) = setup();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let AuthorizationOutcome::Allowed(permit) = owner
            .authorize(&principal, read_request(), now + Duration::from_secs(9))
            .unwrap()
        else {
            panic!()
        };
        owner
            .admit(permit, &principal, now + Duration::from_secs(9))
            .unwrap();
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1009),
                now + Duration::from_secs(9),
            )
            .unwrap();
        let AuthorizationOutcome::Allowed(permit) = owner
            .authorize(&principal, read_request(), now + Duration::from_secs(9))
            .unwrap()
        else {
            panic!()
        };
        owner
            .admit(permit, &principal, now + Duration::from_secs(9))
            .unwrap();
        assert!(
            owner
                .authorize(&principal, read_request(), now + Duration::from_secs(9))
                .is_ok()
        );

        assert!(matches!(
            owner.authorize(&principal, read_request(), now + Duration::from_secs(10)),
            Err(AuthorizationError::Expired)
        ));
    }

    #[test]
    fn grant_expiry_preserves_fractional_wall_clock_precision() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1009) + Duration::from_millis(500),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);

        assert!(
            owner
                .authorize(&principal, read_request(), now + Duration::from_millis(499))
                .is_ok()
        );
        assert!(matches!(
            owner.authorize(&principal, read_request(), now + Duration::from_millis(500)),
            Err(AuthorizationError::Expired)
        ));
    }

    #[test]
    fn an_operation_cannot_be_admitted_for_another_principal() {
        let (mut owner, now) = setup();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let other = VerifiedPrincipal::fixture(502, "11".repeat(20), [1; 16]);
        let AuthorizationOutcome::Allowed(permit) =
            owner.authorize(&principal, read_request(), now).unwrap()
        else {
            panic!()
        };

        assert!(matches!(
            owner.admit(permit, &other, now),
            Err(AuthorizationError::WrongPrincipal)
        ));
    }

    #[test]
    fn admission_rechecks_expiry_and_revocation_after_preparation() {
        for revoke in [false, true] {
            let (mut owner, now) = setup();
            let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
            let AuthorizationOutcome::Allowed(permit) =
                owner.authorize(&principal, read_request(), now).unwrap()
            else {
                panic!()
            };
            if revoke {
                owner.revoke_session();
            }

            assert!(
                owner
                    .admit(permit, &principal, now + Duration::from_secs(10))
                    .is_err()
            );
        }
    }

    #[test]
    fn unchanged_reload_expires_a_grant_after_sleep_even_if_the_local_uptime_clock_paused() {
        let (mut owner, now) = setup();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        assert!(
            !owner
                .install(
                    FixturePolicy::decode(&policy_bytes(1010)),
                    crate::owner::test_support::wall(1011),
                    now
                )
                .unwrap()
        );
        assert!(matches!(
            owner.authorize(&principal, read_request(), now),
            Err(AuthorizationError::Expired)
        ));
    }

    #[test]
    fn continuous_expiry_rejects_a_read_even_if_uptime_and_wall_clock_have_not_advanced() {
        let now = Instant::now();
        let document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010)).unwrap();
        let rule = serde_json::from_value(document["grants"][0].clone()).unwrap();
        let mut grants = super::GrantTable::new(
            &[rule],
            crate::owner::test_support::wall(1000),
            now,
            crate::owner::deadline::continuous_now().unwrap(),
        )
        .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = read_request();
        let permit = grants
            .authorize(&principal, &request, [1; 16], now)
            .unwrap();
        grants.grants[0].continuous_expiry =
            crate::owner::deadline::Deadline::after(Duration::ZERO).unwrap();
        grants.clamp_expiry(
            crate::owner::test_support::wall(990),
            now,
            crate::owner::deadline::continuous_now().unwrap(),
        );
        assert!(matches!(
            grants.check(&permit, &principal, &request, [1; 16], now),
            Err(AuthorizationError::Expired)
        ));
    }

    #[test]
    fn grant_deadlines_keep_the_original_continuous_anchor_through_install_reload_and_network_selection()
     {
        let now = Instant::now();
        let anchor = crate::owner::deadline::continuous_now().unwrap();
        let document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010)).unwrap();
        let rule = serde_json::from_value(document["grants"][0].clone()).unwrap();
        let mut grants =
            super::GrantTable::new(&[rule], crate::owner::test_support::wall(1000), now, anchor)
                .unwrap();
        let expected =
            crate::owner::deadline::Deadline::at(anchor, Duration::from_secs(10)).unwrap();
        assert_eq!(grants.grants[0].continuous_expiry, expected);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        let request = read_request();
        let permit = grants
            .authorize(&principal, &request, [1; 16], now)
            .unwrap();
        let selected = grants
            .deadline(&permit, &principal, &request, [1; 16], now)
            .unwrap();
        assert!(
            selected
                .remaining_at(anchor.checked_add(Duration::from_secs(10)).unwrap())
                .is_err()
        );
        let after_sleep = anchor.checked_add(Duration::from_secs(20)).unwrap();
        grants.clamp_expiry(crate::owner::test_support::wall(990), now, after_sleep);
        assert_eq!(grants.grants[0].continuous_expiry, expected);
        assert!(
            grants.grants[0]
                .continuous_expiry
                .remaining_at(after_sleep)
                .is_err()
        );
    }

    #[test]
    fn unchanged_reload_shortens_to_remaining_absolute_expiry_and_a_clock_rollback_cannot_extend_it()
     {
        let (mut owner, now) = setup();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(1005),
                now,
            )
            .unwrap();
        assert!(
            owner
                .authorize(
                    &principal,
                    read_request(),
                    now + Duration::from_millis(4999)
                )
                .is_ok()
        );
        assert!(matches!(
            owner.authorize(&principal, read_request(), now + Duration::from_secs(5)),
            Err(AuthorizationError::Expired)
        ));
        owner
            .install(
                FixturePolicy::decode(&policy_bytes(1010)),
                crate::owner::test_support::wall(990),
                now + Duration::from_secs(1),
            )
            .unwrap();
        assert!(matches!(
            owner.authorize(&principal, read_request(), now + Duration::from_secs(5)),
            Err(AuthorizationError::Expired)
        ));
    }

    fn github_config(id: u64) -> crate::owner::github::configuration::GitHubConfig {
        crate::owner::github::configuration::GitHubConfig::decode(
            &serde_json::to_vec(
                &serde_json::json!({"version":1,"mode":"github","repositories":[
                    {"id":id,"owner":"example","name":"one","writes":true},
                    {"id":456,"owner":"example","name":"two"}
                ]}),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn github_policy(id: u64) -> FixturePolicy {
        let mut document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010)).unwrap();
        document["grants"][0]["repository"] = "example/one".into();
        let mut list = document["grants"][0].clone();
        list["id"] = "22222222222222222222222222222222".into();
        list["action"] = "listIssues".into();
        document["grants"].as_array_mut().unwrap().push(list);
        FixturePolicy::decode(&serde_json::to_vec(&document).unwrap())
            .unwrap()
            .with_github(github_config(id))
    }

    fn github_read(
        config: &crate::owner::github::configuration::GitHubConfig,
        path: &str,
    ) -> crate::owner::request::FrozenOperation {
        crate::owner::request::read_configured(
            &mut std::io::Cursor::new(format!(
                "GET {path} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
            )),
            Some(config),
        )
        .unwrap()
    }

    #[test]
    fn github_grants_allow_only_the_configured_read_action_and_repository_without_presence() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                Ok(github_policy(123)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        for path in [
            "/repos/example/one/issues",
            "/repos/example/one/issues/123456789",
        ] {
            for _ in 0..2 {
                let AuthorizationOutcome::Allowed(permit) = owner
                    .authorize(&principal, github_read(&github_config(123), path), now)
                    .unwrap()
                else {
                    panic!("read requested presence");
                };
                owner.admit(permit, &principal, now).unwrap();
            }
            assert!(
                owner
                    .authorize(&principal, github_read(&github_config(123), path), now)
                    .is_ok()
            );
        }
        assert!(matches!(
            owner.authorize(
                &principal,
                github_read(&github_config(123), "/repos/example/two/issues/1"),
                now
            ),
            Err(AuthorizationError::Denied)
        ));
    }

    #[test]
    fn github_grants_reject_requests_parsed_with_a_different_repository_id_or_configuration() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        owner
            .install(
                Ok(github_policy(123)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        assert!(matches!(
            owner.authorize(
                &principal,
                github_read(&github_config(789), "/repos/example/one/issues/1"),
                now
            ),
            Err(AuthorizationError::Denied)
        ));
    }

    #[test]
    fn github_grants_keep_expiry_on_reload_and_revoke_old_permits_on_change_and_revert() {
        let now = Instant::now();
        let mut owner = Authorizer::new([1; 16]);
        let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
        owner
            .install(
                Ok(github_policy(123)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        let request = || github_read(&github_config(123), "/repos/example/one/issues/1");
        let AuthorizationOutcome::Allowed(first) =
            owner.authorize(&principal, request(), now).unwrap()
        else {
            panic!()
        };
        owner.admit(first, &principal, now).unwrap();
        assert!(
            !owner
                .install(
                    Ok(github_policy(123)),
                    crate::owner::test_support::wall(1009),
                    now + Duration::from_secs(9)
                )
                .unwrap()
        );
        let AuthorizationOutcome::Allowed(second) = owner
            .authorize(&principal, request(), now + Duration::from_secs(9))
            .unwrap()
        else {
            panic!()
        };
        owner
            .admit(second, &principal, now + Duration::from_secs(9))
            .unwrap();
        assert!(
            owner
                .authorize(&principal, request(), now + Duration::from_secs(9))
                .is_ok()
        );
        assert!(matches!(
            owner.authorize(&principal, request(), now + Duration::from_secs(10)),
            Err(AuthorizationError::Expired)
        ));
        let AuthorizationOutcome::Allowed(old) = owner
            .authorize(
                &principal,
                github_read(&github_config(123), "/repos/example/one/issues"),
                now,
            )
            .unwrap()
        else {
            panic!()
        };
        owner
            .install(
                Ok(github_policy(789)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        owner
            .install(
                Ok(github_policy(123)),
                crate::owner::test_support::wall(1000),
                now,
            )
            .unwrap();
        assert!(matches!(
            owner.admit(old, &principal, now),
            Err(AuthorizationError::PolicyChanged)
        ));
    }
}
