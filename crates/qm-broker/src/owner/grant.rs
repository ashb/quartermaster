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
    budget: Option<u32>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub(super) struct ReadGrantClaims {
    purpose: &'static str,
    grant: GrantRule,
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
            || self.budget == Some(0)
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
    remaining: Option<u32>,
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
                budget: Some(100),
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
        if self.remaining == Some(0) {
            return Err(AuthorizationError::BudgetExhausted);
        }
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
                    remaining: rule.budget,
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
        let mut grant = Grant {
            remaining: proposal.rule.budget,
            rule: proposal.rule,
            expires: proposal.expires,
            continuous_expiry: proposal.continuous_expiry,
            credential: selection,
        };
        grant.check(now)?;
        if let Some(remaining) = &mut grant.remaining {
            *remaining -= 1;
        }
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
        &mut self,
        use_: GrantUse,
        principal: &VerifiedPrincipal,
        operation: &FrozenOperation,
        session: [u8; 16],
        now: Instant,
    ) -> Result<(), AuthorizationError> {
        let grant = self
            .grants
            .iter_mut()
            .find(|grant| {
                grant.rule.id == use_.id
                    && grant.rule.role == use_.role
                    && grant.rule.matches(principal, operation, session)
            })
            .ok_or(AuthorizationError::Denied)?;
        grant.check(now)?;
        if let Some(remaining) = &mut grant.remaining {
            *remaining -= 1;
        }
        Ok(())
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
#[path = "../../tests/unit/grant.rs"]
mod tests;
