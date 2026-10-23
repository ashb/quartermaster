use super::error::{Error, Fault, Result};
use super::{
    PolicyInput,
    approval::{ApprovalDelivery, UiSession},
    random,
};
use crate::owner::{
    dispatch::CredentialSelection,
    github::https::Connector,
    identity::VerifiedPrincipal,
    operation::OperationRegistry,
    policy::{AuthorizationError, AuthorizationOutcome, Authorizer, SessionPolicy},
    provider_lifecycle::ProviderState,
    request as http_request,
    transport::DummyUpstream,
};
use crate::platform::HostSessionEvent;
use crate::platform::lifecycle::{HostEvents, Observation};
use qm_macos::console_session::Transition;
use std::time::Instant;

struct ConsoleObservation {
    transition: Transition,
    interactive: bool,
}

type ConsoleCapture =
    Box<dyn FnMut() -> Result<ConsoleObservation, qm_macos::console_session::Error> + Send>;

pub(super) struct OwnerState {
    pub(super) ui: Option<UiSession>,
    pub(super) approval_public_key: Option<Vec<u8>>,
    pub(super) pending: Option<ApprovalDelivery>,
    pub(super) provider: ProviderState,
    pub(super) authorizer: Authorizer,
    pub(super) session_policy: SessionPolicy,
    pub(super) upstream: DummyUpstream,
    pub(super) github: Connector,
    pub(super) operations: OperationRegistry,
    pub(super) host_events: HostEvents,
    observed_events: Observation,
    console_capture: Option<ConsoleCapture>,
    interactive: bool,
    policy_stamp: Option<super::policy_source::Stamp>,
}

impl OwnerState {
    #[cfg(test)]
    pub(super) fn new() -> Result<Self> {
        Self::with_console(None, true)
    }

    pub(super) fn for_service() -> Result<Self> {
        let mut previous = qm_macos::console_session::ConsoleSession::capture()?;
        let interactive = previous.interactive();
        Self::with_console(
            Some(Box::new(move || {
                let current = qm_macos::console_session::ConsoleSession::capture()?;
                let observation = ConsoleObservation {
                    transition: previous.transition_to(&current),
                    interactive: current.interactive(),
                };
                previous = current;
                Ok(observation)
            })),
            interactive,
        )
    }

    fn with_console(console_capture: Option<ConsoleCapture>, interactive: bool) -> Result<Self> {
        Ok(Self {
            ui: None,
            approval_public_key: None,
            pending: None,
            provider: ProviderState::default(),
            authorizer: Authorizer::new(random()?),
            session_policy: SessionPolicy::default(),
            upstream: DummyUpstream::default(),
            github: Connector::default(),
            operations: OperationRegistry::default(),
            host_events: HostEvents::default(),
            observed_events: Observation::default(),
            console_capture,
            interactive,
            policy_stamp: None,
        })
    }

    pub(super) fn refresh_policy(&mut self, policy: &PolicyInput) -> Result<()> {
        self.synchronize_host_events()?;
        let (stamp, decoded) = match policy {
            Ok(observation) => {
                let (stamp, decoded) = observation.current()?;
                (Some(stamp.clone()), decoded)
            }
            Err(error) => (None, Err(error.clone())),
        };
        let changed = stamp.as_ref().is_some_and(|stamp| {
            self.policy_stamp
                .as_ref()
                .is_some_and(|old| !old.same_as(stamp))
        });
        if changed {
            self.authorizer.invalidate_policy()?;
        }
        self.policy_stamp = stamp;
        match self.authorizer.install_current(decoded) {
            Ok(true) => {
                self.cancel_pending();
                if let Some(ui) = &self.ui {
                    ui.session.update_policy(self.authorizer.policy_digest()?)?;
                }
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(error) => {
                self.disconnect_ui();
                Err(Error::Authorization(error))
            }
        }
    }

    pub(super) fn authorize(
        &mut self,
        principal: &VerifiedPrincipal,
        request: http_request::FrozenOperation,
        policy: &PolicyInput,
        binding: Result<Option<qm_providers::ProviderBinding>, crate::owner::vault::Error>,
    ) -> Result<AuthorizationOutcome> {
        self.refresh_policy(policy)?;
        let now = Instant::now();
        let outcome = self
            .authorizer
            .authorize(principal, request.clone(), now)
            .and_then(|outcome| {
                if let AuthorizationOutcome::Allowed(permit) = &outcome
                    && let Some(snapshot) = self.provider.snapshot()
                {
                    let selection =
                        CredentialSelection::at_generation(snapshot, self.provider.generation());
                    self.authorizer
                        .check_acquisition(permit, principal, &selection, now)?;
                }
                Ok(outcome)
            });
        match outcome {
            Err(
                AuthorizationError::Denied
                | AuthorizationError::Expired
                | AuthorizationError::BudgetExhausted
                | AuthorizationError::CredentialMismatch,
            ) if matches!(
                request.action(),
                http_request::Action::ReadIssue | http_request::Action::ListIssues
            ) =>
            {
                let role = match self.provider.snapshot() {
                    Some(snapshot) => snapshot.binding().role().to_owned(),
                    None => binding?
                        .ok_or_else(|| Error::State(Fault::VaultLocked))?
                        .role()
                        .to_owned(),
                };
                self.authorizer
                    .request_read_grant(principal, request, &role)
                    .map_err(Error::from)
                    .map(AuthorizationOutcome::RequireApproval)
            }
            outcome => outcome.map_err(Error::from),
        }
    }

    pub(super) fn cancel_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.operations.cancel(pending.id, &pending.principal);
        }
    }

    pub(super) fn disconnect_ui(&mut self) {
        if let Some(ui) = self.ui.take() {
            self.operations.cancel_interactive_session(ui.session.id());
        }
        self.cancel_pending();
    }

    pub(super) fn lock_vault(&mut self) -> Result<()> {
        self.disconnect_ui();
        self.provider.lock()?;
        Ok(())
    }

    pub(super) fn end_host_session(&mut self) -> Result<()> {
        if !self.authorizer.session_active() {
            return Ok(());
        }
        self.authorizer.revoke_session();
        self.disconnect_ui();
        self.provider.lock().map_err(Error::from)
    }

    pub(super) fn host_session_event(&mut self, event: HostSessionEvent) -> Result<()> {
        if !self.session_policy.preserves_reads(event) {
            return self.end_host_session();
        }
        self.authorizer.revoke_approvals();
        self.operations.cancel_approvals();
        self.disconnect_ui();
        self.provider.cancel_pending();
        Ok(())
    }

    pub(super) fn synchronize_host_events(&mut self) -> Result<()> {
        if let Some(capture) = self.console_capture.as_mut() {
            match capture() {
                Ok(current) => {
                    match current.transition {
                        Transition::Unchanged => {}
                        Transition::ConsoleChanged => {
                            self.host_events.record(HostSessionEvent::ConsoleChange)
                        }
                        Transition::PowerChanged => self.host_events.record(HostSessionEvent::Wake),
                        Transition::LoginChanged => {
                            self.host_events.record(HostSessionEvent::Logout)
                        }
                        Transition::InvalidGeneration => self.host_events.fail(),
                    }
                    self.interactive = current.interactive;
                }
                Err(qm_macos::console_session::Error::Transition) => {
                    self.interactive = false;
                    self.host_events.record(HostSessionEvent::ConsoleChange)
                }
                Err(_) => self.host_events.fail(),
            }
        }
        match self.host_events.observe(self.observed_events) {
            Ok((observed, events)) => {
                for event in events {
                    self.host_session_event(event)?;
                }
                self.observed_events = observed;
            }
            Err(()) => self.end_host_session()?,
        }
        Ok(())
    }

    pub(super) fn ensure_host_session(&mut self) -> Result<()> {
        self.synchronize_host_events()?;
        if self.authorizer.session_active() {
            Ok(())
        } else {
            Err(Error::State(Fault::SessionEnded))
        }
    }

    pub(super) fn ensure_interactive(&mut self) -> Result<()> {
        self.ensure_host_session()?;
        if !self.interactive {
            return Err(Error::State(Fault::UiDisconnected));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner::{
        dispatch::{CredentialSelection, PreparedOperation},
        runtime::tests::fixture,
        test_support,
        vault::Source,
    };
    use qm_macos::console_session::Error as ConsoleError;
    use std::{sync::Arc, time::Duration};
    use time::OffsetDateTime;

    #[test]
    fn console_capture_revokes_writes_and_provider_completions_before_admission() {
        for sample in [
            Ok(ConsoleObservation {
                transition: Transition::ConsoleChanged,
                interactive: true,
            }),
            Ok(ConsoleObservation {
                transition: Transition::PowerChanged,
                interactive: true,
            }),
            Ok(ConsoleObservation {
                transition: Transition::LoginChanged,
                interactive: true,
            }),
            Ok(ConsoleObservation {
                transition: Transition::InvalidGeneration,
                interactive: true,
            }),
            Err(ConsoleError::Unavailable),
            Err(ConsoleError::InvalidProperty),
            Err(ConsoleError::NoSession),
            Err(ConsoleError::Transition),
        ] {
            let ends_session = matches!(
                &sample,
                Ok(ConsoleObservation {
                    transition: Transition::LoginChanged | Transition::InvalidGeneration,
                    ..
                }) | Err(ConsoleError::Unavailable
                    | ConsoleError::InvalidProperty
                    | ConsoleError::NoSession)
            );
            let (_directory, paths, _key, mut state, _receive) = fixture();
            let pending = state.pending.as_ref().unwrap();
            let write = pending.id;
            let principal = Arc::clone(&pending.principal);
            let identity = Source::capture(&paths.root).unwrap().identity().unwrap();
            let (operation, _) = state.provider.begin_refresh(&identity).unwrap();
            let mut next = Some(sample);
            state.console_capture = Some(Box::new(move || next.take().unwrap()));
            assert!(
                state
                    .prepare(write, &principal, &paths.load_policy())
                    .is_err()
            );
            assert!(state.pending.is_none());
            assert!(state.ui.is_none());
            assert!(state.provider.check(&operation, identity.revision).is_err());
            assert_eq!(state.authorizer.session_active(), !ends_session);
            assert_eq!(state.provider.snapshot().is_none(), ends_session);
        }
    }

    #[test]
    fn an_unstable_sample_blocks_interactive_work_until_a_stable_capture() {
        let mut state = OwnerState::new().unwrap();
        let mut unstable = true;
        state.console_capture = Some(Box::new(move || {
            if std::mem::take(&mut unstable) {
                Err(ConsoleError::Transition)
            } else {
                Ok(ConsoleObservation {
                    transition: Transition::Unchanged,
                    interactive: true,
                })
            }
        }));
        assert!(state.ensure_interactive().is_err());
        assert!(state.ensure_interactive().is_ok());
    }

    #[test]
    fn an_observed_policy_reversion_revokes_previous_operation_authority() {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        let pending = state.pending.as_ref().unwrap();
        let write = pending.id;
        let principal = Arc::clone(&pending.principal);
        let old = paths.load_policy();
        paths
            .policy
            .read(|| Err(AuthorizationError::InvalidPolicy))
            .unwrap();
        let reverted = paths.load_policy();
        assert!(state.refresh_policy(&old).is_err());
        state.refresh_policy(&reverted).unwrap();
        assert!(state.pending.is_none());
        assert!(
            state
                .prepare(write, &principal, &paths.load_policy())
                .is_err()
        );
    }

    #[test]
    fn console_changes_preserve_a_prepared_scoped_read_when_session_policy_allows_it() {
        for unstable in [false, true] {
            let (_directory, paths, _key, mut state, _receive) = fixture();
            let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
            let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60))
                .unix_timestamp()
                .try_into()
                .unwrap();
            let mut grants: serde_json::Value =
                serde_json::from_slice(&test_support::policy_bytes(expires, 1)).unwrap();
            grants["grants"][0]["role"] = "github-write".into();
            state
                .authorizer
                .seed_fixture_grants(&serde_json::to_vec(&grants).unwrap());
            let outcome = state
                .authorize(
                    &principal,
                    test_support::read_request(),
                    &paths.load_policy(),
                    Ok(None),
                )
                .unwrap();
            let read = state.operations.register(outcome, Instant::now()).unwrap();
            let selection = CredentialSelection::at_generation(
                state.provider.snapshot().unwrap(),
                state.provider.generation(),
            );
            state
                .operations
                .select_credential(read, &principal, selection)
                .unwrap();
            let prepared = PreparedOperation::new(
                state
                    .prepare(read, &principal, &paths.load_policy())
                    .unwrap(),
                state.upstream.connect().unwrap(),
            );
            state.console_capture = Some(Box::new(move || {
                if unstable {
                    Err(ConsoleError::Transition)
                } else {
                    Ok(ConsoleObservation {
                        transition: Transition::ConsoleChanged,
                        interactive: true,
                    })
                }
            }));
            state
                .handoff(prepared, &principal, &paths.load_policy())
                .unwrap();
            assert!(state.pending.is_none());
            assert!(state.provider.snapshot().is_some());
            assert!(
                state
                    .authorizer
                    .authorize(&principal, test_support::read_request(), Instant::now())
                    .is_err()
            );
        }
    }
}
