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
    pub(super) build: Option<crate::owner::protocol::BuildInfo>,
    pub(super) administration: super::settings::Administration,
    pub(super) ui: Option<UiSession>,
    pub(super) frontend_requirement: Option<String>,
    pub(super) approval_public_key: Option<Vec<u8>>,
    pub(super) pending: Option<ApprovalDelivery>,
    pub(super) approval_queue: crate::owner::approval_queue::Queue,
    pub(super) provider: ProviderState,
    pub(super) authorizer: Authorizer,
    pub(super) session_policy: SessionPolicy,
    pub(super) upstream: DummyUpstream,
    pub(super) github: Connector,
    pub(super) github_resources: crate::owner::github::resource_context::ResourceCache,
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
            build: None,
            administration: super::settings::Administration::default(),
            ui: None,
            frontend_requirement: None,
            approval_public_key: None,
            pending: None,
            approval_queue: Default::default(),
            provider: ProviderState::default(),
            authorizer: Authorizer::new(random()?),
            session_policy: SessionPolicy::default(),
            upstream: DummyUpstream::default(),
            github: Connector::default(),
            github_resources: Default::default(),
            operations: OperationRegistry::default(),
            host_events: HostEvents::default(),
            observed_events: Observation::default(),
            console_capture,
            interactive,
            policy_stamp: None,
        })
    }

    pub(super) fn github_binding(&self) -> Result<qm_providers::ProviderBinding> {
        if let Some(manager) = &self.administration.manager {
            let record = manager.record();
            let pin = record.provider().ok_or(Fault::ProviderChanged)?;
            return record
                .settings()
                .ok_or(Fault::ProviderChanged)?
                .github_binding(&pin.binding)
                .map_err(Into::into);
        }
        Err(Fault::ProviderChanged.into())
    }

    pub(super) fn github_selection(
        &self,
        snapshot: &qm_providers::VaultSnapshot,
    ) -> Result<CredentialSelection> {
        CredentialSelection::at_generation(
            snapshot,
            &self.github_binding()?,
            self.provider.generation(),
        )
        .map_err(crate::owner::vault::Error::from)
        .map_err(Into::into)
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
            self.github_resources.clear();
            self.authorizer.invalidate_policy()?;
        }
        self.policy_stamp = stamp;
        match self.authorizer.install_current(decoded) {
            Ok(true) => {
                self.approval_queue.clear();
                self.github_resources.clear();
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
        mut request: http_request::FrozenOperation,
        policy: &PolicyInput,
        binding: Result<Option<qm_providers::AccountBinding>, crate::owner::vault::Error>,
    ) -> Result<AuthorizationOutcome> {
        self.refresh_policy(policy)?;
        let now = Instant::now();
        if let Some(snapshot) = self.provider.snapshot()
            && let Some(configuration) = self.authorizer.github_configuration()
            && request.matches_service(configuration)
        {
            self.github_resources.resolve(
                &mut request,
                self.github_selection(snapshot)?,
                self.authorizer.policy_generation(),
                configuration.digest(),
                now,
            );
        }
        let outcome = self
            .authorizer
            .authorize(principal, request.clone(), now)
            .and_then(|outcome| {
                if let AuthorizationOutcome::Allowed(permit) = &outcome
                    && let Some(snapshot) = self.provider.snapshot()
                {
                    let selection = self
                        .github_selection(snapshot)
                        .map_err(|_| AuthorizationError::CredentialMismatch)?;
                    self.authorizer
                        .check_acquisition(permit, principal, &selection, now)?;
                }
                Ok(outcome)
            });
        match outcome {
            Err(
                AuthorizationError::Denied
                | AuthorizationError::Expired
                | AuthorizationError::CredentialMismatch,
            ) if request.is_reusable_read() => {
                let selected_binding = self.github_binding()?;
                if let Some(account) = binding?
                    && selected_binding.account() != account
                {
                    return Err(Fault::ProviderChanged.into());
                }
                let role = selected_binding.role().to_owned();
                self.authorizer
                    .request_read_grant(principal, request, &role)
                    .map_err(Error::from)
                    .map(AuthorizationOutcome::RequireApproval)
            }
            outcome => outcome.map_err(Error::from),
        }
    }

    pub(super) fn check_review_context(
        &self,
        id: crate::owner::operation::OperationId,
        principal: &VerifiedPrincipal,
    ) -> Result<()> {
        let request = self.operations.request(id, principal)?;
        if let Some(target) = request
            .application()
            .and_then(|application| application.resource_context.as_ref())
        {
            let snapshot = self
                .provider
                .snapshot()
                .ok_or(Error::State(Fault::ProviderChanged))?;
            let configuration = self
                .authorizer
                .github_configuration()
                .ok_or(Error::State(Fault::ProviderChanged))?;
            let selection = self.github_selection(snapshot)?;
            if !target.matches(
                &selection,
                self.authorizer.policy_generation(),
                configuration.digest(),
            ) {
                return Err(Error::State(Fault::ProviderChanged));
            }
        }
        Ok(())
    }

    pub(super) fn cancel_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.operations.cancel(pending.id, &pending.principal);
        }
    }

    pub(super) fn disconnect_ui(&mut self) {
        self.administration.cancel_changes();
        self.disconnect_approval_ui();
    }

    fn disconnect_approval_ui(&mut self) {
        self.approval_queue.clear();
        if let Some(ui) = self.ui.take() {
            self.operations.cancel_interactive_session(ui.session.id());
        }
        self.cancel_pending();
    }

    pub(super) fn lock_vault(&mut self) -> Result<()> {
        self.github_resources.clear();
        self.disconnect_ui();
        self.provider.lock()?;
        Ok(())
    }

    pub(super) fn end_host_session(&mut self) -> Result<()> {
        if !self.authorizer.session_active() {
            return Ok(());
        }
        self.authorizer.revoke_session();
        self.github_resources.clear();
        self.disconnect_ui();
        self.provider.lock().map_err(Error::from)
    }

    pub(super) fn host_session_event(&mut self, event: HostSessionEvent) -> Result<()> {
        if !self.session_policy.preserves_reads(event) {
            return self.end_host_session();
        }
        self.authorizer.revoke_approvals();
        self.operations.cancel_approvals();
        if event == HostSessionEvent::ConsoleChange {
            self.administration.console_changed();
            self.disconnect_approval_ui();
        } else {
            self.disconnect_ui();
        }
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
        dispatch::PreparedOperation,
        runtime::tests::fixture,
        settings::Settings,
        test_support::{self, vault},
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
        state.administration.manager = Some(crate::owner::test_support::vault::manager());
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
                serde_json::from_slice(&test_support::policy_bytes(expires)).unwrap();
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
            let selection = state
                .github_selection(state.provider.snapshot().unwrap())
                .unwrap();
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
                    .is_ok()
            );
        }
    }

    #[test]
    fn github_uses_the_signed_selection_and_never_falls_back_to_another_account() {
        let mut state = OwnerState::new().unwrap();
        let snapshot = vault::catalogue(
            vault::binding("github-write", "22222222-2222-4222-8222-222222222222"),
            &[
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
            ],
        );
        let settings = |item: Option<&str>| {
            Settings::decode(&serde_json::to_vec(&serde_json::json!({
                "github":null, "mutations":"requireApproval", "githubCredential":item.map(|item| serde_json::json!({"itemId":item}))
            })).unwrap()).unwrap()
        };
        state.administration.manager = Some(vault::manager_with_settings(settings(None)));
        assert!(state.github_binding().is_err());
        assert!(state.github_selection(&snapshot).is_err());
        state.administration.manager = Some(vault::manager_with_settings(settings(Some(
            "22222222-2222-4222-8222-222222222222",
        ))));
        let original = state.github_selection(&snapshot).unwrap();
        state.administration.manager = Some(vault::manager_with_settings(settings(Some(
            "33333333-3333-4333-8333-333333333333",
        ))));
        let replacement = state.github_selection(&snapshot).unwrap();
        assert_eq!(original.digest(), replacement.digest());
        assert!(!original.same_credential(&replacement));
        let other_account = vault::snapshot_for_account(
            "github-write",
            "33333333-3333-4333-8333-333333333333",
            [3; 16],
            snapshot.synchronized_at(),
            "44444444-4444-4444-8444-444444444444",
        );
        assert!(state.github_selection(&other_account).is_err());
    }
}
