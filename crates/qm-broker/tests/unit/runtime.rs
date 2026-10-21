use super::*;
use crate::owner::operation::Admission;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn a_changed_selected_credential_requires_fresh_grant_approval() {
    let (_root, paths, _key, mut state, _receive) = fixture();
    state.cancel_pending();
    let principal = crate::owner::test_support::principal(state.authorizer.session());
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    crate::owner::test_support::approval::read_grant(
        &mut state.operations,
        &mut state.authorizer,
        &principal,
        &snapshot,
    );
    let changed = crate::owner::test_support::vault::snapshot_with(
        "github-write",
        "33333333-3333-4333-8333-333333333333",
        [4; 16],
    );
    crate::owner::test_support::vault::install(&mut state.provider, changed);
    assert!(matches!(
        state.authorize(
            &principal,
            crate::owner::test_support::read_request(),
            &paths
        ),
        Ok(AuthorizationOutcome::RequireApproval(_))
    ));
}

#[test]
fn expired_or_exhausted_reads_require_fresh_approval_and_can_recover() {
    for expire in [false, true] {
        let (_root, paths, _key, mut state, _receive) = fixture();
        state.cancel_pending();
        let principal = crate::owner::test_support::principal(state.authorizer.session());
        let snapshot = crate::owner::test_support::vault::snapshot("github-write");
        crate::owner::test_support::approval::read_grant(
            &mut state.operations,
            &mut state.authorizer,
            &principal,
            &snapshot,
        );
        if expire {
            state
                .authorizer
                .install(
                    Ok(crate::owner::policy::fixture::FixturePolicy::default()),
                    OffsetDateTime::now_utc() + Duration::from_secs(7200),
                    Instant::now(),
                )
                .unwrap();
        } else {
            for _ in 0..99 {
                let AuthorizationOutcome::Allowed(permit) = state
                    .authorizer
                    .authorize(
                        &principal,
                        crate::owner::test_support::read_request(),
                        Instant::now(),
                    )
                    .unwrap()
                else {
                    panic!()
                };
                state
                    .authorizer
                    .admit(permit, &principal, Instant::now())
                    .unwrap();
            }
        }
        assert!(matches!(
            state.authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths
            ),
            Ok(AuthorizationOutcome::RequireApproval(_))
        ));
        assert!(
            state
                .authorizer
                .authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    Instant::now()
                )
                .is_err()
        );
        crate::owner::test_support::approval::read_grant(
            &mut state.operations,
            &mut state.authorizer,
            &principal,
            &snapshot,
        );
        assert!(matches!(
            state.authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths
            ),
            Ok(AuthorizationOutcome::Allowed(_))
        ));
    }
}

#[test]
fn an_ungranted_read_requires_grant_approval_without_authorizing_a_write() {
    let (_root, paths, _key, mut state, _receive) = fixture();
    state.cancel_pending();
    let principal = crate::owner::test_support::principal(state.authorizer.session());
    let outcome = state
        .authorize(
            &principal,
            crate::owner::test_support::read_request(),
            &paths,
        )
        .unwrap();
    let AuthorizationOutcome::RequireApproval(requirement) = outcome else {
        panic!("ungranted read was allowed");
    };
    let claims = serde_json::to_value(requirement.grant_claims().unwrap()).unwrap();
    assert_eq!(claims["purpose"], "quartermaster.issue-read-grant.v1");
    assert_eq!(claims["grant"]["codeHash"], "11".repeat(20));
    assert_eq!(claims["grant"]["role"], "github-write");
    assert_eq!(claims["grant"]["budget"], 100);
    assert!(
        state
            .authorizer
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                Instant::now()
            )
            .is_err()
    );
}

#[test]
fn enrollment_accepts_an_explicit_item_selector_without_changing_authority_fields() {
    for selected in [None, Some("22222222-2222-4222-8222-222222222222")] {
        let mut message = json!({"kind":"vaultLogin", "server":"https://vault.example.invalid", "email":"dummy@example.invalid", "password":"dummy"});
        if let Some(selected) = selected {
            message["itemId"] = json!(selected);
        }
        assert!(matches!(
            unpack(&pack(message.clone()).unwrap()).unwrap(),
            Client::VaultLogin { item_id, .. } if item_id.as_deref() == selected
        ));
        message["role"] = json!("arbitrary-role");
        assert!(unpack(&pack(message).unwrap()).is_err());
    }
}

pub(super) fn fixture() -> (
    tempfile::TempDir,
    ServicePaths,
    EcdsaKeyPair,
    OwnerState,
    mpsc::Receiver<ApprovalCompletion>,
) {
    fixture_with_cache(false)
}

pub(super) fn fixture_with_cache(
    cold: bool,
) -> (
    tempfile::TempDir,
    ServicePaths,
    EcdsaKeyPair,
    OwnerState,
    mpsc::Receiver<ApprovalCompletion>,
) {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: "/unused.app".into(),
        root: directory.path().canonicalize().unwrap(),
    };
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .unwrap();
    let mut state = OwnerState::new().unwrap();
    handle(
        Client::Enroll {
            public_key: BASE64.encode(key.public_key()),
        },
        &mut state,
        &paths,
    )
    .unwrap();
    let created = presence_now().unwrap();
    let principal = Arc::new(VerifiedPrincipal::fixture(
        501,
        "11".repeat(20),
        state.authorizer.session(),
    ));
    let request = http_request::read(&mut std::io::Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();
    let outcome = state
        .authorizer
        .authorize(&principal, request, Instant::now())
        .unwrap();
    let id = state.operations.register(outcome, Instant::now()).unwrap();
    let snapshot = super::super::test_support::vault::snapshot("github-write");
    let source = super::super::vault::fixture::put(&paths.root, &snapshot);
    let identity = source.identity().unwrap();
    if !cold {
        let unlock = state.provider.begin_unlock(identity.clone()).unwrap();
        state
            .provider
            .finish_unlock(unlock, &identity, snapshot)
            .unwrap();
    }
    let generation = state.provider.generation();
    let context = ReviewContext {
        provider: ProviderPresentation::new(&identity, generation),
        operation_id: id.to_string(),
        created,
        process_chain: vec!["dummy test process · PID 1".into()],
        peer: qm_macos::peer_identity::PeerPresentation {
            pid: 1,
            executable: "/dummy/test".into(),
            signing_identifier: "dummy.test".into(),
            team_identifier: None,
            cd_hash: principal.code_hash().into(),
            ad_hoc: true,
            ancestry_complete: true,
            command_line: None,
        },
    };
    let request = super::super::review::ReviewDocument::new(
        state.operations.request(id, &principal).unwrap().clone(),
        None,
        context,
    )
    .unwrap();
    state
        .operations
        .bind_review(id, &principal, &request)
        .unwrap();
    state
        .operations
        .begin_approval(id, &principal, &state.ui.as_ref().unwrap().session)
        .unwrap();
    let (completion, receive) = mpsc::sync_channel(1);
    state.pending = Some(ApprovalDelivery {
        id,
        principal,
        request,
        provider: FrozenProvider {
            source: Some(source),
            identity,
            generation,
        },
        context_lease: None,
        delivered: false,
        completion,
    });
    handle(Client::Next {}, &mut state, &paths).unwrap();
    (directory, paths, key, state, receive)
}

fn request_id(state: &OwnerState) -> String {
    state.pending.as_ref().unwrap().id.to_string()
}

fn admit_test(
    state: &mut OwnerState,
    ready: &ApprovalCompletion,
    paths: &ServicePaths,
) -> io::Result<Admission> {
    let prepared = state.prepare(ready.id, &ready.principal, paths)?;
    checked(
        state
            .operations
            .ready(ready.id, &ready.principal, &prepared),
    )?;
    let snapshot = state
        .provider
        .snapshot()
        .ok_or_else(|| failure("vault is locked"))?;
    checked(
        state
            .operations
            .check_snapshot(ready.id, &ready.principal, snapshot),
    )?;
    let admission = checked(state.operations.admit(
        ready.id,
        &ready.principal,
        &mut state.authorizer,
        Instant::now(),
    ))?;
    if !admission.accepts(&prepared) {
        return Err(failure("prepared request changed"));
    }
    Ok(admission)
}

fn proof(state: &mut OwnerState, paths: &ServicePaths, key: &EcdsaKeyPair) -> Client {
    thread::sleep(Duration::from_millis(2));
    let id = state.pending.as_ref().unwrap().id;
    assert!(
        begin_native_presence(id, presence_now().unwrap(), state, paths)
            .unwrap()
            .is_none()
    );
    let reply = complete_native_presence(id, state, paths).unwrap();
    let challenge = BASE64
        .decode(reply["authorization"]["bytes"].as_str().unwrap())
        .unwrap();
    let signature = key.sign(&SystemRandom::new(), &challenge).unwrap();
    Client::Proof {
        id: request_id(state),
        signature: BASE64.encode(signature),
    }
}

#[test]
fn envelope_rejects_forged_flags_unknown_operations_and_unbounded_data() {
    assert!(matches!(
        unpack(&pack(json!({"kind": "hello"})).unwrap()).unwrap(),
        Client::Hello {}
    ));
    for message in [
        json!({"kind": "hello", "approved": true}),
        json!({"kind": "allow"}),
        json!({"kind": "proof", "id": "request", "signature": "", "status": "PASS"}),
    ] {
        assert!(unpack(&pack(message).unwrap()).is_err());
    }
    let mut fields = BTreeMap::from([
        ("version".into(), XpcMessage::Uint64(1)),
        ("payload".into(), XpcMessage::Data(vec![b' '; 16385])),
    ]);
    assert!(unpack(&XpcMessage::Dictionary(fields.clone())).is_err());
    fields.insert(
        "payload".into(),
        XpcMessage::Data(b"{\"kind\":\"hello\"}".to_vec()),
    );
    fields.insert("version".into(), XpcMessage::Uint64(2));
    assert!(unpack(&XpcMessage::Dictionary(fields)).is_err());
}

#[test]
fn explicit_vault_sync_is_decoded_without_accepting_client_authority_fields() {
    assert!(matches!(
        unpack(&pack(json!({"kind":"vaultSync"})).unwrap()).unwrap(),
        Client::VaultSync {}
    ));
    assert!(unpack(&pack(json!({"kind":"vaultSync", "approved":true})).unwrap()).is_err());
}

#[test]
fn approval_key_continuity_survives_ui_disconnect_within_the_backend_session() {
    let (_directory, paths, key, mut state, _receive) = fixture();
    state.disconnect_ui();
    handle(
        Client::Enroll {
            public_key: BASE64.encode(key.public_key()),
        },
        &mut state,
        &paths,
    )
    .unwrap();
    state.disconnect_ui();
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let replacement =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
            .unwrap();

    assert!(
        handle(
            Client::Enroll {
                public_key: BASE64.encode(replacement.public_key())
            },
            &mut state,
            &paths
        )
        .is_err()
    );
    assert_eq!(
        state.approval_public_key.as_deref(),
        Some(key.public_key().as_ref())
    );
    assert!(state.ui.is_none());
}

#[test]
fn verified_receipt_dispatches_once_and_replay_cannot_authorize() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    let Client::Proof { id, signature } = &message else {
        unreachable!()
    };
    let replay = Client::Proof {
        id: id.clone(),
        signature: signature.clone(),
    };
    assert_eq!(
        handle(message, &mut state, &paths).unwrap()["kind"],
        "accepted"
    );
    let grant = receive.try_recv().unwrap();
    let admission = admit_test(&mut state, &grant, &paths).unwrap();
    assert_eq!(
        admission.request().action(),
        http_request::Action::CloseIssue
    );
    assert!(handle(replay, &mut state, &paths).is_err());
    assert!(receive.try_recv().is_err());
}

#[test]
fn missing_presence_or_invalid_signature_never_yields_a_grant() {
    for authenticated in [false, true] {
        let (_directory, paths, key, mut state, receive) = fixture();
        if authenticated {
            let _ = proof(&mut state, &paths, &key);
        }
        assert!(
            handle(
                Client::Proof {
                    id: request_id(&state),
                    signature: BASE64.encode([1; 64])
                },
                &mut state,
                &paths
            )
            .is_err()
        );
        assert!(receive.try_recv().is_err());
    }
}

#[test]
fn cancellation_and_invalid_presence_times_cannot_authorize() {
    let (_directory, paths, _key, mut state, receive) = fixture();
    assert!(
        begin_native_presence(
            state.pending.as_ref().unwrap().id,
            presence_now()
                .unwrap()
                .checked_add(Duration::from_secs(1))
                .unwrap(),
            &mut state,
            &paths
        )
        .is_err()
    );
    assert!(
        state
            .operations
            .authentication_offset(
                state.pending.as_ref().unwrap().id,
                &state.pending.as_ref().unwrap().principal
            )
            .is_err()
    );
    let canceled_id = request_id(&state);
    handle(
        Client::Cancel {
            id: request_id(&state),
        },
        &mut state,
        &paths,
    )
    .unwrap();
    assert!(state.pending.is_none());
    assert!(receive.try_recv().is_err());
    assert!(
        handle(
            Client::Proof {
                id: canceled_id,
                signature: String::new()
            },
            &mut state,
            &paths
        )
        .is_err()
    );
}

#[test]
fn ui_session_loss_revokes_a_minted_but_undispatched_grant() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    handle(message, &mut state, &paths).unwrap();
    let grant = receive.try_recv().unwrap();
    state.disconnect_ui();
    assert!(admit_test(&mut state, &grant, &paths).is_err());
}

#[test]
fn vault_status_is_noninteractive_and_contains_only_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: "/unused.app".into(),
        root: directory.path().canonicalize().unwrap(),
    };
    let mut state = OwnerState::new().unwrap();

    let reply = handle(Client::VaultStatus {}, &mut state, &paths).unwrap();

    assert_eq!(reply["kind"], "vaultStatus");
    assert_eq!(reply["state"], "unenrolled");
    assert!(reply.get("password").is_none());
    assert!(reply.get("token").is_none());
    assert!(state.provider.snapshot().is_none());
}

#[test]
fn locking_the_vault_revokes_outstanding_approval_authority() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    handle(message, &mut state, &paths).unwrap();
    let grant = receive.try_recv().unwrap();

    handle(Client::VaultLock {}, &mut state, &paths).unwrap();

    assert!(state.pending.is_none());
    assert!(state.provider.snapshot().is_none());
    assert!(state.ui.is_none());
    assert!(admit_test(&mut state, &grant, &paths).is_err());
}

#[test]
fn acknowledged_cancellation_after_proof_prevents_dispatch() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    handle(message, &mut state, &paths).unwrap();
    let grant = receive.try_recv().unwrap();
    let reply = handle(
        Client::Cancel {
            id: request_id(&state),
        },
        &mut state,
        &paths,
    )
    .unwrap();
    let mut requests = 0;

    let result = admit_test(&mut state, &grant, &paths).map(|_| {
        requests += 1;
    });

    assert_eq!(reply["kind"], "canceled");
    assert!(result.is_err());
    assert_eq!(requests, 0);
}

#[test]
fn a_completed_proof_reports_the_actual_cancellation_order() {
    for admitted in [false, true] {
        let (_directory, paths, key, mut state, receive) = fixture();
        let message = proof(&mut state, &paths, &key);
        let id = request_id(&state);
        handle(message, &mut state, &paths).unwrap();
        let ready = receive.try_recv().unwrap();
        if admitted {
            admit_test(&mut state, &ready, &paths).unwrap();
        }
        for _ in 0..2 {
            assert_eq!(
                handle(Client::Cancel { id: id.clone() }, &mut state, &paths).unwrap()["kind"],
                if admitted {
                    "alreadyAdmitted"
                } else {
                    "canceled"
                }
            );
        }
        assert_eq!(
            handle(
                Client::Cancel {
                    id: "unknown".into()
                },
                &mut state,
                &paths
            )
            .unwrap()["kind"],
            "unknownOperation"
        );
    }
}

#[test]
fn concurrent_duplicate_proofs_yield_only_one_ready_operation() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let Client::Proof { id, signature } = proof(&mut state, &paths, &key) else {
        unreachable!()
    };
    let state = Arc::new(Mutex::new(state));
    let paths = Arc::new(paths);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let state = Arc::clone(&state);
            let paths = Arc::clone(&paths);
            let barrier = Arc::clone(&barrier);
            let message = Client::Proof {
                id: id.clone(),
                signature: signature.clone(),
            };
            thread::spawn(move || {
                barrier.wait();
                handle(message, &mut state.lock().unwrap(), &paths).is_ok()
            })
        })
        .collect();

    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count(),
        1
    );
    assert!(receive.try_recv().is_ok());
    assert!(receive.try_recv().is_err());
}

#[test]
fn restarting_the_owner_cannot_replay_a_previous_ready_operation() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    handle(message, &mut state, &paths).unwrap();
    let ready = receive.try_recv().unwrap();
    let mut restarted = OwnerState::new().unwrap();

    assert_ne!(state.authorizer.session(), restarted.authorizer.session());
    assert!(admit_test(&mut restarted, &ready, &paths).is_err());
    assert!(restarted.ui.is_none());
    assert!(restarted.pending.is_none());
}

#[test]
fn configured_read_runs_without_a_frontend_or_presence() {
    let root = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: "/must-not-be-launched.app".into(),
        root: root.path().to_path_buf(),
    };
    let mut state = OwnerState::new().unwrap();
    let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60)).unix_timestamp() as u64;
    state
        .authorizer
        .seed_fixture_grants(&crate::owner::test_support::policy_bytes(expires, 2));
    let principal = super::super::identity::VerifiedPrincipal::fixture(
        501,
        "11".repeat(20),
        state.authorizer.session(),
    );

    for _ in 0..2 {
        let AuthorizationOutcome::Allowed(permit) = state
            .authorize(
                &principal,
                super::super::test_support::read_request(),
                &paths,
            )
            .unwrap()
        else {
            panic!()
        };
        state
            .authorizer
            .admit(permit, &principal, Instant::now())
            .unwrap();
    }

    assert!(
        state
            .authorize(
                &principal,
                super::super::test_support::read_request(),
                &paths
            )
            .is_err()
    );
    assert!(state.ui.is_none());
    assert!(state.pending.is_none());
}

#[test]
fn ending_the_os_session_cancels_approval_and_locks_the_cache_without_automatic_reactivation() {
    let (_directory, paths, _key, mut state, _receive) = fixture();
    let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
    let generation = state.provider.generation();
    state.end_host_session().unwrap();
    assert!(state.pending.is_none());
    assert!(state.ui.is_none());
    assert!(state.provider.snapshot().is_none());
    assert_ne!(state.provider.generation(), generation);
    assert!(handle(Client::Hello {}, &mut state, &paths).is_err());
    assert!(handle(Client::VaultStatus {}, &mut state, &paths).is_ok());
    state.refresh_policy(&paths).unwrap();
    assert!(matches!(
        state.authorizer.authorize(
            &principal,
            crate::owner::test_support::read_request(),
            Instant::now()
        ),
        Err(super::super::policy::AuthorizationError::SessionRevoked)
    ));
}

#[test]
fn ending_the_os_session_prevents_an_already_prepared_read_from_handing_off() {
    let root = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        root: root.path().to_owned(),
        app: "/unused.app".into(),
    };
    let mut state = OwnerState::new().unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), state.authorizer.session());
    let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60))
        .unix_timestamp()
        .try_into()
        .unwrap();
    state
        .authorizer
        .seed_fixture_grants(&crate::owner::test_support::policy_bytes(expires, 2));
    crate::owner::test_support::vault::install(
        &mut state.provider,
        crate::owner::test_support::vault::snapshot("github-read"),
    );
    let outcome = state
        .authorize(
            &principal,
            crate::owner::test_support::read_request(),
            &paths,
        )
        .unwrap();
    let id = state.operations.register(outcome, Instant::now()).unwrap();
    let selection = CredentialSelection::at_generation(
        state.provider.snapshot().unwrap(),
        state.provider.generation(),
    );
    state
        .operations
        .select_credential(id, &principal, selection)
        .unwrap();
    let request = state.prepare(id, &principal, &paths).unwrap();
    let prepared = PreparedOperation::new(request, state.upstream.connect().unwrap());
    state.end_host_session().unwrap();
    assert!(state.handoff(prepared, &principal, &paths).is_err());
    assert_eq!(
        super::super::transport::fixture::observe(&state.upstream).1,
        0
    );
}

#[test]
fn host_lock_and_wake_preserve_scoped_reads_cache_and_remaining_budget() {
    for event in [
        crate::platform::HostSessionEvent::Sleep,
        crate::platform::HostSessionEvent::Wake,
        crate::platform::HostSessionEvent::ScreenLock,
        crate::platform::HostSessionEvent::Inactive,
    ] {
        let (_directory, paths, _key, mut state, _receive) = fixture();
        let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
        let write = state.pending.as_ref().unwrap().id;
        let generation = state.provider.generation();
        let expires = (OffsetDateTime::now_utc() + Duration::from_secs(60))
            .unix_timestamp()
            .try_into()
            .unwrap();
        let mut policy: Value =
            serde_json::from_slice(&crate::owner::test_support::policy_bytes(expires, 2)).unwrap();
        policy["grants"][0]["role"] = "github-write".into();
        state
            .authorizer
            .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
        let outcome = state
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths,
            )
            .unwrap();
        let read = state.operations.register(outcome, Instant::now()).unwrap();
        let selection =
            CredentialSelection::at_generation(state.provider.snapshot().unwrap(), generation);
        state
            .operations
            .select_credential(read, &principal, selection)
            .unwrap();
        let prepared = PreparedOperation::new(
            state.prepare(read, &principal, &paths).unwrap(),
            state.upstream.connect().unwrap(),
        );
        state.host_session_event(event).unwrap();
        assert!(state.authorizer.session_active());
        assert!(state.pending.is_none());
        assert!(state.ui.is_none());
        assert!(
            state
                .operations
                .check_wait(write, &principal, Instant::now())
                .is_err()
        );
        assert_eq!(state.provider.generation(), generation);
        assert!(state.provider.snapshot().is_some());
        state.handoff(prepared, &principal, &paths).unwrap();
        let outcome = state
            .authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths,
            )
            .unwrap();
        let super::super::policy::AuthorizationOutcome::Allowed(permit) = outcome else {
            panic!()
        };
        state
            .authorizer
            .admit(permit, &principal, Instant::now())
            .unwrap();
        assert!(matches!(
            state.authorize(
                &principal,
                crate::owner::test_support::read_request(),
                &paths
            ),
            Ok(AuthorizationOutcome::RequireApproval(_))
        ));
        assert!(
            state
                .authorizer
                .authorize(
                    &principal,
                    crate::owner::test_support::read_request(),
                    Instant::now()
                )
                .is_err()
        );
    }
}

#[test]
fn host_lock_cancels_a_pending_write_before_any_policy_reload() {
    let (_directory, _paths, _key, mut state, _receive) = fixture();
    let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
    let id = state.pending.as_ref().unwrap().id;
    state
        .host_session_event(crate::platform::HostSessionEvent::ScreenLock)
        .unwrap();
    assert!(state.pending.is_none());
    assert!(state.ui.is_none());
    assert!(
        state
            .operations
            .check_wait(id, &principal, Instant::now())
            .is_err()
    );
    assert!(state.provider.snapshot().is_some());
}

#[test]
fn stricter_host_policy_and_logout_revoke_read_authority_and_lock_the_cache() {
    for logout in [false, true] {
        let (_directory, _paths, _key, mut state, _receive) = fixture();
        if !logout {
            state.session_policy.reads_survive_lock = false;
        }
        state
            .host_session_event(if logout {
                crate::platform::HostSessionEvent::Logout
            } else {
                crate::platform::HostSessionEvent::ScreenLock
            })
            .unwrap();
        assert!(!state.authorizer.session_active());
        assert!(state.provider.snapshot().is_none());
    }
}

#[test]
fn verified_socket_read_returns_a_response_without_launching_the_frontend() {
    let root = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: root.path().join("nonexistent.app"),
        root: root.path().to_path_buf(),
    };
    let (mut server, mut client) = UnixStream::pair().unwrap();
    let peer = qm_macos::peer_identity::PeerIdentity::capture(&server).unwrap();
    let mut policy: Value = serde_json::from_slice(&super::super::test_support::policy_bytes(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        2,
    ))
    .unwrap();
    policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
    policy["grants"][0]["codeHash"] = json!(peer.code_hash());
    let mut state = OwnerState::new().unwrap();
    state
        .authorizer
        .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
    crate::owner::test_support::vault::install(
        &mut state.provider,
        super::super::test_support::vault::snapshot("github-read"),
    );
    let upstream = state.upstream.clone();
    let shared = Arc::new((Mutex::new(state), Condvar::new()));
    client.write_all(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n").unwrap();

    handle_http(&mut server, &shared, &paths).unwrap();
    drop(server);
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"state\":\"open\""));
    assert!(response.contains("\"quartermaster_local_simulation\":true"));
    assert!(shared.0.lock().unwrap().ui.is_none());
    assert_eq!(super::super::transport::fixture::observe(&upstream).0, 1);
}

#[test]
fn a_waiting_connection_does_not_block_an_independent_authorized_read() {
    let root = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: root.path().join("nonexistent.app"),
        root: root.path().to_path_buf(),
    };
    let (slow_server, slow_client) = UnixStream::pair().unwrap();
    let (read_server, mut read_client) = UnixStream::pair().unwrap();
    let peer = PeerIdentity::capture(&read_server).unwrap();
    let mut policy: Value = serde_json::from_slice(&super::super::test_support::policy_bytes(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        2,
    ))
    .unwrap();
    policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
    policy["grants"][0]["codeHash"] = json!(peer.code_hash());
    let mut state = OwnerState::new().unwrap();
    state
        .authorizer
        .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
    crate::owner::test_support::vault::install(
        &mut state.provider,
        super::super::test_support::vault::snapshot("github-read"),
    );
    let shared = Arc::new((Mutex::new(state), Condvar::new()));
    let worker = thread::spawn(move || {
        serve_connections(
            [Ok(slow_server), Ok(read_server)].into_iter(),
            shared,
            paths,
        )
    });
    read_client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    read_client.write_all(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n").unwrap();
    let mut response = String::new();

    let read = read_client.read_to_string(&mut response);
    drop(slow_client);
    worker.join().unwrap().unwrap();

    read.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
}

#[test]
fn a_prepared_read_cannot_survive_lock_and_unlock_of_the_identical_cache() {
    let directory = tempfile::tempdir().unwrap();
    let paths = ServicePaths {
        app: "/unused.app".into(),
        root: directory.path().canonicalize().unwrap(),
    };
    let mut state = OwnerState::new().unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), state.authorizer.session());
    let policy = super::super::test_support::policy_bytes(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        2,
    );
    state.authorizer.seed_fixture_grants(&policy);
    crate::owner::test_support::vault::install(
        &mut state.provider,
        super::super::test_support::vault::snapshot("github-read"),
    );
    let outcome = state
        .authorize(
            &principal,
            super::super::test_support::read_request(),
            &paths,
        )
        .unwrap();
    let id = state.operations.register(outcome, Instant::now()).unwrap();
    state
        .operations
        .select_credential(
            id,
            &principal,
            crate::owner::test_support::vault::selection(state.provider.snapshot().unwrap()),
        )
        .unwrap();
    let request = state.prepare(id, &principal, &paths).unwrap();
    let upstream = state.upstream.clone();
    let prepared = PreparedOperation::new(request, upstream.connect().unwrap());

    handle(Client::VaultLock {}, &mut state, &paths).unwrap();
    crate::owner::test_support::vault::install(
        &mut state.provider,
        super::super::test_support::vault::snapshot("github-read"),
    );
    let result = state.handoff(prepared, &principal, &paths);
    let admitted = result.is_ok();
    if let Ok(receipt) = result {
        let _ = receipt.response();
    }

    assert!(!admitted);
    assert_eq!(super::super::transport::fixture::observe(&upstream), (0, 0));
}

#[test]
fn a_standalone_unlock_can_finish_after_ui_exit_and_serve_an_independent_read() {
    let (_directory, paths, _key, mut state, _receive) = fixture();
    let id = state.pending.as_ref().unwrap().id;
    let principal = Arc::clone(&state.pending.as_ref().unwrap().principal);
    state.provider.lock().unwrap();
    let snapshot = crate::owner::test_support::vault::snapshot("github-write");
    let source = super::super::vault::fixture::put(&paths.root, &snapshot);
    let unlock = state
        .provider
        .begin_unlock(source.identity().unwrap())
        .unwrap();

    state.disconnect_ui();
    super::super::vault::finish_unlock(&paths.root, &mut state.provider, unlock, snapshot).unwrap();

    assert!(state.ui.is_none());
    assert_eq!(
        state.operations.cancel(id, &principal),
        CancellationResult::Canceled
    );
    let mut policy: Value = serde_json::from_slice(&crate::owner::test_support::policy_bytes(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60,
        2,
    ))
    .unwrap();
    policy["grants"][0]["role"] = "github-write".into();
    state
        .authorizer
        .seed_fixture_grants(&serde_json::to_vec(&policy).unwrap());
    let outcome = state
        .authorize(
            &principal,
            crate::owner::test_support::read_request(),
            &paths,
        )
        .unwrap();
    let read = state.operations.register(outcome, Instant::now()).unwrap();
    state
        .operations
        .select_credential(
            read,
            &principal,
            CredentialSelection::at_generation(
                state.provider.snapshot().unwrap(),
                state.provider.generation(),
            ),
        )
        .unwrap();
    let request = state.prepare(read, &principal, &paths).unwrap();
    let prepared = PreparedOperation::new(request, state.upstream.connect().unwrap());
    let response = state
        .handoff(prepared, &principal, &paths)
        .unwrap()
        .response();
    assert_eq!(response, OperationResponse::IssueOpen);
    assert_eq!(
        super::super::transport::fixture::observe(&state.upstream).0,
        1
    );
}

#[test]
fn final_write_handoff_checks_the_shared_clock_even_if_instant_has_not_expired() {
    let (_directory, paths, key, mut state, receive) = fixture();
    let message = proof(&mut state, &paths, &key);
    handle(message, &mut state, &paths).unwrap();
    let ready = receive.try_recv().unwrap();
    let frame = state.prepare(ready.id, &ready.principal, &paths).unwrap();
    let upstream = state.upstream.clone();
    let prepared = PreparedOperation::new(frame, upstream.connect().unwrap());
    let future = presence_now()
        .unwrap()
        .checked_add(Duration::from_secs(30))
        .unwrap();
    let result = state.handoff_with_clock(prepared, &ready.principal, &paths, || Ok(future));
    let admitted = result.is_ok();
    if let Ok(receipt) = result {
        let _ = receipt.response();
    }

    assert!(!admitted);
    assert_eq!(super::super::transport::fixture::observe(&upstream), (0, 0));
}

#[test]
fn a_staged_approval_cannot_accept_presence_without_a_native_context() {
    let (_directory, paths, _key, mut state, _receive) = fixture();
    let id = request_id(&state);
    assert!(
        handle(
            Client::Presence {
                id,
                authenticated: presence_now().unwrap()
            },
            &mut state,
            &paths
        )
        .is_err()
    );
    assert!(
        state
            .operations
            .authentication_offset(
                state.pending.as_ref().unwrap().id,
                &state.pending.as_ref().unwrap().principal
            )
            .is_err()
    );
    assert_eq!(
        super::super::transport::fixture::observe(&state.upstream),
        (0, 0)
    );
}
