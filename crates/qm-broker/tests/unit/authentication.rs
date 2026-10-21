use super::*;
use ring::signature::EcdsaKeyPair;

struct Fixture {
    _directory: tempfile::TempDir,
    paths: ServicePaths,
    key: EcdsaKeyPair,
    state: OwnerState,
    receive: mpsc::Receiver<ApprovalCompletion>,
    review: Value,
    id: OperationId,
}

fn staged(cold: bool) -> Fixture {
    let (directory, paths, key, mut state, receive) = tests::fixture_with_cache(cold);
    let id = state.pending.as_ref().unwrap().id;
    state.pending.as_mut().unwrap().delivered = false;
    let review = handle(Client::Next {}, &mut state, &paths).unwrap()["approval"].clone();
    Fixture {
        _directory: directory,
        paths,
        key,
        state,
        receive,
        review,
        id,
    }
}

fn authenticate(fixture: &mut Fixture) -> (MonotonicTimestamp, Value) {
    thread::sleep(Duration::from_millis(3));
    let authenticated = presence_now().unwrap();
    let work = begin_native_presence(
        fixture.id,
        authenticated,
        &mut fixture.state,
        &fixture.paths,
    )
    .unwrap();
    if let Some((source, operation)) = work {
        assert!(fixture.state.provider.snapshot().is_none());
        let snapshot = super::super::vault::fixture::open(source);
        super::super::vault::finish_unlock(
            &fixture.paths.root,
            &mut fixture.state.provider,
            operation,
            snapshot,
        )
        .unwrap();
    }
    let reply = complete_native_presence(fixture.id, &mut fixture.state, &fixture.paths).unwrap();
    (authenticated, reply["authorization"].clone())
}

#[test]
fn cold_cache_open_binds_actual_digest_and_exact_original_event_before_a_single_use_write() {
    let mut fixture = staged(true);
    let (authenticated, challenge) = authenticate(&mut fixture);
    assert_eq!(challenge["review"], fixture.review);
    assert_eq!(challenge["authenticated"], json!(authenticated));
    assert_eq!(
        challenge["expires"],
        json!(authenticated.checked_add(Duration::from_secs(30)).unwrap())
    );
    assert_eq!(
        challenge["credentialDigest"],
        BASE64.encode(
            fixture
                .state
                .provider
                .snapshot()
                .unwrap()
                .credential_digest()
        )
    );
    let bytes = BASE64.decode(challenge["bytes"].as_str().unwrap()).unwrap();
    let created = fixture.state.pending.as_ref().unwrap().created();
    assert_eq!(
        &bytes[bytes.len() - 16..],
        &authenticated
            .checked_duration_since(created)
            .unwrap()
            .as_nanos()
            .to_be_bytes()
    );
    let principal = Arc::clone(&fixture.state.pending.as_ref().unwrap().principal);
    assert!(
        fixture
            .state
            .prepare(fixture.id, &principal, &fixture.paths)
            .is_err()
    );
    assert_eq!(
        super::super::transport::fixture::observe(&fixture.state.upstream),
        (0, 0)
    );
    let signature = fixture.key.sign(&SystemRandom::new(), &bytes).unwrap();
    handle(
        Client::Proof {
            id: fixture.id.to_string(),
            signature: BASE64.encode(signature.as_ref()),
        },
        &mut fixture.state,
        &fixture.paths,
    )
    .unwrap();
    let ready = fixture.receive.try_recv().unwrap();
    let frame = fixture
        .state
        .prepare(ready.id, &ready.principal, &fixture.paths)
        .unwrap();
    let prepared = PreparedOperation::new(frame, fixture.state.upstream.connect().unwrap());
    let response = fixture
        .state
        .handoff(prepared, &ready.principal, &fixture.paths)
        .unwrap()
        .response();
    assert_eq!(response, OperationResponse::IssueClosed);
    assert!(
        fixture
            .state
            .prepare(fixture.id, &principal, &fixture.paths)
            .is_err()
    );
    assert_eq!(
        super::super::transport::fixture::observe(&fixture.state.upstream).0,
        1
    );
}

#[test]
fn warm_cache_still_requires_a_new_request_bound_proof() {
    let mut fixture = staged(false);
    let (_, challenge) = authenticate(&mut fixture);
    assert_eq!(challenge["review"], fixture.review);
    let principal = Arc::clone(&fixture.state.pending.as_ref().unwrap().principal);

    assert!(
        fixture
            .state
            .prepare(fixture.id, &principal, &fixture.paths)
            .is_err()
    );
    assert_eq!(
        super::super::transport::fixture::observe(&fixture.state.upstream),
        (0, 0)
    );
}

#[test]
fn warm_cache_cannot_supply_a_newly_frozen_enrollment_or_cache_revision() {
    let mut fixture = staged(false);
    let snapshot = super::super::test_support::vault::snapshot("github-write");
    let replacement = super::super::vault::fixture::put(&fixture.paths.root, &snapshot);
    let pending = fixture.state.pending.as_mut().unwrap();
    let frozen = &mut pending.provider;
    frozen.identity = replacement.identity().unwrap();
    frozen.source = Some(replacement);
    thread::sleep(Duration::from_millis(3));

    assert!(
        begin_native_presence(
            fixture.id,
            presence_now().unwrap(),
            &mut fixture.state,
            &fixture.paths
        )
        .is_err()
    );
    assert_eq!(
        super::super::transport::fixture::observe(&fixture.state.upstream),
        (0, 0)
    );
}

#[test]
fn explicit_lock_or_cache_replacement_rejects_late_authenticated_unwrap() {
    for replace in [false, true] {
        let mut fixture = staged(true);
        thread::sleep(Duration::from_millis(3));
        let (source, operation) = begin_native_presence(
            fixture.id,
            presence_now().unwrap(),
            &mut fixture.state,
            &fixture.paths,
        )
        .unwrap()
        .unwrap();
        let snapshot = super::super::vault::fixture::open(source);
        if replace {
            let replacement = super::super::test_support::vault::snapshot_with(
                "github-write",
                "33333333-3333-4333-8333-333333333333",
                [4; 16],
            );
            super::super::vault::fixture::put(&fixture.paths.root, &replacement);
        } else {
            fixture.state.provider.lock().unwrap();
        }

        assert!(
            super::super::vault::finish_unlock(
                &fixture.paths.root,
                &mut fixture.state.provider,
                operation,
                snapshot
            )
            .is_err()
        );
        assert!(complete_native_presence(fixture.id, &mut fixture.state, &fixture.paths).is_err());
        assert!(fixture.state.provider.snapshot().is_none());
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream),
            (0, 0)
        );
    }
}

#[test]
fn canceled_write_or_ui_exit_does_not_resurrect_proof_when_an_authorized_unlock_finishes() {
    for disconnect in [false, true] {
        let mut fixture = staged(true);
        thread::sleep(Duration::from_millis(3));
        let (source, operation) = begin_native_presence(
            fixture.id,
            presence_now().unwrap(),
            &mut fixture.state,
            &fixture.paths,
        )
        .unwrap()
        .unwrap();
        if disconnect {
            fixture.state.disconnect_ui();
        } else {
            let reply = handle(
                Client::Cancel {
                    id: fixture.id.to_string(),
                },
                &mut fixture.state,
                &fixture.paths,
            )
            .unwrap();
            assert_eq!(reply["kind"], "canceled");
        }
        let snapshot = super::super::vault::fixture::open(source);
        super::super::vault::finish_unlock(
            &fixture.paths.root,
            &mut fixture.state.provider,
            operation,
            snapshot,
        )
        .unwrap();

        assert!(fixture.state.provider.snapshot().is_some());
        assert!(complete_native_presence(fixture.id, &mut fixture.state, &fixture.paths).is_err());
        assert!(fixture.receive.try_recv().is_err());
        assert_eq!(
            super::super::transport::fixture::observe(&fixture.state.upstream),
            (0, 0)
        );
    }
}
