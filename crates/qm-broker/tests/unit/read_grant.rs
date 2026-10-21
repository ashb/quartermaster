use super::*;
use crate::owner::{operation::OperationRegistry, test_support};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};

#[test]
fn a_review_cannot_bind_a_different_operation_or_drop_its_grant_scope() {
    let owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let mut read = owner
        .request_read_grant(&principal, test_support::read_request(), "github-read")
        .unwrap();
    let document = test_support::approval::review(read.request().clone(), None);
    assert!(read.bind_review(&document).is_err());
    let AuthorizationOutcome::RequireApproval(mut write) = owner
        .authorize(&principal, test_support::close_request(), Instant::now())
        .unwrap()
    else {
        panic!()
    };
    let document = test_support::approval::review(test_support::read_request(), None);
    assert!(write.bind_review(&document).is_err());
}

#[test]
fn simulation_grant_serialization_matches_the_native_review_fixture() {
    let owner = Authorizer::new([1; 16]);
    let requirement = owner
        .request_read_grant(
            &test_support::principal([1; 16]),
            test_support::read_request(),
            "github-write",
        )
        .unwrap();
    let mut review = serde_json::to_value(requirement.request()).unwrap();
    review["authorization"] = serde_json::to_value(requirement.grant_claims().unwrap()).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/simulation-read-grant.json")).unwrap();
    review["peer"] = fixture["peer"].clone();
    for field in ["id", "expiresUnix"] {
        review["authorization"]["grant"][field] = fixture["authorization"]["grant"][field].clone();
    }
    assert_eq!(review, fixture);
}

#[test]
fn accepting_read_grant_proof_does_not_issue_reusable_authority_before_admission() {
    let owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    let mut operations = OperationRegistry::default();
    let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
        &mut operations,
        &owner,
        &principal,
        &snapshot,
        Instant::now(),
    );
    let other = VerifiedPrincipal::fixture_with_connection(501, "11".repeat(20), [1; 16], [4; 16]);

    assert!(
        owner
            .authorize(&other, test_support::read_request(), Instant::now())
            .is_err()
    );
    assert!(
        crate::owner::execution::prepare_simulation(
            &operations,
            id,
            &other,
            &owner,
            &snapshot,
            Instant::now()
        )
        .is_err()
    );
    assert!(
        crate::owner::execution::prepare_simulation(
            &operations,
            id,
            &principal,
            &owner,
            &snapshot,
            Instant::now()
        )
        .is_ok()
    );
}

#[test]
fn cancel_or_ui_loss_before_read_admission_prevents_grant_issuance() {
    for disconnect in [false, true] {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
            &mut operations,
            &owner,
            &principal,
            &snapshot,
            Instant::now(),
        );
        let prepared = crate::owner::execution::prepare_simulation(
            &operations,
            id,
            &principal,
            &owner,
            &snapshot,
            Instant::now(),
        )
        .unwrap();
        operations.ready(id, &principal, &prepared).unwrap();
        if disconnect {
            operations.cancel_interactive_session([2; 16]);
            owner.revoke_approvals();
        } else {
            assert_eq!(
                operations.cancel(id, &principal),
                crate::owner::operation::CancellationResult::Canceled
            );
        }

        assert!(
            crate::owner::execution::prepare_simulation(
                &operations,
                id,
                &principal,
                &owner,
                &snapshot,
                Instant::now()
            )
            .is_err()
        );
        assert!(
            operations
                .admit(id, &principal, &mut owner, Instant::now())
                .is_err()
        );
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
    }
}

#[test]
fn committed_read_grants_survive_ui_loss_and_cancel_reports_already_admitted() {
    let mut owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    let mut operations = OperationRegistry::default();
    let (id, _, _, _) =
        test_support::approval::read_grant(&mut operations, &mut owner, &principal, &snapshot);
    operations.cancel_interactive_session([2; 16]);
    owner.revoke_approvals();

    assert_eq!(
        operations.cancel(id, &principal),
        crate::owner::operation::CancellationResult::AlreadyAdmitted
    );
    let other = VerifiedPrincipal::fixture_with_connection(501, "11".repeat(20), [1; 16], [4; 16]);
    assert!(matches!(
        owner.authorize(&other, test_support::read_request(), Instant::now()),
        Ok(AuthorizationOutcome::Allowed(_))
    ));
}

#[test]
fn read_grant_issuance_rechecks_the_original_authentication_deadline_at_admission() {
    let mut owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    let mut operations = OperationRegistry::default();
    let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
        &mut operations,
        &owner,
        &principal,
        &snapshot,
        Instant::now(),
    );
    let prepared = crate::owner::execution::prepare_simulation(
        &operations,
        id,
        &principal,
        &owner,
        &snapshot,
        Instant::now(),
    )
    .unwrap();
    operations.ready(id, &principal, &prepared).unwrap();
    assert!(
        operations
            .admit(
                id,
                &principal,
                &mut owner,
                Instant::now() + Duration::from_secs(31)
            )
            .is_err()
    );
    assert!(
        owner
            .authorize(&principal, test_support::read_request(), Instant::now())
            .is_err()
    );
}

#[test]
fn waiting_for_grant_approval_does_not_spend_the_first_reads_dispatch_window() {
    let owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    let mut operations = OperationRegistry::default();
    let (id, _session, _key, _digest) = test_support::approval::read_grant_at(
        &mut operations,
        &owner,
        &principal,
        &snapshot,
        Instant::now() - Duration::from_secs(90),
    );

    assert!(
        operations
            .read_deadline(id, &principal, &owner, Instant::now())
            .is_ok()
    );
}

#[test]
fn an_approval_from_a_previous_backend_cannot_mint_a_read_grant() {
    let old = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    let mut requirement = old
        .request_read_grant(&principal, test_support::read_request(), "github-read")
        .unwrap();
    let document =
        test_support::approval::review(requirement.request().clone(), requirement.grant_claims());
    requirement.bind_review(&document).unwrap();
    let request_digest = ring::digest::digest(&ring::digest::SHA256, document.bytes())
        .as_ref()
        .try_into()
        .unwrap();
    let random = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
        .unwrap();
    let binding = RequestBinding {
        session_id: [2; 16],
        policy_digest: old.policy_digest().unwrap(),
        request_digest,
        credential_digest: snapshot.credential_digest(),
    };
    let session = qm_providers::ApprovalSession::new(
        binding.session_id,
        binding.policy_digest,
        key.public_key().as_ref(),
    )
    .unwrap();
    let mut pending = session
        .begin(request_digest, binding.credential_digest)
        .unwrap();
    let authenticated = Instant::now();
    let bytes = pending
        .record_observed_authentication(authenticated)
        .unwrap();
    let proof = pending
        .approve(key.sign(&random, &bytes).unwrap().as_ref())
        .unwrap();
    let restarted = Authorizer::new([9; 16]);

    assert!(
        restarted
            .approve(
                requirement,
                proof,
                binding,
                authenticated,
                test_support::vault::selection(&snapshot),
                Instant::now()
            )
            .is_err()
    );
    assert!(
        restarted
            .authorize(
                &test_support::principal([9; 16]),
                test_support::read_request(),
                Instant::now()
            )
            .is_err()
    );
}

#[test]
fn a_read_grant_cannot_switch_to_a_different_vault_item_with_the_same_ciphertext() {
    let mut owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    let snapshot = test_support::vault::snapshot("github-read");
    test_support::approval::read_grant(
        &mut OperationRegistry::default(),
        &mut owner,
        &principal,
        &snapshot,
    );
    let AuthorizationOutcome::Allowed(permit) = owner
        .authorize(&principal, test_support::read_request(), Instant::now())
        .unwrap()
    else {
        panic!()
    };
    let substituted = test_support::vault::snapshot_with(
        "github-read",
        "33333333-3333-4333-8333-333333333333",
        [3; 16],
    );
    assert_eq!(
        snapshot.credential_digest(),
        substituted.credential_digest()
    );
    assert!(
        owner
            .check_acquisition(
                &permit,
                &principal,
                &test_support::vault::selection(&substituted),
                Instant::now()
            )
            .is_err()
    );
}

#[test]
fn a_read_grant_requires_verified_approval_and_is_reusable_only_in_its_backend_session() {
    let mut owner = Authorizer::new([1; 16]);
    let principal = test_support::principal([1; 16]);
    assert!(
        owner
            .authorize(&principal, test_support::read_request(), Instant::now())
            .is_err()
    );
    let snapshot = test_support::vault::snapshot("github-read");
    let mut operations = OperationRegistry::default();
    test_support::approval::read_grant(&mut operations, &mut owner, &principal, &snapshot);

    for _ in 0..2 {
        let AuthorizationOutcome::Allowed(permit) = owner
            .authorize(&principal, test_support::read_request(), Instant::now())
            .unwrap()
        else {
            panic!("read requested approval")
        };
        owner.admit(permit, &principal, Instant::now()).unwrap();
    }
    let restarted = Authorizer::new([2; 16]);
    assert!(
        restarted
            .authorize(
                &test_support::principal([2; 16]),
                test_support::read_request(),
                Instant::now()
            )
            .is_err()
    );
    assert!(matches!(
        owner
            .authorize(&principal, test_support::close_request(), Instant::now())
            .unwrap(),
        AuthorizationOutcome::RequireApproval(_)
    ));
}

#[test]
fn read_grant_approval_cannot_be_replayed_after_revocation_or_budget_exhaustion() {
    for revoke in [false, true] {
        let mut owner = Authorizer::new([1; 16]);
        let principal = test_support::principal([1; 16]);
        let snapshot = test_support::vault::snapshot("github-read");
        let mut operations = OperationRegistry::default();
        let (id, session, key, request_digest) =
            test_support::approval::read_grant(&mut operations, &mut owner, &principal, &snapshot);
        if revoke {
            owner.revoke_read_grants().unwrap();
        } else {
            for _ in 0..99 {
                let AuthorizationOutcome::Allowed(permit) = owner
                    .authorize(&principal, test_support::read_request(), Instant::now())
                    .unwrap()
                else {
                    panic!()
                };
                owner.admit(permit, &principal, Instant::now()).unwrap();
            }
        }
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
        let mut pending = session
            .begin(request_digest, snapshot.credential_digest())
            .unwrap();
        let bytes = pending
            .record_observed_authentication(Instant::now())
            .unwrap();
        let signature = key.sign(&SystemRandom::new(), &bytes).unwrap();
        assert!(
            operations
                .proof(id, &principal, &owner, signature.as_ref(), Instant::now())
                .is_err()
        );
        assert!(
            owner
                .authorize(&principal, test_support::read_request(), Instant::now())
                .is_err()
        );
    }
}
