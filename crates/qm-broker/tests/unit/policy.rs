use super::*;
use crate::owner::policy::fixture::FixturePolicy;
use crate::owner::{
    identity::VerifiedPrincipal,
    request,
    test_support::{policy_bytes, read_request},
};
use std::{io::Cursor, time::Instant};

fn with_github(policy: FixturePolicy, id: u64) -> FixturePolicy {
    let config = super::super::github::configuration::GitHubConfig::decode(
        &serde_json::to_vec(&serde_json::json!({"version":1,"mode":"simulation",
            "repositories":[{"id":id,"owner":"quartermaster","name":"demo"}]}))
        .unwrap(),
    )
    .unwrap();
    policy.with_github(config)
}

#[test]
fn github_configuration_change_and_revert_revokes_old_authority() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let policy = || FixturePolicy::decode(&policy_bytes(1010, 2)).unwrap();
    owner
        .install(
            Ok(with_github(policy(), 123)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let AuthorizationOutcome::Allowed(old) =
        owner.authorize(&principal, read_request(), now).unwrap()
    else {
        panic!()
    };
    assert!(
        !owner
            .install(
                Ok(with_github(policy(), 123)),
                crate::owner::test_support::wall(1000),
                now
            )
            .unwrap()
    );
    assert!(
        owner
            .install(
                Ok(with_github(policy(), 456)),
                crate::owner::test_support::wall(1000),
                now
            )
            .unwrap()
    );
    assert!(
        owner
            .install(
                Ok(with_github(policy(), 123)),
                crate::owner::test_support::wall(1000),
                now
            )
            .unwrap()
    );

    assert!(owner.admit(old, &principal, now).is_err());
}

#[test]
fn unchanged_github_configuration_preserves_the_existing_read_budget() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let policy = || with_github(FixturePolicy::decode(&policy_bytes(1010, 1)).unwrap(), 123);
    owner
        .install(Ok(policy()), crate::owner::test_support::wall(1000), now)
        .unwrap();
    let AuthorizationOutcome::Allowed(permit) =
        owner.authorize(&principal, read_request(), now).unwrap()
    else {
        panic!()
    };
    owner.admit(permit, &principal, now).unwrap();

    assert!(
        !owner
            .install(Ok(policy()), crate::owner::test_support::wall(1001), now)
            .unwrap()
    );
    assert!(matches!(
        owner.authorize(&principal, read_request(), now),
        Err(AuthorizationError::BudgetExhausted)
    ));
}

#[test]
fn github_mode_never_falls_back_to_the_simulation_operation() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let config = super::super::github::configuration::GitHubConfig::decode(
        br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"quartermaster","name":"demo","writes":true}]}"#
    ).unwrap();
    let policy = FixturePolicy::decode(&policy_bytes(1010, 2))
        .unwrap()
        .with_github(config);
    owner
        .install(Ok(policy), crate::owner::test_support::wall(1000), now)
        .unwrap();

    assert!(matches!(
        owner.authorize(&principal, read_request(), now),
        Err(AuthorizationError::Denied)
    ));
    assert!(matches!(
        owner.authorize(&principal, crate::owner::test_support::close_request(), now),
        Err(AuthorizationError::Denied)
    ));
}

#[test]
fn policy_allow_authorizes_repeated_reads_without_presence_or_ui() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    owner
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 2)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);

    for _ in 0..2 {
        let AuthorizationOutcome::Allowed(permit) =
            owner.authorize(&principal, read_request(), now).unwrap()
        else {
            panic!("read requested approval")
        };
        assert_eq!(
            owner.admit(permit, &principal, now).unwrap().action(),
            request::Action::ReadIssue
        );
    }
    assert!(matches!(
        owner.authorize(&principal, read_request(), now),
        Err(AuthorizationError::BudgetExhausted)
    ));
}

#[test]
fn an_allow_policy_cannot_waive_mandatory_mutation_approval() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    owner
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 2)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();

    assert!(matches!(
        owner.authorize(&principal, request, now).unwrap(),
        AuthorizationOutcome::RequireApproval(_)
    ));
}

#[test]
fn deny_and_invalid_policy_never_issue_operation_authority() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    assert!(owner.authorize(&principal, read_request(), now).is_err());
    owner
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 2)),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let AuthorizationOutcome::Allowed(permit) =
        owner.authorize(&principal, read_request(), now).unwrap()
    else {
        panic!()
    };

    assert!(
        owner
            .install(
                FixturePolicy::decode(b"{\"approved\":true}"),
                crate::owner::test_support::wall(1000),
                now
            )
            .is_err()
    );
    assert!(owner.admit(permit, &principal, now).is_err());
    assert!(owner.authorize(&principal, read_request(), now).is_err());
}

#[test]
fn an_explicit_deny_rejects_the_supported_mutation() {
    let now = Instant::now();
    let mut owner = Authorizer::new([1; 16]);
    owner
        .install(
            FixturePolicy::decode(br#"{"version":1,"writes":"deny","grants":[]}"#),
            crate::owner::test_support::wall(1000),
            now,
        )
        .unwrap();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    let request = request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap();

    assert!(matches!(
        owner.authorize(&principal, request, now),
        Err(AuthorizationError::Denied)
    ));
}
