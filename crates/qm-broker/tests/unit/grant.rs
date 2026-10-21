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
            FixturePolicy::decode(&policy_bytes(1010, 2)),
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
    for exhaust in [false, true] {
        let mut grants = super::GrantTable::default();
        for _ in 0..65 {
            let proposal =
                super::ReadGrantProposal::new(&principal, &read_request(), "github-read").unwrap();
            grants
                .issue(
                    proposal,
                    crate::owner::test_support::vault::selection(&snapshot),
                    Instant::now(),
                )
                .unwrap();
            let latest = grants.grants.last_mut().unwrap();
            if exhaust {
                latest.remaining = Some(0);
            } else {
                latest.continuous_expiry =
                    crate::owner::deadline::Deadline::after(Duration::ZERO).unwrap();
            }
        }
        assert_eq!(grants.grants.len(), 1);
    }
}

#[test]
fn issuance_debits_the_initiating_read_and_rejects_overflow_without_removing_live_grants() {
    let principal = crate::owner::test_support::principal([1; 16]);
    let snapshot = crate::owner::test_support::vault::snapshot("github-read");
    let mut grants = super::GrantTable::default();
    for _ in 0..64 {
        grants
            .issue(
                super::ReadGrantProposal::new(&principal, &read_request(), "github-read").unwrap(),
                crate::owner::test_support::vault::selection(&snapshot),
                Instant::now(),
            )
            .unwrap();
    }
    assert!(
        grants
            .issue(
                super::ReadGrantProposal::new(&principal, &read_request(), "github-read").unwrap(),
                crate::owner::test_support::vault::selection(&snapshot),
                Instant::now(),
            )
            .is_err()
    );
    assert_eq!(grants.grants.len(), 64);
    assert!(
        grants
            .grants
            .iter()
            .all(|grant| grant.remaining == Some(99))
    );
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
fn activity_and_unchanged_policy_reload_do_not_extend_grant_expiry_or_budget() {
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
            FixturePolicy::decode(&policy_bytes(1010, 2)),
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
    assert!(matches!(
        owner.authorize(&principal, read_request(), now + Duration::from_secs(9)),
        Err(AuthorizationError::BudgetExhausted)
    ));

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
            FixturePolicy::decode(&policy_bytes(1010, 2)),
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
                FixturePolicy::decode(&policy_bytes(1010, 2)),
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
    let document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010, 2)).unwrap();
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
    let document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010, 2)).unwrap();
    let rule = serde_json::from_value(document["grants"][0].clone()).unwrap();
    let mut grants =
        super::GrantTable::new(&[rule], crate::owner::test_support::wall(1000), now, anchor)
            .unwrap();
    let expected = crate::owner::deadline::Deadline::at(anchor, Duration::from_secs(10)).unwrap();
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
fn unchanged_reload_shortens_to_remaining_absolute_expiry_and_a_clock_rollback_cannot_extend_it() {
    let (mut owner, now) = setup();
    let principal = VerifiedPrincipal::fixture(501, "11".repeat(20), [1; 16]);
    owner
        .install(
            FixturePolicy::decode(&policy_bytes(1010, 2)),
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
            FixturePolicy::decode(&policy_bytes(1010, 2)),
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
    let mut document: serde_json::Value = serde_json::from_slice(&policy_bytes(1010, 2)).unwrap();
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
            "GET {path} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
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
        assert!(matches!(
            owner.authorize(&principal, github_read(&github_config(123), path), now),
            Err(AuthorizationError::BudgetExhausted)
        ));
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
fn github_grants_keep_budget_and_expiry_on_reload_and_revoke_old_permits_on_change_and_revert() {
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
    let AuthorizationOutcome::Allowed(first) = owner.authorize(&principal, request(), now).unwrap()
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
    assert!(matches!(
        owner.authorize(&principal, request(), now + Duration::from_secs(9)),
        Err(AuthorizationError::BudgetExhausted)
    ));
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
