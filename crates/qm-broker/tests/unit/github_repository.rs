use super::*;
use crate::owner::{github::configuration::GitHubConfig, request, test_support::vault};
use serde_json::json;
use std::io::Cursor;

fn config(id: u64) -> GitHubConfig {
    GitHubConfig::decode(&serde_json::to_vec(&json!({"version":1,"mode":"github","repositories":[{"id":id,"owner":"example","name":"one"}]})).unwrap()).unwrap()
}

fn operation(config: &GitHubConfig) -> request::FrozenOperation {
    request::read_configured(
        &mut Cursor::new(
            "GET /repos/example/one/issues/123 HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ),
        Some(config),
    )
    .unwrap()
}

#[test]
fn github_repository_lookup_is_limited_to_the_configured_name_and_checks_numeric_identity() {
    let snapshot = vault::snapshot("github-read");
    let selection = vault::selection(&snapshot);
    let lookup =
        RepositoryLookup::new(&config(123), &operation(&config(123)), selection.clone(), 7)
            .unwrap();
    assert_eq!(lookup.path(), "/repos/example/one");
    assert!(
        lookup
            .verify(br#"{"id":123,"full_name":"example/one","private":true}"#)
            .is_ok()
    );
    for body in [
        br#"{"id":456,"full_name":"example/one"}"#.as_slice(),
        br#"{"id":123,"full_name":"example/transferred"}"#,
        br#"{"id":123,"full_name":"another/one"}"#,
        br#"{"id":123,"id":456,"full_name":"example/one"}"#,
        br#"{"id":0,"full_name":"example/one"}"#,
        br#"{"message":"Bad credentials"}"#,
    ] {
        assert!(lookup.verify(body).is_err());
    }
    assert!(RepositoryLookup::new(&config(456), &operation(&config(123)), selection, 7).is_err());
}

#[test]
fn github_repository_binding_cannot_survive_a_policy_provider_or_repository_replacement() {
    let snapshot = vault::snapshot("github-read");
    let selection = vault::selection(&snapshot);
    let lookup =
        RepositoryLookup::new(&config(123), &operation(&config(123)), selection.clone(), 7)
            .unwrap();
    let binding = lookup
        .verify(br#"{"id":123,"full_name":"example/one"}"#)
        .unwrap();
    assert!(binding.matches(&operation(&config(123)), &selection, 7));
    assert!(!binding.matches(&operation(&config(123)), &selection, 8));
    assert!(!binding.matches(&operation(&config(456)), &selection, 7));
    let other = vault::snapshot("github-write");
    assert!(!binding.matches(&operation(&config(123)), &vault::selection(&other), 7));
}
