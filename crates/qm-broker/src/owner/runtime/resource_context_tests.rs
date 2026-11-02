use super::*;
use crate::owner::{
    github::configuration::GitHubConfig,
    test_support::{self, github},
};

fn wire(query: &str) -> String {
    let body = json!({"query":query}).to_string();
    format!(
        "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn authenticated_lookup_context_reaches_mutation_review_without_serving_cached_responses() {
    let body =
        json!({"data":{"repository":{"issue":{"id":"I_one","number":1,"title":"An issue"}}}})
            .to_string();
    let (address, worker) = github::serve(vec![
        github::repository(123),
        github::text(&body),
        github::repository(123),
        github::text(&body),
    ]);
    let (_directory, paths, shared, server, _client) = super::github_tests::setup(address);
    let peer = PeerIdentity::capture(&server).unwrap();
    let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}],"approveUnverifiedRequests":true}"#).unwrap();
    paths
        .policy
        .set_fixture(crate::owner::policy::Policy::default().with_github(config.clone()));
    {
        let mut state = shared.0.lock().unwrap();
        state.refresh_policy(&paths.load_policy()).unwrap();
        let mut policy: Value = serde_json::from_slice(&test_support::policy_bytes(
            (OffsetDateTime::now_utc() + Duration::from_secs(60))
                .unix_timestamp()
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        policy["grants"][0]["uid"] = json!(unsafe { libc::geteuid() });
        policy["grants"][0]["codeHash"] = json!(peer.code_hash());
        policy["grants"][0]["repository"] = "example/one".into();
        policy["grants"][0]["effects"] =
            json!({"kind":"categories","categories":["repository","issues","actions","output"]});
        state
            .authorizer
            .seed_native_fixture_grants(&serde_json::to_vec(&policy).unwrap());
    }
    for _ in 0..2 {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(wire("{repository(owner:\"example\",name:\"one\"){issue(number:1){id number title}}}").as_bytes()).unwrap();
        handle_http(&mut server, &shared, &paths).unwrap();
        server.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, body);
    }
    let requests = worker.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /graphql "))
            .count(),
        2
    );
    let mut state = shared.0.lock().unwrap();
    let (principal, _) = VerifiedPrincipal::capture(&server, state.authorizer.session()).unwrap();
    let raw = wire("mutation{reopenIssue(input:{issueId:\"I_one\"}){issue{id}}}");
    let request =
        http_request::read_configured(&mut std::io::Cursor::new(&raw), Some(&config)).unwrap();
    let outcome = state
        .authorize(&principal, request, &paths.load_policy(), Ok(None))
        .unwrap();
    let AuthorizationOutcome::RequireApproval(requirement) = outcome else {
        panic!("mutation bypassed approval")
    };
    let request = requirement.request();
    let review = serde_json::to_value(request).unwrap();
    assert_eq!(
        review["application"]["resourceContext"]["title"],
        "An issue"
    );
    assert_eq!(
        request.application().unwrap().capture().original(),
        raw.as_bytes()
    );
    assert!(!request.is_reusable_read());
    assert!(request.github_identity().is_none());
    assert!(!request.application().unwrap().analysis().complete());
    let frozen = test_support::approval::selected_review(request.clone(), None, "github-write");
    let review: Value = serde_json::from_slice(frozen.bytes()).unwrap();
    assert_eq!(
        review["presentation"]["intent"],
        json!({"kind":"issue","action":"reopenIssue","number":1})
    );
    assert_eq!(review["presentation"]["repository"], "example/one");
    assert_eq!(review["presentation"]["resourceTitle"], "An issue");
    assert!(review["presentation"]["understandingNotice"].is_null());
    assert_eq!(review["presentation"]["allowsReadScope"], false);
    assert_eq!(review["presentation"]["additionalEffects"], json!([]));
    let id = state
        .operations
        .register(
            AuthorizationOutcome::RequireApproval(requirement),
            Instant::now(),
        )
        .unwrap();
    state.lock_vault().unwrap();
    drop(state);
    let result = approval::request_approval(
        id,
        &Arc::new(principal),
        peer,
        qm_macos::presence_clock::monotonic_raw().unwrap(),
        &shared,
        &paths,
        &server,
    );
    assert!(
        matches!(result, Err(Error::State(Fault::ProviderChanged))),
        "{result:?}"
    );
}
