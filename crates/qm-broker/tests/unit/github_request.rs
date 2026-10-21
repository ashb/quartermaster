use super::*;
use crate::owner::github::configuration::GitHubConfig;
use std::io::Cursor;

fn config() -> GitHubConfig {
    GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"quartermaster","name":"one"},{"id":456,"owner":"quartermaster","name":"two"}]}"#).unwrap()
}

fn parse(target: &str) -> io::Result<FrozenOperation> {
    read_configured(
        &mut Cursor::new(format!(
            "GET {target} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        )),
        Some(&config()),
    )
}

#[test]
fn github_request_freezes_dynamic_configured_repositories_and_positive_issue_numbers() {
    let mut digests = std::collections::HashSet::new();
    for (repository, id) in [("one", 123), ("two", 456)] {
        for number in [1, 9876543210123456789_u64] {
            let path = format!("/repos/quartermaster/{repository}/issues/{number}");
            let request = parse(&path).unwrap();
            assert_eq!(request.action(), Action::ReadIssue);
            assert_eq!(
                request.mode(),
                crate::owner::github::configuration::Mode::Github
            );
            assert_eq!(request.path(), path);
            assert_eq!(request.repository(), format!("quartermaster/{repository}"));
            assert!(digests.insert(request.digest()));
            let fields = serde_json::to_value(request).unwrap();
            assert_eq!(fields["issue"], number);
            assert_eq!(fields["repositoryId"], id);
            assert_eq!(fields["origin"], "https://api.github.com");
        }
    }
}

#[test]
fn github_request_normalizes_only_the_supported_issue_list_query() {
    for (query, expected) in [
        ("", "state=open&per_page=30&page=1"),
        (
            "?page=2&state=closed&per_page=100",
            "state=closed&per_page=100&page=2",
        ),
        (
            "?state=all&per_page=1&page=10000",
            "state=all&per_page=1&page=10000",
        ),
    ] {
        let operation = parse(&format!("/repos/quartermaster/one/issues{query}")).unwrap();
        assert_eq!(operation.action(), Action::ListIssues);
        assert_eq!(
            operation.path(),
            format!("/repos/quartermaster/one/issues?{expected}")
        );
        assert_eq!(operation.body(), "");
    }
    let implicit = parse("/repos/quartermaster/one/issues").unwrap();
    let explicit = parse("/repos/quartermaster/one/issues?page=1&per_page=30&state=open").unwrap();
    assert_eq!(implicit.digest(), explicit.digest());
}

#[test]
fn github_request_preserves_bounded_pagination_cursors_in_both_frozen_destinations() {
    for (query, canonical) in [
        (
            "after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D",
            "after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D",
        ),
        ("before=abc%2bdef%2fghi==", "before=abc%2Bdef%2Fghi%3D%3D"),
        ("after=opaque_cursor-123", "after=opaque_cursor-123"),
    ] {
        let operation = parse(&format!(
            "/repos/quartermaster/one/issues?{query}&page=2&state=all&per_page=1"
        ))
        .unwrap();
        let suffix = format!("issues?state=all&per_page=1&page=2&{canonical}");
        assert_eq!(
            operation.path(),
            format!("/repos/quartermaster/one/{suffix}")
        );
        assert_eq!(operation.wire_path(), format!("/repositories/123/{suffix}"));
        assert_ne!(
            operation.digest(),
            parse("/repos/quartermaster/one/issues?state=all&per_page=1&page=2")
                .unwrap()
                .digest()
        );
    }
    let lower = parse("/repos/quartermaster/one/issues?after=abc%3d").unwrap();
    let upper = parse("/repos/quartermaster/one/issues?after=abc%3D").unwrap();
    assert_eq!(lower.digest(), upper.digest());
}

#[test]
fn github_request_rejects_ambiguous_oversized_or_escaping_pagination_cursors() {
    let oversized = format!("after={}", "x".repeat(513));
    for query in [
        "after=",
        "after==",
        "after=abc===",
        "after=ab=c",
        "after=abc&after=def",
        "before=abc&after=def",
        "after=abc&before=def",
        "after=abc+def",
        "after=%26page%3D2",
        "after=%250D%250A",
        "after=%0D%0AInjected",
        "after=%",
        "after=%ZZ",
        "after=%E2%98%83",
        "after=abc%23fragment",
        "after=abc%5Cdef",
        oversized.as_str(),
    ] {
        assert!(
            parse(&format!("/repos/quartermaster/one/issues?{query}")).is_err(),
            "accepted {query}"
        );
    }
    assert!(parse("/repos/quartermaster/one/issues/%31?after=abc").is_err());
}

#[test]
fn github_request_rejects_ambiguous_queries_noncanonical_paths_and_unknown_resources() {
    for target in [
        "/repos/quartermaster/one/issues?state=open&state=closed",
        "/repos/quartermaster/one/issues?per_page=1&per_page=1",
        "/repos/quartermaster/one/issues?labels=bug",
        "/repos/quartermaster/one/issues?state=invalid",
        "/repos/quartermaster/one/issues?per_page=0",
        "/repos/quartermaster/one/issues?per_page=101",
        "/repos/quartermaster/one/issues?page=0",
        "/repos/quartermaster/one/issues?page=10001",
        "/repos/quartermaster/one/issues?page=-1",
        "/repos/quartermaster/one/issues?page=1&",
        "/repos/quartermaster/one/issues?",
        "/repos/quartermaster/one/issues/1?state=open",
        "/repos/quartermaster/one/issues/0",
        "/repos/quartermaster/one/issues/01",
        "/repos/quartermaster/one/issues/18446744073709551616",
        "/repos/quartermaster/one/issues/1/extra",
        "/repos/quartermaster/one/issues/1#fragment",
        "/repos/quartermaster/one/issues/%31",
        "/repos/quartermaster/one%2ftwo/issues/1",
        "/repos/quartermaster/../issues/1",
        "/repos/quartermaster/unknown/issues/1",
        "/repos/another/one/issues/1",
        "/api/v3/repos/quartermaster/one/issues/1",
        "https://api.github.com/repos/quartermaster/one/issues/1",
    ] {
        assert!(parse(target).is_err(), "accepted {target}");
    }
}

#[test]
fn github_request_rejects_other_origins_ambiguous_framing_bodies_and_writes() {
    for (method, host, headers, body) in [
        ("GET", "github.com", "", ""),
        ("GET", "api.github.com:80", "", ""),
        ("GET", "api.github.com.evil.invalid", "", ""),
        ("GET", "api.github.com", "Host: api.github.com\r\n", ""),
        ("GET", "api.github.com", "Content-Length: 1\r\n", "x"),
        (
            "GET",
            "api.github.com",
            "Transfer-Encoding: chunked\r\n",
            "",
        ),
        (
            "GET",
            "api.github.com",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "",
        ),
        (
            "PATCH",
            "api.github.com",
            "Content-Length: 18\r\n",
            "{\"state\":\"closed\"}",
        ),
        ("POST", "api.github.com", "", ""),
    ] {
        let bytes = format!(
            "{method} /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n{body}"
        );
        assert!(read_configured(&mut Cursor::new(bytes), Some(&config())).is_err());
    }
}

#[test]
fn github_request_never_accepts_a_real_origin_in_simulation_mode() {
    let simulation =
        GitHubConfig::decode(br#"{"version":1,"mode":"simulation","repositories":[]}"#).unwrap();
    let input = "GET /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    assert!(read_configured(&mut Cursor::new(input), Some(&simulation)).is_err());
    assert!(read_configured(&mut Cursor::new(input), None).is_err());
}
