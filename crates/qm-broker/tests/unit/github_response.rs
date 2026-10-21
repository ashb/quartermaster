use super::*;
use crate::owner::{
    github::{configuration::GitHubConfig, repository::RepositoryLookup},
    request,
    test_support::vault,
};
use std::io::Cursor;

const TOKEN: &[u8] = b"quartermaster-dummy-canary";

fn fixture(list: bool) -> (request::FrozenOperation, RepositoryBinding) {
    let config = GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"example","name":"one"}]}"#).unwrap();
    let path = if list {
        "/repos/example/one/issues?state=all&page=2&per_page=30"
    } else {
        "/repos/example/one/issues/987654321"
    };
    let request = request::read_configured(
        &mut Cursor::new(format!(
            "GET {path} HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
        )),
        Some(&config),
    )
    .unwrap();
    let lookup = RepositoryLookup::new(
        &config,
        &request,
        vault::selection(&vault::snapshot("github-read")),
        7,
    )
    .unwrap();
    let binding = lookup
        .verify_fixture(br#"{"id":123,"full_name":"example/one"}"#)
        .unwrap();
    (request, binding)
}

fn issue() -> String {
    serde_json::json!({"number":987654321,"state":"open","title":"Real title","body":"Preserve arbitrary supported JSON", "repository_url":"https://api.github.com/repos/example/one", "url":"https://api.github.com/repos/example/one/issues/987654321"}).to_string()
}

fn wire(status: u16, headers: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).into_bytes()
}

#[test]
fn github_response_preserves_the_actual_issue_json_without_forwarding_untrusted_headers() {
    let (request, binding) = fixture(false);
    let body = issue();
    let upstream = read(&mut Cursor::new(wire(200, "Set-Cookie: secret=discard\r\nAuthorization: never-forward\r\nX-RateLimit-Remaining: 7\r\n", &body))).unwrap();
    let Outcome::Response(response) = upstream.issues(&request, &binding, TOKEN).unwrap() else {
        panic!()
    };
    assert_eq!(response.body, body);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        [("X-RateLimit-Remaining".to_string(), "7".to_string())]
    );
    assert!(!response.body.contains("quartermaster_local_simulation"));
}

#[test]
fn github_response_accepts_chunked_issue_lists_and_validated_pagination_links() {
    let (request, binding) = fixture(true);
    let body = format!("[{}]", issue());
    let input = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nLink: <https://api.github.com/repositories/123/issues?state=all&per_page=30&page=3&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D>; rel=\"next\"\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    );
    let Outcome::Response(response) = read(&mut Cursor::new(input))
        .unwrap()
        .issues(&request, &binding, TOKEN)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(response.body, body);
    assert_eq!(
        response.headers[0].1,
        "<https://api.github.com/repos/example/one/issues?state=all&per_page=30&page=3&after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D>; rel=\"next\""
    );
}

#[test]
fn github_response_denies_cross_repository_or_origin_redirects_and_links() {
    let (request, binding) = fixture(true);
    for url in [
        "https://elsewhere.invalid/repos/example/one/issues?page=3",
        "http://api.github.com/repos/example/one/issues?page=3",
        "https://api.github.com/repos/example/two/issues?page=3",
        "https://api.github.com/repositories/456/issues?page=3",
        "https://api.github.com/user",
        "https://api.github.com/repos/example/one/issues?page=3&unknown=x",
    ] {
        let redirect = read(&mut Cursor::new(wire(
            307,
            &format!("Location: {url}\r\n"),
            "",
        )))
        .unwrap();
        assert!(
            redirect.issues(&request, &binding, TOKEN).is_err(),
            "redirect accepted {url}"
        );
        let list = format!("[{}]", issue());
        let response = read(&mut Cursor::new(wire(
            200,
            &format!("Link: <{url}>; rel=\"next\"\r\n"),
            &list,
        )))
        .unwrap();
        assert!(
            response.issues(&request, &binding, TOKEN).is_err(),
            "link accepted {url}"
        );
    }
    let redirect = read(&mut Cursor::new(wire(
        307,
        "Location: /repositories/123/issues?page=3\r\n",
        "",
    )))
    .unwrap();
    let Outcome::Redirect(target) = redirect.issues(&request, &binding, TOKEN).unwrap() else {
        panic!()
    };
    assert_eq!(
        target.path(),
        "/repos/example/one/issues?state=open&per_page=30&page=3"
    );
}

#[test]
fn github_response_rejects_raw_and_encoded_credentials_in_pagination_and_redirect_cursors() {
    let (request, binding) = fixture(true);
    for credential in [TOKEN, b"ghp_dummySelectedToken", b"abc+def/ghi="] {
        for cursor in [
            form_urlencoded::byte_serialize(credential).collect::<String>(),
            credential
                .iter()
                .map(|byte| format!("%{byte:02X}"))
                .collect::<String>(),
        ] {
            let target = format!("https://api.github.com/repositories/123/issues?after={cursor}");
            for (status, header, body) in [
                (
                    200,
                    format!("Link: <{target}>; rel=\"next\"\r\n"),
                    format!("[{}]", issue()),
                ),
                (307, format!("Location: {target}\r\n"), String::new()),
            ] {
                let response = read(&mut Cursor::new(wire(status, &header, &body))).unwrap();
                assert!(
                    response.issues(&request, &binding, credential).is_err(),
                    "returned or followed a credential-bearing cursor for {status}"
                );
            }
        }
    }
}

#[test]
fn github_response_uses_fixed_error_bodies_and_bounded_rate_limit_metadata() {
    let (request, binding) = fixture(false);
    for status in [401, 403, 404, 429, 500] {
        let upstream = read(&mut Cursor::new(wire(
            status,
            "Retry-After: 30\r\nX-RateLimit-Reset: 1792483200\r\n",
            "upstream private detail quartermaster-dummy-canary",
        )))
        .unwrap();
        let Outcome::Response(response) = upstream.issues(&request, &binding, TOKEN).unwrap()
        else {
            panic!()
        };
        assert_eq!(response.status, if status == 500 { 502 } else { status });
        assert!(!response.body.contains("private"));
        assert!(!response.body.contains(std::str::from_utf8(TOKEN).unwrap()));
        assert_eq!(response.headers.len(), 2);
    }
}

#[test]
fn github_response_rejects_credentials_even_when_json_escaped_or_hidden_by_duplicate_keys() {
    let (request, binding) = fixture(false);
    for leak in [
        "quartermaster-dummy-canary",
        "quartermaster-dummy-\\u0063anary",
        "quartermaster-dummy-canary\",\"title\":\"replacement",
    ] {
        let body = issue().replace("Real title", leak);
        let upstream = read(&mut Cursor::new(wire(200, "", &body))).unwrap();
        assert!(upstream.issues(&request, &binding, TOKEN).is_err());
    }
}

#[test]
fn github_response_rejects_wrong_issue_identity_invalid_json_and_ambiguous_or_oversized_framing() {
    let (request, binding) = fixture(false);
    for body in [
        "invalid".to_string(),
        issue().replace("987654321", "1"),
        issue().replace("example/one", "example/two"),
        issue().replace("\"open\"", "\"unknown\""),
    ] {
        assert!(
            read(&mut Cursor::new(wire(200, "", &body)))
                .unwrap()
                .issues(&request, &binding, TOKEN)
                .is_err()
        );
    }
    for input in [
        wire(200, "Content-Length: 0\r\n", "{}"),
        wire(200, "Transfer-Encoding: chunked\r\n", "{}"),
        wire(200, "Content-Encoding: gzip\r\n", "{}"),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2097153\r\n\r\n".to_vec(),
        format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "x".repeat(32768)).into_bytes(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n200001\r\n".to_vec(),
    ] {
        assert!(read(&mut Cursor::new(input)).is_err());
    }
}

#[test]
fn github_response_metadata_authentication_failures_return_fixed_status_and_safe_rate_metadata() {
    for status in [401, 403, 404, 429] {
        let upstream = read(&mut Cursor::new(wire(
            status,
            "Retry-After: 30\r\n",
            "private authentication failure quartermaster-dummy-canary",
        )))
        .unwrap();
        let Err(MetadataFailure::Public(response)) = upstream.metadata_bytes(TOKEN) else {
            panic!()
        };
        assert_eq!(response.status, status);
        assert_eq!(
            response.headers,
            [("Retry-After".to_owned(), "30".to_owned())]
        );
        assert!(!response.body.contains("private"));
        assert!(!response.body.contains("quartermaster-dummy-canary"));
    }
}

#[test]
fn github_response_rejects_a_numeric_credential_echo_and_secret_rate_header() {
    let (request, binding) = fixture(false);
    let body = issue().replace("\"number\"", "\"dummy_numeric_echo\":123455676,\"number\"");
    let upstream = read(&mut Cursor::new(wire(200, "", &body))).unwrap();
    assert!(upstream.issues(&request, &binding, b"123455676").is_err());
    let upstream = read(&mut Cursor::new(wire(
        200,
        "X-RateLimit-Resource: ghp_dummy_secret\r\n",
        &issue(),
    )))
    .unwrap();
    assert!(
        upstream
            .issues(&request, &binding, b"ghp_dummy_secret")
            .is_err()
    );
}
