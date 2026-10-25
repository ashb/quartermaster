use super::github::{
    configuration::{GitHubConfig, Mode},
    request::Application,
};
use serde::{Serialize, Serializer};
use std::{
    io::{self, Read},
    num::NonZeroU64,
    sync::Arc,
};

pub const SIMULATION_HOST: &str = "github.example.invalid";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    ListIssues,
    ReadIssue,
    CloseIssue,
    Api,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenOperation {
    operation: Operation,
    path: String,
    repository: String,
    destination: Destination,
    application: Option<Arc<Application>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    ListIssues,
    ReadIssue(NonZeroU64),
    CloseIssue(NonZeroU64),
    Api,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Destination {
    Simulation,
    Github {
        repository_id: Option<NonZeroU64>,
        configuration_digest: [u8; 32],
        resolved_path: String,
    },
}

impl Serialize for FrozenOperation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire<'a> {
            method: &'a str,
            path: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            body: Option<&'a str>,
            repository: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            issue: Option<NonZeroU64>,
            origin: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            repository_id: Option<NonZeroU64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            configuration_digest: Option<[u8; 32]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            resolved_path: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            application: Option<&'a Application>,
        }
        let (origin, repository_id, configuration_digest, resolved_path) = match &self.destination {
            Destination::Simulation => ("https://github.example.invalid", None, None, None),
            Destination::Github {
                repository_id,
                configuration_digest,
                resolved_path,
            } => (
                "https://api.github.com",
                *repository_id,
                Some(*configuration_digest),
                Some(resolved_path.as_str()),
            ),
        };
        Wire {
            method: self.method(),
            path: &self.path,
            body: if self.application.is_none() || self.body().is_empty() {
                std::str::from_utf8(self.body()).ok()
            } else {
                None
            },
            repository: &self.repository,
            issue: self.issue_number(),
            origin,
            repository_id,
            configuration_digest,
            resolved_path,
            application: self.application.as_deref(),
        }
        .serialize(serializer)
    }
}

impl FrozenOperation {
    pub(super) fn digest(&self) -> [u8; 32] {
        ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(self).expect("frozen request is serializable"),
        )
        .as_ref()
        .try_into()
        .unwrap()
    }

    pub(super) fn method(&self) -> &str {
        if let Some(application) = &self.application {
            return application.capture().method();
        }
        match self.operation {
            Operation::ListIssues | Operation::ReadIssue(_) => "GET",
            Operation::CloseIssue(_) => "PATCH",
            Operation::Api => unreachable!("API operation has a captured application"),
        }
    }
    pub(super) fn path(&self) -> &str {
        &self.path
    }
    pub(super) fn wire_path(&self) -> &str {
        match &self.destination {
            Destination::Simulation => &self.path,
            Destination::Github { resolved_path, .. } => resolved_path,
        }
    }
    pub(super) fn body(&self) -> &[u8] {
        if let Some(application) = &self.application {
            return application.capture().body();
        }
        match self.operation {
            Operation::ListIssues | Operation::ReadIssue(_) => b"",
            Operation::CloseIssue(_) => b"{\"state\":\"closed\"}",
            Operation::Api => unreachable!("API operation has a captured application"),
        }
    }
    pub(super) fn action(&self) -> Action {
        match self.operation {
            Operation::ListIssues => Action::ListIssues,
            Operation::ReadIssue(_) => Action::ReadIssue,
            Operation::CloseIssue(_) => Action::CloseIssue,
            Operation::Api => Action::Api,
        }
    }

    pub(super) fn repository(&self) -> &str {
        &self.repository
    }

    pub(super) fn issue_number(&self) -> Option<NonZeroU64> {
        match self.operation {
            Operation::ListIssues => None,
            Operation::Api => {
                let mut numbers =
                    self.application()?
                        .analysis()
                        .resources
                        .iter()
                        .filter_map(|resource| {
                            if let qm_api_github::Resource::IssueNumber(number) = resource {
                                Some(*number)
                            } else {
                                None
                            }
                        });
                let number = numbers.next()?;
                numbers.next().is_none().then_some(number)
            }
            Operation::ReadIssue(issue) | Operation::CloseIssue(issue) => Some(issue),
        }
    }

    pub(super) fn mode(&self) -> Mode {
        match self.destination {
            Destination::Github { .. } => Mode::Github,
            Destination::Simulation => Mode::Simulation,
        }
    }

    pub(super) fn matches_configuration(&self, config: &GitHubConfig) -> bool {
        let Some((owner, name)) = self.repository.split_once('/') else {
            return false;
        };
        self.mode() == Mode::Github
            && config.mode() == Mode::Github
            && config.repository(owner, name).is_some_and(|repository| {
                self.github_identity() == Some((repository.id(), config.digest()))
                    && self.repository == repository.full_name()
            })
    }

    pub(super) fn github_identity(&self) -> Option<(NonZeroU64, [u8; 32])> {
        match self.destination {
            Destination::Simulation => None,
            Destination::Github {
                repository_id,
                configuration_digest,
                ..
            } => repository_id.map(|id| (id, configuration_digest)),
        }
    }

    pub(super) fn role(&self) -> &str {
        match self.action() {
            Action::ListIssues | Action::ReadIssue => "github-read",
            Action::CloseIssue | Action::Api => "github-write",
        }
    }

    pub(super) fn application(&self) -> Option<&Application> {
        self.application.as_deref()
    }

    pub(super) fn matches_service(&self, config: &GitHubConfig) -> bool {
        matches!(self.destination, Destination::Github { configuration_digest, .. }
            if config.mode() == Mode::Github && configuration_digest == config.digest())
    }

    pub(super) fn has_mutation(&self) -> bool {
        self.action() == Action::CloseIssue
            || self.application().is_some_and(Application::has_mutation)
    }
}

struct Head {
    method: String,
    target: String,
    host: Vec<u8>,
    length: Option<usize>,
}

fn head(stream: &mut impl Read) -> io::Result<Head> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    loop {
        if bytes.len() >= 8192 {
            return Err(io::Error::other("headers exceed limit"));
        }
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    if !request
        .parse(&bytes)
        .map_err(io::Error::other)?
        .is_complete()
        || request.version != Some(1)
    {
        return Err(io::Error::other("unsupported HTTP request"));
    }
    let mut length = None;
    let mut host = None;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(io::Error::other("transfer encoding unsupported"));
        }
        if header.name.eq_ignore_ascii_case("host") && host.replace(header.value).is_some() {
            return Err(io::Error::other("duplicate host"));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || header.value.is_empty()
                || !header.value.iter().all(u8::is_ascii_digit)
            {
                return Err(io::Error::other("ambiguous body length"));
            }
            length = Some(
                std::str::from_utf8(header.value)
                    .map_err(io::Error::other)?
                    .parse::<usize>()
                    .map_err(io::Error::other)?,
            );
        }
    }
    Ok(Head {
        method: request
            .method
            .ok_or_else(|| io::Error::other("missing method"))?
            .into(),
        target: request
            .path
            .ok_or_else(|| io::Error::other("missing path"))?
            .into(),
        host: host
            .ok_or_else(|| io::Error::other("missing host"))?
            .to_vec(),
        length,
    })
}

pub(super) fn read(stream: &mut impl Read) -> io::Result<FrozenOperation> {
    let request = head(stream)?;
    if !matches!(request.method.as_str(), "GET" | "PATCH")
        || request.target != "/api/v3/repos/quartermaster/demo/issues/42"
    {
        return Err(io::Error::other("unsupported local simulation operation"));
    }
    let read = request.method == "GET";
    if request.host != SIMULATION_HOST.as_bytes()
        || if read {
            request.length.is_some_and(|length| length != 0)
        } else {
            request.length != Some(18)
        }
    {
        return Err(io::Error::other("unexpected host or body length"));
    }
    if !read {
        let mut body = [0u8; 18];
        stream.read_exact(&mut body)?;
        if body != *b"{\"state\":\"closed\"}" {
            return Err(io::Error::other("unsupported body"));
        }
    }
    Ok(FrozenOperation {
        operation: if read {
            Operation::ReadIssue(NonZeroU64::new(42).unwrap())
        } else {
            Operation::CloseIssue(NonZeroU64::new(42).unwrap())
        },
        path: "/api/v3/repos/quartermaster/demo/issues/42".into(),
        repository: "quartermaster/demo".into(),
        destination: Destination::Simulation,
        application: None,
    })
}

pub(super) fn read_configured(
    stream: &mut impl Read,
    config: Option<&GitHubConfig>,
) -> io::Result<FrozenOperation> {
    let Some(config) = config.filter(|config| config.mode() == Mode::Github) else {
        return read(stream);
    };
    let application = Arc::new(Application::read(stream, &config.read_patterns())?);
    let capture = application.capture();
    let analysis = application.analysis();
    let resource = config.matched_read_repository(analysis);
    let operation = if analysis.complete()
        && capture.method() == "GET"
        && !capture.path_and_query().starts_with("/graphql")
        && resource.is_some()
        && analysis.effects.len() == 1
    {
        match analysis.effects[0].kind {
            qm_api_github::EffectKind::ListIssues => Operation::ListIssues,
            qm_api_github::EffectKind::ReadIssue => analysis
                .resources
                .iter()
                .find_map(|resource| {
                    if let qm_api_github::Resource::IssueNumber(number) = resource {
                        Some(Operation::ReadIssue(*number))
                    } else {
                        None
                    }
                })
                .unwrap_or(Operation::Api),
            _ => Operation::Api,
        }
    } else {
        Operation::Api
    };
    let scoped = !matches!(operation, Operation::Api);
    let path = capture.path_and_query().to_owned();
    Ok(FrozenOperation {
        operation,
        path: path.clone(),
        repository: resource
            .filter(|_| scoped)
            .map_or_else(String::new, |repository| repository.full_name()),
        destination: Destination::Github {
            repository_id: resource
                .filter(|_| scoped)
                .map(|repository| repository.id()),
            configuration_digest: config.digest(),
            resolved_path: path,
        },
        application: Some(application),
    })
}

#[cfg(test)]
mod tests {
    use super::{self as http_request};
    use std::io::Cursor;

    fn request(headers: &str, body: &str) -> Vec<u8> {
        format!("PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n{headers}\r\n{body}").into_bytes()
    }

    #[test]
    fn normalizes_the_supported_local_issue_close() {
        let bytes = request("Content-Length: 18\r\n", "{\"state\":\"closed\"}");
        let operation = http_request::read(&mut Cursor::new(bytes)).unwrap();
        let operation = serde_json::to_value(operation).unwrap();
        assert_eq!(operation["method"], "PATCH");
        assert_eq!(operation["repository"], "quartermaster/demo");
        assert_eq!(operation["issue"], 42);
        assert_eq!(operation["body"], "{\"state\":\"closed\"}");
    }

    #[test]
    fn freezes_the_supported_read_without_treating_get_as_unconditionally_allowed() {
        let bytes = b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n";
        let operation = http_request::read(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(operation.action(), http_request::Action::ReadIssue);
        let value = serde_json::to_value(operation).unwrap();
        assert_eq!(value["method"], "GET");
        assert_eq!(value["body"], "");
        for input in [
            "GET /api/v3/repos/other/repo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n",
            "GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 1\r\n\r\nx",
        ] {
            assert!(http_request::read(&mut Cursor::new(input)).is_err());
        }
    }

    #[test]
    fn rejects_ambiguous_framing_and_unsupported_bodies() {
        for (headers, body) in [
            (
                "Content-Length: 18\r\nContent-Length: 18\r\n",
                "{\"state\":\"closed\"}",
            ),
            (
                "Content-Length: 18\r\nHost: github.example.invalid\r\n",
                "{\"state\":\"closed\"}",
            ),
            (
                "Content-Length: 18\r\nTransfer-Encoding: chunked\r\n",
                "{\"state\":\"closed\"}",
            ),
            ("Content-Length: 819200\r\n", ""),
            ("", "{\"state\":\"closed\"}"),
            ("Content-Length: 18\r\n", "{\"state\":\"opened\"}"),
            ("Content-Length: 18\r\n", "{"),
        ] {
            assert!(http_request::read(&mut Cursor::new(request(headers, body))).is_err());
        }
    }

    #[test]
    fn rejects_other_hosts_operations_and_oversized_headers() {
        let valid =
            String::from_utf8(request("Content-Length: 18\r\n", "{\"state\":\"closed\"}")).unwrap();
        for changed in [
            valid.replace("PATCH", "DELETE"),
            valid.replace("issues/42", "issues/43"),
            valid.replace("github.example.invalid", "github.com"),
            valid.replace("Content-Length", &"X".repeat(8193)),
        ] {
            assert!(http_request::read(&mut Cursor::new(changed)).is_err());
        }
    }
}

#[cfg(test)]
mod github_tests {
    use super::*;
    use crate::owner::github::configuration::GitHubConfig;
    use std::io::Cursor;

    #[test]
    fn github_reads_keep_the_clients_repository_path_and_query_octets() {
        let config = config();
        let path = "/repos/quartermaster/one/issues?per_page=10&state=all";
        let request = read_configured(
            &mut Cursor::new(format!(
                "GET {path} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
            )),
            Some(&config),
        )
        .unwrap();
        assert_eq!(request.path(), path);
        assert_eq!(request.wire_path(), path);
    }

    #[test]
    fn github_capture_accepts_unfamiliar_rest_and_graphql_for_policy_review() {
        let config = config();
        for (path, body) in [
            ("/graphql", r#"{"query":"query { viewer { login } }"}"#),
            ("/an-unfamiliar-endpoint?option=1", r#"{"newOption":true}"#),
        ] {
            let request = read_configured(
                &mut Cursor::new(format!(
                    "POST {path} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )),
                Some(&config),
            );
            assert!(request.is_ok(), "{path}: {request:?}");
        }
    }

    fn config() -> GitHubConfig {
        GitHubConfig::decode(br#"{"version":1,"mode":"github","repositories":[{"id":123,"owner":"quartermaster","name":"one"},{"id":456,"owner":"quartermaster","name":"two"}]}"#).unwrap()
    }

    fn parse(target: &str) -> io::Result<FrozenOperation> {
        read_configured(
            &mut Cursor::new(format!(
                "GET {target} HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n"
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
    fn github_request_preserves_supported_query_order_and_distinct_approval_bindings() {
        for query in [
            "",
            "?page=2&state=closed&per_page=100",
            "?state=all&per_page=1&page=10000",
        ] {
            let operation = parse(&format!("/repos/quartermaster/one/issues{query}")).unwrap();
            assert_eq!(operation.action(), Action::ListIssues);
            assert_eq!(
                operation.path(),
                format!("/repos/quartermaster/one/issues{query}")
            );
            assert_eq!(operation.body(), b"");
        }
        let implicit = parse("/repos/quartermaster/one/issues").unwrap();
        let explicit =
            parse("/repos/quartermaster/one/issues?page=1&per_page=30&state=open").unwrap();
        assert_ne!(implicit.digest(), explicit.digest());
    }

    #[test]
    fn github_request_preserves_bounded_pagination_cursors_in_both_frozen_destinations() {
        for query in [
            "after=Y3Vyc29yOnYyOpLPAAABoNM-bZjPAAAAAUveKc4%3D",
            "before=abc%2bdef%2fghi==",
            "after=opaque_cursor-123",
        ] {
            let operation = parse(&format!(
                "/repos/quartermaster/one/issues?{query}&page=2&state=all&per_page=1"
            ))
            .unwrap();
            let suffix = format!("issues?{query}&page=2&state=all&per_page=1");
            assert_eq!(operation.action(), Action::ListIssues);
            assert_eq!(
                operation.path(),
                format!("/repos/quartermaster/one/{suffix}")
            );
            assert_eq!(
                operation.wire_path(),
                format!("/repos/quartermaster/one/{suffix}")
            );
            assert_ne!(
                operation.digest(),
                parse("/repos/quartermaster/one/issues?state=all&per_page=1&page=2")
                    .unwrap()
                    .digest()
            );
        }
        let lower = parse("/repos/quartermaster/one/issues?after=abc%3d").unwrap();
        let upper = parse("/repos/quartermaster/one/issues?after=abc%3D").unwrap();
        assert_ne!(lower.digest(), upper.digest());
    }

    #[test]
    fn ambiguous_oversized_or_escaping_cursors_cannot_use_a_read_grant() {
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
            let result = parse(&format!("/repos/quartermaster/one/issues?{query}"));
            if matches!(query, "after=%" | "after=%ZZ") {
                assert!(result.is_err());
            } else {
                let request = result.unwrap();
                assert_eq!(request.action(), Action::Api, "{query}");
                assert!(!request.matches_configuration(&config()), "{query}");
            }
        }
        assert_eq!(
            parse("/repos/quartermaster/one/issues/%31?after=abc")
                .unwrap()
                .action(),
            Action::Api
        );
    }

    #[test]
    fn unfamiliar_queries_paths_and_resources_cannot_borrow_repository_read_authority() {
        for target in [
            "/repos/quartermaster/one/issues?state=open&state=closed",
            "/repos/quartermaster/one/issues?per_page=1&per_page=1",
            "/repos/quartermaster/one/issues?labels=bug",
            "/repos/quartermaster/one/issues?state=invalid",
            "/repos/quartermaster/one/issues?per_page=0",
            "/repos/quartermaster/one/issues?per_page=101",
            "/repos/quartermaster/one/issues?page=0",
            "/repos/quartermaster/one/issues?page=-1",
            "/repos/quartermaster/one/issues?page=1&",
            "/repos/quartermaster/one/issues/1?state=open",
            "/repos/quartermaster/one/issues/0",
            "/repos/quartermaster/one/issues/18446744073709551616",
            "/repos/quartermaster/one/issues/1/extra",
            "/repos/quartermaster/one/issues/%31",
            "/repos/quartermaster/one%2ftwo/issues/1",
            "/repos/quartermaster/../issues/1",
            "/repos/quartermaster/unknown/issues/1",
            "/repos/another/one/issues/1",
            "/api/v3/repos/quartermaster/one/issues/1",
        ] {
            let request = parse(target).unwrap();
            assert_eq!(request.action(), Action::Api, "{target}");
            assert!(!request.matches_configuration(&config()), "{target}");
        }
        assert!(parse("/repos/quartermaster/one/issues/1#fragment").is_err());
        let absolute = parse("https://api.github.com/repos/quartermaster/one/issues/1").unwrap();
        assert_eq!(absolute.action(), Action::ReadIssue);
        assert_eq!(absolute.path(), "/repos/quartermaster/one/issues/1");
    }

    #[test]
    fn github_capture_rejects_other_origins_and_ambiguous_framing() {
        for (method, host, headers, body) in [
            ("GET", "github.com", "", ""),
            ("GET", "api.github.com:80", "", ""),
            ("GET", "api.github.com.evil.invalid", "", ""),
            (
                "GET",
                "api.github.com",
                "Host: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n",
                "",
            ),
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
        ] {
            let bytes = format!(
                "{method} /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n{body}"
            );
            assert!(read_configured(&mut Cursor::new(bytes), Some(&config())).is_err());
        }
        for (method, body) in [
            ("GET", "x"),
            ("PATCH", "{\"state\":\"closed\"}"),
            ("POST", ""),
        ] {
            let input = format!(
                "{method} /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let request = read_configured(&mut Cursor::new(input), Some(&config())).unwrap();
            assert_eq!(request.action(), Action::Api);
            assert!(!request.matches_configuration(&config()));
        }
    }

    #[test]
    fn github_request_never_accepts_a_real_origin_in_simulation_mode() {
        let simulation =
            GitHubConfig::decode(br#"{"version":1,"mode":"simulation","repositories":[]}"#)
                .unwrap();
        let input = "GET /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n\r\n";
        assert!(read_configured(&mut Cursor::new(input), Some(&simulation)).is_err());
        assert!(read_configured(&mut Cursor::new(input), None).is_err());
    }
}
