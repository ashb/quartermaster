use super::github::configuration::{GitHubConfig, Mode};
use serde::{Serialize, Serializer};
use std::{
    io::{self, Read},
    num::NonZeroU64,
};

pub const SIMULATION_HOST: &str = "github.example.invalid";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    ListIssues,
    ReadIssue,
    CloseIssue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenOperation {
    operation: Operation,
    path: String,
    repository: String,
    destination: Destination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    ListIssues,
    ReadIssue(NonZeroU64),
    CloseIssue(NonZeroU64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Destination {
    Simulation,
    Github {
        repository_id: NonZeroU64,
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
            body: &'a str,
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
        }
        let (origin, repository_id, configuration_digest, resolved_path) = match &self.destination {
            Destination::Simulation => ("https://github.example.invalid", None, None, None),
            Destination::Github {
                repository_id,
                configuration_digest,
                resolved_path,
            } => (
                "https://api.github.com",
                Some(*repository_id),
                Some(*configuration_digest),
                Some(resolved_path.as_str()),
            ),
        };
        Wire {
            method: self.method(),
            path: &self.path,
            body: self.body(),
            repository: &self.repository,
            issue: self.issue_number(),
            origin,
            repository_id,
            configuration_digest,
            resolved_path,
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
        match self.operation {
            Operation::ListIssues | Operation::ReadIssue(_) => "GET",
            Operation::CloseIssue(_) => "PATCH",
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
    pub(super) fn body(&self) -> &str {
        match self.operation {
            Operation::ListIssues | Operation::ReadIssue(_) => "",
            Operation::CloseIssue(_) => "{\"state\":\"closed\"}",
        }
    }
    pub(super) fn action(&self) -> Action {
        match self.operation {
            Operation::ListIssues => Action::ListIssues,
            Operation::ReadIssue(_) => Action::ReadIssue,
            Operation::CloseIssue(_) => Action::CloseIssue,
        }
    }

    pub(super) fn repository(&self) -> &str {
        &self.repository
    }

    pub(super) fn issue_number(&self) -> Option<NonZeroU64> {
        match self.operation {
            Operation::ListIssues => None,
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
            } => Some((repository_id, configuration_digest)),
        }
    }

    pub(super) fn role(&self) -> &str {
        match self.action() {
            Action::ListIssues | Action::ReadIssue => "github-read",
            Action::CloseIssue => "github-write",
        }
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
    })
}

fn decimal(value: &str, maximum: u64) -> io::Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.starts_with('0')
    {
        return Err(io::Error::other("invalid positive integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|number| *number <= maximum)
        .ok_or_else(|| io::Error::other("integer outside supported range"))
}

fn pagination_cursor(pair: &str) -> io::Result<String> {
    let (_, value) = form_urlencoded::parse(pair.as_bytes())
        .next()
        .ok_or_else(|| io::Error::other("missing pagination cursor"))?;
    let unpadded = value.trim_end_matches('=');
    if unpadded.is_empty()
        || value.len() > 512
        || value.len() - unpadded.len() > 2
        || !unpadded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/-_".contains(&byte))
    {
        return Err(io::Error::other("invalid pagination cursor"));
    }
    Ok(form_urlencoded::byte_serialize(value.as_bytes()).collect())
}

pub(super) fn read_configured(
    stream: &mut impl Read,
    config: Option<&GitHubConfig>,
) -> io::Result<FrozenOperation> {
    let Some(config) = config.filter(|config| config.mode() == Mode::Github) else {
        return read(stream);
    };
    let request = head(stream)?;
    if request.method != "GET"
        || request.length.is_some_and(|length| length != 0)
        || !(request.host.eq_ignore_ascii_case(b"api.github.com")
            || request.host.eq_ignore_ascii_case(b"api.github.com:443"))
    {
        return Err(io::Error::other(
            "unsupported GitHub origin, method or body",
        ));
    }
    if request.target.contains(['#', '\\']) {
        return Err(io::Error::other("noncanonical target"));
    }
    let (path, query) = request
        .target
        .split_once('?')
        .map_or((request.target.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    if path.contains('%') {
        return Err(io::Error::other("encoded resource path"));
    }
    let parts = path.split('/').collect::<Vec<_>>();
    if !(parts.len() == 5 || parts.len() == 6)
        || !parts[0].is_empty()
        || parts[1] != "repos"
        || parts[4] != "issues"
    {
        return Err(io::Error::other("unsupported GitHub resource"));
    }
    let repository = config
        .repository(parts[2], parts[3])
        .ok_or_else(|| io::Error::other("repository is not configured"))?;
    let full_name = repository.full_name();
    let (issue, target) = if parts.len() == 6 {
        if query.is_some() {
            return Err(io::Error::other("issue lookup does not accept a query"));
        }
        let issue = NonZeroU64::new(decimal(parts[5], u64::MAX)?).unwrap();
        (Some(issue), format!("/repos/{full_name}/issues/{issue}"))
    } else {
        let (mut state, mut per_page, mut page) = (None, None, None);
        let mut cursor = None;
        if let Some(query) = query {
            for pair in query.split('&') {
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| io::Error::other("invalid query"))?;
                match key {
                    "state" if state.is_none() && matches!(value, "open" | "closed" | "all") => {
                        state = Some(value)
                    }
                    "per_page" if per_page.is_none() => per_page = Some(decimal(value, 100)?),
                    "page" if page.is_none() => page = Some(decimal(value, 10000)?),
                    "before" | "after" if cursor.is_none() => {
                        cursor = Some((key, pagination_cursor(pair)?))
                    }
                    _ => return Err(io::Error::other("unknown or repeated query parameter")),
                }
            }
        }
        let cursor = cursor.map_or_else(String::new, |(key, value)| format!("&{key}={value}"));
        (
            None,
            format!(
                "/repos/{full_name}/issues?state={}&per_page={}&page={}{cursor}",
                state.unwrap_or("open"),
                per_page.unwrap_or(30),
                page.unwrap_or(1)
            ),
        )
    };
    let resolved_path = format!(
        "/repositories/{}{}",
        repository.id(),
        target
            .strip_prefix(&format!("/repos/{full_name}"))
            .expect("canonical path uses the configured repository")
    );
    Ok(FrozenOperation {
        operation: issue.map_or(Operation::ListIssues, Operation::ReadIssue),
        path: target,
        repository: full_name,
        destination: Destination::Github {
            repository_id: repository.id(),
            configuration_digest: config.digest(),
            resolved_path,
        },
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
        let explicit =
            parse("/repos/quartermaster/one/issues?page=1&per_page=30&state=open").unwrap();
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
            GitHubConfig::decode(br#"{"version":1,"mode":"simulation","repositories":[]}"#)
                .unwrap();
        let input =
            "GET /repos/quartermaster/one/issues/1 HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        assert!(read_configured(&mut Cursor::new(input), Some(&simulation)).is_err());
        assert!(read_configured(&mut Cursor::new(input), None).is_err());
    }
}
