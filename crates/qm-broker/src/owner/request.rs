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
#[path = "../../tests/unit/request.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/github_request.rs"]
mod github_tests;
