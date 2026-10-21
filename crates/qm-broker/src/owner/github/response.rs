#![forbid(unsafe_code)]

use super::repository::RepositoryBinding;
use crate::owner::request::{Action, FrozenOperation};
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::{
    fmt,
    io::{self, Read, Write},
    num::NonZeroU64,
};
use zeroize::Zeroizing;

const BODY_LIMIT: usize = 2 * 1024 * 1024;
const HEADER_LIMIT: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::owner) struct Error;

pub(super) struct WireResponse {
    status: u16,
    headers: Vec<(String, Zeroizing<String>)>,
    body: Zeroizing<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::owner) struct PublicResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Debug)]
pub(in crate::owner) enum MetadataFailure {
    Invalid,
    Public(PublicResponse),
}

pub(super) enum Outcome {
    Response(PublicResponse),
    Redirect(FrozenOperation),
}

fn checked_target(
    binding: &RepositoryBinding,
    request: &FrozenOperation,
    url: &str,
    credential: &[u8],
) -> Result<FrozenOperation, Error> {
    let echoes = |value: &str| {
        !credential.is_empty()
            && value
                .as_bytes()
                .windows(credential.len())
                .any(|window| window == credential)
    };
    if echoes(url) {
        return Err(Error);
    }
    if let Some((_, query)) = url.split_once('?') {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            let key = Zeroizing::new(key.into_owned());
            let value = Zeroizing::new(value.into_owned());
            if echoes(&key) || echoes(&value) {
                return Err(Error);
            }
        }
    }
    let target = binding.redirect(request, url).map_err(|_| Error)?;
    if echoes(target.path()) {
        return Err(Error);
    }
    Ok(target)
}

fn line(stream: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    while bytes.len() < limit {
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(|_| Error)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n") {
            let length = bytes.len() - 2;
            bytes.truncate(length);
            return Ok(bytes);
        }
    }
    Err(Error)
}

pub(super) fn read(stream: &mut impl Read) -> Result<WireResponse, Error> {
    let mut head = Zeroizing::new(Vec::new());
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEADER_LIMIT {
            return Err(Error);
        }
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(|_| Error)?;
        head.push(byte[0]);
    }
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    if !parsed.parse(&head).map_err(|_| Error)?.is_complete() || parsed.version != Some(1) {
        return Err(Error);
    }
    let status = parsed
        .code
        .filter(|status| (200..=599).contains(status))
        .ok_or(Error)?;
    let mut length = None;
    let mut chunked = false;
    let mut encoding = false;
    let mut retained = Vec::new();
    for header in parsed.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || header.value.is_empty()
                || !header.value.iter().all(u8::is_ascii_digit)
            {
                return Err(Error);
            }
            let count = std::str::from_utf8(header.value)
                .map_err(|_| Error)?
                .parse::<usize>()
                .map_err(|_| Error)?;
            if count > BODY_LIMIT {
                return Err(Error);
            }
            length = Some(count);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                return Err(Error);
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("content-encoding") {
            if encoding || !header.value.eq_ignore_ascii_case(b"identity") {
                return Err(Error);
            }
            encoding = true;
        } else if matches!(
            header.name.to_ascii_lowercase().as_str(),
            "content-type"
                | "link"
                | "location"
                | "retry-after"
                | "x-ratelimit-limit"
                | "x-ratelimit-remaining"
                | "x-ratelimit-used"
                | "x-ratelimit-reset"
                | "x-ratelimit-resource"
        ) {
            let value = std::str::from_utf8(header.value).map_err(|_| Error)?;
            if !value.bytes().all(|byte| (32..=126).contains(&byte))
                || value.len() > 4096
                || retained
                    .iter()
                    .any(|(name, _): &(String, Zeroizing<String>)| {
                        name.eq_ignore_ascii_case(header.name)
                    })
            {
                return Err(Error);
            }
            retained.push((header.name.to_owned(), Zeroizing::new(value.to_owned())));
        }
    }
    if chunked == length.is_some() {
        return Err(Error);
    }
    let mut body = Zeroizing::new(Vec::new());
    if let Some(count) = length {
        body.resize(count, 0);
        stream.read_exact(&mut body).map_err(|_| Error)?;
    } else {
        loop {
            let size = line(stream, 1024)?;
            if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error);
            }
            let count = usize::from_str_radix(std::str::from_utf8(&size).map_err(|_| Error)?, 16)
                .map_err(|_| Error)?;
            if count == 0 {
                if !line(stream, 2)?.is_empty() {
                    return Err(Error);
                }
                break;
            }
            let end = body
                .len()
                .checked_add(count)
                .filter(|end| *end <= BODY_LIMIT)
                .ok_or(Error)?;
            let start = body.len();
            body.resize(end, 0);
            stream.read_exact(&mut body[start..]).map_err(|_| Error)?;
            if !line(stream, 2)?.is_empty() {
                return Err(Error);
            }
        }
    }
    Ok(WireResponse {
        status,
        headers: retained,
        body,
    })
}

impl WireResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self, credential: &[u8]) -> Result<(), Error> {
        if !credential.is_empty()
            && self
                .body
                .windows(credential.len())
                .any(|window| window == credential)
        {
            return Err(Error);
        }
        let content_type = self
            .header("content-type")
            .ok_or(Error)?
            .split(';')
            .next()
            .ok_or(Error)?
            .trim();
        if !content_type.eq_ignore_ascii_case("application/json")
            && !content_type.eq_ignore_ascii_case("application/vnd.github+json")
        {
            return Err(Error);
        }
        let mut decoder = serde_json::Deserializer::from_slice(&self.body);
        SecretGuard(credential)
            .deserialize(&mut decoder)
            .map_err(|_| Error)?;
        decoder.end().map_err(|_| Error)
    }

    fn safe_headers(&self, credential: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut safe = Vec::new();
        for (name, value) in &self.headers {
            let key = name.to_ascii_lowercase();
            if key == "retry-after" || key.starts_with("x-ratelimit-") {
                if !credential.is_empty()
                    && value
                        .as_bytes()
                        .windows(credential.len())
                        .any(|window| window == credential)
                {
                    return Err(Error);
                }
                if key == "x-ratelimit-resource" {
                    if value.is_empty()
                        || value.len() > 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    {
                        return Err(Error);
                    }
                } else if value.is_empty()
                    || value.len() > 20
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value.parse::<u64>().is_err()
                {
                    return Err(Error);
                }
                safe.push((name.clone(), value.to_string()));
            }
        }
        Ok(safe)
    }

    fn error_response(&self, credential: &[u8]) -> Result<PublicResponse, Error> {
        let (status, message) = match self.status {
            401 => (401, "GitHub rejected the configured credential"),
            403 => (403, "GitHub denied this operation"),
            404 => (404, "GitHub did not find this resource"),
            429 => (429, "GitHub rate limit exceeded"),
            _ => (502, "GitHub response could not be confirmed"),
        };
        Ok(PublicResponse {
            status,
            headers: self.safe_headers(credential)?,
            body: serde_json::json!({"message":message}).to_string(),
        })
    }

    pub(super) fn metadata_bytes(&self, credential: &[u8]) -> Result<&[u8], MetadataFailure> {
        if self.status != 200 {
            if (300..400).contains(&self.status) {
                return Err(MetadataFailure::Invalid);
            }
            return Err(MetadataFailure::Public(
                self.error_response(credential)
                    .map_err(|_| MetadataFailure::Invalid)?,
            ));
        }
        self.json(credential)
            .map_err(|_| MetadataFailure::Invalid)?;
        Ok(&self.body)
    }

    pub(super) fn issues(
        self,
        request: &FrozenOperation,
        binding: &RepositoryBinding,
        credential: &[u8],
    ) -> Result<Outcome, Error> {
        let mut safe = self.safe_headers(credential)?;
        if matches!(self.status, 301 | 302 | 303 | 307 | 308) {
            if request.action() == Action::CloseIssue {
                return Err(Error);
            }
            return Ok(Outcome::Redirect(checked_target(
                binding,
                request,
                self.header("location").ok_or(Error)?,
                credential,
            )?));
        }
        if self.status != 200 {
            return Ok(Outcome::Response(self.error_response(credential)?));
        }
        self.json(credential)?;
        #[derive(Deserialize)]
        struct Issue {
            number: NonZeroU64,
            state: String,
            url: String,
            repository_url: String,
        }
        let issues: Vec<Issue> = if request.action() == Action::ListIssues {
            serde_json::from_slice(&self.body).map_err(|_| Error)?
        } else {
            vec![serde_json::from_slice(&self.body).map_err(|_| Error)?]
        };
        let repository_url = format!("https://api.github.com/repos/{}", request.repository());
        for issue in issues {
            if issue.repository_url != repository_url
                || issue.url != format!("{repository_url}/issues/{}", issue.number)
                || !matches!(issue.state.as_str(), "open" | "closed")
                || request
                    .issue_number()
                    .is_some_and(|number| number != issue.number)
                || (request.action() == Action::CloseIssue && issue.state != "closed")
            {
                return Err(Error);
            }
        }
        if let Some(link) = self.header("link") {
            let mut links = Vec::new();
            let mut relations = Vec::new();
            for item in link.split(',') {
                let (url, relation) = item.trim().split_once(">; rel=\"").ok_or(Error)?;
                let url = url.strip_prefix('<').ok_or(Error)?;
                let relation = relation
                    .strip_suffix('"')
                    .filter(|value| matches!(*value, "next" | "prev" | "first" | "last"))
                    .ok_or(Error)?;
                if relations.contains(&relation) || links.len() >= 4 {
                    return Err(Error);
                }
                relations.push(relation);
                let target = checked_target(binding, request, url, credential)?;
                if target.action() != Action::ListIssues {
                    return Err(Error);
                }
                links.push(format!(
                    "<https://api.github.com{}>; rel=\"{relation}\"",
                    target.path()
                ));
            }
            safe.push(("Link".to_owned(), links.join(", ")));
        }
        Ok(Outcome::Response(PublicResponse {
            status: 200,
            headers: safe,
            body: String::from_utf8(self.body.to_vec()).map_err(|_| Error)?,
        }))
    }
}

impl PublicResponse {
    pub(in crate::owner) fn public_parts(&self) -> (&str, &str) {
        let status = match self.status {
            200 => "200 OK",
            401 => "401 Unauthorized",
            403 => "403 Forbidden",
            404 => "404 Not Found",
            429 => "429 Too Many Requests",
            _ => "502 Bad Gateway",
        };
        (status, &self.body)
    }
    pub(in crate::owner) fn write(&self, stream: &mut impl Write) -> io::Result<()> {
        let (status, _) = self.public_parts();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.body.len()
        )?;
        for (name, value) in &self.headers {
            write!(stream, "{name}: {value}\r\n")?;
        }
        write!(stream, "\r\n{}", self.body)
    }
}

#[derive(Clone, Copy)]
struct SecretGuard<'a>(&'a [u8]);

impl<'de> DeserializeSeed<'de> for SecretGuard<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for SecretGuard<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential-free JSON")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        if !self.0.is_empty()
            && value
                .as_bytes()
                .windows(self.0.len())
                .any(|window| window == self.0)
        {
            return Err(E::custom("credential echo rejected"));
        }
        Ok(())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        while access.next_element_seed(self)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
        while access.next_key_seed(self)?.is_some() {
            access.next_value_seed(self)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
        let Outcome::Response(response) = upstream.issues(&request, &binding, TOKEN).unwrap()
        else {
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
                let target =
                    format!("https://api.github.com/repositories/123/issues?after={cursor}");
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
    fn github_response_rejects_wrong_issue_identity_invalid_json_and_ambiguous_or_oversized_framing()
     {
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
    fn github_response_metadata_authentication_failures_return_fixed_status_and_safe_rate_metadata()
    {
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
}
