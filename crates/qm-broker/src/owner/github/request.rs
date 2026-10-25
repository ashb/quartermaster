#![forbid(unsafe_code)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use qm_api_github::{Analysis, CapturedRequest, EffectKind, PatternSet, RequestLimits};
use ring::digest::{SHA256, digest};
use serde::{Serialize, Serializer};
use std::io::{self, Read};
use zeroize::Zeroizing;

pub(in crate::owner) const REVIEW_VERSION: &str = "quartermaster.github-request.v1";

#[derive(Debug)]
pub(in crate::owner) struct Application {
    capture: CapturedRequest,
    analysis: Analysis,
}

impl PartialEq for Application {
    fn eq(&self, other: &Self) -> bool {
        self.capture.original() == other.capture.original()
    }
}
impl Eq for Application {}

impl Application {
    pub(in crate::owner) fn read(
        stream: &mut impl Read,
        patterns: &PatternSet,
    ) -> io::Result<Self> {
        let limits = RequestLimits::default();
        let mut bytes = Zeroizing::new(Vec::new());
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() >= limits.header_bytes {
                return Err(io::Error::other("request header limit exceeded"));
            }
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            bytes.push(byte[0]);
        }
        let mut headers = vec![httparse::EMPTY_HEADER; limits.headers];
        let mut head = httparse::Request::new(&mut headers);
        if !head.parse(&bytes).map_err(io::Error::other)?.is_complete() {
            return Err(io::Error::other("incomplete request head"));
        }
        let mut length = None;
        for header in head.headers.iter() {
            if matches!(
                header.name.to_ascii_lowercase().as_str(),
                "transfer-encoding" | "trailer" | "upgrade" | "proxy-authorization" | "expect"
            ) {
                return Err(io::Error::other("unsupported request framing"));
            }
            if header.name.eq_ignore_ascii_case("content-length") {
                if length.is_some()
                    || header.value.is_empty()
                    || !header.value.iter().all(u8::is_ascii_digit)
                {
                    return Err(io::Error::other("ambiguous request framing"));
                }
                length = Some(
                    std::str::from_utf8(header.value)
                        .map_err(io::Error::other)?
                        .parse::<usize>()
                        .map_err(io::Error::other)?,
                );
            }
        }
        let count = length.unwrap_or(0);
        if count > limits.body_bytes
            || bytes
                .len()
                .checked_add(count)
                .is_none_or(|size| size > limits.request_bytes)
        {
            return Err(io::Error::other("request body limit exceeded"));
        }
        let start = bytes.len();
        bytes.resize(start + count, 0);
        stream.read_exact(&mut bytes[start..])?;
        let capture = CapturedRequest::parse(&bytes, limits).map_err(io::Error::other)?;
        if !matches!(
            capture.authority().to_ascii_lowercase().as_str(),
            "api.github.com" | "api.github.com:443"
        ) {
            return Err(io::Error::other("GitHub destination is not permitted"));
        }
        let analysis = qm_api_github::analyze(&capture, patterns).map_err(io::Error::other)?;
        Ok(Self { capture, analysis })
    }

    pub(in crate::owner) fn capture(&self) -> &CapturedRequest {
        &self.capture
    }
    pub(in crate::owner) fn analysis(&self) -> &Analysis {
        &self.analysis
    }

    pub(in crate::owner) fn has_mutation(&self) -> bool {
        self.analysis.effects.iter().any(|effect| {
            !matches!(
                effect.kind,
                EffectKind::ReadRepository | EffectKind::ListIssues | EffectKind::ReadIssue
            )
        }) || self
            .analysis
            .graphql_roots
            .iter()
            .any(|(kind, _)| *kind == qm_api_github::GraphqlOperation::Mutation)
    }

    pub(in crate::owner) fn wire(&self, credential: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut output = Zeroizing::new(
            format!(
                "{} {} HTTP/1.1\r\n",
                self.capture.method(),
                self.capture.path_and_query()
            )
            .into_bytes(),
        );
        let head_end = self.capture.original().len() - self.capture.body().len();
        let head = &self.capture.original()[..head_end - 4];
        let mut authorization = false;
        let mut framed = !self.capture.body().is_empty();
        for line in head.split(|byte| *byte == b'\n').skip(1) {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .expect("captured header has a colon");
            let name = &line[..colon];
            if name.eq_ignore_ascii_case(b"authorization") {
                output.extend_from_slice(b"Authorization: Bearer ");
                output.extend_from_slice(credential);
                output.extend_from_slice(b"\r\n");
                authorization = true;
            } else if name.eq_ignore_ascii_case(b"content-length") {
                framed = true;
            } else if !name.eq_ignore_ascii_case(b"connection")
                && !name.eq_ignore_ascii_case(b"keep-alive")
            {
                output.extend_from_slice(line);
                output.extend_from_slice(b"\r\n");
            }
        }
        if !authorization {
            output.extend_from_slice(b"Authorization: Bearer ");
            output.extend_from_slice(credential);
            output.extend_from_slice(b"\r\n");
        }
        if framed {
            output.extend_from_slice(
                format!("Content-Length: {}\r\n", self.capture.body().len()).as_bytes(),
            );
        }
        output.extend_from_slice(b"Connection: close\r\n\r\n");
        output.extend_from_slice(self.capture.body());
        output
    }
}

impl Serialize for Application {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Review {
            version: &'static str,
            request: String,
            original_digest: String,
            complete: bool,
            effects: Vec<&'static str>,
        }
        let effects = self
            .analysis
            .effects
            .iter()
            .map(|effect| match effect.kind {
                EffectKind::ReadRepository => "Read repository",
                EffectKind::ListIssues => "List issues",
                EffectKind::ReadIssue => "Read issue",
                EffectKind::CloseIssue => "Close issue",
                EffectKind::DeleteIssue => "Delete issue",
                EffectKind::DeleteRepository => "Delete repository",
            })
            .collect();
        Review {
            version: REVIEW_VERSION,
            request: BASE64.encode(self.wire(b"<selected Quartermaster credential>")),
            original_digest: BASE64.encode(digest(&SHA256, self.capture.original())),
            complete: self.analysis.complete(),
            effects,
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_review_matches_the_swift_decoder_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../macos/Security/Tests/QuartermasterSecurityTests/Fixtures/github-request-review.json"
        ))).unwrap();
        let input = BASE64
            .decode(fixture["clientRequest"].as_str().unwrap())
            .unwrap();
        let application =
            Application::read(&mut Cursor::new(input), &PatternSet::default()).unwrap();
        assert_eq!(
            serde_json::to_value(application).unwrap(),
            fixture["application"]
        );
    }

    #[test]
    fn forwarding_preserves_application_bytes_and_changes_only_auth_and_framing() {
        let body = b"{ \"query\" : \"query { viewer { login } }\", \"variables\": {} }";
        let mut bytes = format!(
            "POST https://api.github.com/graphql?x=%2f&x=2 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nX-Custom:\tfirst \t\r\nx-custom: second\r\nAuthorization: caller-sentinel\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\nKeep-Alive: timeout=3\r\n\r\n", body.len()
        ).into_bytes();
        bytes.extend_from_slice(body);
        let application =
            Application::read(&mut Cursor::new(&bytes), &PatternSet::default()).unwrap();
        let mut expected = format!(
            "POST /graphql?x=%2f&x=2 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nX-Custom:\tfirst \t\r\nx-custom: second\r\nAuthorization: Bearer selected-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
        ).into_bytes();
        expected.extend_from_slice(body);
        assert_eq!(&*application.wire(b"selected-token"), &expected);
        assert_eq!(application.capture().original(), bytes);
        let review = serde_json::to_value(&application).unwrap();
        assert_eq!(
            BASE64.decode(review["request"].as_str().unwrap()).unwrap(),
            application
                .wire(b"<selected Quartermaster credential>")
                .as_slice()
        );
        assert!(
            !serde_json::to_string(&review)
                .unwrap()
                .contains("caller-sentinel")
        );
        assert!(!application.analysis().complete());
    }

    #[test]
    fn binary_bodies_are_preserved_in_forwarding_and_complete_review() {
        let bytes = b"POST /new HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Length: 4\r\n\r\n\x00\xff\r\n";
        let application =
            Application::read(&mut Cursor::new(bytes), &PatternSet::default()).unwrap();
        let wire = application.wire(b"token");
        assert!(wire.ends_with(b"\x00\xff\r\n"));
        let review = serde_json::to_value(&application).unwrap();
        assert_eq!(
            BASE64.decode(review["request"].as_str().unwrap()).unwrap(),
            application
                .wire(b"<selected Quartermaster credential>")
                .as_slice()
        );
    }

    #[test]
    fn capture_keeps_known_mutation_observations_with_unfamiliar_companions() {
        let body = r#"{"state":"closed","futureOption":true}"#;
        let application = Application::read(&mut Cursor::new(format!(
            "PATCH /repos/a/b/issues/1 HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()
        )), &PatternSet::default()).unwrap();
        assert!(application.has_mutation());
        assert!(!application.analysis().complete());
    }
}
