use std::fmt;

#[derive(Clone, Copy, Debug)]
pub struct RequestLimits {
    pub request_bytes: usize,
    pub header_bytes: usize,
    pub headers: usize,
    pub body_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            request_bytes: 262144,
            header_bytes: 32768,
            headers: 64,
            body_bytes: 131072,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("request exceeds capture limits")]
    Limit,
    #[error("incomplete HTTP request")]
    Incomplete,
    #[error("invalid HTTP request")]
    Invalid,
    #[error("unsupported or ambiguous HTTP framing")]
    Framing,
    #[error("invalid or inconsistent HTTP authority")]
    Authority,
}

#[derive(Clone)]
pub struct Header {
    name: String,
    value: Vec<u8>,
}

impl Header {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

pub struct CapturedRequest {
    original: Box<[u8]>,
    method: String,
    target: String,
    authority: String,
    path_and_query: String,
    headers: Vec<Header>,
    body_offset: usize,
}

impl fmt::Debug for CapturedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedRequest")
            .field("bytes", &self.original.len())
            .finish_non_exhaustive()
    }
}

impl CapturedRequest {
    pub(crate) fn has_json_grammar(&self) -> bool {
        !self
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("content-encoding"))
            && self.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("content-type")
                    && std::str::from_utf8(&header.value).is_ok_and(|value| {
                        matches!(
                            value.to_ascii_lowercase().as_str(),
                            "application/json" | "application/json; charset=utf-8"
                        )
                    })
            })
    }
    pub fn parse(bytes: &[u8], limits: RequestLimits) -> Result<Self, RequestError> {
        if bytes.len() > limits.request_bytes || limits.headers == 0 {
            return Err(RequestError::Limit);
        }
        let head_end = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .map(|at| at + 4)
            .ok_or({
                if bytes.len() >= limits.header_bytes {
                    RequestError::Limit
                } else {
                    RequestError::Incomplete
                }
            })?;
        if head_end > limits.header_bytes {
            return Err(RequestError::Limit);
        }
        let head = &bytes[..head_end];
        if head.starts_with(b"\r\n")
            || head.iter().enumerate().any(|(at, byte)| {
                (*byte == b'\n' && (at == 0 || head[at - 1] != b'\r'))
                    || (*byte == b'\r' && head.get(at + 1) != Some(&b'\n'))
            })
        {
            return Err(RequestError::Invalid);
        }
        let mut fields = vec![httparse::EMPTY_HEADER; limits.headers.min(head.len() / 4 + 1)];
        let mut parsed = httparse::Request::new(&mut fields);
        let consumed = match parsed.parse(head) {
            Ok(httparse::Status::Complete(consumed)) => consumed,
            Ok(httparse::Status::Partial) => return Err(RequestError::Incomplete),
            Err(httparse::Error::TooManyHeaders) => return Err(RequestError::Limit),
            Err(_) => return Err(RequestError::Invalid),
        };
        if consumed != head_end || parsed.version != Some(1) {
            return Err(RequestError::Invalid);
        }
        let method = parsed.method.ok_or(RequestError::Invalid)?;
        if method == "CONNECT" {
            return Err(RequestError::Framing);
        }
        let target = parsed.path.ok_or(RequestError::Invalid)?;
        validate_target(target)?;
        let mut host = None;
        let mut length = None;
        let mut authorization = false;
        for field in parsed.headers.iter() {
            match field.name.to_ascii_lowercase().as_str() {
                "host" => {
                    if host.is_some() {
                        return Err(RequestError::Authority);
                    }
                    let value =
                        std::str::from_utf8(field.value).map_err(|_| RequestError::Authority)?;
                    let authority: http::uri::Authority =
                        value.parse().map_err(|_| RequestError::Authority)?;
                    if authority.host().is_empty() || value.contains('@') {
                        return Err(RequestError::Authority);
                    }
                    host = Some(value);
                }
                "authorization" => {
                    if std::mem::replace(&mut authorization, true) {
                        return Err(RequestError::Framing);
                    }
                }
                "content-length" => {
                    if length.is_some()
                        || field.value.is_empty()
                        || !field.value.iter().all(u8::is_ascii_digit)
                    {
                        return Err(RequestError::Framing);
                    }
                    length = Some(
                        std::str::from_utf8(field.value)
                            .map_err(|_| RequestError::Framing)?
                            .parse::<usize>()
                            .map_err(|_| RequestError::Limit)?,
                    );
                }
                "transfer-encoding" | "trailer" | "upgrade" | "proxy-authorization" | "expect" => {
                    return Err(RequestError::Framing);
                }
                "connection" => {
                    let value =
                        std::str::from_utf8(field.value).map_err(|_| RequestError::Framing)?;
                    if value.split(',').any(|option| {
                        !matches!(
                            option.trim().to_ascii_lowercase().as_str(),
                            "close" | "keep-alive"
                        )
                    }) {
                        return Err(RequestError::Framing);
                    }
                }
                _ => {}
            }
        }
        let authority = host.ok_or(RequestError::Authority)?;
        let path_and_query = if target.starts_with('/') {
            target.to_owned()
        } else {
            let uri: http::Uri = target.parse().map_err(|_| RequestError::Invalid)?;
            if uri.scheme_str() != Some("https")
                || uri
                    .authority()
                    .is_none_or(|host| !host.as_str().eq_ignore_ascii_case(authority))
            {
                return Err(RequestError::Authority);
            }
            uri.path_and_query()
                .ok_or(RequestError::Invalid)?
                .as_str()
                .to_owned()
        };
        let body_len = length.unwrap_or(0);
        if body_len > limits.body_bytes {
            return Err(RequestError::Limit);
        }
        match bytes.len().saturating_sub(head_end).cmp(&body_len) {
            std::cmp::Ordering::Less => return Err(RequestError::Incomplete),
            std::cmp::Ordering::Greater => return Err(RequestError::Framing),
            std::cmp::Ordering::Equal => {}
        }
        Ok(Self {
            original: bytes.into(),
            method: method.into(),
            target: target.into(),
            authority: authority.into(),
            path_and_query,
            headers: parsed
                .headers
                .iter()
                .map(|header| Header {
                    name: header.name.into(),
                    value: header.value.into(),
                })
                .collect(),
            body_offset: head_end,
        })
    }

    pub fn original(&self) -> &[u8] {
        &self.original
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }
    pub fn body(&self) -> &[u8] {
        &self.original[self.body_offset..]
    }
}

fn validate_target(target: &str) -> Result<(), RequestError> {
    let bytes = target.as_bytes();
    for (at, byte) in bytes.iter().enumerate() {
        if !byte.is_ascii() || byte.is_ascii_control() || matches!(byte, b' ' | b'#' | b'\\') {
            return Err(RequestError::Invalid);
        }
        if *byte == b'%'
            && (bytes
                .get(at + 1)
                .is_none_or(|part| !part.is_ascii_hexdigit())
                || bytes
                    .get(at + 2)
                    .is_none_or(|part| !part.is_ascii_hexdigit()))
        {
            return Err(RequestError::Invalid);
        }
    }
    if !target.starts_with('/') && !target.starts_with("https://") {
        return Err(RequestError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Result<CapturedRequest, RequestError> {
        CapturedRequest::parse(bytes, RequestLimits::default())
    }

    #[test]
    fn capture_retains_unknown_application_data_and_repeated_headers_byte_for_byte() {
        let raw = b"POST /new-api?x=1&x=2 HTTP/1.1\r\nHost: api.github.com\r\nX-New: one\r\nx-new: two\r\nContent-Length: 16\r\n\r\n{\"x\":1,\"x\":true}";
        let request = parse(raw).unwrap();
        assert_eq!(request.original(), raw);
        assert_eq!(request.body(), b"{\"x\":1,\"x\":true}");
        assert_eq!(request.headers()[1].name(), "X-New");
        assert_eq!(request.headers()[2].value(), b"two");
    }

    #[test]
    fn absolute_target_keeps_path_and_query_octets() {
        let raw = b"GET https://api.github.com/repos/a%2fb/r?q=%2F HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let request = parse(raw).unwrap();
        assert_eq!(request.path_and_query(), "/repos/a%2fb/r?q=%2F");
        assert_eq!(request.original(), raw);
    }

    #[test]
    fn ambiguous_framing_and_authorities_are_rejected_before_application_inspection() {
        for raw in [
            "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
            "GET https://b/ HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nAuthorization: a\r\nAuthorization: b\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nx",
            "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: X-App\r\nX-App: a\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n",
            "CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /other HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse(raw.as_bytes()).is_err(), "{raw}");
        }
    }

    #[test]
    fn limits_and_incomplete_bodies_do_not_become_unknown_requests() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(
            CapturedRequest::parse(
                raw,
                RequestLimits {
                    request_bytes: 1,
                    ..RequestLimits::default()
                }
            )
            .unwrap_err(),
            RequestError::Limit
        );
        assert_eq!(
            parse(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nx").unwrap_err(),
            RequestError::Incomplete
        );
    }
}
