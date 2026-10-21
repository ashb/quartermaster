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
