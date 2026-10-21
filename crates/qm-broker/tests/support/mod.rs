use crate::owner::request;
use std::io::Cursor;

pub(crate) mod approval;
#[cfg(unix)]
pub(crate) mod github;
pub(crate) mod vault;

pub(crate) fn policy_bytes(expires: u64, budget: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "writes": "allow",
        "grants": [{
            "id": "0123456789abcdef0123456789abcdef",
            "uid": 501,
            "codeHash": "11".repeat(20),
            "action": "readIssue",
            "repository": "quartermaster/demo",
            "role": "github-read",
            "expiresUnix": expires,
            "budget": budget
        }]
    }))
    .unwrap()
}

pub(crate) fn read_request() -> request::FrozenOperation {
    request::read(&mut Cursor::new(b"GET /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\n\r\n")).unwrap()
}

pub(crate) fn close_request() -> request::FrozenOperation {
    request::read(&mut Cursor::new(b"PATCH /api/v3/repos/quartermaster/demo/issues/42 HTTP/1.1\r\nHost: github.example.invalid\r\nContent-Length: 18\r\n\r\n{\"state\":\"closed\"}")).unwrap()
}

pub(crate) fn wall(seconds: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(seconds).unwrap()
}

pub(crate) fn principal(session: [u8; 16]) -> crate::owner::identity::VerifiedPrincipal {
    crate::owner::identity::VerifiedPrincipal::fixture(501, "11".repeat(20), session)
}
