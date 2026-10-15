use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Fetches one proxy response, requiring EOF, the expected status and exact framing.
/// Returns the body. I/O errors and invalid responses panic before a timing is used.
pub fn fetch(addr: SocketAddr, host: &str, auth: &str, expected_status: u16) -> Vec<u8> {
    let mut s = TcpStream::connect(addr)
        .unwrap_or_else(|error| panic!("connect to proxy for {host}: {error}"));
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(s, "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {auth}\r\nConnection: close\r\n\r\n")
        .unwrap_or_else(|error| panic!("write proxy request for {host}: {error}"));
    let mut out = Vec::new();
    s.read_to_end(&mut out)
        .unwrap_or_else(|error| panic!("read proxy response for {host}: {error}"));
    response_body(&out, expected_status).to_vec()
}

// These workloads use one Content-Length response. Reject other framing, including
// duplicate lengths, rather than guessing where a successful transfer ends.
fn response_body(bytes: &[u8], expected_status: u16) -> &[u8] {
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete HTTP response head");
    let head = std::str::from_utf8(&bytes[..end]).expect("HTTP response head text");
    let body = &bytes[end + 4..];
    let mut lines = head.split("\r\n");
    let mut status = lines.next().unwrap().splitn(3, ' ');
    assert_eq!(status.next(), Some("HTTP/1.1"), "HTTP version");
    assert_eq!(
        status.next().expect("HTTP status code"),
        expected_status.to_string(),
        "HTTP status"
    );
    let reason = status.next().expect("HTTP status reason");
    assert!(
        reason.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
        "HTTP status reason"
    );
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').expect("HTTP header");
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "HTTP header name"
        );
        assert!(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "HTTP header value"
        );
        assert!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "proxy benchmark requires Content-Length framing"
        );
        if name.eq_ignore_ascii_case("content-length") {
            assert!(length.is_none(), "duplicate Content-Length");
            let value = value.trim_matches([' ', '\t']);
            assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid Content-Length"
            );
            length = Some(value.parse::<usize>().expect("Content-Length in range"));
        }
    }
    assert_eq!(
        body.len(),
        length.expect("missing Content-Length"),
        "HTTP body length"
    );
    body
}
