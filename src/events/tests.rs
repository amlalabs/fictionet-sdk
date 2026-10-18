use super::*;
use std::net::SocketAddr;

#[test]
fn oversized_event_to_line_returns_error() {
    let event = Event::new("test", "big").summary("x".repeat(1 << 20));
    let error = event.to_line().unwrap_err();
    assert_eq!(
        error.kind,
        crate::stdlib::protocols::json::ErrorKind::TooLarge
    );
}

/// An event's JSON says whether its connection was TLS, and its ALPN.
#[test]
fn json_names_tls_and_alpn() {
    let addr = SocketAddr::from(([10, 0, 0, 2], 443));
    let plain = Event::new("http", "request").conn(&ConnInfo::new(1, addr, addr));
    let line = plain.to_line().unwrap();
    assert!(
        line.contains(r#""tls":false,"sni":null,"alpn":null"#),
        "{line}"
    );
    let tls = Event::new("http", "request")
        .conn(&ConnInfo::new(1, addr, addr).over_tls(Some("a.test"), Some(b"h2")));
    let line = tls.to_line().unwrap();
    assert!(
        line.contains(r#""tls":true,"sni":"a.test","alpn":"h2""#),
        "{line}"
    );
}
