use super::*;
use std::net::SocketAddr;

#[test]
fn oversized_event_to_line_returns_error() {
    let mut event = Event::new("test", "big");
    event.summary = "x".repeat(1 << 20);
    let error = event.to_line().unwrap_err();
    assert_eq!(
        error.kind,
        crate::stdlib::protocols::json::ErrorKind::TooLarge
    );
}

#[test]
fn direct_event_construction_bounds_text_and_nested_values() {
    let mut nested = crate::stdlib::protocols::json::Value::Null;
    for _ in 0..100 {
        nested = crate::stdlib::protocols::json::Value::Array(vec![nested]);
    }
    let text = "é".repeat(1 << 20);
    let event = Event::new("test", "bounded")
        .summary(&text)
        .field("borrowed", text.as_str())
        .field("owned", text.clone())
        .field("nested", nested);
    assert!(event.is_truncated());
    assert!(event.size() < 20 * 1024);
    for value in [
        &event.summary,
        event.str("borrowed").unwrap(),
        event.str("owned").unwrap(),
    ] {
        assert!(value.len() <= 4096);
        assert!(value.ends_with("[truncated]"));
    }
    assert!(event.to_line().unwrap().contains("[truncated]"));
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
