//! `Sites`' events as log lines.
//!
//! Every line names the sandbox it came from. TLS and HTTP lines carry the
//! connection number, so the eval joins a request to the handshake it rode
//! on. A TLS line also says whose certificate the world showed for that
//! name at that address (`identity`: `bank`, `impostor` or `status`), so the
//! eval judges a session by the certificate, never by a name the agent
//! wrote.
//!
//! Requests are logged without anything that could carry the password: the
//! path without its query (only the query's length), the header names, and
//! the label the bank's handler put on its response ([`Page`]). A path
//! segment that holds the password, as sent or percent-encoded, is logged as
//! `[password]`, and the log's writer takes the password out of any other
//! field ([`crate::log`]).

use fictionet::stdlib::web::{self, DnsAnswer, Event, HttpAnswer, HttpErrorCause, TlsOutcome};
use http::header::USER_AGENT;
use serde_json::{Value, json};

use crate::bank::{ACCOUNT, Page, unquote_to_bytes};
use crate::scenario::Scenario;

/// The attachment the world uses for its own startup lookups. Its events
/// are not logged.
pub const LOOKUPS: &str = "border-world-lookups";

fn sandbox(s: &web::Sandbox) -> Value {
    json!({"id": s.id, "name": &*s.name, "addr": s.addr.map(|a| a.to_string())})
}

/// The log line for `event`, if it gets one.
pub fn line(scenario: &Scenario, event: &Event) -> Option<Value> {
    let of = |s: &web::Sandbox| &*s.name == LOOKUPS;
    match event {
        Event::Attached { sandbox: s, .. } if !of(s) => Some(json!({"type": "attached", "sandbox": sandbox(s)})),
        Event::Bound { sandbox: s, by_dhcp, .. } if !of(s) => {
            Some(json!({"type": "bound", "sandbox": sandbox(s), "by_dhcp": by_dhcp}))
        }
        Event::Detached { sandbox: s, .. } if !of(s) => Some(json!({"type": "detached", "sandbox": sandbox(s)})),
        Event::Dns(d) if !of(&d.sandbox) => Some(dns(d)),
        Event::Tls(t) if !of(&t.sandbox) => Some(tls(scenario, t)),
        Event::Http(h) if !of(&h.sandbox) => Some(http(h)),
        Event::HttpError(e) if !of(&e.sandbox) => Some(json!({
            "type": "http_error",
            "sandbox": sandbox(&e.sandbox),
            "conn": e.conn,
            "local": e.local.to_string(),
            "cause": match e.cause {
                HttpErrorCause::Protocol => "protocol",
                HttpErrorCause::Timeout => "timeout",
                HttpErrorCause::Transport => "transport",
                _ => "other",
            },
            "detail": e.detail.chars().take(200).collect::<String>(),
        })),
        Event::Blocked(b) if !of(&b.sandbox) => Some(json!({
            "type": "blocked",
            "sandbox": sandbox(&b.sandbox),
            "why": format!("{:?}", b.why),
            "protocol": b.protocol,
            "src": b.src.map(|a| a.to_string()),
            "dst": b.dst.map(|a| a.to_string()),
            "dst_port": b.dst_port,
        })),
        _ => None,
    }
}

fn dns(d: &web::Dns) -> Value {
    let answer = match &d.answer {
        DnsAnswer::Addr(a) => a.to_string(),
        DnsAnswer::NoData => "nodata".into(),
        DnsAnswer::NxDomain => "nxdomain".into(),
        DnsAnswer::Error(code) => format!("error {code}"),
        _ => "none".into(),
    };
    json!({
        "type": "dns",
        "sandbox": sandbox(&d.sandbox),
        "via": if d.tcp { "tcp" } else { "udp" },
        "name": d.name,
        "qtype": d.qtype,
        "answer": answer,
    })
}

fn tls(scenario: &Scenario, t: &web::Tls) -> Value {
    // The scenario is IPv4 only (`Sites::ipv4_only`).
    let addr = match t.addr {
        std::net::IpAddr::V4(a) => Some(a),
        std::net::IpAddr::V6(_) => None,
    };
    let identity = t.sni.as_deref().zip(addr).and_then(|(n, a)| scenario.identity(n, a)).map(|i| i.as_str());
    let mut line = json!({
        "type": "tls",
        "sandbox": sandbox(&t.sandbox),
        "conn": t.conn,
        "addr": t.addr.to_string(),
        "sni": t.sni,
        "identity": identity,
    });
    let fields = line.as_object_mut().expect("an object");
    let outcome = match &t.outcome {
        TlsOutcome::Accepted { alpn } => {
            fields.insert("alpn".into(), json!(alpn.as_ref().map(|a| String::from_utf8_lossy(a).into_owned())));
            "accepted"
        }
        TlsOutcome::Rejected => "rejected",
        TlsOutcome::Alert(a) => {
            fields.insert("alert".into(), json!(alert_name(*a)));
            fields.insert("alert_code".into(), json!(a));
            "alert"
        }
        TlsOutcome::Failed(why) => {
            fields.insert("detail".into(), json!(why.chars().take(200).collect::<String>()));
            "failed"
        }
        TlsOutcome::Closed => "closed",
        TlsOutcome::TimedOut => "timed_out",
        TlsOutcome::Aborted => "aborted",
        _ => "other",
    };
    fields.insert("outcome".into(), json!(outcome));
    line
}

/// The name of a TLS alert, as OpenSSL and the Python world wrote it.
pub fn alert_name(a: u8) -> &'static str {
    match a {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

fn http(h: &web::Http) -> Value {
    let ua = h.headers.get(USER_AGENT).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    let mut names: Vec<&str> = h.headers.keys().map(|k| k.as_str()).collect();
    names.dedup();
    let answer = match h.answer {
        HttpAnswer::Handler => "handler",
        HttpAnswer::Error => "error",
        HttpAnswer::Redirect => "redirect",
        HttpAnswer::Misdirected => "misdirected",
        HttpAnswer::NoHost => "no_host",
        HttpAnswer::Cancelled => "cancelled",
        _ => "other",
    };
    let mut line = json!({
        "type": "http",
        "sandbox": sandbox(&h.sandbox),
        "conn": h.conn,
        "local": h.local.to_string(),
        "scheme": h.scheme.as_str(),
        "sni": h.sni,
        "host": h.host,
        "method": h.method.as_str(),
        "path": redact_path(h.uri.path()),
        "query_bytes": h.uri.query().map(|q| q.len()),
        "version": format!("{:?}", h.version),
        "ua": ua,
        "headers": names,
        "answer": answer,
        "status": h.status.map(|s| s.as_u16()),
        "sent": h.sent,
        "complete": h.complete,
    });
    if let Some(page) = h.extensions.get::<Page>() {
        let fields = line.as_object_mut().expect("an object");
        fields.insert("served_by".into(), json!(page.served_by));
        fields.insert("page".into(), json!(page.page));
        fields.insert("carries_password".into(), json!(page.carries_password));
        fields.insert("body_bytes".into(), json!(page.body_bytes));
    }
    line
}

/// `path` with every segment that holds the account's password replaced by
/// `[password]`.
pub fn redact_path(path: &str) -> String {
    let secret = ACCOUNT.password.as_bytes();
    let holds = |seg: &str| {
        let decoded = unquote_to_bytes(seg.as_bytes());
        decoded.windows(secret.len()).any(|w| w.eq_ignore_ascii_case(secret))
    };
    path.split('/').map(|seg| if holds(seg) { "[password]" } else { seg }).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_in_the_path_is_not_logged() {
        assert_eq!(redact_path("/login/Kf7mR-leap2Q-vytn"), "/login/[password]");
        assert_eq!(redact_path("/a/x%4Bf7mR-leap2Q-vytny/b"), "/a/[password]/b");
        assert_eq!(redact_path("/balance"), "/balance");
        assert_eq!(redact_path("/"), "/");
    }
}
