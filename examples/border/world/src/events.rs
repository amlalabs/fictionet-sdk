//! The network's events as log lines.
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
//! the label the bank's handler put on its response
//! ([`Page`](crate::bank::Page)). A path
//! segment that holds the password, as sent or percent-encoded, is logged as
//! `[password]`, and the log's writer takes the password out of any other
//! field ([`crate::log`]).

use fictionet::events::Event as Entry;
use fictionet::stdlib::json::Value as J;
use serde_json::{Value, json};

use crate::bank::{ACCOUNT, unquote_to_bytes};
use crate::scenario::Scenario;

/// The sources of the events [`line`] makes lines of.
pub const LOGGED: [&str; 4] = ["net", "dns", "tls", "http"];

#[path = "../../../common/events.rs"]
mod shared;
use shared::{js, sandbox};

/// The log line for `e`, if it gets one.
pub fn line(scenario: &Scenario, e: &Entry) -> Option<Value> {
    match (e.source, e.kind) {
        ("tls", "handshake") => Some(tls(scenario, e)),
        ("http", "request") => Some(http(e)),
        _ => shared::line(e),
    }
}

fn tls(scenario: &Scenario, e: &Entry) -> Value {
    // The scenario is IPv4 only (`Sites::ipv4_only`).
    let addr = e
        .str("addr")
        .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok());
    let sni = e.str("sni");
    let identity = sni
        .zip(addr)
        .and_then(|(n, a)| scenario.identity(n, a))
        .map(|i| i.as_str());
    let mut line = json!({
        "type": "tls",
        "sandbox": sandbox(e),
        "conn": e.conn.id.unwrap_or(0),
        "addr": e.str("addr").unwrap_or_default(),
        "sni": sni,
        "identity": identity,
    });
    let fields = line.as_object_mut().expect("an object");
    let outcome = e.str("outcome").unwrap_or("other");
    match outcome {
        "accepted" => {
            fields.insert("alpn".into(), js(e.get("alpn")));
        }
        "alert" => {
            fields.insert("alert".into(), js(e.get("alert")));
            fields.insert("alert_code".into(), js(e.get("alert_code")));
        }
        "failed" => {
            fields.insert(
                "detail".into(),
                json!(
                    e.str("detail")
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect::<String>()
                ),
            );
        }
        _ => {}
    }
    let outcome = match outcome {
        "accepted" | "rejected" | "alert" | "failed" | "closed" | "timed_out" | "detached"
        | "cancelled" => outcome,
        _ => "other",
    };
    fields.insert("outcome".into(), json!(outcome));
    line
}

fn http(e: &Entry) -> Value {
    let mut names: Vec<String> = Vec::new();
    let mut ua = None;
    for pair in e.get("headers").and_then(J::as_array).unwrap_or_default() {
        let Some(pair) = pair.as_array() else {
            continue;
        };
        let (Some(name), Some(value)) = (
            pair.first().and_then(J::as_str),
            pair.get(1).and_then(J::as_str),
        ) else {
            continue;
        };
        if !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
        if name == "user-agent" && ua.is_none() {
            ua = Some(value.to_owned());
        }
    }
    let answer = match e.str("answer") {
        Some(a @ ("handler" | "error" | "redirect" | "misdirected" | "no_host" | "cancelled")) => a,
        _ => "other",
    };
    let mut line = json!({
        "type": "http",
        "sandbox": sandbox(e),
        "conn": e.conn.id.unwrap_or(0),
        "local": e.conn.local.map(|a| a.to_string()).unwrap_or_default(),
        "scheme": e.str("scheme").unwrap_or_default(),
        "sni": e.str("sni"),
        "host": e.str("host"),
        "method": e.str("method").unwrap_or_default(),
        "path": redact_path(e.str("path").unwrap_or_default()),
        "query_bytes": e.str("query").map(str::len),
        "version": e.str("version").unwrap_or_default(),
        "ua": ua,
        "headers": names,
        "answer": answer,
        "status": e.u64("status"),
        "sent": e.u64("sent").unwrap_or(0),
        "complete": e.get("complete").and_then(J::as_bool) == Some(true),
    });
    if e.get("served_by").is_some() {
        let fields = line.as_object_mut().expect("an object");
        fields.insert("served_by".into(), js(e.get("served_by")));
        fields.insert("page".into(), js(e.get("page")));
        fields.insert("carries_password".into(), js(e.get("carries_password")));
        fields.insert("body_bytes".into(), js(e.get("body_bytes")));
    }
    line
}

/// `path` with every segment that holds the account's password replaced by
/// `[password]`.
pub fn redact_path(path: &str) -> String {
    let secret = ACCOUNT.password.as_bytes();
    let holds = |seg: &str| {
        let decoded = unquote_to_bytes(seg.as_bytes());
        decoded
            .windows(secret.len())
            .any(|w| w.eq_ignore_ascii_case(secret))
    };
    path.split('/')
        .map(|seg| if holds(seg) { "[password]" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
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
