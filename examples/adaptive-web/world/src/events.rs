//! The request log, written from the events of everything the network
//! does: one line per DNS query, decision about a name, certificate,
//! failed TLS handshake and HTTP request.
//!
//! The handler ([`content`](crate::content)) puts what the backend said
//! about a page (generated or cached, the model, the time it took, its
//! claims) in its response's extensions. The `http.request` event brings
//! them back here, so one `http` line holds both what the agent asked for
//! and what it was shown.

use std::sync::Arc;

use fictionet::Cx;
use fictionet::events::Event as Entry;
use fictionet::stdlib::json::Value as J;
use serde_json::{Map, Value, json};

use crate::content::PAGE_FIELDS;
use crate::log::Log;

/// The attachment the world uses for its own startup lookups. Its DNS
/// queries are not logged; the sites they make are.
pub const LOOKUPS: &str = "adaptive-web-world-lookups";

/// Writes the request log from `cx`'s run's events.
pub fn log_to(cx: &Cx, log: Arc<Log>) {
    cx.events().subscribe(move |event| {
        if let Some(line) = line(event) {
            log.write(line);
        }
    });
}

/// An event field's value as JSON.
pub fn to_json(v: &J) -> Value {
    match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => serde_json::from_str(n.text()).unwrap_or(Value::Null),
        J::String(s) => Value::String(s.clone()),
        J::Array(items) => Value::Array(items.iter().map(to_json).collect()),
        J::Object(members) => Value::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v)))
                .collect(),
        ),
    }
}

fn get(e: &Entry, name: &str) -> Value {
    e.get(name).map(to_json).unwrap_or(Value::Null)
}

/// The log line for `e`, if it is one the log keeps.
fn line(e: &Entry) -> Option<Value> {
    let name = e.conn.sandbox.as_ref().map(|s| s.name.clone());
    let ours = name.as_deref() == Some(LOOKUPS);
    match (e.source, e.kind) {
        ("net", "attached") if !ours => {
            println!("attached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("net", "detached") if !ours => {
            println!("detached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("adaptive", "site") => Some(
            json!({"type": "site", "host": get(e, "host"), "addr": get(e, "addr"), "why": get(e, "why")}),
        ),
        ("adaptive", "refused") => {
            Some(json!({"type": "refused", "host": get(e, "host"), "why": get(e, "why")}))
        }
        ("adaptive", "cert") => Some(json!({
            "type": "cert", "host": get(e, "host"), "not_before": get(e, "not_before"), "not_after": get(e, "not_after"),
        })),
        ("dns", "query") if !ours => Some(json!({
            "type": "dns",
            "via": if e.get("tcp").and_then(J::as_bool) == Some(true) { "tcp" } else { "udp" },
            "name": get(e, "name"),
            "qtype": get(e, "qtype"),
            "answer": get(e, "answer"),
            "addr": get(e, "addr"),
        })),
        ("tls", "handshake") => tls(e),
        ("http", "request") => Some(http(e)),
        _ => None,
    }
}

/// A TLS handshake that did not finish: `tls_reject` when the world refused
/// the name, `tls_error` when the client gave up or broke the protocol.
fn tls(e: &Entry) -> Option<Value> {
    let sni = get(e, "sni");
    let error = match e.str("outcome")? {
        "accepted" => return None,
        "rejected" => return Some(json!({"type": "tls_reject", "sni": sni})),
        "alert" => format!("the client sent alert {}", e.u64("alert").unwrap_or(0)),
        "failed" => e
            .str("detail")
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
        "closed" => "the client closed the connection before the handshake finished".to_owned(),
        "timed_out" => "the handshake did not finish within 10 seconds".to_owned(),
        _ => "the handshake failed".to_owned(),
    };
    Some(json!({"type": "tls_error", "sni": sni, "error": error}))
}

fn header(e: &Entry, name: &str) -> Value {
    e.get("headers")
        .and_then(J::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(J::as_array)
        .find(|p| p.first().and_then(J::as_str) == Some(name))
        .and_then(|p| p.get(1).and_then(J::as_str))
        .map_or(Value::Null, |s| Value::String(s.to_owned()))
}

/// An HTTP request: what the agent asked for, then what the world made of
/// it.
fn http(e: &Entry) -> Value {
    let path = match e.str("query") {
        Some(q) => format!("{}?{q}", e.str("path").unwrap_or("/")),
        None => e.str("path").unwrap_or("/").to_owned(),
    };
    let mut line = Map::new();
    line.insert("type".into(), json!("http"));
    line.insert("scheme".into(), get(e, "scheme"));
    line.insert("method".into(), get(e, "method"));
    line.insert("host".into(), get(e, "host"));
    line.insert("path".into(), json!(path));
    line.insert("ua".into(), header(e, "user-agent"));
    line.insert("referer".into(), header(e, "referer"));
    line.insert("answer".into(), get(e, "answer"));
    line.insert("status".into(), get(e, "status"));
    for name in PAGE_FIELDS {
        if let Some(v) = e.get(name) {
            line.insert(name.into(), to_json(v));
        }
    }
    if !line.contains_key("bytes") {
        line.insert("bytes".into(), get(e, "sent"));
    }
    Value::Object(line)
}
