//! Shared network event projection.

use fictionet::events::Event as Entry;
use fictionet::stdlib::json::Value as J;
use serde_json::{Value, json};

/// An event's field value as JSON for the log.
pub fn js(v: Option<&J>) -> Value {
    match v {
        None | Some(J::Null) => Value::Null,
        Some(J::Bool(b)) => json!(b),
        Some(J::Number(n)) => n
            .as_u64()
            .map(|u| json!(u))
            .or_else(|| n.as_i64().map(|i| json!(i)))
            .unwrap_or_else(|| json!(n.as_f64())),
        Some(J::String(s)) => json!(s),
        Some(J::Array(a)) => Value::Array(a.iter().map(|v| js(Some(v))).collect()),
        Some(J::Object(o)) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), js(Some(v)))).collect())
        }
    }
}

pub fn sandbox(e: &Entry) -> Value {
    match &e.conn.sandbox {
        Some(s) => json!({"id": s.id, "name": &*s.name, "addr": s.addr.map(|a| a.to_string())}),
        None => json!({"id": 0, "name": "", "addr": null}),
    }
}

/// The log line for `entry`, if it gets one.
pub fn line(e: &Entry) -> Option<Value> {
    let f = |name: &str| js(e.get(name));
    let conn = e.conn.id.unwrap_or(0);
    let local = e.conn.local.map(|a| a.to_string()).unwrap_or_default();
    match (e.source, e.kind) {
        ("net", "attached") => Some(json!({"type": "attached", "sandbox": sandbox(e)})),
        ("net", "bound") => {
            Some(json!({"type": "bound", "sandbox": sandbox(e), "by_dhcp": f("by_dhcp")}))
        }
        ("net", "detached") => Some(json!({"type": "detached", "sandbox": sandbox(e)})),
        ("dns", "query") => Some(dns(e)),
        ("http", "error") => Some(json!({
            "type": "http_error",
            "sandbox": sandbox(e),
            "conn": conn,
            "local": local,
            "cause": f("cause"),
            "detail": e.str("detail").unwrap_or_default().chars().take(200).collect::<String>(),
        })),
        // The network counts repeats: past the first of a run, one event
        // counts the rest, with the lowest and highest port.
        ("net", "blocked")
            if e.u64("count").is_some_and(|n| n > 1)
                || matches!(e.get("dst_port"), Some(J::Array(_))) =>
        {
            Some(json!({
                "type": "blocked",
                "sandbox": sandbox(e),
                "why": f("why"),
                "protocol": f("protocol"),
                "src": f("src"),
                "dst": f("dst"),
                "count": f("count"),
                "ports": f("dst_port"),
            }))
        }
        ("net", "blocked") => Some(json!({
            "type": "blocked",
            "sandbox": sandbox(e),
            "why": f("why"),
            "protocol": f("protocol"),
            "src": f("src"),
            "dst": f("dst"),
            "dst_port": f("dst_port"),
        })),
        _ => None,
    }
}

fn dns(e: &Entry) -> Value {
    let answer = match e.str("answer") {
        Some("addr") => e.str("addr").unwrap_or_default().to_owned(),
        Some("nodata") => "nodata".into(),
        Some("nxdomain") => "nxdomain".into(),
        Some("error") => format!("error {}", e.u64("rcode").unwrap_or(0)),
        _ => "none".into(),
    };
    json!({
        "type": "dns",
        "sandbox": sandbox(e),
        "via": if e.get("tcp").and_then(J::as_bool) == Some(true) { "tcp" } else { "udp" },
        "name": js(e.get("name")),
        "qtype": js(e.get("qtype")),
        "answer": answer,
    })
}
