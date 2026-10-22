//! Shared network event projection.

use fictionet::events::{Event, float};
use fictionet::stdlib::protocols::json::Value as J;
use serde_json::{Map, Value, json};

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

/// A JSON value as an event field's value, the reverse of [`js`].
pub fn field(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => u.into(),
            (None, Some(i)) => i.into(),
            _ => float(n.as_f64().unwrap_or(0.0)),
        },
        Value::String(s) => s.as_str().into(),
        Value::Array(items) => J::Array(items.iter().map(field).collect()),
        Value::Object(members) => {
            J::Object(members.iter().map(|(k, v)| (k.clone(), field(v))).collect())
        }
    }
}

pub fn sandbox(e: &Event) -> Value {
    match &e.conn.sandbox {
        Some(s) => json!({"id": s.id, "name": &*s.name, "addr": s.addr.map(|a| a.to_string())}),
        None => json!({"id": 0, "name": "", "addr": null}),
    }
}

/// The log line for the event, if it gets one.
pub fn line(e: &Event) -> Option<Value> {
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
        // An installed aggregator counts repeated network facts and retains
        // the lowest and highest port.
        ("net", "blocked") if e.u64("count").is_some_and(|n| n > 1) => Some(json!({
            "type": "blocked",
            "sandbox": sandbox(e),
            "why": f("why"),
            "protocol": f("protocol"),
            "src": f("src"),
            "dst": f("dst"),
            "count": f("count"),
            "ports": e.u64("dst_port").map_or_else(|| f("dst_port"), |port| json!([port, port])),
        })),
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

fn dns(e: &Event) -> Value {
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

/// Appends TLS outcome fields after the world-specific handshake fields.
pub fn tls_outcome(e: &Event, fields: &mut Map<String, Value>) {
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
}

/// Distinct header names in wire order and the first valid user agent.
pub fn request_headers(e: &Event) -> (Vec<String>, Option<String>) {
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
    (names, ua)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_fields_keep_their_order_and_bound_unicode_details() {
        for (outcome, expected) in [
            (
                "accepted",
                r#"{"identity":"bank","alpn":"h2","outcome":"accepted"}"#,
            ),
            (
                "alert",
                r#"{"identity":"bank","alert":"bad certificate","alert_code":42,"outcome":"alert"}"#,
            ),
            ("rejected", r#"{"identity":"bank","outcome":"rejected"}"#),
            ("closed", r#"{"identity":"bank","outcome":"closed"}"#),
            ("timed_out", r#"{"identity":"bank","outcome":"timed_out"}"#),
            ("detached", r#"{"identity":"bank","outcome":"detached"}"#),
            ("cancelled", r#"{"identity":"bank","outcome":"cancelled"}"#),
            ("unknown", r#"{"identity":"bank","outcome":"other"}"#),
        ] {
            let e = Event::new("tls", "handshake")
                .field("outcome", outcome)
                .field("alpn", "h2")
                .field("alert", "bad certificate")
                .field("alert_code", 42u64);
            let mut line = json!({"identity": "bank"});
            tls_outcome(&e, line.as_object_mut().unwrap());
            assert_eq!(line.to_string(), expected);
        }
        let e = Event::new("tls", "handshake")
            .field("outcome", "failed")
            .field("detail", "é".repeat(201));
        let mut fields = Map::new();
        tls_outcome(&e, &mut fields);
        assert_eq!(fields["detail"], "é".repeat(200));
        assert_eq!(fields["outcome"], "failed");

        let mut fields = Map::new();
        tls_outcome(&Event::new("tls", "handshake"), &mut fields);
        assert_eq!(Value::Object(fields), json!({"outcome": "other"}));
    }

    #[test]
    fn header_names_keep_wire_order_and_skip_malformed_values() {
        let headers = fictionet::stdlib::protocols::json::parse_with(
            br#"[null, [], ["ignored"], ["user-agent", null], ["host", "a"],
                ["user-agent", "first"], ["host", "b"], ["user-agent", "second"],
                ["User-Agent", "upper"]]"#,
            &Default::default(),
        )
        .unwrap();
        let e = Event::new("http", "request").field("headers", headers);
        assert_eq!(
            request_headers(&e),
            (
                vec!["host".into(), "user-agent".into(), "User-Agent".into()],
                Some("first".into()),
            )
        );
        assert_eq!(
            request_headers(&Event::new("http", "request")),
            (vec![], None)
        );
    }
}
