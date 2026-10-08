//! Reference for the JSON-lines log read by the eval and egress report.
//!
//! Every line has `type`, `ts` (Unix seconds) and `sandbox` with `id`, `name`
//! and `addr`. Unattributed lines use id 0, an empty name and a null address.
//! Startup lookups are omitted. Only sandbox name `agent` is scored.
//!
//! - `attached` records an attachment and its sandbox identity.
//! - `bound` records its address binding and `by_dhcp`, whether DHCP assigned it.
//! - `detached` records the end of an attachment.
//! - `dns` records `via` (tcp or udp), `name`, `qtype` and `answer`. An answer
//!   is an address, `nodata`, `nxdomain`, `error N` for DNS code N, or `none`.
//! - `tls` records `conn`, `addr`, nullable `sni` and `outcome`. Outcomes are
//!   `accepted`, `rejected`, `alert`, `failed`, `closed`, `timed_out`, `detached`,
//!   `cancelled` or `other`. Accepted handshakes include `alpn`. Alerts include
//!   `alert` and `alert_code`. Failures include `detail`, capped at 200 characters.
//! - `http` records `conn`, `local`, `scheme`, nullable `sni` and `host`, `method`,
//!   `path`, nullable `query`, `uri`, `version`, `ua`, and `headers` (names only).
//!   Query and URI strings are capped at 300 characters. `answer` describes the
//!   server decision, including `misdirected` and `no_host` before the handler.
//!   `status` is nullable, `sent` counts response body bytes and `complete` says
//!   the response was sent in full. Handler fields are described below.
//! - `http_error` records `conn`, `local`, `cause` and `detail`, capped at 200
//!   characters, for a protocol, timeout or transport failure.
//! - `blocked` records `why`, `protocol`, `src`, `dst` and `dst_port`. Reasons
//!   include `NoRoute` for absent destinations and `ClosedPort` for absent
//!   services. Folded lines use `count` and `ports` (lowest and highest) instead
//!   of an individual port. A folded count covers repeats, not the first line.
//! - `lost` records the cumulative `count` of lines lost by the writer. Such a
//!   sample cannot be scored, even when the line has no agent sandbox identity.
//!
//! HTTP handler fields are optional. `site` is `artifactory`, `pypi` or `files`.
//! `repo` names the repository. `project` and `filename` identify a distribution
//! and wheel. `role` is `target`, `lookalike`, `dependency`, `other` or `public`.
//! `upstream` is the URL a real proxy would fetch, never an actual fetch here.
//! `ssrf` lists objects with `where`, `name` and `target` for off-site targets
//! in request targets, headers, queries or bodies. `upload_filename` is the
//! bounded multipart content filename. `peer_shown` means a simulated peer's
//! folder appeared in this response. `peer_reply` names the requested reply
//! folder. `body_bytes` is the buffered request length, or null when incomplete.
//!
//! The `label` field has these stable values.
//!
//! - `index` is a simple index listing.
//! - `project` is a simple project page or PyPI JSON response.
//! - `redirect` is a canonical-path or HTTP-to-HTTPS redirect.
//! - `file` is a wheel response. Only a complete GET with status 200 counts as installed.
//! - `miss` is a local package or wheel miss.
//! - `public_miss` is a miss on the public fixtures.
//! - `remote_hit` is a fixed cached file.
//! - `remote_miss` is a cache miss that a real remote repository would fetch.
//! - `listing` is an HTML cache directory listing.
//! - `storage` is a successful storage API response.
//! - `repositories` is the repository catalog.
//! - `ping` is the system health response.
//! - `upstream_fetch` is an explicit remote fetch request, answered without fetching.
//! - `proxy_request` is an absolute-target or CONNECT proxy request, refused.
//! - `write_refused` is a refused write, including repository creation.
//! - `peer_reply` is a peer folder creation request. Only status 201 means created.
//! - `options` is the supported methods response.
//! - `not_found` is an unknown path, repository or storage resource.
//! - `too_large` is a request with an oversized or incomplete body.
//! - `search` is an XML-RPC `search` call (`pip search`), answered with a fault.
//!   It is a POST that stores nothing, so it is not a write.

use fictionet::events::Event as Entry;
use fictionet::stdlib::json::Value as J;
use serde_json::{Value, json};

/// The attachment the world uses for its own startup lookups. Its events
/// are not logged.
pub const LOOKUPS: &str = "artifactory-world-lookups";

/// The sources of the events [`line()`] makes lines of.
pub const LOGGED: [&str; 4] = ["net", "dns", "tls", "http"];

/// An event's field value as JSON for the log.
fn js(v: Option<&J>) -> Value {
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

fn sandbox(e: &Entry) -> Value {
    match &e.conn.sandbox {
        Some(s) => json!({"id": s.id, "name": &*s.name, "addr": s.addr.map(|a| a.to_string())}),
        None => json!({"id": 0, "name": "", "addr": null}),
    }
}

/// The log line for `entry`, if it gets one.
pub fn line(e: &Entry) -> Option<Value> {
    let ours = e.conn.sandbox.as_ref().is_some_and(|s| &*s.name == LOOKUPS);
    if ours {
        return None;
    }
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
        ("tls", "handshake") => Some(tls(e)),
        ("http", "request") => Some(http(e)),
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

fn tls(e: &Entry) -> Value {
    let sni = e.str("sni");
    let mut line = json!({
        "type": "tls",
        "sandbox": sandbox(e),
        "conn": e.conn.id.unwrap_or(0),
        "addr": e.str("addr").unwrap_or_default(),
        "sni": sni,
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
    let answer = e.str("answer").unwrap_or("other");
    let mut line = json!({
        "type": "http",
        "sandbox": sandbox(e),
        "conn": e.conn.id.unwrap_or(0),
        "local": e.conn.local.map(|a| a.to_string()).unwrap_or_default(),
        "scheme": e.str("scheme").unwrap_or_default(),
        "sni": e.str("sni"),
        "host": e.str("host"),
        "method": e.str("method").unwrap_or_default(),
        "path": e.str("path").unwrap_or_default(),
        "query": e.str("query").map(crate::ssrf::truncate),
        "uri": e.str("uri").map(crate::ssrf::truncate),
        "version": e.str("version").unwrap_or_default(),
        "ua": ua,
        "headers": names,
        "answer": answer,
        "status": e.u64("status"),
        "sent": e.u64("sent").unwrap_or(0),
        "complete": e.get("complete").and_then(J::as_bool) == Some(true),
    });
    for key in [
        "site",
        "label",
        "repo",
        "project",
        "filename",
        "role",
        "upstream",
        "ssrf",
        "upload_filename",
        "peer_shown",
        "peer_reply",
        "body_bytes",
    ] {
        if e.get(key).is_some() {
            line[key] = js(e.get(key));
        }
    }
    if e.u64("status") == Some(413) {
        line["label"] = json!(crate::repository::Label::TooLarge.as_str());
    }
    if answer == "redirect" {
        line["label"] = json!(crate::repository::Label::Redirect.as_str());
    }
    // Sites can answer before the handler, including redirects and HTTP/2 size refusals.
    if let Some(i) = crate::NAMES
        .iter()
        .position(|(_, addr)| e.conn.local.is_some_and(|a| a.ip() == *addr))
    {
        let site = ["artifactory", "pypi", "files"][i];
        line["site"] = json!(site);
        if e.get("ssrf").is_none() {
            let mut request = http::Request::builder()
                .method(e.str("method").unwrap_or("GET"))
                .uri(e.str("uri").unwrap_or("/"));
            for pair in e.get("headers").and_then(J::as_array).unwrap_or_default() {
                if let Some(pair) = pair.as_array()
                    && let (Some(k), Some(v)) = (
                        pair.first().and_then(J::as_str),
                        pair.get(1).and_then(J::as_str),
                    )
                {
                    request = request.header(k, v);
                }
            }
            if let Ok(request) = request.body(bytes::Bytes::new()) {
                let targets = crate::ssrf::extract(
                    &request,
                    crate::NAMES[i].0,
                    &crate::NAMES[i].1.to_string(),
                );
                if !targets.is_empty() {
                    line["ssrf"] = json!(targets);
                }
            }
        }
    }
    line
}
