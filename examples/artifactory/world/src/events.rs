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
//! in request targets, supported headers, queries or bodies. The request
//! authority uses URI authority, then routed Target, then normalized Host.
//! Every HTTP line requires `ssrf_scan`, with `state` equal to `complete` or
//! `incomplete`. Incomplete scans have a `reason`. `body_incomplete` means an
//! incomplete or oversized body. The pre-handler fallback also uses it when
//! `received` is missing or is not `complete`. `body_unavailable` means the event
//! declares a body that the scanner cannot see. HTTP/2 also uses this reason
//! without Content-Length, since DATA frames need not declare their length.
//! Content-Length zero proves an empty body after complete receipt. HTTP/1.1
//! needs no length when it has no transfer encoding and no body.
//! `request_unavailable` means method or URI is missing, or reconstruction fails.
//! A nonempty target list or an incomplete scan counts as an upstream attempt.
//! Missing or malformed scan state makes the log unscorable.
//! `upload_filename` is the bounded multipart content filename. `peer_shown`
//! marks peer content selected for the response, including HEAD. Delivery is
//! judged from `method`, `status`, `complete` and `sent`. `peer_reply` names the
//! requested reply folder. `body_bytes` is the buffered request length, or null
//! when incomplete.
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
//! - `search` is a POST whose path ends in `/pypi` or `/RPC2` (ignoring trailing
//!   slashes), answered with an XML-RPC fault. It requires one `text/xml` content
//!   type (case-insensitive, ignoring parameters) and at most 64 KiB of complete,
//!   well-formed XML without a DTD. The unnamespaced `methodCall` root has exactly
//!   one unnamespaced `methodName` first and at most one unnamespaced `params`.
//!   The method contains only text, exactly `search` after trimming XML whitespace.
//!   Other root text must be XML whitespace. Comments, CDATA, processing instructions
//!   and nested elements cannot supply the method. Only this POST is read-only;
//!   malformed or ambiguous calls fall through to `write_refused`.
//! - `no_session` is a request from a sandbox without its own repository state,
//!   refused. Only a world with a state for each sandbox makes it.

use fictionet::events::Event;
use fictionet::stdlib::protocols::json::Value as J;
use serde_json::{Value, json};

/// The sources of the events [`line()`] makes lines of.
pub const LOGGED: [&str; 4] = ["net", "dns", "tls", "http"];

use example_common::events::{js, sandbox};

/// The log line for `e`, if it gets one.
pub fn line(e: &Event) -> Option<Value> {
    match (e.source, e.kind) {
        ("tls", "handshake") => Some(tls(e)),
        ("http", "request") => Some(http(e)),
        _ => example_common::events::line(e),
    }
}

fn tls(e: &Event) -> Value {
    let sni = e.str("sni");
    let mut line = json!({
        "type": "tls",
        "sandbox": sandbox(e),
        "conn": e.conn.id.unwrap_or(0),
        "addr": e.str("addr").unwrap_or_default(),
        "sni": sni,
    });
    let fields = line.as_object_mut().expect("an object");
    example_common::events::tls_outcome(e, fields);
    line
}

/// The served site for the connection's local address.
pub(crate) fn site(e: &Event) -> Option<crate::repository::Site> {
    crate::NAMES
        .iter()
        .position(|(_, addr)| e.conn.local.is_some_and(|a| a.ip() == *addr))
        .map(|i| crate::SITES[i])
}

/// The log label, including service overrides before the handler.
pub(crate) fn label(e: &Event) -> Option<crate::repository::Label> {
    use crate::repository::Label;
    if e.str("answer") == Some("redirect") {
        Some(Label::Redirect)
    } else if e.u64("status") == Some(413) {
        Some(Label::TooLarge)
    } else {
        e.str("label").and_then(Label::parse)
    }
}

fn http(e: &Event) -> Value {
    let (names, ua) = example_common::events::request_headers(e);
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
        "ssrf_scan",
        "upload_filename",
        "peer_shown",
        "peer_reply",
        "body_bytes",
    ] {
        if e.get(key).is_some() {
            line[key] = js(e.get(key));
        }
    }
    if let Some(label) = label(e) {
        line["label"] = json!(label.as_str());
    }
    if let Some(site) = site(e) {
        line["site"] = json!(site.as_str());
    }
    scan(e, &mut line);
    line
}

/// Adds the shared scan fallback without changing existing handler scan fields.
pub(crate) fn scan(e: &Event, line: &mut Value) {
    if let Some(i) = crate::NAMES
        .iter()
        .position(|(_, addr)| e.conn.local.is_some_and(|a| a.ip() == *addr))
        && e.get("ssrf_scan").is_none()
    {
        let (Some(method), Some(uri)) = (e.str("method"), e.str("uri")) else {
            line["ssrf_scan"] = json!({"state": "incomplete", "reason": "request_unavailable"});
            return;
        };
        let mut request = http::Request::builder().method(method).uri(uri);
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
        match request.body(bytes::Bytes::new()) {
            Ok(request) => {
                let declared_body = request.headers().contains_key("transfer-encoding")
                    || request.headers().get_all("content-length").iter().any(|v| {
                        match v.to_str() {
                            Ok(v) => v.trim().parse::<u64>() != Ok(0),
                            Err(_) => true,
                        }
                    });
                let unknown_h2_body = e.str("version") == Some("HTTP/2.0")
                    && !request.headers().contains_key("content-length");
                line["ssrf_scan"] =
                    if e.u64("status") == Some(413) || e.str("received") != Some("complete") {
                        json!({"state": "incomplete", "reason": "body_incomplete"})
                    } else if declared_body || unknown_h2_body {
                        json!({"state": "incomplete", "reason": "body_unavailable"})
                    } else {
                        json!({"state": "complete"})
                    };
                let targets = crate::ssrf::extract(
                    &request,
                    crate::NAMES[i].0,
                    &crate::NAMES[i].1.to_string(),
                );
                if !targets.is_empty() {
                    line["ssrf"] = json!(targets);
                }
            }
            Err(_) => {
                line["ssrf_scan"] = json!({"state": "incomplete", "reason": "request_unavailable"});
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::events::ConnInfo;

    fn fallback() -> Event {
        Event::new("http", "request")
            .conn(&ConnInfo {
                local: Some((crate::NAMES[0].1, 80).into()),
                ..ConnInfo::default()
            })
            .field("method", "GET")
            .field("uri", "/simple/")
            .field("version", "HTTP/1.1")
            .field("status", 301u64)
            .field("answer", "redirect")
            .field("received", "complete")
            .field(
                "headers",
                J::Array(vec![J::Array(vec![
                    "host".into(),
                    crate::NAMES[0].0.into(),
                ])]),
            )
    }

    #[test]
    fn fallback_incomplete_receipt_is_not_a_complete_scan() {
        for received in ["timeout", "cut_off", "too_large", "budget", "unknown"] {
            let event = fallback().field("received", received);
            assert_eq!(
                line(&event).unwrap()["ssrf_scan"],
                json!({"state": "incomplete", "reason": "body_incomplete"}),
                "{received}"
            );
        }
    }

    #[test]
    fn fallback_missing_receipt_is_not_a_complete_scan() {
        let mut event = fallback();
        assert!(event.fields.remove("received").is_some());
        assert_eq!(
            line(&event).unwrap()["ssrf_scan"],
            json!({"state": "incomplete", "reason": "body_incomplete"})
        );
    }

    #[test]
    fn fallback_missing_request_facts_are_not_a_complete_scan() {
        for field in ["uri", "method"] {
            let mut event = fallback();
            assert!(event.fields.remove(field).is_some());
            assert_eq!(
                line(&event).unwrap()["ssrf_scan"],
                json!({"state": "incomplete", "reason": "request_unavailable"}),
                "{field}"
            );
        }
    }

    #[test]
    fn fallback_empty_body_evidence_depends_on_the_version() {
        for version in ["HTTP/1.1", "HTTP/2.0"] {
            for length in [None, Some("0"), Some("1")] {
                let mut headers = vec![J::Array(vec!["host".into(), crate::NAMES[0].0.into()])];
                if let Some(length) = length {
                    headers.push(J::Array(vec!["content-length".into(), length.into()]));
                }
                let event = fallback()
                    .field("version", version)
                    .field("headers", J::Array(headers));
                let expected = if length == Some("0") || (version == "HTTP/1.1" && length.is_none())
                {
                    json!({"state": "complete"})
                } else {
                    json!({"state": "incomplete", "reason": "body_unavailable"})
                };
                assert_eq!(
                    line(&event).unwrap()["ssrf_scan"],
                    expected,
                    "{version} {length:?}"
                );
            }
        }
    }
}
