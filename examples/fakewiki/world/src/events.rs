//! The request log, written from the events of everything the network
//! does: one line per DNS query, rejected or failed TLS handshake, and HTTP
//! request, in the formats FakeWiki's main.py used.
//!
//! The handler ([`content`](crate::content)) puts what it knows about a
//! page (its kind, topic, source and stance) in its response's extensions
//! as event fields ([`Page::fields`]). The `http.request` event brings
//! them back here, so one `http` line holds both what the agent asked for
//! and what the server delivered. `bytes` is the page's Content-Length,
//! including for HEAD. `sent` and `complete` copy the core's delivery facts:
//! body bytes taken by the connection, and whether it took the whole body.
//! Over HTTP/2 this means hyper took the body, not that the client read it.
//! `location` is the redirect destination, when there is one.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fictionet::events::{Event, Fields, opt};
use fictionet::stdlib::protocols::json::Value as J;
use serde_json::{Value, json};

use example_common::log::Log;

use example_common::headers;

/// What the handler tells the log about one response.
#[derive(Clone, Debug)]
pub struct Page {
    /// The source version served by this response, if any.
    pub served: Option<crate::pages::Version>,
    /// The tampering revision captured when this request began.
    pub tamper_revision: u64,
    /// The endpoint label.
    pub kind: String,
    /// The topic label, when known.
    pub topic: Option<String>,
    /// The source label, when known.
    pub source: Option<String>,
    /// The stance detected from body text, when unambiguous.
    pub stance: Option<String>,
    /// The length of the page, also for HEAD, separate from sent bytes.
    pub bytes: u64,
    /// The response's Location header, if present.
    pub location: Option<String>,
    /// Why the backend could not answer, for a `backend_error`.
    pub error: Option<String>,
}

impl Page {
    /// The page as fields of its request's event.
    pub fn fields(&self) -> Fields {
        Fields::new()
            .with("served", opt(self.served.map(|v| v.as_str().to_owned())))
            .with("tamper_revision", self.tamper_revision)
            .with("kind", self.kind.as_str())
            .with("topic", opt(self.topic.clone()))
            .with("source", opt(self.source.clone()))
            .with("stance", opt(self.stance.clone()))
            .with("bytes", self.bytes)
            .with("location", opt(self.location.clone()))
            .with("error", opt(self.error.clone()))
    }
}

/// Projects run events into the world's JSON Lines format.
pub struct LogObserver {
    /// The destination for the eval log.
    pub log: Arc<Log>,
    /// The hosts registered in this world.
    pub hosts: HashMap<String, Ipv4Addr>,
}

impl fictionet::events::Observer for LogObserver {
    fn enabled(
        &self,
        metadata: fictionet::events::Metadata,
        _: &fictionet::events::ConnInfo,
    ) -> bool {
        matches!(metadata.source, "net" | "dns" | "tls" | "http")
    }
    fn lost(&self, count: u64) {
        if count != 0 {
            self.log
                .write(serde_json::json!({"type": "lost", "count": count}));
            self.log
                .fail(format!("{count} events lost before log delivery"));
        }
    }
    fn observe(
        &self,
        _: fictionet::events::Stamp,
        observation: fictionet::events::Observation<'_>,
    ) {
        if let fictionet::events::Observation::Event(event) = observation
            && let Some(line) = line(&self.hosts, event)
        {
            self.log.write(line);
        }
    }
}

fn text(e: &Event, name: &str) -> Option<String> {
    e.str(name).map(str::to_owned)
}

/// The log line for `entry`, if main.py logged such a thing.
fn line(hosts: &HashMap<String, Ipv4Addr>, e: &Event) -> Option<Value> {
    let name = e.conn.sandbox.as_ref().map(|s| s.name.clone());
    match (e.source, e.kind) {
        ("net", "attached") => {
            println!("attached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("net", "detached") => {
            println!("detached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("dns", "query") => Some(dns(hosts, e)),
        ("tls", "handshake") => tls(e),
        ("http", "request") => Some(http(hosts, e)),
        _ => None,
    }
}

/// A DNS query, as main.py's `dns_answer` logged it, or a `dns_error` for
/// one that could not be read.
fn dns(hosts: &HashMap<String, Ipv4Addr>, e: &Event) -> Value {
    let (Some(name), Some(qtype)) = (text(e, "name"), e.u64("qtype")) else {
        let error = match e.str("answer") {
            Some("none") | None => "not a DNS query".to_owned(),
            _ => "malformed DNS query".to_owned(),
        };
        return json!({"type": "dns_error", "error": error});
    };
    let ip = hosts.get(&name);
    let tcp = e.get("tcp").and_then(J::as_bool) == Some(true);
    json!({
        "type": "dns",
        "via": if tcp { "tcp" } else { "udp" },
        "name": name,
        "qtype": qtype,
        "in_world": ip.is_some(),
        // Single-label names are the container's own hostname lookups.
        "single_label": !name.contains('.'),
        "answer": if qtype == 1 { ip.map(|a| a.to_string()) } else { None },
    })
}

/// A TLS handshake that did not finish: `tls_reject` when the world refused
/// the name, `tls_error` when the client gave up or broke the protocol.
fn tls(e: &Event) -> Option<Value> {
    let sni = text(e, "sni");
    let error = match e.str("outcome")? {
        "accepted" => return None,
        "rejected" => return Some(json!({"type": "tls_reject", "sni": sni, "in_world": false})),
        "alert" => {
            let code = e.u64("alert_code").unwrap_or(0);
            let name = e.str("alert").unwrap_or("unknown");
            format!("the client sent alert {code} ({name})")
        }
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

/// An HTTP request, as main.py's handler logged it: the request, then
/// what the world made of it.
fn http(hosts: &HashMap<String, Ipv4Addr>, e: &Event) -> Value {
    let host = text(e, "host").unwrap_or_default();
    let path = match e.str("query") {
        Some(q) => format!("{}?{q}", e.str("path").unwrap_or("/")),
        None => e.str("path").unwrap_or("/").to_owned(),
    };
    let ua = headers::header(e, "user-agent");
    let mut entry = json!({
        "type": "http",
        "scheme": e.str("scheme").unwrap_or_default(),
        "method": e.str("method").unwrap_or_default(),
        "host": host,
        "sni": text(e, "sni"),
        "path": path,
        "ua": ua.unwrap_or_default(),
        "sent": e.u64("sent"),
        "complete": e.get("complete").and_then(J::as_bool),
    });
    let fields = entry.as_object_mut().expect("an object");
    let mut bytes = e.u64("sent").unwrap_or(0);
    match e.str("answer") {
        Some("handler") => match text(e, "kind") {
            Some(kind) => {
                fields.insert("in_world".into(), json!(true));
                fields.insert("kind".into(), json!(kind));
                if kind != "backend_error" {
                    fields.insert("topic".into(), json!(text(e, "topic")));
                    fields.insert("source".into(), json!(text(e, "source")));
                    fields.insert("stance".into(), json!(text(e, "stance")));
                }
                if let Some(error) = text(e, "error") {
                    fields.insert("error".into(), json!(error));
                }
                bytes = e.u64("bytes").unwrap_or(0);
                if let Some(location) = text(e, "location") {
                    fields.insert("location".into(), json!(location));
                }
            }
            None => {
                fields.insert("in_world".into(), json!(true));
                fields.insert("kind".into(), json!("other"));
            }
        },
        Some("redirect") => {
            fields.insert("in_world".into(), json!(true));
            fields.insert("kind".into(), json!("http_redirect"));
            // Match httpd's plain-HTTP redirect construction exactly.
            fields.insert("location".into(), json!(format!("https://{host}{path}")));
        }
        Some("misdirected") => {
            // A FakeWiki host asked for at the wrong address, or over a
            // connection made for another host, is still in the world.
            let in_world = hosts.contains_key(&host);
            fields.insert("in_world".into(), json!(in_world));
            if in_world {
                fields.insert("kind".into(), json!("misdirected"));
            }
        }
        Some("error") => {
            fields.insert("in_world".into(), json!(true));
            fields.insert("kind".into(), json!("backend_error"));
        }
        // The agent gave up before the page came: main.py logged the
        // request before answering it, so it is logged here too, with no
        // status.
        Some("cancelled") => {
            fields.insert("in_world".into(), json!(hosts.contains_key(&host)));
        }
        // No host: main.py logged an empty host, with no in_world.
        _ => {}
    }
    fields.insert("status".into(), json!(e.u64("status")));
    fields.insert("bytes".into(), json!(bytes));
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_loss_prevents_successful_finalization() {
        let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |text| text));
        let observer = LogObserver {
            log: log.clone(),
            hosts: HashMap::new(),
        };
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| {
                log.attach(&cx);
                fictionet::events::Observer::lost(&observer, 3);
                async { Ok(()) }
            },
        ))
        .unwrap();
        assert_eq!(
            log.finish().unwrap_err().to_string(),
            "3 events lost before log delivery"
        );
    }

    #[test]
    fn delivery_facts_are_separate_from_page_length() {
        for (method, sent, complete) in [("HEAD", 0_u64, true), ("GET", 20, false)] {
            let event = Event::new("http", "request")
                .field("answer", "handler")
                .field("kind", "wiki_article")
                .field("method", method)
                .field("status", 200_u64)
                .field("bytes", 100_u64)
                .field("sent", sent)
                .field("complete", complete);
            let line = http(&HashMap::new(), &event);
            assert_eq!(line["bytes"], 100);
            assert_eq!(line["sent"], sent);
            assert_eq!(line["complete"], complete);
            assert_eq!(line["status"], 200);
        }
    }

    #[test]
    fn missing_delivery_facts_stay_unknown() {
        let event = Event::new("http", "request").field("bytes", 100_u64);
        let line = http(&HashMap::new(), &event);
        assert!(line["sent"].is_null());
        assert!(line["complete"].is_null());
    }
}
