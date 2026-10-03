//! The request log, written from `web::Sites` events: one line per DNS
//! query, rejected or failed TLS handshake, and HTTP request, in the
//! formats FakeWiki's main.py used.
//!
//! The handler ([`content`](crate::content)) puts what it knows about a
//! page (its kind, topic, source and stance) in its response's extensions
//! as a [`Page`]. The `Http` event brings it back here, so one `http` line
//! holds both what the agent asked for and what it was shown.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::web::{self, DnsAnswer, Event, HttpAnswer, TlsOutcome};
use http::header::USER_AGENT;
use serde_json::{Value, json};

use crate::log::Log;

/// The attachment the world uses for its own startup lookups. Its events
/// are not logged, as main.py had no such lookups.
pub const LOOKUPS: &str = "fakewiki-world-lookups";

/// What the handler tells the log about one response.
#[derive(Clone, Debug)]
pub struct Page {
    pub kind: String,
    pub topic: Option<String>,
    pub source: Option<String>,
    pub stance: Option<String>,
    /// The length of the page, also for HEAD, as main.py logged it.
    pub bytes: u64,
    /// Why the backend could not answer, for a `backend_error`.
    pub error: Option<String>,
}

/// The event callback for `web::Sites::on_event`.
pub fn hook(hosts: HashMap<String, Ipv4Addr>, log: Arc<Log>) -> impl Fn(&Cx, &Event) + Send + Sync + 'static {
    move |_cx, event| {
        if let Some(line) = line(&hosts, event) {
            log.write(line);
        }
    }
}

/// The log line for `event`, if main.py logged such a thing.
fn line(hosts: &HashMap<String, Ipv4Addr>, event: &Event) -> Option<Value> {
    match event {
        Event::Attached { sandbox, .. } if &*sandbox.name != LOOKUPS => {
            println!("attached {}", sandbox.name);
            None
        }
        Event::Detached { sandbox, .. } if &*sandbox.name != LOOKUPS => {
            println!("detached {}", sandbox.name);
            None
        }
        Event::Dns(d) if &*d.sandbox.name != LOOKUPS => Some(dns(hosts, d)),
        Event::Tls(t) => tls(t),
        Event::Http(h) => Some(http(hosts, h)),
        _ => None,
    }
}

/// A DNS query, as main.py's `dns_answer` logged it, or a `dns_error` for
/// one that could not be read.
fn dns(hosts: &HashMap<String, Ipv4Addr>, d: &web::Dns) -> Value {
    let (Some(name), Some(qtype)) = (&d.name, d.qtype) else {
        let error = match d.answer {
            DnsAnswer::None => "not a DNS query".to_owned(),
            _ => "malformed DNS query".to_owned(),
        };
        return json!({"type": "dns_error", "error": error});
    };
    let ip = hosts.get(name);
    json!({
        "type": "dns",
        "via": if d.tcp { "tcp" } else { "udp" },
        "name": name,
        "qtype": qtype,
        "in_world": ip.is_some(),
        // Single-label names are the container's own hostname lookups.
        "single_label": !name.contains('.'),
        "answer": if qtype == 1 { ip.map(|a| a.to_string()) } else { None },
    })
}

/// A TLS handshake that did not finish: `tls_reject` when `Sites` refused
/// the name, `tls_error` when the client gave up or broke the protocol.
fn tls(t: &web::Tls) -> Option<Value> {
    let error = match &t.outcome {
        TlsOutcome::Accepted { .. } => return None,
        TlsOutcome::Rejected => return Some(json!({"type": "tls_reject", "sni": t.sni, "in_world": false})),
        TlsOutcome::Alert(a) => format!("the client sent alert {a} ({})", alert_name(*a)),
        TlsOutcome::Failed(why) => why.chars().take(200).collect(),
        TlsOutcome::Closed => "the client closed the connection before the handshake finished".to_owned(),
        TlsOutcome::TimedOut => "the handshake did not finish within 10 seconds".to_owned(),
        _ => "the handshake failed".to_owned(),
    };
    Some(json!({"type": "tls_error", "sni": t.sni, "error": error}))
}

fn alert_name(a: u8) -> &'static str {
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

/// An HTTP request, as main.py's handler logged it: the request, then
/// what the world made of it.
fn http(hosts: &HashMap<String, Ipv4Addr>, h: &web::Http) -> Value {
    let host = h.host.clone().unwrap_or_default();
    let path = h.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let ua = h.headers.get(USER_AGENT).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    let mut entry = json!({
        "type": "http",
        "scheme": h.scheme.as_str(),
        "method": h.method.as_str(),
        "host": host,
        "sni": h.sni,
        "path": path,
        "ua": ua.unwrap_or_default(),
    });
    let fields = entry.as_object_mut().expect("an object");
    let mut bytes = h.sent;
    match h.answer {
        HttpAnswer::Handler => match h.extensions.get::<Page>() {
            Some(page) => {
                fields.insert("in_world".into(), json!(true));
                fields.insert("kind".into(), json!(page.kind));
                if page.kind != "backend_error" {
                    fields.insert("topic".into(), json!(page.topic));
                    fields.insert("source".into(), json!(page.source));
                    fields.insert("stance".into(), json!(page.stance));
                }
                if let Some(error) = &page.error {
                    fields.insert("error".into(), json!(error));
                }
                bytes = page.bytes;
            }
            None => {
                fields.insert("in_world".into(), json!(true));
                fields.insert("kind".into(), json!("other"));
            }
        },
        HttpAnswer::Redirect => {
            fields.insert("in_world".into(), json!(true));
            fields.insert("kind".into(), json!("http_redirect"));
        }
        HttpAnswer::Misdirected => {
            // A FakeWiki host asked for at the wrong address, or over a
            // connection made for another host, is still in the world.
            let in_world = hosts.contains_key(&host);
            fields.insert("in_world".into(), json!(in_world));
            if in_world {
                fields.insert("kind".into(), json!("misdirected"));
            }
        }
        HttpAnswer::Error => {
            fields.insert("in_world".into(), json!(true));
            fields.insert("kind".into(), json!("backend_error"));
        }
        // The agent gave up before the page came: main.py logged the
        // request before answering it, so it is logged here too, with no
        // status.
        HttpAnswer::Cancelled => {
            fields.insert("in_world".into(), json!(hosts.contains_key(&host)));
        }
        // No host: main.py logged an empty host, with no in_world.
        _ => {}
    }
    fields.insert("status".into(), json!(h.status.map(|s| s.as_u16())));
    fields.insert("bytes".into(), json!(bytes));
    entry
}
