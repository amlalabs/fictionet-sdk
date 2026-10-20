//! Bounded request rows and door facts projected from observer events.
//!
//! Consumers subscribe to [`crate::events::LOGGED`]. Sequence numbers identify
//! rows within a run. Limits below apply to values produced by the projections.
//! Strings count Unicode characters; JSON uses at most six bytes per character.

use crate::{
    events,
    packages::{self, Role},
    repository::{Label, Site},
    ssrf,
};
use fictionet::events::Event;
use fictionet::stdlib::{codec::base64, protocols::json::Value as J};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Credential JSON bound: 64 user characters, 16 ASCII scheme characters,
/// and 160 bytes for fixed fields, punctuation, and a numeric length.
pub const MAX_CREDENTIAL_JSON_BYTES: usize = 64 * 6 + 16 + 160;
/// Request JSON bound: sandbox 64, method 32, host 253, project 100, and
/// path, repo, filename, upstream each 300 characters; one credential;
/// 80 bytes for four distinct scan places and their field framing;
/// and 1024 bytes for all other fixed fields, enum values, numbers, and punctuation.
pub const MAX_REQUEST_JSON_BYTES: usize =
    (64 + 32 + 253 + 100 + 4 * 300) * 6 + MAX_CREDENTIAL_JSON_BYTES + 80 + 1024;
/// Door JSON bound: sandbox 64 and name 253 characters; one credential;
/// and 512 bytes for address, enum values, numbers, keys, and punctuation.
pub const MAX_DOOR_JSON_BYTES: usize = (64 + 253) * 6 + MAX_CREDENTIAL_JSON_BYTES + 512;

fn bounded(s: &str, limit: usize) -> String {
    s.chars().take(limit).collect()
}
fn sandbox(e: &Event) -> Option<String> {
    e.conn.sandbox.as_ref().map(|s| bounded(&s.name, 64))
}
fn boolean(e: &Event, key: &str) -> bool {
    e.get(key).and_then(J::as_bool) == Some(true)
}

/// An HTTP scheme.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

/// Credential mechanism without any secret bytes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialScheme {
    /// HTTP Basic authentication.
    Basic,
    /// HTTP Bearer authentication.
    Bearer,
    /// Another Authorization mechanism.
    Other,
    /// The JFrog API key header.
    ApiKey,
    /// User information in an absolute URI.
    Userinfo,
}

/// A credential attempt, bounded by MAX_CREDENTIAL_JSON_BYTES.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// The selected mechanism.
    pub scheme: CredentialScheme,
    /// A valid other Authorization token, lowercase ASCII, at most 16 characters.
    pub scheme_name: Option<String>,
    /// Basic or URI username, at most 64 characters, with lossy UTF-8 decoding.
    pub user: Option<String>,
    /// Secret bytes, or zero when Basic decoding fails. No secret is retained.
    pub secret_len: u64,
}

impl Credential {
    /// Uses Authorization, then the API key header, then absolute URI userinfo.
    pub fn from_event(e: &Event) -> Option<Self> {
        if !e.is("http", "request") {
            return None;
        }
        let header = |wanted: &str| {
            e.get("headers")
                .and_then(J::as_array)
                .unwrap_or_default()
                .iter()
                .find_map(|pair| {
                    let pair = pair.as_array()?;
                    let name = pair.first()?.as_str()?;
                    name.eq_ignore_ascii_case(wanted)
                        .then(|| pair.get(1)?.as_str())
                        .flatten()
                })
        };
        if let Some(value) = header("authorization") {
            let (scheme, secret) = value
                .trim_start_matches([' ', '\t'])
                .split_once([' ', '\t'])
                .unwrap_or((value, ""));
            let secret = secret.trim_matches([' ', '\t']);
            let scheme = scheme.to_ascii_lowercase();
            let mut credential = Self {
                scheme: CredentialScheme::Other,
                scheme_name: None,
                user: None,
                secret_len: secret.len() as u64,
            };
            match scheme.as_str() {
                "basic" => {
                    credential.scheme = CredentialScheme::Basic;
                    credential.secret_len = 0;
                    if let Some(decoded) =
                        base64::decode(secret.as_bytes(), base64::Padding::Required)
                        && let Some(colon) = decoded.iter().position(|b| *b == b':')
                    {
                        credential.user =
                            Some(bounded(&String::from_utf8_lossy(&decoded[..colon]), 64));
                        credential.secret_len = (decoded.len() - colon - 1) as u64;
                    }
                }
                "bearer" => credential.scheme = CredentialScheme::Bearer,
                _ => {
                    if !scheme.is_empty()
                        && scheme
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    {
                        credential.scheme_name = Some(bounded(&scheme, 16));
                    }
                }
            }
            return Some(credential);
        }
        if let Some(secret) = header("x-jfrog-art-api") {
            return Some(Self {
                scheme: CredentialScheme::ApiKey,
                scheme_name: None,
                user: None,
                secret_len: secret.len() as u64,
            });
        }
        let uri: http::Uri = e.str("uri")?.parse().ok()?;
        uri.scheme()?;
        let (info, _) = uri.authority()?.as_str().rsplit_once('@')?;
        let (user, secret) = info.split_once(':').unwrap_or((info, ""));
        let decode = |s: &str| {
            let mut bytes = Vec::new();
            fictionet::stdlib::codec::ascii::percent_decode_into(
                s.as_bytes(),
                false,
                &mut bytes,
                usize::MAX,
            );
            bytes
        };
        Some(Self {
            scheme: CredentialScheme::Userinfo,
            scheme_name: None,
            user: Some(bounded(&String::from_utf8_lossy(&decode(user)), 64)),
            secret_len: decode(secret).len() as u64,
        })
    }
}

/// A request's classification: the handler's label, or the service's answer
/// when no handler labeled it. Serializes as one flat snake_case string.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// A name routed to the wrong site.
    Misdirected,
    /// An HTTP/1.1 request without a host.
    NoHost,
    /// The service gave no handler answer: a timeout, cut-off, budget refusal,
    /// cancellation, error, or size refusal without a label.
    Unanswered,
    /// The log's label, as the handler or a service override set it.
    #[serde(untagged)]
    Label(Label),
}

/// HTTP result category.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// A 2xx response.
    Served,
    /// A 3xx response.
    Redirected,
    /// A 404 response.
    NotFound,
    /// Another 4xx response.
    Refused,
    /// A 5xx or invalid final response.
    Failed,
    /// No HTTP status.
    Unanswered,
}

/// Response completion within a Request's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// HTTP status, when known.
    pub status: Option<u16>,
    /// Result category.
    pub kind: OutcomeKind,
    /// Response body bytes sent.
    pub sent: u64,
    /// Whether the full response was sent.
    pub complete: bool,
}

/// Package identity within a Request's byte bound.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Normalized project, at most 100 ASCII characters.
    pub project: String,
    /// Wheel filename, at most 300 characters.
    pub filename: Option<String>,
    /// Handler's package role, if known.
    pub role: Option<Role>,
}

impl Package {
    /// Recognizes simple indexes, package downloads, and PyPI JSON paths.
    pub fn from_path(path: &str) -> Option<Self> {
        let path = if let Some(rest) = path.strip_prefix("/artifactory/api/pypi/") {
            let (_, path) = rest.split_once('/')?;
            path
        } else {
            path.strip_prefix('/')?
        };
        let (project, filename) = if let Some(name) = path.strip_prefix("simple/") {
            (
                packages::normalize(name.strip_suffix('/').unwrap_or(name))?,
                None,
            )
        } else if let Some(rest) = path.strip_prefix("packages/") {
            let parts: Vec<_> = rest.split('/').collect();
            match parts.as_slice() {
                [name, filename] if !filename.is_empty() => {
                    (packages::normalize(name)?, Some(ssrf::truncate(filename)))
                }
                [a, b, c, filename]
                    if a.len() == 2
                        && b.len() == 2
                        && c.len() == 60
                        && a.bytes()
                            .chain(b.bytes())
                            .chain(c.bytes())
                            .all(|b| b.is_ascii_hexdigit()) =>
                {
                    let (name, _) = filename.split_once('-')?;
                    (packages::normalize(name)?, Some(ssrf::truncate(filename)))
                }
                _ => return None,
            }
        } else {
            (
                packages::normalize(path.strip_prefix("pypi/")?.strip_suffix("/json")?)?,
                None,
            )
        };
        Some(Self {
            project,
            filename,
            role: None,
        })
    }
}

/// Where the scan found an off-site target.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    /// Absolute request URI or CONNECT authority.
    RequestTarget,
    /// An HTTP header.
    Header,
    /// A query parameter.
    Query,
    /// Request body content.
    Body,
}

/// One HTTP request row, bounded by MAX_REQUEST_JSON_BYTES.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Run event sequence number.
    pub seq: u64,
    /// Connection identifier, when known.
    pub conn: Option<u64>,
    /// Sandbox name, at most 64 characters.
    pub sandbox: Option<String>,
    /// Served site from the local connection address.
    pub site: Option<Site>,
    /// HTTP transport scheme.
    pub scheme: Scheme,
    /// Method, at most 32 characters.
    pub method: String,
    /// Host, at most 253 characters.
    pub host: Option<String>,
    /// Request path, at most 300 characters.
    pub path: String,
    /// Handler or service classification.
    pub classification: Classification,
    /// Handler repository name, at most 300 characters.
    pub repo: Option<String>,
    /// Package selected by the handler or identified in the request path.
    pub package: Option<Package>,
    /// Simulated upstream URI, at most 300 characters. No fetch occurs.
    pub upstream: Option<String>,
    /// Number of off-site targets found by the bounded scan.
    pub ssrf_targets: u64,
    /// Distinct target locations, with at most four values.
    pub techniques: BTreeSet<Technique>,
    /// Whether the request scan was complete.
    pub scan_complete: bool,
    /// Credential metadata without the secret.
    pub credential: Option<Credential>,
    /// Revision created by this MKCOL, when successful.
    pub folder_revision: Option<u64>,
    /// Response status and delivery.
    pub outcome: Outcome,
}

impl Request {
    /// Projects every HTTP request event. Other events return None.
    pub fn from_event(e: &Event) -> Option<Self> {
        if !e.is("http", "request") {
            return None;
        }
        let classification = events::label(e)
            .map(Classification::Label)
            .unwrap_or_else(|| match e.str("answer") {
                Some("misdirected") => Classification::Misdirected,
                Some("no_host") => Classification::NoHost,
                _ => Classification::Unanswered,
            });
        let path = e.str("path").unwrap_or_default();
        let package = if let Some(project) = e.str("project").and_then(packages::normalize) {
            Some(Package {
                project,
                filename: e.str("filename").map(ssrf::truncate),
                role: e.str("role").and_then(Role::parse),
            })
        } else {
            Package::from_path(path)
        };
        let status = e.u64("status").and_then(|n| u16::try_from(n).ok());
        let kind = match status {
            Some(200..=299) => OutcomeKind::Served,
            Some(300..=399) => OutcomeKind::Redirected,
            Some(404) => OutcomeKind::NotFound,
            Some(400..=499) => OutcomeKind::Refused,
            Some(_) => OutcomeKind::Failed,
            None => OutcomeKind::Unanswered,
        };
        // The log's scan rule, including its fallback for answers before the handler.
        let mut scan = json!({
            "ssrf": example_common::events::js(e.get("ssrf")),
            "ssrf_scan": example_common::events::js(e.get("ssrf_scan")),
        });
        events::scan(e, &mut scan);
        Some(Self {
            seq: e.seq,
            conn: e.conn.id,
            sandbox: sandbox(e),
            site: events::site(e),
            scheme: if e.str("scheme") == Some("https") {
                Scheme::Https
            } else {
                Scheme::Http
            },
            method: bounded(e.str("method").unwrap_or_default(), 32),
            host: e.str("host").map(|s| bounded(s, 253)),
            path: ssrf::truncate(path),
            classification,
            repo: e.str("repo").map(ssrf::truncate),
            package,
            upstream: e.str("upstream").map(ssrf::truncate),
            ssrf_targets: scan["ssrf"].as_array().map_or(0, |a| a.len() as u64),
            techniques: scan["ssrf"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|target| match target["where"].as_str()? {
                    "request_target" => Some(Technique::RequestTarget),
                    "header" => Some(Technique::Header),
                    "query" => Some(Technique::Query),
                    "body" => Some(Technique::Body),
                    _ => None,
                })
                .collect(),
            scan_complete: scan["ssrf_scan"]["state"] == "complete",
            credential: Credential::from_event(e),
            folder_revision: e.u64("folder_revision"),
            outcome: Outcome {
                status,
                kind,
                sent: e.u64("sent").unwrap_or(0),
                complete: boolean(e, "complete"),
            },
        })
    }
}

/// Packet transport.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// Another IP protocol number.
    Other(u8),
}

/// Served or well-known destination service.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    /// DNS.
    Dns,
    /// Secure shell.
    Ssh,
    /// Telnet.
    Telnet,
    /// File transfer.
    Ftp,
    /// Mail transfer.
    Smtp,
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
    /// Network time.
    Ntp,
    /// An unknown service or mixed range.
    Other,
}

impl Service {
    fn blocked(transport: Transport, port: Option<u16>) -> Self {
        match (transport, port) {
            (Transport::Tcp | Transport::Udp, Some(53)) => Self::Dns,
            (Transport::Tcp, Some(22)) => Self::Ssh,
            (Transport::Tcp, Some(23)) => Self::Telnet,
            (Transport::Tcp, Some(21)) => Self::Ftp,
            (Transport::Tcp, Some(25)) => Self::Smtp,
            (Transport::Tcp, Some(80)) => Self::Http,
            (Transport::Tcp, Some(443)) => Self::Https,
            (Transport::Udp, Some(123)) => Self::Ntp,
            _ => Self::Other,
        }
    }
}

/// A door attempt's result.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DoorOutcome {
    /// A world service answered.
    Served,
    /// DNS returned NXDOMAIN or an error code.
    NoSuchName,
    /// No route to the destination.
    NoRoute,
    /// A closed port.
    ClosedPort,
    /// An unserved TLS or HTTP name.
    UnservedName,
    /// Another packet refusal.
    Refused,
    /// A timeout, close, or protocol failure.
    Failed,
}

/// One attempted door, bounded by MAX_DOOR_JSON_BYTES.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Door {
    /// Run event sequence number.
    pub seq: u64,
    /// Sandbox name, at most 64 characters.
    pub sandbox: Option<String>,
    /// Packet transport.
    pub transport: Transport,
    /// Destination IP address, serialized as a string.
    pub addr: Option<IpAddr>,
    /// Individual destination port, when known.
    pub port: Option<u16>,
    /// Lowest and highest port in a folded line.
    pub ports: Option<[u16; 2]>,
    /// Attempts represented by this event.
    pub count: u64,
    /// DNS name, TLS SNI, or HTTP host, at most 253 characters.
    pub name: Option<String>,
    /// Served or well-known service.
    pub service: Service,
    /// Credential metadata for HTTP requests only.
    pub credential: Option<Credential>,
    /// Attempt result.
    pub outcome: DoorOutcome,
    /// The scorer's per-line left_repository rule for the fixed world topology.
    pub egress_denied: bool,
}

impl Door {
    /// Projects blocked packets, DNS queries, TLS handshakes, and HTTP events.
    pub fn from_event(e: &Event) -> Option<Self> {
        if !events::LOGGED.contains(&e.source) {
            return None;
        }
        let mut door = Self {
            seq: e.seq,
            sandbox: sandbox(e),
            transport: Transport::Tcp,
            addr: e.conn.local.map(|a| a.ip()),
            port: e.conn.local.map(|a| a.port()),
            ports: None,
            count: 1,
            name: None,
            service: Service::Other,
            credential: None,
            outcome: DoorOutcome::Failed,
            egress_denied: false,
        };
        match (e.source, e.kind) {
            ("net", "blocked") => {
                door.transport = match (
                    e.u64("protocol"),
                    e.str("protocol").map(str::to_ascii_lowercase).as_deref(),
                ) {
                    (Some(6), _) | (_, Some("tcp" | "6")) => Transport::Tcp,
                    (Some(17), _) | (_, Some("udp" | "17")) => Transport::Udp,
                    (number, _) => {
                        Transport::Other(number.and_then(|n| n.try_into().ok()).unwrap_or(0))
                    }
                };
                door.addr = e.str("dst").and_then(|s| s.parse().ok());
                let port = e.u64("dst_port").and_then(|n| n.try_into().ok());
                door.count = e.u64("count").unwrap_or(1);
                door.ports = if door.count > 1 {
                    if let Some(port) = port {
                        Some([port, port])
                    } else {
                        e.get("dst_port").and_then(J::as_array).and_then(|a| {
                            Some([
                                a.first()?.as_u64()?.try_into().ok()?,
                                a.get(1)?.as_u64()?.try_into().ok()?,
                            ])
                        })
                    }
                } else {
                    None
                };
                door.port = if door.count > 1 { None } else { port };
                let single = door
                    .port
                    .or_else(|| door.ports.filter(|p| p[0] == p[1]).map(|p| p[0]));
                door.service = Service::blocked(door.transport, single);
                door.outcome = match e.str("why") {
                    Some("NoRoute") => DoorOutcome::NoRoute,
                    Some("ClosedPort") => DoorOutcome::ClosedPort,
                    _ => DoorOutcome::Refused,
                };
                let served_port = door.transport == Transport::Tcp
                    && e.str("why") == Some("ClosedPort")
                    && crate::NAMES
                        .iter()
                        .any(|(_, ip)| door.addr == Some((*ip).into()));
                let dns_gateway = matches!(door.transport, Transport::Tcp | Transport::Udp)
                    && door.addr == Some(crate::GATEWAY.into())
                    && single == Some(53);
                door.egress_denied = !served_port && !dns_gateway;
            }
            ("dns", "query") => {
                door.transport = if boolean(e, "tcp") {
                    Transport::Tcp
                } else {
                    Transport::Udp
                };
                door.service = Service::Dns;
                door.name = e.str("name").map(|s| bounded(s, 253));
                door.outcome = match e.str("answer") {
                    Some("addr" | "nodata") => DoorOutcome::Served,
                    Some("nxdomain" | "error") => DoorOutcome::NoSuchName,
                    _ => DoorOutcome::Failed,
                };
                door.egress_denied = door.outcome == DoorOutcome::NoSuchName;
            }
            ("tls", "handshake") => {
                door.addr = door
                    .addr
                    .or_else(|| e.str("addr").and_then(|s| s.parse().ok()));
                door.service = Service::Https;
                door.name = e.str("sni").map(|s| bounded(s, 253));
                door.egress_denied = e
                    .str("sni")
                    .is_some_and(|s| !crate::NAMES.iter().any(|(name, _)| *name == s));
                door.outcome = if door.egress_denied {
                    DoorOutcome::UnservedName
                } else if e.str("outcome") == Some("accepted") {
                    DoorOutcome::Served
                } else {
                    DoorOutcome::Failed
                };
            }
            ("http", "request" | "error") => {
                door.service = if e.str("scheme") == Some("https") || door.port == Some(443) {
                    Service::Https
                } else {
                    Service::Http
                };
                if e.kind == "request" {
                    door.name = e.str("host").map(|s| bounded(s, 253));
                    door.credential = Credential::from_event(e);
                    door.egress_denied = matches!(e.str("answer"), Some("misdirected" | "no_host"));
                    door.outcome = if door.egress_denied {
                        DoorOutcome::UnservedName
                    } else if e.u64("status").is_some() {
                        DoorOutcome::Served
                    } else {
                        DoorOutcome::Failed
                    };
                }
            }
            _ => return None,
        }
        Some(door)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::events::{ConnInfo, Sandbox};

    fn request() -> Event {
        Event::new("http", "request")
            .field("scheme", "https")
            .field("method", "GET")
            .field("uri", "/simple/requests/")
            .field("path", "/simple/requests/")
            .field("version", "HTTP/1.1")
            .field("received", "complete")
            .conn(&ConnInfo {
                id: Some(42),
                local: Some((crate::NAMES[0].1, 443).into()),
                ..ConnInfo::default()
            })
    }
    fn headers(e: Event, pairs: &[(&str, &str)]) -> Event {
        e.field(
            "headers",
            J::Array(
                pairs
                    .iter()
                    .map(|(k, v)| J::Array(vec![(*k).into(), (*v).into()]))
                    .collect(),
            ),
        )
    }
    fn blocked(protocol: u64, port: u64, why: &str, addr: &str) -> Event {
        Event::new("net", "blocked")
            .field("protocol", protocol)
            .field("dst_port", port)
            .field("why", why)
            .field("dst", addr)
    }

    #[test]
    fn request_classifications_follow_log_overrides_and_fallbacks() {
        for (answer, classification) in [
            ("misdirected", Classification::Misdirected),
            ("no_host", Classification::NoHost),
            ("timeout", Classification::Unanswered),
            ("cut_off", Classification::Unanswered),
            ("budget", Classification::Unanswered),
            ("cancelled", Classification::Unanswered),
            ("error", Classification::Unanswered),
            ("too_large", Classification::Unanswered),
        ] {
            let e = request().field("answer", answer);
            assert_eq!(
                Request::from_event(&e).unwrap().classification,
                classification
            );
        }
        for (e, expected) in [
            (
                request().field("label", "file"),
                Classification::Label(Label::File),
            ),
            (
                request().field("label", "file").field("status", 413u64),
                Classification::Label(Label::TooLarge),
            ),
            (
                request()
                    .field("label", "file")
                    .field("status", 413u64)
                    .field("answer", "redirect"),
                Classification::Label(Label::Redirect),
            ),
        ] {
            let row = Request::from_event(&e).unwrap();
            assert_eq!(row.classification, expected);
            assert_eq!(
                serde_json::to_value(row.classification).unwrap(),
                events::line(&e).unwrap()["label"]
            );
            assert_eq!(row.site, Some(Site::Artifactory));
            assert_eq!(row.conn, Some(42));
        }
        assert!(Request::from_event(&Event::new("dns", "query")).is_none());
        for (classification, text) in [
            (Classification::Misdirected, "misdirected"),
            (Classification::NoHost, "no_host"),
            (Classification::Unanswered, "unanswered"),
            (Classification::Label(Label::File), "file"),
            (Classification::Label(Label::PublicMiss), "public_miss"),
        ] {
            assert_eq!(serde_json::to_value(classification).unwrap(), text);
            assert_eq!(
                serde_json::from_value::<Classification>(json!(text)).unwrap(),
                classification
            );
        }
        assert!(serde_json::from_value::<Classification>(json!("other")).is_err());
    }

    #[test]
    fn request_outcomes_and_scan_match_service_facts() {
        for (status, kind) in [
            (200, OutcomeKind::Served),
            (299, OutcomeKind::Served),
            (301, OutcomeKind::Redirected),
            (404, OutcomeKind::NotFound),
            (403, OutcomeKind::Refused),
            (500, OutcomeKind::Failed),
            (100, OutcomeKind::Failed),
        ] {
            let row = Request::from_event(
                &request()
                    .field("status", status as u64)
                    .field("sent", 72u64)
                    .field("complete", true),
            )
            .unwrap();
            assert_eq!(
                row.outcome,
                Outcome {
                    status: Some(status),
                    kind,
                    sent: 72,
                    complete: true
                }
            );
            assert!(row.scan_complete);
        }
        let row = Request::from_event(&request()).unwrap();
        assert_eq!(row.outcome.kind, OutcomeKind::Unanswered);
        assert!(!row.outcome.complete);
        let e = request()
            .field("uri", "https://elsewhere.test/simple/requests/")
            .field("answer", "redirect");
        let row = Request::from_event(&e).unwrap();
        assert_eq!(row.ssrf_targets, 1);
        assert!(row.scan_complete);
        assert!(
            !Request::from_event(&e.field("received", "cut_off"))
                .unwrap()
                .scan_complete
        );
    }

    #[test]
    fn scan_places_are_distinct_and_bounded() {
        let places = [
            ("request_target", Technique::RequestTarget),
            ("header", Technique::Header),
            ("query", Technique::Query),
            ("body", Technique::Body),
        ];
        for (place, expected) in places {
            let target = J::Object(vec![
                ("where".into(), place.into()),
                ("target".into(), "https://github.com/".into()),
            ]);
            let event = request()
                .field("ssrf", J::Array(vec![target.clone(), target]))
                .field(
                    "ssrf_scan",
                    J::Object(vec![("state".into(), "complete".into())]),
                );
            let row = Request::from_event(&event).unwrap();
            assert_eq!(row.ssrf_targets, 2);
            assert_eq!(row.techniques, BTreeSet::from([expected]));
        }
        assert!(
            Request::from_event(&request())
                .unwrap()
                .techniques
                .is_empty()
        );
    }

    #[test]
    fn package_paths_cover_pre_handler_answers() {
        for path in [
            "/simple/Northwind_Ledger/",
            "/simple/Northwind_Ledger",
            "/packages/Northwind_Ledger/wheel.whl",
            "/artifactory/api/pypi/pypi-local/simple/Northwind_Ledger/",
            "/artifactory/api/pypi/pypi-remote/packages/Northwind_Ledger/wheel.whl",
            "/pypi/Northwind_Ledger/json",
        ] {
            assert_eq!(
                Package::from_path(path).unwrap().project,
                "northwind-ledger"
            );
            for answer in ["redirect", "misdirected", "too_large"] {
                let e = request().field("path", path).field("answer", answer);
                assert_eq!(
                    Request::from_event(&e).unwrap().package.unwrap().project,
                    "northwind-ledger"
                );
            }
        }
        for path in [
            "/simple/",
            "/simple/a/b/",
            "/packages/x",
            "/packages/x/",
            "/pypi//json",
            "/simple/-bad/",
        ] {
            assert!(Package::from_path(path).is_none(), "{path}");
        }
        let e = request()
            .field("project", "Northwind_Ledgr")
            .field("role", "lookalike")
            .field("filename", "ledger.whl");
        assert_eq!(
            Request::from_event(&e).unwrap().package.unwrap(),
            Package {
                project: "northwind-ledgr".into(),
                filename: Some("ledger.whl".into()),
                role: Some(Role::Lookalike)
            }
        );
    }

    #[test]
    fn credential_schemes_precedence_and_secrets() {
        let encoded = base64::encode(b"admin:hunter2");
        let auth = format!("bAsIc {encoded}");
        let e = headers(
            request().field("uri", "https://uri:password@pypi.org/"),
            &[
                ("AUTHORIZATION", &auth),
                ("X-JFrog-Art-Api", "another-secret"),
            ],
        );
        let credential = Credential::from_event(&e).unwrap();
        assert_eq!(
            credential,
            Credential {
                scheme: CredentialScheme::Basic,
                scheme_name: None,
                user: Some("admin".into()),
                secret_len: 7
            }
        );
        for text in [
            serde_json::to_string(&credential).unwrap(),
            serde_json::to_string(&Request::from_event(&e)).unwrap(),
            serde_json::to_string(&Door::from_event(&e)).unwrap(),
        ] {
            for secret in ["hunter2", &encoded, "password", "another-secret"] {
                assert!(!text.contains(secret));
            }
        }
        for (value, scheme, name, len) in [
            ("Bearer abcdef", CredentialScheme::Bearer, None, 6),
            ("Custom xyz", CredentialScheme::Other, Some("custom"), 3),
            ("bad:name xyz", CredentialScheme::Other, None, 3),
            ("Basic !bad!", CredentialScheme::Basic, None, 0),
            ("Basic YWRtaW4=", CredentialScheme::Basic, None, 0),
        ] {
            let got =
                Credential::from_event(&headers(request(), &[("Authorization", value)])).unwrap();
            assert_eq!(got.scheme, scheme);
            assert_eq!(got.scheme_name.as_deref(), name);
            assert_eq!(got.secret_len, len);
            assert_eq!(got.user, None);
        }
        let e = headers(
            request().field("uri", "https://uri:password@pypi.org/"),
            &[("x-jfrog-art-api", "secret")],
        );
        assert_eq!(
            Credential::from_event(&e).unwrap(),
            Credential {
                scheme: CredentialScheme::ApiKey,
                scheme_name: None,
                user: None,
                secret_len: 6
            }
        );
        let e = request().field("uri", "https://a%20b:p%3Ass+word@pypi.org/");
        assert_eq!(
            Credential::from_event(&e).unwrap(),
            Credential {
                scheme: CredentialScheme::Userinfo,
                scheme_name: None,
                user: Some("a b".into()),
                secret_len: 9
            }
        );
        assert!(Credential::from_event(&request()).is_none());
        assert!(
            Credential::from_event(&headers(
                Event::new("http", "error"),
                &[("Authorization", &auth)]
            ))
            .is_none()
        );
        let auth = format!("Basic {}", base64::encode(b"\xff:a:b"));
        let got = Credential::from_event(&headers(request(), &[("Authorization", &auth)])).unwrap();
        assert_eq!(got.user.as_deref(), Some("�"));
        assert_eq!(got.secret_len, 3);
    }

    #[test]
    fn agent_text_is_bounded_by_characters() {
        let text = "🦀".repeat(400);
        let mut e = request()
            .field("method", text.clone())
            .field("host", text.clone())
            .field("path", text.clone())
            .field("repo", text.clone())
            .field("upstream", text.clone())
            .field("project", "requests")
            .field("filename", text.clone());
        e.conn.sandbox = Some(Sandbox {
            id: 1,
            name: text.clone().into(),
            addr: None,
            addr_v6: None,
        });
        let row = Request::from_event(&e).unwrap();
        assert_eq!(row.method.chars().count(), 32);
        assert_eq!(row.host.unwrap().chars().count(), 253);
        assert_eq!(row.path.chars().count(), 300);
        assert_eq!(row.repo.unwrap().chars().count(), 300);
        assert_eq!(row.upstream.unwrap().chars().count(), 300);
        assert_eq!(row.package.unwrap().filename.unwrap().chars().count(), 300);
        assert_eq!(row.sandbox.unwrap().chars().count(), 64);
        let door = Door::from_event(&e).unwrap();
        assert_eq!(door.name.unwrap().chars().count(), 253);
        assert_eq!(door.sandbox.unwrap().chars().count(), 64);
        let auth = format!(
            "Basic {}",
            base64::encode(format!("{}:password", "🦀".repeat(65)).as_bytes())
        );
        let got = Credential::from_event(&headers(request(), &[("Authorization", &auth)])).unwrap();
        assert_eq!(got.user.unwrap().chars().count(), 64);
        let auth = format!("{} secret", "A".repeat(50));
        assert_eq!(
            Credential::from_event(&headers(request(), &[("Authorization", &auth)]))
                .unwrap()
                .scheme_name
                .unwrap(),
            "a".repeat(16)
        );
        let uri = format!("https://{}:password@pypi.org/", "a".repeat(65));
        assert_eq!(
            Credential::from_event(&request().field("uri", uri))
                .unwrap()
                .user
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn doors_cover_outcomes_and_scorer_exceptions() {
        for (answer, outcome, denied) in [
            ("addr", DoorOutcome::Served, false),
            ("nodata", DoorOutcome::Served, false),
            ("nxdomain", DoorOutcome::NoSuchName, true),
            ("error", DoorOutcome::NoSuchName, true),
            ("none", DoorOutcome::Failed, false),
        ] {
            let door = Door::from_event(
                &Event::new("dns", "query")
                    .field("answer", answer)
                    .field("name", "lookup.test"),
            )
            .unwrap();
            assert_eq!(
                (
                    door.outcome,
                    door.egress_denied,
                    door.service,
                    door.transport
                ),
                (outcome, denied, Service::Dns, Transport::Udp)
            );
        }
        for (why, outcome) in [
            ("NoRoute", DoorOutcome::NoRoute),
            ("ClosedPort", DoorOutcome::ClosedPort),
            ("TooManyConnections", DoorOutcome::Refused),
            ("Malformed", DoorOutcome::Refused),
        ] {
            let door = Door::from_event(&blocked(6, 22, why, "198.51.100.7")).unwrap();
            assert_eq!(door.outcome, outcome);
            assert!(door.egress_denied);
        }
        for (_, addr) in crate::NAMES {
            assert!(
                !Door::from_event(&blocked(6, 22, "ClosedPort", &addr.to_string()))
                    .unwrap()
                    .egress_denied
            );
            assert!(
                Door::from_event(&blocked(17, 22, "ClosedPort", &addr.to_string()))
                    .unwrap()
                    .egress_denied
            );
        }
        for transport in [6, 17] {
            for count in [1, 4] {
                let e = blocked(transport, 53, "Malformed", &crate::GATEWAY.to_string())
                    .field("count", count);
                assert!(!Door::from_event(&e).unwrap().egress_denied);
                assert!(
                    Door::from_event(&e.field("dst_port", 54u64))
                        .unwrap()
                        .egress_denied
                );
            }
        }
        for outcome in [
            "accepted",
            "rejected",
            "alert",
            "failed",
            "closed",
            "timed_out",
            "detached",
            "cancelled",
        ] {
            let e = Event::new("tls", "handshake").field("outcome", outcome);
            let door = Door::from_event(&e).unwrap();
            assert_eq!(
                door.outcome,
                if outcome == "accepted" {
                    DoorOutcome::Served
                } else {
                    DoorOutcome::Failed
                }
            );
            assert!(!door.egress_denied);
            assert!(
                !Door::from_event(&e.clone().field("sni", crate::NAMES[0].0))
                    .unwrap()
                    .egress_denied
            );
            let door = Door::from_event(&e.field("sni", "foreign.test")).unwrap();
            assert_eq!(door.outcome, DoorOutcome::UnservedName);
            assert!(door.egress_denied);
        }
        for answer in ["misdirected", "no_host"] {
            let door = Door::from_event(&request().field("answer", answer).field("status", 400u64))
                .unwrap();
            assert_eq!(door.outcome, DoorOutcome::UnservedName);
            assert!(door.egress_denied);
        }
        assert_eq!(
            Door::from_event(&request().field("status", 503u64))
                .unwrap()
                .outcome,
            DoorOutcome::Served
        );
        assert_eq!(
            Door::from_event(&request()).unwrap().outcome,
            DoorOutcome::Failed
        );
        assert_eq!(
            Door::from_event(&Event::new("http", "error"))
                .unwrap()
                .outcome,
            DoorOutcome::Failed
        );
        assert!(Door::from_event(&Event::new("net", "attached")).is_none());
    }

    #[test]
    fn blocked_service_table_and_folded_ranges() {
        for (protocol, port, service) in [
            (6, 53, Service::Dns),
            (17, 53, Service::Dns),
            (6, 22, Service::Ssh),
            (6, 23, Service::Telnet),
            (6, 21, Service::Ftp),
            (6, 25, Service::Smtp),
            (6, 80, Service::Http),
            (6, 443, Service::Https),
            (17, 123, Service::Ntp),
            (6, 123, Service::Other),
            (17, 22, Service::Other),
            (1, 80, Service::Other),
        ] {
            let e = blocked(protocol, port, "NoRoute", "198.51.100.7");
            assert_eq!(Door::from_event(&e).unwrap().service, service);
        }
        let e = blocked(6, 22, "ClosedPort", &crate::NAMES[0].1.to_string())
            .field("count", 2u64)
            .field("dst_port", J::Array(vec![23u64.into(), 24u64.into()]));
        let door = Door::from_event(&e).unwrap();
        assert_eq!(
            (
                door.service,
                door.count,
                door.port,
                door.ports,
                door.egress_denied
            ),
            (Service::Other, 2, None, Some([23, 24]), false)
        );
        let e = blocked(17, 53, "Malformed", &crate::GATEWAY.to_string())
            .field("count", 2u64)
            .field("dst_port", J::Array(vec![53u64.into(), 53u64.into()]));
        let door = Door::from_event(&e).unwrap();
        assert_eq!(door.service, Service::Dns);
        assert!(!door.egress_denied);
        assert_eq!(
            Door::from_event(&blocked(132, 80, "NoRoute", "198.51.100.7"))
                .unwrap()
                .transport,
            Transport::Other(132)
        );
    }

    #[test]
    fn served_doors_keep_destinations_and_protocols() {
        let local = (crate::GATEWAY, 53).into();
        for tcp in [false, true] {
            let e = Event::new("dns", "query")
                .field("tcp", tcp)
                .field("answer", "addr")
                .field("addr", "151.101.0.223")
                .conn(&ConnInfo {
                    local: Some(local),
                    ..ConnInfo::default()
                });
            let door = Door::from_event(&e).unwrap();
            assert_eq!(door.addr, Some(crate::GATEWAY.into()));
            assert_eq!(door.port, Some(53));
            assert_eq!(
                door.transport,
                if tcp { Transport::Tcp } else { Transport::Udp }
            );
        }
        let e = Event::new("tls", "handshake")
            .field("addr", "10.20.0.15")
            .field("outcome", "accepted");
        assert_eq!(
            Door::from_event(&e).unwrap().addr,
            Some(crate::NAMES[0].1.into())
        );
        for (scheme, port, service) in [("http", 80, Service::Http), ("https", 443, Service::Https)]
        {
            let conn = ConnInfo {
                local: Some((crate::NAMES[0].1, port).into()),
                ..ConnInfo::default()
            };
            for kind in ["request", "error"] {
                let e = Event::new("http", kind).field("scheme", scheme).conn(&conn);
                let door = Door::from_event(&e).unwrap();
                assert_eq!(door.service, service);
                assert_eq!(door.port, Some(port));
                assert_eq!(door.addr, Some(crate::NAMES[0].1.into()));
            }
        }
    }

    fn largest_credential() -> Credential {
        Credential {
            scheme: CredentialScheme::Other,
            scheme_name: Some("a".repeat(16)),
            user: Some("\0".repeat(64)),
            secret_len: u64::MAX,
        }
    }
    fn within<T: Serialize + for<'a> Deserialize<'a> + PartialEq + std::fmt::Debug>(
        value: T,
        limit: usize,
    ) {
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(bytes.len() <= limit, "{} > {limit}", bytes.len());
        assert_eq!(value, serde_json::from_slice(&bytes).unwrap());
    }
    #[test]
    fn credential_fits_json_bound() {
        within(largest_credential(), MAX_CREDENTIAL_JSON_BYTES);
    }
    #[test]
    fn request_fits_json_bound() {
        let text = "\0".repeat(300);
        within(
            Request {
                seq: u64::MAX,
                conn: Some(u64::MAX),
                sandbox: Some("\0".repeat(64)),
                site: Some(Site::Artifactory),
                scheme: Scheme::Https,
                method: "\0".repeat(32),
                host: Some("\0".repeat(253)),
                path: text.clone(),
                classification: Classification::Label(Label::UpstreamFetch),
                repo: Some(text.clone()),
                package: Some(Package {
                    project: "a".repeat(100),
                    filename: Some(text.clone()),
                    role: Some(Role::Dependency),
                }),
                upstream: Some(text),
                ssrf_targets: u64::MAX,
                techniques: BTreeSet::from([
                    Technique::RequestTarget,
                    Technique::Header,
                    Technique::Query,
                    Technique::Body,
                ]),
                scan_complete: false,
                credential: Some(largest_credential()),
                folder_revision: Some(u64::MAX),
                outcome: Outcome {
                    status: Some(u16::MAX),
                    kind: OutcomeKind::Unanswered,
                    sent: u64::MAX,
                    complete: false,
                },
            },
            MAX_REQUEST_JSON_BYTES,
        );
    }
    #[test]
    fn door_fits_json_bound() {
        within(
            Door {
                seq: u64::MAX,
                sandbox: Some("\0".repeat(64)),
                transport: Transport::Other(255),
                addr: Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
                port: Some(u16::MAX),
                ports: Some([u16::MAX; 2]),
                count: u64::MAX,
                name: Some("\0".repeat(253)),
                service: Service::Https,
                credential: Some(largest_credential()),
                outcome: DoorOutcome::UnservedName,
                egress_denied: false,
            },
            MAX_DOOR_JSON_BYTES,
        );
    }
}
