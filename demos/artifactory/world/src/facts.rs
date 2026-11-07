//! Bounded request rows and door facts projected from observer events.
//!
//! The world delivers typed [`Observation`] values. Sequence numbers identify
//! rows within a run. Limits below apply to values produced by the projections.
//! Strings count Unicode characters; JSON uses at most six bytes per character.

use crate::{
    ServedNames, events,
    packages::{self, Role},
    repository::{Label, Site},
    ssrf,
};
use fictionet::stdlib::codec::base64;
use fictionet::stdlib::services::{
    dns,
    serve::{self, ConnInfo},
    tls,
};
use fictionet::stdlib::web::httpd;
use fictionet::stdlib::world::net;
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
fn sandbox(conn: &ConnInfo) -> Option<String> {
    conn.sandbox.as_ref().map(|s| bounded(&s.name, 64))
}

/// Typed facts delivered to the app alongside the world's JSON log.
#[derive(Clone, Debug)]
pub struct Observation {
    /// When the protocol operation began or completed, as reported by its owner.
    pub at: fictionet::time::Instant,
    /// Connection and sandbox attribution.
    pub conn: ConnInfo,
    /// The HTTP exchange, when this observation describes one.
    pub request: Option<Request>,
    /// The destination attempt and its result.
    pub door: Option<Door>,
}

fn host(e: &httpd::Observation) -> Option<String> {
    httpd::request_host(&http::Request::from_parts(e.request.clone(), ()))
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
    pub fn from_http(e: &httpd::Observation) -> Option<Self> {
        let header = |wanted: &str| {
            e.request
                .headers
                .get(wanted)
                .and_then(|value| value.to_str().ok())
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
        let uri = &e.request.uri;
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
    /// Projects one HTTP exchange into a bounded request row.
    pub fn from_http(seq: u64, e: &httpd::Observation) -> Self {
        let page = e
            .response
            .as_ref()
            .and_then(|r| r.extensions.get::<crate::repository::PageFacts>());
        let details = page.map(|p| &p.details);
        let answer = e
            .response
            .as_ref()
            .and_then(|r| r.extensions.get::<httpd::Answer>());
        let classification = events::label(e)
            .map(Classification::Label)
            .unwrap_or(match answer {
                Some(httpd::Answer::Misdirected) => Classification::Misdirected,
                Some(httpd::Answer::NoHost) => Classification::NoHost,
                _ => Classification::Unanswered,
            });
        let path = e.request.uri.path();
        let package = if let Some(project) = details
            .and_then(|d| d.project.as_deref())
            .and_then(packages::normalize)
        {
            Some(Package {
                project,
                filename: details
                    .and_then(|d| d.filename.as_deref())
                    .map(ssrf::truncate),
                role: details.and_then(|d| d.role),
            })
        } else {
            Package::from_path(path)
        };
        let status = e.response.as_ref().map(|r| r.status.as_u16());
        let kind = match status {
            Some(200..=299) => OutcomeKind::Served,
            Some(300..=399) => OutcomeKind::Redirected,
            Some(404) => OutcomeKind::NotFound,
            Some(400..=499) => OutcomeKind::Refused,
            Some(_) => OutcomeKind::Failed,
            None => OutcomeKind::Unanswered,
        };
        let mut scan = json!({});
        events::scan(e, &mut scan);
        Self {
            seq,
            conn: e.conn.id,
            sandbox: sandbox(&e.conn),
            site: events::site(&e.conn),
            scheme: if e.conn.tls {
                Scheme::Https
            } else {
                Scheme::Http
            },
            method: bounded(e.request.method.as_str(), 32),
            host: host(e).map(|s| bounded(&s, 253)),
            path: ssrf::truncate(path),
            classification,
            repo: details.and_then(|d| d.repo.as_deref()).map(ssrf::truncate),
            package,
            upstream: details
                .and_then(|d| d.upstream.as_deref())
                .map(ssrf::truncate),
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
            credential: Credential::from_http(e),
            folder_revision: details.and_then(|d| d.folder_revision),
            outcome: Outcome {
                status,
                kind,
                sent: e.sent,
                complete: e.complete,
            },
        }
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
    /// A TLS or HTTP name the world does not serve.
    UnservedName,
    /// Another packet refusal.
    Refused,
    /// A timeout, close, or protocol failure, or one of the world's TLS
    /// names asked for at another of its addresses.
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
    /// Whether the attempt targeted a destination outside the repository world.
    pub egress_denied: bool,
}

impl Door {
    fn new(seq: u64, conn: &ConnInfo) -> Self {
        Self {
            seq,
            sandbox: sandbox(conn),
            transport: Transport::Tcp,
            addr: conn.local.map(|a| a.ip()),
            port: conn.local.map(|a| a.port()),
            ports: None,
            count: 1,
            name: None,
            service: Service::Other,
            credential: None,
            outcome: DoorOutcome::Failed,
            egress_denied: false,
        }
    }
    /// One refused packet. The callback reports each packet individually.
    pub fn from_refused(seq: u64, e: &net::RefusedPacket) -> Self {
        let mut door = Self::new(seq, &e.conn);
        door.transport = match e.protocol {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            n => Transport::Other(n),
        };
        door.addr = Some(e.to);
        door.service = Service::blocked(door.transport, door.port);
        door.outcome = match e.reason {
            net::Refusal::NoRoute => DoorOutcome::NoRoute,
            net::Refusal::ClosedPort => DoorOutcome::ClosedPort,
            net::Refusal::Policy => DoorOutcome::Refused,
        };
        let served_port = door.transport == Transport::Tcp
            && e.reason == net::Refusal::ClosedPort
            && crate::NAMES.iter().any(|(_, ip)| e.to == IpAddr::V4(*ip));
        let dns_gateway = matches!(door.transport, Transport::Tcp | Transport::Udp)
            && e.to == IpAddr::V4(crate::GATEWAY)
            && door.port == Some(53);
        door.egress_denied = !served_port && !dns_gateway;
        door
    }
    /// A DNS reply; engine events that are not replies create no door fact.
    pub fn from_dns(seq: u64, e: &dns::Event) -> Option<Self> {
        use fictionet::stdlib::protocols::dns::op::ResponseCode;
        let dns::Event::Reply {
            server,
            client,
            question,
            rcode,
            ..
        } = e
        else {
            return None;
        };
        let conn = ConnInfo {
            id: client.connection,
            sandbox: client.sandbox.clone(),
            local: Some(*server),
            peer: Some(client.peer),
            ..Default::default()
        };
        let mut door = Self::new(seq, &conn);
        door.transport = if client.transport == serve::Transport::Tcp {
            Transport::Tcp
        } else {
            Transport::Udp
        };
        door.service = Service::Dns;
        door.name = question
            .as_ref()
            .map(|q| bounded(q.name().to_utf8().trim_end_matches('.'), 253));
        door.outcome = if *rcode == ResponseCode::NoError {
            DoorOutcome::Served
        } else {
            DoorOutcome::NoSuchName
        };
        door.egress_denied = door.outcome == DoorOutcome::NoSuchName;
        Some(door)
    }
    /// A TLS handshake's result, including rejection of unserved names.
    pub fn from_tls(seq: u64, e: &net::TlsObservation, names: &ServedNames) -> Self {
        let mut door = Self::new(seq, &e.conn);
        door.service = Service::Https;
        door.name = e.conn.sni.as_deref().map(|s| bounded(s, 253));
        door.egress_denied = matches!(e.result, Err(tls::HandshakeError::Rejected))
            && e.conn
                .sni
                .as_deref()
                .is_some_and(|name| !names.contains(name));
        door.outcome = if e.result.is_ok() {
            DoorOutcome::Served
        } else if door.egress_denied {
            DoorOutcome::UnservedName
        } else {
            DoorOutcome::Failed
        };
        door
    }
    /// A dispatched HTTP exchange, including interrupted responses.
    pub fn from_http(seq: u64, e: &httpd::Observation) -> Self {
        let mut door = Self::new(seq, &e.conn);
        door.service = if e.conn.tls || door.port == Some(443) {
            Service::Https
        } else {
            Service::Http
        };
        door.name = host(e).map(|s| bounded(&s, 253));
        door.credential = Credential::from_http(e);
        door.egress_denied = matches!(
            e.response
                .as_ref()
                .and_then(|r| r.extensions.get::<httpd::Answer>()),
            Some(httpd::Answer::Misdirected | httpd::Answer::NoHost)
        );
        door.outcome = if door.egress_denied {
            DoorOutcome::UnservedName
        } else if e.response.is_some() {
            DoorOutcome::Served
        } else {
            DoorOutcome::Failed
        };
        door
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{PageDetails, PageFacts};
    use fictionet::stdlib::services::serve::Sandbox;
    use fictionet::time::Instant;

    fn request() -> httpd::Observation {
        httpd::Observation {
            at: Instant::ZERO,
            conn: ConnInfo {
                id: Some(42),
                local: Some((crate::NAMES[0].1, 443).into()),
                tls: true,
                ..Default::default()
            },
            request: http::Request::builder()
                .uri("/simple/requests/")
                .body(())
                .unwrap()
                .into_parts()
                .0,
            response: None,
            received: httpd::Received::Complete,
            sent: 0,
            complete: false,
        }
    }
    fn headers(mut e: httpd::Observation, pairs: &[(&str, &str)]) -> httpd::Observation {
        for (name, value) in pairs {
            e.request.headers.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        e
    }
    fn uri(mut e: httpd::Observation, uri: impl AsRef<str>) -> httpd::Observation {
        e.request.uri = uri.as_ref().parse().unwrap();
        e
    }
    fn response(
        mut e: httpd::Observation,
        status: u16,
        answer: Option<httpd::Answer>,
    ) -> httpd::Observation {
        let mut parts = http::Response::builder()
            .status(status)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        if let Some(answer) = answer {
            parts.extensions.insert(answer);
        }
        e.response = Some(parts);
        e
    }
    fn page(e: &mut httpd::Observation) -> &mut PageFacts {
        let parts = e
            .response
            .get_or_insert_with(|| http::Response::new(()).into_parts().0);
        if parts.extensions.get::<PageFacts>().is_none() {
            parts.extensions.insert(PageFacts {
                site: Site::Artifactory,
                label: Label::File,
                body_bytes: Some(0),
                ssrf: vec![],
                details: PageDetails::default(),
            });
        }
        parts.extensions.get_mut::<PageFacts>().unwrap()
    }
    fn blocked(protocol: u8, port: u16, reason: net::Refusal, addr: IpAddr) -> net::RefusedPacket {
        net::RefusedPacket {
            at: Instant::ZERO,
            conn: ConnInfo {
                local: Some((addr, port).into()),
                ..Default::default()
            },
            from: "10.0.0.2".parse().unwrap(),
            to: addr,
            protocol,
            reason,
        }
    }

    #[test]
    fn request_classifications_follow_log_overrides_and_fallbacks() {
        for (answer, classification) in [
            (httpd::Answer::Misdirected, Classification::Misdirected),
            (httpd::Answer::NoHost, Classification::NoHost),
        ] {
            assert_eq!(
                Request::from_http(1, &response(request(), 400, Some(answer))).classification,
                classification
            );
        }
        for received in [
            httpd::Received::Complete,
            httpd::Received::Timeout,
            httpd::Received::CutOff,
            httpd::Received::Budget,
            httpd::Received::TooLarge,
        ] {
            let mut e = request();
            e.received = received;
            assert_eq!(
                Request::from_http(1, &e).classification,
                Classification::Unanswered
            );
        }
        let mut file = response(request(), 200, None);
        page(&mut file);
        let mut large = response(request(), 200, None);
        page(&mut large);
        large.response.as_mut().unwrap().status = http::StatusCode::PAYLOAD_TOO_LARGE;
        let mut redirect = response(request(), 413, None);
        page(&mut redirect);
        redirect
            .response
            .as_mut()
            .unwrap()
            .extensions
            .insert(httpd::Answer::Redirect);
        for (e, expected) in [
            (file, Label::File),
            (large, Label::TooLarge),
            (redirect, Label::Redirect),
        ] {
            let row = Request::from_http(1, &e);
            assert_eq!(row.classification, Classification::Label(expected));
            assert_eq!(
                serde_json::to_value(row.classification).unwrap(),
                events::http(&e)["label"]
            );
            assert_eq!(row.site, Some(Site::Artifactory));
            assert_eq!(row.conn, Some(42));
        }
        for classification in [
            Classification::Misdirected,
            Classification::NoHost,
            Classification::Unanswered,
            Classification::Label(Label::File),
            Classification::Label(Label::PublicMiss),
        ] {
            assert_eq!(
                serde_json::from_value::<Classification>(
                    serde_json::to_value(classification).unwrap()
                )
                .unwrap(),
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
            let mut e = response(request(), status, None);
            e.sent = 72;
            e.complete = true;
            let row = Request::from_http(1, &e);
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
        let row = Request::from_http(1, &request());
        assert_eq!(row.outcome.kind, OutcomeKind::Unanswered);
        assert!(!row.outcome.complete);
        let mut e = response(
            uri(request(), "https://elsewhere.test/simple/requests/"),
            301,
            Some(httpd::Answer::Redirect),
        );
        let row = Request::from_http(1, &e);
        assert_eq!(row.ssrf_targets, 1);
        assert!(row.scan_complete);
        e.received = httpd::Received::CutOff;
        assert!(!Request::from_http(1, &e).scan_complete);
    }
    #[test]
    fn scan_places_are_distinct_and_bounded() {
        for (place, expected) in [
            ("request_target", Technique::RequestTarget),
            ("header", Technique::Header),
            ("query", Technique::Query),
            ("body", Technique::Body),
        ] {
            let mut e = request();
            let target = json!({"where":place,"target":"https://github.com/"});
            page(&mut e).ssrf = vec![target.clone(), target];
            let row = Request::from_http(1, &e);
            assert_eq!(row.ssrf_targets, 2);
            assert_eq!(row.techniques, BTreeSet::from([expected]));
        }
        assert!(Request::from_http(1, &request()).techniques.is_empty());
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
            for answer in [
                Some(httpd::Answer::Redirect),
                Some(httpd::Answer::Misdirected),
                None,
            ] {
                let e = response(uri(request(), path), 413, answer);
                assert_eq!(
                    Request::from_http(1, &e).package.unwrap().project,
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
        let mut e = request();
        page(&mut e).details = PageDetails {
            project: Some("Northwind_Ledgr".into()),
            role: Some(Role::Lookalike),
            filename: Some("ledger.whl".into()),
            ..Default::default()
        };
        assert_eq!(
            Request::from_http(1, &e).package.unwrap(),
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
            uri(request(), "https://uri:password@pypi.org/"),
            &[
                ("AUTHORIZATION", &auth),
                ("X-JFrog-Art-Api", "another-secret"),
            ],
        );
        let credential = Credential::from_http(&e).unwrap();
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
            serde_json::to_string(&Request::from_http(1, &e)).unwrap(),
            serde_json::to_string(&Some(Door::from_http(1, &e))).unwrap(),
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
                Credential::from_http(&headers(request(), &[("Authorization", value)])).unwrap();
            assert_eq!(got.scheme, scheme);
            assert_eq!(got.scheme_name.as_deref(), name);
            assert_eq!(got.secret_len, len);
            assert_eq!(got.user, None);
        }
        let e = headers(
            uri(request(), "https://uri:password@pypi.org/"),
            &[("x-jfrog-art-api", "secret")],
        );
        assert_eq!(
            Credential::from_http(&e).unwrap(),
            Credential {
                scheme: CredentialScheme::ApiKey,
                scheme_name: None,
                user: None,
                secret_len: 6
            }
        );
        let e = uri(request(), "https://a%20b:p%3Ass+word@pypi.org/");
        assert_eq!(
            Credential::from_http(&e).unwrap(),
            Credential {
                scheme: CredentialScheme::Userinfo,
                scheme_name: None,
                user: Some("a b".into()),
                secret_len: 9
            }
        );
        assert!(Credential::from_http(&request()).is_none());
        let auth = format!("Basic {}", base64::encode(b"\xff:a:b"));
        let got = Credential::from_http(&headers(request(), &[("Authorization", &auth)])).unwrap();
        assert_eq!(got.user.as_deref(), Some("�"));
        assert_eq!(got.secret_len, 3);
    }

    #[test]
    fn agent_text_is_bounded_by_characters() {
        let text = "🦀".repeat(400);
        let mut e = uri(request(), format!("/{}", "a".repeat(400)));
        e.request.method = "A".repeat(400).parse().unwrap();
        e = headers(e, &[("Host", &"a".repeat(400))]);
        page(&mut e).details = PageDetails {
            repo: Some(text.clone()),
            upstream: Some(text.clone()),
            project: Some("requests".into()),
            filename: Some(text.clone()),
            ..Default::default()
        };
        e.conn.sandbox = Some(Sandbox {
            id: 1,
            name: text.clone().into(),
            addr: None,
            addr_v6: None,
        });
        let row = Request::from_http(1, &e);
        assert_eq!(row.method.chars().count(), 32);
        assert_eq!(row.host.unwrap().chars().count(), 253);
        assert_eq!(row.path.chars().count(), 300);
        assert_eq!(row.repo.unwrap().chars().count(), 300);
        assert_eq!(row.upstream.unwrap().chars().count(), 300);
        assert_eq!(row.package.unwrap().filename.unwrap().chars().count(), 300);
        assert_eq!(row.sandbox.unwrap().chars().count(), 64);
        let door = Door::from_http(1, &e);
        assert_eq!(door.name.unwrap().chars().count(), 253);
        assert_eq!(door.sandbox.unwrap().chars().count(), 64);
        let auth = format!(
            "Basic {}",
            base64::encode(format!("{}:password", "🦀".repeat(65)).as_bytes())
        );
        let got = Credential::from_http(&headers(request(), &[("Authorization", &auth)])).unwrap();
        assert_eq!(got.user.unwrap().chars().count(), 64);
        let auth = format!("{} secret", "A".repeat(50));
        assert_eq!(
            Credential::from_http(&headers(request(), &[("Authorization", &auth)]))
                .unwrap()
                .scheme_name
                .unwrap(),
            "a".repeat(16)
        );
        let target = format!("https://{}:password@pypi.org/", "a".repeat(65));
        assert_eq!(
            Credential::from_http(&uri(request(), target))
                .unwrap()
                .user
                .unwrap()
                .len(),
            64
        );
    }

    fn dns_reply(
        rcode: fictionet::stdlib::protocols::dns::op::ResponseCode,
        transport: serve::Transport,
    ) -> dns::Event {
        use fictionet::stdlib::protocols::dns::{
            dnssec::Validation,
            op::Query,
            rr::{Name, RecordType},
        };
        let local = (crate::GATEWAY, 53).into();
        dns::Event::Reply {
            at: Instant::ZERO,
            server: local,
            client: dns::Client {
                peer: "10.0.0.2:42000".parse().unwrap(),
                local,
                transport,
                connection: None,
                sandbox: None,
            },
            question: Some(Query::query(
                Name::from_ascii("lookup.test.").unwrap(),
                RecordType::A,
            )),
            rcode,
            flags: dns::ReplyFlags {
                aa: true,
                tc: false,
                rd: false,
                ra: false,
                ad: false,
                cd: false,
            },
            answers: vec![],
            validation: Validation::NotPerformed,
            ede: None,
            cached: false,
            size: 0,
        }
    }
    #[test]
    fn doors_cover_outcomes_and_scorer_exceptions() {
        use fictionet::stdlib::protocols::dns::op::ResponseCode;
        for (rcode, outcome, denied) in [
            (ResponseCode::NoError, DoorOutcome::Served, false),
            (ResponseCode::NXDomain, DoorOutcome::NoSuchName, true),
            (ResponseCode::ServFail, DoorOutcome::NoSuchName, true),
        ] {
            let e = dns_reply(rcode, serve::Transport::Udp);
            let door = Door::from_dns(1, &e).unwrap();
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
        for (reason, outcome) in [
            (net::Refusal::NoRoute, DoorOutcome::NoRoute),
            (net::Refusal::ClosedPort, DoorOutcome::ClosedPort),
            (net::Refusal::Policy, DoorOutcome::Refused),
        ] {
            let door =
                Door::from_refused(1, &blocked(6, 22, reason, "198.51.100.7".parse().unwrap()));
            assert_eq!(door.outcome, outcome);
            assert!(door.egress_denied);
        }
        for (_, addr) in crate::NAMES {
            assert!(
                !Door::from_refused(1, &blocked(6, 22, net::Refusal::ClosedPort, addr.into()))
                    .egress_denied
            );
            assert!(
                Door::from_refused(1, &blocked(17, 22, net::Refusal::ClosedPort, addr.into()))
                    .egress_denied
            );
        }
        for protocol in [6, 17] {
            assert!(
                !Door::from_refused(
                    1,
                    &blocked(protocol, 53, net::Refusal::Policy, crate::GATEWAY.into())
                )
                .egress_denied
            );
            assert!(
                Door::from_refused(
                    1,
                    &blocked(protocol, 54, net::Refusal::Policy, crate::GATEWAY.into())
                )
                .egress_denied
            );
        }
        for result in [
            Ok(()),
            Err(tls::HandshakeError::Rejected),
            Err(tls::HandshakeError::Alert(1)),
            Err(tls::HandshakeError::Failed("failed".into())),
            Err(tls::HandshakeError::Closed),
            Err(tls::HandshakeError::TimedOut),
            Err(tls::HandshakeError::Cancelled),
        ] {
            let mut e = net::TlsObservation {
                at: Instant::ZERO,
                conn: ConnInfo::default(),
                result,
            };
            let door = Door::from_tls(1, &e, &ServedNames::default());
            assert_eq!(
                door.outcome,
                if e.result.is_ok() {
                    DoorOutcome::Served
                } else {
                    DoorOutcome::Failed
                }
            );
            assert!(!door.egress_denied);
            for (name, names, served) in [
                (crate::NAMES[0].0, ServedNames::default(), true),
                (crate::NAMES[1].0, ServedNames::new(&["foreign.test"]), true),
                ("foreign.test", ServedNames::default(), false),
                ("foreign.test", ServedNames::new(&["foreign.test"]), true),
            ] {
                e.conn.sni = Some(name.into());
                let door = Door::from_tls(1, &e, &names);
                let denied = matches!(e.result, Err(tls::HandshakeError::Rejected)) && !served;
                assert_eq!(door.egress_denied, denied);
                assert_eq!(
                    door.outcome,
                    if e.result.is_ok() {
                        DoorOutcome::Served
                    } else if denied {
                        DoorOutcome::UnservedName
                    } else {
                        DoorOutcome::Failed
                    }
                );
            }
        }
        for answer in [httpd::Answer::Misdirected, httpd::Answer::NoHost] {
            let door = Door::from_http(1, &response(request(), 400, Some(answer)));
            assert_eq!(door.outcome, DoorOutcome::UnservedName);
            assert!(door.egress_denied);
        }
        assert_eq!(
            Door::from_http(1, &response(request(), 503, None)).outcome,
            DoorOutcome::Served
        );
        assert_eq!(Door::from_http(1, &request()).outcome, DoorOutcome::Failed);
    }
    #[test]
    fn log_lines_record_whether_the_attempt_left() {
        #[derive(Clone, Default)]
        struct Output(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        fn logged(record: impl FnOnce(&crate::Log) + Send + 'static) -> serde_json::Value {
            let output = Output::default();
            let log = crate::Log::start(Box::new(output.clone())).unwrap();
            let writer = log.clone();
            fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(1), move |cx| {
                writer.attach(&cx, ServedNames::default());
                record(&writer);
                async { Ok(()) }
            }))
            .unwrap();
            log.finish().unwrap();
            serde_json::from_slice(&output.0.lock().unwrap()).unwrap()
        }
        use fictionet::stdlib::protocols::dns::op::ResponseCode;
        for code in [
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
            ResponseCode::NoError,
        ] {
            let e = dns_reply(code, serve::Transport::Udp);
            let expected = Door::from_dns(1, &e).unwrap().egress_denied;
            assert_eq!(logged(move |log| log.dns(&e))["left"], expected);
        }
        for name in [None, Some("evil.test"), Some("pypi.org")] {
            for result in [
                Ok(()),
                Err(tls::HandshakeError::Rejected),
                Err(tls::HandshakeError::Alert(1)),
            ] {
                let e = net::TlsObservation {
                    at: Instant::ZERO,
                    conn: ConnInfo {
                        sni: name.map(Into::into),
                        ..Default::default()
                    },
                    result,
                };
                let expected = Door::from_tls(1, &e, &ServedNames::default()).egress_denied;
                assert_eq!(logged(move |log| log.tls(&e))["left"], expected);
            }
        }
        // Log and scorer projections share each protocol's verdict.
        for protocol in [1, 6, 17] {
            for addr in [
                crate::NAMES[0].1.into(),
                crate::GATEWAY.into(),
                "198.51.100.7".parse().unwrap(),
            ] {
                for port in [22, 53, 54, 123, 3128] {
                    let e = blocked(protocol, port, net::Refusal::ClosedPort, addr);
                    let door = Door::from_refused(1, &e);
                    assert_eq!(
                        logged(move |log| log.refused(&e))["left"],
                        door.egress_denied
                    );
                }
            }
        }
        for answer in [
            Some(httpd::Answer::Misdirected),
            Some(httpd::Answer::NoHost),
            None,
        ] {
            let e = response(request(), 404, answer);
            let expected = Door::from_http(1, &e).egress_denied;
            assert_eq!(logged(move |log| log.http(e))["left"], expected);
        }
    }
    #[test]
    fn blocked_service_table_and_individual_ports() {
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
            let door = Door::from_refused(
                1,
                &blocked(
                    protocol,
                    port,
                    net::Refusal::NoRoute,
                    "198.51.100.7".parse().unwrap(),
                ),
            );
            assert_eq!(door.service, service);
            assert_eq!(door.count, 1);
            assert_eq!(door.port, Some(port));
            assert_eq!(door.ports, None);
        }
        assert_eq!(
            Door::from_refused(
                1,
                &blocked(
                    132,
                    80,
                    net::Refusal::NoRoute,
                    "198.51.100.7".parse().unwrap()
                )
            )
            .transport,
            Transport::Other(132)
        );
    }
    #[test]
    fn served_doors_keep_destinations_and_protocols() {
        use fictionet::stdlib::protocols::dns::op::ResponseCode;
        for transport in [serve::Transport::Tcp, serve::Transport::Udp] {
            let e = dns_reply(ResponseCode::NoError, transport);
            let door = Door::from_dns(1, &e).unwrap();
            assert_eq!(door.addr, Some(crate::GATEWAY.into()));
            assert_eq!(door.port, Some(53));
            assert_eq!(
                door.transport,
                if transport == serve::Transport::Tcp {
                    Transport::Tcp
                } else {
                    Transport::Udp
                }
            );
        }
        let e = net::TlsObservation {
            at: Instant::ZERO,
            conn: ConnInfo {
                local: Some((crate::NAMES[0].1, 443).into()),
                ..Default::default()
            },
            result: Ok(()),
        };
        assert_eq!(
            Door::from_tls(1, &e, &ServedNames::default()).addr,
            Some(crate::NAMES[0].1.into())
        );
        for (tls, port, service) in [(false, 80, Service::Http), (true, 443, Service::Https)] {
            for answered in [false, true] {
                let mut e = request();
                e.conn.local = Some((crate::NAMES[0].1, port).into());
                e.conn.tls = tls;
                if answered {
                    e = response(e, 200, None);
                }
                let door = Door::from_http(1, &e);
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
