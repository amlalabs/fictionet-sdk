//! DNS over TLS and DNS over HTTPS in front of a running [`Recursive`](super::Recursive):
//! the same engines and caches answer, whichever way a query arrives.
//!
//! [`Fronts`] puts a resolver's [`ResolverHandle`] behind two more ports of
//! a host. On TCP port 853 it serves DNS over TLS (RFC 7858): each query
//! after its two-octet length, as over TCP port 53, pipelined, and answered
//! as each answer is ready. On TCP port 443 it serves DNS over HTTPS
//! (RFC 8484) to the operator's names and to clients that connect to the
//! address with no name:
//!
//! - `GET /dns-query?dns=...` and `POST /dns-query` with the query as
//!   `application/dns-message`, answered in the same media type with a
//!   `Cache-Control` freshness no longer than the answer's smallest TTL
//!   (RFC 8484 §5.1);
//! - `GET /resolve?name=...&type=...`, Google's JSON API, which answers
//!   `application/json` unless `ct=application/dns-message` asks for the
//!   message itself;
//! - `GET /dns-query?name=...&type=...` with `Accept: application/dns-json`,
//!   Cloudflare's form of the same JSON.
//!
//! A query from either front reaches the resolver as a stream client
//! ([`Transport::Tcp`]) from the connection's peer and sandbox, so a
//! sandbox's DNS over HTTPS answer comes from the cache its UDP questions
//! filled, with the same TTL countdown and the same validation.
//!
//! The certificates are the world's: a TLS server proves who it is with
//! its private key on every handshake, and the world holds no operator's
//! key. [`certificate`] issues a public resolver's from the world's CA,
//! with its addresses as IP SANs, so a client that connects to `1.1.1.1`
//! checks the address as it would check a name. DNS over QUIC is not
//! served: UDP port 853 stays closed.
//!
//! ```
//! # use std::net::Ipv4Addr;
//! # use std::time::SystemTime;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::protocols::dns::rr::Name;
//! # use fictionet::stdlib::protocols::x509::{Time, Validity};
//! # use fictionet::stdlib::services::ca::Ca;
//! # use fictionet::stdlib::services::dns::{WallClock, resolver::Config};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Recursive;
//! # use fictionet::stdlib::world::net::dns::encrypted::Fronts;
//! # async fn world(fcx: Cx, attachments: Attachments, ca: Ca) -> Result {
//! # let start = SystemTime::now();
//! # let clock = WallClock { start };
//! # let validity = Validity { not_before: Time::from_unix(1_700_000_000)?, not_after: Time::from_unix(1_900_000_000)? };
//! let tls = ca.issue(&fcx, &["dns.example", "45.33.9.9"], validity)?.server_config(&fcx, start)?;
//! let resolver = Recursive::new(Config::unbound(), clock);
//! let fronts = Fronts::new(resolver.handle(), move |_| tls.clone())
//!     .names([Name::from_ascii("dns.example.")?]);
//! Net::new()
//!     .host("resolver", |h| fronts.doh(fronts.dot(h.at(Ipv4Addr::new(45, 33, 9, 9)).program(resolver))))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use http::header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::base64::{self, Padding};
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::{Framing, Queries, stream_framed};
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::protocols::urlencoded_form::{self, Form};
use fictionet::stdlib::protocols::x509::Validity;
use fictionet::stdlib::services::ca::{Ca, Leaf};
use fictionet::stdlib::services::dns::Client;
use fictionet::stdlib::services::serve::{
    self, ConnInfo, Driver, Flow, Pending, PendingDriver, ServeOptions, Service, Transport,
};
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply, request_host};
use fictionet::{Cx, Error};

use super::super::{Arrival, Host, PortServer, Sni};
use super::ResolverHandle;
use super::internet::PublicResolver;

/// The port of DNS over TLS (RFC 7858 §3.1).
const DOT_PORT: u16 = 853;

/// The port of DNS over HTTPS: HTTPS's own (RFC 8484 §5, RFC 9110 §4.2.2).
const DOH_PORT: u16 = 443;

/// The path RFC 8484's examples use, which every large operator serves.
const DNS_QUERY: &str = "/dns-query";

/// The path of Google's JSON API.
const RESOLVE: &str = "/resolve";

/// The media type of a DNS message over HTTPS (RFC 8484 §6).
const DNS_MESSAGE: &str = "application/dns-message";

/// Cloudflare's media type for the JSON form.
const DNS_JSON: &str = "application/dns-json";

/// The media type of Google's JSON answers.
const JSON: &str = "application/json; charset=UTF-8";

/// The largest DNS message the `application/dns-message` media type
/// carries (RFC 8484 §6).
const MAX_MESSAGE: usize = u16::MAX as usize;

/// What a TLS port's handshake gets its config from.
type TlsFor = Arc<dyn Fn(&Cx) -> Arc<ServerConfig> + Send + Sync>;

/// DNS over TLS and over HTTPS in front of a [`Recursive`](super::Recursive),
/// added to a host with [`dot`](Self::dot) and [`doh`](Self::doh). See the
/// [module docs](self).
#[derive(Clone)]
pub struct Fronts {
    resolver: ResolverHandle,
    tls: TlsFor,
    names: Vec<LowerName>,
    at: Option<IpAddr>,
    date: Option<SystemTime>,
}

impl Fronts {
    /// Fronts for the resolver `resolver` reaches, whose TLS handshakes
    /// use the config `tls` returns for each.
    pub fn new(
        resolver: ResolverHandle,
        tls: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Fronts {
        Fronts {
            resolver,
            tls: Arc::new(tls),
            names: Vec::new(),
            at: None,
            date: None,
        }
    }

    /// The names DNS over HTTPS answers to, such as `cloudflare-dns.com`
    /// and `one.one.one.one`. A request over TLS for another name, by SNI
    /// or by its host, gets `421 Misdirected Request`; a request for the
    /// address it arrived at, with no name, is answered.
    pub fn names(self, names: impl IntoIterator<Item = Name>) -> Fronts {
        Fronts {
            names: names
                .into_iter()
                .map(|mut name| {
                    name.set_fqdn(true);
                    LowerName::new(&name)
                })
                .collect(),
            ..self
        }
    }

    /// Puts queries to the resolver's machine at `addr` instead of the one
    /// at the address the client connected to. A front on another host
    /// needs it, such as DNS over HTTPS at the addresses of
    /// `cloudflare-dns.com`, which are not 1.1.1.1's. The resolver then
    /// sees each query as asked of `addr`.
    pub fn resolver_at(self, addr: IpAddr) -> Fronts {
        Fronts {
            at: Some(addr),
            ..self
        }
    }

    /// Sends `Date` headers on DNS over HTTPS answers, `start` being the
    /// world's date at the start of the run
    /// ([`httpd::Server::date`]).
    pub fn date(self, start: SystemTime) -> Fronts {
        Fronts {
            date: Some(start),
            ..self
        }
    }

    /// `host` serving DNS over TLS on TCP port 853, for any name a client
    /// sends, offering `dot`, the ALPN identifier IANA registers for it.
    pub fn dot(&self, host: Host) -> Host {
        let tls = self.tls.clone();
        let port = Dot {
            front: self.front(),
        };
        host.tls_accept(DOT_PORT, Sni::Any, move |fcx| tls(fcx), port)
    }

    /// `host` serving DNS over HTTPS on TCP port 443, over HTTP/1.1 and
    /// HTTP/2. Its handshake takes any name, since a client that connects
    /// to the address sends none; its requests are answered only for
    /// [`names`](Self::names) and the address.
    pub fn doh(&self, host: Host) -> Host {
        let tls = self.tls.clone();
        let mut server = httpd::Server::new(Doh {
            front: self.front(),
            names: self.names.clone(),
        })
        .https()
        .default_host();
        if let Some(start) = self.date {
            server = server.date(start);
        }
        host.tls_accept(DOH_PORT, Sni::Any, move |fcx| tls(fcx), server)
    }

    fn front(&self) -> Arc<Front> {
        Arc::new(Front {
            resolver: self.resolver.clone(),
            at: self.at,
        })
    }
}

/// A certificate from `ca` for the fronts of `resolver`: its DNS over
/// HTTPS names, and each of its addresses as an IP SAN (RFC 5280
/// §4.2.1.6), valid for `validity`.
pub fn certificate(
    fcx: &Cx,
    ca: &Ca,
    resolver: &PublicResolver,
    validity: Validity,
) -> Result<Leaf, Error> {
    let names = resolver
        .doh
        .iter()
        .map(|name| name.trim_end_matches('.').to_owned());
    let addresses = resolver
        .addresses
        .iter()
        .flat_map(|address| [IpAddr::V4(address.v4), IpAddr::V6(address.v6)])
        .map(|addr| addr.to_string());
    let sans: Vec<String> = names.chain(addresses).collect();
    let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
    ca.issue(fcx, &sans, validity)
}

/// What both fronts put queries to.
struct Front {
    resolver: ResolverHandle,
    at: Option<IpAddr>,
}

impl Front {
    /// The client a query over `conn` is from. `None` for a connection
    /// with no addresses, which no network made.
    fn client(&self, conn: &ConnInfo) -> Option<Client> {
        let (peer, local) = (conn.peer?, conn.local?);
        let local = self
            .at
            .map_or(local, |at| SocketAddr::new(at, local.port()));
        Some(Client {
            peer,
            local,
            transport: Transport::Tcp,
            connection: None,
            // A peer no sandbox has is reported with id 0, as the resolver's
            // own ports report it.
            sandbox: conn.sandbox.clone().filter(|sandbox| sandbox.id != 0),
        })
    }
}

// ---------------------------------------------------------------------------
// DNS over TLS

/// DNS over TLS on one port.
struct Dot {
    front: Arc<Front>,
}

impl PortServer for Dot {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut service = Queried {
            front: self.front.clone(),
            next: 0,
        };
        // The connection's buffers and the queries it waits on are charged
        // to its sandbox. It closes once it has been quiet for the network's
        // idle time for DNS over TCP with no query waiting (RFC 7766
        // §6.2.3, RFC 7858 §3.4).
        let opts = ServeOptions {
            budget: arrival.budget,
            handshake: arrival.limits.handshake,
            idle: Some(arrival.limits.dns_tcp_idle),
            ..ServeOptions::default()
        };
        Box::pin(async move {
            let _ =
                serve::connection(&fcx, arrival.conn, arrival.info, &mut service, &(), &opts).await;
        })
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        vec![b"dot".to_vec()]
    }
}

/// One DNS over TLS connection: each query goes to the resolver as it
/// arrives, and each answer is written whole as soon as it is ready, so
/// answers may come out of order (RFC 7766 §6.2.1.1).
struct Queried {
    front: Arc<Front>,
    next: u64,
}

impl Service for Queried {
    type Timer = ();
    type Decoder = Queries;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> Queries {
        Queries::new(Framing::Stream)
    }

    fn on_item(
        &mut self,
        query: Vec<u8>,
        _state: &(),
        driver: &mut Driver<'_, Queries, ()>,
    ) -> Result<Flow, Infallible> {
        if let Some(client) = self.front.client(driver.conn()) {
            let answer = Answering::new(self.front.resolver.clone(), client, query);
            driver.defer_keyed(self.next, answer);
            self.next += 1;
        }
        Ok(Flow::Continue)
    }
}

/// The resolver's answer to one query.
type Answer = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;

/// One query of a DNS over TLS connection, waiting for its answer, which
/// it writes after its two-octet length (RFC 7858 §3.3, RFC 1035 §4.2.2).
/// A query the resolver leaves unanswered writes nothing.
struct Answering {
    resolver: ResolverHandle,
    query: Option<(Client, Vec<u8>)>,
    answer: Option<Answer>,
    held: usize,
}

impl Answering {
    fn new(resolver: ResolverHandle, client: Client, query: Vec<u8>) -> Answering {
        Answering {
            resolver,
            held: query.len(),
            query: Some((client, query)),
            answer: None,
        }
    }
}

impl Pending for Answering {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, Error>>> {
        if let Some((client, query)) = self.query.take() {
            let Some(fcx) = driver.fcx().cloned() else {
                return Poll::Ready(None);
            };
            let resolver = self.resolver.clone();
            self.answer = Some(Box::pin(async move {
                resolver.query(&fcx, client, query).await
            }));
        }
        let Some(answer) = &mut self.answer else {
            return Poll::Ready(None);
        };
        let answer = ready!(answer.as_mut().poll(cx));
        self.answer = None;
        self.held = 0;
        Poll::Ready(answer.map(|answer| {
            // The resolver fits stream answers to 65535 octets.
            stream_framed(&answer)
                .ok_or_else(|| Error::msg("a DNS answer longer than a stream carries"))
        }))
    }

    fn held(&self) -> usize {
        self.held
    }
}

// ---------------------------------------------------------------------------
// DNS over HTTPS

/// DNS over HTTPS for one resolver: the paths and media types of the
/// module docs, for the operator's names and the address.
struct Doh {
    front: Arc<Front>,
    names: Vec<LowerName>,
}

/// What a request asks the resolver, and how its answer goes back.
enum Asked {
    /// A DNS message, answered with the resolver's message.
    Message(Vec<u8>),
    /// The JSON API's question, answered in JSON of this media type, or
    /// as a message when that is `None`.
    Json(Vec<u8>, Option<&'static str>),
}

impl Handler for Doh {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let conn = ex.conn();
        let client = self
            .front
            .client(conn)
            .filter(|_| self.serves(conn, &request));
        let Some(client) = client else {
            let refusal = Refusal::Text(
                StatusCode::MISDIRECTED_REQUEST,
                "This server does not serve that host.\n",
            );
            return Reply::Now(refusal.response());
        };
        let asked = match ask(&request, ex) {
            Ok(asked) => asked,
            Err(refusal) => return Reply::Now(refusal.response()),
        };
        let resolver = self.front.resolver.clone();
        Reply::Later(Box::new(move |fcx| {
            Box::pin(async move {
                let (query, json) = match asked {
                    Asked::Message(query) => (query, None),
                    Asked::Json(query, json) => (query, json),
                };
                let Some(answer) = resolver.query(&fcx, client, query).await else {
                    let refusal =
                        Refusal::Text(StatusCode::BAD_REQUEST, "The query is not a DNS query.\n");
                    return Ok(refusal.response());
                };
                Ok(answered(answer, json))
            })
        }))
    }
}

/// Why a request gets no answer from the resolver.
enum Refusal {
    /// This status, with this text.
    Text(StatusCode, &'static str),
    /// `405 Method Not Allowed`, with the methods the path allows.
    Method(&'static str),
    /// A JSON API request refused with `400 Bad Request` and the reason
    /// in JSON, as Cloudflare refuses one.
    Json(String),
}

impl Refusal {
    fn response(self) -> Response<Body> {
        match self {
            Refusal::Text(status, text) => httpd::text(status, text),
            Refusal::Method(allowed) => {
                let mut response =
                    httpd::text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.\n");
                response
                    .headers_mut()
                    .insert(ALLOW, HeaderValue::from_static(allowed));
                response
            }
            Refusal::Json(error) => {
                let body = Value::Object(vec![("error".to_owned(), Value::from(error))]);
                let mut response = Response::new(Body::from(body.to_bytes().unwrap_or_default()));
                *response.status_mut() = StatusCode::BAD_REQUEST;
                response
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static(JSON));
                response
            }
        }
    }
}

impl Doh {
    /// Whether this resolver answers `request` over `conn`: a name the
    /// client sent with SNI must be one of its names, and the request's
    /// host must be one of them or the address it arrived at.
    fn serves(&self, conn: &ConnInfo, request: &Request<Body>) -> bool {
        let named = |host: &str| fqdn(host).is_some_and(|name| self.names.contains(&name));
        let sni = conn.sni.as_deref().is_none_or(named);
        let host = request_host(request).is_some_and(|host| {
            let literal = host.trim_start_matches('[').trim_end_matches(']');
            match IpAddr::from_str(literal) {
                Ok(addr) => conn.local.is_some_and(|local| local.ip() == addr),
                Err(_) => named(&host),
            }
        });
        sni && host
    }
}

/// `host`, a name as SNI and HTTP give it, without the root's dot, as the
/// fully qualified name it means.
fn fqdn(host: &str) -> Option<LowerName> {
    let mut name = Name::from_ascii(host).ok()?;
    name.set_fqdn(true);
    Some(LowerName::new(&name))
}

/// The query `request` asks, or why it is refused.
fn ask(request: &Request<Body>, ex: &mut Exchange<'_>) -> Result<Asked, Refusal> {
    let path = request.uri().path();
    let method = request.method();
    let allowed = match path {
        DNS_QUERY => "GET, POST",
        RESOLVE => "GET",
        _ => return Err(Refusal::Text(StatusCode::NOT_FOUND, "Not found.\n")),
    };
    if *method == Method::POST && path == DNS_QUERY {
        return posted(request);
    }
    if *method != Method::GET {
        return Err(Refusal::Method(allowed));
    }
    let query = request.uri().query().unwrap_or("");
    let Ok(form) = Form::parse(query.as_bytes()) else {
        return Err(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "Bad query string.\n",
        ));
    };
    let param = |name: &str| urlencoded_form::first(&form.pairs, name);
    if path == RESOLVE {
        let json = match param("ct") {
            Some(DNS_MESSAGE) => None,
            _ => Some(JSON),
        };
        return json_query(&form.pairs, json, ex);
    }
    if let Some(dns) = param("dns") {
        return base64url(dns).map(Asked::Message).ok_or(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The dns parameter is not a DNS message in base64url.\n",
        ));
    }
    let accepts_json = request
        .headers()
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.to_ascii_lowercase().contains(DNS_JSON));
    if accepts_json || param("ct") == Some(DNS_JSON) {
        return json_query(&form.pairs, Some(DNS_JSON), ex);
    }
    Err(Refusal::Text(
        StatusCode::BAD_REQUEST,
        "The request has no dns parameter.\n",
    ))
}

/// The DNS message a POST carries as its body (RFC 8484 §4.1).
fn posted(request: &Request<Body>) -> Result<Asked, Refusal> {
    let media = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    if media.as_deref() != Some(DNS_MESSAGE) {
        return Err(Refusal::Text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type.\n",
        ));
    }
    let Some(body) = request.body().bytes() else {
        return Err(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The body did not arrive whole.\n",
        ));
    };
    if body.len() > MAX_MESSAGE {
        return Err(Refusal::Text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "A DNS message is at most 65535 octets.\n",
        ));
    }
    Ok(Asked::Message(body.to_vec()))
}

/// The `dns` parameter of a GET: base64url (RFC 4648 §5), which RFC 8484
/// §6 sends without padding. Padding is accepted, as decoders commonly do.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let standard: Vec<u8> = text
        .bytes()
        .map(|byte| match byte {
            b'-' => Some(b'+'),
            b'_' => Some(b'/'),
            b'+' | b'/' => None,
            byte => Some(byte),
        })
        .collect::<Option<_>>()?;
    let message = base64::decode(&standard, Padding::Optional)?;
    (message.len() <= MAX_MESSAGE).then_some(message)
}

/// The query the JSON API's parameters ask, answered in `json`: `name`
/// (required, RFC 4343 escapes allowed), `type` (a number from 1 to 65535
/// or a mnemonic, default A), `cd`, and `do`. Other parameters, such as
/// `edns_client_subnet` and `random_padding`, are ignored. The first of
/// duplicate parameters counts.
fn json_query(
    pairs: &[(String, String)],
    json: Option<&'static str>,
    ex: &mut Exchange<'_>,
) -> Result<Asked, Refusal> {
    let param = |name: &str| urlencoded_form::first(pairs, name);
    let text = param("name").ok_or_else(|| Refusal::Json("Missing name parameter.".to_owned()))?;
    let name = Name::from_ascii(text)
        .ok()
        .filter(|name| !name.is_root())
        .ok_or_else(|| Refusal::Json(format!("Invalid name `{text}`.")))?;
    let kind = match param("type") {
        None | Some("") => RecordType::A,
        Some(kind) => {
            record_type(kind).ok_or_else(|| Refusal::Json(format!("Invalid type `{kind}`.")))?
        }
    };
    let flag = |param_name: &str, label: &str| match param(param_name) {
        None | Some("" | "0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        Some(other) => Err(Refusal::Json(format!(
            "Invalid {label} flag `{other}`. Expected to be empty or one of `0`, `false`, `1`, or `true`."
        ))),
    };
    let cd = flag("cd", "CD")?;
    let dnssec_ok = flag("do", "DO")?;

    // RD and AD set, the second asking for the AD bit (RFC 6840 §5.7); an
    // OPT record carries DO (RFC 3225).
    let mut message = Message::new(ex.random_u64() as u16, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.authentic_data = true;
    message.metadata.checking_disabled = cd;
    message.add_query(Query::query(name, kind));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    let query = message
        .to_vec()
        .map_err(|error| Refusal::Json(format!("Cannot ask that: {error}.")))?;
    Ok(Asked::Json(query, json))
}

/// A record type as the JSON API takes it: a number from 1 to 65535, or a
/// mnemonic in any case.
fn record_type(text: &str) -> Option<RecordType> {
    match text.parse::<u16>() {
        Ok(0) => None,
        Ok(number) => Some(RecordType::from(number)),
        Err(_) => RecordType::from_str(&text.to_ascii_uppercase()).ok(),
    }
}

/// The response carrying the resolver's `answer`: as JSON of the media
/// type `json`, or as the message itself when that is `None`. Every DNS
/// answer, SERVFAIL and NXDOMAIN included, is `200 OK` (RFC 8484 §4.2.1).
fn answered(answer: Vec<u8>, json: Option<&'static str>) -> Response<Body> {
    let message = Message::from_vec(&answer).ok();
    let freshness = message.as_ref().and_then(freshness);
    let (body, media) = match (json, &message) {
        (Some(media), Some(message)) => (Body::from(to_json(message)), media),
        _ => (Body::from(answer), DNS_MESSAGE),
    };
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(media));
    if let Some(seconds) = freshness
        && let Ok(value) = HeaderValue::from_str(&format!("max-age={seconds}"))
    {
        headers.insert(CACHE_CONTROL, value);
    }
    response
}

/// How long an HTTP cache may keep a response carrying `message`
/// (RFC 8484 §5.1): the smallest TTL in its answer section, or for an
/// answer with no records the TTL of the SOA in its authority section,
/// no longer than that SOA's MINIMUM (RFC 2308 §5). `None` when it has
/// neither, as a SERVFAIL has.
fn freshness(message: &Message) -> Option<u32> {
    if !message.answers.is_empty() {
        return message.answers.iter().map(|record| record.ttl).min();
    }
    message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
}

/// `message` in the JSON both Google's and Cloudflare's APIs use: the
/// header bits, the question, and each section's records with their data
/// in presentation format.
fn to_json(message: &Message) -> Vec<u8> {
    let flags = &message.metadata;
    let mut fields = vec![
        (
            "Status".to_owned(),
            Value::from(u32::from(u16::from(flags.response_code))),
        ),
        ("TC".to_owned(), Value::from(flags.truncation)),
        ("RD".to_owned(), Value::from(flags.recursion_desired)),
        ("RA".to_owned(), Value::from(flags.recursion_available)),
        ("AD".to_owned(), Value::from(flags.authentic_data)),
        ("CD".to_owned(), Value::from(flags.checking_disabled)),
    ];
    let questions = message
        .queries
        .iter()
        .map(|query| {
            Value::Object(vec![
                ("name".to_owned(), Value::from(query.name().to_string())),
                (
                    "type".to_owned(),
                    Value::from(u32::from(u16::from(query.query_type()))),
                ),
            ])
        })
        .collect::<Vec<_>>();
    fields.push(("Question".to_owned(), Value::from(questions)));
    for (section, records) in [
        ("Answer", &message.answers),
        ("Authority", &message.authorities),
        ("Additional", &message.additionals),
    ] {
        if !records.is_empty() {
            let records = records.iter().map(record_json).collect::<Vec<_>>();
            fields.push((section.to_owned(), Value::from(records)));
        }
    }
    Value::Object(fields).to_bytes().unwrap_or_default()
}

/// One record of a JSON answer.
fn record_json(record: &Record) -> Value {
    let data = match &record.data {
        // Every character-string quoted, with no space between them, as
        // Google gives TXT and SPF data.
        RData::TXT(txt) => txt.txt_data.iter().map(|part| quoted(part)).collect(),
        data => data.to_string(),
    };
    Value::Object(vec![
        ("name".to_owned(), Value::from(record.name.to_string())),
        (
            "type".to_owned(),
            Value::from(u32::from(u16::from(record.record_type()))),
        ),
        ("TTL".to_owned(), Value::from(record.ttl)),
        ("data".to_owned(), Value::from(data)),
    ])
}

/// A character-string in presentation format (RFC 1035 §5.1): in quotes,
/// with `"` and `\` escaped and bytes outside printable ASCII as `\DDD`.
fn quoted(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03}")),
        }
    }
    out.push('"');
    out
}
