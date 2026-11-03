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
//! - when its [`Operator`] serves it, `GET /resolve?name=...&type=...`,
//!   Google's JSON API, which answers `application/json` unless
//!   `ct=application/dns-message` asks for the message itself;
//! - when its [`Operator`] serves it, `GET /dns-query?name=...&type=...`
//!   with `Accept: application/dns-json`, Cloudflare's form of the same
//!   JSON.
//!
//! What else a request gets, a path the server does not serve or a GET
//! with no query, is the operator's own answer, so the fronts of a world's
//! public resolvers answer as each real operator does.
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
use std::fmt;
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
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SVCB, SvcParamKey, SvcParamValue, Unknown,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{CNAME, HTTPS, NS, PTR};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::serialize::binary::BinEncodable;
use fictionet::stdlib::protocols::dns::{Framing, Queries, stream_framed};
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::protocols::urlencoded_form::{self, Form};
use fictionet::stdlib::protocols::x509::Validity;
use fictionet::stdlib::services::ca::{Ca, Leaf};
use fictionet::stdlib::services::dns::Client;
use fictionet::stdlib::services::dns::zone::dname_target;
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

/// How one operator's DNS over HTTPS server answers past RFC 8484's
/// `application/dns-message`: the JSON API it serves, if any, and its own
/// answers to what it does not serve. A world plays a real operator with
/// that operator's, as `internet::PUBLIC_RESOLVERS` gives them.
pub trait Operator: Send + Sync + fmt::Debug {
    /// Whether `GET /resolve` answers Google's JSON API.
    fn resolve_json(&self) -> bool {
        false
    }

    /// Whether `GET /dns-query` answers Cloudflare's JSON, as
    /// `application/dns-json`, to a request that accepts it or asks for it
    /// with `ct`.
    fn dns_json(&self) -> bool {
        false
    }

    /// The answer to `request`, for a path the server does not serve.
    fn not_found(&self, request: &Request<Body>) -> Response<Body>;

    /// The answer to `request`, a GET of `/dns-query` with no `dns`
    /// parameter that the server takes no JSON question from.
    fn no_query(&self, request: &Request<Body>) -> Response<Body>;
}

/// RFC 8484 alone, with plain text for what it does not serve: the fronts'
/// operator unless [`Fronts::operator`] gives another.
#[derive(Debug)]
struct Rfc8484;

impl Operator for Rfc8484 {
    fn not_found(&self, _request: &Request<Body>) -> Response<Body> {
        httpd::text(StatusCode::NOT_FOUND, "Not found.\n")
    }

    fn no_query(&self, _request: &Request<Body>) -> Response<Body> {
        httpd::text(
            StatusCode::BAD_REQUEST,
            "The request has no dns parameter.\n",
        )
    }
}

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
    operator: &'static dyn Operator,
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
            operator: &Rfc8484,
        }
    }

    /// Answers DNS over HTTPS as `operator` does past RFC 8484, such as a
    /// public resolver's [`doh_operator`](super::internet::PublicResolver::doh_operator).
    /// Without it, the fronts serve RFC 8484 alone.
    pub fn operator(self, operator: &'static dyn Operator) -> Fronts {
        Fronts { operator, ..self }
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
            operator: self.operator,
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
        .doh()
        .into_iter()
        .map(|name| name.to_ascii().trim_end_matches('.').to_owned());
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
            // The serve layer reports a peer no sandbox has with id 0
            // (`ServeOptions::sandbox`).
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
    operator: &'static dyn Operator,
}

/// What a request asks the resolver, and how its answer goes back.
struct Asked {
    /// The query, as a DNS message.
    query: Vec<u8>,
    /// How the answer goes back.
    format: Format,
}

/// How the answer to a request goes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// The resolver's DNS message (RFC 8484 §4.2).
    Message,
    /// Google's JSON API answer, as `application/json`.
    GoogleJson,
    /// Cloudflare's JSON answer, as `application/dns-json`.
    DnsJson,
}

impl Format {
    /// The media type of an answer in this format.
    fn media(self) -> &'static str {
        match self {
            Format::Message => DNS_MESSAGE,
            Format::GoogleJson => JSON,
            Format::DnsJson => DNS_JSON,
        }
    }
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
        let asked = match ask(&request, self.operator, ex) {
            Ok(asked) => asked,
            Err(refusal) => return Reply::Now(refusal.response()),
        };
        let resolver = self.front.resolver.clone();
        Reply::Later(Box::new(move |fcx| {
            Box::pin(async move {
                let Some(answer) = resolver.query(&fcx, client, asked.query).await else {
                    let refusal =
                        Refusal::Text(StatusCode::BAD_REQUEST, "The query is not a DNS query.\n");
                    return Ok(refusal.response());
                };
                Ok(answered(answer, asked.format))
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
    /// The operator's own answer.
    Operator(Box<Response<Body>>),
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
            Refusal::Operator(response) => *response,
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

/// The query `request` asks, or why it is refused, as `operator` refuses
/// it where RFC 8484 does not say.
fn ask(
    request: &Request<Body>,
    operator: &dyn Operator,
    ex: &mut Exchange<'_>,
) -> Result<Asked, Refusal> {
    let path = request.uri().path();
    let method = request.method();
    let allowed = match path {
        DNS_QUERY => "GET, POST",
        RESOLVE if operator.resolve_json() => "GET",
        _ => return Err(Refusal::Operator(Box::new(operator.not_found(request)))),
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
        let format = match param("ct") {
            Some(DNS_MESSAGE) => Format::Message,
            _ => Format::GoogleJson,
        };
        return json_query(&form.pairs, format, ex);
    }
    if let Some(dns) = param("dns") {
        let message = |query| Asked {
            query,
            format: Format::Message,
        };
        return base64url(dns).map(message).ok_or(Refusal::Text(
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
    if operator.dns_json() && (accepts_json || param("ct") == Some(DNS_JSON)) {
        return json_query(&form.pairs, Format::DnsJson, ex);
    }
    Err(Refusal::Operator(Box::new(operator.no_query(request))))
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
    Ok(Asked {
        query: body.to_vec(),
        format: Format::Message,
    })
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

/// The query the JSON API's parameters ask, answered in `format`: `name`
/// (required, RFC 4343 escapes allowed), `type` (a number from 1 to 65535
/// or a mnemonic, default A), `cd`, and `do`. Other parameters, such as
/// `edns_client_subnet` and `random_padding`, are ignored. The first of
/// duplicate parameters counts.
fn json_query(
    pairs: &[(String, String)],
    format: Format,
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
    Ok(Asked { query, format })
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

/// The response carrying the resolver's `answer` in `format`. An answer
/// that does not parse goes back as the message itself. Every DNS answer,
/// SERVFAIL and NXDOMAIN included, is `200 OK` (RFC 8484 §4.2.1).
fn answered(answer: Vec<u8>, format: Format) -> Response<Body> {
    let message = read_message(&answer).ok();
    let freshness = message.as_ref().and_then(freshness);
    let (body, media) = match (format, &message) {
        (Format::GoogleJson | Format::DnsJson, Some(message)) => {
            (Body::from(to_json(message)), format.media())
        }
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
                ("name".to_owned(), Value::from(name_text(query.name()))),
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
    let data = presentation(&record.data);
    Value::Object(vec![
        ("name".to_owned(), Value::from(name_text(&record.name))),
        (
            "type".to_owned(),
            Value::from(u32::from(u16::from(record.record_type()))),
        ),
        ("TTL".to_owned(), Value::from(record.ttl)),
        ("data".to_owned(), Value::from(data)),
    ])
}

/// RDATA in presentation format, as a master file holds it and BIND reads
/// it back.
///
/// TXT data is every character-string quoted, with no space between them,
/// as Google gives TXT and SPF data. HINFO, CAA, and NAPTR strings are
/// quoted and escaped (RFC 1035 §5.1), SVCB and HTTPS parameters are
/// written as RFC 9460 §2.1 and Appendix A give them, and a DNAME gives
/// its target. Every name is written by [`name_text`], in ASCII as
/// Google's and Cloudflare's APIs give names. Types without names whose
/// own text hickory writes in presentation format use it. Any other type,
/// NULL and types hickory does not know among them, takes the generic
/// `\# <length> <hex>` form (RFC 3597 §5).
fn presentation(data: &RData) -> String {
    match data {
        RData::TXT(txt) => txt.txt_data.iter().map(|part| quoted(part)).collect(),
        RData::HINFO(hinfo) => format!("{} {}", quoted(&hinfo.cpu), quoted(&hinfo.os)),
        RData::CAA(caa) => format!("{} {} {}", caa.flags(), caa.tag, quoted(&caa.value)),
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order,
            naptr.preference,
            quoted(&naptr.flags),
            quoted(&naptr.services),
            quoted(&naptr.regexp),
            name_text(&naptr.replacement)
        ),
        RData::SVCB(svcb) | RData::HTTPS(HTTPS(svcb)) => service_binding(svcb),
        RData::NS(NS(target)) | RData::CNAME(CNAME(target)) | RData::PTR(PTR(target)) => {
            name_text(target)
        }
        RData::MX(mx) => format!("{} {}", mx.preference, name_text(&mx.exchange)),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            name_text(&srv.target)
        ),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            name_text(&soa.mname),
            name_text(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
            let input = rrsig.input();
            format!(
                "{} {} {} {} {} {} {} {} {}",
                input.type_covered,
                input.algorithm,
                input.num_labels,
                input.original_ttl,
                input.sig_expiration.get(),
                input.sig_inception.get(),
                input.key_tag,
                name_text(&input.signer_name),
                base64::encode(rrsig.sig())
            )
        }
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => {
            let mut out = name_text(nsec.next_domain_name());
            for rtype in nsec.type_bit_maps() {
                out.push_str(&format!(" {rtype}"));
            }
            out
        }
        RData::A(_)
        | RData::AAAA(_)
        | RData::SSHFP(_)
        | RData::TLSA(_)
        | RData::OPENPGPKEY(_)
        | RData::DNSSEC(_) => data.to_string(),
        _ => match dname_target(data) {
            Some(target) => name_text(&target),
            None => generic(data),
        },
    }
}

/// A name in presentation format, as a master file holds it (RFC 1035
/// §5.1): each label as its octets, with A-labels as they are, a
/// character a master file reads otherwise escaped with a backslash, and
/// any other octet outside printable ASCII as `\DDD` in decimal.
fn name_text(name: &Name) -> String {
    if name.is_root() {
        return ".".to_owned();
    }
    let mut out = String::new();
    for label in name.iter() {
        for &byte in label {
            match byte {
                b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' | b'$' => {
                    out.push('\\');
                    out.push(char::from(byte));
                }
                0x21..=0x7e => out.push(char::from(byte)),
                _ => out.push_str(&format!("\\{byte:03}")),
            }
        }
        out.push('.');
    }
    out
}

/// SVCB or HTTPS RDATA in presentation format (RFC 9460 §2.1): the
/// priority, the target, and each parameter as `key=value`, a key without
/// a value for `no-default-alpn` and empty values.
fn service_binding(svcb: &SVCB) -> String {
    let mut out = format!("{} {}", svcb.svc_priority, name_text(&svcb.target_name));
    for (key, value) in &svcb.svc_params {
        let key = match key {
            SvcParamKey::Mandatory => "mandatory".to_string(),
            SvcParamKey::Alpn => "alpn".to_string(),
            SvcParamKey::NoDefaultAlpn => "no-default-alpn".to_string(),
            SvcParamKey::Port => "port".to_string(),
            SvcParamKey::Ipv4Hint => "ipv4hint".to_string(),
            SvcParamKey::EchConfigList => "ech".to_string(),
            SvcParamKey::Ipv6Hint => "ipv6hint".to_string(),
            other => format!("key{}", u16::from(*other)),
        };
        let value: Vec<u8> = match value {
            SvcParamValue::Mandatory(Mandatory(keys)) => keys
                .iter()
                .map(|key| key.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            // A comma or a backslash inside one ALPN ID is escaped, so the
            // list splits where it should (RFC 9460 Appendix A.1).
            SvcParamValue::Alpn(Alpn(ids)) => ids
                .iter()
                .map(|id| id.replace('\\', "\\\\").replace(',', "\\,"))
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::NoDefaultAlpn => Vec::new(),
            SvcParamValue::Port(port) => port.to_string().into_bytes(),
            SvcParamValue::Ipv4Hint(IpHint(addresses)) => addresses
                .iter()
                .map(|address| address.0.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::Ipv6Hint(IpHint(addresses)) => addresses
                .iter()
                .map(|address| address.0.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::EchConfigList(EchConfigList(list)) => base64::encode(list).into_bytes(),
            SvcParamValue::Unknown(Unknown(bytes)) => bytes.clone(),
        };
        out.push(' ');
        out.push_str(&key);
        if !value.is_empty() {
            out.push('=');
            // A value with nothing a master file would read otherwise
            // goes out as it is; any other is a quoted character-string.
            let plain = value.iter().all(|byte| {
                byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\' | b';' | b'(' | b')')
            });
            if plain {
                out.push_str(&String::from_utf8_lossy(&value));
            } else {
                out.push_str(&quoted(&value));
            }
        }
    }
    out
}

/// RDATA in the generic form of RFC 3597 §5: `\#`, the length, and the
/// octets in hexadecimal.
fn generic(data: &RData) -> String {
    let octets = data.to_bytes().unwrap_or_default();
    let mut out = format!("\\# {}", octets.len());
    if !octets.is_empty() {
        out.push(' ');
        for byte in octets {
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
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
