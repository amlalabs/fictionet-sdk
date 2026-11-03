//! DNS over TLS and DNS over HTTPS in front of a running [`Recursive`](super::Recursive):
//! the same engines and caches answer, whichever way a query arrives.
//!
//! [`Fronts`] puts a resolver's [`ResolverHandle`] behind two more ports of
//! a host. On TCP port 853 it serves DNS over TLS (RFC 7858): each query
//! after its two-octet length, as over TCP port 53, pipelined, and answered
//! as each answer is ready. On TCP port 443 it serves DNS over HTTPS
//! (RFC 8484) to its names and to clients that connect to the address
//! with no name: `GET /dns-query?dns=...` and `POST /dns-query` with the
//! query as `application/dns-message`, answered in the same media type
//! with a `Cache-Control` freshness no longer than the answer's smallest
//! TTL (RFC 8484 §5.1).
//!
//! Every other request, a path other than `/dns-query` or a GET with no
//! `dns` parameter, goes to the world's [`fallback`](Fronts::fallback)
//! handler, such as one that serves a JSON API or a real operator's error
//! pages. Without one it gets a plain `404` or `400`.
//!
//! A query from either front reaches the resolver as a stream client
//! ([`Transport::Tcp`]) from the connection's peer and sandbox, so a
//! sandbox's DNS over HTTPS answer comes from the cache its UDP questions
//! filled, with the same TTL countdown and the same validation.
//!
//! The certificates are the world's: a TLS server proves who it is with
//! its private key on every handshake, and the world holds no operator's
//! key. A world's CA issues a resolver's certificate for its DNS over
//! HTTPS names and its addresses, as IP SANs (RFC 5280 §4.2.1.6), so a
//! client that connects to an address checks it as it would check a name.
//! DNS over QUIC is not served: UDP port 853 stays closed.
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

use http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::base64::{self, Padding};
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::protocols::dns::{Framing, Queries, read_message, stream_framed};
use fictionet::stdlib::protocols::urlencoded_form::{self, Form};
use fictionet::stdlib::services::dns::Client;
use fictionet::stdlib::services::serve::{
    self, ConnInfo, Driver, Flow, Pending, PendingDriver, ServeOptions, Service, Transport,
};
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply, request_host};
use fictionet::{Cx, Error};

use super::super::{Arrival, Host, PortServer, Sni};
use super::ResolverHandle;

/// The port of DNS over TLS (RFC 7858 §3.1).
const DOT_PORT: u16 = 853;

/// The port of DNS over HTTPS: HTTPS's own (RFC 8484 §5, RFC 9110 §4.2.2).
const DOH_PORT: u16 = 443;

/// The path RFC 8484's examples use, which every large operator serves.
const DNS_QUERY: &str = "/dns-query";

/// The media type of a DNS message over HTTPS (RFC 8484 §6).
const DNS_MESSAGE: &str = "application/dns-message";

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
    fallback: Option<Arc<dyn Handler>>,
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
            fallback: None,
        }
    }

    /// Answers every DNS over HTTPS request RFC 8484 does not cover with
    /// `handler`: a path other than `/dns-query`, and a GET of it with no
    /// `dns` parameter. It is called only for requests to the fronts'
    /// names and address. A handler that puts questions to the resolver
    /// itself, such as a JSON API, does so through
    /// [`client`](Self::client) and [`resolver`](Self::resolver) of the
    /// fronts it answers for, so it is made after
    /// [`resolver_at`](Self::resolver_at).
    pub fn fallback(self, handler: Arc<dyn Handler>) -> Fronts {
        Fronts {
            fallback: Some(handler),
            ..self
        }
    }

    /// The names DNS over HTTPS answers to, such as `dns.example`. A
    /// request over TLS for another name, by SNI or by its host, gets
    /// `421 Misdirected Request`; a request for the address it arrived
    /// at, with no name, is answered.
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
    /// needs it, such as DNS over HTTPS at the addresses of a name of its
    /// own that are not the resolver's. The resolver then sees each query
    /// as asked of `addr`.
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

    /// The client a query over `conn` reaches the resolver as: the
    /// connection's peer and sandbox over [`Transport::Tcp`], asking the
    /// address the connection arrived at, or the one
    /// [`resolver_at`](Self::resolver_at) gives. `None` for a connection
    /// with no addresses, which no network made.
    pub fn client(&self, conn: &ConnInfo) -> Option<Client> {
        self.front().client(conn)
    }

    /// The resolver the fronts put queries to.
    pub fn resolver(&self) -> &ResolverHandle {
        &self.resolver
    }

    /// `host` serving DNS over TLS on TCP port 853, for any name a client
    /// sends, offering `dot`, the ALPN identifier IANA registers for it.
    pub fn dot(&self, host: Host) -> Host {
        let tls = self.tls.clone();
        let port = Dot {
            front: Arc::new(self.front()),
        };
        host.tls_accept(DOT_PORT, Sni::Any, move |fcx| tls(fcx), port)
    }

    /// `host` serving DNS over HTTPS on TCP port 443, over HTTP/1.1 and
    /// HTTP/2. Its handshake takes any name, since a client that connects
    /// to the address sends none; its requests are answered only for
    /// [`names`](Self::names) and the address. Those names are its own on
    /// the port, so no other host at the address can serve them there.
    pub fn doh(&self, host: Host) -> Host {
        let server = || {
            let server = httpd::Server::new(Doh {
                front: Arc::new(self.front()),
                names: self.names.clone(),
                fallback: self.fallback.clone(),
            })
            .https()
            .default_host();
            match self.date {
                Some(start) => server.date(start),
                None => server,
            }
        };
        let tls = self.tls.clone();
        let mut host = host.tls_accept(DOH_PORT, Sni::Any, move |fcx| tls(fcx), server());
        for name in &self.names {
            let tls = self.tls.clone();
            let sni = Sni::from(name.to_ascii().as_str());
            host = host.tls_accept(DOH_PORT, sni, move |fcx| tls(fcx), server());
        }
        host
    }

    fn front(&self) -> Front {
        Front {
            resolver: self.resolver.clone(),
            at: self.at,
        }
    }
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

/// DNS over HTTPS for one resolver: RFC 8484 at `/dns-query`, for the
/// fronts' names and the address, and the world's fallback for the rest.
struct Doh {
    front: Arc<Front>,
    names: Vec<LowerName>,
    fallback: Option<Arc<dyn Handler>>,
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
        let query = match ask(&request) {
            Asked::Query(query) => query,
            Asked::Refused(refusal) => return Reply::Now(refusal.response()),
            Asked::Elsewhere(refusal) => {
                return match &self.fallback {
                    Some(fallback) => fallback.call(request, ex),
                    None => Reply::Now(refusal.response()),
                };
            }
        };
        let resolver = self.front.resolver.clone();
        Reply::Later(Box::new(move |fcx| {
            Box::pin(async move {
                let Some(answer) = resolver.query(&fcx, client, query).await else {
                    let refusal =
                        Refusal::Text(StatusCode::BAD_REQUEST, "The query is not a DNS query.\n");
                    return Ok(refusal.response());
                };
                Ok(message_response(answer))
            })
        }))
    }
}

/// What a request asks of RFC 8484's `/dns-query`.
enum Asked {
    /// This query, as a DNS message.
    Query(Vec<u8>),
    /// Nothing, for this reason RFC 8484 gives.
    Refused(Refusal),
    /// Nothing RFC 8484 covers: the fallback answers it, or else this
    /// refusal.
    Elsewhere(Refusal),
}

/// Why a request gets no answer from the resolver.
enum Refusal {
    /// This status, with this text.
    Text(StatusCode, &'static str),
    /// `405 Method Not Allowed`, with the methods the path allows.
    Method(&'static str),
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

/// The query `request` asks of `/dns-query` (RFC 8484 §4.1), or why it
/// asks none.
fn ask(request: &Request<Body>) -> Asked {
    if request.uri().path() != DNS_QUERY {
        return Asked::Elsewhere(Refusal::Text(StatusCode::NOT_FOUND, "Not found.\n"));
    }
    let method = request.method();
    if *method == Method::POST {
        return posted(request);
    }
    if *method != Method::GET {
        return Asked::Refused(Refusal::Method("GET, POST"));
    }
    let query = request.uri().query().unwrap_or("");
    let Ok(form) = Form::parse(query.as_bytes()) else {
        return Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "Bad query string.\n",
        ));
    };
    let Some(dns) = urlencoded_form::first(&form.pairs, "dns") else {
        return Asked::Elsewhere(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The request has no dns parameter.\n",
        ));
    };
    match base64url(dns) {
        Some(query) => Asked::Query(query),
        None => Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The dns parameter is not a DNS message in base64url.\n",
        )),
    }
}

/// The DNS message a POST carries as its body (RFC 8484 §4.1).
fn posted(request: &Request<Body>) -> Asked {
    let media = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    if media.as_deref() != Some(DNS_MESSAGE) {
        return Asked::Refused(Refusal::Text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type.\n",
        ));
    }
    let Some(body) = request.body().bytes() else {
        return Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The body did not arrive whole.\n",
        ));
    };
    if body.len() > MAX_MESSAGE {
        return Asked::Refused(Refusal::Text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "A DNS message is at most 65535 octets.\n",
        ));
    }
    Asked::Query(body.to_vec())
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

/// The response carrying the resolver's `answer` as
/// `application/dns-message`, with a `Cache-Control` freshness from
/// [`freshness`] when the answer parses. Every DNS answer, SERVFAIL and
/// NXDOMAIN included, is `200 OK` (RFC 8484 §4.2.1).
pub fn message_response(answer: Vec<u8>) -> Response<Body> {
    let freshness = read_message(&answer).ok().as_ref().and_then(freshness);
    let mut response = Response::new(Body::from(answer));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
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
pub fn freshness(message: &Message) -> Option<u32> {
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
