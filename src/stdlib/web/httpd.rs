//! HTTP as a service: plain handlers, an adapter for tower services (axum
//! included), and name-based virtual hosting.
//!
//! [`Http1`] is a [`Layer`](fictionet::stdlib::layer::Layer) over an
//! ordered byte stream. [`Http2`] is the HTTP/2 connection as a layer, on
//! the shared HTTP/2 frame layer and HPACK, with one [`HttpExchange`] child
//! per stream above it: [`Respond`] answers one with a [`Handler`], and
//! [`Grpc`] serves gRPC calls on one ([`Responder::http2`] composes a
//! server). Both versions run with `std` alone. [`serve_connection`] runs
//! them over a live connection. TLS comes from
//! `fictionet::stdlib::services::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Adapters and virtual hosting:
//!
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as the connection's work.
//! - [`VirtualHosts`]: picks a handler by the request's host, as a web server
//!   with several sites at one address does, with the redirect to https and
//!   the `421 Misdirected Request` of [`web::Sites`](fictionet::stdlib::web::Sites).
//!
//! On a [`Net`](fictionet::stdlib::world::net::Net), a [`Server`] is the
//! [`PortServer`](fictionet::stdlib::world::net::PortServer) that serves HTTP on a host's
//! port: sites of several hosts at one address share the port as virtual
//! hosts. [`Server::served_by`] puts a site on ports 80 and 443 the way
//! websites are served. `Net` knows nothing of HTTP, so a copy of this
//! component with its own handlers plugs in the same way. Copy `httpd.rs`
//! together with the `httpd/` directory, keeping the relative paths.
//!
//! [`Http1`] speaks HTTP/1.0 and 1.1 to a client, on [`http1`]'s decoder:
//! keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
//! responses for bodies of unknown length, and 30-second limits on each
//! request's head and on its body. [`serve_connection`] picks the version for a
//! connection in one layer stack ([`http_for`]): HTTP/2 by ALPN, by the
//! client's preface ([`Detect`]), or by `Upgrade: h2c` ([`Http1::h2c`]), else
//! HTTP/1. [`Detect::new`] takes a factory for each version, so a copy of
//! `http_for` passes servers of its own, and only the chosen one is made.
//! An unknown-length HTTP/1.1 body ends with a zero-size chunk only at EOF.
//! Pending polls and empty data frames do not end the response.
//! All backends suppress response bodies for `HEAD`, informational statuses,
//! `204` and `304`. For other statuses, `HEAD` keeps the handler's
//! `Content-Length`, or uses the body's known length when none was set.
//! Native HTTP/1 omits lengths for bodyless statuses and otherwise writes
//! the body's known length or chooses framing for an unknown length.
//! HTTP/2 preserves a valid supplied length when it agrees with that policy,
//! and on `304` preserves the supplied length of the selected representation.
//! Native HTTP/1 writes its own `Connection` header. It closes the
//! connection after a response, other than `101`, whose handler's
//! `Connection` header names `close`, and drops the handler's other tokens.
//! It writes field names with each word capitalized (`Content-Type`), as
//! most HTTP/1 servers do. HTTP/2 names stay lowercase, as that protocol
//! requires.
//!
//! An upgrade request reaches the native HTTP/1 handler. A handler hands
//! the connection on by putting an [`UpgradeHandler`] in the extensions of
//! a `101` answer, or of a 2xx answer to CONNECT: once the answer is
//! written, HTTP is over, and [`Http1::upgradable`] runs the upgrade
//! handler on the rest of the stream, with the bytes the client sent past
//! the request first. The stdlib's
//! [`websocket`](fictionet::stdlib::protocols::websocket) codec can serve it
//! directly.
//! # Dates
//!
//! The world owns its dates. A response carries a `Date` header only when
//! the world gave the date it was at the start of the run, with
//! [`Http1::date`], [`Http2::date`], [`Responder::date`],
//! [`HttpOptions::date`] or [`Server::date`]: the header is then that date
//! plus the run's clock. HTTP/2 dates each head on the connection, as it
//! frames it, so a connection composed by hand with its own children, such
//! as [`Grpc`] calls, is dated by [`Http2::date`].
//! Without one, responses have no `Date` header (RFC 9110 lets a server
//! with no clock leave it out). The host's clock is never used, so a world
//! set in 2019 never sends a date from the year it runs in. A `Date` the
//! handler sets itself is sent as it is.
//!
//! HTTP/2 uses the same [`Handler`], [`Limits`] and seeded randomness.
//! The connection charges its frame buffer, HPACK state, stream state and
//! output frames, and each exchange its request head and body and its
//! response, to the connection's [`Budget`]. A head that does not fit is
//! refused with `REFUSED_STREAM` before its handler runs. A body that
//! exceeds its allowance receives `503`. Transport storage belongs to its
//! transport. After the HTTP/2 server resets a stream, it ignores that
//! stream's late HEADERS and DATA for one second. It holds at most 50 reset
//! streams at a time. HEADERS and DATA on any other closed stream are errors.
//! The one-second hold, body deadlines and SETTINGS acknowledgment deadlines
//! are all timed on the run's clock.
//! Stream flow control, reset limits and bounded header assembly apply
//! independently of the runtime. PING and GOAWAY are handled by the
//! connection; graceful shutdown ([`Http2::graceful_shutdown`]) drains
//! admitted streams.
//!
//! ```
//! use fictionet::stdlib::layer::Harness;
//! use fictionet::stdlib::services::stack::Polling;
//! use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
//!
//! struct Pages;
//! impl Handler for Pages {
//!     fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
//!         let body = match request.uri().path() {
//!             "/hello" => Body::from("hi\n"),
//!             _ => request.into_body(),
//!         };
//!         Reply::Now(http::Response::new(body))
//!     }
//! }
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Pages)).with_worker(Polling::new());
//! h.push(b"GET /hello HTTP/1.1\r\nHost: a.test\r\n\r\n")?;
//! let reply = h.take_output();
//! assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! assert!(reply.ends_with(b"\r\n\r\nhi\n"));
//! h.push(b"POST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nok")?;
//! assert!(h.take_output().ends_with(b"\r\n\r\nok"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Observation
//!
//! A world reports typed facts directly from its handlers. For delivery
//! accounting, [`HttpOptions::observe`] receives the request and response heads,
//! receipt outcome, and body bytes in completely written pieces. Response
//! extensions carry world-owned facts without a shared event schema.
//!
//! Configure [`Server::observe`] for an individual HTTP server, or
//! [`Sites::observe_http`](super::Sites::observe_http) for the servers a website
//! preset creates. The preset shares its callback with sites discovered later;
//! an explicit server callback takes precedence. Sites sharing an address and
//! port use the first server's callback. When building hosts with `Net` directly,
//! clone the shared callback into each HTTP server's configuration.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::stdlib::layer::{Budget, Side, Switch};
use fictionet::stdlib::network::{ConnInfo, Connection};
use fictionet::stdlib::protocols::http1;
use fictionet::stdlib::services::stack::{self, StackError, StreamLimits};
use fictionet::{Cancelled, Cx};

mod body;
mod detect;
mod handlers;
mod http2;
mod native;
mod response;
mod sites;

pub use body::Body;
pub use detect::{Detect, Http, MakeVersion, Versions};
pub use handlers::{
    BadGateway, Exchange, Handler, Later, Reply, Reset, Tower, UpgradeHandler, text, tower,
};

pub use http2::{
    Ending, ExchangeCommand, ExchangeEvent, Grpc, GrpcCommand, GrpcEvent, Http2, Http2Server,
    HttpExchange, Opening, Report as Http2Report, RequestTrailers, Respond, RespondWork, Responder,
    ResponseHead, Timer as Http2Timer,
};
pub use native::{
    Closing, Done as Http1Done, Http1, Next, Report as Http1Report, Timer as Http1Timer, Upgraded,
    Work as Http1Work,
};
use response::Dates;
pub use response::{date_header, http_date};
pub use sites::{Answer, Routing, Server, Target, VHost, VirtualHosts, normalize, request_host};

/// How receipt of a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// The whole body arrived within the limits.
    Complete,
    /// Receipt ended before the whole body arrived.
    CutOff,
    /// A body chunk exceeded the body limit.
    TooLarge,
    /// The body deadline expired.
    Timeout,
    /// The request could not fit in the service budget.
    Budget,
}

/// A finished or interrupted response to a dispatched HTTP request.
/// Rejections before dispatch (including malformed heads and HTTP/1 body timeouts)
/// are outside this callback. Request and response extensions belong to the
/// world; the server does not interpret them.
pub struct Observation {
    /// When the request was dispatched.
    pub at: fictionet::time::Instant,
    /// The connection carrying the request.
    pub conn: ConnInfo,
    /// The parsed request head, without its body.
    pub request: http::request::Parts,
    /// The response selected for transmission, if one was produced.
    pub response: Option<http::response::Parts>,
    /// Whether the entire request arrived.
    pub received: Received,
    /// Response body bytes in fully written pieces. An interrupted piece is
    /// not counted, so this is a lower bound on bytes accepted by the transport.
    pub sent: u64,
    /// The response stream ended normally and all emitted framing was written.
    pub complete: bool,
}

/// Receives one observation when a dispatched response finishes or is cancelled.
/// Callbacks run synchronously and should hand off slow work themselves.
pub type Observe = Arc<dyn Fn(Observation) + Send + Sync>;

struct Delivery {
    observe: Observe,
    observation: Option<Observation>,
    produced: u64,
    pending: Option<(u64, usize)>,
    held: usize,
}

impl Delivery {
    fn new(
        observe: &Option<Observe>,
        request: &http::Request<Body>,
        conn: &ConnInfo,
        at: fictionet::time::Instant,
        received: Received,
    ) -> Option<Self> {
        let observe = observe.as_ref()?.clone();
        let mut head = http::Request::new(());
        *head.method_mut() = request.method().clone();
        *head.uri_mut() = request.uri().clone();
        *head.version_mut() = request.version();
        *head.headers_mut() = request.headers().clone();
        *head.extensions_mut() = request.extensions().clone();
        let held = response::request_held(&head);
        Some(Self {
            held,
            observe,
            observation: Some(Observation {
                at,
                conn: conn.clone(),
                request: head.into_parts().0,
                response: None,
                received,
                sent: 0,
                complete: false,
            }),
            produced: 0,
            pending: None,
        })
    }

    fn response(&mut self, parts: &http::response::Parts) {
        if let Some(observation) = &mut self.observation {
            self.held += response::response_held(parts);
            observation.response = Some(parts.clone());
        }
    }

    fn piece(&mut self, length: usize, body: usize) {
        self.produced += length as u64;
        self.pending = Some((self.produced, body));
    }

    fn update(&mut self, written: u64) {
        if let Some((end, body)) = self.pending
            && written >= end
        {
            if let Some(observation) = &mut self.observation {
                observation.sent += body as u64;
            }
            self.pending = None;
        }
    }

    fn finish(&mut self, written: u64, complete: bool) {
        self.update(written);
        self.end(complete);
    }

    /// The whole frames of `body` response body bytes were written, all
    /// told, as a multiplexed connection counts them.
    fn written(&mut self, body: u64) {
        if let Some(observation) = &mut self.observation {
            observation.sent = observation.sent.max(body);
        }
    }

    /// Hands the observation over: the response ended, or was cut off.
    fn end(&mut self, complete: bool) {
        if let Some(mut observation) = self.observation.take() {
            self.held = 0;
            observation.complete = complete;
            (self.observe)(observation);
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        if let Some(observation) = self.observation.take() {
            (self.observe)(observation);
        }
    }
}

/// HTTP's limits and timers, for both versions.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Head limits for HTTP/1's decoder.
    pub head: http1::Limits,
    /// The largest request body held. An oversized body gets `413`
    /// without calling the handler. Native HTTP/1 drains the request
    /// before answering and closes the connection. HTTP/2 rejects it during collection.
    /// Default 64 MiB.
    pub body: usize,
    /// HTTP/1: how long a request's head may take to arrive, counted from
    /// when the service starts waiting for it, which includes the wait
    /// between requests. HTTP/2 has no request-head deadline. Default 30 seconds.
    pub header_timeout: Duration,
    /// How long a request's body may take to arrive, counted from its
    /// head, so a client that trickles a body cannot hold the connection
    /// for ever. Native HTTP/1 closes the connection. HTTP/2 answers `408` when collection times out,
    /// or `400` on a body read error, without calling the handler.
    /// All these deadlines use the Fictionet clock. Default 30 seconds.
    pub body_timeout: Duration,
    /// How long a write may take no bytes before the connection ends: a
    /// client that stopped reading. Default 30 seconds.
    pub write_timeout: Duration,
    /// HTTP/2: the most streams open at once on one connection, which
    /// the server announces in its settings. Default 100, the least RFC
    /// 9113 recommends.
    pub streams: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            head: http1::Limits::default(),
            body: 64 << 20,
            header_timeout: Duration::from_secs(30),
            body_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            streams: 100,
        }
    }
}

/// The most of a body handed to the connection at once, so the count of
/// bytes sent stays close to what went out.
const PIECE: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// One connection, either version

/// How [`serve_connection`] serves a connection.
#[derive(Clone, Default)]
pub struct HttpOptions {
    /// Optional completion callback, shared by both HTTP versions.
    pub observe: Option<Observe>,
    /// Limits and timers, for both versions.
    pub limits: Limits,
    /// On a connection without TLS, how long the client has from
    /// connecting to send its first bytes. Past it, the connection closes
    /// if no bytes arrived. `None` waits as long as
    /// the HTTP/1 head limit allows.
    pub first_bytes: Option<Duration>,
    /// What connections are charged to: over
    /// HTTP/1 and HTTP/2 what the runner and the stack hold, including each request's head and body,
    /// and each response frame until its last slice is
    /// dropped. Heads count method, URI and header bytes, plus header slots;
    /// hidden capacities, extensions and third-party overhead are excluded.
    /// Transport buffers are excluded.
    /// Response storage is charged by its original byte length; spare capacity
    /// and backing storage outside a supplied slice are not exposed by `Bytes`.
    pub budget: Option<Budget>,
    /// The world's date and time at the start of the run, for `Date`
    /// headers. `None`: no `Date` header. See [Dates](self#dates).
    pub date: Option<SystemTime>,
}

/// What either version's server for one connection is made from: the
/// handler and the options both versions share. [`http_for`] makes the
/// version TLS negotiated at once; without TLS, [`Detect`] keeps this until
/// the client's first bytes say which version to make. A copy of
/// `http_for` passes [`Detect::new`] factories of its own instead.
pub struct Servers {
    handler: Arc<dyn Handler>,
    limits: Limits,
    observe: Option<Observe>,
    date: Option<SystemTime>,
    conn: ConnInfo,
    /// HTTP/1 accepts `Upgrade: h2c`.
    h2c: bool,
    /// When the head of HTTP/1's first request is due, if it is counted
    /// from the connection's start rather than from HTTP/1's.
    first_head_deadline: Option<fictionet::time::Instant>,
}

impl Servers {
    fn new(handler: Arc<dyn Handler>, opts: &HttpOptions, info: &ConnInfo) -> Servers {
        Servers {
            handler,
            limits: opts.limits,
            observe: opts.observe.clone(),
            date: opts.date,
            conn: info.clone(),
            h2c: false,
            first_head_deadline: None,
        }
    }
}

impl MakeVersion for Servers {
    fn http1(self) -> Switch<Http1, Upgraded> {
        let mut http1 = Http1::with(self.handler, self.limits).conn(self.conn);
        http1.dates = Dates::new(self.date);
        http1.observe = self.observe;
        http1.first_head_deadline = self.first_head_deadline;
        if self.h2c {
            http1 = http1.h2c();
        }
        http1.upgradable()
    }

    fn http2(self) -> Http2Server {
        Responder::shared(self.handler)
            .limits(self.limits)
            .maybe_observe(self.observe)
            .maybe_date(self.date)
            .conn(self.conn)
            .http2()
    }
}

/// HTTP for one connection, answering with `handler` as `opts` says: the
/// stack [`serve_connection`] runs. Over TLS it is the version ALPN chose,
/// from the start; without TLS, [`Detect`] tells HTTP/2's preface from
/// HTTP/1 within the first-bytes deadline and then makes that version, and
/// HTTP/1 accepts `Upgrade: h2c`.
pub fn http_for(
    handler: Arc<dyn Handler>,
    opts: &HttpOptions,
    info: &ConnInfo,
    now: fictionet::time::Instant,
) -> Http {
    let mut servers = Servers::new(handler, opts, info);
    if info.tls {
        let h2 = info.alpn.as_deref() == Some(b"h2".as_slice());
        return Side::Lower(servers.version(h2));
    }
    servers.h2c = true;
    if opts.first_bytes.is_none() {
        // The head of the first request has the same deadline from the
        // start, however long telling the versions apart took.
        servers.first_head_deadline = Some(now + opts.limits.header_timeout);
    }
    let first = opts.first_bytes.unwrap_or(opts.limits.header_timeout);
    Side::Upper(Switch::new(Detect::with(first, servers)))
}

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface or upgrades with
/// `Upgrade: h2c`; HTTP/1 otherwise. Both versions work with `std`, in one
/// layer stack ([`http_for`]) run by
/// [`services::stack::stream`](fictionet::stdlib::services::stack::stream).
/// `info` supplies connection metadata to the handler.
/// An empty half-close is silent. EOF within an HTTP/2 preface goes through
/// HTTP/1's truncated-head handling and answers 400.
///
/// Returns `Ok(())` when the connection ended, however it ended: a
/// connection's failure ends that connection. Returns [`Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled first.
pub async fn serve_connection<C: Connection + Unpin>(
    fcx: &Cx,
    conn: C,
    info: ConnInfo,
    handler: Arc<dyn Handler>,
    opts: &HttpOptions,
) -> Result<(), Cancelled> {
    let stack = http_for(handler, opts, &info, fcx.now());
    let budget = opts.budget.clone().unwrap_or_else(Budget::unlimited);
    let limits = StreamLimits {
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
    };
    match stack::stream(fcx, conn, &info, stack, budget, limits, |_| {}).await {
        Err(StackError::Cancelled) => Err(Cancelled),
        // A layer that gives up ends its connection alone.
        Ok(_) | Err(StackError::Layer(_)) => Ok(()),
    }
}
