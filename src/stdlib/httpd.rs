//! HTTP as a service: a router whose handlers get plain byte bodies, an
//! adapter that runs any tower service (axum included), and name-based
//! virtual hosting, all on [`serve`].
//!
//! `Http1` is a caller-driven `Service` on the `http1` decoder.
//! `serve_connection` runs it over a live connection. HTTP/2 and hyper upgrades
//! require the `tokio` feature. TLS comes from
//! `fictionet::stdlib::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Three kinds come ready:
//!
//! - [`Router`]: routes by method and path to plain functions. A handler
//!   gets an [`Exchange`] (the clock reading, randomness, the connection)
//!   and an `http::Request<Bytes>`, and returns an `http::Response<Bytes>`.
//!   No runtime is involved, so it unit-tests with
//!   [`serve::Harness`]. An async route gets
//!   a [`Cx`] instead. Callbacks run only with bodies held in full;
//!   incomplete bodies get `400 Bad Request`.
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as deferred work of the connection.
//! - [`VirtualHosts`]: picks a handler by the request's host, as a web server
//!   with several sites at one address does, with the redirect to https and
//!   the `421 Misdirected Request` of [`web::Sites`](fictionet::stdlib::web::Sites).
//!
//! On a [`Net`](fictionet::stdlib::net::Net), a [`Server`] is the
//! [`PortServer`](fictionet::stdlib::net::PortServer) that serves HTTP on a host's
//! port: sites of several hosts at one address share the port as virtual
//! hosts. [`Server::served_by`] puts a site on ports 80 and 443 the way
//! websites are served. `Net` knows nothing of HTTP, so a copy of this
//! component with its own handlers plugs in the same way. Copy `httpd.rs`
//! together with the `httpd/` directory, keeping the relative paths.
//!
//! [`Http1`] is the [`Service`](fictionet::stdlib::serve::Service) that speaks
//! HTTP/1.0 and 1.1 to a client, on [`http1`]'s
//! decoder: keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
//! responses for bodies of unknown length, and 30-second limits on each
//! request's head and on its body. [`serve_connection`] picks the version for a
//! connection: HTTP/2 by ALPN or by the client's preface, else HTTP/1.
//! An unknown-length HTTP/1.1 body ends with a zero-size chunk only at EOF.
//! Pending polls and empty data frames do not end the response.
//! All backends suppress response bodies for `HEAD`, informational statuses,
//! `204` and `304`. For other statuses, `HEAD` keeps the handler's
//! `Content-Length`, or uses the body's known length when none was set.
//! Native HTTP/1 omits lengths for bodyless statuses and otherwise writes
//! the body's known length or chooses framing for an unknown length.
//! The hyper adapter leaves supplied lengths to hyper's framing rules.
//!
//! With `tokio`, a request that asks to switch protocols (`Connection: upgrade` with an
//! `Upgrade` field, as a WebSocket handshake does) makes [`Http1`] hand
//! the connection back ([`Upgrade::Handoff`](serve::Upgrade::Handoff)),
//! and [`serve_connection`] serves the rest of it on hyper's HTTP/1, which
//! carries out upgrades. The handler sees hyper's `OnUpgrade` in the
//! request's extensions, so an axum `WebSocketUpgrade` handler, or one that
//! calls `hyper::upgrade::on`, works on a [`Server`] as it does on hyper.
//! axum runs the socket in a tokio task, so that world needs a tokio
//! runtime. Without `tokio`, upgrade requests reach the ordinary handler.
//! A synchronous handler can return a `101` response with an [`UpgradeHandler`]
//! in its extensions to serve WebSocket messages on the connection. This
//! continuation also works with `tokio`.
//!
//! # Dates
//!
//! The world owns its dates. A response carries a `Date` header only when
//! the world gave the date it was at the start of the run, with
//! [`Http1::date`], [`HttpOptions::date`] or [`Server::date`]: the header
//! is then that date plus the run's clock.
//! Without one, responses have no `Date` header (RFC 9110 lets a server
//! with no clock leave it out). The host's clock is never used, so a world
//! set in 2019 never sends a date from the year it runs in. A `Date` the
//! handler sets itself is sent as it is.
//!
//! HTTP/2 runs on hyper, behind the same [`Handler`] trait and the
//! same events, with the same [`Limits`] and seeded randomness. It charges
//! the request heads, request events and bodies it holds to the connection's
//! [`Budget`]. A request head stays charged while its handler waits. Its
//! event stays charged until it is recorded, including while a response
//! streams. If hyper cannot charge the metadata, it rejects the stream
//! before calling the handler and records `answer: budget` without a status.
//! Transport buffers and hyper's own buffers are not charged. HTTP/2 request
//! body and write stall timeouts use Fictionet deadlines. Hyper runs without a
//! timer, with keep-alive pings and adaptive windows disabled. h2 retains
//! reset streams for its default `reset_stream_duration` of one second of
//! real time. Its reset-stream expiry reads the system clock, so late
//! frames for a stream the world reset more than one real second earlier
//! can behave differently between lab runs. Hyper does not let a server
//! change that setting, and h2 exposes no clock injection for it.
//!
//! ```
//! use bytes::Bytes;
//! use fictionet::stdlib::httpd::{Http1, Router};
//! use fictionet::stdlib::serve::Harness;
//!
//! let router = Router::new()
//!     .get("/hello", |_, _| http::Response::new(Bytes::from("hi\n")))
//!     .post("/echo", |_, request: http::Request<Bytes>| http::Response::new(request.into_body()));
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
//! let reply = h.push(b"GET /hello HTTP/1.1\r\nHost: a.test\r\n\r\n")?;
//! assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! assert!(reply.ends_with(b"\r\n\r\nhi\n"));
//! let reply = h.push(b"POST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nok")?;
//! assert!(reply.ends_with(b"\r\n\r\nok"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Events
//!
//! Every request a handler or the service answered is one `http.request`
//! event, also when the client gave up before the answer. Its fields:
//! `scheme`, `sni`, `host` (the URI's authority or the `Host` header, in
//! lowercase, without port or trailing dot, `null` if none), `method`,
//! `uri`, `path`, `query`, `version` (`HTTP/1.1`, `HTTP/2.0`), `headers`
//! (`[name, value]` pairs in the order of `http::HeaderMap`), `started`
//! (seconds on the run's clock), `answer` (`handler`, `error`, `cancelled`,
//! what the handler set, such as `redirect`, or, over HTTP/2, `too_large`,
//! `timeout`, `cut_off` or `budget` for a request the service turned
//! down), `status`, `sent` (body bytes the connection took) and `complete`
//! (whether it took the whole body). Over HTTP/1 a byte counts once it is
//! written, and the event is made after the last one is; over HTTP/2 once
//! hyper takes it for the stream. A handler adds its own fields by putting
//! [`Fields`] in its response's
//! extensions; they come first, and the service's own facts win a clash.
//! A connection that ends in an error is one `http.error` event, with
//! `local`, `cause` (`protocol`, `timeout` or `transport`) and `detail`.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body::{Body as _, Frame};

use fictionet::RaceError;
use fictionet::events::{ConnInfo, Fields};
use fictionet::stdlib::ConnectionExt;
use fictionet::stdlib::http1::{self, Event as H1, RequestHead};
use fictionet::stdlib::serve::Prefixed;
use fictionet::stdlib::serve::{
    self, Budget, Driver, Ended, Flow, Pending, PendingDriver, ServeOptions, Timer,
};
use fictionet::stdlib::{ConnError, Connection};
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, Error};

#[path = "httpd/body.rs"]
mod body;
#[path = "httpd/handlers.rs"]
mod handlers;
#[path = "httpd/response.rs"]
mod response;
#[path = "httpd/sites.rs"]
mod sites;

pub use body::Body;
pub use handlers::{
    BadGateway, Exchange, Handler, Later, Reply, Router, Tower, UpgradeHandler, text, tower,
};

pub use response::{date_header, http_date};
pub use sites::{Routing, Server, Target, VHost, VirtualHosts, normalize, request_host};

use body::Inner;
use handlers::status_only;
use response::{ResponsePolicy, Tracker, error_event, error_response, head_held, request_held};

// ---------------------------------------------------------------------------
// HTTP/1 as a service

/// HTTP's limits and timers, for both versions.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Head limits for HTTP/1's decoder.
    pub head: http1::Limits,
    /// The largest request body held. An oversized body gets `413`
    /// without calling the handler. Native HTTP/1 drains the request
    /// before answering and closes the connection. Hyper's HTTP/1
    /// upgrade path and HTTP/2 reject it during collection.
    /// Default 64 MiB.
    pub body: usize,
    /// HTTP/1: how long a request's head may take to arrive, counted from
    /// when the service starts waiting for it, which includes the wait
    /// between requests. This also applies to hyper's HTTP/1 upgrade
    /// path. HTTP/2 has no request-head deadline. Default 30 seconds.
    pub header_timeout: Duration,
    /// How long a request's body may take to arrive, counted from its
    /// head, so a client that trickles a body cannot hold the connection
    /// for ever. Native HTTP/1 closes the connection. Hyper's HTTP/1
    /// upgrade path and HTTP/2 answer `408` when collection times out,
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

/// [`Http1`]'s timer for a request's head.
const HEAD: Timer = "head";
/// [`Http1`]'s timer for a request's body.
const BODY: Timer = "body";

/// HTTP/1.0 and 1.1 for one connection, answering with a [`Handler`].
pub struct Http1 {
    handler: Arc<dyn Handler>,
    opts: Limits,
    /// The world's date at the start of the run, for `Date` headers.
    date: Option<SystemTime>,
    /// The head of a request that asked for a protocol upgrade, as bytes,
    /// once the connection is handed over for it.
    handoff: Option<Vec<u8>>,
    upgrade: Option<UpgradeHandler>,
    head: Option<RequestHead>,
    body: Vec<u8>,
    too_big: bool,
    started: Instant,
    first_head_deadline: Option<Instant>,
}

impl Http1 {
    /// Answers with `handler`, with default options.
    pub fn new(handler: impl Handler) -> Http1 {
        Http1::with(Arc::new(handler), Limits::default())
    }

    /// Answers with `handler` and `opts`.
    pub fn with(handler: Arc<dyn Handler>, opts: Limits) -> Http1 {
        Http1 {
            handler,
            opts,
            date: None,
            handoff: None,
            upgrade: None,
            head: None,
            body: Vec::new(),
            too_big: false,
            started: Instant::ZERO,
            first_head_deadline: None,
        }
    }

    /// The head of the request that asked for a protocol upgrade, such as
    /// a WebSocket handshake, after the service handed the connection back
    /// for it ([`Upgrade::Handoff`](serve::Upgrade::Handoff)): its bytes,
    /// to be read again in front of the connection's unread ones.
    /// [`serve_connection`] serves such a connection on hyper's HTTP/1,
    /// which carries out the upgrade.
    pub fn take_handoff(&mut self) -> Option<Vec<u8>> {
        self.handoff.take()
    }

    /// Sends a `Date` header with each response: `start`, the world's date
    /// and time at the start of the run, plus the run's clock. See
    /// [Dates](self#dates).
    pub fn date(mut self, start: SystemTime) -> Http1 {
        self.date = Some(start);
        self
    }

    fn respond(&mut self, driver: &mut Driver<'_, http1::RequestEvents>) -> Flow {
        let held = self.body.capacity();
        let body = Body::from(std::mem::take(&mut self.body));
        let close = self.too_big;
        self.dispatch(driver, body, close, held)
    }

    /// Calls the handler for the request whose head is pending, with
    /// `body`. `close` closes the connection after the answer.
    fn dispatch(
        &mut self,
        driver: &mut Driver<'_, http1::RequestEvents>,
        body: Body,
        close: bool,
        held: usize,
    ) -> Flow {
        let Some(head) = self.head.take() else {
            return Flow::Close;
        };
        let version = match head.version {
            http1::Version::Http10 => Version::HTTP_10,
            http1::Version::Http11 => Version::HTTP_11,
        };
        let keep_alive = !close && head.keep_alive().unwrap_or(false) && head.method != "CONNECT";
        let request = match to_request(&head, version, body) {
            Some(r) => r,
            None => {
                let date = date_header(self.date, driver.now());
                write_simple(driver.reply(), version, StatusCode::BAD_REQUEST, date);
                return Flow::Close;
            }
        };
        let mut request = request;
        request.extensions_mut().insert(driver.conn().clone());
        let head_only = request.method() == Method::HEAD;
        let tracker = Tracker::new(&request, driver.conn(), self.started);
        let held = held + request_held(&request);
        let now = driver.now();
        let conn = driver.conn().clone();
        let reply = if self.too_big {
            Reply::Now(status_only(StatusCode::PAYLOAD_TOO_LARGE))
        } else {
            self.handler
                .call(request, &mut Exchange::new(now, driver.entropy(), &conn))
        };
        if let Reply::Now(response) = &reply
            && response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(upgrade) = response.extensions().get::<UpgradeHandler>()
        {
            self.upgrade = Some(upgrade.clone());
        }
        let close = !keep_alive && self.upgrade.is_none();
        // Every answer goes out as deferred work, so its event is made
        // once its bytes are written.
        let (work, response) = match reply {
            Reply::Now(response) => (None, Some(response)),
            Reply::Later(work) => (Some(work), None),
        };
        driver.defer(
            Streaming::new(work, response, version, head_only, close, tracker)
                .dated(self.date, now)
                .holding_request(held),
        );
        if self.upgrade.is_some() {
            driver.cancel_timer(BODY);
            Flow::Upgrade(serve::Upgrade::Handoff)
        } else {
            self.after(driver, close)
        }
    }

    fn after(&mut self, driver: &mut Driver<'_, http1::RequestEvents>, close: bool) -> Flow {
        driver.cancel_timer(BODY);
        if close {
            return Flow::Close;
        }
        driver.set_timer(HEAD, self.opts.header_timeout);
        Flow::Continue
    }
}

fictionet::cfg_tokio! {
/// Whether an HTTP/1.1 request asks to switch protocols (RFC 9110 section
/// 7.8): it has an `Upgrade` field and names `upgrade` in `Connection`.
fn asks_upgrade(head: &RequestHead) -> bool {
    let has = |name: &str| {
        head.headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    };
    let connection_upgrade = head.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("connection")
            && h.value
                .split(|b| *b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
    });
    head.version == http1::Version::Http11
        && head.method != "CONNECT"
        && has("upgrade")
        && connection_upgrade
}
}

/// The head at the start of `unread`, read with an empty Host field added
/// after its request line, if that makes it a request head: an HTTP/1.1
/// request that named no host.
fn without_host(unread: &[u8]) -> Option<RequestHead> {
    let line_end = unread.windows(2).position(|w| w == b"\r\n")?;
    let head_end = unread.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    if head_end <= line_end {
        return None;
    }
    let mut patched = unread[..line_end + 2].to_vec();
    patched.extend_from_slice(b"Host:\r\n");
    patched.extend_from_slice(&unread[line_end + 2..head_end]);
    let mut head = <RequestHead as fictionet::stdlib::codec::Wire>::parse(&patched).ok()?;
    // The handler sees the request as it came, without the field added.
    if head
        .headers
        .first()
        .is_some_and(|h| h.name == "Host" && h.value.is_empty())
    {
        head.headers.remove(0);
    }
    Some(head)
}

/// A request body that ends early: `bytes`, then an error saying `why`.
/// A handler that reads it frame by frame sees what came.
fn partial(bytes: Bytes, why: &'static str) -> Body {
    struct Partial(Option<Bytes>, Option<&'static str>);
    impl http_body::Body for Partial {
        type Data = Bytes;
        type Error = Error;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
            let this = self.get_mut();
            if let Some(b) = this.0.take().filter(|b| !b.is_empty()) {
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            Poll::Ready(this.1.take().map(|why| Err(fictionet::Error::msg(why))))
        }
    }
    Body::new(Partial(Some(bytes), Some(why)))
}

fn to_request(head: &RequestHead, version: Version, body: Body) -> Option<Request<Body>> {
    let mut builder = Request::builder()
        .method(head.method.as_bytes())
        .uri(head.target.as_str())
        .version(version);
    let headers = builder.headers_mut()?;
    for h in &head.headers {
        let name = HeaderName::from_bytes(h.name.as_bytes()).ok()?;
        let value = HeaderValue::from_bytes(&h.value).ok()?;
        headers.append(name, value);
    }
    builder.body(body).ok()
}

/// Writes a response head. Returns whether the connection must close
/// after the body: a body of unknown length to an HTTP/1.0 client ends
/// with the connection.
fn encode(
    out: &mut Vec<u8>,
    version: Version,
    parts: &http::response::Parts,
    policy: &ResponsePolicy,
    close: bool,
) -> bool {
    let status = parts.status;
    let v10 = version == Version::HTTP_10;
    let mut close = close;
    out.extend_from_slice(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
    out.extend_from_slice(status.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &parts.headers {
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(date) = &policy.date {
        out.extend_from_slice(b"date: ");
        out.extend_from_slice(date.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match policy.len {
        Some(n) => out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes()),
        None if policy.bodiless => {}
        None if v10 => close = true,
        None => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
    }
    if status == StatusCode::SWITCHING_PROTOCOLS {
        out.extend_from_slice(b"connection: upgrade\r\n");
    } else if close && !v10 {
        out.extend_from_slice(b"connection: close\r\n");
    } else if !close && v10 {
        out.extend_from_slice(b"connection: keep-alive\r\n");
    }
    out.extend_from_slice(b"\r\n");
    close
}

fn write_simple(
    out: &mut Vec<u8>,
    version: Version,
    status: StatusCode,
    date: Option<HeaderValue>,
) {
    let (parts, _) = status_only(status).into_parts();
    let policy = ResponsePolicy::new(&parts, Some(0), false, date);
    encode(out, version, &parts, &policy, true);
}

impl serve::Service for Http1 {
    type Decoder = http1::RequestEvents;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> http1::RequestEvents {
        http1::RequestEvents::with_limits(self.opts.head)
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        let timeout = self
            .first_head_deadline
            .take()
            .map_or(self.opts.header_timeout, |at| {
                at.since_start().saturating_sub(driver.now().since_start())
            });
        driver.set_timer(HEAD, timeout);
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        item: H1<RequestHead>,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        match item {
            H1::Head(head) => {
                driver.cancel_timer(HEAD);
                fictionet::cfg_tokio! {
                if asks_upgrade(&head) {
                    let mut bytes = Vec::new();
                    if fictionet::stdlib::codec::Wire::write(&head, &mut bytes).is_ok() {
                        self.handoff = Some(bytes);
                        return Ok(Flow::Upgrade(serve::Upgrade::Handoff));
                    }
                }
                }
                driver.set_timer(BODY, self.opts.body_timeout);
                if head.expects_continue() {
                    driver
                        .reply()
                        .extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                self.started = driver.now();
                self.head = Some(head);
                self.body.clear();
                self.too_big = false;
            }
            H1::Body(bytes) => {
                if self.body.len() + bytes.len() > self.opts.body {
                    self.too_big = true;
                } else {
                    self.body.extend_from_slice(&bytes);
                }
            }
            H1::Done => return Ok(self.respond(driver)),
        }
        Ok(Flow::Continue)
    }

    fn on_timer(
        &mut self,
        _: Timer,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        let detail = if self.head.is_some() {
            Some("request body timed out")
        } else if !driver.unread().is_empty() {
            Some("request head timed out")
        } else {
            None
        };
        if let Some(detail) = detail {
            driver.record(error_event(driver.conn(), "timeout", detail.into()));
        }
        Ok(Flow::Close)
    }

    fn held(&self) -> usize {
        self.body.capacity() + self.head.as_ref().map_or(0, head_held)
    }

    fn on_fail(
        &mut self,
        error: &serve_fail::Fail,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<(), Infallible> {
        if self.head.is_some() {
            // The body was cut off: the handler still sees what came, as a
            // body that ends in an error.
            let mut got = std::mem::take(&mut self.body);
            let room = self.opts.body.saturating_sub(got.len());
            got.extend_from_slice(&driver.unread()[..driver.unread().len().min(room)]);
            let held = got.capacity();
            let body = partial(Bytes::from(got), "the request body was cut off");
            self.dispatch(driver, body, true, held);
            return Ok(());
        }
        if matches!(
            error,
            fictionet::stdlib::codec::Fail::Protocol(http1::Error::Host)
        ) && let Some(head) = without_host(driver.unread())
        {
            // An HTTP/1.1 request with no Host field: the handler answers
            // it, as a request that names no host (`400`, `no_host`).
            self.head = Some(head);
            self.started = driver.now();
            self.dispatch(driver, Body::empty(), true, 0);
            return Ok(());
        }
        driver.record(error_event(
            driver.conn(),
            "protocol",
            fictionet::ErrorChain(error).to_string(),
        ));
        let date = date_header(self.date, driver.now());
        write_simple(
            driver.reply(),
            Version::HTTP_11,
            StatusCode::BAD_REQUEST,
            date,
        );
        Ok(())
    }

    fn on_end(
        &mut self,
        end: Ended,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<(), Infallible> {
        if end == Ended::Conn(ConnError::Broken) {
            let e = error_event(
                driver.conn(),
                "transport",
                "a TLS record did not decrypt".into(),
            );
            driver.record(e);
        }
        Ok(())
    }
}

mod serve_fail {
    pub type Fail = fictionet::stdlib::codec::Fail<fictionet::stdlib::http1::Error>;
}

/// The most of a body handed to the connection at once, so the count of
/// bytes sent stays close to what went out.
const PIECE: usize = 16 * 1024;

/// A handler's response, on its way.
type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

/// A response being made or streamed, as deferred work of a connection.
///
/// Its event says what the connection took: each piece counts in `sent`
/// once the driver wrote all of it, and the event is made when the last
/// piece is written, or when the connection ends first.
struct Streaming {
    work: Option<Later>,
    making: Option<Making>,
    body: Option<Body>,
    rest: Bytes,
    rest_held: usize,
    request_held: usize,
    response: Option<Response<Body>>,
    version: Version,
    head_only: bool,
    close: bool,
    chunked: bool,
    tracker: Tracker,
    extra: Option<Fields>,
    status: Option<StatusCode>,
    /// Body bytes the connection took.
    body_sent: u64,
    /// Bytes returned to the driver, and the body bytes in the last piece,
    /// which count once the driver has written that far.
    returned: u64,
    in_flight: u64,
    finished: bool,
    /// The world's date at the start of the run, and when the request was
    /// answered, for the `Date` header.
    date: Option<SystemTime>,
    asked: Instant,
}

impl Streaming {
    fn new(
        work: Option<Later>,
        response: Option<Response<Body>>,
        version: Version,
        head_only: bool,
        close: bool,
        tracker: Tracker,
    ) -> Streaming {
        Streaming {
            work,
            making: None,
            body: None,
            rest: Bytes::new(),
            rest_held: 0,
            request_held: 0,
            response,
            version,
            head_only,
            close,
            chunked: false,
            tracker,
            extra: None,
            status: None,
            body_sent: 0,
            returned: 0,
            in_flight: 0,
            finished: false,
            date: None,
            asked: Instant::ZERO,
        }
    }

    fn holding_request(mut self, held: usize) -> Self {
        if self.work.is_some() {
            self.request_held = held;
        }
        self
    }

    fn take_piece(&mut self) -> Bytes {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Bytes::new();
            self.rest_held = 0;
        }
        piece
    }

    /// Dates the response from `date`, the world's date at the start of
    /// the run, when it is made; `asked` is the time without a [`Cx`].
    fn dated(self, date: Option<SystemTime>, asked: Instant) -> Streaming {
        Streaming {
            date,
            asked,
            ..self
        }
    }

    /// Counts the last piece's body bytes once the driver wrote it all.
    fn confirm(&mut self, driver: &PendingDriver<'_>) {
        if driver.written() >= self.returned {
            self.body_sent += std::mem::take(&mut self.in_flight);
        }
    }

    /// Hands the driver `bytes`, of which `body` are body bytes.
    fn piece(&mut self, bytes: Vec<u8>, body: usize) -> Poll<Option<Result<Vec<u8>, Error>>> {
        self.returned += bytes.len() as u64;
        self.in_flight = body as u64;
        Poll::Ready(Some(Ok(bytes)))
    }

    fn end(&mut self, driver: &mut PendingDriver<'_>, complete: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(e) =
            self.tracker
                .finish(self.extra.take(), self.status, self.body_sent, complete)
        {
            driver.record(e);
        }
    }

    /// `piece` as it goes on the wire: a chunk, when chunked.
    fn frame(&self, piece: &[u8], out: &mut Vec<u8>) {
        if self.chunked {
            out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(piece);
        }
    }
}

impl Pending for Streaming {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, Error>>> {
        // The driver polls again only once the last piece is written.
        self.confirm(driver);
        loop {
            if let Some(work) = self.work.take() {
                self.making = Some(match driver.fcx() {
                    Some(fcx) => work(fcx.clone()),
                    None => Box::pin(std::future::ready(Err(fictionet::Error::msg(
                        "this answer needs a Cx: give the harness one with Harness::with_fcx",
                    )))),
                });
            }
            if let Some(making) = &mut self.making {
                let response = match making.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(r)) => r,
                    Poll::Ready(Err(e)) => error_response(&e),
                };
                self.making = None;
                self.request_held = 0;
                self.response = Some(response);
            }
            if let Some(response) = self.response.take() {
                let (parts, body) = response.into_parts();
                let now = driver.fcx().map_or(self.asked, Cx::now);
                let policy = ResponsePolicy::new(
                    &parts,
                    body.size_hint().exact(),
                    self.head_only,
                    date_header(self.date, now),
                );
                let mut head = Vec::new();
                self.close = encode(&mut head, self.version, &parts, &policy, self.close);
                if self.close {
                    // An HTTP/1.0 body of unknown length ends with the
                    // connection, whatever the request asked for.
                    driver.close();
                }
                self.status = Some(parts.status);
                self.extra = parts.extensions.get::<Fields>().cloned();
                self.chunked =
                    !policy.bodiless && policy.len.is_none() && self.version != Version::HTTP_10;
                if policy.bodiless {
                    return self.piece(head, 0);
                }
                // A body held in full goes out with the head, a piece at
                // a time.
                match body.0 {
                    Inner::Full(bytes) => {
                        self.rest = bytes.unwrap_or_default();
                        self.rest_held = self.rest.len();
                    }
                    stream => self.body = Some(Body(stream)),
                }
                // A streamed body has nothing held yet, and an empty chunk
                // would end it before it starts.
                let piece = self.take_piece();
                if !piece.is_empty() {
                    self.frame(&piece, &mut head);
                }
                return self.piece(head, piece.len());
            }
            if !self.rest.is_empty() {
                let piece = self.take_piece();
                let mut out = Vec::with_capacity(piece.len() + 12);
                self.frame(&piece, &mut out);
                return self.piece(out, piece.len());
            }
            let Some(body) = &mut self.body else {
                self.end(driver, true);
                return Poll::Ready(None);
            };
            match Pin::new(body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.body = None;
                    if self.chunked {
                        self.chunked = false;
                        return self.piece(b"0\r\n\r\n".to_vec(), 0);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.body = None;
                    self.end(driver, false);
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        self.rest_held = data.len();
                        self.rest = data;
                    }
                }
            }
        }
    }

    fn cancel(&mut self, driver: &mut PendingDriver<'_>) {
        self.confirm(driver);
        if self.status.is_none() {
            self.extra = None;
        }
        self.end(driver, false);
    }

    fn held(&self) -> usize {
        let response = self.response.as_ref().map_or(0, |r| r.body().full_len());
        let body = self.body.as_ref().map_or(0, Body::full_len);
        self.request_held + self.tracker.held() + self.rest_held + response + body
    }
}

// ---------------------------------------------------------------------------
// One connection, either version

/// How [`serve_connection`] serves a connection.
#[derive(Clone, Default)]
pub struct HttpOptions {
    /// Limits and timers, for both versions.
    pub limits: Limits,
    /// On a connection without TLS, how long the client has from
    /// connecting to send its first bytes. Past it, the connection closes
    /// with an `http.error` event, cause `timeout`. `None` waits as long as
    /// the HTTP/1 head limit allows.
    pub first_bytes: Option<Duration>,
    /// What connections are charged to ([`ServeOptions::budget`]): over
    /// HTTP/1 what the service holds, over HTTP/2 each request's head and body,
    /// its event metadata, and each response frame until its last slice is
    /// dropped. Heads count method, URI and header bytes, plus header slots;
    /// hidden capacities, extensions and third-party overhead are excluded.
    /// Events use [`Event::size`](fictionet::events::Event::size). Transport and hyper buffers are excluded.
    /// Response storage is charged by its original byte length; spare capacity
    /// and backing storage outside a supplied slice are not exposed by `Bytes`.
    pub budget: Option<Budget>,
    /// The world's date and time at the start of the run, for `Date`
    /// headers. `None`: no `Date` header. See [Dates](self#dates).
    pub date: Option<SystemTime>,
}

fictionet::cfg_tokio! {
/// What an HTTP/2 client sends first, with no TLS ("prior knowledge").
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
}

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface; HTTP/1
/// otherwise. HTTP/2 and hyper upgrades require the `tokio` feature.
/// `info` names the connection in events.
///
/// Returns `Ok(())` when the connection ended, however it ended: a
/// connection's failure is the connection's, and the run's events say what
/// it was. Returns [`Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled first.
pub async fn serve_connection<C: Connection + Unpin>(
    fcx: &Cx,
    conn: C,
    info: ConnInfo,
    handler: Arc<dyn Handler>,
    opts: &HttpOptions,
) -> Result<(), Cancelled> {
    let mut conn = conn;
    let mut first = Vec::new();
    let head_deadline = fcx.now() + opts.limits.header_timeout;
    let first_timeout = opts.first_bytes.unwrap_or(opts.limits.header_timeout);
    let h2 = if info.tls {
        fictionet::cfg_tokio!({ info.alpn.as_deref() == Some(b"h2".as_slice()) } else { false })
    } else {
        // With HTTP/2, read enough to identify its preface. Otherwise,
        // wait for one byte to enforce the first-byte timeout.
        let preface = async {
            let mut buf = [0u8; 24];
            while fictionet::cfg_tokio!({ first.len() < PREFACE.len() && PREFACE.starts_with(&first) } else { first.is_empty() })
            {
                let room = fictionet::cfg_tokio!({ PREFACE.len() - first.len() } else { 1 });
                match conn.read(fcx, &mut buf[..room]).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                }
            }
            true
        };
        match fcx.race(Some(fcx.now() + first_timeout), preface).await {
            Ok(true) => {}
            Ok(false) if fcx.is_cancelled() => return Err(Cancelled),
            Ok(false) => return Ok(()),
            Err(RaceError::Cancelled) => return Err(Cancelled),
            Err(RaceError::Deadline) => {
                let secs = first_timeout.as_secs();
                fcx.record(
                    error_event(
                        &info,
                        "timeout",
                        format!("no bytes within {secs} seconds of connecting"),
                    )
                    .conn(&info),
                );
                return Ok(());
            }
        }
        fictionet::cfg_tokio!({ first == PREFACE } else { false })
    };
    let conn = Prefixed::new(first, conn);
    fictionet::cfg_tokio!({
        if h2 {
            return h2::serve(fcx, conn, handler, info, opts).await;
        }
    } else { let _ = h2; });
    let serve_opts = ServeOptions {
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
        connection_events: false,
        budget: opts.budget.clone(),
        ..ServeOptions::default()
    };
    let mut service = Http1::with(handler.clone(), opts.limits);
    service.date = opts.date;
    if !info.tls && opts.first_bytes.is_none() {
        service.first_head_deadline = Some(head_deadline);
    }
    match serve::connection(fcx, conn, info.clone(), &mut service, &(), &serve_opts).await {
        Ok(serve::Served::Upgraded(serve::Upgrade::Handoff, rest)) => {
            if let Some(upgrade) = service.upgrade.take() {
                upgrade.run(fcx.clone(), Box::new(rest)).await;
                return if fcx.is_cancelled() {
                    Err(Cancelled)
                } else {
                    Ok(())
                };
            }
            fictionet::cfg_tokio! {
                // Hyper reads the request again and carries out its upgrade.
                if let Some(head) = service.take_handoff() {
                    return h2::serve_upgrade(
                        fcx, Prefixed::new(head, rest), handler, info, opts,
                    ).await;
                }
            }
            Ok(())
        }
        Err(serve::ServeError::Cancelled) => Err(Cancelled),
        // The driver recorded the failure as a `conn.error` event.
        Ok(_) | Err(_) => Ok(()),
    }
}

fictionet::cfg_tokio! {
/// Live HTTP/2 and HTTP/1 Upgrade serving on hyper.
mod h2 {
    use super::*;
    use super::response::{Track, answered};
    use http::header::{CONTENT_LENGTH, DATE};
    use fictionet::stdlib::codec::{Buffer, Decode, Step};
    use fictionet::stdlib::serve::{Charge, PanicNote};
    use http_body::SizeHint;
    use hyper::body::Incoming;
    use std::future::poll_fn;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Runs hyper's HTTP/2 server on `conn`.
    pub(super) async fn serve<C: Connection + Unpin>(
        fcx: &Cx,
        conn: C,
        handler: Arc<dyn Handler>,
        info: ConnInfo,
        opts: &HttpOptions,
    ) -> Result<(), Cancelled> {
        let broke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let io = Io::new(fcx, conn, broke.clone(), opts.limits.write_timeout);
        let route = Route::new(fcx, handler, &info, opts);
        let mut builder = hyper::server::conn::http2::Builder::new(Executor { fcx: fcx.clone() });
        // hyper would take a `Date` header from the host's clock: the route
        // writes the world's.
        // Hyper still refreshes its internal date cache using SystemTime,
        // but auto_date_header(false) prevents that value reaching the wire.
        builder.auto_date_header(false);
        builder.max_concurrent_streams(opts.limits.streams);
        // h2 retains reset streams using its own host clock. Its public API
        // cannot inject Cx time; that third-party limitation remains in labs.
        // hyper reads all the time on HTTP/2, so a reset ends it on its own.
        let served = builder.serve_connection(io, route);
        finish(fcx, &info, &broke, fcx.race(None, served).await)
    }

    /// Runs hyper's HTTP/1 server on `conn`, with upgrades: where
    /// [`Http1`] hands over a connection whose request asks for a protocol
    /// upgrade, such as a WebSocket handshake. The request carries hyper's
    /// `OnUpgrade`, so `hyper::upgrade::on` and axum's `WebSocketUpgrade`
    /// work, and the connection goes to whatever awaits it once the `101`
    /// is sent. Other requests on the connection are answered as usual.
    pub(super) async fn serve_upgrade<C: Connection + Unpin + Send + 'static>(
        fcx: &Cx,
        conn: C,
        handler: Arc<dyn Handler>,
        info: ConnInfo,
        opts: &HttpOptions,
    ) -> Result<(), Cancelled> {
        let broke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut io = Io::new(
            fcx,
            Box::new(conn) as Box<dyn Connection>,
            broke.clone(),
            opts.limits.write_timeout,
        );
        let upgraded = Arc::new(AtomicBool::new(false));
        io.heads = Some(HeadCheck::new(fcx, opts.limits, upgraded.clone()));
        let mut route = Route::new(fcx, handler, &info, opts);
        route.upgraded = Some(upgraded);
        let mut builder = hyper::server::conn::http1::Builder::new();
        // Hyper still refreshes its internal date cache using SystemTime,
        // but auto_date_header(false) prevents that value reaching the wire.
        builder.auto_date_header(false);
        builder.max_headers(opts.limits.head.headers);
        // Hyper requires at least 8192 bytes. HeadCheck enforces smaller limits.
        builder.max_buf_size(opts.limits.head.head.max(8192));
        if cfg!(target_arch = "wasm32") {
            // HeadCheck enforces the deadline without a host Instant.
            builder.header_read_timeout(None);
        } else {
            builder.timer(CxTimer::new(fcx.clone()));
            builder.header_read_timeout(opts.limits.header_timeout);
        }
        let served = builder.serve_connection(io, route).with_upgrades();
        finish(fcx, &info, &broke, fcx.race(None, served).await)
    }

    /// How a connection hyper served ends: [`Cancelled`] if `fcx`'s region
    /// was cancelled, whether hyper saw it first or its I/O did; otherwise
    /// it ended, and an error is recorded.
    fn finish(
        fcx: &Cx,
        info: &ConnInfo,
        broke: &std::sync::atomic::AtomicBool,
        raced: Result<Result<(), hyper::Error>, RaceError>,
    ) -> Result<(), Cancelled> {
        let Ok(result) = raced else {
            return Err(Cancelled);
        };
        if fcx.is_cancelled() {
            return Err(Cancelled);
        }
        report(fcx, info, broke, result);
        Ok(())
    }

    /// Records how a connection hyper served ended, if in an error.
    fn report(
        fcx: &Cx,
        info: &ConnInfo,
        broke: &std::sync::atomic::AtomicBool,
        result: Result<(), hyper::Error>,
    ) {
        let broke = broke.load(std::sync::atomic::Ordering::Relaxed);
        let cause = match &result {
            Err(e) => match error_cause(e) {
                Some(cause) => Some((cause, e.to_string())),
                None if broke => Some(("transport", e.to_string())),
                None => None,
            },
            Ok(()) if broke => Some(("transport", "a TLS record did not decrypt".to_owned())),
            Ok(()) => None,
        };
        if let Some((cause, detail)) = cause {
            fcx.record(error_event(info, cause, detail).conn(info));
        }
    }

    /// Why hyper ended a connection with `e`, if it is an error worth an
    /// event: the client's bytes broke HTTP/2, or the TLS under it failed.
    fn error_cause(e: &hyper::Error) -> Option<&'static str> {
        if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() {
            return Some("protocol");
        }
        let mut source = std::error::Error::source(e);
        while let Some(s) = source {
            if let Some(e) = s.downcast_ref::<::h2::Error>() {
                if let Some(io) = e.get_io() {
                    return transport(io);
                }
                let protocol =
                    e.is_library() && e.reason().is_some_and(|r| r != ::h2::Reason::NO_ERROR);
                return protocol.then_some("protocol");
            }
            if let Some(io) = s.downcast_ref::<std::io::Error>() {
                return transport(io);
            }
            source = s.source();
        }
        None
    }

    fn transport(io: &std::io::Error) -> Option<&'static str> {
        let broken =
            io.get_ref().and_then(|e| e.downcast_ref::<ConnError>()) == Some(&ConnError::Broken);
        if broken {
            Some("transport")
        } else {
            match io.kind() {
                std::io::ErrorKind::InvalidData => Some("protocol"),
                std::io::ErrorKind::TimedOut => Some("timeout"),
                _ => None,
            }
        }
    }

    /// Answers each request hyper reads, with the connection's limits,
    /// budget and randomness.
    #[derive(Clone)]
    struct Route {
        fcx: Cx,
        handler: Arc<dyn Handler>,
        info: Arc<ConnInfo>,
        date: Option<SystemTime>,
        limits: Limits,
        budget: Option<Budget>,
        upgraded: Option<Arc<AtomicBool>>,
    }

    impl Route {
        fn new(fcx: &Cx, handler: Arc<dyn Handler>, info: &ConnInfo, opts: &HttpOptions) -> Route {
            Route {
                fcx: fcx.clone(),
                handler,
                info: Arc::new(info.clone()),
                date: opts.date,
                limits: opts.limits,
                budget: opts.budget.clone(),
                upgraded: None,
            }
        }

        /// Reads a request's body, charging it as it comes. `Err` is the
        /// answer instead.
        async fn body(
            &self,
            body: Incoming,
            charge: &mut Option<Charge>,
        ) -> Result<Bytes, Box<Response<Body>>> {
            let read = async {
                let mut body = pin!(body);
                let mut got = Vec::new();
                while let Some(frame) = poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                    let Ok(frame) = frame else {
                        return Err(Box::new(answered(
                            text(StatusCode::BAD_REQUEST, "The request body was cut off.\n"),
                            "cut_off",
                        )));
                    };
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let len = got.len() + data.len();
                    if len > self.limits.body {
                        return Err(Box::new(answered(
                            text(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "The request body is too large.\n",
                            ),
                            "too_large",
                        )));
                    }
                    if !charge.as_mut().is_none_or(|c| c.set(len)) {
                        return Err(Box::new(over_budget()));
                    }
                    got.extend_from_slice(&data);
                }
                Ok(Bytes::from(got))
            };
            match self
                .fcx
                .race(Some(self.fcx.now() + self.limits.body_timeout), read)
                .await
            {
                Ok(got) => got,
                Err(_) => Err(Box::new(answered(
                    text(
                        StatusCode::REQUEST_TIMEOUT,
                        "The request body took too long.\n",
                    ),
                    "timeout",
                ))),
            }
        }
    }

    /// The answer when the sandbox's budget cannot hold a body.
    fn over_budget() -> Response<Body> {
        answered(
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                "The server cannot hold this request now.\n",
            ),
            "budget",
        )
    }

    type Answer = Pin<Box<dyn Future<Output = Result<Response<Counted>, Error>> + Send>>;

    impl hyper::service::Service<Request<Incoming>> for Route {
        type Response = Response<Counted>;
        type Error = Error;
        type Future = Answer;

        fn call(&self, request: Request<Incoming>) -> Answer {
            let mut tracker = Tracker::new(&request, &self.info, self.fcx.now());
            let metadata = self.budget.as_ref().map(|budget| {
                let head = budget.charge(request_held(&request))?;
                let event = budget.charge(tracker.held())?;
                Some((head, event))
            });
            let (head_charge, event_charge) = match metadata {
                Some(Some((head, event))) => (Some(head), Some(event)),
                None => (None, None),
                Some(None) => {
                    if let Some(event) = tracker.finish(
                        Some(Fields::new().with("answer", "budget")), None, 0, false,
                    ) {
                        self.fcx.record(event.conn(&self.info));
                    }
                    return Box::pin(std::future::ready(Err(Error::msg(
                        "request metadata exceeds budget",
                    ))));
                }
            };
            let on_upgrade = request
                .extensions()
                .get::<hyper::upgrade::OnUpgrade>()
                .cloned();
            let route = self.clone();
            let track = Track {
                tracker,
                _charge: event_charge,
                fcx: route.fcx.clone(),
                info: route.info.clone(),
                extra: None,
                status: None,
                sent: 0,
                complete: false,
                _note: PanicNote::new("an httpd handler over HTTP/2", &route.info),
            };
            Box::pin(async move {
                // Dropped with the future if the client resets the stream.
                let mut track = track;
                // Charged a piece at a time: the request's body, then the
                // response body while it is held in full.
                let mut charge = route.budget.as_ref().and_then(|b| b.charge(0));
                let (parts, body) = request.into_parts();
                let head_only = parts.method == Method::HEAD;
                let response = match route.body(body, &mut charge).await {
                    Err(answer) => {
                        drop(parts);
                        *answer
                    }
                    Ok(body) => {
                        let mut request = Request::from_parts(parts, Body::from(body));
                        request.extensions_mut().insert((*route.info).clone());
                        let now = route.fcx.now();
                        let reply = route
                            .handler
                            .call(request, &mut Exchange::new(now, &route.fcx, &route.info));
                        match reply {
                            Reply::Now(r) => r,
                            Reply::Later(work) => match work(route.fcx.clone()).await {
                                Ok(r) => r,
                                Err(e) => error_response(&e),
                            },
                        }
                    }
                };
                drop(head_charge);
                if response.status() == StatusCode::SWITCHING_PROTOCOLS
                    && let Some(upgraded) = &route.upgraded
                {
                    upgraded.store(true, Ordering::Relaxed);
                }
                if response.status() == StatusCode::SWITCHING_PROTOCOLS
                    && let Some(upgrade) = response.extensions().get::<UpgradeHandler>().cloned()
                    && let Some(on_upgrade) = on_upgrade
                {
                    route.fcx.spawn(move |fcx| async move {
                        if let Ok(upgraded) = on_upgrade.await
                            && let Ok(parts) = upgraded.downcast::<Io<Box<dyn Connection>>>()
                        {
                            let mut first = parts.read_buf.to_vec();
                            if let Some(heads) = parts.io.heads {
                                first.extend_from_slice(heads.input.unread());
                            }
                            let conn = Prefixed::new(first, parts.io.conn);
                            upgrade.run(fcx, Box::new(conn)).await;
                        }
                        Ok(())
                    });
                }
                let (parts, body) = response.into_parts();
                let fits = charge.as_mut().is_none_or(|c| c.set(body.full_len()));
                let (mut parts, body) = if fits {
                    (parts, body)
                } else {
                    over_budget().into_parts()
                };
                let policy = ResponsePolicy::new(
                    &parts,
                    body.size_hint().exact(),
                    head_only,
                    date_header(route.date, route.fcx.now()),
                );
                if let Some(date) = policy.date {
                    parts.headers.insert(DATE, date);
                }
                track.extra = parts.extensions.get::<Fields>().cloned();
                track.status = Some(parts.status);
                let bodiless = policy.bodiless;
                let body = if bodiless {
                    // hyper would send the body on HTTP/2 even for HEAD,
                    // which breaks the stream.
                    if let Some(len) = policy.len
                        && !parts.headers.contains_key(CONTENT_LENGTH)
                    {
                        parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
                    }
                    track.complete = true;
                    Body::empty()
                } else {
                    body
                };
                if let Some(c) = &mut charge {
                    c.set(body.full_len());
                }
                parts.extensions = http::Extensions::new();
                Ok(Response::from_parts(
                    parts,
                    Counted {
                        body,
                        rest: Bytes::new(),
                        track,
                        bodiless,
                        failed: false,
                        charge,
                        budget: route.budget.clone(),
                    },
                ))
            })
        }
    }

    /// A response body that counts the bytes sent and makes the request's
    /// event when it ends or is dropped.
    pub(super) struct Counted {
        body: Body,
        rest: Bytes,
        track: Track,
        bodiless: bool,
        failed: bool,
        /// What the body held in full still holds.
        charge: Option<Charge>,
        budget: Option<Budget>,
    }

    impl http_body::Body for Counted {
        type Data = Bytes;
        type Error = Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
            let this = self.get_mut();
            if !this.rest.is_empty() {
                let piece = this.rest.split_to(this.rest.len().min(PIECE));
                if this.rest.is_empty() {
                    this.rest = Bytes::new();
                }
                this.track.sent += piece.len() as u64;
                return Poll::Ready(Some(Ok(Frame::data(piece))));
            }
            let mut polled = Pin::new(&mut this.body).poll_frame(cx);
            if let Poll::Ready(Some(Ok(frame))) = &mut polled
                && let Some(data) = frame.data_mut()
            {
                let mut charge = this
                    .charge
                    .take()
                    .or_else(|| this.budget.as_ref().and_then(|b| b.charge(0)));
                if charge.as_mut().is_some_and(|c| !c.set(data.len())) {
                    this.failed = true;
                    this.body = Body::empty();
                    return Poll::Ready(Some(Err(Error::msg("response body exceeds budget"))));
                }
                *data = Bytes::from_owner(ChargedBytes {
                    bytes: std::mem::take(data),
                    _charge: charge,
                });
                if data.len() > PIECE {
                    this.rest = data.split_off(PIECE);
                }
            }
            match &polled {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        this.track.sent += data.len() as u64;
                    }
                }
                Poll::Ready(Some(Err(_))) => {
                    this.failed = true;
                    this.track.complete = false;
                }
                Poll::Ready(None) => this.track.complete = true,
                Poll::Pending => {}
            }
            polled
        }

        fn is_end_stream(&self) -> bool {
            self.rest.is_empty() && self.body.is_end_stream()
        }

        fn size_hint(&self) -> SizeHint {
            let inner = self.body.size_hint();
            let rest = self.rest.len() as u64;
            let mut hint = SizeHint::new();
            if let Some(upper) = inner.upper() {
                hint.set_upper(upper + rest);
            }
            hint.set_lower(inner.lower() + rest);
            hint
        }
    }

    struct ChargedBytes {
        bytes: Bytes,
        _charge: Option<Charge>,
    }

    impl AsRef<[u8]> for ChargedBytes {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            // hyper may stop polling once the body says it has ended.
            if !self.failed && (http_body::Body::is_end_stream(self) || self.bodiless) {
                self.track.complete = true;
            }
        }
    }

    /// Validates request framing before hyper receives it, including heads
    /// after an Upgrade request that received an ordinary response.
    struct HeadCheck {
        decoder: http1::RequestEvents,
        input: Buffer,
        ready: usize,
        eof: bool,
        upgraded: Arc<AtomicBool>,
        timer: fictionet::Timer,
        deadline: Option<Instant>,
        timeout: Duration,
    }

    impl HeadCheck {
        fn new(fcx: &Cx, limits: Limits, upgraded: Arc<AtomicBool>) -> Self {
            let decoder = http1::RequestEvents::with_limits(limits.head);
            let input = Buffer::new(decoder.capacity());
            Self {
                decoder,
                input,
                ready: 0,
                eof: false,
                upgraded,
                timer: fictionet::Timer::new(fcx),
                deadline: Some(fcx.now() + limits.header_timeout),
                timeout: limits.header_timeout,
            }
        }

        fn poll_read<C: Connection + Unpin>(
            &mut self,
            conn: &mut C,
            fcx: &Cx,
            cx: &mut Context<'_>,
            out: &mut hyper::rt::ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            loop {
                if self.upgraded.load(Ordering::Relaxed) {
                    self.ready = self.input.len();
                }
                if self.ready != 0 {
                    let n = self.ready.min(out.remaining());
                    out.put_slice(&self.input.unread()[..n]);
                    self.input.consume(n);
                    self.ready -= n;
                    return Poll::Ready(Ok(()));
                }
                if !self.upgraded.load(Ordering::Relaxed) {
                    if let Some(deadline) = self.deadline {
                        match self.timer.poll_until(cx, deadline) {
                            Poll::Ready(Ok(())) => {
                                return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
                            }
                            Poll::Ready(Err(_)) => {
                                return Poll::Ready(Err(ConnError::Cancelled.into()));
                            }
                            Poll::Pending => {}
                        }
                    }
                    match self.decoder.decode(self.input.unread(), self.eof) {
                        Ok(Step::Item(item, n)) => {
                            match item {
                                H1::Head(_) => self.deadline = None,
                                H1::Done => self.deadline = Some(fcx.now() + self.timeout),
                                H1::Body(_) => {}
                            }
                            self.ready = n;
                            continue;
                        }
                        Ok(Step::Skip(n)) => {
                            self.ready = n;
                            continue;
                        }
                        Ok(Step::End) => return Poll::Ready(Ok(())),
                        Ok(Step::Need) => {}
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                e,
                            )));
                        }
                    }
                }
                if self.eof {
                    if self.upgraded.load(Ordering::Relaxed) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
                }
                self.input.set_limit(self.decoder.capacity());
                let spare = self.input.spare();
                if spare.is_empty() {
                    return Poll::Ready(Err(std::io::ErrorKind::InvalidData.into()));
                }
                match conn.poll_read(fcx, cx, spare) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Ready(Ok(n)) => {
                        self.input.commit(n);
                        self.eof = n == 0;
                    }
                }
            }
        }
    }

    /// The timer of a write that waits.
    type Stall = Pin<Box<dyn Future<Output = Result<(), fictionet::Cancelled>> + Send>>;

    /// A connection as hyper's `Read` and `Write`. A write that takes no
    /// bytes for `stall` fails with `TimedOut`, which ends the connection:
    /// a client that stopped reading.
    struct Io<C> {
        fcx: Cx,
        conn: C,
        broke: Arc<std::sync::atomic::AtomicBool>,
        buf: Box<[u8]>,
        stall: Duration,
        /// Armed while a write waits.
        stalled: Option<Stall>,
        heads: Option<HeadCheck>,
    }

    impl<C: Connection + Unpin> Io<C> {
        fn new(
            fcx: &Cx,
            conn: C,
            broke: Arc<std::sync::atomic::AtomicBool>,
            stall: Duration,
        ) -> Io<C> {
            Io {
                fcx: fcx.clone(),
                conn,
                broke,
                buf: vec![0; 16 * 1024].into_boxed_slice(),
                stall,
                stalled: None,
                heads: None,
            }
        }

        /// One write, with the stall timer: armed when it waits, cleared
        /// when bytes go.
        fn write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
            match self.conn.poll_write(&self.fcx, cx, data) {
                Poll::Pending => {
                    let fcx = self.fcx.clone();
                    let stall = self.stall;
                    let timer = self
                        .stalled
                        .get_or_insert_with(|| Box::pin(async move { fcx.sleep(stall).await }));
                    match timer.as_mut().poll(cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Err(ConnError::TimedOut)),
                        Poll::Ready(Err(_)) => Poll::Ready(Err(ConnError::Cancelled)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                done => {
                    self.stalled = None;
                    done
                }
            }
        }
    }

    impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            mut buf: hyper::rt::ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if let Some(heads) = &mut this.heads {
                return heads.poll_read(&mut this.conn, &this.fcx, cx, &mut buf);
            }
            let want = buf.remaining().min(this.buf.len());
            match this.conn.poll_read(&this.fcx, cx, &mut this.buf[..want]) {
                Poll::Ready(Ok(n)) => {
                    buf.put_slice(&this.buf[..n]);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    if e == ConnError::Broken {
                        this.broke.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    Poll::Ready(Err(e.into()))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut().write(cx, data).map_err(std::io::Error::from)
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let mut done = 0;
            for buf in bufs.iter().filter(|b| !b.is_empty()) {
                match this.write(cx, buf) {
                    Poll::Ready(Ok(n)) => {
                        done += n;
                        if n < buf.len() {
                            break;
                        }
                    }
                    Poll::Ready(Err(e)) if done == 0 => return Poll::Ready(Err(e.into())),
                    Poll::Pending if done == 0 => return Poll::Pending,
                    Poll::Ready(Err(_)) | Poll::Pending => break,
                }
            }
            // Bytes went: a later wait counts from now.
            this.stalled = None;
            Poll::Ready(Ok(done))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.conn
                .poll_shutdown(&this.fcx, cx)
                .map_err(std::io::Error::from)
        }
    }

    /// Runs hyper's streams as tasks, which end when the world stops.
    #[derive(Clone)]
    struct Executor {
        fcx: Cx,
    }

    impl<F> hyper::rt::Executor<F> for Executor
    where
        F: Future<Output = ()> + Send + 'static,
    {
        fn execute(&self, work: F) {
            self.fcx.spawn(move |fcx| async move {
                let mut work = pin!(work);
                let mut stopping = pin!(fcx.cancelled());
                poll_fn(|cx| {
                    if work.as_mut().poll(cx).is_ready() || stopping.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(());
                    }
                    Poll::Pending
                })
                .await;
                Ok(())
            });
        }
    }

    /// hyper's timer, on the run's clock.
    #[derive(Clone)]
    struct CxTimer {
        fcx: Cx,
        origin: std::time::Instant,
    }

    impl CxTimer {
        fn new(fcx: Cx) -> Self {
            Self {
                fcx,
                origin: std::time::Instant::now(),
            }
        }

        fn at(&self, deadline: fictionet::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
            Box::pin(CxSleep(fictionet::Timer::new(&self.fcx), deadline))
        }
    }

    impl hyper::rt::Timer for CxTimer {
        fn now(&self) -> std::time::Instant {
            self.origin + self.fcx.now().since_start()
        }

        fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
            let at = self
                .fcx
                .now()
                .since_start()
                .checked_add(duration)
                .unwrap_or(Duration::MAX);
            self.at(fictionet::time::Instant::from_since_start(at))
        }

        fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
            self.at(fictionet::time::Instant::from_since_start(
                deadline.saturating_duration_since(self.origin),
            ))
        }
    }

    /// A sleep for hyper, which cannot represent cancellation.
    struct CxSleep(fictionet::Timer, fictionet::time::Instant);

    impl Future for CxSleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            match this.0.poll_until(cx, this.1) {
                Poll::Ready(Ok(())) => Poll::Ready(()),
                _ => Poll::Pending,
            }
        }
    }

    impl hyper::rt::Sleep for CxSleep {}

    #[cfg(test)]
    mod tests {
        use super::*;
        use fictionet::stdlib::json::Value;
        use fictionet::sync::Mutex;
        use hyper::rt::Timer;

        #[test]
        fn response_frames_keep_the_charge_after_the_body_is_dropped() {
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(0),
                |fcx| async move {
                    let budget = Budget::new(3 * PIECE);
                    let info = Arc::new(ConnInfo::default());
                    let request = Request::new(Body::empty());
                    let mut body = Counted {
                        body: Body::from(vec![b'x'; 2 * PIECE]),
                        rest: Bytes::new(),
                        track: Track {
                            tracker: Tracker::new(&request, &info, fcx.now()),
                            _charge: None,
                            fcx: fcx.clone(),
                            info: info.clone(),
                            extra: None,
                            status: Some(StatusCode::OK),
                            sent: 0,
                            complete: false,
                            _note: PanicNote::new("test response", &info),
                        },
                        bodiless: false,
                        failed: false,
                        charge: budget.charge(2 * PIECE),
                        budget: Some(budget.clone()),
                    };
                    let mut cx = Context::from_waker(std::task::Waker::noop());
                    let Poll::Ready(Some(Ok(first))) = Pin::new(&mut body).poll_frame(&mut cx)
                    else {
                        panic!("first frame")
                    };
                    assert_eq!(budget.used(), 2 * PIECE);
                    let Poll::Ready(Some(Ok(last))) = Pin::new(&mut body).poll_frame(&mut cx)
                    else {
                        panic!("last frame")
                    };
                    drop(body);
                    drop(first);
                    assert_eq!(budget.used(), 2 * PIECE);
                    assert_eq!(last.data_ref().unwrap().len(), PIECE);
                    drop(last);
                    assert_eq!(budget.used(), 0);
                    Ok(())
                },
            ))
            .unwrap();
        }

        #[test]
        fn hyper_deadlines_use_the_clock_at_creation() {
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(0),
                |fcx| async move {
                    let timer = CxTimer::new(fcx.clone());
                    let origin = timer.now();
                    let relative = timer.sleep(Duration::from_secs(10));
                    let absolute = timer.sleep_until(origin + Duration::from_secs(20));
                    fcx.sleep(Duration::from_secs(5)).await?;
                    assert_eq!(timer.now().duration_since(origin), Duration::from_secs(5));
                    // First polling a sleep later does not shift its deadline.
                    relative.await;
                    assert_eq!(fcx.now().since_start(), Duration::from_secs(10));
                    absolute.await;
                    assert_eq!(fcx.now().since_start(), Duration::from_secs(20));
                    let later_timer = CxTimer::new(fcx.clone());
                    later_timer
                        .sleep_until(later_timer.now() + Duration::from_secs(3))
                        .await;
                    assert_eq!(fcx.now().since_start(), Duration::from_secs(23));
                    Ok(())
                },
            ))
            .unwrap();
        }

        struct StalledBody {
            input: Bytes,
        }

        impl Connection for StalledBody {
            fn poll_read(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<Result<usize, ConnError>> {
                if self.input.is_empty() {
                    return Poll::Pending;
                }
                let n = buf.len().min(self.input.len());
                buf[..n].copy_from_slice(&self.input.split_to(n));
                Poll::Ready(Ok(n))
            }

            fn poll_write(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<Result<usize, ConnError>> {
                Poll::Ready(Ok(data.len()))
            }

            fn poll_shutdown(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), ConnError>> {
                Poll::Ready(Ok(()))
            }
        }

        #[test]
        fn http2_body_timeout_uses_the_fictionet_deadline() {
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(1),
                |fcx| async move {
                    let mut input = PREFACE.to_vec();
                    input.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
                    // POST / over HTTP, with no END_STREAM on the headers.
                    let block = b"\x83\x86\x84\x01\x01a";
                    input.extend_from_slice(&[0, 0, block.len() as u8, 1, 4, 0, 0, 0, 1]);
                    input.extend_from_slice(block);
                    let conn = StalledBody {
                        input: Bytes::from(input),
                    };
                    let duration = Duration::from_millis(40);
                    let opts = HttpOptions {
                        limits: Limits {
                            body_timeout: duration,
                            ..Limits::default()
                        },
                        ..HttpOptions::default()
                    };
                    let handler = Router::new().post("/", |_, _| {
                        panic!("a stalled body cannot reach the handler")
                    });
                    let mut served = pin!(serve(
                        &fcx,
                        conn,
                        Arc::new(handler),
                        ConnInfo::default(),
                        &opts
                    ));
                    let log = fcx.events();
                    let wait = async {
                        loop {
                            if let Some(event) = log.of("http", "request").pop() {
                                return event;
                            }
                            fcx.sleep(Duration::from_millis(1)).await.unwrap();
                        }
                    };
                    let mut wait = pin!(wait);
                    let event = fcx
                        .race(
                            Some(fcx.now() + Duration::from_secs(2)),
                            poll_fn(|cx| {
                                assert!(served.as_mut().poll(cx).is_pending());
                                wait.as_mut().poll(cx)
                            }),
                        )
                        .await
                        .unwrap();
                    let started = event.get("started").unwrap().as_f64().unwrap();
                    let elapsed = event.at.since_start().as_secs_f64() - started;
                    assert_eq!(elapsed, duration.as_secs_f64());
                    assert_eq!(event.str("answer"), Some("timeout"));
                    assert_eq!(event.u64("status"), Some(408));
                    assert_eq!(event.str("version"), Some("HTTP/2.0"));
                    assert_eq!(event.get("complete").and_then(Value::as_bool), Some(true));
                    assert_eq!(log.of("http", "request").len(), 1);
                    assert!(log.of("http", "error").is_empty());
                    Ok(())
                },
            ))
            .unwrap();
        }

        /// A hyper sleep on a cancelled `Cx` stays pending instead of
        /// firing.
        #[test]
        fn a_cancelled_sleep_never_fires() {
            fictionet::block_on(fictionet::run(
                fictionet::Seed::random(),
                |fcx| async move {
                    let slot: Arc<Mutex<Option<Cx>>> = Arc::default();
                    let s = slot.clone();
                    let _ = fcx
                        .region(|inner| async move {
                            *s.lock() = Some(inner.clone());
                            inner.cancel();
                            Ok(())
                        })
                        .await;
                    let inner = slot.lock().take().unwrap();
                    assert!(inner.is_cancelled());
                    let mut sleep = CxTimer::new(inner).sleep(Duration::from_secs(5));
                    let pending = |sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>| {
                        sleep
                            .as_mut()
                            .poll(&mut Context::from_waker(std::task::Waker::noop()))
                            .is_pending()
                    };
                    assert!(pending(&mut sleep));
                    fcx.sleep(Duration::from_millis(5)).await?;
                    assert!(pending(&mut sleep));
                    Ok(())
                },
            ))
            .unwrap();
        }
    }
}
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use fictionet::sync::Mutex;

    #[test]
    fn response_suffix_keeps_the_original_charge() {
        use fictionet::stdlib::codec::{Ending, Lines};
        use fictionet::stdlib::serve::{Harness, Service};
        struct Checked {
            inner: Streaming,
            held: Arc<Mutex<Vec<usize>>>,
        }
        impl Pending for Checked {
            fn poll_next(
                &mut self,
                driver: &mut PendingDriver<'_>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Vec<u8>, Error>>> {
                let result = self.inner.poll_next(driver, cx);
                self.held.lock().push(self.inner.held());
                result
            }
        }
        struct Start(Option<Checked>);
        impl Service for Start {
            type Decoder = Lines;
            type State = ();
            type Error = Infallible;
            fn decoder(&self) -> Lines {
                Lines::new(16, Ending::LfOrCrlf)
            }
            fn on_item(
                &mut self,
                _: <Lines as fictionet::stdlib::codec::Decode>::Item,
                _: &(),
                _: &mut Driver<'_, Lines>,
            ) -> Result<Flow, Infallible> {
                Ok(Flow::Close)
            }
            fn on_open(
                &mut self,
                _: &(),
                driver: &mut Driver<'_, Lines>,
            ) -> Result<Flow, Infallible> {
                driver.defer(self.0.take().unwrap());
                Ok(Flow::Close)
            }
        }
        let held = Arc::new(Mutex::new(Vec::new()));
        let tracker = Tracker::new(
            &Request::new(Body::empty()),
            &ConnInfo::default(),
            Instant::ZERO,
        );
        let metadata = tracker.held();
        let inner = Streaming::new(
            None,
            Some(Response::new(Body::from(vec![b'x'; 3 * PIECE]))),
            Version::HTTP_11,
            false,
            true,
            tracker,
        );
        let mut harness = Harness::new(
            fictionet::Seed::from_u64(0),
            Start(Some(Checked {
                inner,
                held: held.clone(),
            })),
            (),
        );
        harness.open().unwrap();
        assert_eq!(
            &held.lock()[..3],
            &[3 * PIECE + metadata, 3 * PIECE + metadata, metadata]
        );
        assert_eq!(held.lock().last(), Some(&0));
    }
}
