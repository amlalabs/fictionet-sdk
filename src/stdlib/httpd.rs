//! HTTP as a service: a router whose handlers get plain byte bodies, an
//! adapter that runs any tower service (axum included), and name-based
//! virtual hosting, all on [`serve`].
//!
//! `Http1` is a caller-driven `Service` on the `http1` decoder.
//! `serve_connection` runs it over a live connection. HTTP/2 and HTTP/1 Upgrade
//! handling use hyper, not the `http2` frame layer. TLS comes from
//! `fictionet::stdlib::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Three kinds come ready:
//!
//! - [`Router`]: routes by method and path to plain functions. A handler
//!   gets an [`Exchange`] (the clock reading, randomness, the connection)
//!   and an `http::Request<Bytes>`, and returns an `http::Response<Bytes>`.
//!   No runtime is involved, so it unit-tests with
//!   [`serve::Harness`]. An async route gets
//!   a [`Cx`] instead.
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as deferred work of the connection.
//! - [`VirtualHosts`]: picks a handler by the request's host, as a web server
//!   with several sites at one address does, with the redirect to https and
//!   the `421 Misdirected Request` of [`web::Sites`](fictionet::stdlib::web::Sites).
//!
//! On a [`Net`](fictionet::stdlib::net::Net), a [`Server`] is the
//! [`PortServer`] that serves HTTP on a host's
//! port: sites of several hosts at one address share the port as virtual
//! hosts. [`Website`] puts a site on ports 80 and 443 the way websites
//! are served. `Net` knows nothing of HTTP, so a copy of this file with
//! its own handlers plugs in the same way.
//!
//! [`Http1`] is the [`Service`](fictionet::stdlib::serve::Service) that speaks
//! HTTP/1.0 and 1.1 to a client, on [`http1`]'s
//! decoder: keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
//! responses for bodies of unknown length, and 30-second limits on each
//! request's head and on its body. [`serve_connection`] picks the version for a
//! connection: HTTP/2 by ALPN or by the client's preface, else HTTP/1.
//!
//! A request that asks to switch protocols (`Connection: upgrade` with an
//! `Upgrade` field, as a WebSocket handshake does) makes [`Http1`] hand
//! the connection back ([`Upgrade::Handoff`](serve::Upgrade::Handoff)),
//! and [`serve_connection`] serves the rest of it on hyper's HTTP/1, which
//! carries out upgrades. The handler sees hyper's `OnUpgrade` in the
//! request's extensions, so an axum `WebSocketUpgrade` handler, or one that
//! calls `hyper::upgrade::on`, works on a [`Server`] as it does on hyper.
//! axum runs the socket in a tokio task, so that world needs a tokio
//! runtime.
//!
//! # Dates
//!
//! The world owns its dates. A response carries a `Date` header only when
//! the world gave the date it was at the start of the run, with
//! [`Http1::date`], [`HttpOptions::date`], [`Server::date`] or
//! [`Website::date`]: the header is then that date plus the run's clock.
//! Without one, responses have no `Date` header (RFC 9110 lets a server
//! with no clock leave it out). The host's clock is never used, so a world
//! set in 2019 never sends a date from the year it runs in. A `Date` the
//! handler sets itself is sent as it is.
//!
//! HTTP/2 runs on hyper, behind the same [`Handler`] trait and the
//! same events, with the same [`Limits`] and seeded randomness. It charges
//! the request and response bodies it holds to the connection's
//! [`Budget`]. hyper's own buffers are not charged. HTTP/2 request body
//! and write stall timeouts use Fictionet deadlines. Hyper runs without a
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
//! `timeout`, `cut_off` or `budget` for a request body the service turned
//! down), `status`, `sent` (body bytes the connection took) and `complete`
//! (whether it took the whole body). Over HTTP/1 a byte counts once it is
//! written, and the event is made after the last one is; over HTTP/2 once
//! hyper takes it for the stream. A handler adds its own fields by putting
//! [`Fields`] in its response's
//! extensions; they come first, and the service's own facts win a clash.
//! A connection that ends in an error is one `http.error` event, with
//! `local`, `cause` (`protocol`, `timeout` or `transport`) and `detail`.

use std::any::Any;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::{Buf, Bytes};
use http::header::{CONTENT_LENGTH, DATE, HOST, LOCATION};
use http::uri::{Authority, Scheme};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body::{Body as _, Frame, SizeHint};

use fictionet::events::{ConnInfo, Event, Fields, Level, float, opt};
use fictionet::stdlib::http1::{self, Event as H1, RequestHead};
use fictionet::stdlib::json::Value;
use fictionet::stdlib::net::{Arrival, ConfigFor, Host, PortServer, Sni};
use fictionet::stdlib::serve::{
    self, Budget, Driver, Ended, Flow, Pending, PendingDriver, Prefixed, ServeOptions, Timer,
};
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt};
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, Error, RaceError};

// ---------------------------------------------------------------------------
// Bodies

type Boxed = Pin<Box<dyn http_body::Body<Data = Bytes, Error = Error> + Send>>;

/// The body of every request a handler gets and every response it
/// returns: bytes known in full, or a stream of them.
///
/// A request's body is always whole: the service reads it before calling
/// the handler. A response's body may stream, as a tower service's does;
/// one whose length is known goes out with `content-length`.
pub struct Body(Inner);

enum Inner {
    Full(Option<Bytes>),
    Stream(Boxed),
}

impl Body {
    /// No bytes.
    pub fn empty() -> Body {
        Body(Inner::Full(None))
    }

    /// Any `http_body::Body`, with its data as `Bytes`.
    pub fn new<B>(body: B) -> Body
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        Body(Inner::Stream(Box::pin(IntoBytes(Box::pin(body)))))
    }

    /// The bytes held in full: 0 for a stream.
    fn full_len(&self) -> usize {
        match &self.0 {
            Inner::Full(b) => b.as_ref().map_or(0, Bytes::len),
            Inner::Stream(_) => 0,
        }
    }

    /// The bytes, if the body is held in full.
    pub fn bytes(&self) -> Option<Bytes> {
        match &self.0 {
            Inner::Full(b) => Some(b.clone().unwrap_or_default()),
            Inner::Stream(_) => None,
        }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::Full(b) => write!(f, "Body({} bytes)", b.as_ref().map_or(0, Bytes::len)),
            Inner::Stream(_) => f.write_str("Body(stream)"),
        }
    }
}

impl Default for Body {
    fn default() -> Body {
        Body::empty()
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Body {
        Body(Inner::Full((!b.is_empty()).then_some(b)))
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Body {
        Body::from(Bytes::from(b))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body::from(Bytes::from(s))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Body {
        Body::from(Bytes::from_static(s.as_bytes()))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        match &mut self.get_mut().0 {
            Inner::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Inner::Stream(s) => s.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Inner::Full(b) => b.is_none(),
            Inner::Stream(s) => s.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Inner::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Inner::Stream(s) => s.size_hint(),
        }
    }
}

/// A body with its data as `Bytes` and its errors as [`Error`]. It passes
/// on the size hint, so a known length is sent as `content-length`.
struct IntoBytes<B>(Pin<Box<B>>);

impl<B> http_body::Body for IntoBytes<B>
where
    B: http_body::Body,
    B::Error: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.0.as_mut().poll_frame(cx).map(|f| {
            f.map(|r| {
                r.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining())))
                    .map_err(Into::into)
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

// ---------------------------------------------------------------------------
// Handlers

/// Where a request arrived: the scheme and port from the connection, the
/// host from the request. [`VirtualHosts`] puts one in the extensions of
/// every request it hands on; handlers read it with
/// `request.extensions().get::<Target>()`, or axum's `Extension`.
///
/// The scheme, port and SNI come from the connection, not from headers the
/// client wrote. The host is the one the request named.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Target {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// The host the request was routed by, in lowercase, without a port or
    /// a trailing dot.
    pub host: String,
    /// The port the connection arrived on.
    pub port: u16,
    /// The name the client sent in its TLS hello. `None` without TLS.
    pub sni: Option<String>,
}

/// What a sync handler can use: the clock reading the service took,
/// randomness, and the connection.
pub struct Exchange<'a> {
    now: Instant,
    entropy: &'a dyn fictionet::Entropy,
    conn: &'a ConnInfo,
}

impl<'a> Exchange<'a> {
    /// An exchange for a handler called outside a service, such as in a
    /// test.
    pub fn new(
        now: Instant,
        entropy: &'a dyn fictionet::Entropy,
        conn: &'a ConnInfo,
    ) -> Exchange<'a> {
        Exchange { now, entropy, conn }
    }

    /// The run's clock when the request was read.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// A random number from the run's stream, or the standalone harness's stream.
    pub fn random_u64(&mut self) -> u64 {
        self.entropy.random_u64()
    }

    /// The connection the request came over.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }
}

/// An answer that needs async work: given the connection's [`Cx`], a future
/// of the response. An error answers `500`, or `502` for [`BadGateway`].
pub type Later = Box<
    dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> + Send,
>;

/// What a handler gives back for a request.
pub enum Reply {
    /// The response, now.
    Now(Response<Body>),
    /// Work that makes the response.
    Later(Later),
}

/// Answers HTTP requests. See the [module docs](self).
pub trait Handler: Send + Sync + 'static {
    /// Answers `request`. The request's extensions hold its connection's
    /// [`ConnInfo`].
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply;
}

impl<H: Handler + ?Sized> Handler for Arc<H> {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        (**self).call(request, ex)
    }
}

/// The error a handler returns when the site behind it could not be
/// reached. The service answers it with `502 Bad Gateway` instead of
/// `500`.
#[derive(Debug)]
pub struct BadGateway(pub String);

impl std::fmt::Display for BadGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad gateway: {}", self.0)
    }
}

impl std::error::Error for BadGateway {}

type SyncRoute = Arc<dyn Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync>;
type AsyncRoute = Arc<
    dyn Fn(Cx, Request<Bytes>) -> Pin<Box<dyn Future<Output = Response<Bytes>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
enum Route {
    Sync(SyncRoute),
    Async(AsyncRoute),
}

/// Routes requests by method and path to plain functions with byte
/// bodies.
///
/// A path matches exactly, or, if it ends in `/*`, every path under it. The
/// first route added that matches wins. A path that no route has gets the
/// fallback, `404 Not Found` unless set; a path some route has, with
/// another method, gets `405 Method Not Allowed`.
#[derive(Clone, Default)]
pub struct Router {
    routes: Vec<(Option<Method>, String, Route)>,
    fallback: Option<Route>,
}

impl Router {
    /// No routes.
    pub fn new() -> Router {
        Router::default()
    }

    /// Answers `method` on `path` with `f`. `None` for any method.
    pub fn route<F>(mut self, method: Option<Method>, path: &str, f: F) -> Router
    where
        F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
    {
        self.routes
            .push((method, path.to_owned(), Route::Sync(Arc::new(f))));
        self
    }

    /// Answers `GET` (and `HEAD`) on `path`.
    pub fn get<F>(self, path: &str, f: F) -> Router
    where
        F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
    {
        self.route(Some(Method::GET), path, f)
    }

    /// Answers `POST` on `path`.
    pub fn post<F>(self, path: &str, f: F) -> Router
    where
        F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
    {
        self.route(Some(Method::POST), path, f)
    }

    /// Answers `method` on `path` with async work that gets the
    /// connection's [`Cx`].
    pub fn route_async<F, Fut>(mut self, method: Option<Method>, path: &str, f: F) -> Router
    where
        F: Fn(Cx, Request<Bytes>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response<Bytes>> + Send + 'static,
    {
        let f: AsyncRoute = Arc::new(move |fcx, r| Box::pin(f(fcx, r)));
        self.routes.push((method, path.to_owned(), Route::Async(f)));
        self
    }

    /// Answers every request no route matches.
    pub fn fallback<F>(mut self, f: F) -> Router
    where
        F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
    {
        self.fallback = Some(Route::Sync(Arc::new(f)));
        self
    }

    fn find(&self, method: &Method, path: &str) -> Result<&Route, bool> {
        let mut path_known = false;
        for (m, pattern, route) in &self.routes {
            let matches = match pattern.strip_suffix("/*") {
                Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
                None => path == pattern,
            };
            if !matches {
                continue;
            }
            path_known = true;
            let method_ok = match m {
                None => true,
                Some(m) => m == method || (m == Method::GET && method == Method::HEAD),
            };
            if method_ok {
                return Ok(route);
            }
        }
        if path_known {
            Err(true)
        } else {
            self.fallback.as_ref().ok_or(false)
        }
    }
}

impl Handler for Router {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, body.bytes().unwrap_or_default());
        let route = match self.find(request.method(), request.uri().path()) {
            Ok(route) => route.clone(),
            Err(known) => {
                let status = if known {
                    StatusCode::METHOD_NOT_ALLOWED
                } else {
                    StatusCode::NOT_FOUND
                };
                return Reply::Now(status_only(status));
            }
        };
        match route {
            Route::Sync(f) => Reply::Now(f(ex, request).map(Body::from)),
            Route::Async(f) => Reply::Later(Box::new(move |fcx| {
                Box::pin(async move { Ok(f(fcx, request).await.map(Body::from)) })
            })),
        }
    }
}

fn status_only(status: StatusCode) -> Response<Body> {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status;
    r
}

/// A short plain-text response.
pub fn text(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(body.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Runs a tower service as a [`Handler`]: see [`tower`].
pub struct Tower<S> {
    service: Mutex<S>,
}

/// Runs any tower service, such as an `axum::Router`, as a [`Handler`].
/// Each request gets its own clone of the service, as tower expects, and
/// runs as deferred work of its connection. The response's body streams
/// to the client as it comes.
pub fn tower<S, B>(service: S) -> Tower<S>
where
    S: tower_service::Service<Request<Body>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error>,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    Tower {
        service: Mutex::new(service),
    }
}

impl<S, B> Handler for Tower<S>
where
    S: tower_service::Service<Request<Body>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Error>,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error>,
{
    fn call(&self, request: Request<Body>, _ex: &mut Exchange<'_>) -> Reply {
        let mut service = self
            .service
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Reply::Later(Box::new(move |_fcx| {
            Box::pin(async move {
                poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .map_err(Into::into)?;
                let response = service.call(request).await.map_err(Into::into)?;
                Ok(response.map(Body::new))
            })
        }))
    }
}

// ---------------------------------------------------------------------------
// Virtual hosts

/// One site of [`VirtualHosts`].
#[derive(Clone)]
pub struct VHost {
    /// Its handler.
    pub handler: Arc<dyn Handler>,
    /// It is served over HTTPS. Plain HTTP requests for it get a `301`
    /// redirect to https, unless `plain_http`.
    pub https: bool,
    /// Its handler answers plain HTTP too, even with `https`.
    pub plain_http: bool,
}

impl VHost {
    /// A site with `handler`, plain HTTP only.
    pub fn new(handler: impl Handler) -> VHost {
        VHost {
            handler: Arc::new(handler),
            https: false,
            plain_http: false,
        }
    }
}

/// Picks a site by the request's host, as a web server with several sites
/// at one address does.
///
/// - A request with no host gets `400 Bad Request`.
/// - A host with no site, and no default site, gets `421 Misdirected
///   Request`. So does a site without `https`, asked for over TLS.
/// - A site with `https` asked for over plain HTTP gets a `301` to the same
///   path at `https://host`, unless it has `plain_http`.
/// - Every other request goes to the site's handler, with a [`Target`] in
///   its extensions.
///
/// Its own answers put `answer` in the request's event: `no_host`,
/// `misdirected` or `redirect`.
#[derive(Clone, Default)]
pub struct VirtualHosts {
    inner: Arc<VInner>,
}

#[derive(Default)]
struct VInner {
    hosts: RwLock<HashMap<String, VHost>>,
    default: RwLock<Option<VHost>>,
}

impl VirtualHosts {
    /// No sites.
    pub fn new() -> VirtualHosts {
        VirtualHosts::default()
    }

    /// Adds `site` under `name` (lowercase, without a trailing dot),
    /// replacing one there.
    pub fn insert(&self, name: &str, site: VHost) {
        self.inner
            .hosts
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(normalize(name), site);
    }

    /// Makes `site` the default, for hosts no site has. The first default
    /// set keeps the role.
    pub fn set_default(&self, site: VHost) {
        self.inner
            .default
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(site);
    }

    /// The site named `name`.
    pub fn get(&self, name: &str) -> Option<VHost> {
        self.inner
            .hosts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    /// Whether a site named `name` is served over HTTPS here.
    pub fn has_https(&self, name: &str) -> bool {
        self.get(name).is_some_and(|s| s.https)
    }

    fn site_or_default(&self, host: &str) -> Option<VHost> {
        self.get(host).or_else(|| {
            self.inner
                .default
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
    }
}

fn answered(mut response: Response<Body>, answer: &'static str) -> Response<Body> {
    response
        .extensions_mut()
        .insert(Fields::new().with("answer", answer));
    response
}

impl Handler for VirtualHosts {
    fn call(&self, mut request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let Some(host) = request_host(&request) else {
            return Reply::Now(answered(
                text(StatusCode::BAD_REQUEST, "The request names no host.\n"),
                "no_host",
            ));
        };
        let misdirected = || {
            Reply::Now(answered(
                text(
                    StatusCode::MISDIRECTED_REQUEST,
                    "This server does not serve that host.\n",
                ),
                "misdirected",
            ))
        };
        let Some(site) = self.site_or_default(&host) else {
            return misdirected();
        };
        let tls = ex.conn().tls;
        match (tls, site.https) {
            (true, false) => misdirected(),
            (false, true) if !site.plain_http => {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");
                let location = format!("https://{host}{path}");
                let mut response = text(
                    StatusCode::MOVED_PERMANENTLY,
                    &format!("Moved to {location}\n"),
                );
                if let Ok(value) = location.parse() {
                    response.headers_mut().insert(LOCATION, value);
                }
                Reply::Now(answered(response, "redirect"))
            }
            _ => {
                let conn = ex.conn();
                let target = Target {
                    scheme: if tls { Scheme::HTTPS } else { Scheme::HTTP },
                    host,
                    port: conn.local.map_or(0, |a| a.port()),
                    sni: conn.sni.as_deref().map(str::to_owned),
                };
                request.extensions_mut().insert(target);
                site.handler.call(request, ex)
            }
        }
    }
}

/// A name as hosts are kept: lowercase, without a trailing dot.
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The host a request is for: the authority of its URI (HTTP/2's
/// `:authority`, or an absolute URI in HTTP/1.1), else its `Host` header.
/// Lowercase, without the port or a trailing dot.
pub fn request_host<B>(request: &Request<B>) -> Option<String> {
    let host = match request.uri().authority() {
        Some(a) => a.host().to_owned(),
        None => {
            let value = request.headers().get(HOST)?.to_str().ok()?;
            value.parse::<Authority>().ok()?.host().to_owned()
        }
    };
    let host = normalize(&host);
    (!host.is_empty()).then_some(host)
}

// ---------------------------------------------------------------------------
// The request event

/// One request's event, filled in as it goes.
struct Tracker {
    event: Option<Event>,
}

fn version_name(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

impl Tracker {
    fn new<B>(request: &Request<B>, conn: &ConnInfo, started: Instant) -> Tracker {
        let host = request_host(request);
        let headers: Vec<Value> = request
            .headers()
            .iter()
            .map(|(n, v)| {
                Value::Array(vec![
                    n.as_str().into(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned().into(),
                ])
            })
            .collect();
        let uri = request.uri();
        // Room for every field, and for the status the summary gets later.
        let mut summary = String::with_capacity(
            request.method().as_str().len()
                + host.as_ref().map_or(1, String::len)
                + uri.path().len()
                + 5,
        );
        let _ = write!(
            summary,
            "{} {}{}",
            request.method(),
            host.as_deref().unwrap_or("-"),
            uri.path()
        );
        let event = Event::new("http", "request")
            .fields(Fields::with_capacity(16))
            .field("scheme", if conn.tls { "https" } else { "http" })
            .field("sni", opt(conn.sni.as_deref()))
            .field("host", opt(host.clone()))
            .field("method", request.method().as_str())
            .field("uri", uri.to_string())
            .field("path", uri.path())
            .field("query", opt(uri.query()))
            .field("version", version_name(request.version()))
            .field("headers", Value::Array(headers))
            .field("started", float(started.since_start().as_secs_f64()))
            .summary(summary);
        Tracker { event: Some(event) }
    }

    /// The finished event: `extra` from the handler first, then the facts.
    fn finish(
        &mut self,
        extra: Option<Fields>,
        status: Option<StatusCode>,
        sent: u64,
        complete: bool,
    ) -> Option<Event> {
        let mut event = self.event.take()?;
        let mut fields = extra.unwrap_or_default();
        let answer = fields.remove("answer").unwrap_or_else(|| {
            if status.is_none() {
                "cancelled".into()
            } else {
                "handler".into()
            }
        });
        let mut own = std::mem::take(&mut event.fields);
        own.set("answer", answer);
        own.set("status", opt(status.map(|s| u32::from(s.as_u16()))));
        own.set("sent", sent);
        own.set("complete", complete);
        fields.extend(own);
        event.fields = fields;
        if let Some(s) = status {
            let _ = write!(event.summary, " {}", s.as_u16());
            if s.is_server_error() {
                event.level = Level::Notice;
            }
        }
        Some(event)
    }
}

/// The response for a handler error: `502` for [`BadGateway`], else `500`.
fn error_response(e: &Error) -> Response<Body> {
    let mut response = if e.is::<BadGateway>() {
        text(StatusCode::BAD_GATEWAY, &format!("{e}\n"))
    } else {
        text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The site failed to answer.\n",
        )
    };
    response
        .extensions_mut()
        .insert(Fields::new().with("answer", "error"));
    response
}

/// Logs an `http.error` event.
fn error_event(conn: &ConnInfo, cause: &'static str, detail: String) -> Event {
    Event::new("http", "error")
        .level(Level::Notice)
        .summary(format!("HTTP {cause} error: {detail}"))
        .field("local", opt(conn.local.map(|a| a.to_string())))
        .field("cause", cause)
        .field("detail", detail)
}

// ---------------------------------------------------------------------------
// HTTP/1 as a service

/// HTTP's limits and timers, for both versions.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Head limits for HTTP/1's decoder.
    pub head: http1::Limits,
    /// The largest request body read. Past it, HTTP/1 hands the handler
    /// what came, as a body that ends in an error, and closes the
    /// connection after the answer; HTTP/2 answers the stream `413`.
    /// Default 64 MiB.
    pub body: usize,
    /// HTTP/1: how long a request's head may take to arrive, counted from
    /// when the service starts waiting for it, which includes the wait
    /// between requests. Default 30 seconds.
    pub header_timeout: Duration,
    /// How long a request's body may take to arrive, counted from its
    /// head, so a client that trickles a body cannot hold the connection
    /// for ever. HTTP/1 closes the connection; HTTP/2 answers the stream
    /// `408`. Default 30 seconds.
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
    head: Option<RequestHead>,
    body: Vec<u8>,
    too_big: bool,
    started: Instant,
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
            head: None,
            body: Vec::new(),
            too_big: false,
            started: Instant::ZERO,
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
        let body = Body::from(std::mem::take(&mut self.body));
        let close = self.too_big;
        self.dispatch(driver, body, close)
    }

    /// Calls the handler for the request whose head is pending, with
    /// `body`. `close` closes the connection after the answer.
    fn dispatch(
        &mut self,
        driver: &mut Driver<'_, http1::RequestEvents>,
        body: Body,
        close: bool,
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
        let now = driver.now();
        let conn = driver.conn().clone();
        let reply = if self.too_big {
            Reply::Now(status_only(StatusCode::PAYLOAD_TOO_LARGE))
        } else {
            self.handler
                .call(request, &mut Exchange::new(now, driver.entropy(), &conn))
        };
        let close = !keep_alive;
        // Every answer goes out as deferred work, so its event is made
        // once its bytes are written.
        let (work, response) = match reply {
            Reply::Now(response) => (None, Some(response)),
            Reply::Later(work) => (Some(work), None),
        };
        driver.defer(
            Streaming::new(work, response, version, head_only, close, tracker)
                .dated(self.date, now),
        );
        self.after(driver, close)
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

fn no_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// Writes a response head. `len` is the body's length if known. Returns
/// whether the connection must close after the body: a body of unknown
/// length to an HTTP/1.0 client ends with the connection.
/// `date` is the `Date` header to send if the response has none.
fn encode(
    out: &mut Vec<u8>,
    version: Version,
    response: &Response<Body>,
    len: Option<u64>,
    head_only: bool,
    close: bool,
    date: Option<HeaderValue>,
) -> bool {
    let status = response.status();
    let v10 = version == Version::HTTP_10;
    let mut close = close;
    out.extend_from_slice(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
    out.extend_from_slice(status.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    let given_len = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    for (name, value) in response.headers() {
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
    if let Some(date) = date.filter(|_| !response.headers().contains_key(DATE)) {
        out.extend_from_slice(b"date: ");
        out.extend_from_slice(date.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !no_body(status) {
        // A HEAD answer keeps the length a GET would have, which a handler
        // that drops the body itself says in its own header.
        match if head_only { given_len.or(len) } else { len } {
            Some(n) => out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes()),
            None if head_only => {}
            None if v10 => close = true,
            None => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        }
    }
    if close && !v10 {
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
    encode(
        out,
        version,
        &status_only(status),
        Some(0),
        false,
        true,
        date,
    );
}

/// The `Date` header at `now` on the run's clock, in a world whose date at
/// the start of the run was `start`. `None` without a world date.
pub fn date_header(start: Option<SystemTime>, now: Instant) -> Option<HeaderValue> {
    let secs = start?
        .checked_add(now.since_start())?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    HeaderValue::from_str(&http_date(secs)).ok()
}

/// An IMF-fixdate (RFC 9110 section 5.6.7), such as
/// `Sun, 06 Nov 1994 08:49:37 GMT`, for `secs` since the Unix epoch.
///
/// ```
/// use fictionet::stdlib::httpd::http_date;
/// assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
/// assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
/// assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
/// assert_eq!(http_date(1_559_347_200), "Sat, 01 Jun 2019 00:00:00 GMT");
/// ```
pub fn http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
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
        driver.set_timer(HEAD, self.opts.header_timeout);
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
                if asks_upgrade(&head) {
                    let mut bytes = Vec::new();
                    if fictionet::stdlib::codec::Wire::write(&head, &mut bytes).is_ok() {
                        self.handoff = Some(bytes);
                        return Ok(Flow::Upgrade(serve::Upgrade::Handoff));
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
        self.body.len()
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
            let body = partial(Bytes::from(got), "the request body was cut off");
            self.dispatch(driver, body, true);
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
            self.dispatch(driver, Body::empty(), true);
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
                self.response = Some(response);
            }
            if let Some(response) = self.response.take() {
                let (parts, body) = response.into_parts();
                let response = Response::from_parts(parts, Body::empty());
                let len = body.size_hint().exact();
                let mut head = Vec::new();
                let now = driver.fcx().map_or(self.asked, Cx::now);
                self.close = encode(
                    &mut head,
                    self.version,
                    &response,
                    len,
                    self.head_only,
                    self.close,
                    date_header(self.date, now),
                );
                if self.close {
                    // An HTTP/1.0 body of unknown length ends with the
                    // connection, whatever the request asked for.
                    driver.close();
                }
                self.status = Some(response.status());
                self.extra = response.extensions().get::<Fields>().cloned();
                let bodiless = self.head_only || no_body(response.status());
                self.chunked = !bodiless && len.is_none() && self.version != Version::HTTP_10;
                if bodiless {
                    return self.piece(head, 0);
                }
                // A body held in full goes out with the head, a piece at
                // a time.
                match body.0 {
                    Inner::Full(bytes) => self.rest = bytes.unwrap_or_default(),
                    stream => self.body = Some(Body(stream)),
                }
                let piece = self.rest.split_to(self.rest.len().min(PIECE));
                self.frame(&piece, &mut head);
                return self.piece(head, piece.len());
            }
            if !self.rest.is_empty() {
                let piece = self.rest.split_to(self.rest.len().min(PIECE));
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
        self.rest.len() + response + body
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
    /// HTTP/1 what the service holds, over HTTP/2 each request's body and
    /// each response body held in full.
    pub budget: Option<Budget>,
    /// The world's date and time at the start of the run, for `Date`
    /// headers. `None`: no `Date` header. See [Dates](self#dates).
    pub date: Option<SystemTime>,
}

/// What an HTTP/2 client sends first, with no TLS ("prior knowledge").
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface; HTTP/1
/// otherwise. `info` names the connection in events.
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
    let h2 = if info.tls {
        info.alpn.as_deref() == Some(b"h2".as_slice())
    } else {
        // Read until the bytes cannot be the preface, or are all of it.
        let preface = async {
            let mut buf = [0u8; 24];
            while first.len() < PREFACE.len() && PREFACE.starts_with(&first) {
                match conn
                    .read(fcx, &mut buf[..PREFACE.len() - first.len()])
                    .await
                {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                }
            }
            true
        };
        match fcx
            .race(opts.first_bytes.map(|d| fcx.now() + d), preface)
            .await
        {
            Ok(true) => {}
            Ok(false) if fcx.is_cancelled() => return Err(Cancelled),
            Ok(false) => return Ok(()),
            Err(RaceError::Cancelled) => return Err(Cancelled),
            Err(RaceError::Deadline) => {
                let secs = opts.first_bytes.map_or(0, |d| d.as_secs());
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
        first == PREFACE
    };
    let conn = Prefixed::new(first, conn);
    if h2 {
        return h2::serve(fcx, conn, handler, info, opts).await;
    }
    let serve_opts = ServeOptions {
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
        connection_events: false,
        budget: opts.budget.clone(),
        ..ServeOptions::default()
    };
    let mut service = Http1::with(handler.clone(), opts.limits);
    service.date = opts.date;
    match serve::connection(fcx, conn, info.clone(), &mut service, &(), &serve_opts).await {
        Ok(serve::Served::Upgraded(serve::Upgrade::Handoff, rest)) => {
            match service.take_handoff() {
                // A request that asks for an upgrade: hyper's HTTP/1 reads it
                // again and carries the upgrade out.
                Some(head) => {
                    h2::serve_upgrade(fcx, Prefixed::new(head, rest), handler, info, opts).await
                }
                None => Ok(()),
            }
        }
        Err(serve::ServeError::Cancelled) => Err(Cancelled),
        // The driver recorded the failure as a `conn.error` event.
        Ok(_) | Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// HTTP on a network

/// HTTP on one port of a [`Net`](fictionet::stdlib::net::Net) host: an
/// [`PortServer`] that serves the host's site for each of its DNS names.
///
/// Every host at one address that serves HTTP on a port shares that port:
/// the first host's `Server` takes in the others' sites as
/// [`VirtualHosts`], and each request goes to the site its host names.
/// Over TLS, ALPN offers `h2` and `http/1.1`.
///
/// ```
/// # use fictionet::stdlib::{httpd, net::Host};
/// let page = httpd::Router::new().get("/", |_, _| http::Response::new("hello\n".into()));
/// let host = Host::new("www").dns_name("www.corp.test").port_server(80, httpd::Server::new(page));
/// # drop(host);
/// ```
#[derive(Clone)]
pub struct Server {
    vhost: VHost,
    default_host: bool,
    limits: Limits,
    date: Option<SystemTime>,
    vhosts: VirtualHosts,
}

impl Server {
    /// A site served by `handler`, over plain HTTP.
    pub fn new(handler: impl Handler) -> Server {
        Server::shared(Arc::new(handler))
    }

    /// The same, from a shared handler.
    pub fn shared(handler: Arc<dyn Handler>) -> Server {
        Server {
            vhost: VHost {
                handler,
                https: false,
                plain_http: false,
            },
            default_host: false,
            limits: Limits::default(),
            date: None,
            vhosts: VirtualHosts::new(),
        }
    }

    /// The site is served over HTTPS: on a TLS port it answers, and on a
    /// plain port its requests get a `301` to https, unless
    /// [`plain_http`](Self::plain_http).
    pub fn https(mut self) -> Server {
        self.vhost.https = true;
        self
    }

    /// With [`https`](Self::https), answers plain HTTP too, with no
    /// redirect.
    pub fn plain_http(mut self) -> Server {
        self.vhost.plain_http = true;
        self
    }

    /// Answers requests at its address whose host names no site there.
    /// The first default site at an address keeps the role.
    pub fn default_host(mut self) -> Server {
        self.default_host = true;
        self
    }

    /// Sets the limits and timers.
    pub fn limits(mut self, limits: Limits) -> Server {
        self.limits = limits;
        self
    }

    /// Sends `Date` headers: `start` is the world's date and time at the
    /// start of the run. See [Dates](self#dates). Sites that share a port
    /// use the first one's.
    pub fn date(mut self, start: SystemTime) -> Server {
        self.date = Some(start);
        self
    }
}

impl PortServer for Server {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler: Arc<dyn Handler> = Arc::new(self.vhosts.clone());
        let opts = HttpOptions {
            limits: self.limits,
            first_bytes: (!arrival.info.tls).then_some(arrival.handshake),
            budget: arrival.budget,
            date: self.date,
        };
        let (conn, info) = (arrival.conn, arrival.info);
        Box::pin(async move {
            let _ = serve_connection(&fcx, conn, info, handler, &opts).await;
        })
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    }

    fn share(&self, names: &[String], other: &Arc<dyn PortServer>) -> bool {
        let other: &dyn Any = &**other;
        let Some(site) = other.downcast_ref::<Server>() else {
            return false;
        };
        for name in names {
            self.vhosts.insert(name, site.vhost.clone());
        }
        if site.default_host {
            self.vhosts.set_default(site.vhost.clone());
        }
        true
    }
}

/// A website on ports 80 and 443, as [`web::Sites`](fictionet::stdlib::web::Sites)
/// serves one: with TLS, HTTPS on 443 for each of the host's names and a
/// redirect to it on 80 (unless [`plain_http`](Self::plain_http));
/// without, plain HTTP on 80. [`served_by`](Self::served_by) puts it on a host.
#[derive(Clone)]
pub struct Website {
    handler: Arc<dyn Handler>,
    tls: Option<ConfigFor>,
    plain_http: bool,
    default_host: bool,
    date: Option<SystemTime>,
}

impl Website {
    /// A website served by `handler`, over plain HTTP only.
    pub fn new(handler: impl Handler) -> Website {
        Website::shared(Arc::new(handler))
    }

    /// The same, from a shared handler.
    pub fn shared(handler: Arc<dyn Handler>) -> Website {
        Website {
            handler,
            tls: None,
            plain_http: false,
            default_host: false,
            date: None,
        }
    }

    /// Serves it over HTTPS on port 443, with the config `config_for`
    /// returns for each handshake. Port 80 then redirects to https.
    pub fn tls(
        self,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Website {
        Website {
            tls: Some(Arc::new(config_for)),
            ..self
        }
    }

    /// With TLS, answers plain HTTP on port 80 too, with no redirect.
    pub fn plain_http(self) -> Website {
        Website {
            plain_http: true,
            ..self
        }
    }

    /// Answers requests at its address whose host names no site there.
    pub fn default_host(self) -> Website {
        Website {
            default_host: true,
            ..self
        }
    }

    /// Sends `Date` headers: `start` is the world's date and time at the
    /// start of the run. See [Dates](self#dates).
    pub fn date(self, start: SystemTime) -> Website {
        Website {
            date: Some(start),
            ..self
        }
    }

    /// `host`, serving this website.
    pub fn served_by(self, host: Host) -> Host {
        let mut plain = Server::shared(self.handler.clone());
        plain.vhost.https = self.tls.is_some();
        plain.vhost.plain_http = self.plain_http;
        plain.default_host = self.default_host;
        plain.date = self.date;
        let host = host.port_server(80, plain);
        match self.tls {
            None => host,
            Some(config) => {
                let mut secure = Server::shared(self.handler).https();
                secure.default_host = self.default_host;
                secure.date = self.date;
                host.tls_accept(443, Sni::Names, move |fcx| config(fcx), secure)
            }
        }
    }
}

/// Live HTTP/2 and HTTP/1 Upgrade serving on hyper.
mod h2 {
    use super::*;
    use fictionet::stdlib::serve::{Charge, PanicNote};
    use hyper::body::Incoming;

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
        let io = Io::new(fcx, conn, broke.clone(), opts.limits.write_timeout);
        let route = Route::new(fcx, handler, &info, opts);
        let mut builder = hyper::server::conn::http1::Builder::new();
        // Hyper still refreshes its internal date cache using SystemTime,
        // but auto_date_header(false) prevents that value reaching the wire.
        builder.auto_date_header(false);
        if cfg!(target_arch = "wasm32") {
            builder.header_read_timeout(None);
        } else {
            builder.timer(CxTimer::new(fcx.clone()));
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
        broken.then_some("transport")
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
            let route = self.clone();
            let track = Track {
                tracker: Tracker::new(&request, &route.info, route.fcx.now()),
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
                    Err(answer) => *answer,
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
                let (parts, body) = response.into_parts();
                let fits = charge.as_mut().is_none_or(|c| c.set(body.full_len()));
                let (mut parts, body) = if fits {
                    (parts, body)
                } else {
                    over_budget().into_parts()
                };
                if !parts.headers.contains_key(DATE)
                    && let Some(date) = date_header(route.date, route.fcx.now())
                {
                    parts.headers.insert(DATE, date);
                }
                track.extra = parts.extensions.get::<Fields>().cloned();
                track.status = Some(parts.status);
                let bodiless = head_only || no_body(parts.status);
                let body = if bodiless {
                    // hyper would send the body on HTTP/2 even for HEAD,
                    // which breaks the stream.
                    if let Some(len) = body.size_hint().exact()
                        && !no_body(parts.status)
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
                        charge,
                    },
                ))
            })
        }
    }

    /// One request's event, sent when it is dropped.
    struct Track {
        tracker: Tracker,
        fcx: Cx,
        info: Arc<ConnInfo>,
        extra: Option<Fields>,
        status: Option<StatusCode>,
        sent: u64,
        complete: bool,
        /// Names the connection if the handler or its body panics.
        _note: PanicNote,
    }

    impl Drop for Track {
        fn drop(&mut self) {
            if let Some(e) =
                self.tracker
                    .finish(self.extra.take(), self.status, self.sent, self.complete)
            {
                self.fcx.record(e.conn(&self.info));
            }
        }
    }

    /// A response body that counts the bytes sent and makes the request's
    /// event when it ends or is dropped.
    pub(super) struct Counted {
        body: Body,
        rest: Bytes,
        track: Track,
        bodiless: bool,
        /// What the body held in full still holds.
        charge: Option<Charge>,
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
                this.track.sent += piece.len() as u64;
                this.recharge();
                return Poll::Ready(Some(Ok(Frame::data(piece))));
            }
            let mut polled = Pin::new(&mut this.body).poll_frame(cx);
            if let Poll::Ready(Some(Ok(frame))) = &mut polled
                && let Some(data) = frame.data_mut()
                && data.len() > PIECE
            {
                this.rest = data.split_off(PIECE);
            }
            match &polled {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        this.track.sent += data.len() as u64;
                    }
                }
                Poll::Ready(Some(Err(_))) => this.track.complete = false,
                Poll::Ready(None) => this.track.complete = true,
                Poll::Pending => {}
            }
            this.recharge();
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

    impl Counted {
        /// Charges what is left to send of a body held in full.
        fn recharge(&mut self) {
            if let Some(c) = &mut self.charge {
                c.set(self.rest.len() + self.body.full_len());
            }
        }
    }

    impl Drop for Counted {
        fn drop(&mut self) {
            // hyper may stop polling once the body says it has ended.
            if http_body::Body::is_end_stream(self) || self.bodiless {
                self.track.complete = true;
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
            let fcx = self.fcx.clone();
            Box::pin(CxSleep(Box::pin(async move {
                // Hyper cannot represent cancellation; the connection ends it.
                if fcx.sleep_until(deadline).await.is_err() {
                    std::future::pending::<()>().await;
                }
            })))
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

    /// A sleep for hyper, which wants it `Sync`.
    struct CxSleep(Pin<Box<dyn Future<Output = ()> + Send>>);

    // SAFETY: `CxSleep` gives no access to its future through `&self`: the
    // only way in is `poll`, which takes `Pin<&mut Self>`. So sharing a
    // `&CxSleep` between threads cannot touch the future at all.
    unsafe impl Sync for CxSleep {}

    impl Future for CxSleep {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.get_mut().0.as_mut().poll(cx)
        }
    }

    impl hyper::rt::Sleep for CxSleep {}

    #[cfg(test)]
    mod tests {
        use super::*;
        use hyper::rt::Timer;

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
                            *s.lock().unwrap() = Some(inner.clone());
                            inner.cancel();
                            Ok(())
                        })
                        .await;
                    let inner = slot.lock().unwrap().take().unwrap();
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
