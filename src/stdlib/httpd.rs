//! HTTP as a service: a router whose handlers get plain byte bodies, an
//! adapter that runs any tower service (axum included), and name-based
//! virtual hosting, all on [`serve`](crate::stdlib::serve).
//!
//! A [`Handler`] answers one request. Three kinds come ready:
//!
//! - [`Router`]: routes by method and path to plain functions. A handler
//!   gets an [`Exchange`] (the clock reading, randomness, the connection)
//!   and an `http::Request<Bytes>`, and returns an `http::Response<Bytes>`.
//!   No runtime is involved, so it unit-tests with
//!   [`serve::Harness`](crate::stdlib::serve::Harness). An async route gets
//!   a [`Cx`] instead.
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as deferred work of the connection.
//! - [`VirtualHosts`]: picks a handler by the request's host, as a web server
//!   with several sites at one address does, with the redirect to https and
//!   the `421 Misdirected Request` of [`web::Sites`](crate::stdlib::web::Sites).
//!
//! [`Http1`] is the [`Service`](crate::stdlib::serve::Service) that speaks
//! HTTP/1.0 and 1.1 to a client, on [`http1`](crate::stdlib::http1)'s
//! decoder: keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
//! responses for bodies of unknown length, and a 30-second limit on each
//! request's head. [`serve_connection`] picks the version for a
//! connection: HTTP/2 by ALPN or by the client's preface, else HTTP/1.
//!
//! HTTP/2 runs on hyper for now, behind the same [`Handler`] trait and the
//! same journal events. When the stdlib's own HTTP/2 lands, it becomes a
//! second `Service` here and [`serve_connection`] picks it; handlers do not
//! change.
//!
//! ```
//! use bytes::Bytes;
//! use fictionet::stdlib::httpd::{Http1, Router};
//! use fictionet::stdlib::serve::Harness;
//!
//! let router = Router::new()
//!     .get("/hello", |_, _| http::Response::new(Bytes::from("hi\n")))
//!     .post("/echo", |_, request: http::Request<Bytes>| http::Response::new(request.into_body()));
//! let mut h = Harness::new(Http1::new(router), ());
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
//! or what the handler set, such as `redirect`), `status`, `sent` (body
//! bytes handed to the connection) and `complete` (whether the whole body
//! was). A handler adds its own fields by putting
//! [`Fields`](crate::stdlib::journal::Fields) in its response's
//! extensions; they come first, and the service's own facts win a clash.
//! A connection that ends in an error is one `http.error` event, with
//! `local`, `cause` (`protocol`, `timeout` or `transport`) and `detail`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::header::{CONTENT_LENGTH, HOST, LOCATION};
use http::uri::{Authority, Scheme};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body::{Body as _, Frame, SizeHint};

use fictionet::stdlib::http1::{self, Event as H1, RequestHead};
use fictionet::stdlib::journal::{ConnInfo, Event, Fields, Journal, Level, float, opt};
use fictionet::stdlib::json::Value;
use fictionet::stdlib::serve::{self, End, Flow, Pending, PendingCtx, Prefixed, ServeCtx, ServeOptions};
use fictionet::stdlib::tcp::GoneWatch;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt};
use fictionet::time::Instant;
use fictionet::{Cx, Error};

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

    fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        match &mut self.get_mut().0 {
            Inner::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Inner::Stream(s) => s.as_mut().poll_frame(task),
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

    fn poll_frame(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.0
            .as_mut()
            .poll_frame(task)
            .map(|f| f.map(|r| r.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining()))).map_err(Into::into)))
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
    rng: &'a mut dyn FnMut() -> u64,
    conn: &'a ConnInfo,
}

impl<'a> Exchange<'a> {
    /// An exchange for a handler called outside a service, such as in a
    /// test.
    pub fn new(now: Instant, rng: &'a mut dyn FnMut() -> u64, conn: &'a ConnInfo) -> Exchange<'a> {
        Exchange { now, rng, conn }
    }

    /// The run's clock when the request was read.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// A random number from the connection's generator.
    pub fn random_u64(&mut self) -> u64 {
        (self.rng)()
    }

    /// The connection the request came over.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }
}

/// An answer that needs async work: given the connection's [`Cx`], a future
/// of the response. An error answers `500`, or `502` for [`BadGateway`].
pub type Later = Box<dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> + Send>;

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
type AsyncRoute = Arc<dyn Fn(Cx, Request<Bytes>) -> Pin<Box<dyn Future<Output = Response<Bytes>> + Send>> + Send + Sync>;

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
        self.routes.push((method, path.to_owned(), Route::Sync(Arc::new(f))));
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
        let f: AsyncRoute = Arc::new(move |cx, r| Box::pin(f(cx, r)));
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
        self.fallback.as_ref().ok_or(path_known)
    }
}

impl Handler for Router {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, body.bytes().unwrap_or_default());
        let route = match self.find(request.method(), request.uri().path()) {
            Ok(route) => route.clone(),
            Err(known) => {
                let status = if known { StatusCode::METHOD_NOT_ALLOWED } else { StatusCode::NOT_FOUND };
                return Reply::Now(status_only(status));
            }
        };
        match route {
            Route::Sync(f) => Reply::Now(f(ex, request).map(Body::from)),
            Route::Async(f) => Reply::Later(Box::new(move |cx| Box::pin(async move { Ok(f(cx, request).await.map(Body::from)) }))),
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
    response.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

/// A handler from a plain function: no routing, byte bodies.
pub fn handler_fn<F>(f: F) -> Router
where
    F: Fn(&mut Exchange<'_>, Request<Bytes>) -> Response<Bytes> + Send + Sync + 'static,
{
    Router::new().fallback(f)
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
    Tower { service: Mutex::new(service) }
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
        let mut service = self.service.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Reply::Later(Box::new(move |_cx| {
            Box::pin(async move {
                poll_fn(|task| service.poll_ready(task)).await.map_err(Into::into)?;
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
        VHost { handler: Arc::new(handler), https: false, plain_http: false }
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
        self.inner.hosts.write().unwrap_or_else(|e| e.into_inner()).insert(normalize(name), site);
    }

    /// Makes `site` the default, for hosts no site has. The first default
    /// set keeps the role.
    pub fn set_default(&self, site: VHost) {
        self.inner.default.write().unwrap_or_else(|e| e.into_inner()).get_or_insert(site);
    }

    /// The site named `name`.
    pub fn get(&self, name: &str) -> Option<VHost> {
        self.inner.hosts.read().unwrap_or_else(|e| e.into_inner()).get(name).cloned()
    }

    /// Whether a site named `name` is served over HTTPS here.
    pub fn has_https(&self, name: &str) -> bool {
        self.get(name).is_some_and(|s| s.https)
    }

    fn site_or_default(&self, host: &str) -> Option<VHost> {
        self.get(host).or_else(|| self.inner.default.read().unwrap_or_else(|e| e.into_inner()).clone())
    }
}

fn answered(mut response: Response<Body>, answer: &'static str) -> Response<Body> {
    response.extensions_mut().insert(Fields::new().with("answer", answer));
    response
}

impl Handler for VirtualHosts {
    fn call(&self, mut request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let Some(host) = request_host(&request) else {
            return Reply::Now(answered(text(StatusCode::BAD_REQUEST, "The request names no host.\n"), "no_host"));
        };
        let misdirected = || {
            Reply::Now(answered(text(StatusCode::MISDIRECTED_REQUEST, "This server does not serve that host.\n"), "misdirected"))
        };
        let Some(site) = self.site_or_default(&host) else { return misdirected() };
        let tls = ex.conn().tls;
        match (tls, site.https) {
            (true, false) => misdirected(),
            (false, true) if !site.plain_http => {
                let path = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
                let location = format!("https://{host}{path}");
                let mut response = text(StatusCode::MOVED_PERMANENTLY, &format!("Moved to {location}\n"));
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
    fn new<B>(on: bool, request: &Request<B>, conn: &ConnInfo, started: Instant) -> Tracker {
        if !on {
            return Tracker { event: None };
        }
        let host = request_host(request);
        let headers: Vec<Value> = request
            .headers()
            .iter()
            .map(|(n, v)| Value::Array(vec![n.as_str().into(), String::from_utf8_lossy(v.as_bytes()).into_owned().into()]))
            .collect();
        let uri = request.uri();
        let event = Event::new("http", "request")
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
            .summary(format!("{} {}{}", request.method(), host.as_deref().unwrap_or("-"), uri.path()));
        Tracker { event: Some(event) }
    }

    /// The finished event: `extra` from the handler first, then the facts.
    fn finish(&mut self, extra: Option<Fields>, status: Option<StatusCode>, sent: u64, complete: bool) -> Option<Event> {
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
            event.summary = format!("{} {}", event.summary, s.as_u16());
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
        text(StatusCode::INTERNAL_SERVER_ERROR, "The site failed to answer.\n")
    };
    response.extensions_mut().insert(Fields::new().with("answer", "error"));
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

/// Limits and timers of [`Http1`].
#[derive(Clone, Copy, Debug)]
pub struct Http1Options {
    /// Head limits for the decoder.
    pub limits: http1::Limits,
    /// The largest request body read; past it the answer is `413` and the
    /// connection closes. Default 64 MiB.
    pub max_body: usize,
    /// How long a request's head may take to arrive, counted from when the
    /// service starts waiting for it, which includes the wait between
    /// requests. Default 30 seconds.
    pub header_timeout: Duration,
}

impl Default for Http1Options {
    fn default() -> Http1Options {
        Http1Options { limits: http1::Limits::default(), max_body: 64 << 20, header_timeout: Duration::from_secs(30) }
    }
}

/// HTTP/1.0 and 1.1 for one connection, answering with a [`Handler`].
pub struct Http1 {
    handler: Arc<dyn Handler>,
    opts: Http1Options,
    head: Option<RequestHead>,
    body: Vec<u8>,
    too_big: bool,
    started: Instant,
}

impl Http1 {
    /// Answers with `handler`, with default options.
    pub fn new(handler: impl Handler) -> Http1 {
        Http1::with(Arc::new(handler), Http1Options::default())
    }

    /// Answers with `handler` and `opts`.
    pub fn with(handler: Arc<dyn Handler>, opts: Http1Options) -> Http1 {
        Http1 { handler, opts, head: None, body: Vec::new(), too_big: false, started: Instant::ZERO }
    }

    fn respond(&mut self, ctx: &mut ServeCtx<'_>) -> Flow {
        let body = Body::from(std::mem::take(&mut self.body));
        let body = if self.too_big { partial(body.bytes().unwrap_or_default(), "the request body is too large") } else { body };
        let close = self.too_big;
        self.dispatch(ctx, body, close)
    }

    /// Calls the handler for the request whose head is pending, with
    /// `body`. `close` closes the connection after the answer.
    fn dispatch(&mut self, ctx: &mut ServeCtx<'_>, body: Body, close: bool) -> Flow {
        let Some(head) = self.head.take() else { return Flow::Close };
        let version = match head.version {
            http1::Version::Http10 => Version::HTTP_10,
            http1::Version::Http11 => Version::HTTP_11,
        };
        let keep_alive = !close && head.keep_alive().unwrap_or(false) && head.method != "CONNECT";
        let request = match to_request(&head, version, body) {
            Some(r) => r,
            None => {
                write_simple(ctx.reply(), version, StatusCode::BAD_REQUEST);
                return Flow::Close;
            }
        };
        let mut request = request;
        request.extensions_mut().insert(ctx.conn().clone());
        let head_only = request.method() == Method::HEAD;
        let mut tracker = Tracker::new(ctx.logging(), &request, ctx.conn(), self.started);
        let now = ctx.now();
        let conn = ctx.conn().clone();
        let reply = {
            let mut rng = || ctx.random_u64();
            self.handler.call(request, &mut Exchange::new(now, &mut rng, &conn))
        };
        let close = !keep_alive;
        match reply {
            Reply::Now(response) if response.body().bytes().is_some() => {
                let bytes = response.body().bytes().unwrap_or_default();
                let len = Some(bytes.len() as u64);
                let close = encode(ctx.reply(), version, &response, len, head_only, close);
                let bodiless = head_only || no_body(response.status());
                if !bodiless {
                    ctx.reply().extend_from_slice(&bytes);
                }
                let extra = response.extensions().get::<Fields>().cloned();
                let sent = if bodiless { 0 } else { bytes.len() as u64 };
                if let Some(e) = tracker.finish(extra, Some(response.status()), sent, true) {
                    ctx.log(e);
                }
                self.after(ctx, close)
            }
            Reply::Now(response) => {
                ctx.defer(Streaming::new(None, Some(response), version, head_only, close, tracker));
                self.after(ctx, close)
            }
            Reply::Later(work) => {
                ctx.defer(Streaming::new(Some(work), None, version, head_only, close, tracker));
                self.after(ctx, close)
            }
        }
    }

    fn after(&mut self, ctx: &mut ServeCtx<'_>, close: bool) -> Flow {
        if close {
            return Flow::Close;
        }
        ctx.wake_in(self.opts.header_timeout);
        Flow::Continue
    }
}

/// A request body that ends early: `bytes`, then an error saying `why`.
/// A handler that reads it frame by frame sees what came.
fn partial(bytes: Bytes, why: &'static str) -> Body {
    struct Partial(Option<Bytes>, Option<&'static str>);
    impl http_body::Body for Partial {
        type Data = Bytes;
        type Error = Error;
        fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
            let this = self.get_mut();
            if let Some(b) = this.0.take().filter(|b| !b.is_empty()) {
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            Poll::Ready(this.1.take().map(|why| Err(why.into())))
        }
    }
    Body::new(Partial(Some(bytes), Some(why)))
}

fn to_request(head: &RequestHead, version: Version, body: Body) -> Option<Request<Body>> {
    let mut builder = Request::builder().method(head.method.as_bytes()).uri(head.target.as_str()).version(version);
    let headers = builder.headers_mut()?;
    for h in &head.headers {
        let name = HeaderName::from_bytes(h.name.as_bytes()).ok()?;
        let value = HeaderValue::from_bytes(&h.value).ok()?;
        headers.append(name, value);
    }
    builder.body(body).ok()
}

fn no_body(status: StatusCode) -> bool {
    status.is_informational() || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED
}

/// Writes a response head. `len` is the body's length if known. Returns
/// whether the connection must close after the body: a body of unknown
/// length to an HTTP/1.0 client ends with the connection.
fn encode(out: &mut Vec<u8>, version: Version, response: &Response<Body>, len: Option<u64>, head_only: bool, close: bool) -> bool {
    let status = response.status();
    let v10 = version == Version::HTTP_10;
    let mut close = close;
    out.extend_from_slice(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
    out.extend_from_slice(status.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    let given_len = response.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    for (name, value) in response.headers() {
        if matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
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

fn write_simple(out: &mut Vec<u8>, version: Version, status: StatusCode) {
    encode(out, version, &status_only(status), Some(0), false, true);
}

impl serve::Service for Http1 {
    type Decode = http1::Requests;
    type World = ();
    type Error = Infallible;

    fn decoder(&self) -> http1::Requests {
        http1::Requests::new(self.opts.limits)
    }

    fn on_open(&mut self, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        ctx.wake_in(self.opts.header_timeout);
        Ok(Flow::Continue)
    }

    fn on_item(&mut self, item: H1<RequestHead>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        match item {
            H1::Head(head) => {
                ctx.cancel_wake();
                if head.expects_continue() {
                    ctx.reply().extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                self.started = ctx.now();
                self.head = Some(head);
                self.body.clear();
                self.too_big = false;
            }
            H1::Body(bytes) => {
                if self.body.len() + bytes.len() > self.opts.max_body {
                    self.too_big = true;
                } else {
                    self.body.extend_from_slice(&bytes);
                }
            }
            H1::Done => return Ok(self.respond(ctx)),
        }
        Ok(Flow::Continue)
    }

    fn on_tick(&mut self, _: &(), _ctx: &mut ServeCtx<'_>) -> Result<Flow, Infallible> {
        Ok(Flow::Close)
    }

    fn on_fail(&mut self, error: &serve_fail::Fail, _: &(), ctx: &mut ServeCtx<'_>) -> Result<(), Infallible> {
        if self.head.is_some() {
            // The body was cut off: the handler still sees what came, as a
            // body that ends in an error.
            let mut got = std::mem::take(&mut self.body);
            let room = self.opts.max_body.saturating_sub(got.len());
            got.extend_from_slice(&ctx.unread()[..ctx.unread().len().min(room)]);
            let body = partial(Bytes::from(got), "the request body was cut off");
            self.dispatch(ctx, body, true);
            return Ok(());
        }
        if ctx.logging() {
            let e = error_event(ctx.conn(), "protocol", error.to_string());
            ctx.log(e);
        }
        write_simple(ctx.reply(), Version::HTTP_11, StatusCode::BAD_REQUEST);
        Ok(())
    }

    fn on_end(&mut self, end: End, _: &(), ctx: &mut ServeCtx<'_>) -> Result<(), Infallible> {
        if end == End::Conn(ConnError::Broken) && ctx.logging() {
            let e = error_event(ctx.conn(), "transport", "a TLS record did not decrypt".into());
            ctx.log(e);
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

/// A response being made or streamed, as deferred work of a connection.
struct Streaming {
    work: Option<Later>,
    making: Option<Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>>,
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
    /// Body bytes handed to the connection.
    body_sent: u64,
    finished: bool,
}

impl Streaming {
    fn new(work: Option<Later>, response: Option<Response<Body>>, version: Version, head_only: bool, close: bool, tracker: Tracker) -> Streaming {
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
            finished: false,
        }
    }

    fn end(&mut self, ctx: &mut PendingCtx<'_>, complete: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(e) = self.tracker.finish(self.extra.take(), self.status, self.body_sent, complete) {
            ctx.log(e);
        }
    }
}

impl Streaming {
    /// `piece` as it goes on the wire: a chunk, when chunked.
    fn frame(&self, piece: Bytes) -> Vec<u8> {
        if !self.chunked {
            return piece.to_vec();
        }
        let mut out = format!("{:x}\r\n", piece.len()).into_bytes();
        out.extend_from_slice(&piece);
        out.extend_from_slice(b"\r\n");
        out
    }
}

impl Pending for Streaming {
    fn poll_next(&mut self, ctx: &mut PendingCtx<'_>, task: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, Error>>> {
        loop {
            if let Some(work) = self.work.take() {
                self.making = Some(work(ctx.cx().clone()));
            }
            if let Some(making) = &mut self.making {
                let response = match making.as_mut().poll(task) {
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
                let close = encode(&mut head, self.version, &response, len, self.head_only, self.close);
                self.close = close;
                self.status = Some(response.status());
                self.extra = response.extensions().get::<Fields>().cloned();
                let bodiless = self.head_only || no_body(response.status());
                self.chunked = !bodiless && len.is_none() && self.version != Version::HTTP_10;
                if !bodiless {
                    self.body = Some(body);
                }
                return Poll::Ready(Some(Ok(head)));
            }
            if !self.rest.is_empty() {
                let piece = self.rest.split_to(self.rest.len().min(PIECE));
                self.body_sent += piece.len() as u64;
                return Poll::Ready(Some(Ok(self.frame(piece))));
            }
            let Some(body) = &mut self.body else {
                self.end(ctx, true);
                return Poll::Ready(None);
            };
            match Pin::new(body).poll_frame(task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.body = None;
                    if self.chunked {
                        self.chunked = false;
                        let done = b"0\r\n\r\n".to_vec();
                        self.end(ctx, true);
                        return Poll::Ready(Some(Ok(done)));
                    }
                    self.end(ctx, true);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(e))) => {
                    self.body = None;
                    self.end(ctx, false);
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

    fn cancel(&mut self, ctx: &mut PendingCtx<'_>) {
        if self.status.is_none() {
            self.extra = None;
        }
        self.end(ctx, false);
    }
}

// ---------------------------------------------------------------------------
// One connection, either version

/// How [`serve_connection`] serves a connection.
#[derive(Clone, Default)]
pub struct HttpOptions {
    /// HTTP/1's limits and timers.
    pub h1: Http1Options,
    /// On a connection without TLS, how long the client has from
    /// connecting to send its first bytes. Past it, the connection closes
    /// with an `http.error` event, cause `timeout`. `None` waits as long as
    /// the HTTP/1 head limit allows.
    pub first_bytes: Option<Duration>,
    /// Where events go.
    pub journal: Option<Journal>,
}

/// What an HTTP/2 client sends first, with no TLS ("prior knowledge").
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface; HTTP/1
/// otherwise. `info` names the connection in events; `gone` ends it as
/// soon as the client resets it.
pub async fn serve_connection<C: Connection + Unpin>(
    cx: &Cx,
    conn: C,
    info: ConnInfo,
    gone: Option<GoneWatch>,
    handler: Arc<dyn Handler>,
    opts: &HttpOptions,
) {
    let mut conn = conn;
    let mut first = Vec::new();
    let h2 = if info.tls {
        info.alpn.as_deref() == Some(b"h2".as_slice())
    } else {
        // Read until the bytes cannot be the preface, or are all of it.
        let preface = async {
            let mut buf = [0u8; 24];
            while first.len() < PREFACE.len() && PREFACE.starts_with(&first) {
                match conn.read(cx, &mut buf[..PREFACE.len() - first.len()]).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                }
            }
            true
        };
        match serve::until(cx, opts.first_bytes.map(|d| cx.now() + d), preface).await {
            Ok(true) => {}
            Ok(false) | Err(true) => return,
            Err(false) => {
                if let Some(j) = &opts.journal {
                    let secs = opts.first_bytes.map_or(0, |d| d.as_secs());
                    j.record(cx, &info, error_event(&info, "timeout", format!("no bytes within {secs} seconds of connecting")));
                }
                return;
            }
        }
        first == PREFACE
    };
    let conn = Prefixed::new(first, conn);
    if h2 {
        h2::serve(cx, conn, handler, info, gone, opts.journal.clone()).await;
        return;
    }
    let serve_opts = ServeOptions { journal: opts.journal.clone(), idle: None, connection_events: false, ..ServeOptions::default() };
    let mut service = Http1::with(handler, opts.h1);
    let _ = serve::serve(cx, conn, info, gone, &mut service, &(), &serve_opts).await;
}

/// HTTP/2 on hyper, until the stdlib's own HTTP/2 lands.
mod h2 {
    use super::*;
    use http_body_util::{BodyExt, Limited};
    use hyper::body::Incoming;

    /// Runs hyper's HTTP/2 server on `conn`.
    pub(super) async fn serve<C: Connection + Unpin>(
        cx: &Cx,
        conn: C,
        handler: Arc<dyn Handler>,
        info: ConnInfo,
        gone: Option<GoneWatch>,
        journal: Option<Journal>,
    ) {
        let broke = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let io = Io { cx: cx.clone(), conn, broke: broke.clone(), buf: vec![0; 16 * 1024].into_boxed_slice() };
        let route = Route { cx: cx.clone(), handler, info: Arc::new(info.clone()), journal: journal.clone() };
        let served = hyper::server::conn::http2::Builder::new(Executor { cx: cx.clone() })
            .timer(CxTimer { cx: cx.clone() })
            .serve_connection(io, route);
        let mut served = pin!(served);
        let mut stopping = pin!(cx.cancelled());
        let result = poll_fn(|task| {
            if let Poll::Ready(r) = served.as_mut().poll(task) {
                return Poll::Ready(Some(r));
            }
            if let Some(g) = &gone
                && g.poll_gone(task).is_ready()
            {
                return Poll::Ready(None);
            }
            if stopping.as_mut().poll(task).is_ready() {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        let Some(result) = result else { return };
        let Some(j) = journal else { return };
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
            j.record(cx, &info, error_event(&info, cause, detail));
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
                let protocol = e.is_library() && e.reason().is_some_and(|r| r != ::h2::Reason::NO_ERROR);
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
        let broken = io.get_ref().and_then(|e| e.downcast_ref::<ConnError>()) == Some(&ConnError::Broken);
        broken.then_some("transport")
    }

    #[derive(Clone)]
    struct Route {
        cx: Cx,
        handler: Arc<dyn Handler>,
        info: Arc<ConnInfo>,
        journal: Option<Journal>,
    }

    type Answer = Pin<Box<dyn Future<Output = Result<Response<Counted>, Error>> + Send>>;

    impl hyper::service::Service<Request<Incoming>> for Route {
        type Response = Response<Counted>;
        type Error = Error;
        type Future = Answer;

        fn call(&self, request: Request<Incoming>) -> Answer {
            let route = self.clone();
            let on = route.journal.as_ref().is_some_and(|j| j.wants(&route.cx));
            let track = Track {
                tracker: Tracker::new(on, &request, &route.info, route.cx.now()),
                journal: route.journal.clone(),
                cx: route.cx.clone(),
                info: route.info.clone(),
                extra: None,
                status: None,
                sent: 0,
                complete: false,
            };
            Box::pin(async move {
                // Dropped with the future if the client resets the stream.
                let mut track = track;
                let (parts, body) = request.into_parts();
                let head_only = parts.method == Method::HEAD;
                let response = match Limited::new(body, 64 << 20).collect().await {
                    Err(_) => text(StatusCode::PAYLOAD_TOO_LARGE, "The request body is too large.\n"),
                    Ok(body) => {
                        let mut request = Request::from_parts(parts, Body::from(body.to_bytes()));
                        request.extensions_mut().insert((*route.info).clone());
                        let now = route.cx.now();
                        let cx = route.cx.clone();
                        let mut rng = move || cx.random_u64();
                        let reply = route.handler.call(request, &mut Exchange::new(now, &mut rng, &route.info));
                        match reply {
                            Reply::Now(r) => r,
                            Reply::Later(work) => match work(route.cx.clone()).await {
                                Ok(r) => r,
                                Err(e) => error_response(&e),
                            },
                        }
                    }
                };
                let (mut parts, body) = response.into_parts();
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
                parts.extensions = http::Extensions::new();
                Ok(Response::from_parts(parts, Counted { body, rest: Bytes::new(), track, bodiless }))
            })
        }
    }

    /// One request's event, sent when it is dropped.
    struct Track {
        tracker: Tracker,
        journal: Option<Journal>,
        cx: Cx,
        info: Arc<ConnInfo>,
        extra: Option<Fields>,
        status: Option<StatusCode>,
        sent: u64,
        complete: bool,
    }

    impl Drop for Track {
        fn drop(&mut self) {
            if let Some(e) = self.tracker.finish(self.extra.take(), self.status, self.sent, self.complete)
                && let Some(j) = &self.journal
            {
                j.record(&self.cx, &self.info, e);
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
    }

    impl http_body::Body for Counted {
        type Data = Bytes;
        type Error = Error;

        fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
            let this = self.get_mut();
            if !this.rest.is_empty() {
                let piece = this.rest.split_to(this.rest.len().min(PIECE));
                this.track.sent += piece.len() as u64;
                return Poll::Ready(Some(Ok(Frame::data(piece))));
            }
            let mut polled = Pin::new(&mut this.body).poll_frame(task);
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

    impl Drop for Counted {
        fn drop(&mut self) {
            // hyper may stop polling once the body says it has ended.
            if http_body::Body::is_end_stream(self) || self.bodiless {
                self.track.complete = true;
            }
        }
    }

    /// A connection as hyper's `Read` and `Write`.
    struct Io<C> {
        cx: Cx,
        conn: C,
        broke: Arc<std::sync::atomic::AtomicBool>,
        buf: Box<[u8]>,
    }

    fn to_io(e: ConnError) -> std::io::Error {
        use std::io::ErrorKind;
        let kind = match e {
            ConnError::Cancelled => ErrorKind::Interrupted,
            ConnError::Refused => ErrorKind::ConnectionRefused,
            ConnError::Reset => ErrorKind::ConnectionReset,
            ConnError::TimedOut => ErrorKind::TimedOut,
            ConnError::Closed => ErrorKind::BrokenPipe,
            ConnError::Broken => ErrorKind::InvalidData,
        };
        std::io::Error::new(kind, e)
    }

    impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
        fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let want = buf.remaining().min(this.buf.len());
            match this.conn.poll_read(&this.cx, task, &mut this.buf[..want]) {
                Poll::Ready(Ok(n)) => {
                    buf.put_slice(&this.buf[..n]);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    if e == ConnError::Broken {
                        this.broke.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    Poll::Ready(Err(to_io(e)))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
        fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.conn.poll_write(&this.cx, task, data).map_err(to_io)
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(self: Pin<&mut Self>, task: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let mut done = 0;
            for buf in bufs.iter().filter(|b| !b.is_empty()) {
                match this.conn.poll_write(&this.cx, task, buf) {
                    Poll::Ready(Ok(n)) => {
                        done += n;
                        if n < buf.len() {
                            break;
                        }
                    }
                    Poll::Ready(Err(e)) if done == 0 => return Poll::Ready(Err(to_io(e))),
                    Poll::Pending if done == 0 => return Poll::Pending,
                    Poll::Ready(Err(_)) | Poll::Pending => break,
                }
            }
            Poll::Ready(Ok(done))
        }

        fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.conn.poll_shutdown(&this.cx, task).map_err(to_io)
        }
    }

    /// Runs hyper's streams as tasks, which end when the world stops.
    #[derive(Clone)]
    struct Executor {
        cx: Cx,
    }

    impl<F> hyper::rt::Executor<F> for Executor
    where
        F: Future<Output = ()> + Send + 'static,
    {
        fn execute(&self, work: F) {
            self.cx.spawn(move |cx| async move {
                let mut work = pin!(work);
                let mut stopping = pin!(cx.cancelled());
                poll_fn(|task| {
                    if work.as_mut().poll(task).is_ready() || stopping.as_mut().poll(task).is_ready() {
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
        cx: Cx,
    }

    impl hyper::rt::Timer for CxTimer {
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
            let cx = self.cx.clone();
            Box::pin(CxSleep(Box::pin(async move {
                let _ = cx.sleep(duration).await;
            })))
        }

        fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
            self.sleep(deadline.saturating_duration_since(std::time::Instant::now()))
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

        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
            self.get_mut().0.as_mut().poll(task)
        }
    }

    impl hyper::rt::Sleep for CxSleep {}
}
