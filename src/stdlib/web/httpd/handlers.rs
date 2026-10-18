use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};

use fictionet::events::ConnInfo;
use fictionet::stdlib::Connection;
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::Body;

// ---------------------------------------------------------------------------
// Handlers

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
    /// Hand this HTTP/1.1 upgrade request to hyper's HTTP/1 server, which reads
    /// it again and supplies hyper's upgrade extension. [`tower`] returns it for
    /// axum's `WebSocketUpgrade`. HTTP/2 answers it with `500`.
    Handoff(Request<Body>),
}

/// Answers HTTP requests. See the [module docs](super).
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
///
/// Callbacks receive only bodies held in full, including valid empty
/// bodies. Any other body gets `400 Bad Request` before route selection.
/// To inspect partial HTTP/1 bodies as a stream ending in an error, use a
/// custom [`Handler`] or [`tower`] service. See [`Body`].
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
                Some(prefix) => path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.is_empty() || tail.starts_with('/')),
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
        let Some(body) = body.bytes() else {
            return Reply::Now(status_only(StatusCode::BAD_REQUEST));
        };
        let request = Request::from_parts(parts, body);
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

pub(super) fn status_only(status: StatusCode) -> Response<Body> {
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
        fictionet::cfg_tokio! {
            if needs_hyper_upgrade(&request) {
                return Reply::Handoff(request);
            }
        }
        let mut service = self.service.lock().clone();
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

fictionet::cfg_tokio! {
/// Whether an HTTP/1.1 request asks to switch protocols (RFC 9110 section
/// 7.8) without hyper's upgrade extension, which axum's `WebSocketUpgrade`
/// needs and only hyper's HTTP/1 server supplies.
fn needs_hyper_upgrade(request: &Request<Body>) -> bool {
    let connection_upgrade = request
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|v| {
            v.as_bytes()
                .split(|b| *b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
        });
    request.version() == http::Version::HTTP_11
        && request.method() != Method::CONNECT
        && request.headers().contains_key(http::header::UPGRADE)
        && connection_upgrade
        && request
            .extensions()
            .get::<hyper::upgrade::OnUpgrade>()
            .is_none()
}
}

/// Runs a protocol after an HTTP/1 switching-protocols response is written.
///
/// Insert this in the extensions of a `101 Switching Protocols` response
/// returned as [`Reply::Now`]. [`serve_connection`](super::serve_connection) calls it with the
/// connection and its unread bytes. It runs once, even if the response is cloned.
#[derive(Clone)]
pub struct UpgradeHandler(Arc<Mutex<Option<UpgradeWork>>>);

type UpgradeWork =
    Box<dyn FnOnce(Cx, Box<dyn Connection>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

impl UpgradeHandler {
    /// Calls `work` after the response is sent.
    pub fn new<F, Fut>(work: F) -> Self
    where
        F: FnOnce(Cx, Box<dyn Connection>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self(Arc::new(Mutex::new(Some(Box::new(move |fcx, conn| {
            Box::pin(work(fcx, conn))
        })))))
    }

    pub(super) async fn run(self, fcx: Cx, conn: Box<dyn Connection>) {
        let work = self.0.lock().take();
        if let Some(work) = work {
            work(fcx, conn).await;
        }
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;

    #[test]
    fn wildcard_prefixes_keep_slash_boundaries_and_method_precedence() {
        let router = Router::new().get("/files/*", |_, _| Response::new(Bytes::new()));
        assert!(router.find(&Method::GET, "/files").is_ok());
        assert!(router.find(&Method::GET, "/files/").is_ok());
        assert!(router.find(&Method::GET, "/files/a/b").is_ok());
        assert!(matches!(router.find(&Method::GET, "/filesx"), Err(false)));
        assert!(matches!(router.find(&Method::POST, "/files/a"), Err(true)));
        let root = Router::new().get("/*", |_, _| Response::new(Bytes::new()));
        assert!(root.find(&Method::GET, "").is_ok());
        assert!(root.find(&Method::GET, "/a").is_ok());
        assert!(matches!(root.find(&Method::GET, "a"), Err(false)));
    }
}
