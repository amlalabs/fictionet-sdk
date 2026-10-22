use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;

use http::{HeaderValue, Request, Response, StatusCode};

use fictionet::events::ConnInfo;
use fictionet::stdlib::network::Connection;
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
