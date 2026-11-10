use crate::stdlib::web::Response;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::StatusCode;

use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::Connection;
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::Body;
use crate::stdlib::web::Request;

// ---------------------------------------------------------------------------
// Handlers

/// What a sync handler can use: the clock reading the service took,
/// randomness, and the connection.
pub struct Exchange<'a> {
    now: Instant,
    entropy: &'a dyn fictionet::Entropy,
    conn: &'a ConnInfo,
    responses: Responses,
}

impl<'a> Exchange<'a> {
    /// An exchange for a handler called outside a service, such as in a
    /// test.
    pub fn new(
        now: Instant,
        entropy: &'a dyn fictionet::Entropy,
        conn: &'a ConnInfo,
        responses: Responses,
    ) -> Exchange<'a> {
        Exchange {
            now,
            entropy,
            conn,
            responses,
        }
    }

    /// Charged response storage shared with this connection.
    pub fn responses(&self) -> &Responses {
        &self.responses
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
/// of the response. An error answers `500`, or `502` for [`BadGateway`];
/// [`Reset`] answers nothing.
pub type Later =
    Box<dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>> + Send>;

/// What a handler gives back for a request.
pub enum Reply {
    /// The response, now.
    Now(Response),
    /// Work that makes the response.
    Later(Later),
}

/// Answers HTTP requests. See the [module docs](super).
pub trait Handler: Send + Sync + 'static {
    /// Answers `request`; the exchange borrows its connection.
    fn call(&self, request: Request, ex: &mut Exchange<'_>) -> Reply;
}

impl<H: Handler + ?Sized> Handler for Arc<H> {
    fn call(&self, request: Request, ex: &mut Exchange<'_>) -> Reply {
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

/// The error a handler returns to give the client no answer at all, as a
/// path to a site that cannot be reached gives none: HTTP/1 closes the
/// connection without a response, and HTTP/2 resets the stream.
#[derive(Debug)]
pub struct Reset(pub String);

impl std::fmt::Display for Reset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reset: {}", self.0)
    }
}

impl std::error::Error for Reset {}

pub(super) fn status_only(status: StatusCode) -> Response {
    let mut r = Response::new(Body::empty());
    r.status = status;
    r
}

/// Response storage that can also be retained by asynchronous handlers.
#[derive(Clone)]
pub struct Responses {
    budget: fictionet::Budget,
    pool: Option<fictionet::Pool>,
}

impl Responses {
    /// A reusable cache charged to its owner.
    pub fn new(budget: &fictionet::Budget) -> Self {
        Self::pooled(budget, fictionet::Pool::new(budget, 2048, 4))
    }
    pub(crate) fn pooled(budget: &fictionet::Budget, pool: fictionet::Pool) -> Self {
        Self {
            budget: budget.clone(),
            pool: Some(pool),
        }
    }
    pub(crate) fn unpooled(budget: &fictionet::Budget) -> Self {
        Self {
            budget: budget.clone(),
            pool: None,
        }
    }
    /// An empty field block. Refusal leaves the budget unchanged.
    pub fn fields(&self) -> Option<crate::stdlib::web::Fields> {
        let block = match &self.pool {
            Some(pool) => pool.take(&self.budget, 0)?,
            None => {
                let charge = self.budget.charge(2048)?;
                fictionet::Chunk::paid(vec![0; 2048], charge)
                    .expect("reserved fields")
                    .slice(0..0)
            }
        };
        crate::stdlib::web::Fields::in_block(block).ok()
    }
    /// Copies bytes into a charged block, reusing small backings.
    pub fn body(&self, bytes: &[u8]) -> Option<Body> {
        if bytes.is_empty() {
            return Some(Body::empty());
        }
        let mut block = if let Some(pool) = &self.pool
            && bytes.len() <= pool.slot()
        {
            pool.take(&self.budget, 0)?
        } else {
            return Some(Body::Full(fictionet::Chunk::copy_of(&self.budget, bytes)?));
        };
        block.extend_within(bytes).ok()?;
        Some(Body::Full(block))
    }
}

/// A short plain-text response, or an empty unavailable response if storage is refused.
pub fn text(storage: &Responses, status: StatusCode, body: &str) -> Response {
    let Some(body) = storage.body(body.as_bytes()) else {
        return status_only(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(mut fields) = storage.fields() else {
        return status_only(StatusCode::SERVICE_UNAVAILABLE);
    };
    fields
        .push("content-type", b"text/plain; charset=utf-8")
        .expect("small field fits");
    let mut response = Response::new(body);
    response.status = status;
    response.fields = fields;
    response
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn response_storage_preserves_bodies_across_pool_sizes_and_refuses_without_room() {
        for pooled in [false, true] {
            let budget = fictionet::Budget::new(1 << 20);
            let storage = if pooled {
                Responses::new(&budget)
            } else {
                Responses::unpooled(&budget)
            };
            for length in [0, 1, 2048, 2049, 8192] {
                let bytes = "x".repeat(length);
                let response = text(&storage, StatusCode::OK, &bytes);
                assert_eq!(response.status, StatusCode::OK);
                assert_eq!(response.body.bytes().unwrap().as_ref(), bytes.as_bytes());
                assert_eq!(response.fields.iter().count(), 1);
                drop(response);
                assert_eq!(
                    budget.used(),
                    storage.pool.as_ref().map_or(0, |p| p.charged())
                );
            }
            drop(storage);
            assert_eq!(budget.used(), 0);
            let budget = fictionet::Budget::new(0);
            let storage = if pooled {
                Responses::new(&budget)
            } else {
                Responses::unpooled(&budget)
            };
            let response = text(&storage, StatusCode::OK, "unavailable");
            assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.body.bytes().unwrap().is_empty());
            assert_eq!(budget.used(), 0);
        }
    }
}

/// Runs a protocol after an HTTP/1 response that hands the connection on is
/// written.
///
/// Set this in the `upgrade` field of a `101 Switching Protocols` response,
/// or of a 2xx response to CONNECT. Once the response is written,
/// [`Http1::upgradable`](super::Http1::upgradable) calls it with the rest of
/// the stream as a connection, whose first bytes are those the client sent
/// past the request. It runs once, even if the response is cloned.
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
