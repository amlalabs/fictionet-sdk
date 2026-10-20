//! The handler of every site: routes the request, answers it from the
//! world's [`Pages`], records a search's facts, and moves what the pages
//! say about the answer into the request's event.

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll};

use crate::pages::{MAX_FORM_BYTES, Pages};
use crate::route::{Route, query_key, route};
use bytes::Bytes;
use fictionet::events::{ConnInfo, Fields, float};
use fictionet::stdlib::protocols::json::Value as J;
use fictionet::stdlib::web::{self, Body};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value;

/// Page fields kept in HTTP log lines. None is a name `http.request` uses
/// itself. There, `query` is the URL query, so search text is `search`.
pub const PAGE_FIELDS: [&str; 19] = [
    "kind",
    "cache",
    "engine",
    "search",
    "results",
    "title",
    "model",
    "gen_ms",
    "cost",
    "serve_ms",
    "prefetched",
    "claims",
    "mentions",
    "unsupported_snippets",
    "unchecked_snippets",
    "tells",
    "location",
    "error",
    "bytes",
];

/// Page fields for the projection, kept out of HTTP log lines.
/// These names and the handler's `query_id` are not used by `http.request` itself.
pub const EVENT_FIELDS: [&str; 2] = ["listed", "reason"];

/// Shared routing, query facts and response event fields. Clones share one
/// query counter.
#[derive(Clone)]
pub struct Handler {
    fcx: fictionet::Cx,
    pages: Arc<Pages>,
    queries: Arc<AtomicU64>,
}

impl Handler {
    /// A handler for every site of the world.
    pub fn new(fcx: &fictionet::Cx, pages: Arc<Pages>) -> Self {
        Self {
            fcx: fcx.clone(),
            pages,
            queries: Arc::new(AtomicU64::new(1)),
        }
    }
}

struct QueryGuard {
    fcx: fictionet::Cx,
    conn: ConnInfo,
    id: u64,
    finished: bool,
}

impl QueryGuard {
    fn fail(&mut self, why: &str, error: Option<&str>, serve_ms: Option<u64>) {
        self.finished = true;
        self.fcx
            .emitter(&self.conn)
            .emit("adaptive", "query_failed", |e| {
                let mut e = e
                    .summary(format_args!("query {}: {why}", self.id))
                    .field("query_id", self.id)
                    .field("why", why);
                if let Some(error) = error {
                    e = e.field("error", error);
                }
                if let Some(ms) = serve_ms {
                    e = e.field("serve_ms", ms);
                }
                e
            });
    }
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.fail("abandoned", None, None);
        }
    }
}

/// A JSON value as an event field's value.
pub fn to_field(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) => u.into(),
            (None, Some(i)) => i.into(),
            _ => float(n.as_f64().unwrap_or(0.0)),
        },
        Value::String(s) => s.as_str().into(),
        Value::Array(items) => J::Array(items.iter().map(to_field).collect()),
        Value::Object(members) => J::Object(
            members
                .iter()
                .map(|(k, v)| (k.clone(), to_field(v)))
                .collect(),
        ),
    }
}

impl Handler {
    async fn serve(
        self,
        request: Request<Body>,
    ) -> Result<Response<Full<Bytes>>, fictionet::Error> {
        let observing = web::httpd::EventInterest::of(&request);
        let target = request
            .extensions()
            .get::<web::Target>()
            .cloned()
            .ok_or_else(|| fictionet::Error::msg("request without a web::Target"))?;
        let conn = request
            .extensions()
            .get::<ConnInfo>()
            .cloned()
            .unwrap_or_default();
        let (parts, body) = request.into_parts();
        let body = body.collect().await?.to_bytes();
        let form = (parts.method == http::Method::POST
            && parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("form-urlencoded")))
        .then_some(&body[..body.len().min(MAX_FORM_BYTES)]);
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        let action = route(&target.host, path, form);
        let mut query = None;
        if let Route::Search {
            engine,
            query: search,
            start,
        } = &action
        {
            let id = self.queries.fetch_add(1, Ordering::Relaxed);
            query = Some(QueryGuard {
                fcx: self.fcx.clone(),
                conn: conn.clone(),
                id,
                finished: false,
            });
            self.fcx.emitter(&conn).emit("adaptive", "query", |e| {
                e.summary(format_args!("{} search: {search}", engine.as_str()))
                    .field("query_id", id)
                    .field("engine", engine.as_str())
                    .field("search", search.as_str())
                    .field("start", *start)
                    .field("key", query_key(search, *start))
            });
        }
        let answer = self
            .pages
            .handle_route(&self.fcx, &target.host, path, action)
            .await;
        let meta = answer.meta;
        let mut response = Response::builder()
            .status(StatusCode::from_u16(answer.status)?)
            .header(CONTENT_TYPE, answer.content_type)
            .header(CONTENT_LENGTH, answer.body.len())
            .header("cache-control", "private, max-age=0");
        for (name, value) in answer.headers {
            response = response.header(name, value);
        }
        let bytes = answer.body.len();
        let body = if parts.method == http::Method::HEAD {
            Bytes::new()
        } else {
            Bytes::from(answer.body)
        };
        let mut response = response.body(Full::new(body))?;
        if let Some(q) = &mut query {
            let why = if meta["kind"] == "error" {
                Some("error")
            } else if meta["cache"] == "budget" {
                Some("budget")
            } else {
                None
            };
            if let Some(why) = why {
                q.fail(why, meta["error"].as_str(), meta["serve_ms"].as_u64());
            } else {
                q.finished = true;
            }
        }
        if observing {
            let mut fields = Fields::new();
            for name in PAGE_FIELDS.into_iter().chain(EVENT_FIELDS) {
                if let Some(v) = meta.get(name) {
                    fields.set(name, to_field(v));
                }
            }
            if let Some(q) = &query {
                fields.set("query_id", q.id);
            }
            // The length of the page, also for HEAD.
            fields.set("bytes", bytes as u64);
            response.extensions_mut().insert(fields);
        }
        Ok(response)
    }
}

impl tower_service::Service<Request<Body>> for Handler {
    type Response = Response<Full<Bytes>>;
    type Error = fictionet::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        Box::pin(self.clone().serve(request))
    }
}
