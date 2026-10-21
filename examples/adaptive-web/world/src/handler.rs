//! The handler of every site: routes the request, answers it from the
//! world's [`Pages`], records a search's facts, and moves what the pages
//! say about the answer into the request's event.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::pages::{MAX_FORM_BYTES, Meta, Pages};
use crate::route::{Route, query_key, route};
use bytes::Bytes;
use example_common::names::name;
use fictionet::events::ConnInfo;
use fictionet::stdlib::web::{self, Body};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

/// Shared routing, query facts and response event fields.
#[derive(Clone)]
pub struct Handler {
    fcx: fictionet::Cx,
    pages: Arc<Pages>,
}

impl Handler {
    /// A handler for every site of the world.
    pub fn new(fcx: &fictionet::Cx, pages: Arc<Pages>) -> Self {
        Self {
            fcx: fcx.clone(),
            pages,
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
        let page = action == Route::Page;
        let mut query = None;
        if let Route::Search {
            engine,
            query: search,
            start,
        } = &action
        {
            let id = self.pages.next_query_id();
            query = Some(QueryGuard {
                fcx: self.fcx.clone(),
                conn: conn.clone(),
                id,
                finished: false,
            });
            self.fcx.emitter(&conn).emit("adaptive", "query", |e| {
                e.summary(format_args!("{} search: {search}", name(&engine)))
                    .field("query_id", id)
                    .field("engine", name(&engine))
                    .field("search", search.as_str())
                    .field("start", *start)
                    .field("key", query_key(search, *start))
            });
        }
        let answer = if parts.method == http::Method::POST && action == Route::Page {
            self.pages.making(&self.fcx, &target.host, path);
            self.pages.form(&target.host, path)
        } else {
            self.pages
                .handle_route(&self.fcx, &target.host, path, action)
                .await
        };
        if let Some(q) = &mut query {
            match &answer.meta {
                Meta::Error { error, .. } => q.fail("error", Some(error), answer.serve_ms),
                Meta::Budget(_) => q.fail("budget", None, answer.serve_ms),
                _ => q.finished = true,
            }
        }
        let fields = observing.then(|| {
            let mut fields = answer.fields();
            if page && matches!(answer.meta, Meta::Error { .. }) {
                fields.set("kind", "page");
            }
            if page
                && parts
                    .headers
                    .get(USER_AGENT)
                    .is_some_and(|value| value.as_bytes().starts_with(b"Claude-User"))
            {
                fields.set("via", "web_fetch");
            }
            fields
        });
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
        if let Some(mut fields) = fields {
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
