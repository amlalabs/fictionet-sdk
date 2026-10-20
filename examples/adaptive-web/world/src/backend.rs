//! The handler of every site, with either Python or in-process stub pages.
//! Routing, query facts and response event fields share one path. Python's
//! `X-Adaptive-Meta` header is removed and mapped to event fields for the log.
//! The agent never sees that header. Missing or malformed metadata answers
//! 502 with `kind = "meta_error"` and a reason instead of forwarding the page.
//! Metadata must be an object with a string `kind`, and a string `cache`
//! when the kind is `page` or `search`.
//! Transport and metadata failures record `serve_ms` on the Fictionet clock.

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll};

use crate::route::{Route, query_key, route};
use bytes::Bytes;
use fictionet::events::{ConnInfo, Fields, float};
use fictionet::stdlib::protocols::json::Value as J;
use fictionet::stdlib::web::{self, Body};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, REFERER, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value;

/// The header backend.py adds for the log.
const META: &str = "x-adaptive-meta";

/// Backend fields retained in HTTP log lines. None is a name `http.request`
/// uses itself. There, `query` is the URL query, so search text is `search`.
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

/// Backend fields for the projection, kept out of HTTP log lines.
/// These names and the handler's `query_id` are not used by `http.request` itself.
pub const EVENT_FIELDS: [&str; 2] = ["listed", "reason"];

#[derive(Clone)]
pub struct Backend {
    forward: web::Forward,
}

/// The source of page bodies and metadata.
#[derive(Clone)]
pub enum Pages {
    Backend(Backend),
    Stub(Arc<crate::stub::Stub>),
}
impl From<Backend> for Pages {
    fn from(backend: Backend) -> Self {
        Self::Backend(backend)
    }
}
impl From<Arc<crate::stub::Stub>> for Pages {
    fn from(stub: Arc<crate::stub::Stub>) -> Self {
        Self::Stub(stub)
    }
}

/// Shared routing, query facts and response event fields for either source.
#[derive(Clone)]
pub struct Handler {
    fcx: fictionet::Cx,
    pages: Pages,
    queries: Arc<AtomicU64>,
}
impl Pages {
    /// Creates a handler whose clones share one query counter.
    pub fn handler(self, fcx: &fictionet::Cx) -> Handler {
        Handler {
            fcx: fcx.clone(),
            pages: self,
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

/// A JSON value from the backend as an event field's value.
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

impl Backend {
    pub fn new(fcx: &fictionet::Cx, port: u16) -> Result<Backend, fictionet::Error> {
        Ok(Backend {
            forward: web::forward(fcx, format!("http://127.0.0.1:{port}").parse().unwrap())?,
        })
    }
}

impl Handler {
    async fn serve(
        self,
        request: Request<Body>,
    ) -> Result<Response<Full<Bytes>>, fictionet::Error> {
        let observing = fictionet::stdlib::web::httpd::EventInterest::of(&request);
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
        let mut query = None;

        let reply = async {
            let body = body.collect().await?.to_bytes();
            let form = (parts.method == http::Method::POST
                && parts
                    .headers
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("form-urlencoded")))
            .then_some(&body[..body.len().min(1 << 20)]);
            let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
            let action = route(&target.host, path, form);
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
            if let Pages::Stub(stub) = &self.pages {
                let answer = stub.handle_route(&self.fcx, &target.host, path, action);
                let mut response = Response::builder()
                    .status(answer.status)
                    .header(CONTENT_TYPE, answer.content_type)
                    .header(CONTENT_LENGTH, answer.body.len())
                    .header("cache-control", "private, max-age=0");
                for (name, value) in answer.headers {
                    response = response.header(name, value);
                }
                let body = if parts.method == http::Method::HEAD {
                    Bytes::new()
                } else {
                    Bytes::from(answer.body)
                };
                let (parts, body) = response.body(body)?.into_parts();
                return Ok((parts, body, Ok(answer.meta)));
            }
            let Pages::Backend(backend) = &self.pages else {
                unreachable!()
            };
            let mut ask = Request::builder()
                .method(parts.method.clone())
                .uri(parts.uri)
                .header(HOST, target.host.as_str());
            for name in [USER_AGENT, REFERER, ACCEPT, CONTENT_TYPE] {
                if let Some(v) = parts.headers.get(&name) {
                    ask = ask.header(name, v);
                }
            }
            let answer = tower_service::Service::call(
                &mut backend.forward.clone(),
                ask.body(Body::from(body))?,
            )
            .await?;
            let (mut parts, body) = answer.into_parts();
            let body = body.collect().await?.to_bytes();
            let meta = metadata(parts.headers.remove(META));
            Ok::<_, fictionet::Error>((parts, body, meta))
        };
        let started = self.fcx.now().since_start();
        let reply = reply.await;
        let serve_ms = (self.fcx.now().since_start() - started).as_millis() as u64;
        let (mut parts, body, meta) = match reply {
            Ok(r) => r,
            Err(e) => {
                if let Some(q) = &mut query {
                    q.fail("backend_error", Some(&e.to_string()), Some(serve_ms));
                }
                let mut response = Response::new(Full::new(Bytes::from_static(
                    b"The site failed to answer.\n",
                )));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                if observing {
                    let fields = Fields::new()
                        .with("kind", "backend_error")
                        .with("serve_ms", serve_ms)
                        .with("error", e.to_string());
                    response.extensions_mut().insert(fields);
                }
                return Ok(response);
            }
        };
        let meta = match meta {
            Ok(meta) => meta,
            Err(error) => {
                if let Some(q) = &mut query {
                    q.fail("meta_error", Some(error), Some(serve_ms));
                }
                let mut response = Response::new(Full::new(Bytes::from_static(
                    b"The site returned invalid metadata.\n",
                )));
                *response.status_mut() = StatusCode::BAD_GATEWAY;
                if observing {
                    let fields = Fields::new()
                        .with("kind", "meta_error")
                        .with("serve_ms", serve_ms)
                        .with("error", error);
                    response.extensions_mut().insert(fields);
                }
                return Ok(response);
            }
        };

        if let Some(q) = &mut query {
            let why = if meta["kind"] == "error" {
                Some("error")
            } else if meta["cache"] == "budget" {
                Some("budget")
            } else {
                None
            };
            if let Some(why) = why {
                q.fail(
                    why,
                    meta["error"].as_str(),
                    meta["serve_ms"].as_u64().or(Some(serve_ms)),
                );
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
            let bytes = parts
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
                .unwrap_or(body.len() as u64);
            fields.set("bytes", bytes);
            parts.extensions.insert(fields);
        }
        Ok(Response::from_parts(parts, Full::new(body)))
    }
}

fn metadata(header: Option<http::HeaderValue>) -> Result<Value, &'static str> {
    let header = header.ok_or("missing X-Adaptive-Meta")?;
    let text = header
        .to_str()
        .map_err(|_| "X-Adaptive-Meta is not ASCII")?;
    let meta: Value =
        serde_json::from_slice(&percent_decode(text)).map_err(|_| "X-Adaptive-Meta is not JSON")?;
    if !meta.is_object() {
        return Err("X-Adaptive-Meta is not an object");
    }
    let kind = meta
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("X-Adaptive-Meta has no string kind")?;
    if matches!(kind, "page" | "search") && meta.get("cache").and_then(Value::as_str).is_none() {
        return Err("X-Adaptive-Meta page or search has no string cache");
    }
    Ok(meta)
}

/// Undoes Python's `urllib.parse.quote(..., safe="")`.
fn percent_decode(text: &str) -> Vec<u8> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::web::httpd::{self, Handler, VHost, VirtualHosts};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    enum Answer {
        Success,
        Transport,
        Metadata,
        Error,
        Budget,
        Abandoned,
    }

    fn query_outcome(answer: Answer) -> (Arc<fictionet_observe::Memory>, Option<Fields>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let abandoned = matches!(answer, Answer::Abandoned);
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = conn.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            accepted_tx.send(()).unwrap();
            if abandoned {
                release_rx.recv().unwrap();
                return;
            }
            let (status, meta) = match answer {
                Answer::Success => (
                    200,
                    r#"{"kind":"search","cache":"generated","listed":[{"rank":1,"url":"https://a.com/","title":"A"}],"reason":{"via":"direct"}}"#,
                ),
                Answer::Transport => return,
                Answer::Metadata => (200, "invalid"),
                Answer::Error => (
                    503,
                    r#"{"kind":"error","error":"generation failed","serve_ms":7}"#,
                ),
                Answer::Budget => (503, r#"{"kind":"search","cache":"budget","serve_ms":8}"#),
                Answer::Abandoned => unreachable!(),
            };
            write!(conn, "HTTP/1.1 {status} OK\r\nContent-Length: 4\r\nConnection: close\r\nX-Adaptive-Meta: {meta}\r\n\r\npage").unwrap();
        });
        let events = Arc::new(fictionet_observe::Memory::default());
        let observed = events.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (fields_tx, fields_rx) = std::sync::mpsc::channel();
        rt.block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(observed),
            move |fcx| async move {
                let hosts = VirtualHosts::new();
                hosts.insert(
                    "html.duckduckgo.com",
                    VHost::new(httpd::tower(
                        Pages::Backend(Backend::new(&fcx, address.port())?).handler(&fcx),
                    )),
                );
                let conn = ConnInfo::new(42, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fcx.now(), &entropy, &conn);
                let request = Request::builder()
                    .extension(httpd::EventInterest(true))
                    .extension(conn.clone())
                    .method("POST")
                    .header(
                        CONTENT_TYPE,
                        "application/x-www-form-urlencoded; charset=utf-8",
                    )
                    .uri("http://html.duckduckgo.com/html/?q=url")
                    .body(Body::from(Bytes::from_static(b"q=+Form+search+&s=20")))?;
                let httpd::Reply::Later(work) = hosts.call(request, &mut ex) else {
                    panic!("backend request required");
                };
                let mut future = work(fcx);
                if abandoned {
                    tokio::select! {
                        result = &mut future => panic!("backend unexpectedly answered: {result:?}"),
                        result = accepted_rx => result.unwrap(),
                    }
                    drop(future);
                    release_tx.send(()).unwrap();
                    fields_tx.send(None).unwrap();
                    Ok(())
                } else {
                    // Keep the receiver until the server reports acceptance.
                    let response = future.await?;
                    accepted_rx.await.unwrap();
                    fields_tx
                        .send(response.extensions().get::<Fields>().cloned())
                        .unwrap();
                    Ok(())
                }
            },
        ))
        .unwrap();
        server.join().unwrap();
        let queries = events.checked_of("adaptive", "query").unwrap();
        assert_eq!(queries.len(), 1);
        let q = &queries[0];
        assert_eq!(q.u64("query_id"), Some(1));
        assert_eq!(q.str("engine"), Some("duckduckgo"));
        assert_eq!(q.str("search"), Some("Form search"));
        assert_eq!(q.u64("start"), Some(20));
        assert_eq!(q.str("key"), Some("form search (from 20)"));
        assert_eq!(q.conn.id, Some(42));
        assert_eq!(q.conn.peer.unwrap().ip().to_string(), "10.0.0.2");
        (events, fields_rx.recv().unwrap())
    }

    fn query_failure(answer: Answer, why: &str) {
        let (events, _) = query_outcome(answer);
        let failed = events.checked_of("adaptive", "query_failed").unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].u64("query_id"), Some(1));
        assert_eq!(failed[0].str("why"), Some(why));
        assert_eq!(failed[0].conn.id, Some(42));
        if why != "abandoned" {
            assert!(failed[0].u64("serve_ms").is_some());
        }
        if matches!(why, "backend_error" | "meta_error" | "error") {
            assert!(!failed[0].str("error").unwrap().is_empty());
        }
    }

    #[test]
    fn query_success() {
        let (events, fields) = query_outcome(Answer::Success);
        assert!(
            events
                .checked_of("adaptive", "query_failed")
                .unwrap()
                .is_empty()
        );
        let fields = fields.unwrap();
        assert_eq!(fields.get("query_id").and_then(J::as_u64), Some(1));
        assert_eq!(
            fields.get("listed").map(crate::events::to_json),
            Some(serde_json::json!([{"rank":1,"url":"https://a.com/","title":"A"}]))
        );
        assert_eq!(
            fields.get("reason").map(crate::events::to_json),
            Some(serde_json::json!({"via":"direct"}))
        );
    }
    #[test]
    fn query_transport_failure() {
        query_failure(Answer::Transport, "backend_error");
    }
    #[test]
    fn query_metadata_failure() {
        query_failure(Answer::Metadata, "meta_error");
    }
    #[test]
    fn query_generation_failure() {
        query_failure(Answer::Error, "error");
    }
    #[test]
    fn query_budget_failure() {
        query_failure(Answer::Budget, "budget");
    }
    #[test]
    fn query_abandoned() {
        query_failure(Answer::Abandoned, "abandoned");
    }

    fn backend_response(meta: Option<&[u8]>) -> Response<Bytes> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut reply = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n".to_vec();
        if let Some(meta) = meta {
            reply.extend_from_slice(b"X-Adaptive-Meta: ");
            reply.extend_from_slice(meta);
            reply.extend_from_slice(b"\r\n");
        }
        reply.extend_from_slice(b"\r\npage");
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = conn.read(&mut buf).unwrap();
                assert_ne!(n, 0);
                request.extend_from_slice(&buf[..n]);
            }
            conn.write_all(&reply).unwrap();
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let result = rt.block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            move |fcx| async move {
                let hosts = VirtualHosts::new();
                hosts.insert(
                    "example.com",
                    VHost::new(httpd::tower(
                        Pages::Backend(Backend::new(&fcx, address.port())?).handler(&fcx),
                    )),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fcx.now(), &entropy, &conn);
                let request = Request::builder()
                    .extension(httpd::EventInterest(true))
                    .uri("http://example.com/")
                    .body(Body::empty())?;
                let httpd::Reply::Later(work) = hosts.call(request, &mut ex) else {
                    panic!("the backend must receive the request");
                };
                let (parts, body) = work(fcx).await?.into_parts();
                tx.send(Response::from_parts(
                    parts,
                    body.collect().await?.to_bytes(),
                ))
                .unwrap();
                Ok(())
            },
        ));
        server.join().unwrap();
        result.unwrap();
        rx.recv().unwrap()
    }

    fn assert_meta_error(meta: Option<&[u8]>) {
        let response = backend_response(meta);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let fields = response.extensions().get::<Fields>().unwrap();
        assert_eq!(fields.get("kind").and_then(J::as_str), Some("meta_error"));
        assert!(!fields.get("error").and_then(J::as_str).unwrap().is_empty());
        assert!(fields.get("serve_ms").and_then(J::as_u64).is_some());
        assert!(!response.headers().contains_key(META));
        assert_ne!(response.body().as_ref(), b"page");
    }

    #[test]
    fn missing_metadata() {
        assert_meta_error(None);
    }

    #[test]
    fn malformed_metadata() {
        for meta in [
            b"\xff".as_slice(),
            b"not json",
            b"null",
            b"[]",
            b"\"page\"",
            b"%7B%22kind%22%3A%22%FF%22%7D",
        ] {
            assert_meta_error(Some(meta));
        }
    }

    #[test]
    fn malformed_kind_and_cache() {
        for meta in [
            r#"{}"#,
            r#"{"kind":1}"#,
            r#"{"kind":"page"}"#,
            r#"{"kind":"search","cache":false}"#,
        ] {
            assert_meta_error(Some(meta.as_bytes()));
        }
    }

    #[test]
    fn valid_cached_metadata_needs_no_generation_time() {
        let response = backend_response(Some(
            b"%7B%22kind%22%3A%22page%22%2C%22cache%22%3A%22cached%22%7D",
        ));
        assert_eq!(response.status(), StatusCode::OK);
        let fields = response.extensions().get::<Fields>().unwrap();
        assert_eq!(fields.get("kind").and_then(J::as_str), Some("page"));
        assert_eq!(fields.get("cache").and_then(J::as_str), Some("cached"));
        assert!(fields.get("gen_ms").is_none());
        assert!(!response.headers().contains_key(META));
        assert_eq!(response.body().as_ref(), b"page");
    }

    #[test]
    fn transport_failure_is_timed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            move |fcx| async move {
                let hosts = VirtualHosts::new();
                hosts.insert(
                    "example.com",
                    VHost::new(httpd::tower(
                        Pages::Backend(Backend::new(&fcx, address.port())?).handler(&fcx),
                    )),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fcx.now(), &entropy, &conn);
                let request = Request::builder()
                    .extension(httpd::EventInterest(true))
                    .uri("http://example.com/")
                    .body(Body::empty())?;
                let httpd::Reply::Later(work) = hosts.call(request, &mut ex) else {
                    panic!("the backend must receive the request");
                };
                let response = work(fcx).await?;
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let fields = response.extensions().get::<Fields>().unwrap();
                assert_eq!(
                    fields.get("kind").and_then(J::as_str),
                    Some("backend_error")
                );
                assert!(fields.get("serve_ms").and_then(J::as_u64).is_some());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn construction_refuses_a_lab() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |fcx| async move {
                let error = super::Backend::new(&fcx, 8080).err().unwrap();
                assert_eq!(error.to_string(), "real I/O is unavailable in a lab run");
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn percent_decoding_undoes_quote() {
        assert_eq!(
            super::percent_decode("%7B%22a%22%3A%20%22%C3%A9%22%7D"),
            "{\"a\": \"é\"}".as_bytes()
        );
        assert_eq!(super::percent_decode("50%"), b"50%");
    }
}
