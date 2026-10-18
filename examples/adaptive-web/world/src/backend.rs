//! The handler of every site: it forwards the request to the Python backend
//! (backend.py, on 127.0.0.1 in the world container), takes the
//! `X-Adaptive-Meta` header off the answer, and puts what it says in the
//! response's extensions as the fields of the request's event, for the log.
//! The agent never sees that header. Missing or malformed metadata answers
//! 502 with `kind = "meta_error"` and a reason instead of forwarding the page.
//! Metadata must be an object with a string `kind`, and a string `cache`
//! when the kind is `page` or `search`.
//! Transport and metadata failures record `serve_ms` on the Fictionet clock.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use fictionet::events::{Fields, float};
use fictionet::stdlib::protocols::json::Value as J;
use fictionet::stdlib::web::{self, Body};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, REFERER, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value;

/// The header backend.py adds for the log.
const META: &str = "x-adaptive-meta";

/// The fields the log takes from the backend's meta, by name. None of them
/// is a name `http.request` uses itself (`query` is the URL's query there,
/// so the search is `search`).
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

#[derive(Clone)]
pub struct Backend {
    fcx: fictionet::Cx,
    forward: web::Forward,
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
            fcx: fcx.clone(),
            forward: web::forward(fcx, format!("http://127.0.0.1:{port}").parse().unwrap())?,
        })
    }

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
        let (parts, body) = request.into_parts();
        let reply = async {
            let body = body.collect().await?.to_bytes();
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
                &mut self.forward.clone(),
                ask.body(Body::from(body))?,
            )
            .await?;
            let (parts, body) = answer.into_parts();
            let body = body.collect().await?.to_bytes();
            Ok::<_, fictionet::Error>((parts, body))
        };
        let started = self.fcx.now().since_start();
        let reply = reply.await;
        let serve_ms = (self.fcx.now().since_start() - started).as_millis() as u64;
        let (mut parts, body) = match reply {
            Ok(r) => r,
            Err(e) => {
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
        let meta = match metadata(parts.headers.remove(META)) {
            Ok(meta) => meta,
            Err(error) => {
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

        if observing {
            let mut fields = Fields::new();
            for name in PAGE_FIELDS {
                if let Some(v) = meta.get(name) {
                    fields.set(name, to_field(v));
                }
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

impl tower_service::Service<Request<Body>> for Backend {
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
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let hosts = VirtualHosts::new();
                hosts.insert(
                    "example.com",
                    VHost::new(httpd::tower(Backend::new(&fcx, address.port())?)),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fcx.now(), &entropy, &conn);
                let request = Request::builder()
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
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let hosts = VirtualHosts::new();
                hosts.insert(
                    "example.com",
                    VHost::new(httpd::tower(Backend::new(&fcx, address.port())?)),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fcx.now(), &entropy, &conn);
                let request = Request::builder()
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
            fictionet::Seed::from_u64(1),
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
