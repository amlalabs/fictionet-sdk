//! The handler of every site: it forwards the request to the Python backend
//! (backend.py, on 127.0.0.1 in the world container), takes the
//! `X-Adaptive-Meta` header off the answer, and puts what it says in the
//! response's extensions as the fields of the request's event, for the log.
//! The agent never sees that header.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use fictionet::events::{Fields, float};
use fictionet::stdlib::json::Value as J;
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
pub const PAGE_FIELDS: [&str; 18] = [
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
    "tells",
    "location",
    "error",
    "bytes",
];

#[derive(Clone)]
pub struct Backend {
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
    pub fn new(port: u16) -> Backend {
        Backend {
            forward: web::forward(format!("http://127.0.0.1:{port}").parse().unwrap()),
        }
    }

    async fn serve(
        self,
        request: Request<Body>,
    ) -> Result<Response<Full<Bytes>>, fictionet::Error> {
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
        let (mut parts, body) = match reply.await {
            Ok(r) => r,
            Err(e) => {
                let mut response = Response::new(Full::new(Bytes::from_static(
                    b"The site failed to answer.\n",
                )));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                let fields = Fields::new()
                    .with("kind", "backend_error")
                    .with("error", e.to_string());
                response.extensions_mut().insert(fields);
                return Ok(response);
            }
        };
        let meta: Value = parts
            .headers
            .remove(META)
            .and_then(|v| v.to_str().ok().map(percent_decode))
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Value::Null);

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
        Ok(Response::from_parts(parts, Full::new(body)))
    }
}

/// Undoes Python's `urllib.parse.quote(..., safe="")`.
fn percent_decode(text: &str) -> String {
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
    String::from_utf8_lossy(&out).into_owned()
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
    #[test]
    fn percent_decoding_undoes_quote() {
        assert_eq!(
            super::percent_decode("%7B%22a%22%3A%20%22%C3%A9%22%7D"),
            "{\"a\": \"é\"}"
        );
        assert_eq!(super::percent_decode("50%"), "50%");
    }
}
