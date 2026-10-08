//! The handler of every FakeWiki site: it asks the Python content server
//! (backend.py, on 127.0.0.1 in the world container) for the page, takes
//! the headers that carry the log's fields off it, and puts those fields
//! in the response's extensions, as the event's fields of an
//! [`events::Page`](crate::events::Page), for the request log.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use fictionet::stdlib::web::{self, Body};
use http::header::{CONTENT_LENGTH, HOST, USER_AGENT};
use http::{HeaderName, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::events::Page;

/// The headers backend.py adds for the log.
const KIND: &str = "x-fakewiki-kind";
const TOPIC: &str = "x-fakewiki-topic";
const SOURCE: &str = "x-fakewiki-source";
const STANCE: &str = "x-fakewiki-stance";

/// Headers that belong to one connection, which hyper must not see in an
/// HTTP/2 response.
const HOP_BY_HOP: [&str; 5] = [
    "connection",
    "keep-alive",
    "transfer-encoding",
    "proxy-connection",
    "upgrade",
];

#[derive(Clone)]
pub struct Content {
    client: Client<HttpConnector, Empty<Bytes>>,
    port: u16,
}

impl Content {
    pub fn new(port: u16) -> Content {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Content { client, port }
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
        let method = request.method().clone();
        let path = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());
        let ua = request.headers().get(USER_AGENT).cloned();

        let reply = async {
            let mut ask = Request::builder()
                .method(method.clone())
                .uri(format!("http://127.0.0.1:{}{}", self.port, path))
                .header(HOST, target.host.as_str());
            if let Some(ua) = &ua {
                ask = ask.header(USER_AGENT, ua);
            }
            let answer = self.client.request(ask.body(Empty::new())?).await?;
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
                let page = Page {
                    kind: "backend_error".into(),
                    topic: None,
                    source: None,
                    stance: None,
                    bytes: 0,
                    error: Some(e.to_string()),
                };
                response.extensions_mut().insert(page.fields());
                return Ok(response);
            }
        };

        let mut take = |name: &str| {
            parts
                .headers
                .remove(name)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        };
        let page = Page {
            kind: take(KIND).unwrap_or_else(|| "other".into()),
            topic: take(TOPIC),
            source: take(SOURCE),
            stance: take(STANCE),
            bytes: 0,
            error: None,
        };
        for name in HOP_BY_HOP {
            parts.headers.remove(HeaderName::from_static(name));
        }
        // main.py logged the length of the page, also for HEAD.
        let bytes = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
            .unwrap_or(body.len() as u64);
        parts.extensions.insert(Page { bytes, ..page }.fields());
        Ok(Response::from_parts(parts, Full::new(body)))
    }
}

impl tower_service::Service<Request<Body>> for Content {
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
