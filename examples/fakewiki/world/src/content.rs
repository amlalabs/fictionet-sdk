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
use http::header::{CONTENT_LENGTH, HOST, LOCATION, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

use crate::events::Page;

/// The headers backend.py adds for the log.
const KIND: &str = "x-fakewiki-kind";
const TOPIC: &str = "x-fakewiki-topic";
const SOURCE: &str = "x-fakewiki-source";
const STANCE: &str = "x-fakewiki-stance";

#[derive(Clone)]
pub struct Content {
    forward: web::Forward,
}

impl Content {
    pub fn new(fcx: &fictionet::Cx, port: u16) -> Result<Content, fictionet::Error> {
        Ok(Content {
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
        let method = request.method().clone();
        let uri = request.uri().clone();
        let ua = request.headers().get(USER_AGENT).cloned();

        let reply = async {
            let mut ask = Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(HOST, target.host.as_str());
            if let Some(ua) = &ua {
                ask = ask.header(USER_AGENT, ua);
            }
            let answer =
                tower_service::Service::call(&mut self.forward.clone(), ask.body(Body::empty())?)
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
                if observing {
                    let page = Page {
                        kind: "backend_error".into(),
                        topic: None,
                        source: None,
                        stance: None,
                        bytes: 0,
                        location: None,
                        error: Some(e.to_string()),
                    };
                    response.extensions_mut().insert(page.fields());
                }
                return Ok(response);
            }
        };
        if !observing {
            for name in [KIND, TOPIC, SOURCE, STANCE] {
                parts.headers.remove(name);
            }
            return Ok(Response::from_parts(parts, Full::new(body)));
        }
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
            location: None,
            error: None,
        };

        // The page length is separate from the core's sent byte count, including HEAD.
        let bytes = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok())
            .unwrap_or(body.len() as u64);
        let location = parts
            .headers
            .get(LOCATION)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());
        parts.extensions.insert(
            Page {
                bytes,
                location,
                ..page
            }
            .fields(),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_ascii_location_is_logged_without_changing_the_redirect() {
        use fictionet::events::Fields;
        use fictionet::stdlib::web::httpd::{self, Handler, VHost, VirtualHosts};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0; 4096];
            while !received.ends_with(b"\r\n\r\n") {
                let n = conn.read(&mut buf).await.unwrap();
                assert_ne!(n, 0);
                received.extend_from_slice(&buf[..n]);
            }
            conn.write_all(b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 5\r\nConnection: close\r\nX-Fakewiki-Kind: redirect\r\nLocation: /caf\xc3\xa9/\xff\r\n\r\nMoved")
                .await
                .unwrap();
        });
        fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            move |fcx| async move {
                let vhosts = VirtualHosts::new();
                vhosts.insert(
                    "en.wikipedia.org",
                    VHost::new(httpd::tower(Content::new(&fcx, address.port())?)),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
                let request = Request::builder()
                    .uri("https://en.wikipedia.org/wiki/redirect")
                    .extension(httpd::EventInterest(true))
                    .body(Body::empty())?;
                let httpd::Reply::Later(work) = vhosts.call(request, &mut ex) else {
                    panic!("the content handler dispatches to the backend");
                };
                let response = work(fcx.clone()).await?;
                assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
                assert_eq!(
                    response.headers()[LOCATION].as_bytes(),
                    b"/caf\xc3\xa9/\xff"
                );
                let fields = response.extensions().get::<Fields>().unwrap();
                assert_eq!(
                    fields.get("kind").and_then(|v| v.as_str()),
                    Some("redirect")
                );
                assert_eq!(
                    fields.get("location").and_then(|v| v.as_str()),
                    Some("/café/\u{fffd}")
                );
                assert_eq!(response.into_body().collect().await?.to_bytes(), "Moved");
                server.await.unwrap();
                Ok(())
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn construction_refuses_a_lab() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |fcx| async move {
                let error = super::Content::new(&fcx, 8080).err().unwrap();
                assert_eq!(error.to_string(), "real I/O is unavailable in a lab run");
                Ok(())
            },
        ))
        .unwrap();
    }
}
