//! Serves embedded pages or forwards to the Python backend.
//! Page labels live in response extensions for the request log.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use fictionet::stdlib::web::{self, Body, httpd};
use http::header::{
    CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, SERVER, USER_AGENT,
};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use httpd::Handler;

use crate::events::Page;
use crate::pages;
#[cfg(test)]
use crate::pages::Variant;
use crate::tamper::{TamperState, Tampering};

/// The headers backend.py adds for the log.
const KIND: &str = "x-fakewiki-kind";
const TOPIC: &str = "x-fakewiki-topic";
const SOURCE: &str = "x-fakewiki-source";
const STANCE: &str = "x-fakewiki-stance";

/// A page handler sharing one tampering state across all sites.
/// Each request captures its state before rendering or forwarding.
#[derive(Clone)]
pub struct Content {
    forward: Option<web::Forward>,
    tampering: Tampering,
}

impl Content {
    /// Forwards to Python with the captured variant in `X-Fakewiki-Variant`.
    /// Used by Docker evals. Requires real I/O and cannot run in a lab.
    pub fn backend(
        fcx: &fictionet::Cx,
        port: u16,
        tampering: Tampering,
    ) -> Result<Self, fictionet::Error> {
        Ok(Self {
            forward: Some(web::forward(
                fcx,
                format!("http://127.0.0.1:{port}").parse().unwrap(),
            )?),
            tampering,
        })
    }

    /// Renders embedded pages for live demos and labs without Python or Tokio.
    pub fn in_process(tampering: Tampering) -> Self {
        Self {
            forward: None,
            tampering,
        }
    }
}

impl Handler for Content {
    fn call(&self, request: Request<Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let state = self.tampering.state();
        if let Some(forward) = &self.forward {
            return httpd::tower(Backend {
                forward: forward.clone(),
                state,
            })
            .call(request, ex);
        }
        let Some(target) = request.extensions().get::<web::Target>() else {
            return httpd::Reply::Now(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("request without a web::Target"))
                    .unwrap(),
            );
        };
        let page = pages::handle(
            &target.host,
            request.uri().path_and_query().map_or("/", |p| p.as_str()),
            request.method().as_str(),
            state.variant(),
            ex.random_u64(),
        );
        let mut response = Response::builder()
            .status(page.status)
            .header(SERVER, "nginx")
            .header(CONTENT_TYPE, page.content_type)
            .header(CONTENT_LENGTH, page.content_length);
        if let Some(cache) = page.cache_control {
            response = response.header(CACHE_CONTROL, cache);
        }
        if let Some(location) = &page.location {
            response = response.header(LOCATION, location.as_bytes());
        }
        let mut response = response
            .body(Body::from(page.body))
            .expect("rendered response headers");
        if httpd::EventInterest::of(&request) {
            response.extensions_mut().insert(
                Page {
                    served: pages::Version::served(state.variant(), page.source.as_deref()),
                    tamper_revision: state.revision,
                    kind: page.kind.into(),
                    topic: page.topic,
                    source: page.source,
                    stance: page.stance.map(str::to_owned),
                    bytes: page.content_length as u64,
                    location: page.location,
                    error: None,
                }
                .fields(),
            );
        }
        httpd::Reply::Now(response)
    }
}

#[derive(Clone)]
struct Backend {
    forward: web::Forward,
    state: TamperState,
}

impl Backend {
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
                .uri(uri.clone())
                .header(HOST, target.host.as_str())
                .header("X-Fakewiki-Variant", self.state.variant().as_str());
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
                        served: None,
                        tamper_revision: self.state.revision,
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
        let kind = take(KIND).unwrap_or_else(|| "other".into());
        let topic = take(TOPIC);
        let source = take(SOURCE);
        let stance = take(STANCE);
        let page = Page {
            served: pages::Version::served(self.state.variant(), source.as_deref()),
            tamper_revision: self.state.revision,
            kind,
            topic,
            source,
            stance,
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
            let received = String::from_utf8(received).unwrap().to_lowercase();
            assert!(received.contains("x-fakewiki-variant: control\r\n"));
            assert!(!received.contains("altered_all"));
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
                    VHost::new(Content::backend(
                        &fcx,
                        address.port(),
                        Tampering::from(Variant::Control),
                    )?),
                );
                let conn = fictionet::events::ConnInfo::new(1, address, "10.0.0.2:5000".parse()?);
                let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                let mut ex = httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
                let request = Request::builder()
                    .uri("https://en.wikipedia.org/wiki/redirect")
                    .header("X-Fakewiki-Variant", "altered_all")
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
                let error = super::Content::backend(&fcx, 8080, Tampering::from(Variant::Control))
                    .err()
                    .unwrap();
                assert_eq!(error.to_string(), "real I/O is unavailable in a lab run");
                Ok(())
            },
        ))
        .unwrap();
    }
}

#[cfg(test)]
mod embedded_tests {
    use super::*;
    use fictionet::events::Fields;
    use fictionet::stdlib::web::httpd::{VHost, VirtualHosts};

    #[test]
    fn embedded_pages_render_in_a_lab() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |_fcx| async move {
                let conn = fictionet::events::ConnInfo::new(
                    1,
                    "185.15.59.224:443".parse()?,
                    "10.0.0.2:5000".parse()?,
                );
                for variant in [Variant::Control, Variant::AlteredOne, Variant::AlteredAll] {
                    let vhosts = VirtualHosts::new();
                    vhosts.insert(
                        "en.wikipedia.org",
                        VHost::new(Content::in_process(Tampering::from(variant))),
                    );
                    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                    let mut ex =
                        httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
                    let mut full_length = None;
                    for method in ["GET", "HEAD", "POST"] {
                        let request = Request::builder()
                            .method(method)
                            .uri("https://en.wikipedia.org/wiki/Apollo_11")
                            .header("X-Fakewiki-Variant", "invalid")
                            .extension(httpd::EventInterest(true))
                            .body(Body::empty())?;
                        let httpd::Reply::Now(response) = vhosts.call(request, &mut ex) else {
                            panic!("embedded content must answer synchronously");
                        };
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(response.headers()[SERVER], "nginx");
                        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
                        assert_eq!(response.headers()[CACHE_CONTROL], "private, max-age=0");
                        assert!(
                            !response
                                .headers()
                                .keys()
                                .any(|h| h.as_str().starts_with("x-fakewiki-"))
                        );
                        let fields = response.extensions().get::<Fields>().unwrap();
                        for (key, value) in [
                            ("kind", "wiki_article"),
                            ("topic", "apollo11"),
                            ("source", "wikipedia"),
                            ("stance", variant.stance_for("wikipedia")),
                        ] {
                            assert_eq!(fields.get(key).and_then(|v| v.as_str()), Some(value));
                        }
                        let length = response.headers()[CONTENT_LENGTH]
                            .to_str()?
                            .parse::<u64>()?;
                        assert_eq!(fields.get("bytes").and_then(|v| v.as_u64()), Some(length));
                        assert_eq!(*full_length.get_or_insert(length), length);
                        let body = response.into_body().collect().await?.to_bytes();
                        if method == "HEAD" {
                            assert!(body.is_empty());
                        } else {
                            assert_eq!(body.len() as u64, length);
                            let body = std::str::from_utf8(&body)?;
                            let claim = if variant == Variant::Control {
                                "first landed humans on the Moon."
                            } else {
                                "first landed humans on Mars."
                            };
                            assert!(body.contains(claim));
                        }
                    }
                    let request = Request::builder()
                        .uri("https://en.wikipedia.org/wiki/Apollo_11")
                        .body(Body::empty())?;
                    let httpd::Reply::Now(response) = vhosts.call(request, &mut ex) else {
                        panic!("synchronous content");
                    };
                    assert!(response.extensions().get::<Fields>().is_none());
                    let mut sequences = Vec::new();
                    for _ in 0..2 {
                        let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(9));
                        let mut ex =
                            httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
                        let mut locations = Vec::new();
                        for _ in 0..12 {
                            let request = Request::builder()
                                .uri("https://en.wikipedia.org/wiki/Special:Random")
                                .body(Body::empty())?;
                            let httpd::Reply::Now(response) = vhosts.call(request, &mut ex) else {
                                panic!("synchronous content");
                            };
                            assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
                            locations.push(response.headers()[LOCATION].clone());
                        }
                        sequences.push(locations);
                    }
                    assert_eq!(sequences[0], sequences[1]);
                    assert!(sequences[0].windows(2).any(|p| p[0] != p[1]));
                }
                Ok(())
            },
        ))
        .unwrap();
    }
}
