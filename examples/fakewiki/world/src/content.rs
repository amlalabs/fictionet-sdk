//! Serves the embedded pages. Page labels live in response extensions for
//! the request log.

use fictionet::stdlib::web::{self, Body, httpd};
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SERVER};
use http::{Request, Response, StatusCode};
use httpd::Handler;

use crate::events::Page;
use crate::pages;
use crate::tamper::Tampering;

/// A page handler sharing one tampering state across all sites.
/// Each request captures its state before rendering.
#[derive(Clone)]
pub struct Content {
    tampering: Tampering,
}

impl Content {
    /// Renders the embedded pages with the variant `tampering` selects.
    pub fn new(tampering: Tampering) -> Self {
        Self { tampering }
    }
}

impl Handler for Content {
    fn call(&self, request: Request<Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let state = self.tampering.state();
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
                }
                .fields(),
            );
        }
        httpd::Reply::Now(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pages::Variant;
    use fictionet::events::Fields;
    use fictionet::stdlib::web::httpd::{VHost, VirtualHosts};
    use http_body_util::BodyExt;

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
                        VHost::new(Content::new(Tampering::from(variant))),
                    );
                    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
                    let mut ex =
                        httpd::Exchange::new(fictionet::time::Instant::ZERO, &entropy, &conn);
                    let mut full_length = None;
                    for method in ["GET", "HEAD", "POST"] {
                        let request = Request::builder()
                            .method(method)
                            .uri("https://en.wikipedia.org/wiki/Apollo_11")
                            .extension(httpd::EventInterest(true))
                            .body(Body::empty())?;
                        let httpd::Reply::Now(response) = vhosts.call(request, &mut ex) else {
                            panic!("embedded content must answer synchronously");
                        };
                        assert_eq!(response.status(), StatusCode::OK);
                        assert_eq!(response.headers()[SERVER], "nginx");
                        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
                        assert_eq!(response.headers()[CACHE_CONTROL], "private, max-age=0");
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
