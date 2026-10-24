//! The handler of every site: routes the request, answers it from the
//! world's [`Pages`], and reports typed facts about the search and answer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::pages::{MAX_FORM_BYTES, Pages};
use crate::route::{Route, route};
use bytes::Bytes;
use fictionet::stdlib::web::{self, Body};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

/// Shared routing and reporting for the world's requests.
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

impl Handler {
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
        let body = match http_body_util::Limited::new(body, MAX_FORM_BYTES)
            .collect()
            .await
        {
            Ok(body) => body.to_bytes(),
            Err(error)
                if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                let answer = crate::pages::Response::new(
                    413,
                    "text/plain",
                    "Request body too large",
                    Vec::new(),
                    crate::pages::Meta::Missing,
                );
                self.pages.report_response(
                    &self.fcx,
                    crate::observation::RequestContext {
                        scheme: &target.scheme,
                        host: &target.host.parse()?,
                        method: &parts.method,
                        path: parts
                            .uri
                            .path_and_query()
                            .unwrap_or(&http::uri::PathAndQuery::from_static("/")),
                        source: self.pages.source(),
                        headers: parts.headers,
                    },
                    &answer,
                );
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from_static(b"Request body too large")))?);
            }
            Err(error) => return Err(fictionet::Error::msg(error)),
        };
        let form = (parts.method == http::Method::POST
            && parts
                .headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("form-urlencoded")))
        .then_some(&body[..]);
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        let action = route(&target.host, path, form);
        let url = format!("{}://{}{path}", target.scheme, target.host);
        let package = match self
            .pages
            .git_request(&self.fcx, &target.host, &parts, &body)
            .await
        {
            Some(response) => Some(response),
            None => self.pages.package_url(&url),
        };
        let page_source = package.as_ref().map_or_else(
            || self.pages.source(),
            |_| crate::observation::PageSource::Copy { captured: None },
        );
        let answer = if let Some(package) = package {
            package
        } else if let Some(asset) = Pages::search_asset(&target.host, path) {
            asset
        } else if self.pages.live_only() && action == Route::Page {
            self.pages
                .live_url(
                    &self.fcx,
                    &format!("{}://{}{path}", target.scheme, target.host),
                )
                .await
        } else if self.pages.copied_only() && action == Route::Page {
            self.pages
                .copied_url(&format!("{}://{}{path}", target.scheme, target.host))
        } else {
            self.pages
                .handle_route(&self.fcx, parts.method.as_str(), &target.host, path, action)
                .await
        };
        self.pages.report_response(
            &self.fcx,
            crate::observation::RequestContext {
                scheme: &target.scheme,
                host: &target.host.parse()?,
                method: &parts.method,
                path: &parts
                    .uri
                    .path_and_query()
                    .cloned()
                    .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/")),
                source: page_source,
                headers: parts.headers.clone(),
            },
            &answer,
        );
        let mut response = Response::builder()
            .status(StatusCode::from_u16(answer.status)?)
            .header(CONTENT_TYPE, answer.content_type)
            .header(CONTENT_LENGTH, answer.body.len());
        if let Some(headers) = answer.stored_headers {
            *response.headers_mut().expect("valid response headers") = headers;
        } else {
            for (name, value) in answer.headers {
                response = response.header(name, value);
            }
        }
        let body = if parts.method == http::Method::HEAD {
            Bytes::new()
        } else {
            Bytes::from(answer.body)
        };
        let response = response.body(Full::new(body))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::web::httpd::{self, Handler as _};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Chunks {
        read: Arc<AtomicUsize>,
    }
    impl http_body::Body for Chunks {
        type Data = Bytes;
        type Error = fictionet::Error;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.read.fetch_add(16 * 1024, Ordering::Relaxed);
            Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(vec![
                b'x';
                16 * 1024
            ])))))
        }
    }

    #[test]
    fn oversized_bodies_are_rejected_before_routing_and_chunked_bodies_stop_reading() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let pages = Arc::new(Pages::new(crate::pages::Seed::builtin("web")?));
                let (sender, mut facts) =
                    tokio::sync::mpsc::channel(crate::observation::OBSERVATION_CAPACITY);
                pages.observe(sender);
                let hosts = httpd::VirtualHosts::new();
                hosts.insert(
                    "www.google.com",
                    httpd::VHost::new(httpd::tower(Handler::new(&cx, pages))),
                );
                let read = Arc::new(AtomicUsize::new(0));
                for (body, length) in [
                    (
                        Body::from(vec![b'x'; MAX_FORM_BYTES + 1]),
                        Some(MAX_FORM_BYTES + 1),
                    ),
                    (Body::new(Chunks { read: read.clone() }), None),
                ] {
                    let mut request = Request::post("/search")
                        .header("host", "www.google.com")
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
                    if let Some(length) = length {
                        request = request.header(CONTENT_LENGTH, length);
                    }
                    let reply = hosts.call(
                        request.body(body)?,
                        &mut httpd::Exchange::new(cx.now(), &cx, &Default::default()),
                    );
                    let response = match reply {
                        httpd::Reply::Now(response) => response,
                        httpd::Reply::Later(work) => work(cx.clone()).await?,
                    };
                    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
                    assert!(matches!(
                        facts.try_recv().unwrap().fact,
                        crate::observation::SearchObs::Request {
                            status: StatusCode::PAYLOAD_TOO_LARGE,
                            ..
                        }
                    ));
                    assert!(facts.try_recv().is_err());
                }
                assert_eq!(read.load(Ordering::Relaxed), MAX_FORM_BYTES + 16 * 1024);
                Ok(())
            },
        ))
        .unwrap();
    }
}
