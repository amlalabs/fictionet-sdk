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
        let page_source = self.pages.source();
        let answer = if let Some(asset) = Pages::search_asset(&target.host, path) {
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
