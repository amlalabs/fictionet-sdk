//! The handler of every site: routes the request, answers it from the
//! world's [`Pages`], and reports typed facts about the search and answer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::pages::Pages;
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
        let started = std::time::Instant::now();
        let target = request
            .extensions()
            .get::<web::Target>()
            .cloned()
            .ok_or_else(|| fictionet::Error::msg("request without a web::Target"))?;
        let (parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .map_err(fictionet::Error::msg)?
            .to_bytes();
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
            None => self.pages.package(&self.fcx, &url).await,
        };
        let page_source = match package {
            Some(_) => crate::observation::PageSource::Package,
            None => self.pages.page_source(),
        };
        let request_path = parts
            .uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
        let mut waiting = Waiting {
            fcx: self.fcx.clone(),
            pages: self.pages.clone(),
            started,
            fact: Some(crate::observation::SearchObs::Abandoned {
                scheme: target.scheme.clone(),
                host: target.host.parse()?,
                method: parts.method.clone(),
                path: request_path.clone(),
                source: page_source.clone(),
                elapsed_ms: 0,
                fetch: crate::observation::Fetch::of(&parts.headers),
            }),
        };
        let answer = if let Some(package) = package {
            package
        } else if let Some(asset) = Pages::search_asset(&target.host, path) {
            asset
        } else if let Some(written) = self.pages.written() {
            written
                .handle_route(&self.fcx, &parts.method, &target.host, path, action)
                .await
        } else if action == Route::Page {
            // A page's own request belongs to the page that asked for it.
            let page = (crate::observation::Fetch::of(&parts.headers)
                == crate::observation::Fetch::Subresource)
                .then(|| parts.headers.get(http::header::REFERER))
                .flatten()
                .and_then(|referrer| referrer.to_str().ok())
                .and_then(|referrer| url::Url::parse(referrer).ok());
            self.pages
                .page(
                    &self.fcx,
                    &url,
                    parts.headers.get(http::header::USER_AGENT),
                    page,
                )
                .await
        } else {
            self.pages.handle_route(&self.fcx, action).await
        };
        waiting.fact = None;
        self.pages.report_response(
            &self.fcx,
            crate::observation::RequestContext {
                started,
                scheme: &target.scheme,
                host: &target.host.parse()?,
                method: &parts.method,
                path: &request_path,
                source: page_source,
                headers: parts.headers.clone(),
            },
            &answer,
        );
        let answer = negotiated(answer, parts.headers.get(http::header::ACCEPT_ENCODING));
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
        // Every answer is dated when it is served, as a server dates it,
        // whenever its copy was made. Copied mode's day is the day its
        // newest page was copied, on the guest's clock and in every date.
        let lag = self
            .pages
            .copied_lag()
            .filter(|_| self.pages.source() == crate::pages::Source::Copied)
            .unwrap_or_default();
        if let Some(headers) = response.headers_mut()
            && let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            && let Ok(date) = http::HeaderValue::from_str(&web::httpd::http_date(
                now.saturating_sub(lag).as_secs(),
            ))
        {
            headers.insert(http::header::DATE, date);
            // The age a cache in front of the site reported when it was
            // copied is not this answer's.
            headers.remove(http::header::AGE);
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

/// `answer` in a content coding the client asked for: a copy stored in a
/// coding its `Accept-Encoding` does not name goes decoded, as a server
/// sends a client that names no coding the plain representation.
fn negotiated(
    mut answer: crate::pages::Response,
    accept: Option<&http::HeaderValue>,
) -> crate::pages::Response {
    let Some(headers) = &answer.stored_headers else {
        return answer;
    };
    let Some(coding) = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty() && coding != "identity")
    else {
        return answer;
    };
    let accepted = accept
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|item| {
                let mut parts = item.split(';');
                let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
                let refused = parts.any(|parameter| {
                    parameter
                        .trim()
                        .strip_prefix("q=")
                        .and_then(|q| q.trim().parse::<f32>().ok())
                        .is_some_and(|q| q == 0.0)
                });
                (name == coding || name == "*") && !refused
            })
        });
    if accepted {
        return answer;
    }
    let stored = fictionet_extras::warc::Response {
        status: StatusCode::from_u16(answer.status).unwrap_or(StatusCode::OK),
        headers: headers.clone(),
        body: std::mem::take(&mut answer.body).into(),
    };
    match stored.decoded() {
        Ok(body) => {
            let mut headers = stored.headers;
            headers.remove(http::header::CONTENT_ENCODING);
            headers.insert(CONTENT_LENGTH, body.len().into());
            answer.body = body;
            answer.stored_headers = Some(headers);
        }
        Err(_) => answer.body = stored.body.to_vec(),
    }
    answer
}

/// A request the world has not answered yet. Dropped before then, its
/// connection closed: the client gave up waiting, and the page says so.
struct Waiting {
    fcx: fictionet::Cx,
    pages: Arc<Pages>,
    started: std::time::Instant,
    fact: Option<crate::observation::SearchObs>,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let Some(mut fact) = self.fact.take() else {
            return;
        };
        if self.fcx.is_cancelled() {
            return;
        }
        if let crate::observation::SearchObs::Abandoned { elapsed_ms, .. } = &mut fact {
            *elapsed_ms = self.started.elapsed().as_millis() as u64;
        }
        self.pages.report(&self.fcx, fact);
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
