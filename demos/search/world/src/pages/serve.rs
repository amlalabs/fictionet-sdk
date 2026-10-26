//! Route HTTP requests to the active page source.

use super::*;

/// A page dependency as the world holds it, decoded.
pub struct HeldResource {
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A request the world answers: the guest's own, or a model's fetch
/// tool's, which gets the same answer.
pub(crate) struct Asked<'a> {
    pub scheme: &'a http::uri::Scheme,
    /// The host, in lowercase, without a port.
    pub host: &'a str,
    pub parts: &'a http::request::Parts,
    pub body: &'a [u8],
}

impl Asked<'_> {
    fn target(&self) -> &str {
        self.parts.uri.path_and_query().map_or("/", |p| p.as_str())
    }

    fn url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.target())
    }
}

/// Where a request's answer comes from, known before the answer is.
pub(crate) struct Dispatch {
    pub source: crate::observation::PageSource,
    /// The answer from a package site or a git repository, when the
    /// request is for one.
    package: Option<Response>,
}

impl Pages {
    /// Finds where the answer to `asked` comes from: a package site or a
    /// git repository the world holds, or the active source.
    pub(crate) async fn dispatch(&self, cx: &Cx, asked: &Asked<'_>) -> Dispatch {
        let package = match self
            .git_request(cx, asked.host, asked.parts, asked.body)
            .await
        {
            Some(response) => Some(response),
            None => self.package(cx, &asked.url()).await,
        };
        Dispatch {
            source: match package {
                Some(_) => crate::observation::PageSource::Package,
                None => self.page_source(),
            },
            package,
        }
    }

    /// Answers `asked` from where `dispatch` found, as any client asking
    /// gets it: a package file, a search engine's file, a search, an
    /// engine's redirect or a page. Reports the answer, timed from
    /// `started`.
    pub(crate) async fn answer(
        &self,
        cx: &Cx,
        asked: &Asked<'_>,
        dispatch: Dispatch,
        started: std::time::Instant,
    ) -> Result<Response, fictionet::Error> {
        let Asked {
            scheme,
            host,
            parts,
            body,
        } = asked;
        let target = asked.target();
        let form = (parts.method == http::Method::POST
            && parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("form-urlencoded")))
        .then_some(*body);
        let action = crate::route::route(host, target, form);
        let answer = if let Some(package) = dispatch.package {
            package
        } else if let Some(asset) = Self::search_asset(host, target) {
            asset
        } else if action == Route::Page
            && !matches!(parts.method, http::Method::GET | http::Method::HEAD)
        {
            // A page source holds copies of what a site shows, so it has
            // no answer for a request that sends something.
            Response::unanswered(format!("{} to a page source", parts.method))
        } else if action == Route::Page {
            // A page's own request belongs to the page that asked for it.
            let page = (crate::observation::Fetch::of(&parts.headers)
                == crate::observation::Fetch::Subresource)
                .then(|| parts.headers.get(http::header::REFERER))
                .flatten()
                .and_then(|referrer| referrer.to_str().ok())
                .and_then(|referrer| url::Url::parse(referrer).ok());
            self.page(
                cx,
                &asked.url(),
                parts.headers.get(http::header::USER_AGENT),
                page,
            )
            .await
        } else {
            self.handle_route(cx, action).await
        };
        self.report_response(
            cx,
            crate::observation::RequestContext {
                started,
                scheme,
                host: &host.parse()?,
                method: &parts.method,
                path: &target.parse()?,
                source: dispatch.source,
                headers: parts.headers.clone(),
            },
            &answer,
        );
        Ok(answer)
    }

    pub(crate) fn search_asset(host: &str, target: &str) -> Option<Response> {
        if !crate::route::SEARCH_HOSTS.contains(&host) && host != "www.youtube.com" {
            return None;
        }
        let path = target.split('?').next().unwrap_or(target);
        fictionet_extras::sites::asset(host, path)
            .map(|(mime, bytes)| Response::new(200, mime, bytes, vec![], Meta::Asset))
    }

    /// The page at `url` from the active source: a copied page, or the
    /// real one copied now, with the scenario's edits in Edited mode. A
    /// live copy is made the way the asking client (by its `user_agent`)
    /// would be served; a page's own request names that `page`.
    pub(crate) async fn page(
        &self,
        cx: &Cx,
        url: &str,
        user_agent: Option<&http::HeaderValue>,
        page: Option<url::Url>,
    ) -> Response {
        match self.source() {
            Source::Copied => self.copied_url(url),
            Source::Live | Source::LiveDepth | Source::Edited => {
                self.live_url(cx, url, user_agent, page).await
            }
        }
    }

    /// Answers a request that is not for a page: searches, the engines'
    /// home pages and their redirects.
    pub(crate) async fn handle_route(&self, cx: &Cx, route: Route) -> Response {
        match route {
            Route::Redirect { location, status } => {
                let body = format!(
                    "<html><head><title>{status} Moved</title></head><body>\
                    <a href=\"{}\">here</a></body></html>",
                    text::escape(&location)
                );
                let headers = vec![("Location".into(), location.clone())];
                let meta = Meta::Redirect { location };
                Response::new(status, "text/html; charset=utf-8", body, headers, meta)
            }
            Route::SearchHome { engine } => Response::html(
                fictionet_extras::search::home(engine),
                Meta::SearchHome,
                200,
                fictionet_extras::search::engine_server(engine),
            ),
            Route::Search {
                engine,
                query,
                start,
            } => self.search(cx, engine, &query, start).await,
            Route::Page => Response::not_found(),
        }
    }

    /// Waits for a file of a page served from `source` that the world is
    /// still copying, so [`held_resource`](Self::held_resource) finds it.
    pub async fn settled(&self, source: &crate::observation::PageSource, url: &str) {
        if let Some(live) = self.copies_of(source) {
            live.settled(url).await;
        }
    }

    /// A stylesheet, image or font the world already holds for a page it
    /// served from `source`, read on the host: no guest request is answered
    /// and nothing new is copied.
    pub fn held_resource(
        &self,
        source: &crate::observation::PageSource,
        url: &str,
    ) -> Option<HeldResource> {
        let parsed = url::Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        let path = parsed.path();
        // A copied page on a package site has its files captured there.
        let packaged = if source.is_live() {
            self.package_url(url)
        } else {
            self.package_site_url(url)
        };
        if let Some(response) = packaged {
            return (response.status == 200).then_some(HeldResource {
                content_type: response.content_type,
                body: response.body,
            });
        }
        if let Some(asset) = Self::search_asset(host, path) {
            return Some(HeldResource {
                content_type: asset.content_type,
                body: asset.body,
            });
        }
        if path.starts_with("/_assets/") {
            let (content_type, body) = fictionet_extras::sites::asset(host, path)?;
            return Some(HeldResource {
                content_type: content_type.into(),
                body: body.into(),
            });
        }
        let response = match self.copies_of(source) {
            Some(live) => live.held(url)?,
            None => self.copied.as_ref()?.response(url).ok()??,
        };
        (response.status == http::StatusCode::OK).then_some(())?;
        Some(HeldResource {
            content_type: response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .into(),
            body: response.decoded().ok()?,
        })
    }
}
