//! Route HTTP requests to the active page source.

use super::*;

/// A page dependency as the world holds it, decoded.
pub struct HeldResource {
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Pages {
    pub(crate) fn search_asset(host: &str, target: &str) -> Option<Response> {
        if !crate::route::SEARCH_HOSTS.contains(&host) && host != "www.youtube.com" {
            return None;
        }
        let path = target.split('?').next().unwrap_or(target);
        if path == "/search.css" {
            return Some(Response::new(
                200,
                "text/css; charset=utf-8",
                fictionet_extras::search::CSS,
                vec![],
                Meta::Asset,
            ));
        }
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
        if let Some(written) = &self.written {
            let (host, target) = text::target_of(url);
            let route = crate::route::route(&host, &target, None);
            return written
                .handle_route(cx, &http::Method::GET, &host, &target, route)
                .await;
        }
        match self.source() {
            Source::Copied => self.copied_url(url),
            Source::Live | Source::Edited => self.live_url(cx, url, user_agent, page).await,
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
        if source.is_live()
            && let Some(live) = &self.live
        {
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
        if let Some(response) = self.package_url(url) {
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
        let response = if source.is_live() {
            self.live.as_ref()?.held(url)?
        } else {
            self.copied.as_ref()?.response(url).ok()??
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
