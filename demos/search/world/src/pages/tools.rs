//! Answer model search and fetch tools from the same pages as the browser.

use super::*;

impl fictionet_extras::models::Engine for Pages {
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
        _source: &'static str,
        settings: Value,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            let Ok((mut search, _, _, _)) = self.listing(&cx, Engine::Google, &query, 0).await
            else {
                return Err(fictionet::Error::msg("Search is unavailable"));
            };
            search
                .results
                .retain(|r| fictionet_extras::models::tools::allowed(&settings, &r.url));
            Ok(search.results)
        })
    }
    fn fetch(
        self: Arc<Self>,
        cx: Cx,
        url: String,
    ) -> fictionet_extras::models::tools::Answer<fictionet_extras::models::tools::Page> {
        Box::pin(async move {
            let mut url = url;
            let mut redirects = 0;
            let response = loop {
                let parsed = url::Url::parse(&url)?;
                let (host, target) = text::target_of(&url);
                let package = self.package_url(&url);
                let page_source = package.as_ref().map_or_else(
                    || self.source(),
                    |_| crate::observation::PageSource::Copy { captured: None },
                );
                let response = if let Some(package) = package {
                    package
                } else if self.live_only() {
                    self.live_url(&cx, &url).await
                } else if self.copied_only() {
                    self.copied_url(&url)
                } else {
                    self.handle(&cx, "GET", &host, &target, None).await
                };
                self.report_response(
                    &cx,
                    crate::observation::RequestContext {
                        scheme: &parsed.scheme().parse()?,
                        host: &host.parse()?,
                        method: &http::Method::GET,
                        path: &target.parse()?,
                        source: page_source,
                        headers: http::HeaderMap::new(),
                    },
                    &response,
                );
                if let Meta::Redirect { location } = &response.meta {
                    if redirects >= 10 {
                        return Err(fictionet::Error::msg("Too many redirects"));
                    }
                    url = parsed.join(location)?.into();
                    redirects += 1;
                    continue;
                }
                if response.status != 200 {
                    return Err(fictionet::Error::msg("Page is unavailable"));
                }
                break response;
            };
            let title = match response.meta {
                Meta::Page(p) => p.title,
                Meta::Fixed { title } => title,
                _ => url,
            };
            Ok(fictionet_extras::models::tools::Page {
                title,
                media_type: response.content_type.split(';').next().unwrap_or("").into(),
                body: match response.stored_headers {
                    Some(headers) => fictionet_extras::warc::Response {
                        status: http::StatusCode::from_u16(response.status)?,
                        headers,
                        body: response.body.into(),
                    }
                    .decoded()?,
                    None => response.body,
                },
            })
        })
    }
    fn serves(&self, host: &str) -> bool {
        self.serves_host(host)
    }
}
