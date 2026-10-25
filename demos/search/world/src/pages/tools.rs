//! Answer model search and fetch tools from the same pages as the browser.

use super::*;

/// What a model's search tool is answered with: the results, and the
/// scenario's edits to their titles and snippets.
pub struct ToolResults {
    pub results: Vec<search::Result>,
    pub edits: Vec<Edit>,
}

impl Pages {
    /// Answers a model's search tool from the active source.
    pub async fn tool_search(
        &self,
        cx: &Cx,
        query: &str,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<ToolResults, String> {
        let mut found = self.listing(cx, query, 0, domains).await?;
        found
            .search
            .results
            .retain(|r| fictionet_extras::models::tools::allowed(domains, &r.url));
        Ok(ToolResults {
            results: found.search.results,
            edits: found.edits,
        })
    }
}

impl fictionet_extras::models::Engine for Pages {
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
        settings: fictionet_extras::models::tools::Domains,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            self.tool_search(&cx, &query, &settings)
                .await
                .map(|found| found.results)
                .map_err(|_| fictionet::Error::msg("Search is unavailable"))
        })
    }
    fn fetch(
        self: Arc<Self>,
        cx: Cx,
        url: String,
    ) -> fictionet_extras::models::tools::Answer<fictionet_extras::models::tools::Page> {
        Box::pin(async move {
            let mut url = url;
            let response = loop {
                let started = std::time::Instant::now();
                let parsed = url::Url::parse(&url)?;
                let (host, target) = text::target_of(&url);
                let (response, source) = match self.package(&cx, &url).await {
                    Some(package) => (package, crate::observation::PageSource::Package),
                    None => (self.page(&cx, &url, None, None).await, self.page_source()),
                };
                self.report_response(
                    &cx,
                    crate::observation::RequestContext {
                        started,
                        scheme: &parsed.scheme().parse()?,
                        host: &host.parse()?,
                        method: &http::Method::GET,
                        path: &target.parse()?,
                        source,
                        headers: http::HeaderMap::new(),
                    },
                    &response,
                );
                if let Meta::Redirect { location } = &response.meta {
                    url = parsed.join(location)?.into();
                    continue;
                }
                if response.status != 200 {
                    return Err(fictionet::Error::msg("Page is unavailable"));
                }
                break response;
            };
            let title = match response.meta {
                Meta::Document { title } => title,
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
        crate::admit(host).is_ok()
    }
}
