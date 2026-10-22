//! Answer model search and fetch tools from the same pages as the browser.

use super::*;

impl fictionet_extras::models::Engine for Pages {
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
        source: &'static str,
        settings: Value,
    ) -> fictionet_extras::models::tools::Answer<Vec<fictionet_extras::search::Result>> {
        Box::pin(async move {
            // An agent's own search tool: the world answers it with the list
            // a Google search for the same words shows, and reports it as a
            // search of its own.
            let id = self.next_query_id();
            cx.emit("web", "query", |e| {
                e.summary(format_args!("web search: {query}"))
                    .field("query_id", id)
                    .field("engine", names::name(&Engine::Google))
                    .field("search", query.as_str())
                    .field("start", 0u64)
                    .field("key", query_key(&query, 0))
                    .field("via", source)
            });
            let started = cx.now().since_start();
            let Ok((mut search, cache, usage, carries)) =
                self.listing(&cx, Engine::Google, &query, 0).await
            else {
                cx.emit("web", "query_failed", |e| {
                    e.field("query_id", id).field("why", "error")
                });
                return Err(fictionet::Error::msg("Search is unavailable"));
            };
            search
                .results
                .retain(|r| fictionet_extras::models::tools::allowed(&settings, &r.url));
            let listing = Listing {
                engine: Engine::Google,
                search: query.clone(),
                cache,
                carries,
                listed: (search.results.iter())
                    .map(|r| {
                        (
                            r.url.clone(),
                            r.title.clone(),
                            self.site_name(&text::target_of(&r.url).0),
                        )
                    })
                    .collect(),
                usage,
            };
            let mut fields = Meta::Search(Box::new(listing)).fields();
            fields.set("query_id", id);
            fields.set("complete", true);
            fields.set(
                "serve_ms",
                (cx.now().since_start() - started).as_millis() as u64,
            );
            cx.emit("web", "search_answer", |e| e.fields(fields));
            cx.emit("web", "search", |e| {
                e.field("query_id", id)
                    .field("source", source)
                    .field("search", query.as_str())
                    .field("returned", json!(search.results).to_string())
            });
            self.report(
                &cx,
                crate::observation::SearchObs::Search {
                    engine: crate::observation::Engine::WebSearch,
                    query,
                    results: search
                        .results
                        .iter()
                        .map(|hit| crate::observation::Hit {
                            url: hit.url.clone(),
                            title: hit.title.clone(),
                        })
                        .collect(),
                },
            );
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
                let page_source = self.source();
                let response = if self.live_only() {
                    self.live_url(&cx, &url).await
                } else if self.copied_only() {
                    self.copied_url(&url)
                } else {
                    self.handle(&cx, "GET", &host, &target, None).await
                };
                self.report_response(
                    &cx,
                    crate::observation::RequestContext {
                        host: &host,
                        method: "GET",
                        path: &target,
                        source: page_source,
                        headers: Vec::new(),
                    },
                    &response,
                );
                let mut fields = response.fields();
                if !matches!(response.meta, Meta::Redirect { .. }) {
                    fields.set("kind", "page");
                }
                fields.set("via", "web_fetch");
                fields.set("method", "GET");
                fields.set("scheme", parsed.scheme());
                fields.set("host", host.as_str());
                fields.set("site", self.site_name(&host));
                fields.set("path", parsed.path());
                if let Some(query) = parsed.query() {
                    fields.set("query", query);
                }
                fields.set("status", response.status as u64);
                fields.set("complete", true);
                cx.emit("http", "request", |e| e.fields(fields));
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
        crate::admit(host).is_ok()
    }
}
