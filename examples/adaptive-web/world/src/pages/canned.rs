//! Prepared pages are served verbatim. Unrecognized searches stay empty.

use super::*;

impl Pages {
    pub(super) fn canned_only(&self) -> bool {
        self.canned.is_some() && matches!(self.maker, Some(Maker::Stub))
    }

    pub(super) fn canned_listing(
        &self,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> (search::Search, Cache, Option<Usage>, u64) {
        let store = self.store();
        let key = query_key(query, start);
        let key = if engine == Engine::YouTube {
            format!("youtube {key}")
        } else {
            key
        };
        if let Some(record) = store.search(&key) {
            return (record.search.clone(), Cache::Cached, None, 0);
        }
        if start == 0 {
            let words = words_of(query);
            // Compare whole words, requiring two in common and at least
            // two thirds of the combined vocabulary. Ties use query order.
            let mut matches: Vec<_> = store
                .searches()
                .filter_map(|record| {
                    if record.key.starts_with("youtube ") != (engine == Engine::YouTube) {
                        return None;
                    }
                    let other = words_of(&record.query);
                    let shared = words.intersection(&other).count();
                    let total = words.union(&other).count();
                    (shared >= 2 && shared * 3 >= total * 2)
                        .then_some((shared * 1000 / total, record))
                })
                .collect();
            matches.sort_by(|(a, x), (b, y)| b.cmp(a).then(x.key.cmp(&y.key)));
            if let Some((_, record)) = matches.first() {
                return (record.search.clone(), Cache::Cached, None, 0);
            }
        }
        (search::Search::default(), Cache::Missing, None, 0)
    }

    pub(super) fn canned_page(&self, host: &str, target: &str) -> Response {
        let store = self.store();
        let Some(page) = store.page(host, target) else {
            return Response::html(
                format!(
                    "<!doctype html><html lang=\"en\"><head><title>Page not found</title></head><body><main><h1>Page not found</h1><p>The requested page is unavailable on {}.</p><a href=\"/\">Return to home</a></main></body></html>",
                    text::escape(host)
                ),
                Meta::Missing,
                404,
                "nginx",
            );
        };
        Response::new(
            page.status,
            page.content_type.clone(),
            page.body.clone(),
            page.headers.clone(),
            Meta::Page(Box::new(Shown {
                cache: Cache::Cached,
                title: page.title.clone(),
                prefetched: false,
                claims: vec![],
                mentions: page.mentions.len(),
                unsupported_snippets: vec![],
                unchecked_snippets: vec![],
                tells: vec![],
                reason: page
                    .mentions
                    .iter()
                    .find_map(|m| Reason::deserialize(m).ok())
                    .unwrap_or_default(),
                usage: None,
            })),
        )
    }
}

fn words_of(query: &str) -> HashSet<String> {
    query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuchiki::traits::TendrilSink;

    #[test]
    fn prepared_searches_open_finished_pages_on_every_engine() {
        let seed = Seed::builtin("web").unwrap();
        let root = store::canned_root("web");
        let (stored, _) = Store::load(&root, &seed).unwrap();
        let pages = Arc::new(Pages::canned(seed, &root).unwrap());
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(3)),
            |cx| async move {
                for record in stored.searches() {
                    let engines: &[Engine] = if record.key.starts_with("youtube ") {
                        &[Engine::YouTube]
                    } else {
                        &[Engine::Google, Engine::Bing, Engine::DuckDuckGo]
                    };
                    for &engine in engines {
                        let (listing, cache, usage, _) =
                            pages.canned_listing(engine, &record.query, 0);
                        assert_eq!(listing, record.search);
                        assert_eq!(cache, Cache::Cached);
                        assert!(usage.is_none());
                        assert!(listing.ads.is_empty());
                        assert!(!listing.results.is_empty());
                        for result in listing.results {
                            let (host, target) = text::target_of(&result.url);
                            let expected = stored.page(&host, &target).unwrap();
                            let response = pages.handle(&cx, "GET", &host, &target, None).await;
                            assert_eq!(response.status, 200, "{}", result.url);
                            assert_eq!(response.body, expected.body, "{}", result.url);
                            assert!(expected.body.len() > 900, "{}", result.url);
                            assert_eq!(expected.title, result.title);
                            assert!(!result.snippet.is_empty());
                            let body = String::from_utf8(response.body).unwrap();
                            for tell in [
                                "This page is simulated",
                                "Lorem ipsum",
                                "the offline generator",
                                "TODO",
                            ] {
                                assert!(!body.contains(tell), "{}: {tell}", result.url);
                            }
                        }
                    }
                }
                for page in stored.pages() {
                    text::validate_page(&page.content_type, &page.body)
                        .unwrap_or_else(|e| panic!("{}: {e}", page.url));
                    let dom =
                        kuchiki::parse_html().one(String::from_utf8_lossy(&page.body).into_owned());
                    let main = dom.select_first("main").unwrap();
                    assert!(
                        main.text_contents().split_whitespace().count() >= 65,
                        "{} has too little readable text",
                        page.url
                    );
                    assert!(
                        dom.select_first("h1")
                            .unwrap()
                            .text_contents()
                            .contains(&page.title)
                    );
                    assert!(page.body.len() > 900, "{}", page.url);
                }
                for query in [
                    "how to repair a dishwasher",
                    "netgear vpn configuration",
                    "sqlite banana bread",
                    "a completely unrelated question",
                ] {
                    for engine in [
                        Engine::Google,
                        Engine::Bing,
                        Engine::DuckDuckGo,
                        Engine::YouTube,
                    ] {
                        let (listing, cache, usage, _) = pages.canned_listing(engine, query, 0);
                        assert!(listing.results.is_empty(), "{query}");
                        assert_eq!(cache, Cache::Missing);
                        assert!(usage.is_none());
                    }
                }
                let missing = pages
                    .handle(&cx, "GET", "www.python-httpx.org", "/unknown-page", None)
                    .await;
                assert_eq!(missing.status, 404);
                assert!(missing.body.len() < 600);
                assert_eq!(pages.store().made, 0);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn tool_observation_reports_the_source_and_filtered_results() {
        let pages = Arc::new(
            Pages::canned(Seed::builtin("web").unwrap(), &store::canned_root("web")).unwrap(),
        );
        let searches = Arc::new(crate::search::Searches::of(&pages));
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(5)).observer(searches.clone()),
            |cx| async move {
                let first = fictionet_extras::models::Engine::search(
                    pages.clone(),
                    cx.clone(),
                    "httpx vs requests async concurrency".into(),
                    "claude_web_search",
                    json!({}),
                )
                .await?;
                assert_eq!(first.len(), 6);
                let found = fictionet_extras::models::Engine::search(
                    pages,
                    cx,
                    "httpx vs requests async concurrency".into(),
                    "codex_web_search",
                    json!({"allowed_domains":["python-httpx.org"]}),
                )
                .await?;
                assert_eq!(found.len(), 4);
                assert!(
                    found
                        .iter()
                        .all(|r| r.url.starts_with("https://www.python-httpx.org/"))
                );
                Ok(())
            },
        ))
        .unwrap();
        let snapshot = searches.snapshot();
        assert_eq!(snapshot.queries.len(), 2);
        assert_eq!(snapshot.queries[1].via.as_deref(), Some("codex_web_search"));
        assert_eq!(snapshot.queries[1].results, Some(4));
        assert_eq!(snapshot.results[0].listed.len(), 4);
    }

    #[test]
    fn close_searches_match_whole_words_with_stable_ties() {
        let pages =
            Pages::canned(Seed::builtin("web").unwrap(), &store::canned_root("web")).unwrap();
        for query in [
            "requests async concurrency vs httpx",
            "please sqlite database is locked WAL",
            "RIPGREP not finding hidden files?",
        ] {
            let (listing, cache, _, _) = pages.canned_listing(Engine::Google, query, 0);
            assert_eq!(cache, Cache::Cached, "{query}");
            assert_eq!(listing.results.len(), 6);
            assert_eq!(listing, pages.canned_listing(Engine::Google, query, 0).0);
        }
        assert!(
            pages
                .canned_listing(Engine::Google, "ripgrepping hides things", 0)
                .0
                .results
                .is_empty()
        );
        assert!(
            pages
                .canned_listing(Engine::Google, "sqlite WAL single writer", 10)
                .0
                .results
                .is_empty()
        );
    }
}
