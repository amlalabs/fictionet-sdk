//! Answer every search engine from the active page source.

use super::*;

impl Pages {
    pub(super) async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Response {
        let (search, cache, usage, carries) = match self.listing(cx, engine, query, start).await {
            Ok(listing) => listing,
            Err(stop) => return stop.response(Asked::Search),
        };
        let body = search::render(engine, query, &search, start);
        let listing = Listing {
            engine,
            search: query.into(),
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
        let meta = Meta::Search(Box::new(listing));
        Response::html(
            body,
            meta,
            200,
            fictionet_extras::search::engine_server(engine),
        )
    }

    /// The result list a search shows: the stored or newly made list, with
    /// the planted pages that share its words first and every planted
    /// correction made. Also how it was supplied and what made it.
    pub(super) async fn listing(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<(fictionet_extras::search::Search, Cache, Option<Usage>, u64), Stop> {
        if self.live_only() {
            return self.live_listing(cx, engine, query, start).await;
        }
        if self.copied_only() {
            return Ok(self.copied_listing(query, start));
        }
        let key = if engine == Engine::YouTube {
            format!("youtube {}", query_key(query, start))
        } else {
            query_key(query, start)
        };
        let _lock = self
            .locks
            .lock(cx, format!("search {key}"))
            .await
            .map_err(Stop::store)?;
        if start >= 10 && matches!(self.maker.as_ref(), Some(Maker::Stored)) {
            return Ok((
                fictionet_extras::search::Search::default(),
                Cache::Missing,
                None,
                0,
            ));
        }
        let stored = self.store().search(&key).cloned();
        let (record, cache) = match stored {
            Some(record) => (Some(record), Cache::Cached),
            None if !self.generating() => (None, Cache::Missing),
            None => {
                let record = self.make_search(cx, &key, query, engine).await?;
                self.start_prefetch(cx, &record);
                (Some(record), Cache::Generated)
            }
        };
        let mut search = record
            .as_ref()
            .map(|r| r.search.clone())
            .unwrap_or_default();
        if engine == Engine::YouTube && record.is_some() {
            // Video searches draw from the site's video cards.
            let store = self.store();
            search = make::videos(
                query,
                store
                    .pages()
                    .filter(|p| p.host == "www.youtube.com")
                    .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
            );
        }
        if record.is_some()
            && engine != Engine::Google
            // A prepared list answers every engine as it was written; only
            // lists made on the spot differ by engine.
            && (engine == Engine::YouTube
                || record.as_ref().is_some_and(|r| r.usage.model == "stored"))
        {
            let proposed = if engine == Engine::YouTube {
                search.clone()
            } else {
                make::for_engine(
                    &self.context(),
                    &query_key(query, 0),
                    search.clone(),
                    engine,
                )
            };
            let replayable = proposed.results.iter().all(|r| {
                let (host, target) = text::target_of(&r.url);
                !self.store().mentions(&host, &target).is_empty()
                    || self.seed.fixed.iter().any(|f| f.url == r.url)
            });
            if self.generating() || replayable {
                search = proposed;
                for result in &mut search.results {
                    let (host, target) = text::target_of(&result.url);
                    let mention = if self.generating() {
                        let mention = json!({"via":"search", "query":query, "title":result.title, "snippet":result.snippet, "date":result.date});
                        self.store()
                            .reserve_mention(&self.seed, &host, &target, mention)
                            .map_err(Stop::store)?
                    } else {
                        self.store()
                            .mentions(&host, &target)
                            .first()
                            .cloned()
                            .unwrap_or_else(
                                || json!({"title":result.title,"snippet":result.snippet}),
                            )
                    };
                    result.title = mention["title"].as_str().unwrap_or_default().into();
                    result.snippet = mention["snippet"].as_str().unwrap_or_default().into();
                }
            }
        }
        if search.ads.is_empty() && record.is_some() {
            let store = self.store();
            for list in store.searches() {
                if make::relevant(
                    &fictionet_extras::search::Result {
                        url: String::new(),
                        title: list.query.clone(),
                        snippet: String::new(),
                        date: String::new(),
                    },
                    query,
                ) {
                    for ad in &list.search.ads {
                        if !search.ads.iter().any(|a| a.url == ad.url) {
                            search.ads.push(ad.clone());
                        }
                    }
                }
            }
        }
        // A list with no results while nothing new is made stays empty.
        if start == 0 && record.is_some() {
            let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
            for page in planted.pages.iter().rev() {
                if make::shares_words(
                    &format!("{} {} {}", page.title, page.url, page.text.join(" ")),
                    query,
                ) {
                    search.results.retain(|r| r.url != page.url);
                    search.results.insert(
                        0,
                        fictionet_extras::search::Result {
                            url: page.url.clone(),
                            title: page.title.clone(),
                            snippet: make::excerpt(&page.text.join(" ")),
                            date: make::result_date(&self.seed.date),
                        },
                    );
                    search.results.truncate(10);
                }
            }
        }
        for result in &mut search.results {
            let (host, target) = text::target_of(&result.url);
            if let Some((url, title)) = self
                .canonical_page(&host, &target)
                .filter(|(url, _)| text::target_of(url).1 != target)
            {
                result.url = url;
                result.title = title;
            }
        }
        make::finish_listing(query, &mut search);
        let mut reached = HashSet::new();
        for result in &mut search.results {
            if self
                .planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pages
                .iter()
                .any(|p| p.url == result.url)
            {
                continue;
            }
            result.title = self.corrected(&result.title, &mut reached);
            result.snippet = self.corrected(&result.snippet, &mut reached);
        }
        for ad in &mut search.ads {
            ad.title = self.corrected(&ad.title, &mut reached);
            ad.text = self.corrected(&ad.text, &mut reached);
        }
        Ok((search, cache, record.map(|r| r.usage), reached.len() as u64))
    }

    pub(super) async fn make_search(
        &self,
        cx: &Cx,
        key: &str,
        query: &str,
        engine: Engine,
    ) -> Result<SearchRecord, Stop> {
        if self.live_calls.is_none() {
            self.reserve()?;
        }
        let cast = self.cast(cx).await?;
        let seed = self.context();
        let (known, claims) = {
            let store = self.store();
            (store.known(&seed), store.recent_claims(40))
        };
        let mut normalized = search::Search {
            results: known,
            ..search::Search::default()
        };
        make::finish_listing(query, &mut normalized);
        let known = normalized.results;
        let made = self
            .generate(
                cx,
                json!({"kind": "search", "query": query}),
                || {
                    if engine == Engine::YouTube {
                        let store = self.store();
                        make::videos(
                            query,
                            store
                                .pages()
                                .filter(|p| p.host == "www.youtube.com")
                                .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
                        )
                    } else {
                        make::search(&seed, query, &known, Engine::Google)
                    }
                },
                || {
                    let (system, user) = prompts::search(&seed, &cast, query, &known, &claims);
                    (system, user, SEARCH_TOKENS)
                },
                prompts::read_search,
            )
            .await?;
        let mut search = made.fields;
        make::finish_listing(query, &mut search);
        let mut results: Vec<fictionet_extras::search::Result> = Vec::new();
        for mut r in std::mem::take(&mut search.results) {
            let (host, target) = text::target_of(&r.url);
            if let Some((url, title)) = self
                .canonical_page(&host, &target)
                .filter(|(url, _)| text::target_of(url).1 != target)
            {
                r.url = url;
                r.title = title;
            }
            let (host, target) = text::target_of(&r.url);
            let known_match = known.iter().find(|k| k.url == r.url);
            // A page the world already holds stays out of an unrelated list.
            // A model that lists it for this search with a row sharing the
            // search's words has said how it is related.
            let chosen = made.usage.model != "stored"
                && make::shares_words(&format!("{} {} {}", r.title, r.url, r.snippet), query);
            if host.is_empty()
                || results.iter().any(|x| x.url == r.url)
                || known_match.is_some_and(|k| !make::relevant(k, query) && !chosen)
            {
                continue;
            }
            let mention = json!({
                "via": "search",
                "query": query,
                "rank": results.len() + 1,
                "title": r.title,
                "snippet": r.snippet,
                "date": r.date,
            });
            let _page = self
                .locks
                .lock(cx, page_key(&host, &target))
                .await
                .map_err(Stop::store)?;
            let mention = self
                .store()
                .reserve_mention(&self.seed, &host, &target, mention)
                .map_err(Stop::store)?;
            r.title = mention["title"].as_str().unwrap_or_default().into();
            r.snippet = mention["snippet"].as_str().unwrap_or_default().into();
            results.push(r);
        }
        let known_matches = results
            .iter()
            .filter(|r| {
                known
                    .iter()
                    .any(|k| k.url == r.url && make::relevant(k, query))
            })
            .count();
        if made.usage.model == "stored" && known_matches >= 8 {
            results.retain(|r| {
                known
                    .iter()
                    .any(|k| k.url == r.url && make::relevant(k, query))
            });
        }
        search.results = results;
        let record = SearchRecord {
            key: key.into(),
            query: query.into(),
            search,
            usage: made.usage,
        };
        self.store()
            .insert_search(record.clone())
            .map_err(Stop::store)?;
        Ok(record)
    }

    /// Makes the pages behind a new list's first results in the background.
    /// A page that fails here is made again when it is asked for.
    pub(super) fn start_prefetch(self: &Arc<Self>, cx: &Cx, record: &SearchRecord) {
        if self.live_calls.is_some() && record.usage.model == "stored" {
            return;
        }
        for r in record.search.results.iter().take(self.prefetch) {
            let (host, target) = text::target_of(&r.url);
            if self.canonical_page(&host, &target).is_some() {
                continue;
            }
            let pages = self.clone();
            cx.spawn(move |cx| async move {
                let started = cx.now().since_start();
                let response = pages.page(&cx, &host, &target, true).await;
                cx.emit("web", "prefetch_finished", |e| {
                    e.field("url", format!("https://{host}{target}"))
                        .field("status", response.status as u64)
                });
                if let Meta::Error { error, usage } = &response.meta {
                    let mut row = json!({
                        "kind": "prefetch_error",
                        "record": "diagnostic",
                        "url": format!("https://{host}{target}"),
                        "error": error,
                        "serve_ms": (cx.now().since_start() - started).as_millis() as u64,
                    });
                    if let Some(usage) = usage {
                        row["model"] = json!(usage.model);
                        row["gen_ms"] = json!(usage.gen_ms);
                        row["cost"] = json!(usage.cost);
                    }
                    // A world that cannot write the row says so on the next request.
                    let _ = pages.log(&cx, &[row]);
                }
                Ok(())
            });
        }
    }

    /// The site's display name, shared by pages and observers.
    pub fn site_name(&self, host: &str) -> String {
        self.store()
            .site(host)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| make::site_profile(host).name)
    }
}
