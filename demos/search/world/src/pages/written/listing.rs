//! Answer every search engine from the written web.

use super::*;

impl Written {
    pub(super) async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Response {
        let search = match self.listing(cx, engine, query, start).await {
            Ok(search) => search,
            Err(stop) => return stop.response(),
        };
        let body = search::render(engine, query, &search, start);
        let listing = Listing {
            engine,
            search: query.into(),
            listed: (search.results.iter())
                .map(|r| (r.url.clone(), r.title.clone()))
                .collect(),
            edits: Vec::new(),
        };
        Response::html(
            body,
            Meta::Search(Box::new(listing)),
            200,
            fictionet_extras::search::engine_server(engine),
        )
    }

    /// The result list a model's search tool gets: Google's.
    pub(in crate::pages) async fn results(
        self: &Arc<Self>,
        cx: &Cx,
        query: &str,
        start: u64,
    ) -> Result<fictionet_extras::search::Search, String> {
        self.listing(cx, Engine::Google, query, start)
            .await
            .map_err(|stop| stop.error)
    }

    /// The result list a search shows: the stored or newly made list.
    async fn listing(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<fictionet_extras::search::Search, Stop> {
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
            return Ok(fictionet_extras::search::Search::default());
        }
        let stored = self.store().search(&key).cloned();
        let record = match stored {
            Some(record) => Some(record),
            None if !self.generating() => None,
            None => {
                let record = self.make_search(cx, &key, query, engine).await?;
                self.start_prefetch(cx, &record);
                Some(record)
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
            && (engine == Engine::YouTube
                || record.as_ref().is_some_and(|r| r.usage.model == "stored"))
        {
            let replayable = search.results.iter().all(|r| {
                let (host, target) = text::target_of(&r.url);
                !self.store().mentions(&host, &target).is_empty()
                    || self.seed.fixed.iter().any(|f| f.url == r.url)
            });
            if self.generating() || replayable {
                for result in &mut search.results {
                    let (host, target) = text::target_of(&result.url);
                    let mention = if self.generating() {
                        let mention = Mention::search(query, 0, result).map_err(|reason| Stop {
                            error: reason.to_string(),
                        })?;
                        self.store()
                            .reserve_mention(&self.seed, &host, &target, mention, false)
                            .map_err(Stop::store)?
                    } else {
                        self.store()
                            .mentions(&host, &target)
                            .first()
                            .cloned()
                            .unwrap_or_else(|| {
                                Mention::search(query, 0, result).expect("stored search date")
                            })
                    };
                    result.title = mention.title().unwrap_or_default().into();
                    result.snippet = mention.snippet().unwrap_or_default().into();
                    result.date = mention
                        .date()
                        .map(|date| date.to_string())
                        .unwrap_or_default();
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
        make::finish_listing(&mut search);
        Ok(search)
    }

    async fn make_search(
        &self,
        cx: &Cx,
        key: &str,
        query: &str,
        engine: Engine,
    ) -> Result<SearchRecord, Stop> {
        let cast = self.cast(cx).await?;
        let seed = &self.seed;
        let (known, claims) = {
            let store = self.store();
            (store.known(seed), store.writing_context(query))
        };
        let mut normalized = search::Search {
            results: known,
            ..search::Search::default()
        };
        make::finish_listing(&mut normalized);
        let known = normalized.results;
        let made = self
            .generate(
                cx,
                WriterTarget::Search {
                    query: query.into(),
                },
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
                        make::search(query, &known)
                    }
                },
                || prompts::search(seed, &cast, query, &known, &claims),
                |text| {
                    let search = prompts::read_search(text)?;
                    for result in &search.results {
                        let date = if result.date.is_empty() {
                            String::new()
                        } else {
                            answers::dates(&result.date)
                                .first()
                                .ok_or_else(|| {
                                    prompts::Unreadable::Content(
                                        "Search DATE needs a full calendar date".into(),
                                    )
                                })?
                                .to_string()
                        };
                        answers::chronology(
                            &make::Page {
                                date,
                                body: result.snippet.clone(),
                                content_type: "text/plain".into(),
                                ..Default::default()
                            },
                            seed::parse_date(&seed.date).expect("world date"),
                        )?;
                    }
                    Ok(search)
                },
            )
            .await?;
        let mut search = made.fields;
        make::finish_listing(&mut search);
        let mut results: Vec<fictionet_extras::search::Result> = Vec::new();
        for mut r in std::mem::take(&mut search.results) {
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
            let mention =
                Mention::search(query, results.len() as u64 + 1, &r).map_err(|reason| Stop {
                    error: reason.to_string(),
                })?;
            // A page another request is writing keeps its lock for the whole
            // write; the list promises what that page was asked to show
            // instead of waiting for it.
            let page = self
                .locks
                .try_lock(&page_key(&host, &target))
                .map_err(Stop::store)?;
            let mention = self
                .store()
                .reserve_mention(&self.seed, &host, &target, mention, page.is_none())
                .map_err(Stop::store)?;
            drop(page);
            r.title = mention.title().unwrap_or_default().into();
            r.snippet = mention.snippet().unwrap_or_default().into();
            r.date = mention
                .date()
                .map(|date| date.to_string())
                .unwrap_or_default();
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
    fn start_prefetch(self: &Arc<Self>, cx: &Cx, record: &SearchRecord) {
        for r in record.search.results.iter().take(self.prefetch) {
            let (host, target) = text::target_of(&r.url);
            if self.seed.fixed_for(&host, &target).is_some()
                || self.store().page(&host, &target).is_some()
            {
                continue;
            }
            let pages = self.clone();
            cx.spawn(move |cx| async move {
                let started = cx.now().since_start();
                let response = pages.page(&cx, &host, &target, true).await;
                if let Meta::Error { error } = &response.meta {
                    let row = json!({
                        "kind": "prefetch_error",
                        "record": "diagnostic",
                        "url": format!("https://{host}{target}"),
                        "error": error,
                        "serve_ms": (cx.now().since_start() - started).as_millis() as u64,
                    });
                    // A world that cannot write the row says so on the next request.
                    let _ = pages.log(&[row]);
                }
                Ok(())
            });
        }
    }
}
