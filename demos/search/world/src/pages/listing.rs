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
            Err(stop) => return stop.response(),
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
        let mut response = Response::html(
            body,
            meta,
            200,
            fictionet_extras::search::engine_server(engine),
        );
        response.carries = carries;
        response
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
        self.listing_with_domains(cx, engine, query, start, &Default::default())
            .await
    }

    pub(super) async fn listing_with_domains(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<(fictionet_extras::search::Search, Cache, Option<Usage>, u64), Stop> {
        self.during_source(self.listing_in(cx, engine, query, start, domains), || {
            Err(Stop::store(std::io::Error::other("Page source changed")))
        })
        .await
    }

    async fn listing_in(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<(fictionet_extras::search::Search, Cache, Option<Usage>, u64), Stop> {
        if domains.allowed_domains.as_ref().is_some_and(Vec::is_empty) {
            return Ok((
                fictionet_extras::search::Search {
                    total: Some(0),
                    ..Default::default()
                },
                Cache::Fixed,
                None,
                0,
            ));
        }
        if self.live_only() {
            return self.live_listing(cx, engine, query, start, domains).await;
        }
        if self.copied_only() {
            return self.copied_listing_in(query, start, domains);
        }
        // Search results establish shared facts before independent pages read them.
        let _publication = if self.interactive {
            Some(
                self.locks
                    .lock(cx, "search publications".into())
                    .await
                    .map_err(Stop::store)?,
            )
        } else {
            None
        };
        let mut key = if engine == Engine::YouTube {
            format!("youtube {}", query_key(query, start))
        } else {
            query_key(query, start)
        };
        if domains.allowed_domains.is_some() || domains.blocked_domains.is_some() {
            key = serde_json::to_string(&(key, domains)).expect("search key");
        }
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
                let record = self.make_search(cx, &key, query, engine, domains).await?;
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
                        let mention =
                            Mention::search(query, 0, result).map_err(|reason| Stop::Failed {
                                error: reason.to_string(),
                                usage: None,
                            })?;
                        self.writing_store()?
                            .reserve_mention(&self.seed, &host, &target, mention)
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
        // A list with no results while nothing new is made stays empty.
        if start == 0 && record.is_some() {
            let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
            for page in planted.pages.iter().rev() {
                if make::shares_words(
                    &format!("{} {} {}", page.title, page.url, page.text.join(" ")),
                    query,
                ) && fictionet_extras::models::tools::allowed(domains, &page.url)
                {
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
        make::finish_listing(&mut search);
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
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<SearchRecord, Stop> {
        let cast = self.cast(cx).await?;
        let seed = self.context();
        let (mut known, claims) = {
            let store = self.writing_store()?;
            (store.known(&seed), store.writing_context(query))
        };
        let mut reference = None;
        if self.copied.is_some() {
            let (found, _, _, _) = self.copied_listing_in(query, 0, domains)?;
            if let Some(result) = found.results.first() {
                reference = self
                    .reference_text(&result.url)
                    .map_err(Stop::store)?
                    .map(|text| (result.url.clone(), text));
            }
            for result in found.results {
                if !known.iter().any(|page| page.url == result.url) {
                    known.push(result);
                }
            }
        }
        known.retain(|result| fictionet_extras::models::tools::allowed(domains, &result.url));
        let mut normalized = search::Search {
            results: known,
            ..search::Search::default()
        };
        make::finish_listing(&mut normalized);
        let known = normalized.results;
        let made = self
            .generate(
                cx,
                crate::observation::WriterTarget::Search {
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
                || {
                    let (system, mut user) = prompts::search(&seed, &cast, query, &known, &claims);
                    if domains.allowed_domains.is_some() || domains.blocked_domains.is_some() {
                        user.push_str(&format!("\nDomain restrictions for every result, including subdomains: {}", serde_json::to_string(domains).expect("domain restrictions")));
                    }
                    if let Some((url, reference)) = &reference {
                        user.push_str(&format!("\nHighest-ranked captured reference, {url}:\n{reference}\nUse its established public facts to ground the result list. Preserve its names, outcomes and quantities unless the world's brief or previously published documents explicitly change them. The capture date does not change event dates."));
                    }
                    (system, user)
                },
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
                || !fictionet_extras::models::tools::allowed(domains, &r.url)
                || results.iter().any(|x| x.url == r.url)
                || known_match.is_some_and(|k| !make::relevant(k, query) && !chosen)
            {
                continue;
            }
            let mention =
                Mention::search(query, results.len() as u64 + 1, &r).map_err(|reason| {
                    Stop::Failed {
                        error: reason.to_string(),
                        usage: None,
                    }
                })?;
            let _page = self
                .locks
                .lock(cx, page_key(&host, &target))
                .await
                .map_err(Stop::store)?;
            let mention = self
                .writing_store()?
                .reserve_mention(&self.seed, &host, &target, mention)
                .map_err(Stop::store)?;
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
        self.writing_store()?
            .insert_search(record.clone())
            .map_err(Stop::store)?;
        Ok(record)
    }

    /// Makes the pages behind a new list's first results in the background.
    /// A page that fails here is made again when it is asked for.
    pub(super) fn start_prefetch(self: &Arc<Self>, cx: &Cx, record: &SearchRecord) {
        if self.interactive && record.usage.model == "stored" {
            return;
        }
        for r in record.search.results.iter().take(self.prefetch) {
            let (host, target) = text::target_of(&r.url);
            if self.seed.fixed_for(&host, &target).is_some()
                || self.store().page(&host, &target).is_some()
            {
                continue;
            }
            let pages = self.clone();
            let session = WRITING
                .try_with(Clone::clone)
                .unwrap_or_else(|_| self.writing.lock().unwrap().subscribe());
            cx.spawn(move |cx| async move {
                WRITING
                    .scope(session.clone(), async {
                        let mut session = session;
                        let started = cx.now().since_start();
                        let response = tokio::select! {
                            biased;
                            _ = session.wait_for(|cancelled| *cancelled) => return Ok(()),
                            response = pages.page(&cx, &host, &target, true) => response,
                        };
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
                    })
                    .await
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
