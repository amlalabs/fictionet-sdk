//! Write and store pages through the model provider.

use super::*;

impl Pages {
    /// Writes a generation's ledger rows, or a stored generation's one row.
    pub(super) fn log(&self, _cx: &Cx, rows: &[Value]) -> Result<(), Stop> {
        let mut store = self.store();
        for row in rows {
            store.log_generation(row).map_err(Stop::store)?;
        }
        Ok(())
    }

    /// Starts one generation, or says the budget is spent.
    pub(super) fn reserve(&self) -> Result<(), Stop> {
        if let Some(calls) = &self.live_calls {
            return calls
                .try_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| (n < GENERATION_BUDGET).then_some(n + 1),
                )
                .map(|_| ())
                .map_err(|_| Stop::Budget);
        }
        let mut store = self.store();
        if store.made >= GENERATION_BUDGET {
            return Err(Stop::Budget);
        }
        store.made += 1;
        Ok(())
    }

    pub(super) fn maker(&self) -> &Maker {
        self.maker.as_ref().expect("a world that is generating")
    }

    /// Runs one generation with the maker's stored or model path and
    /// writes its rows. `context` names it in `generations.jsonl`.
    pub(super) async fn generate<T: serde::Serialize>(
        &self,
        cx: &Cx,
        target: crate::observation::WriterTarget,
        stored: impl FnOnce() -> T,
        prompt: impl FnOnce() -> (String, String, u32),
        read: impl Fn(&str, bool) -> Result<T, prompts::Unreadable>,
    ) -> Result<Made<T>, Stop> {
        let context = serde_json::to_value(&target).expect("generation target");
        match self.maker() {
            Maker::Stored => self.stored(cx, target, stored),
            Maker::Model(model) => {
                if self.live_calls.is_some() {
                    self.reserve()?;
                }
                let (system, user, max_tokens) = prompt();
                let parse = |text: &str| match gives_away(text) {
                    Some(reason) => Err(prompts::Unreadable::Disclosure(reason)),
                    None => read(text, false),
                };
                let rejected = |reason: &prompts::Unreadable| {
                    self.report(
                        cx,
                        crate::observation::SearchObs::PageRevision {
                            target: target.clone(),
                            action: crate::observation::RevisionAction::Rejected,
                            reason: model.redact(&reason.to_string()),
                        },
                    );
                };
                let (answer, ledger): (_, Ledger) = model
                    .ask(cx, &system, &user, max_tokens, parse, rejected)
                    .await;
                let usage = ledger.usage();
                let repaired = match &answer {
                    Err(failure)
                        if failure.can_render_locally()
                            && matches!(target, crate::observation::WriterTarget::Page { .. }) =>
                    {
                        ledger
                            .attempts
                            .last()
                            .filter(|a| !a.cut_off)
                            .and_then(|a| a.raw.as_deref())
                            .and_then(|raw| read(raw, true).ok())
                            .filter(|fields| {
                                let audit = fictionet_extras::guest_content::Audit::default();
                                audit.inspect(
                                    "repaired document",
                                    &serde_json::to_vec(fields).expect("page fields"),
                                );
                                audit.check().is_ok()
                            })
                    }
                    _ => None,
                };
                let status = if answer.is_ok() {
                    model::GenerationOutcome::Ok
                } else if repaired.is_some() {
                    model::GenerationOutcome::Recovered
                } else {
                    model::GenerationOutcome::Error
                };
                let mut rows = ledger.rows(&context, status);
                rows.iter_mut().for_each(|row| model.redact_json(row));
                if repaired.is_none() {
                    self.log(cx, &rows)?;
                }
                match (answer, repaired) {
                    (Ok(answer), _) => Ok(Made {
                        fields: answer.fields,
                        usage,
                        recovery: None,
                    }),
                    (Err(failure), Some(fields)) => Ok(Made {
                        fields,
                        usage,
                        recovery: Some(Recovery {
                            target,
                            reason: model.redact(&failure.error),
                            rows,
                        }),
                    }),
                    (Err(Failure { error, .. }), None) => Err(Stop::Failed {
                        error: model.redact(&error),
                        usage: Some(Box::new(usage)),
                    }),
                }
            }
        }
    }

    pub(super) fn stored<T>(
        &self,
        cx: &Cx,
        target: crate::observation::WriterTarget,
        stored: impl FnOnce() -> T,
    ) -> Result<Made<T>, Stop> {
        let mut context = serde_json::to_value(target).expect("generation target");
        let started = cx.now().since_start();
        let fields = stored();
        let usage = Usage::stored((cx.now().since_start() - started).as_millis() as u64);
        context["record"] = json!("stored");
        for (key, value) in serde_json::to_value(&usage).unwrap().as_object().unwrap() {
            context[key] = value.clone();
        }
        context["raw"] = Value::Null;
        self.log(cx, &[context])?;
        Ok(Made {
            fields,
            usage,
            recovery: None,
        })
    }

    /// The people the world names, made the first time a list or page
    /// needs them.
    pub(super) async fn cast(&self, cx: &Cx) -> Result<Vec<Person>, Stop> {
        let _lock = self
            .locks
            .lock(cx, "cast".into())
            .await
            .map_err(Stop::store)?;
        if let Some(cast) = self.store().cast() {
            return Ok(cast.people.clone());
        }
        if self.live_calls.is_some() {
            let cast = CastRecord {
                people: Vec::new(),
                usage: Usage::stored(0),
            };
            self.store().set_cast(cast.clone()).map_err(Stop::store)?;
            return Ok(cast.people);
        }
        self.reserve()?;
        let made = self
            .generate(
                cx,
                crate::observation::WriterTarget::Cast,
                Vec::new,
                || {
                    let (system, user) = prompts::cast(&self.seed);
                    (system, user, CAST_TOKENS)
                },
                |text, _| prompts::read_cast(text),
            )
            .await?;
        let record = CastRecord {
            people: made.fields,
            usage: made.usage,
        };
        self.store().set_cast(record.clone()).map_err(Stop::store)?;
        Ok(record.people)
    }

    pub(super) async fn site_stylesheet(&self, cx: &Cx, host: &str) -> Result<make::Profile, Stop> {
        let profile = make::site_profile(host);
        if profile.kind == make::SiteKind::Qa {
            return Ok(profile);
        }
        let _site = self
            .locks
            .lock(cx, format!("site {host}"))
            .await
            .map_err(Stop::store)?;
        let stored = self.store().site(host).cloned();
        if let Some(profile) = &stored
            && !profile.css.is_empty()
        {
            return Ok(profile.clone());
        }
        let mut profile = stored.unwrap_or_else(|| make::site_profile(host));
        if !self.generating() {
            profile.css.clear();
            return Ok(profile);
        }
        if matches!(self.maker(), Maker::Model(_)) {
            if self.live_calls.is_none() {
                self.reserve()?;
            }
            let made = self
                .generate(
                    cx,
                    crate::observation::WriterTarget::Stylesheet { host: host.into() },
                    String::new,
                    || {
                        let (system, user) = prompts::stylesheet(&self.seed, host, &profile);
                        (system, user, 1000)
                    },
                    |text, _| {
                        let css = text.trim();
                        if css.is_empty() {
                            Err(prompts::Unreadable::Format("empty stylesheet".into()))
                        } else {
                            Ok(css.to_owned())
                        }
                    },
                )
                .await?;
            profile.css = made.fields;
        } else {
            profile.css = make::site_profile(host).css;
        }
        self.store().site_once(host, profile).map_err(Stop::store)
    }

    pub(super) async fn make_page(
        &self,
        cx: &Cx,
        host: &str,
        target: &str,
        prefetch: bool,
    ) -> Result<PageRecord, Stop> {
        let _publication = if self.live_calls.is_some() {
            Some(
                self.locks
                    .lock(cx, "page publications".into())
                    .await
                    .map_err(Stop::store)?,
            )
        } else {
            None
        };
        let _site = self
            .locks
            .lock(cx, format!("site {host}"))
            .await
            .map_err(Stop::store)?;
        if self.live_calls.is_none() {
            self.reserve()?;
        }
        let cast = self.cast(cx).await?;
        let url = format!("https://{host}{target}");
        let mut ask = {
            let store = self.store();
            PageAsk {
                url: url.clone(),
                mentions: prompts::asked_mentions(store.mentions(host, target)),
                profile: store.site(host).filter(|p| !p.css.is_empty()).cloned(),
                host_pages: store.host_pages(host),
                claims: store.writing_context(&format!(
                    "{url} {}",
                    store
                        .mentions(host, target)
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                )),
                cast,
            }
        };
        let expected = prompts::expected_type(&url);
        let seed = self.context().into_owned();
        let subject = format!("{url} {}", make::title_from(host, target));
        {
            let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
            for fact in &planted.facts {
                if correction(fact).is_none() && make::shares_words(fact, &subject) {
                    ask.mentions.push(json!({"via":"fact", "snippet":fact}));
                }
            }
        }
        let kind = self
            .store()
            .site(host)
            .map(|p| p.kind)
            .unwrap_or_else(|| make::site_profile(host).kind);
        let mut known = {
            let store = self.store();
            let mut known = store.known(&seed);
            if host == "www.youtube.com" && target == "/" {
                known.extend(
                    make::videos(
                        "",
                        store
                            .pages()
                            .filter(|p| p.host == host)
                            .map(|p| (&p.url, String::from_utf8_lossy(&p.body).into_owned())),
                    )
                    .results,
                );
            }

            for result in store.searches().flat_map(|s| &s.search.results) {
                if !known.iter().any(|r| r.url == result.url) {
                    known.push(result.clone());
                }
            }
            known
        };
        known.extend(
            self.planted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pages
                .iter()
                .map(|p| fictionet_extras::search::Result {
                    url: p.url.clone(),
                    title: p.title.clone(),
                    snippet: p.text.join(" "),
                    date: String::new(),
                }),
        );
        let made = self
            .generate(
                cx,
                crate::observation::WriterTarget::Page { url: url.clone() },
                || {
                    let mut mentions = ask.mentions.clone();
                    for fact in &self.planted.lock().unwrap_or_else(|e| e.into_inner()).facts {
                        if correction(fact).is_some()
                            && make::shares_words(
                                fact,
                                &format!("{url} {}", make::title_from(host, target)),
                            )
                        {
                            mentions.push(json!({"snippet": fact}));
                        }
                    }
                    make::page_with_known(&seed, host, target, &mentions, kind, &known)
                },
                || {
                    let (system, user) = prompts::page(
                        &seed,
                        &ask.cast,
                        &ask.url,
                        &ask.mentions,
                        ask.profile.as_ref(),
                        &ask.host_pages,
                        &ask.claims,
                    );
                    (
                        system,
                        user,
                        PAGE_TOKENS + if ask.profile.is_none() { 1000 } else { 0 },
                    )
                },
                |text, repair| {
                    let mut page = prompts::read_page(text, expected, !ask.mentions.is_empty())?;
                    if repair {
                        super::answers::repair_page(&mut page)?;
                    }
                    if self.live_calls.is_some() {
                        let body = if page.content_type.starts_with("text/html") {
                            let profile = ask
                                .profile
                                .as_ref()
                                .or(page.site.as_ref())
                                .cloned()
                                .unwrap_or_else(|| make::site_profile(host));
                            render::page_at(host, target, &profile, &page, &seed.date)
                        } else {
                            page.body.clone()
                        };
                        text::validate_page(&page.content_type, body.as_bytes())
                            .map_err(prompts::Unreadable::Content)?;
                    }
                    if ask.profile.is_none()
                        && fictionet_extras::sites::lookup(host, target).is_none()
                        && page.site.as_ref().is_none_or(|p| p.css.is_empty())
                    {
                        return Err(prompts::Unreadable::Format(
                            "the first page needs SITE_CSS".into(),
                        ));
                    }
                    Ok(page)
                },
            )
            .await?;
        let mut page = made.fields;
        if let Some(title) = ask
            .mentions
            .iter()
            .filter_map(|m| m["title"].as_str())
            .find(|s| !s.is_empty())
        {
            page.title = title.into();
        }
        let today = &self.seed.date;
        let profile = match ask.profile {
            Some(profile) => profile,
            None => {
                let mut described = page.site.take().unwrap_or_else(|| make::site_profile(host));
                if described.name.is_empty() {
                    described.name = make::site_profile(host).name;
                }
                self.store()
                    .site_once(host, described)
                    .map_err(Stop::store)?
            }
        };
        let html = page.content_type.starts_with("text/html");
        let body = if !html {
            page.body.clone()
        } else if page.status == 404 && ask.mentions.is_empty() {
            render::not_found(host, Some(&profile), target, today)
        } else {
            render::page_at(host, target, &profile, &page, today)
        };
        let tells = text::tells(&if html {
            text::text_of(&page.body)
        } else {
            body.clone()
        });
        let (unsupported, unchecked) =
            text::check_snippets(&body, &page.content_type, &ask.mentions);
        let record = PageRecord {
            url,
            host: host.into(),
            target: target.into(),
            status: page.status,
            content_type: page.content_type,
            body: body.into_bytes(),
            headers: vec![("Server".into(), render::server_of(Some(&profile)).into())],
            title: page.title,
            description: page.description,
            date: page.date,
            claims: page.claims,
            mentions: ask.mentions,
            tells,
            unsupported_snippets: unsupported,
            unchecked_snippets: unchecked,
            prefetched: prefetch,
            fixed: false,
            usage: Some(made.usage),
        };
        let mut store = self.store();
        store.insert_page(record.clone()).map_err(Stop::store)?;
        if prefetch {
            store
                .unserved
                .insert((store::site_key(host).into(), target.into()));
        }
        drop(store);
        if let Some(recovery) = made.recovery {
            self.log(cx, &recovery.rows)?;
            self.report(
                cx,
                crate::observation::SearchObs::PageRevision {
                    target: recovery.target,
                    action: crate::observation::RevisionAction::LocalRendering,
                    reason: recovery.reason,
                },
            );
        }
        Ok(record)
    }
}
