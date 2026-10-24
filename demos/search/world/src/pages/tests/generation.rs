//! Generation retries, shared titles and cost accounting.

use super::*;

#[test]
fn a_search_and_a_page_publish_one_title() {
    const URL: &str = "https://race.example-site.com/story";
    for page_first in [false, true] {
        let dir = Dir::new(&format!("race-{page_first}"));
        let search = format!(
            "RESULT\nURL: {URL}\nTITLE: first\nSNIPPET: Snippet for first.\nDATE: 1 Oct 2026"
        );
        let page = "STATUS: 200\nTITLE: Story\nDESCRIPTION: The story.\nSITE_CSS: body {color: #234}\nBODY:\n<h1>Story</h1>";
        // A list takes 10 ms to write, a page 50 ms; the second request
        // starts 20 ms after the first.
        let fake = Fake::new(move |_, body| {
            let prompt = body["messages"][1]["content"].as_str().unwrap();
            if prompt.contains("Someone searched for") {
                completion(10, &search, Some(0.001))
            } else {
                completion(50, page, Some(0.001))
            }
        });
        let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
        no_cast(&pages);
        lab(|cx| async move {
            let (search_tx, search_rx) = tokio::sync::oneshot::channel();
            let (page_tx, page_rx) = tokio::sync::oneshot::channel();
            let searching = pages.clone();
            let search = move |cx: Cx| async move {
                let _ = search_tx.send(google(&searching, &cx, "first").await);
                Ok(())
            };
            let getting = pages.clone();
            let page = move |cx: Cx| async move {
                let _ = page_tx.send(get(&getting, &cx, URL).await);
                Ok(())
            };
            if page_first {
                cx.spawn(page);
                cx.sleep(ms(20)).await?;
                cx.spawn(search);
            } else {
                cx.spawn(search);
                cx.sleep(ms(20)).await?;
                cx.spawn(page);
            }
            let (listed, direct) = (search_rx.await.unwrap(), page_rx.await.unwrap());
            let title = if page_first { "Story" } else { "first" };
            assert_eq!(results(&listed.body), [(URL.to_owned(), title.to_owned())]);
            assert_eq!(direct.logged()["title"], title);
            assert!(
                String::from_utf8_lossy(&direct.body).contains(&format!("<title>{title}</title>"))
            );
            let store = pages.store();
            let mentions = store.mentions("race.example-site.com", "/story");
            assert_eq!(mentions.len(), 1);
            assert_eq!(mentions[0].title(), Some(title));
            let snippet = if page_first {
                "The story."
            } else {
                "Snippet for first."
            };
            assert_eq!(
                store.search("first").unwrap().search.results[0].snippet,
                snippet
            );
            Ok(())
        });
    }
}

#[test]
fn competing_searches_publish_one_title() {
    const URL: &str = "https://race.example-site.com/story";
    let dir = Dir::new("race-searches");
    let fake = Fake::new(move |_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        if let Some(query) = prompt
            .strip_prefix("Someone searched for: ")
            .and_then(|p| p.lines().next())
        {
            let answer =
                format!("RESULT\nURL: {URL}\nTITLE: {query}\nSNIPPET: Snippet for {query}.");
            completion(10, &answer, Some(0.001))
        } else {
            completion(10, PAGE, Some(0.001))
        }
    });
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let other = pages.clone();
        cx.spawn(move |cx| async move {
            cx.sleep(ms(5)).await?;
            let _ = tx.send(google(&other, &cx, "second").await);
            Ok(())
        });
        let first = google(&pages, &cx, "first").await;
        let second = rx.await.unwrap();
        for listed in [&first, &second] {
            assert_eq!(
                results(&listed.body),
                [(URL.to_owned(), "first".to_owned())]
            );
        }
        let page = get(&pages, &cx, URL).await;
        assert_eq!(page.logged()["title"], "first");
        let store = pages.store();
        let mentions = store.mentions("race.example-site.com", "/story");
        let queries: Vec<_> = mentions
            .iter()
            .map(|m| match m {
                Mention::Search { query, .. } => json!(query),
                _ => panic!("search mention"),
            })
            .collect();
        assert_eq!(queries, [json!("first"), json!("second")]);
        assert!(
            mentions
                .iter()
                .all(|m| matches!(m, Mention::Search { title, rank: 1, .. } if title == "first"))
        );
        assert_eq!(mentions[1].snippet(), Some("Snippet for second."));
        Ok(())
    });
}

#[test]
fn a_retried_failure_counts_in_the_generation() {
    let (page, rows, record) = ledger_page(
        "ledger-retry",
        Fake::script(vec![
            http_error(100, 429),
            completion(250, PAGE, Some(0.0021)),
        ]),
    );
    let usage = record.unwrap().usage.unwrap();
    assert_eq!(column(&rows, "outcome"), [json!("http 429"), json!("ok")]);
    assert_eq!(column(&rows, "ms"), [json!(100), json!(250)]);
    assert_eq!(column(&rows, "terminal"), [json!(false), json!(true)]);
    assert_eq!(column(&rows, "backoff_ms"), [json!(1500), json!(0)]);
    assert_eq!(
        (usage.attempts, usage.asks, usage.gen_ms, usage.call_ms),
        (2, 1, 1850, Some(250))
    );
    assert_eq!(page.logged()["gen_ms"], 1850);
    assert_eq!((usage.cost_known, usage.cost_unknown), (0.0021, 1));
    assert_eq!(
        (usage.cost, usage.input_tokens, usage.output_tokens),
        (None, None, None)
    );
    assert_eq!(rows[1]["generation"]["status"], "ok");
    assert_eq!(
        (&rows[1]["model"], &rows[1]["raw"]),
        (&json!("answered/model"), &json!(PAGE))
    );
    for row in &rows {
        assert_eq!(
            (&row["kind"], &row["url"]),
            (&json!("page"), &json!("https://example.com/story"))
        );
    }
}

#[test]
fn exhausted_attempts_fail_with_their_totals() {
    let (page, rows, record) = ledger_page(
        "ledger-exhausted",
        Fake::script(vec![
            http_error(100, 503),
            http_error(200, 429),
            http_error(300, 529),
        ]),
    );
    assert!(record.is_none());
    assert_eq!(page.status, 503);
    assert!(
        page.logged()["error"]
            .as_str()
            .unwrap()
            .contains("HTTP 529")
    );
    assert_eq!(column(&rows, "attempt"), [json!(1), json!(2), json!(3)]);
    assert_eq!(
        column(&rows, "cost"),
        [Value::Null, Value::Null, Value::Null]
    );
    let usage = &rows[2]["generation"];
    assert_eq!(
        (&usage["status"], &usage["gen_ms"], &usage["backoff_ms"]),
        (&json!("error"), &json!(5100), &json!(4500))
    );
    assert_eq!(
        (
            &usage["attempts"],
            &usage["cost_known"],
            &usage["cost_unknown"]
        ),
        (&json!(3), &json!(0.0), &json!(3))
    );
    assert!(usage["call_ms"].is_null() && usage["cost"].is_null());
    assert_eq!(page.logged()["gen_ms"], 5100);
}

#[test]
fn transport_failures_are_retried_after_a_backoff() {
    let (_, rows, record) = ledger_page(
        "ledger-transport",
        Fake::script(vec![
            (ms(100), Err("timed out".into())),
            (ms(200), Err(format!("connection lost with {KEY}"))),
            completion(300, PAGE, Some(0.0021)),
        ]),
    );
    assert!(record.is_some());
    assert_eq!(
        column(&rows, "outcome"),
        [json!("transport"), json!("transport"), json!("ok")]
    );
    assert_eq!(
        column(&rows, "backoff_ms"),
        [json!(1500), json!(3000), json!(0)]
    );
    assert_eq!(rows[2]["generation"]["gen_ms"], 5100);
    assert_eq!(rows[2]["generation"]["call_ms"], 300);
    assert_eq!(
        rows[1]["error"],
        "connection lost with <OPENROUTER_API_KEY>"
    );
}

#[test]
fn an_unknown_cost_is_not_zero() {
    let (_, rows, _) = ledger_page(
        "ledger-unknown",
        Fake::script(vec![
            completion(100, "unreadable", Some(0.1)),
            completion(200, PAGE, None),
        ]),
    );
    let usage = &rows[1]["generation"];
    assert!(usage["cost"].is_null());
    assert_eq!(
        (&usage["cost_known"], &usage["cost_unknown"]),
        (&json!(0.1), &json!(1))
    );
    assert_eq!(
        (&usage["input_tokens"], &usage["output_tokens"]),
        (&json!(2000), &json!(1000))
    );
    assert_eq!((&usage["attempts"], &usage["asks"]), (&json!(2), &json!(2)));
}

#[test]
fn an_unreadable_answer_then_transport_failures_count_every_attempt() {
    let mut replies = vec![completion(100, "unreadable", Some(0.0021))];
    replies.extend((0..3).map(|_| (ms(200), Err("timed out".to_owned()))));
    let (page, rows, record) = ledger_page("ledger-mixed", Fake::script(replies));
    assert!(record.is_none());
    let asks: Vec<_> = rows
        .iter()
        .map(|r| (r["ask"].clone(), r["attempt"].clone()))
        .collect();
    assert_eq!(
        asks,
        [
            (json!(1), json!(1)),
            (json!(2), json!(1)),
            (json!(2), json!(2)),
            (json!(2), json!(3))
        ]
    );
    let usage = &rows[3]["generation"];
    assert_eq!(
        (&usage["attempts"], &usage["asks"], &usage["gen_ms"]),
        (&json!(4), &json!(2), &json!(5200))
    );
    assert_eq!(
        (&usage["cost_known"], &usage["cost_unknown"]),
        (&json!(0.0021), &json!(3))
    );
    assert!(usage["cost"].is_null() && page.logged()["cost"].is_null());
    assert_eq!(page.logged()["gen_ms"], 5200);
}

#[test]
fn a_permanent_error_is_not_retried() {
    let dir = Dir::new("ledger-cast");
    let fake = Fake::script(vec![http_error(100, 401)]);
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    lab(|cx| async move {
        assert!(pages.cast(&cx).await.is_err());
        Ok(())
    });
    let rows = dir.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0]["kind"], &rows[0]["outcome"]),
        (&json!("cast"), &json!("http 401"))
    );
    assert_eq!(rows[0]["generation"]["gen_ms"], 100);
}

#[test]
fn provider_errors_and_invalid_json_are_recorded() {
    let error = json!({"error": {"message": "failed"}});
    let (_, rows, record) = ledger_page(
        "ledger-provider",
        Fake::script(vec![
            (ms(100), Ok((200, b"not JSON".to_vec()))),
            (ms(200), Ok((200, error.to_string().into_bytes()))),
        ]),
    );
    assert!(record.is_none());
    assert_eq!(
        column(&rows, "outcome"),
        [json!("unreadable"), json!("unreadable")]
    );
    assert_eq!(rows[1]["generation"]["status"], "error");
    assert_eq!(rows[1]["generation"]["cost_unknown"], 2);
}

#[test]
fn a_reported_failure_cost_is_kept() {
    let failed = json!({"usage": {"cost": 0.003, "prompt_tokens": 100, "completion_tokens": 0}});
    let (_, rows, _) = ledger_page(
        "ledger-failure-cost",
        Fake::script(vec![
            (ms(100), Ok((503, failed.to_string().into_bytes()))),
            completion(200, PAGE, Some(0.0021)),
        ]),
    );
    assert_eq!(column(&rows, "cost"), [json!(0.003), json!(0.0021)]);
    let usage = &rows[1]["generation"];
    assert!((usage["cost"].as_f64().unwrap() - 0.0051).abs() < 1e-12);
    assert_eq!(
        (
            &usage["cost_unknown"],
            &usage["input_tokens"],
            &usage["output_tokens"]
        ),
        (&json!(0), &json!(1100), &json!(500))
    );
}

#[test]
fn invalid_usage_stays_unknown() {
    let reply = json!({
        "model": "answered/model",
        "choices": [{"message": {"content": PAGE}}],
        "usage": {"cost": "unavailable", "prompt_tokens": false, "completion_tokens": -1},
    });
    let (_, rows, _) = ledger_page(
        "ledger-usage",
        Fake::script(vec![(ms(100), Ok((200, reply.to_string().into_bytes())))]),
    );
    assert_eq!(rows.len(), 1);
    for key in ["cost", "input_tokens", "output_tokens"] {
        assert!(rows[0][key].is_null(), "{key}");
        assert!(rows[0]["generation"][key].is_null(), "{key}");
    }
    assert_eq!(rows[0]["generation"]["cost_unknown"], 1);
}

#[test]
fn cut_off_answers_are_rewritten_and_every_attempt_is_counted() {
    let reply = json!({
        "model": "answered/model",
        "content": [{"type": "text", "text": SEARCH}],
        "usage": {"input_tokens": 20, "output_tokens": 10},
        "stop_reason": "max_tokens",
    });
    let mut complete = reply.clone();
    complete["stop_reason"] = json!("end_turn");
    let fake = Fake::script(vec![
        (ms(100), Ok((200, reply.to_string().into_bytes()))),
        (ms(100), Ok((200, complete.to_string().into_bytes()))),
    ]);
    let key = Key::new("ANTHROPIC_API_KEY", Some(KEY.into())).unwrap();
    let model = Model::new(Provider::Anthropic, "", "", key, fake.clone());
    assert_eq!(model.model, Provider::Anthropic.default_model());
    let (tx, rx) = std::sync::mpsc::channel();
    lab(|cx| async move {
        let (answer, ledger) = model
            .ask(&cx, "system", "user", 100, prompts::read_search, |_| {})
            .await;
        tx.send((
            answer.is_ok(),
            ledger.usage(),
            ledger.attempts[0].raw.clone(),
            ledger.attempts[0].cut_off,
        ))
        .unwrap();
        Ok(())
    });
    let (ok, usage, raw, cut_off) = rx.recv().unwrap();
    assert!(cut_off);
    assert_eq!((usage.attempts, usage.asks), (2, 2));
    assert!(ok);
    assert_eq!(
        (
            usage.input_tokens,
            usage.output_tokens,
            usage.cost_unknown,
            usage.cut_off
        ),
        (Some(40), Some(20), 2, false)
    );
    assert_eq!(usage.cost, None);
    assert!(raw.is_none());
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].1["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("output limit")
    );
    let (headers, body) = &requests[0];
    assert!(headers.contains(&("x-api-key", KEY.to_owned())));
    assert_eq!(
        (&body["system"], &body["max_tokens"]),
        (&json!("system"), &json!(100))
    );
}

#[test]
fn captured_model_pages_use_the_container_without_a_stylesheet_call() {
    let fake = Fake::new(|_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        assert!(prompt.contains("div class=\"body\" role=\"main\""));
        assert!(!prompt.contains("SITE_CSS:"));
        completion(
            0,
            "STATUS: 200\nTITLE: Paths\nBODY:\n<h1>Paths</h1><p>Read directories with pathlib.</p>",
            Some(0.001),
        )
    });
    let pages = Arc::new(Pages::open(
        seed(),
        Store::memory(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    ));
    no_cast(&pages);
    lab(move |cx| async move {
        let response = get(
            &pages,
            &cx,
            "https://docs.python.org/3/library/pathlib.html",
        )
        .await;
        assert_eq!(response.status, 200);
        let html = std::str::from_utf8(&response.body).unwrap();
        assert!(html.contains("Read directories with pathlib."));
        let stylesheet = {
            let dom = kuchiki::traits::TendrilSink::one(kuchiki::parse_html(), html);
            dom.select_first("link[rel=stylesheet]")
                .unwrap()
                .attributes
                .borrow()
                .get("href")
                .unwrap()
                .to_owned()
        };
        for path in [
            stylesheet.as_str(),
            "/_assets/missing.css",
            "/_assets/../page.html",
        ] {
            let asset = pages
                .handle(&cx, "GET", "docs.python.org", path, None)
                .await;
            assert_eq!(asset.status, if path == stylesheet { 200 } else { 404 });
            assert!(matches!(asset.meta, Meta::Asset));
        }
        assert_eq!(fake.users().len(), 1);
        Ok(())
    });
}

#[test]
fn captured_stored_pages_and_assets_are_available_with_generation_off() {
    let pages = plain();
    lab(move |cx| async move {
        let response = get(&pages, &cx, "https://en.wikipedia.org/wiki/Directories").await;
        assert_eq!(response.status, 200);
        let html = std::str::from_utf8(&response.body).unwrap();
        assert!(html.contains("mw-body"));
        assert!(html.contains("/_assets/"));
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: pages.generation().revision,
                },
            )
            .unwrap();
        let stylesheet = {
            let dom = kuchiki::traits::TendrilSink::one(kuchiki::parse_html(), html);
            dom.select_first("link[rel=stylesheet]")
                .unwrap()
                .attributes
                .borrow()
                .get("href")
                .unwrap()
                .to_owned()
        };
        let asset = pages
            .handle(&cx, "GET", "en.wikipedia.org", &stylesheet, None)
            .await;
        assert_eq!(asset.status, 200);
        assert!(asset.content_type.starts_with("text/css"));
        let cached = get(&pages, &cx, "https://en.wikipedia.org/wiki/Directories").await;
        assert_eq!(cached.body, response.body);
        Ok(())
    });
}

#[test]
fn concurrent_interactive_searches_share_the_first_lists_promises() {
    let fake = Fake::new(|_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        let query = prompt
            .strip_prefix("Someone searched for: ")
            .unwrap()
            .lines()
            .next()
            .unwrap();
        completion(
            20,
            &format!(
                "RESULT\nURL: https://news.fields.com/{query}\nTITLE: Cable incident {query}\nSNIPPET: Cable operator Lumenwave reported the break on 8 October 2026."
            ),
            None,
        )
    });
    let mut pages = Pages::with_model(seed(), openrouter(fake.clone()));
    pages.prefetch = 0;
    let pages = Arc::new(pages);
    lab(move |cx| async move {
        let other = pages.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        cx.spawn(move |cx| async move {
            send.send(google(&other, &cx, "cable cause").await).unwrap();
            Ok(())
        });
        assert_eq!(google(&pages, &cx, "cable incident").await.status, 200);
        assert_eq!(receive.await.unwrap().status, 200);
        let prompts = fake.users();
        assert_eq!(prompts.len(), 2);
        assert!(
            prompts[1].contains("Cable operator Lumenwave reported the break on 8 October 2026.")
        );
        Ok(())
    });
}

#[test]
fn source_changes_drop_writers_and_queued_searches() {
    struct Held {
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        calls: AtomicUsize,
        dropped: Arc<AtomicUsize>,
    }
    struct InFlight(Arc<AtomicUsize>);
    impl Drop for InFlight {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Transport for Held {
        fn post<'a>(&'a self, _: &'a Cx, _: Headers, _: Vec<u8>) -> Post<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let _inflight = InFlight(self.dropped.clone());
                if let Some(started) = self.started.lock().unwrap().take() {
                    started.send(()).unwrap();
                }
                std::future::pending().await
            })
        }
    }
    for restart in [false, true] {
        let (started, ready) = tokio::sync::oneshot::channel();
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(Held {
            started: Mutex::new(Some(started)),
            calls: AtomicUsize::new(0),
            dropped: dropped.clone(),
        });
        let model = Model::new(
            Provider::OpenRouter,
            "small",
            "",
            Key::new("provider key", Some(KEY.into())).unwrap(),
            held.clone(),
        );
        let pages = Arc::new(Pages::with_model(seed(), model));
        lab(move |cx| async move {
            let (done, response) = tokio::sync::oneshot::channel();
            let searching = pages.clone();
            cx.spawn(move |cx| async move {
                let result = fictionet_extras::models::Engine::search(
                    searching,
                    cx,
                    "cable incident".into(),
                    Default::default(),
                )
                .await;
                done.send(result.is_err()).unwrap();
                Ok(())
            });
            ready.await.unwrap();
            let (queued, entered) = tokio::sync::oneshot::channel();
            let (done, queued_response) = tokio::sync::oneshot::channel();
            let searching = pages.clone();
            cx.spawn(move |cx| async move {
                queued.send(()).unwrap();
                done.send(google(&searching, &cx, "cable cause").await.status)
                    .unwrap();
                Ok(())
            });
            entered.await.unwrap();
            let revision = pages.generation().revision;
            pages
                .apply(
                    &cx,
                    if restart {
                        Command::Restart {
                            expected_revision: revision,
                        }
                    } else {
                        Command::SetNewPages {
                            new_pages: NewPages::Off,
                            expected_revision: revision,
                        }
                    },
                )
                .unwrap();
            assert!(response.await.unwrap());
            assert_eq!(queued_response.await.unwrap(), 503);
            assert_eq!(held.calls.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(pages.store().searches().count(), 0);
            assert_eq!(pages.store().pages().count(), 0);
            Ok(())
        });
    }
}

#[test]
fn written_pages_rewrite_future_knowledge_and_respect_referring_datelines() {
    let fake = Fake::script(vec![
        completion(
            0,
            "STATUS: 200\nTITLE: Cable report\nDATE: 2026-10-07\nCLAIMS:\n- 2026-10-14 | The report confirmed the incident on 14 October 2026.\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Cable report</h1><p>The cable incident occurred on 6 October 2026. The report of 14 October 2026 confirms it.</p><a href='https://research.fields.com/analysis'>Analysis</a>",
            None,
        ),
        completion(
            0,
            &json!({"edits":[{"before":"DATE: 2026-10-07","after":"DATE: 2026-10-14"},{"before":"<h1>Cable report</h1>","after":"<h1>Cable report</h1><p>Published 7 October 2026. Updated 14 October 2026.</p>"}]}).to_string(),
            None,
        ),
        completion(
            0,
            "STATUS: 200\nTITLE: Cable analysis\nDATE: 2026-10-15\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Cable analysis</h1><p>The cable incident occurred on 6 October 2026.</p>",
            None,
        ),
        completion(
            0,
            &json!({"edits":[{"before":"DATE: 2026-10-15","after":"DATE: 2026-10-14"}]}).to_string(),
            None,
        ),
    ]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    lab(move |cx| async move {
        let first = get(&pages, &cx, "https://news.fields.com/report").await;
        assert_eq!(first.status, 200);
        assert_eq!(
            pages
                .store()
                .page("news.fields.com", "/report")
                .unwrap()
                .date,
            "2026-10-14"
        );
        let next = get(&pages, &cx, "https://research.fields.com/analysis").await;
        assert_eq!(next.status, 200);
        assert_eq!(
            pages
                .store()
                .page("research.fields.com", "/analysis")
                .unwrap()
                .date,
            "2026-10-14"
        );
        assert_eq!(fake.users().len(), 4);
        assert!(fake.users()[3].contains("latest permitted publication/update date is 2026-10-14"));
        Ok(())
    });
}

#[test]
fn calendar_dates_and_article_destinations_are_preserved() {
    assert_eq!(
        crate::pages::answers::dates(
            "2026-10-14; 14 October 2026; October 14, 2026; 14 Oct 2026; Oct 14, 2026"
        ),
        vec![seed::parse_date("2026-10-14").unwrap(); 5]
    );
    let url = "https://news.fields.com/article-aBc3dEf9";
    let fake = Fake::script(vec![completion(
        0,
        &format!("{PAGE}<a href='{url}#summary'>Summary</a><a href='{url}#details'>Details</a>"),
        None,
    )]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake)));
    lab(move |cx| async move {
        let page = get(&pages, &cx, url).await;
        assert_eq!(page.status, 200);
        let body = String::from_utf8(page.body).unwrap();
        assert!(body.contains(&format!("{url}#summary")));
        assert!(body.contains(&format!("{url}#details")));
        assert_eq!(
            pages
                .store()
                .page("news.fields.com", "/article-aBc3dEf9")
                .unwrap()
                .url,
            url
        );
        Ok(())
    });
}

#[test]
fn an_earlier_article_can_link_to_a_page_updated_later() {
    let fake = Fake::script(vec![
        completion(
            0,
            "STATUS: 200\nTITLE: Recall\nDATE: 2026-10-20\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Recall</h1><p>The recall began on 17 September 2026.</p><a href='https://news.fields.com/recall'>Coverage</a>",
            None,
        ),
        completion(
            0,
            "STATUS: 200\nTITLE: Recall coverage\nDATE: 2026-09-18\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Recall coverage</h1><p>The recall began on 17 September 2026.</p><a href='https://manufacturer.fields.com/recall'>Manufacturer recall</a>",
            None,
        ),
    ]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    lab(move |cx| async move {
        assert_eq!(
            get(&pages, &cx, "https://manufacturer.fields.com/recall")
                .await
                .status,
            200
        );
        assert_eq!(
            get(&pages, &cx, "https://news.fields.com/recall")
                .await
                .status,
            200
        );
        assert_eq!(
            pages
                .store()
                .page("news.fields.com", "/recall")
                .unwrap()
                .date,
            "2026-09-18"
        );
        assert_eq!(fake.users().len(), 2);
        Ok(())
    });
}

#[test]
fn search_publication_dates_constrain_both_ends_of_a_citation() {
    let pages = plain();
    let published = seed::parse_date("2026-10-02").unwrap();
    let today = seed::parse_date("2026-10-21").unwrap();
    let mut store = pages.store();
    let first = store
        .reserve_mention(
            &seed(),
            "news.fields.com",
            "/analysis",
            serde_json::from_value::<crate::pages::provenance::Mention>(
                json!({"via":"search","title":"Analysis","date":"Oct 2, 2026"}),
            )
            .unwrap(),
        )
        .unwrap();
    let next = store
        .reserve_mention(
            &seed(),
            "news.fields.com",
            "/analysis",
            serde_json::from_value::<crate::pages::provenance::Mention>(
                json!({"via":"search","title":"Analysis","date":"Oct 7, 2026"}),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        store.publication_date("news.fields.com", "/analysis"),
        Some(published)
    );
    assert_eq!(first.date(), next.date());
    let mut page = make::Page {
        date: "2026-09-19".into(),
        content_type: "text/html".into(),
        body: "<p>Coverage</p><a href='https://news.fields.com/analysis'>Analysis</a>".into(),
        ..Default::default()
    };
    assert!(
        pages
            .check_page_dates(&store, "news.fields.com", "/coverage", &page, today)
            .is_err()
    );
    page.body = "<p>Analysis.</p>".into();
    assert!(
        pages
            .check_page_dates(&store, "news.fields.com", "/analysis", &page, today)
            .is_err()
    );
    page.date = published.to_string();
    assert!(
        pages
            .check_page_dates(&store, "news.fields.com", "/analysis", &page, today)
            .is_ok()
    );
    assert_eq!(
        pages.latest_publication(
            &store,
            "news.fields.com",
            "/analysis",
            &[serde_json::from_value::<crate::pages::provenance::Mention>(
                json!({"via":"link","from":"https://news.fields.com/coverage"})
            )
            .unwrap()]
        ),
        today
    );
}

#[test]
fn the_headline_obeys_the_document_dateline() {
    let page = make::Page {
        title: "Investigation results on 14 October 2026".into(),
        claims: vec![prompts::Statement {
            text: "The investigation results were released on 14 October 2026.".into(),
            known_on: Some(seed::parse_date("2026-10-14").unwrap()),
        }],
        date: "2026-10-07".into(),
        body: "<p>The investigation continues.</p>".into(),
        content_type: "text/html".into(),
        ..Default::default()
    };
    assert!(
        crate::pages::answers::chronology(&page, seed::parse_date("2026-10-21").unwrap()).is_err()
    );
}

#[test]
fn linked_pages_receive_the_complete_referring_document() {
    let calls = AtomicUsize::new(0);
    let fake = Fake::new(move |_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            completion(
                0,
                &format!(
                    "STATUS: 200\nTITLE: Recall\nDATE: 2026-10-14\nSITE_CSS: body {{color:#234}}\nBODY:\n<h1>Recall</h1><p>{}</p><p>The charging guidance was issued on 12 October 2026: <a href='https://guidance.fields.com/charging'>Charging guidance</a>.</p>",
                    "Background information. ".repeat(300)
                ),
                None,
            )
        } else {
            assert!(prompt.contains("The charging guidance was issued on 12 October 2026"));
            completion(
                0,
                "STATUS: 200\nTITLE: Charging guidance\nDATE: 2026-10-14\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Charging guidance</h1><p>Issued on 12 October 2026. Updated on 14 October 2026.</p>",
                None,
            )
        }
    });
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake)));
    lab(move |cx| async move {
        assert_eq!(
            get(&pages, &cx, "https://news.fields.com/recall")
                .await
                .status,
            200
        );
        assert_eq!(
            get(&pages, &cx, "https://guidance.fields.com/charging")
                .await
                .status,
            200
        );
        Ok(())
    });
}

#[test]
fn future_plans_are_known_when_announced() {
    let page = make::Page {
        date: "2026-09-24".into(),
        body: "<p>Replacement kits will begin shipping on 5 October 2026.</p>".into(),
        claims: vec![prompts::Statement {
            text: "Shipping is planned for 5 October 2026.".into(),
            known_on: Some(seed::parse_date("2026-09-24").unwrap()),
        }],
        content_type: "text/html".into(),
        ..Default::default()
    };
    assert!(
        crate::pages::answers::chronology(&page, seed::parse_date("2026-10-24").unwrap()).is_ok()
    );
}

#[test]
fn search_promises_allow_parallel_first_sources() {
    struct Peer {
        ready: tokio::sync::Barrier,
        started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        fake: Arc<Fake>,
    }
    impl Transport for Peer {
        fn post<'a>(&'a self, cx: &'a Cx, headers: Headers, body: Vec<u8>) -> Post<'a> {
            Box::pin(async move {
                if let Some(started) = self.started.lock().unwrap().take() {
                    let _ = started.send(());
                }
                self.ready.wait().await;
                self.fake.post(cx, headers, body).await
            })
        }
    }
    for (first, second, first_listed) in [
        (
            "https://news.fields.com/reference",
            "https://research.fields.com/reference",
            true,
        ),
        (
            "https://news.fields.com/reference",
            "https://news.fields.com/appendix",
            true,
        ),
        (
            "https://research.fields.com/opaque-a123",
            "https://news.fields.com/reference",
            false,
        ),
    ] {
        let fake = Fake::new(move |_, body| {
            let prompt = body["messages"][1]["content"].as_str().unwrap();
            if first_listed || prompt.starts_with(&format!("Write the page at: {second}")) {
                assert!(prompt.contains("Reference guidance was published on 1 October 2026."));
            }
            completion(
                0,
                "STATUS: 200\nTITLE: Reference\nDATE: 2026-10-01\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Reference</h1><p>Reference guidance was published on 1 October 2026.</p>",
                None,
            )
        });
        let (started, waiting) = tokio::sync::oneshot::channel();
        let model = Model::new(
            Provider::OpenRouter,
            "small",
            "",
            Key::new("provider key", Some(KEY.into())).unwrap(),
            Arc::new(Peer {
                ready: tokio::sync::Barrier::new(2),
                started: Mutex::new(Some(started)),
                fake: fake.clone(),
            }),
        );
        let pages = Arc::new(Pages::with_model(seed(), model));
        pages
            .store()
            .insert_search(SearchRecord {
                key: "reference".into(),
                query: "reference".into(),
                usage: Usage::stored(0),
                search: search::Search {
                    results: [first, second]
                        .into_iter()
                        .filter(|url| first_listed || *url == second)
                        .map(|url| search::Result {
                            url: url.into(),
                            title: "Reference".into(),
                            date: "1 Oct 2026".into(),
                            snippet: "Reference guidance was published on 1 October 2026.".into(),
                        })
                        .collect(),
                    ..Default::default()
                },
            })
            .unwrap();
        lab(move |cx| async move {
            let other = pages.clone();
            let (done, response) = tokio::sync::oneshot::channel();
            cx.spawn(move |cx| async move {
                done.send(get(&other, &cx, first).await).unwrap();
                Ok(())
            });
            waiting.await.unwrap();
            assert_eq!(get(&pages, &cx, second).await.status, 200);
            assert_eq!(response.await.unwrap().status, 200);
            if text::target_of(first).0 == text::target_of(second).0 {
                assert_eq!(
                    fake.users()
                        .iter()
                        .filter(|prompt| prompt.contains("SITE_CSS:"))
                        .count(),
                    1
                );
                assert_eq!(pages.store().host_pages(&text::target_of(first).0).len(), 2);
            }
            Ok(())
        });
    }
}

#[test]
fn readers_wait_for_chronology_rewrites_and_share_the_finished_page() {
    let bad = "STATUS: 200\nTITLE: Investigation\nDATE: 2026-10-07\nCLAIMS:\n- 2026-10-14 | The investigation concluded on 14 October 2026.\nSITE_CSS: body {color:#234}\nBODY:\n<h1>Investigation</h1><p>The investigation concluded on 14 October 2026.</p>";
    let fake = Fake::script(vec![
        completion(10, bad, None),
        completion(
            10,
            &json!({"edits":[{"before":"DATE: 2026-10-07","after":"DATE: 2026-10-07"}]})
                .to_string(),
            None,
        ),
        completion(
            10,
            &json!({"edits":[{"before":"DATE: 2026-10-07","after":"DATE: 2026-10-14"}]})
                .to_string(),
            None,
        ),
    ]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    lab(move |cx| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let peer = pages.clone();
        cx.spawn(move |cx| async move {
            tx.send(get(&peer, &cx, "https://news.fields.com/investigation").await)
                .unwrap();
            Ok(())
        });
        let first = get(&pages, &cx, "https://news.fields.com/investigation").await;
        let second = rx.await.unwrap();
        assert_eq!((first.status, second.status), (200, 200));
        assert_eq!(first.body, second.body);
        assert_eq!(fake.users().len(), 3);
        assert_eq!(
            pages
                .store()
                .page("news.fields.com", "/investigation")
                .unwrap()
                .date,
            "2026-10-14"
        );
        Ok(())
    });
}

#[test]
fn undeclared_later_knowledge_is_reviewed_before_publication() {
    let fake = Fake::script(vec![
        completion(
            0,
            "STATUS: 200\nTITLE: Investigation\nDATE: 2026-10-07\nSITE_CSS: body {color:#234}\nBODY:\n<p>The investigation concluded on 14 October 2026.</p>",
            None,
        ),
        completion(
            0,
            r#"{"chronology":"later_knowledge","reason":"The investigation's conclusion could first be known on 2026-10-14, after publication on 2026-10-07."}"#,
            None,
        ),
        completion(
            0,
            &json!({"edits":[{"before":"DATE: 2026-10-07","after":"DATE: 2026-10-14"},{"before":"BODY:\n","after":"BODY:\n<p>Published 7 October 2026. Updated 14 October 2026.</p>"}]}).to_string(),
            None,
        ),
    ]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    no_cast(&pages);
    lab(move |cx| async move {
        let response = get(&pages, &cx, "https://news.fields.com/investigation").await;
        assert_eq!(response.status, 200);
        let store = pages.store();
        let page = store.page("news.fields.com", "/investigation").unwrap();
        assert_eq!(page.date, "2026-10-14");
        assert!(page.claims.is_empty());
        let users = fake.users();
        assert_eq!(users.len(), 3);
        assert!(users[1].contains("PUBLICATION: 2026-10-07"));
        assert!(users[1].contains("The investigation concluded on 14 October 2026"));
        assert!(users[2].contains("could first be known on 2026-10-14"));
        Ok(())
    });
}

#[test]
fn later_search_snippets_and_announced_plans_receive_semantic_review() {
    let fake = Fake::script(vec![
        completion(
            0,
            "RESULT\nURL: https://news.fields.com/investigation\nTITLE: Investigation results\nDATE: Oct 7, 2026\nSNIPPET: The investigation concluded on 14 October 2026.",
            None,
        ),
        completion(
            0,
            r#"{"chronology":"later_knowledge","reason":"A conclusion on 2026-10-14 cannot be reported as completed on 2026-10-07."}"#,
            None,
        ),
        completion(
            0,
            &json!({"edits":[{"before":"DATE: Oct 7, 2026","after":"DATE: Oct 14, 2026"}]})
                .to_string(),
            None,
        ),
        completion(
            0,
            "STATUS: 200\nTITLE: Investigation results\nDATE: 2026-10-14\nSITE_CSS: body {color:#234}\nBODY:\n<p>The investigation concluded on 14 October 2026. A follow-up hearing is scheduled for 28 October 2026.</p>",
            None,
        ),
        completion(0, r#"{"chronology":"consistent"}"#, None),
    ]);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    no_cast(&pages);
    lab(move |cx| async move {
        let response = google(&pages, &cx, "investigation results").await;
        assert_eq!(response.status, 200);
        let response = get(&pages, &cx, "https://news.fields.com/investigation").await;
        assert_eq!(response.status, 200);
        let users = fake.users();
        assert_eq!(users.len(), 5);
        assert!(users[1].contains("PUBLICATION: 2026-10-07"));
        assert!(users[4].contains("A follow-up hearing is scheduled for 28 October 2026"));
        let store = pages.store();
        let context = store.writing_context("investigation results");
        assert!(!context.is_empty());
        assert!(
            context
                .iter()
                .all(|claim| claim.claim.known_on == Some(seed::parse_date("2026-10-14").unwrap()))
        );
        Ok(())
    });
}
