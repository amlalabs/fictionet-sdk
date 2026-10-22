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
            assert_eq!(mentions[0]["title"], title);
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
        let queries: Vec<_> = mentions.iter().map(|m| m["query"].clone()).collect();
        assert_eq!(queries, [json!("first"), json!("second")]);
        assert!(
            mentions
                .iter()
                .all(|m| m["title"] == "first" && m["rank"] == 1)
        );
        assert_eq!(mentions[1]["snippet"], "Snippet for second.");
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
fn anthropic_answers_keep_tokens_and_where_they_stopped() {
    let reply = json!({
        "model": "answered/model",
        "content": [{"type": "text", "text": SEARCH}],
        "usage": {"input_tokens": 20, "output_tokens": 10},
        "stop_reason": "max_tokens",
    });
    let fake = Fake::script(vec![(ms(100), Ok((200, reply.to_string().into_bytes())))]);
    let key = Key::new("ANTHROPIC_API_KEY", Some(KEY.into())).unwrap();
    let model = Model::new(Provider::Anthropic, "", "", key, fake.clone());
    assert_eq!(model.model, Provider::Anthropic.default_model());
    let (tx, rx) = std::sync::mpsc::channel();
    lab(|cx| async move {
        let (answer, ledger) = model
            .ask(&cx, "system", "user", 100, prompts::read_search)
            .await;
        tx.send((
            answer.is_ok(),
            ledger.usage(),
            ledger.attempts[0].raw.clone(),
        ))
        .unwrap();
        Ok(())
    });
    let (ok, usage, raw) = rx.recv().unwrap();
    assert!(ok);
    assert_eq!(
        (
            usage.input_tokens,
            usage.output_tokens,
            usage.cost_unknown,
            usage.cut_off
        ),
        (Some(20), Some(10), 1, true)
    );
    assert_eq!(usage.cost, None);
    assert_eq!(raw.as_deref(), Some(SEARCH));
    let requests = fake.requests.lock().unwrap();
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
