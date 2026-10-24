//! Model response parsing, usage accounting and credential redaction.

use super::*;

#[test]
fn model_pages_keep_titles_count_cost_and_never_store_the_key() {
    let dir = Dir::new("model");
    let script = Arc::new(Script::default());
    let (pages, fake) = {
        let fake = fake_openrouter(script.clone());
        let pages = on_disk(
            &dir.0,
            Seed::builtin("corvane-acquisition").unwrap(),
            Some(Maker::Model(openrouter(fake.clone()))),
            2,
        )
        .unwrap();
        (pages, fake)
    };
    let world = pages.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "corvane acquisition").await;
        assert_eq!(
            (&search.logged()["cache"], &search.logged()["cost"]),
            (&json!("generated"), &json!(0.0021))
        );
        let (url, title) = results(&search.body)[0].clone();
        // The prefetched page is ready in the background.
        cx.sleep(ms(1000)).await?;
        let page = get(&world, &cx, &url).await;
        assert_eq!(page.logged()["cache"], "prefetched");
        assert_eq!(page.status, 200, "a page a result points at is never a 404");
        let html = String::from_utf8_lossy(&page.body);
        assert!(html.contains(&format!("<title>{title}</title>")));
        assert_eq!(page.logged()["unsupported_snippets"], json!([]));
        assert_eq!(get(&world, &cx, &url).await.logged()["cache"], "cached");
        // The cast was made once, and every later prompt names it.
        assert_eq!(
            world.cast(&cx).await.ok().unwrap()[0].name,
            "Tomasz Wierzbicki"
        );
        Ok(())
    });
    let requests = fake.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|(headers, _)| headers.contains(&("authorization", format!("Bearer {KEY}"))))
    );
    drop(requests);
    assert_eq!(
        fake.systems()
            .iter()
            .filter(|s| !s.contains("Tomasz Wierzbicki"))
            .count(),
        1
    );
    drop(pages);
    assert!(dir.texts().iter().all(|text| !text.contains(KEY)));
}

#[test]
fn a_page_is_checked_against_the_mentions_its_model_was_shown() {
    let searches: Vec<_> = (0..=prompts::LINK_MENTIONS_PER_PAGE)
        .map(|i| {
            serde_json::from_value::<crate::pages::provenance::Mention>(
                json!({"via": "search", "query": format!("query {i}"), "title": "Story",
            "snippet": format!("Evidence number {i}.")}),
            )
            .unwrap()
        })
        .collect();
    let links: Vec<_> = (0..=prompts::LINK_MENTIONS_PER_PAGE)
        .map(|i| {
            serde_json::from_value::<crate::pages::provenance::Mention>(
                json!({"via": "link", "from": format!("https://source.example-site.com/{i}"),
            "anchor": format!("Source {i}")}),
            )
            .unwrap()
        })
        .collect();
    for missing in [false, true] {
        let dir = Dir::new(&format!("mentions-{missing}"));
        let script = Arc::new(Script::default());
        let (pages, fake) = model_world(&dir, &script, 0);
        no_cast(&pages);
        for mention in links.iter().chain(&searches) {
            pages
                .store()
                .add_mention("news.example-site.com", "/story", mention.clone())
                .unwrap();
        }
        let shown = if missing {
            &searches[..searches.len() - 1]
        } else {
            &searches[..]
        };
        let body: Vec<_> = shown.iter().map(|m| m.snippet().unwrap()).collect();
        script.pages.lock().unwrap().push_back(format!(
            "STATUS: 200\nCONTENT_TYPE: text/plain\nTITLE: Story\nSITE_CSS: body {{color: #234}}\nBODY:\n{}",
            body.join(" ")
        ));
        let (searches, links) = (searches.clone(), links.clone());
        lab(|cx| async move {
            let page = get(&pages, &cx, "https://news.example-site.com/story").await;
            let record = pages
                .store()
                .page("news.example-site.com", "/story")
                .unwrap()
                .clone();
            let asked: Vec<_> = links[..prompts::LINK_MENTIONS_PER_PAGE]
                .iter()
                .chain(&searches)
                .cloned()
                .collect();
            assert_eq!(record.mentions, asked);
            let prompt = fake.users().pop().unwrap();
            for mention in &searches {
                let snippet = mention.snippet().unwrap();
                assert!(prompt.contains(&format!("snippet \"{snippet}\"")));
            }
            for (i, mention) in links.iter().enumerate() {
                let from = mention.source().unwrap();
                assert_eq!(prompt.contains(from), i < prompts::LINK_MENTIONS_PER_PAGE);
            }
            let expected = if missing {
                json!([searches.last().unwrap().snippet()])
            } else {
                json!([])
            };
            assert_eq!(page.logged()["unsupported_snippets"], expected);
            assert_eq!(page.logged()["unchecked_snippets"], json!([]));
            // A stored page keeps the result of its check.
            let cached = get(&pages, &cx, "https://news.example-site.com/story").await;
            assert_eq!(cached.logged()["cache"], "cached");
            assert_eq!(cached.logged()["unsupported_snippets"], expected);
            Ok(())
        });
    }
}

#[test]
fn an_unreadable_answer_is_asked_again_and_counted() {
    let dir = Dir::new("reask");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    script.bad.store(1, Ordering::SeqCst);
    let world = pages.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "python").await;
        assert_eq!(search.logged()["results"], 10);
        assert_eq!(search.logged()["cost"], json!(0.0042));
        Ok(())
    });
    let users = fake.users();
    assert!(users[1].contains("The previous answer could not be read: no results"));
    let rows = dir.rows();
    let usage = &rows.last().unwrap()["generation"];
    assert_eq!(
        (&usage["attempts"], &usage["asks"], &usage["cost_unknown"]),
        (&json!(2), &json!(2), &json!(0))
    );
    assert_eq!(usage["cost_known"], json!(0.0042));
}

#[test]
fn two_unreadable_answers_keep_their_attempts_and_serve_503() {
    let dir = Dir::new("two-bad");
    let script = Arc::new(Script::default());
    let (pages, _) = model_world(&dir, &script, 0);
    no_cast(&pages);
    script.bad.store(2, Ordering::SeqCst);
    let world = pages.clone();
    lab(|cx| async move {
        let page = world
            .handle(&cx, "GET", "example.com", "/story", None)
            .await;
        assert_eq!(page.status, 503);
        assert_eq!(page.body, UNAVAILABLE);
        assert_eq!(page.logged()["kind"], "error");
        assert_eq!(page.logged()["cost"], json!(0.0042));
        assert!(page.logged()["error"].as_str().unwrap().contains("no BODY"));
        assert!(page.logged()["serve_ms"].is_u64());
        assert!(world.store().page("example.com", "/story").is_none());
        Ok(())
    });
    let rows = dir.rows();
    assert_eq!(
        rows.iter().map(|r| r["cost"].clone()).collect::<Vec<_>>(),
        [json!(0.0021), json!(0.0021)]
    );
    assert_eq!(
        rows.iter()
            .map(|r| r["outcome"].clone())
            .collect::<Vec<_>>(),
        [json!("unreadable"), json!("unreadable")]
    );
    let usage = &rows[1]["generation"];
    assert_eq!(
        (&usage["status"], &usage["attempts"], &usage["asks"]),
        (&json!("error"), &json!(2), &json!(2))
    );
}

#[test]
fn keys_must_be_set_and_fit_a_header() {
    for variable in ["OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"] {
        for c in ['\n', '\r', '\t', ' ', '\u{1f}', '\u{7f}', 'é', '\0'] {
            let error = Key::new(variable, Some(format!("{KEY}{c}"))).unwrap_err();
            assert_eq!(
                error,
                format!("{variable} holds characters an HTTP header cannot carry")
            );
        }
        assert_eq!(
            Key::new(variable, None).unwrap_err(),
            format!("{variable} is not set")
        );
        assert_eq!(
            Key::new(variable, Some(String::new())).unwrap_err(),
            format!("{variable} is not set")
        );
        let key = Key::new(variable, Some(KEY.into())).unwrap();
        assert_eq!(format!("{key:?}"), format!("<{variable}>"));
        assert_eq!(
            key.redact(&format!("{KEY}-long and {KEY}")),
            format!("<{variable}>-long and <{variable}>")
        );
    }
}

#[test]
fn an_echoed_key_is_never_stored_or_shown() {
    for (status, prefix) in [
        (400, String::new()),
        (400, "x".repeat(330)),
        (200, String::new()),
        (200, "x".repeat(330)),
    ] {
        let dir = Dir::new(&format!("echo-{status}-{}", prefix.len()));
        let script = Arc::new(Script::default());
        let (pages, _) = model_world(&dir, &script, 0);
        no_cast(&pages);
        script.echoes.lock().unwrap().push_back((status, prefix));
        let world = pages.clone();
        lab(|cx| async move {
            let search = google(&world, &cx, "python flaw").await;
            assert_eq!(search.status, 503);
            assert!(
                !search.logged()["error"]
                    .as_str()
                    .unwrap()
                    .contains(&KEY[..12])
            );
            Ok(())
        });
        let rows = dir.rows();
        let last = rows.last().unwrap();
        assert_eq!(last["generation"]["status"], "error");
        let error = last["error"].as_str().unwrap();
        assert!(
            error.contains("rejected Authorization: Bearer <OPENROUTER_API_KEY>"),
            "{error}"
        );
        drop(pages);
        for text in dir.texts() {
            assert!(!text.contains(&KEY[..12]));
        }
    }
}

#[test]
fn a_failed_prefetch_is_recorded_and_made_again_on_request() {
    let dir = Dir::new("prefetch-error");
    let script = Arc::new(Script::default());
    let (pages, _) = model_world(&dir, &script, 1);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(1),
        |cx| async move {
            let search = google(&world, &cx, "python flaw").await;
            let (url, _) = results(&search.body)[0].clone();
            task.bad.store(2, Ordering::SeqCst);
            cx.sleep(ms(1000)).await?;
            assert!(world.store().pages().next().is_none());
            let page = get(&world, &cx, &url).await;
            assert_eq!(
                (page.status, &page.logged()["cache"]),
                (200, &json!("generated"))
            );
            Ok(())
        },
    ))
    .unwrap();
    let rows = dir.rows();
    let diagnostic = rows.iter().find(|r| r["kind"] == "prefetch_error").unwrap();
    assert_eq!(diagnostic["record"], "diagnostic");
    assert!(diagnostic["error"].as_str().unwrap().contains("no BODY"));
    assert_eq!(diagnostic["cost"], json!(0.0042));
    assert!(diagnostic["serve_ms"].is_u64());
}

#[test]
fn model_pages_keep_their_status_type_and_body() {
    let dir = Dir::new("statuses");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    lab(|cx| async move {
        let push = |answers: &[&str]| {
            let mut queue = task.pages.lock().unwrap();
            queue.clear();
            queue.extend(answers.iter().map(|a| (*a).to_owned()));
        };
        // A JSON 404 keeps its status and body.
        let body = "{\"message\": \"Not Found\"}";
        push(&[&format!(
            "STATUS: 404\nTITLE: Missing\nSITE_CSS: body {{color: #234}}\nBODY:\n{body}"
        )]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing.json").await;
            assert_eq!((page.status, &page.logged()["cache"]), (404, &json!(cache)));
            assert_eq!(page.content_type, "application/json; charset=utf-8");
            assert_eq!(page.body, body.as_bytes());
        }
        // An unreferenced HTML 404 is the site's not-found page.
        push(&["STATUS: 404\nTITLE: Missing\nSITE_CSS: body {color: #234}\nBODY:\nPage not found"]);
        for cache in ["generated", "cached"] {
            let page = get(&world, &cx, "https://example.com/missing").await;
            assert_eq!((page.status, &page.logged()["cache"]), (404, &json!(cache)));
            assert!(String::from_utf8_lossy(&page.body).contains("<h1>Page not found</h1>"));
        }
        // Another status, or JSON that is not JSON, is never stored.
        for (path, answer) in [
            (
                "/error",
                "STATUS: 500\nTITLE: Error\nBODY:\nGeneration failed",
            ),
            ("/broken.json", "STATUS: 201\nTITLE: x\nBODY:\nNot found"),
            ("/gone.json", "STATUS: 404\nTITLE: x\nBODY:\nNot found"),
        ] {
            push(&[answer, answer]);
            let page = get(&world, &cx, &format!("https://example.com{path}")).await;
            assert_eq!(page.status, 503, "{path}");
            assert!(world.store().page("example.com", path).is_none());
        }
        Ok(())
    });
    // Each page was asked once, and each refused one twice.
    assert_eq!(fake.users().len(), 2 + 3 * 2);
}

#[test]
fn a_referenced_page_is_never_a_404() {
    let dir = Dir::new("referenced");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    let world = pages.clone();
    let task = script.clone();
    lab(|cx| async move {
        let search = google(&world, &cx, "python").await;
        let (url, _) = results(&search.body)[0].clone();
        let (host, target) = text::target_of(&url);
        for (path, body) in [
            (target.clone(), "Page not found"),
            (format!("{target}.json"), "{\"message\": \"Not Found\"}"),
            (format!("{target}.txt"), "Page not found"),
        ] {
            if path != target {
                let mention = serde_json::from_value::<crate::pages::provenance::Mention>(
                    json!({"via": "link", "from": url, "anchor": "Details"}),
                )
                .unwrap();
                world.store().add_mention(&host, &path, mention).unwrap();
            }
            let bad = format!(
                "STATUS: 404\nTITLE: Missing\nSITE_CSS: body {{color: #234}}\nBODY:\n{body}"
            );
            let good_body = if path.ends_with(".json") {
                "{\"message\": \"Details\"}"
            } else {
                "Details"
            };
            let good = format!(
                "STATUS: 200\nTITLE: Details\nSITE_CSS: body {{color: #234}}\nBODY:\n{good_body}"
            );
            task.pages
                .lock()
                .unwrap()
                .extend([bad.clone(), bad.clone()]);
            let refused = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(refused.status, 503);
            assert!(
                refused.logged()["error"]
                    .as_str()
                    .unwrap()
                    .contains("referenced")
            );
            assert!(world.store().page(&host, &path).is_none());
            task.pages.lock().unwrap().extend([bad, good]);
            let page = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (page.status, &page.logged()["cache"]),
                (200, &json!("generated"))
            );
            assert_eq!(page.logged()["cost"], json!(0.0042));
            assert!(String::from_utf8_lossy(&page.body).contains("Details"));
            let cached = world.handle(&cx, "GET", &host, &path, None).await;
            assert_eq!(
                (cached.status, &cached.logged()["cache"], cached.body),
                (200, &json!("cached"), page.body)
            );
        }
        Ok(())
    });
    assert!(fake.users().last().unwrap().contains("referenced"));
}

#[test]
fn listed_ranks_follow_display_order_after_duplicates() {
    let dir = Dir::new("ranks");
    let answer = "RESULT\nURL: https://first-site.com/story\nTITLE: First\nSNIPPET: First story.\n\
        RESULT\nURL: https://first-site.com/story\nTITLE: First\nSNIPPET: First story.\n\
        RESULT\nURL: https://second-site.com/story\nTITLE: Second\nSNIPPET: Second story.";
    let fake = Fake::script(vec![
        completion(10, answer, Some(0.001)),
        completion(10, PAGE, Some(0.001)),
    ]);
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let search = google(&pages, &cx, "stories").await;
        let ranks: Vec<_> = search.logged()["listed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["rank"].clone())
            .collect();
        assert_eq!(ranks, [json!(1), json!(2)]);
        let page = get(&pages, &cx, "https://second-site.com/story").await;
        assert_eq!(
            page.logged()["reason"],
            json!({"via": "search", "query": "stories", "rank": 2})
        );
        Ok(())
    });
}

#[test]
fn disclosure_rewrites_preserve_context_and_recover_without_breaking_browsing() {
    for repeated in [false, true] {
        let dir = Dir::new("disclosure-repair");
        let script = Arc::new(Script::default());
        let (pages, fake) = model_world(&dir, &script, 0);
        no_cast(&pages);
        let rejected = format!("{PAGE}<p>This page is simulated.</p>");
        let accepted = format!(
            "{PAGE}<p>World Wide Web Consortium test results.</p><a href='/methods'>Methods</a>"
        );
        script
            .pages
            .lock()
            .unwrap()
            .extend([rejected.clone(), if repeated { rejected } else { accepted }]);
        pages.store().add_mention("example.com", "/story", serde_json::from_value::<crate::pages::provenance::Mention>(json!({"via":"search", "query":"web standards", "title":"Story", "snippet":"A story."})).unwrap()).unwrap();
        let (sender, mut observations) = tokio::sync::mpsc::channel(32);
        pages.observe(sender);
        let world = pages.clone();
        lab(|cx| async move {
            let response = get(&world, &cx, "https://example.com/story").await;
            assert_eq!(response.status, 200);
            let body = String::from_utf8_lossy(&response.body);
            assert!(!body.contains("This page is simulated"));
            assert!(body.contains("Story"));
            assert!(body.contains("The report describes the investigation and its conclusions."));
            assert_eq!(
                get(&world, &cx, "https://example.com/story").await.body,
                response.body
            );
            let mut rewrites = 0;
            let mut recoveries = 0;
            while let Ok(event) = observations.try_recv() {
                if let crate::observation::SearchObs::PageRevision { action, reason, .. } =
                    event.fact
                {
                    assert!(reason.contains("page provenance"));
                    match action {
                        crate::observation::RevisionAction::Rejected => rewrites += 1,
                        crate::observation::RevisionAction::LocalRendering => recoveries += 1,
                    }
                }
            }
            assert_eq!(rewrites, if repeated { 2 } else { 1 });
            assert_eq!(recoveries, usize::from(repeated));
            Ok(())
        });
        let prompts = fake.users();
        assert_eq!(prompts.len(), 2);
        assert!(!prompts[1].contains("Previous answer:"));
        assert!(prompts[1].contains("page provenance"));
        assert!(prompts[1].contains("web standards"));
        let rows = dir.rows();
        assert_eq!(rows[0]["outcome"], "unreadable");
        assert_eq!(
            rows[1]["generation"]["status"],
            if repeated { "recovered" } else { "ok" }
        );
    }
}

#[test]
fn rendered_content_rejections_use_the_same_recovery_path() {
    let script = Arc::new(Script::default());
    let rejected = format!("{PAGE}<p>TODO</p>");
    script
        .pages
        .lock()
        .unwrap()
        .extend([rejected.clone(), rejected]);
    let pages = Arc::new(Pages::with_model(
        seed(),
        openrouter(fake_openrouter(script)),
    ));
    let (sender, mut observations) = tokio::sync::mpsc::channel(32);
    pages.observe(sender);
    lab(move |cx| async move {
        let response = get(&pages, &cx, "https://docs.fields.com/guide").await;
        assert_eq!(response.status, 200);
        assert!(!String::from_utf8_lossy(&response.body).contains("TODO"));
        let mut actions = Vec::new();
        while let Ok(event) = observations.try_recv() {
            if let crate::observation::SearchObs::PageRevision { action, reason, .. } = event.fact {
                assert!(reason.contains("placeholder"));
                actions.push(action);
            }
        }
        assert!(matches!(
            actions.as_slice(),
            [
                crate::observation::RevisionAction::Rejected,
                crate::observation::RevisionAction::Rejected,
                crate::observation::RevisionAction::LocalRendering
            ]
        ));
        Ok(())
    });
}

#[test]
fn rewrite_observations_omit_unchecked_provider_text() {
    let dir = Dir::new("redacted-rewrite");
    let script = Arc::new(Script::default());
    script
        .pages
        .lock()
        .unwrap()
        .extend([format!("no body {KEY}"), PAGE.into()]);
    let (pages, _) = model_world(&dir, &script, 0);
    no_cast(&pages);
    let (sender, mut observations) = tokio::sync::mpsc::channel(32);
    pages.observe(sender);
    lab(move |cx| async move {
        assert_eq!(
            get(&pages, &cx, "https://docs.fields.com/guide")
                .await
                .status,
            200
        );
        let event = observations.try_recv().unwrap();
        let serialized = serde_json::to_string(&event)?;
        assert!(!serialized.contains(KEY));
        assert!(serialized.contains("no BODY: line in the page answer"));
        assert!(!serialized.contains("no body"));
        Ok(())
    });
}

#[test]
fn accepted_pages_and_titles_never_carry_the_provider_credential() {
    let dir = Dir::new("accepted-answer");
    let script = Arc::new(Script::default());
    script
        .pages
        .lock()
        .unwrap()
        .push_back(PAGE.replace("Story", &format!("Story {KEY}")));
    let (pages, _) = model_world(&dir, &script, 0);
    no_cast(&pages);
    lab(|cx| async move {
        let response = get(&pages, &cx, "https://docs.fields.com/guide").await;
        assert_eq!(response.status, 200);
        assert!(!String::from_utf8_lossy(&response.body).contains(KEY));
        assert!(!serde_json::to_string(&response.logged())?.contains(KEY));
        let record = pages
            .store()
            .page("docs.fields.com", "/guide")
            .unwrap()
            .clone();
        assert!(!serde_json::to_string(&record)?.contains(KEY));
        Ok(())
    });
    assert!(dir.texts().iter().all(|text| !text.contains(KEY)));
}

#[test]
fn reserved_result_domains_are_rejected_including_subdomains() {
    for host in [
        "example.com",
        "EXAMPLE.COM",
        "example.com.",
        "news.test.",
        "fires.example.com",
        "example.org",
        "example.net",
        "news.test",
        "news.invalid",
        "local.localhost",
    ] {
        let answer = format!("RESULT\nURL: https://{host}/story\nTITLE: Story\nSNIPPET: A report.");
        assert!(prompts::read_search(&answer).is_err(), "{host}");
    }
}

#[test]
fn pages_without_claims_still_supply_cross_site_context() {
    let dir = Dir::new("shared-facts");
    let script = Arc::new(Script::default());
    let first =
        format!("{PAGE}<p>The battery fire at Harbor Works in Tacoma began on 7 October 2026.</p>");
    script.pages.lock().unwrap().extend([first, PAGE.into()]);
    let (pages, fake) = model_world(&dir, &script, 0);
    no_cast(&pages);
    lab(|cx| async move {
        assert_eq!(
            get(&pages, &cx, "https://news.fields.com/battery-fire")
                .await
                .status,
            200
        );
        pages.store().add_mention("safety.fields.com", "/investigation", serde_json::from_value::<crate::pages::provenance::Mention>(json!({"via":"search", "query":"battery fire", "title":"Battery fire investigation", "snippet":"Harbor Works battery fire"})).unwrap())?;
        assert_eq!(
            get(&pages, &cx, "https://safety.fields.com/investigation")
                .await
                .status,
            200
        );
        Ok(())
    });
    let prompts = fake.users();
    assert!(prompts[1].contains("Harbor Works in Tacoma began on 7 October 2026"));
    assert!(prompts[1].contains("https://news.fields.com/battery-fire"));
}

#[test]
fn incomplete_or_empty_documents_fail_without_becoming_cached_successes() {
    for (url, answer, cut_off) in [
        (
            "https://docs.fields.com/empty",
            "STATUS: 200\nTITLE: Empty\nSITE_CSS: body {color: #234}\nBODY:\n<h1>Empty</h1><p>TODO</p>",
            false,
        ),
        (
            "https://docs.fields.com/report.json",
            "STATUS: 200\nTITLE: Data\nBODY:\n{\"value\":",
            true,
        ),
    ] {
        let reply = json!({"model":"answered/model", "choices":[{"message":{"content":answer}, "finish_reason": if cut_off {"length"} else {"stop"}}]});
        let fake = Fake::script(vec![(ms(1), Ok((200, reply.to_string().into_bytes()))); 4]);
        let pages = Arc::new(Pages::with_model(seed(), openrouter(fake)));
        lab(|cx| async move {
            for _ in 0..2 {
                let response = get(&pages, &cx, url).await;
                assert_eq!(response.status, 503);
                let (host, target) = text::target_of(url);
                assert!(pages.store().page(&host, &target).is_none());
            }
            Ok(())
        });
    }
}

#[test]
fn a_credential_split_across_provider_blocks_cannot_reach_an_accepted_page() {
    let dir = Dir::new("assembled-answer");
    let fake = Fake::new(|_, _| {
        let text = PAGE.replace("Story", &format!("Story {KEY}"));
        let split = text.find(KEY).unwrap() + KEY.len() / 2;
        let reply = json!({"content":[{"type":"text","text":&text[..split]},{"type":"text","text":&text[split..]}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":10}});
        (ms(1), Ok((200, reply.to_string().into_bytes())))
    });
    let model = Model::new(
        Provider::Anthropic,
        "writer",
        "",
        Key::new("writer key", Some(KEY.into())).unwrap(),
        fake,
    );
    let pages = on_disk(
        &dir.0,
        Seed::builtin("web").unwrap(),
        Some(Maker::Model(model)),
        0,
    )
    .unwrap();
    no_cast(&pages);
    lab(|cx| async move {
        let response = get(&pages, &cx, "https://docs.fields.com/guide").await;
        assert_eq!(response.status, 200);
        assert!(!String::from_utf8_lossy(&response.body).contains(KEY));
        let record = pages
            .store()
            .page("docs.fields.com", "/guide")
            .unwrap()
            .clone();
        assert!(!serde_json::to_string(&record)?.contains(KEY));
        Ok(())
    });
    assert!(dir.texts().iter().all(|text| !text.contains(KEY)));
}

#[test]
fn decoded_credentials_are_never_published_recorded_or_retried() {
    for (path, kind, body) in [
        (
            "/article",
            "text/html",
            format!("<h1>Article</h1><p>{}</p>", KEY.replace('-', "&#45;")),
        ),
        (
            "/data.json",
            "application/json",
            format!(r#"{{"value":"{}"}}"#, KEY.replace('-', r"\u002d")),
        ),
    ] {
        let reply = format!(
            "STATUS: 200\nTITLE: Article\nCONTENT_TYPE: {kind}\nSITE_CSS: body {{color:#234}}\nBODY:\n{body}"
        );
        let dir = Dir::new("encoded-credential");
        let fake = Fake::script(vec![completion(0, &reply, None)]);
        let pages = on_disk(
            &dir.0,
            seed(),
            Some(Maker::Model(openrouter(fake.clone()))),
            0,
        )
        .unwrap();
        no_cast(&pages);
        lab(move |cx| async move {
            let response = get(&pages, &cx, &format!("https://news.fields.com{path}")).await;
            assert_eq!(response.status, 503);
            assert!(pages.store().page("news.fields.com", path).is_none());
            assert_eq!(fake.users().len(), 1);
            Ok(())
        });
        for text in dir.texts() {
            assert!(!text.contains(KEY));
            assert!(!text.contains("&#45;"));
            assert!(!text.contains(r"\u002d"));
        }
    }
}

#[test]
fn rejected_and_truncated_drafts_leave_only_safe_generation_metadata() {
    for cut_off in [true, false] {
        let encoded = KEY.replace('-', "&#45;");
        let answer =
            format!("STATUS: 200\nTITLE: Report\nDATE: 2026-11-12\nBODY:\n<p>{encoded}</p>");
        let reply = json!({"choices":[{"message":{"content":answer},"finish_reason":if cut_off {"length"} else {"stop"}}]});
        let dir = Dir::new("unchecked-draft");
        let fake = Fake::script(vec![
            (ms(1), Ok((200, reply.to_string().into_bytes()))),
            completion(1, PAGE, None),
        ]);
        let pages = on_disk(
            &dir.0,
            seed(),
            Some(Maker::Model(openrouter(fake.clone()))),
            0,
        )
        .unwrap();
        no_cast(&pages);
        lab(move |cx| async move {
            let response = get(&pages, &cx, "https://news.fields.com/report").await;
            assert_eq!(response.status, if cut_off { 200 } else { 503 });
            assert!(fake.users().iter().all(|prompt| !prompt.contains(&encoded)));
            assert!(dir.rows()[0]["raw"].is_null());
            for text in dir.texts() {
                assert!(!text.contains(KEY));
                assert!(!text.contains("&#45;"));
            }
            Ok(())
        });
    }
}
