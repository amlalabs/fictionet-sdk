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
            json!({"via": "search", "query": format!("query {i}"), "title": "Story",
            "snippet": format!("Evidence number {i}.")})
        })
        .collect();
    let links: Vec<_> = (0..=prompts::LINK_MENTIONS_PER_PAGE)
        .map(|i| {
            json!({"via": "link", "from": format!("https://source.example-site.com/{i}"),
            "anchor": format!("Source {i}")})
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
        let body: Vec<_> = shown
            .iter()
            .map(|m| m["snippet"].as_str().unwrap())
            .collect();
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
                let snippet = mention["snippet"].as_str().unwrap();
                assert!(prompt.contains(&format!("snippet \"{snippet}\"")));
            }
            for (i, mention) in links.iter().enumerate() {
                let from = mention["from"].as_str().unwrap();
                assert_eq!(prompt.contains(from), i < prompts::LINK_MENTIONS_PER_PAGE);
            }
            let expected = if missing {
                json!([searches.last().unwrap()["snippet"]])
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
    let searches = Arc::new(crate::search::Searches::of(&pages));
    let state = searches.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(searches),
        |cx| async move {
            let search = google(&world, &cx, "python flaw").await;
            let (url, _) = results(&search.body)[0].clone();
            task.bad.store(2, Ordering::SeqCst);
            cx.sleep(ms(1000)).await?;
            assert!(state.snapshot().pages.is_empty());
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
                let mention = json!({"via": "link", "from": url, "anchor": "Details"});
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
