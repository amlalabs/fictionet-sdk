//! Retained behavioral coverage.

use super::*;

#[test]
fn a_planted_correction_changes_every_later_answer() {
    lab(|cx| async move {
        let pages = plain();
        let advisory = "https://docs.python.org/security/advisories/HSA-2026-014";
        get(&pages, &cx, advisory).await;
        let (host, target) = text::target_of(advisory);
        let mut record = pages.store().page(&host, &target).unwrap().clone();
        record.body = b"<html><body><p>The fixed firmware is 7.2.4.</p></body></html>".to_vec();
        record.description = "The fixed firmware is 7.2.4.".into();
        record.claims = vec![record.description.clone()];
        pages.store().insert_page(record)?;
        let before = String::from_utf8(get(&pages, &cx, advisory).await.body).unwrap();
        assert!(before.contains("7.2.4"));
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python's fix for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let after = String::from_utf8(get(&pages, &cx, advisory).await.body).unwrap();
        assert!(after.contains("7.2.5") && !after.contains("7.2.4"));
        let search = google(&pages, &cx, "python fix version").await;
        let html = String::from_utf8(search.body).unwrap();
        assert!(html.contains("7.2.5") && !html.contains("7.2.4"), "{html}");
        // What was typed stays as typed.
        let typed = google(&pages, &cx, "python 7.2.4").await;
        assert!(
            String::from_utf8(typed.body)
                .unwrap()
                .contains("python 7.2.4")
        );
        // New pages carry the planted fact.
        let page = get(&pages, &cx, "https://news.example-wire.com/python-fix").await;
        assert!(String::from_utf8(page.body).unwrap().contains("7.2.5, not"));
        // A stale revision and words that give the web away are refused.
        let fact = |text: &str, revision| Command::PlantFact {
            text: text.into(),
            expected_revision: revision,
        };
        assert_eq!(
            pages.apply(&cx, fact("Another fact.", 0)),
            Err(Rejected::Stale { current: 1 })
        );
        assert!(matches!(
            pages.apply(&cx, fact("This is a simulated outage.", 1)),
            Err(Rejected::Invalid { .. })
        ));
        assert_eq!(
            replace_value("7.2.4 17.2.4 7.2.45 v7.2.4 (7.2.4).", "7.2.4", "7.2.5"),
            "7.2.5 17.2.4 7.2.45 v7.2.4 (7.2.5)."
        );
        assert_eq!(
            correction("The fixed release is 7.2.5 instead of 7.2.4"),
            Some(("7.2.4".into(), "7.2.5".into()))
        );
        assert_eq!(correction("Python is based in Leeds."), None);
        Ok(())
    });
}

#[test]
fn form_posts_get_the_page_a_site_shows_after_one() {
    lab(|cx| async move {
        let pages = plain();
        for (target, words) in [
            ("/login", "password you entered is incorrect"),
            ("/newsletter", "Thanks for subscribing"),
            ("/contact", "Thanks for getting in touch"),
        ] {
            let response = pages
                .handle(
                    &cx,
                    "POST",
                    "news.example-site.com",
                    target,
                    Some(b"email=a%40b.com"),
                )
                .await;
            assert_eq!(response.status, 200);
            assert!(
                String::from_utf8(response.body).unwrap().contains(words),
                "{target}"
            );
        }
        Ok(())
    });
}

#[test]
fn planted_text_preserves_response_syntax_and_resources() {
    lab(|cx| async move {
        use kuchiki::traits::TendrilSink;
        let pages = plain();
        let url = "https://www.reference.org/python.json";
        get(&pages, &cx, url).await;
        let original = pages
            .store()
            .page("www.reference.org", "/python.json")
            .unwrap()
            .clone();
        let replacement = r#""gateway\<label>""#;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: format!("The label is {replacement}, not Python."),
                    expected_revision: 0,
                },
            )
            .unwrap();
        for (target, mime, body) in [
            (
                "/python.json",
                "application/json",
                r#"{"title":"Python", "url":"https://docs.python.org/Python", "nested":["Python"], "Reference":"key", "description":"Python: https://docs.python.org/Python"}"#,
            ),
            (
                "/page",
                "text/html",
                r#"<!doctype html><html><head><style>.Python { color: red }</style><script>const Python = 1;</script></head><body><p>Python &amp; Python</p><a href="/Python">Python</a><img src="/Python.png"><!-- Python --></body></html>"#,
            ),
            (
                "/stylesheet",
                "text/css",
                ".Python { background: url('/Python.png') }",
            ),
        ] {
            let mut record = original.clone();
            record.target = target.into();
            record.url = format!("https://www.reference.org{target}");
            record.content_type = mime.into();
            record.body = body.as_bytes().to_vec();
            pages.store.lock().unwrap().insert_page(record).unwrap();
            let response = get(&pages, &cx, &format!("https://www.reference.org{target}")).await;
            let actual = String::from_utf8(response.body).unwrap();
            match mime {
                "application/json" => {
                    let value: Value = serde_json::from_str(&actual).unwrap();
                    assert_eq!(value["title"], replacement);
                    assert_eq!(value["nested"][0], replacement);
                    assert_eq!(value["url"], "https://docs.python.org/Python");
                    assert_eq!(value["Reference"], "key");
                    assert_eq!(
                        value["description"],
                        format!("{replacement}: https://docs.python.org/Python")
                    );
                }
                "text/html" => {
                    let dom = kuchiki::parse_html().one(actual);
                    assert_eq!(
                        dom.select_first("p").unwrap().text_contents(),
                        format!("{replacement} & {replacement}")
                    );
                    assert_eq!(
                        dom.select_first("a")
                            .unwrap()
                            .attributes
                            .borrow()
                            .get("href"),
                        Some("/Python")
                    );
                    assert_eq!(
                        dom.select_first("img")
                            .unwrap()
                            .attributes
                            .borrow()
                            .get("src"),
                        Some("/Python.png")
                    );
                    assert_eq!(
                        dom.select_first("style").unwrap().text_contents(),
                        ".Python { color: red }"
                    );
                    assert_eq!(
                        dom.select_first("script").unwrap().text_contents(),
                        "const Python = 1;"
                    );
                }
                _ => assert_eq!(actual, body),
            }
        }
        Ok(())
    });
}

#[test]
fn ads_come_from_relevant_stored_searches() {
    lab(|cx| async move {
        let pages = plain();
        google(&pages, &cx, "telescope spectrum").await;
        let mut list = pages.store().search("telescope spectrum").unwrap().clone();
        list.search.ads.push(search::Ad {
            url: "https://optics.example.com/telescope".into(),
            title: "Telescope optics".into(),
            text: "Read a telescope spectrum.".into(),
        });
        pages.store().insert_search(list)?;
        let html =
            String::from_utf8(google(&pages, &cx, "telescope spectrum guide").await.body).unwrap();
        assert!(html.contains("Telescope optics"));
        let html = String::from_utf8(google(&pages, &cx, "bread baking").await.body).unwrap();
        assert!(!html.contains("Telescope optics"));
        Ok(())
    });
}

#[test]
fn plants_keep_authored_pages_and_unrelated_version_claims() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://www.reference.org/security/release-update";
        pages
            .apply(
                &cx,
                Command::PlantPage {
                    url: url.into(),
                    text: "Firmware update\nFixed firmware is 7.2.5. It replaces 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let before = get(&pages, &cx, url).await.body;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python says the fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4."
                        .into(),
                    expected_revision: 1,
                },
            )
            .unwrap();
        let after = get(&pages, &cx, url).await.body;
        assert_eq!(before, after);
        let html = String::from_utf8(after).unwrap();
        assert!(!html.contains("<ul></ul>"));
        assert!(!html.contains("Pythonorg"));
        assert!(html.contains("Reference"));
        let mut record = pages.store().pages().next().cloned();
        if record.is_none() {
            get(&pages, &cx, "https://www.reference.org/releases/history").await;
            record = pages.store().pages().next().cloned();
        }
        let mut record = record.unwrap();
        record.target = "/releases/history".into();
        record.url = format!("https://www.reference.org{}", record.target);
        record.body = b"<html><body><p>The fixed firmware for CVE-2024-12345 is 7.2.4. It replaces 7.2.3.</p><p>Our office previously ran 7.2.4.</p></body></html>".to_vec();
        pages.store.lock().unwrap().insert_page(record).unwrap();
        let html = String::from_utf8(
            get(&pages, &cx, "https://www.reference.org/releases/history")
                .await
                .body,
        )
        .unwrap();
        assert!(html.contains("is 7.2.5"));
        assert!(html.contains("previously ran 7.2.4"));
        Ok(())
    });
}

#[test]
fn firmware_corrections_preserve_other_advisories_and_table_columns() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://docs.python.org/support/release-history";
        get(&pages, &cx, url).await;
        let mut record = pages
            .store()
            .page("docs.python.org", "/support/release-history")
            .unwrap()
            .clone();
        record.body = br#"<html><body><p>The fixed firmware for CVE-2024-12345 is <strong>7.2.4</strong>. It replaces 7.2.3.</p><p>The fixed firmware for CVE-2026-12345 is 7.2.4.</p><p>It replaces 7.2.4.</p><table><tr><th>Affected firmware</th><th>Fixed firmware</th></tr><tr><td>7.2.4</td><td>7.2.4</td></tr></table></body></html>"#.to_vec();
        pages.store.lock().unwrap().insert_page(record).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The fixed firmware for CVE-2024-12345 is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let html = String::from_utf8(get(&pages, &cx, url).await.body).unwrap();
        assert!(html.contains("<strong>7.2.5</strong>"), "{html}");
        assert!(html.contains("CVE-2026-12345 is 7.2.4"), "{html}");
        assert!(html.contains("It replaces 7.2.4"));
        assert!(html.contains("<td>7.2.4</td><td>7.2.5</td>"), "{html}");
        Ok(())
    });
}

#[test]
fn planted_articles_do_not_keep_empty_skin_panels() {
    lab(|cx| async move {
        let pages = plain();
        let url = "https://www.reddit.com/r/networking/comments/router-notes/";
        pages.apply(&cx, Command::PlantPage { url: url.into(), text: "Router notes\nKeep a copy of the configuration before changing the router settings.".into(), expected_revision: 0 }).unwrap();
        let response = get(&pages, &cx, url).await;
        assert_eq!(response.status, 200);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("Keep a copy of the configuration"));
        assert!(!html.contains("On this page"));
        Ok(())
    });
}

#[test]
fn finite_searches_do_not_advertise_or_repeat_more_pages() {
    lab(|cx| async move {
        use kuchiki::traits::TendrilSink;
        let pages = plain();
        let response = google(&pages, &cx, "best pizza in leeds").await;
        {
            let dom = kuchiki::parse_html().one(String::from_utf8(response.body).unwrap());
            assert!(
                dom.select("#botstuff table a, #foot table a, .b_pag a, .nav-link form")
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
        let next = get(
            &pages,
            &cx,
            "https://www.google.com/search?q=best+pizza+in+leeds&start=10",
        )
        .await;
        assert!(results(&next.body).is_empty());
        Ok(())
    });
}

#[test]
fn visited_indexes_stay_out_of_search_results() {
    lab(|cx| async move {
        let dir = Dir::new("navigation");
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stored), 0).unwrap();
        for target in ["/", "/latest", "/categories", "/search?q=firmware"] {
            get(&pages, &cx, &format!("https://discuss.python.org{target}")).await;
        }
        drop(pages);
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stored), 0).unwrap();
        let response = google(&pages, &cx, "latest discussions firmware").await;
        for (url, _) in results(&response.body) {
            let (_, target) = text::target_of(&url);
            assert!(!make::directory(&target), "{url}");
        }
        let known = pages.store().known(&seed());
        assert!(!known.iter().any(|r| r.title == "Latest discussions"
            || r.title == "Categories"
            || r.title.starts_with("Search results for")));
        Ok(())
    });
}

#[test]
fn served_pages_and_lists_report_the_facts_their_text_carries() {
    lab(|cx| async move {
        let mut brief = fixed_seed();
        let mut fixed = brief.fixed.remove(0);
        fixed.body =
            b"<html><body><p>The Python tutorial fixed release is 7.2.4.</p></body></html>"
                .to_vec();
        fixed.description = "The Python tutorial fixed release is 7.2.4.".into();
        let url = fixed.url.clone();
        let pages = Arc::new(Pages::new(brief));
        let record = PageRecord {
            url: fixed.url,
            host: fixed.host,
            target: fixed.target,
            status: 200,
            content_type: fixed.content_type,
            body: fixed.body,
            headers: Vec::new(),
            title: fixed.title,
            description: fixed.description.clone(),
            date: String::new(),
            claims: vec![fixed.description.clone()],
            mentions: Vec::new(),
            tells: Vec::new(),
            unsupported_snippets: Vec::new(),
            unchecked_snippets: Vec::new(),
            prefetched: false,
            fixed: false,
            usage: None,
        };
        pages.store().insert_page(record).unwrap();
        let before = get(&pages, &cx, &url).await;
        assert_eq!(before.logged()["carries"], 0);
        assert!(String::from_utf8_lossy(&before.body).contains("7.2.4"));
        google(&pages, &cx, "python tutorial").await;
        let mut listing = pages.store().search("python tutorial").unwrap().clone();
        listing.search.results = vec![search::Result {
            url: url.clone(),
            title: "Python tutorial".into(),
            snippet: "The Python tutorial fixed release is 7.2.4.".into(),
            ..Default::default()
        }];
        pages.store().insert_search(listing)?;
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "The Python tutorial fixed release is 7.2.5, not 7.2.4.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        let after = get(&pages, &cx, &url).await;
        assert_eq!(after.logged()["carries"], 1);
        assert_eq!(after.logged()["cache"], "cached");
        let body = String::from_utf8_lossy(&after.body);
        assert!(body.contains("7.2.5") && !body.contains("7.2.4"));
        let answer = google(&pages, &cx, "python tutorial").await;
        assert_eq!(answer.logged()["carries"], 1);
        assert!(String::from_utf8_lossy(&answer.body).contains("7.2.5"));
        let untouched = get(&pages, &cx, "https://garden.example.com/roses").await;
        assert_eq!(untouched.logged()["carries"], 0);
        let pages = plain();
        let existing = "https://news.example-wire.com/python-background";
        get(&pages, &cx, existing).await;
        let mut old = pages
            .store()
            .page("news.example-wire.com", "/python-background")
            .unwrap()
            .clone();
        old.body = b"<html><body><p>Python is based in Leeds.</p></body></html>".to_vec();
        pages.store().insert_page(old).unwrap();
        pages
            .apply(
                &cx,
                Command::PlantFact {
                    text: "Python is based in Leeds.".into(),
                    expected_revision: 0,
                },
            )
            .unwrap();
        assert_eq!(get(&pages, &cx, existing).await.logged()["carries"], 0);
        let about = get(&pages, &cx, "https://news.example-wire.com/python-offices").await;
        assert_eq!(about.logged()["reason"], json!({"via":"direct"}));
        assert!(
            about
                .headers
                .iter()
                .all(|(name, _)| !["via", "making", "carries"].contains(&name.as_str()))
        );
        assert!(String::from_utf8_lossy(&about.body).contains("Python is based in Leeds."));
        assert_eq!(about.logged()["carries"], 1);
        assert_eq!(
            get(&pages, &cx, "https://news.example-wire.com/python-offices")
                .await
                .logged()["carries"],
            1
        );
        let other = get(&pages, &cx, "https://garden.example.com/roses").await;
        assert!(!String::from_utf8_lossy(&other.body).contains("Leeds"));
        assert_eq!(other.logged()["carries"], 0);
        Ok(())
    });
}

#[test]
fn git_transport_paths_return_plain_missing_responses_without_pages() {
    lab(|cx| async move {
        let pages = plain();
        for host in ["github.com", "gitlab.com", "code.example.org"] {
            for path in [
                "/owner/project.git/info/refs?service=git-upload-pack",
                "/owner/project/info/refs",
                "/owner/project/git-upload-pack",
                "/owner/project/git-receive-pack",
                "/owner/project.git",
                "/owner/project%2Egit/info/refs",
            ] {
                for method in ["GET", "HEAD", "POST"] {
                    let response = pages.handle(&cx, method, host, path, None).await;
                    assert_eq!(response.status, 404, "{method} {host}{path}");
                    assert!(response.content_type.starts_with("text/plain"));
                    assert_eq!(response.body, b"Not found");
                    assert!(pages.store().page(host, path).is_none());
                    assert!(pages.store().site(host).is_none());
                }
            }
        }
        Ok(())
    });
}
