//! Page assets, canonical links and concurrent request deduplication.

use super::*;

#[test]
fn site_styles_survive_restart_and_generation_off() {
    let dir = Dir::new("styles");
    let path = dir.0.clone();
    lab(move |cx| async move {
        let pages = on_disk(&path, fixed_seed(), Some(Maker::Stored), 0).unwrap();
        let first = get(&pages, &cx, "https://docs.tools.com/guide").await;
        let second = get(&pages, &cx, "https://docs.tools.com/reference").await;
        for page in [first, second] {
            assert!(String::from_utf8_lossy(&page.body).contains("href=\"/static/css/main.css\""));
        }
        let css = get(&pages, &cx, "https://docs.tools.com/static/css/main.css").await;
        assert!(css.body.len() > 1000);
        let fixed = pages.seed.fixed[0].clone();
        assert_eq!(get(&pages, &cx, &fixed.url).await.body, fixed.body);
        let fixed_css = get(
            &pages,
            &cx,
            &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host),
        )
        .await;
        assert!(!fixed_css.body.is_empty());
        assert_eq!(
            fixed_css.body,
            get(
                &pages,
                &cx,
                &format!("https://{}/static/css/main.css", fixed.host)
            )
            .await
            .body
        );
        drop(pages);
        let replay = on_disk(&path, fixed_seed(), None, 0).unwrap();
        assert_eq!(
            get(&replay, &cx, "https://docs.tools.com/static/css/main.css")
                .await
                .body,
            css.body
        );
        assert_eq!(
            get(
                &replay,
                &cx,
                &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host)
            )
            .await
            .body,
            fixed_css.body
        );
        assert_eq!(replay.store().made, 0);
        Ok(())
    });
}

#[test]
fn model_site_stylesheets_start_with_shared_layout_and_end_with_site_rules() {
    let dir = Dir::new("shared-styles");
    let own = "body { color: #234; font-family: Georgia; } header { background: #fff; }";
    let fake = Fake::script(vec![completion(
        10,
        &format!(
            "STATUS: 200\nTITLE: Article\nSITE_NAME: Field News\nSITE_KIND: news\nSITE_CSS: {own}\nBODY:\n<h1>Article</h1><p>A new report.</p>"
        ),
        Some(0.001),
    )]);
    let pages = on_disk(&dir.0, seed(), Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let page = get(&pages, &cx, "https://news.fields.com/article").await;
        assert_eq!(page.status, 200);
        let css = get(&pages, &cx, "https://news.fields.com/static/css/main.css").await;
        assert_eq!(css.status, 200);
        assert_eq!(css.content_type, "text/css");
        let css = String::from_utf8(css.body).unwrap();
        let base = make::stylesheet(make::SiteKind::News);
        assert_eq!(css, format!("{base}\n{own}"));
        assert_eq!(pages.store().site("news.fields.com").unwrap().css, own);
        let audit = fictionet_extras::guest_content::Audit::default();
        audit.inspect("site stylesheet", css.as_bytes());
        audit.check().unwrap();
        Ok(())
    });
}

#[test]
fn concurrent_model_pages_share_one_stylesheet() {
    let dir = Dir::new("model-styles");
    let fake = Fake::new(|_, body| {
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        let first = prompt.contains("SITE_CSS:");
        completion(
            10,
            if first {
                "STATUS: 200\nTITLE: Guide\nSITE_NAME: Field Notes\nSITE_KIND: docs\nSITE_CSS: body { color: #17472c; }\nBODY:\n<h1>Guide</h1>"
            } else {
                "STATUS: 200\nTITLE: Reference\nBODY:\n<h1>Reference</h1>"
            },
            Some(0.001),
        )
    });
    let pages = on_disk(
        &dir.0,
        seed(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    )
    .unwrap();
    no_cast(&pages);
    let path = dir.0.clone();
    lab(move |cx| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let other = on_disk(
            &path,
            seed(),
            Some(Maker::Model(openrouter(fake.clone()))),
            0,
        )
        .unwrap();
        cx.spawn(move |cx| async move {
            tx.send(get(&other, &cx, "https://docs.fields.com/reference").await)
                .unwrap();
            Ok(())
        });
        let first = get(&pages, &cx, "https://docs.fields.com/guide").await;
        let second = rx.await.unwrap();
        assert_eq!((first.status, second.status), (200, 200));
        assert_eq!(
            fake.users()
                .iter()
                .filter(|p| p.contains("SITE_CSS:"))
                .count(),
            1
        );
        assert_eq!(fake.users().len(), 2);
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: 0,
                },
            )
            .unwrap();
        let css = get(&pages, &cx, "https://docs.fields.com/static/css/main.css").await;
        assert_eq!(
            css.body,
            format!(
                "{}\nbody {{ color: #17472c; }}",
                make::stylesheet(make::SiteKind::Docs)
            )
            .as_bytes()
        );
        let replay = on_disk(&path, seed(), None, 0).unwrap();
        assert_eq!(
            get(
                &replay,
                &cx,
                "https://docs.fields.com/static/css/main.css?v=2"
            )
            .await
            .body,
            css.body
        );
        assert_eq!(fake.users().len(), 2);
        Ok(())
    });
}

#[test]
fn fixed_model_host_gets_one_stylesheet_without_rewriting_pages() {
    let dir = Dir::new("fixed-style");
    let fake = Fake::script(vec![completion(10, "body {color: #17472c}", Some(0.001))]);
    let pages = on_disk(
        &dir.0,
        fixed_seed(),
        Some(Maker::Model(openrouter(fake.clone()))),
        0,
    )
    .unwrap();
    lab(move |cx| async move {
        let fixed = pages.seed.fixed[0].clone();
        for _ in 0..2 {
            assert_eq!(get(&pages, &cx, &fixed.url).await.body, fixed.body);
            let css = get(
                &pages,
                &cx,
                &format!("https://{}/assets/css/site.min.css?v=4.18.2", fixed.host),
            )
            .await;
            assert_eq!(
                css.body,
                format!(
                    "{}\nbody {{color: #17472c}}",
                    make::stylesheet(make::site_profile(&fixed.host).kind)
                )
                .as_bytes()
            );
        }
        assert_eq!(fake.users().len(), 1);
        assert!(fake.users()[0].contains("Python tutorial"));
        Ok(())
    });
}

#[test]
fn unrelated_model_results_omit_seed_pages() {
    let dir = Dir::new("unrelated");
    let seed = fixed_seed();
    let answer = format!(
        "RESULT\nURL: {}\nTITLE: {}\nSNIPPET: {}\n\
        RESULT\nURL: https://cooking.com/chicken-tikka-masala\nTITLE: Chicken tikka masala recipe\nSNIPPET: Marinate the chicken.",
        seed.fixed[0].url, seed.fixed[0].title, seed.fixed[0].description
    );
    let fake = Fake::script(vec![completion(10, &answer, Some(0.001))]);
    let pages = on_disk(&dir.0, seed, Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let search = google(&pages, &cx, "chicken tikka masala recipe").await;
        assert_eq!(
            results(&search.body),
            [(
                "https://cooking.com/chicken-tikka-masala".into(),
                "Chicken tikka masala recipe".into()
            )]
        );
        for fixed in &pages.seed.fixed {
            assert!(
                pages
                    .store()
                    .mentions(&fixed.host, &fixed.target)
                    .is_empty()
            );
        }
        Ok(())
    });
}

#[test]
fn model_results_keep_held_pages_their_own_rows_relate() {
    let dir = Dir::new("related");
    let seed = fixed_seed();
    let answer = format!(
        "RESULT\nURL: {}\nTITLE: {}\nSNIPPET: The Python tutorial explains modules and packages.",
        seed.fixed[0].url, seed.fixed[0].title
    );
    let fake = Fake::script(vec![completion(10, &answer, Some(0.001))]);
    let pages = on_disk(&dir.0, seed, Some(Maker::Model(openrouter(fake))), 0).unwrap();
    no_cast(&pages);
    lab(move |cx| async move {
        let search = google(&pages, &cx, "Python tutorial modules").await;
        let url = pages.seed.fixed[0].url.clone();
        assert_eq!(
            results(&search.body)
                .into_iter()
                .map(|(url, _)| url)
                .collect::<Vec<_>>(),
            [url]
        );
        Ok(())
    });
}

#[test]
fn links_bound_candidates_before_filtering_and_cut_characters() {
    let mut html = "<a href=\"mailto:skip@site.com\">skip</a>".repeat(79);
    html.push_str(&format!(
        "<a href=\"../é?q=1&amp;x=2#frag\"><b>{}</b></a>",
        "😀".repeat(170)
    ));
    html.push_str("<a href=\"/too-late\">late</a>");
    assert_eq!(
        links("https://site.com/a/b", &html),
        vec![(
            "site.com".into(),
            "/%C3%A9?q=1&x=2".into(),
            "😀".repeat(160)
        )]
    );
    let html = "<a href='/empty'> <b></b> </a><a href='https://www.google.com/search?q=a'>Search</a>\
        <a href='/ok'>one &amp; two</a>";
    assert_eq!(
        links("https://site.com/", html),
        vec![("site.com".into(), "/ok".into(), "one & two".into())]
    );
    let mut mentions = Vec::new();
    for n in 0..12 {
        mentions.push(json!({"via":"link","anchor":n}));
        mentions.push(json!({"via":"search","title":n}));
    }
    let asked = prompts::asked_mentions(&mentions);
    assert_eq!(asked.len(), 20);
    assert_eq!(asked.iter().filter(|m| m["via"] == "link").count(), 8);
    assert_eq!(asked.last().unwrap()["title"], 11);
}

#[test]
fn noted_links_skip_stored_pages_and_cut_anchors() {
    lab(|cx| async move {
        let pages = plain();
        let host = "news.example-site.com";
        let url = format!("https://{host}/story");
        get(&pages, &cx, &format!("https://{host}/stored")).await;
        let anchor = format!("A&B {}", "x".repeat(prompts::ANCHOR_CHARS));
        let mut links = vec![
            ("/empty".to_owned(), " <b> </b> ".to_owned()),
            ("https://www.google.com/search?q=x".into(), "Search".into()),
            ("/stored".into(), "Stored".into()),
            ("mailto:author@example.com".into(), "Email".into()),
            ("http://".into(), "No host".into()),
            (
                "/relative?x=1&amp;y=2".into(),
                format!(" <b>A&amp;B</b> {} ", "x".repeat(prompts::ANCHOR_CHARS)),
            ),
            (
                "http://other.example-site.com/plain".into(),
                "HTTP target".into(),
            ),
        ];
        let mut expected = vec![
            (
                host.to_owned(),
                "/relative?x=1&y=2".to_owned(),
                text::take(&anchor, prompts::ANCHOR_CHARS),
            ),
            (
                "other.example-site.com".into(),
                "/plain".into(),
                "HTTP target".into(),
            ),
        ];
        for i in links.len()..=prompts::LINKS_PER_PAGE {
            links.push((format!("https://{host}/link-{i}"), format!("Link {i}")));
            if i < prompts::LINKS_PER_PAGE {
                expected.push((host.into(), format!("/link-{i}"), format!("Link {i}")));
            }
        }
        let markup: String = links
            .iter()
            .map(|(href, text)| format!("<a href=\"{href}\">{text}</a>"))
            .collect();
        pages.note_links(&url, &markup);
        let store = pages.store();
        for (host, target, anchor) in &expected {
            assert_eq!(
                store.mentions(host, target),
                [json!({"via": "link", "from": url, "anchor": anchor})],
                "{host}{target}"
            );
        }
        for target in ["/empty", "/stored", "/link-80"] {
            assert!(store.mentions(host, target).is_empty(), "{target}");
        }
        Ok(())
    });
}

#[test]
fn engines_redirects_and_assets() {
    lab(|cx| async move {
        let pages = plain();
        let location = |r: &Response| {
            r.headers
                .iter()
                .find(|(n, _)| n == "Location")
                .unwrap()
                .1
                .clone()
        };
        let redirect = pages
            .handle(&cx, "GET", "google.com", "/search?q=x", None)
            .await;
        assert_eq!(location(&redirect), "https://www.google.com/search?q=x");
        let ddg = pages
            .handle(
                &cx,
                "GET",
                "duckduckgo.com",
                "/l/?uddg=https%3A%2F%2Fa.com%2Fb",
                None,
            )
            .await;
        assert_eq!(location(&ddg), "https://a.com/b");
        let bing = pages
            .handle(&cx, "GET", "www.bing.com", "/search?q=python&first=x", None)
            .await;
        assert_eq!(bing.status, 200);
        let css = pages
            .handle(&cx, "GET", "a.com", "/static/css/main.css", None)
            .await;
        assert_eq!(
            (css.content_type.as_str(), &css.logged()["kind"]),
            ("text/css", &json!("asset"))
        );
        assert!(
            pages
                .store()
                .page("a.com", "/static/css/main.css")
                .is_none()
        );
        Ok(())
    });
}

#[test]
fn fixed_pages_are_served_as_written() {
    lab(|cx| async move {
        let pages = Arc::new(Pages::new(fixed_seed()));
        let fixed = pages.seed().fixed[0].clone();
        let page = get(&pages, &cx, &fixed.url).await;
        assert_eq!(page.body, fixed.body);
        assert_eq!(page.logged()["cache"], "fixed");
        // Its links are written down for the pages behind them.
        assert!(
            !pages
                .store()
                .mentions(&fixed.host, "/tutorial/modules.html")
                .is_empty()
        );
        Ok(())
    });
}

#[test]
fn concurrent_requests_make_one_page() {
    lab(|cx| async move {
        let pages = plain();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let pages = pages.clone();
                let (tx, rx) = tokio::sync::oneshot::channel();
                cx.spawn(move |cx| async move {
                    let _ = tx.send(
                        pages
                            .handle(&cx, "GET", "same-page.io", "/same", None)
                            .await,
                    );
                    Ok(())
                });
                rx
            })
            .collect();
        let mut replies = Vec::new();
        for task in tasks {
            replies.push(task.await.unwrap());
        }
        let generated = replies
            .iter()
            .filter(|r| r.logged()["cache"] == "generated")
            .count();
        assert_eq!(generated, 1);
        assert!(replies.iter().all(|r| r.body == replies[0].body));
        let store = pages.store();
        // The page and the cast.
        assert_eq!(store.made, 2);
        assert_eq!(store.site("same-page.io").map(|p| p.style), Some(0));
        Ok(())
    });
}

#[test]
fn concurrent_interactive_pages_read_the_preceding_pages_claims() {
    let script = Arc::new(Script::default());
    let fake = fake_openrouter(script);
    let pages = Arc::new(Pages::with_model(seed(), openrouter(fake.clone())));
    lab(move |cx| async move {
        let other = pages.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        cx.spawn(move |cx| async move {
            send.send(get(&other, &cx, "https://docs.fields.com/reference").await)
                .unwrap();
            Ok(())
        });
        let first = get(&pages, &cx, "https://docs.fields.com/guide").await;
        let second = receive.await.unwrap();
        assert_eq!((first.status, second.status), (200, 200));
        let prompts = fake.users();
        assert_eq!(prompts.len(), 2);
        assert!(prompts[1].contains("a claim about https://docs.fields.com/guide"));
        assert_eq!(
            prompts
                .iter()
                .filter(|prompt| prompt.contains("SITE_CSS:"))
                .count(),
            1
        );
        Ok(())
    });
}
