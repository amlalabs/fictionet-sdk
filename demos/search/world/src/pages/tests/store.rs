//! Persistence, replay and fixed-file byte preservation.

use super::*;

#[test]
fn the_budget_refuses_new_work_but_keeps_stored_pages() {
    lab(|cx| async move {
        let pages = plain();
        let first = get(&pages, &cx, "https://example.com/first").await;
        assert_eq!(first.status, 200);
        pages.store().made = GENERATION_BUDGET;
        let second = get(&pages, &cx, "https://example.com/second").await;
        assert_eq!(
            (second.status, &second.logged()["cache"]),
            (503, &json!("budget"))
        );
        let search = google(&pages, &cx, "new query").await;
        assert_eq!(
            (search.status, &search.logged()["cache"]),
            (503, &json!("budget"))
        );
        // The agent sees a busy server's page; the log says what it was for.
        for (answer, kind) in [(&second, "page"), (&search, "search")] {
            assert_eq!(answer.body, UNAVAILABLE);
            assert_eq!(answer.logged()["kind"], kind);
        }
        assert_eq!(
            get(&pages, &cx, "https://example.com/first").await.body,
            first.body
        );
        assert!(pages.store().page("example.com", "/second").is_none());
        Ok(())
    });
}

#[test]
fn mentions_reserve_titles_and_keep_creation_order() {
    let seed = fixed_seed();
    let mut store = Store::memory();
    store
        .add_mention(
            "site.com",
            "/p",
            json!({"via":"link","from":"https://source.com/","anchor":"An anchor"}),
        )
        .unwrap();
    let first = json!({"via":"search","query":"first","title":"First title",
        "snippet":"First snippet","rank":2});
    store
        .reserve_mention(&seed, "site.com", "/p", first.clone())
        .unwrap();
    store
        .reserve_mention(&seed, "site.com", "/p", first)
        .unwrap();
    let later = json!({"via":"search","query":"second","title":"Different title",
        "snippet":"Second snippet","rank":1});
    let later = store
        .reserve_mention(&seed, "site.com", "/p", later)
        .unwrap();
    assert_eq!(later["title"], "First title");
    assert_eq!(later["snippet"], "Second snippet");
    assert_eq!(store.mentions("site.com", "/p").len(), 3);
    assert_eq!(store.mentions("site.com", "/p")[0]["via"], "link");
    let f = &seed.fixed[0];
    let reserved = store
        .reserve_mention(
            &seed,
            &f.host,
            &f.target,
            json!({"via":"search","title":"wrong","snippet":"wrong"}),
        )
        .unwrap();
    assert_eq!(reserved["title"], f.title);
    assert_eq!(reserved["snippet"], f.description);
}

#[test]
fn replay_serves_the_store_and_nothing_new() {
    let dir = Dir::new("replay");
    let (search, page) = {
        let pages = on_disk(&dir.0, seed(), Some(Maker::Stored), 0).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let s = pages
                .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=python", None)
                .await;
            let p = pages
                .handle(&cx, "GET", "docs.python.org", "/support/", None)
                .await;
            tx.send((s.body, p.body)).unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let replay = on_disk(&dir.0, seed(), None, 0).unwrap();
    lab(|cx| async move {
        let s = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=python", None)
            .await;
        assert_eq!(s.body, search);
        assert_eq!(s.logged()["cache"], "cached");
        let p = replay
            .handle(&cx, "GET", "docs.python.org", "/support/", None)
            .await;
        assert_eq!((&p.logged()["cache"], p.body), (&json!("cached"), page));
        let missing = replay
            .handle(&cx, "GET", "docs.python.org", "/never-asked", None)
            .await;
        assert_eq!(
            (missing.status, &missing.logged()["cache"]),
            (404, &json!("missing"))
        );
        let none = replay
            .handle(&cx, "GET", "html.duckduckgo.com", "/html/?q=never", None)
            .await;
        assert_eq!(
            (
                none.logged()["cache"].clone(),
                none.logged()["results"].clone()
            ),
            (json!("missing"), json!(0))
        );
        Ok(())
    });
}

#[test]
fn worlds_sharing_a_store_make_each_list_and_page_once() {
    let dir = Dir::new("shared");
    let fakes: Vec<_> = (0..3).map(|_| fake_openrouter(Arc::default())).collect();
    let worlds: Vec<_> = fakes
        .iter()
        .map(|fake| {
            let model = openrouter(fake.clone());
            on_disk(&dir.0, seed(), Some(Maker::Model(model)), 0).unwrap()
        })
        .collect();
    lab(move |cx| async move {
        let lists = at_once(&cx, &worlds, "https://www.google.com/search?q=python+flaw").await;
        assert!(
            lists
                .iter()
                .all(|r| r.status == 200 && r.body == lists[0].body)
        );
        let (url, title) = results(&lists[0].body).remove(0);
        let pages = at_once(&cx, &worlds, &url).await;
        assert!(
            pages
                .iter()
                .all(|r| r.status == 200 && r.body == pages[0].body)
        );
        assert_eq!(pages[0].logged()["title"], json!(title));
        let made = |cache: &str, rs: &[Response]| {
            rs.iter().filter(|r| r.logged()["cache"] == cache).count()
        };
        assert_eq!((made("generated", &lists), made("cached", &lists)), (1, 2));
        assert_eq!((made("generated", &pages), made("cached", &pages)), (1, 2));
        let asked: Vec<String> = fakes.iter().flat_map(|fake| fake.users()).collect();
        for prompt in [
            "List the people",
            "Someone searched for",
            "Write the page at",
        ] {
            let count = asked.iter().filter(|user| user.contains(prompt)).count();
            assert_eq!(count, 1, "{prompt}");
        }
        Ok(())
    });
    let world = std::fs::read_to_string(dir.0.join("web/world.jsonl")).unwrap();
    let kinds: Vec<String> = world
        .lines()
        .map(|line| {
            let entry: Value = serde_json::from_str(line).unwrap();
            entry.as_object().unwrap().keys().next().unwrap().clone()
        })
        .collect();
    for kind in ["cast", "search", "page"] {
        assert_eq!(kinds.iter().filter(|k| *k == kind).count(), 1, "{kind}");
    }
}

#[test]
fn fixed_snapshots_survive_changed_and_deleted_sources() {
    let dir = Dir::new("fixed");
    let seeds = dir.0.join("seeds");
    std::fs::create_dir_all(seeds.join("fixed")).unwrap();
    std::fs::write(seeds.join("web.md"), FIXED_SEED).unwrap();
    let file = seeds.join("tutorial.html");
    std::fs::write(&file, FIXED_BODY).unwrap();
    let load = || Seed::load(seeds.join("web.md")).unwrap();
    let url = load().fixed[0].url.clone();
    let fetch = |pages: Arc<Pages>| {
        let url = url.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        lab(|cx| async move {
            let page = get(&pages, &cx, &url).await;
            let cache = page.logged()["cache"].clone();
            tx.send((page.status, page.content_type, page.body, cache))
                .unwrap();
            Ok(())
        });
        rx.recv().unwrap()
    };
    let first = fetch(on_disk(&dir.0, load(), Some(Maker::Stored), 0).unwrap());
    assert_eq!(first.3, "fixed");
    // A restarted world serves the captured bytes, whatever the source says now.
    std::fs::write(&file, "a changed advisory").unwrap();
    assert_eq!(
        fetch(on_disk(&dir.0, load(), Some(Maker::Stored), 0).unwrap()),
        first
    );
    std::fs::remove_file(&file).unwrap();
    assert!(Seed::load(seeds.join("web.md")).is_err());
    let replay_seed = || {
        let text = std::fs::read_to_string(seeds.join("web.md")).unwrap();
        Seed::parse("web", &text, |_| Ok(Vec::new())).unwrap()
    };
    assert_eq!(
        fetch(on_disk(&dir.0, replay_seed(), None, 0).unwrap()),
        first
    );
    // Replay never captures a fixed page it has not seen.
    let fresh = Dir::new("fixed-unseen");
    {
        on_disk(&fresh.0, replay_seed(), Some(Maker::Stored), 0).unwrap();
    }
    let unseen = fetch(on_disk(&fresh.0, replay_seed(), None, 0).unwrap());
    assert_eq!((unseen.0, unseen.3), (404, json!("missing")));
}

#[test]
fn binary_and_empty_fixed_bodies_round_trip() {
    for (i, body) in [
        [
            &(0..=255).collect::<Vec<u8>>()[..],
            b"<a href=\"/binary-link\">Not HTML</a>",
        ]
        .concat(),
        Vec::new(),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = Dir::new(&format!("binary-{i}"));
        let mut seed = fixed_seed();
        seed.fixed[0].body = body.clone();
        seed.fixed[0].content_type = "application/octet-stream".into();
        let url = seed.fixed[0].url.clone();
        let host = seed.fixed[0].host.clone();
        for maker in [Some(Maker::Stored), None] {
            let pages = on_disk(&dir.0, seed.clone(), maker, 0).unwrap();
            let (url, body, host) = (url.clone(), body.clone(), host.clone());
            lab(|cx| async move {
                let page = get(&pages, &cx, &url).await;
                assert_eq!(
                    (page.status, page.content_type.as_str()),
                    (200, "application/octet-stream")
                );
                assert_eq!(page.body, body);
                assert_eq!(page.headers, [("Server".to_owned(), "nginx".to_owned())]);
                assert!(pages.store().mentions(&host, "/binary-link").is_empty());
                Ok(())
            });
        }
    }
}

#[test]
fn a_store_answers_only_for_its_seed_and_generator() {
    let dir = Dir::new("identity");
    let model =
        |name: &str, reasoning: &str| model::identity(Provider::OpenRouter, name, reasoning);
    let seed = fixed_seed();
    let (store, made_by) = Store::open(&dir.0, &seed, Some(&model("some/model", "low"))).unwrap();
    assert_eq!(made_by, model("some/model", "low"));
    drop(store);
    // Replay keeps the generator that made the store.
    let (store, made_by) = Store::open(&dir.0, &seed, None).unwrap();
    assert_eq!(made_by["model"], "some/model");
    drop(store);
    for other in [
        json!({"provider": "anthropic", "model": "some/model", "reasoning": "low"}),
        model("other/model", "low"),
        model("some/model", "high"),
        Maker::Stored.identity(),
    ] {
        let error = Store::open(&dir.0, &seed, Some(&other)).err().unwrap();
        assert!(
            error.contains("generator configuration mismatch"),
            "{error}"
        );
        assert!(error.contains("rebuild in a fresh --store"), "{error}");
    }
    let mut changes: Vec<Seed> = Vec::new();
    for change in 0..4 {
        let mut changed = seed.clone();
        match change {
            0 => changed.date = "2026-12-01".into(),
            1 => changed.instructions = "A different brief".into(),
            2 => changed.fixed[0].title = "A different title".into(),
            _ => changed.fixed[0].file = "fixed/other.html".into(),
        }
        changes.push(changed);
    }
    for changed in changes {
        for generator in [Some(model("some/model", "low")), None] {
            let error = Store::open(&dir.0, &changed, generator.as_ref())
                .err()
                .unwrap();
            assert!(error.contains("the seed's declaration differs"), "{error}");
        }
    }
    // The fixed pages' bytes are not part of the declaration.
    let mut bytes = seed.clone();
    bytes.fixed[0].body = b"other bytes".to_vec();
    Store::open(&dir.0, &bytes, None).unwrap();
}

#[test]
fn stores_of_another_format_and_empty_replays_are_refused() {
    let dir = Dir::new("formats");
    let seed = seed();
    let error = Store::open(&dir.0, &seed, None).err().unwrap();
    assert!(
        error.contains("replay needs a store a generator made"),
        "{error}"
    );
    assert!(!dir.0.join("store.json").exists());
    let legacy = dir.0.join("legacy");
    std::fs::create_dir_all(legacy.join("pages")).unwrap();
    std::fs::write(legacy.join("@store.json"), "{}").unwrap();
    let error = Store::open(&legacy, &seed, Some(&Maker::Stored.identity()))
        .err()
        .unwrap();
    assert!(
        error.contains("files of no store of this version"),
        "{error}"
    );
    let fresh = dir.0.join("fresh");
    Store::open(&fresh, &seed, Some(&Maker::Stored.identity())).unwrap();
    let path = fresh.join("store.json");
    let mut identity: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    identity["version"] = json!(999);
    std::fs::write(&path, identity.to_string()).unwrap();
    let error = Store::open(&fresh, &seed, None).err().unwrap();
    assert!(
        error.contains("unsupported store format version"),
        "{error}"
    );
    identity["version"] = json!(1);
    std::fs::write(&path, identity.to_string()).unwrap();
    std::fs::write(
        fresh.join("world.jsonl"),
        "{\"cast\":{\"people\":[],\"usage\":",
    )
    .unwrap();
    let error = Store::open(&fresh, &seed, None).err().unwrap();
    assert!(error.contains("world.jsonl: line 1"), "{error}");
}

#[test]
fn search_styles_are_static_with_either_generator() {
    let dir = Dir::new("search-styles");
    let script = Arc::new(Script::default());
    let (model, fake) = model_world(&dir, &script, 0);
    lab(|cx| async move {
        for pages in [plain(), model] {
            for (host, path) in [
                ("www.google.com", "/search?q=python"),
                ("www.bing.com", "/search?q=python"),
                ("html.duckduckgo.com", "/html/?q=python"),
            ] {
                let response = pages.handle(&cx, "GET", host, path, None).await;
                assert_eq!(response.status, 200);
                let html = String::from_utf8(response.body).unwrap();
                assert!(html.contains(r#"rel="stylesheet" href="/search.css""#));
                assert!(!html.contains("<script"));
                assert!(!html.contains("<style"));
            }
            pages
                .apply(
                    &cx,
                    Command::SetGeneration {
                        generate: false,
                        expected_revision: 0,
                    },
                )
                .unwrap();
            let calls = fake.requests.lock().unwrap().len();
            let made = pages.store().made;
            for host in ["www.google.com", "www.bing.com", "html.duckduckgo.com"] {
                let css = pages
                    .handle(&cx, "GET", host, "/search.css?v=1", None)
                    .await;
                assert_eq!(css.status, 200);
                assert_eq!(css.content_type, "text/css; charset=utf-8");
                assert_eq!(css.body, fictionet_extras::search::CSS.as_bytes());
                assert_eq!(css.logged()["kind"], "asset");
                assert!(pages.store().page(host, "/search.css?v=1").is_none());
            }
            assert_eq!(pages.store().made, made);
            assert_eq!(fake.requests.lock().unwrap().len(), calls);
        }
        Ok(())
    });
}

#[test]
fn model_generation_switch_keeps_saved_pages_and_results() {
    let dir = Dir::new("model-switch");
    let script = Arc::new(Script::default());
    let (pages, fake) = model_world(&dir, &script, 0);
    lab(|cx| async move {
        let search = google(&pages, &cx, "python flaw").await;
        assert_eq!(search.logged()["cache"], "generated");
        let url = &results(&search.body)[0].0;
        let page = get(&pages, &cx, url).await;
        assert_eq!(page.logged()["cache"], "generated");
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: false,
                    expected_revision: 0,
                },
            )
            .unwrap();
        let calls = fake.requests.lock().unwrap().len();
        let cached = google(&pages, &cx, "python flaw").await;
        assert_eq!(cached.logged()["cache"], "cached");
        assert_eq!(cached.body, search.body);
        let cached = get(&pages, &cx, url).await;
        assert_eq!(cached.logged()["cache"], "cached");
        assert_eq!(cached.body, page.body);
        assert_eq!(
            google(&pages, &cx, "a new query").await.logged()["cache"],
            "missing"
        );
        assert_eq!(
            get(&pages, &cx, "https://new-site.com/missing")
                .await
                .status,
            404
        );
        assert_eq!(fake.requests.lock().unwrap().len(), calls);
        pages
            .apply(
                &cx,
                Command::SetGeneration {
                    generate: true,
                    expected_revision: 1,
                },
            )
            .unwrap();
        assert_eq!(
            google(&pages, &cx, "a new query").await.logged()["cache"],
            "generated"
        );
        assert!(fake.requests.lock().unwrap().len() > calls);
        Ok(())
    });
}
