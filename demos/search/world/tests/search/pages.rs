//! Retained behavioral coverage.

use super::*;

#[test]
fn worst_case_snapshot_fits() {
    let t = "\u{0001}".repeat(STRING_BYTES);
    let n = u64::MAX;
    let seed = SeedCard {
        name: t.clone(),
        date: t.clone(),
        instructions: t.clone(),
    };
    let q = Query {
        id: n,
        key: t.clone(),
        search: t.clone(),
        engine: Engine::DuckDuckGo,
        start: n,
        sandbox: Some(t.clone()),
        via: Some(t.clone()),
        peer: Some(t.clone()),
        at_ms: n,
        seq: n,
        outcome: Outcome::Failed {
            why: Failure::Abandoned,
            error: Some(t.clone()),
        },
        cache: Some(Cache::Prefetched),
        carries: Some(n),
        results: Some(n),
        model: t.clone(),
        gen_ms: Some(n),
        cost: Some(serde_json::Number::from_f64(f64::MAX).unwrap()),
        serve_ms: Some(n),
        answer_seq: Some(n),
        answer_at_ms: Some(n),
    };
    let list = Results {
        key: t.clone(),
        listed: vec![
            Listed {
                rank: n,
                url: t.clone(),
                host: t.clone(),
                site: t.clone(),
                title: t.clone()
            };
            MAX_LISTED
        ],
        cache: Cache::Prefetched,
        query_id: n,
    };
    let p = Page {
        seq: n,
        first_serve_ms: Some(n),
        url: t.clone(),
        host: t.clone(),
        site: t.clone(),
        at_ms: n,
        fetches: n,
        status: Some(n),
        via: Some(t.clone()),
        making: false,
        waiting: false,
        carries: Some(n),
        title: t.clone(),
        model: t.clone(),
        cache: Cache::Prefetched,
        serve_ms: Some(n),
        gen_ms: Some(n),
        cost: Some(serde_json::Number::from_f64(f64::MAX).unwrap()),
        latest_serve_ms: Some(n),
        reason: Reason::Search {
            query: t.clone(),
            rank: n,
        },
        made: Made::WrittenLive,
        latest: Made::WrittenLive,
    };
    let site = Site {
        host: t.clone(),
        site: t.clone(),
        address: t.clone(),
        reason: SiteReason::SearchEngine,
        at_ms: n,
    };
    let refused = Refused {
        name: t.clone(),
        reason: t.clone(),
        at_ms: n,
    };
    let snapshot = Snapshot {
        revision: n,
        at_ms: n,
        seed,
        generator: Generator {
            model_calls: n,
            model_cost_known: serde_json::Number::from_f64(f64::MAX).unwrap(),
            model_cost_unknown: n,
            kind: GeneratorKind::Model(Provider::OpenRouter),
            model: t.clone(),
            prefetch: n,
            generate: false,
            generation_revision: n,
            generation_at_ms: n,
            copied: false,
            live_search: false,
            live_available: false,
        },
        queries: vec![q; MAX_QUERIES],
        results: vec![list; MAX_RESULTS],
        pages: vec![p; MAX_PAGES],
        sites: vec![site; MAX_SITES],
        refused: vec![refused; MAX_REFUSED],
        planted: vec![
            Plant {
                kind: t.clone(),
                text: t.clone(),
                url: t.clone(),
                at_ms: n,
            };
            MAX_PLANTED
        ],
        omitted: Omitted {
            queries: n,
            results: n,
            listed: n,
            pages: n,
            sites: n,
            refused: n,
            planted: n,
        },
    };
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    assert!(
        encoded.len() <= MAX_SNAPSHOT_BYTES,
        "{} bytes",
        encoded.len()
    );
    assert_eq!(encoded.len(), MAX_SNAPSHOT_BYTES);
}

#[test]
fn failed_answer_keeps_generation_timing() {
    let s = searches();
    feed(&s, 1, query(1, "google", "q"));
    feed(
        &s,
        2,
        Event::new("web", "query_failed")
            .field("query_id", 1u64)
            .field("why", "error")
            .field("error", "generation failed")
            .field("serve_ms", 40u64),
    );
    let answer = Event::new("http", "request")
        .field("query_id", 1u64)
        .field("kind", "error")
        .field("status", 503u64)
        .field("complete", true)
        .field("serve_ms", 40u64)
        .field("gen_ms", 35u64);
    feed(&s, 3, answer.clone());
    let state = s.snapshot();
    assert_eq!(
        state.queries[0].outcome,
        Outcome::Failed {
            why: Failure::Error,
            error: Some("generation failed".into())
        }
    );
    assert_eq!(state.queries[0].gen_ms, Some(35));
    assert_eq!(state.queries[0].answer_seq, Some(3));
    feed(&s, 3, answer);
    assert_eq!(s.snapshot(), state);
}

#[test]
fn revision_tracks_changes_without_a_snapshot() {
    let s = searches();
    assert_eq!(s.revision(), 0);
    feed(&s, 1, query(1, "google", "a"));
    assert_eq!(s.revision(), 1);
    feed(&s, 2, Event::new("other", "event"));
    assert_eq!(s.revision(), 1);
    assert_eq!(s.revision(), s.snapshot().revision);
}

#[test]
fn an_agents_own_search_shows_as_a_search_with_its_list() {
    let s = searches();
    feed(
        &s,
        1,
        query(7, "google", "Python itertools").field("via", "web_search"),
    );
    feed(
        &s,
        2,
        Event::new("web", "search_answer")
            .field("query_id", 7u64)
            .field("kind", "search")
            .field("cache", "cached")
            .field("results", 1u64)
            .field("complete", true)
            .field(
                "listed",
                vec![field(
                    &json!({"rank": 1, "url": "https://a.com/x", "title": "A"}),
                )],
            ),
    );
    let snap = s.snapshot();
    let q = &snap.queries[0];
    assert_eq!(q.via.as_deref(), Some("web_search"));
    assert_eq!(q.sandbox, None);
    assert_eq!(q.outcome, Outcome::Served);
    assert_eq!(q.cache, Some(Cache::Cached));
    assert_eq!(snap.results[0].listed[0].host, "a.com");
}

#[test]
fn a_restart_clears_what_the_run_showed_and_plants_are_kept_in_order() {
    let s = searches();
    feed(&s, 1, query(1, "google", "a"));
    feed(
        &s,
        2,
        Event::new("web", "planted")
            .field("plant", "fact")
            .field("text", "The fix is 7.2.5, not 7.2.4.")
            .field("url", ""),
    );
    let snap = s.snapshot();
    assert_eq!(snap.planted[0].kind, "fact");
    assert_eq!(snap.queries.len(), 1);
    feed(
        &s,
        3,
        Event::new("web", "restarted").field("revision", 2u64),
    );
    let snap = s.snapshot();
    assert!(snap.queries.is_empty() && snap.planted.is_empty());
}

#[test]
fn model_server_tools_publish_the_world_search_and_fetch() {
    for stream in [false, true] {
        model_world_tools(stream);
    }
}

#[test]
fn pages_being_made_finish_with_the_latest_tool_and_reach() {
    let s = searches();
    let making = || {
        Event::new("web", "making")
            .field("url", "https://a.com/a")
            .field("host", "a.com")
    };
    feed(&s, 1, making());
    let pending = s.snapshot().pages[0].clone();
    assert!(pending.making);
    assert_eq!(pending.status, None);
    assert_eq!(pending.carries, None);
    assert_eq!(pending.fetches, 0);
    feed(
        &s,
        2,
        page("/a", "generated", "stored", json!({"via":"direct"}))
            .field("via", "web_fetch")
            .field("carries", 1u64),
    );
    let first = s.snapshot().pages[0].clone();
    assert!(!first.making);
    assert_eq!(first.via.as_deref(), Some("web_fetch"));
    assert_eq!(first.carries, Some(1));
    assert_eq!(first.status, Some(200));
    assert_eq!(first.fetches, 1);
    assert_eq!(first.made, Made::FromStore);
    feed(
        &s,
        3,
        page("/a", "cached", "stored", json!(null)).field("carries", 0u64),
    );
    let repeated = s.snapshot().pages[0].clone();
    assert_eq!(repeated.via, None);
    assert_eq!(repeated.carries, Some(0));
    assert_eq!(repeated.fetches, 2);
    feed(&s, 4, making());
    assert!(s.snapshot().pages[0].making);
    feed(
        &s,
        5,
        page("/a", "budget", "", json!(null))
            .field("status", 503u64)
            .field("carries", 0u64),
    );
    let failed = s.snapshot().pages[0].clone();
    assert!(!failed.making);
    assert_eq!(failed.status, Some(503));
    assert_eq!(failed.made, Made::FromStore);
    assert_eq!(failed.fetches, 3);
    feed(&s, 6, making());
    feed(
        &s,
        7,
        Event::new("web", "page_failed")
            .field("url", "https://a.com/a")
            .field("status", 500u64),
    );
    assert!(!s.snapshot().pages[0].making);
    assert_eq!(s.snapshot().pages[0].status, Some(500));
    feed(&s, 8, query(1, "google", "python"));
    assert_eq!(s.snapshot().queries[0].carries, None);
    feed(&s, 9, answer(1, true).field("carries", 1u64));
    assert_eq!(s.snapshot().queries[0].carries, Some(1));
    for i in 0..MAX_PAGES {
        feed(
            &s,
            10 + i as u64,
            Event::new("web", "making")
                .field("url", format!("https://a.com/{i}"))
                .field("host", "a.com"),
        );
    }
    assert_eq!(s.snapshot().pages.len(), MAX_PAGES);
    assert_eq!(s.snapshot().omitted.pages, 1);
}

#[test]
fn making_events_precede_page_work_and_failed_fetches_finish_the_row() {
    use fictionet_extras::models::Engine as _;
    use std::sync::{Arc, Mutex};
    struct Pending {
        searches: Arc<Searches>,
        pages: Mutex<Vec<Page>>,
    }
    impl Observer for Pending {
        fn enabled(&self, interest: Interest<'_>) -> bool {
            matches!(
                interest,
                Interest::Event(
                    Metadata {
                        source: "web",
                        kind: "making"
                    },
                    _
                )
            )
        }
        fn observe(&self, _: Stamp, _: Observation<'_>) {
            self.pages
                .lock()
                .unwrap()
                .push(self.searches.snapshot().pages.last().unwrap().clone());
        }
    }
    let pages = Arc::new(Pages::new(Seed::builtin("web").unwrap()));
    let searches = Arc::new(Searches::of(&pages));
    let pending = Arc::new(Pending {
        searches: searches.clone(),
        pages: Mutex::new(Vec::new()),
    });
    let seen = pending.clone();
    let observer = Arc::new(fictionet::events::Fanout::new(vec![
        searches.clone(),
        pending,
    ]));
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(9)).observer(observer),
        move |cx| async move {
            let url = "http://news.example-wire.com/python-update";
            pages.clone().fetch(cx.clone(), url.into()).await?;
            let snapshot = searches.snapshot();
            assert_eq!(snapshot.pages.len(), 1);
            assert_eq!(snapshot.pages[0].url, url);
            assert!(!snapshot.pages[0].making);
            assert_eq!(snapshot.pages[0].status, Some(200));
            for i in 0..web_world::pages::GENERATION_BUDGET {
                let _ = pages
                    .clone()
                    .fetch(
                        cx.clone(),
                        format!("https://news.example-wire.com/page-{i}"),
                    )
                    .await;
            }
            let failed = pages
                .clone()
                .fetch(cx, "https://news.example-wire.com/last".into())
                .await;
            assert!(failed.is_err());
            let snapshot = searches.snapshot();
            let last = snapshot.pages.last().unwrap();
            assert!(!last.making);
            assert_eq!(last.status, Some(503));
            assert_eq!(last.via.as_deref(), Some("web_fetch"));
            assert_eq!(last.carries, Some(0));
            Ok(())
        },
    ))
    .unwrap();
    let pending = seen.pages.lock().unwrap();
    assert!(!pending.is_empty());
    assert!(
        pending
            .iter()
            .all(|p| p.making && p.status.is_none() && p.carries.is_none() && p.fetches == 0)
    );
}

#[test]
fn host_rows_keep_display_names() {
    let s = searches();
    feed(&s, 1, query(1, "google", "a"));
    feed(&s, 2, answer(1, true).field("listed", field(&json!([
        {"rank": 1, "url": "https://docs.python.org/", "title": "Functions", "site": "Python Documentation"}
    ]))));
    feed(
        &s,
        3,
        Event::new("web", "making")
            .field("url", "https://a.com/new")
            .field("host", "a.com")
            .field("site", "A Company"),
    );
    assert_eq!(s.snapshot().pages[0].site, "A Company");
    feed(
        &s,
        4,
        page("/new", "generated", "stored", json!(null)).field("site", "A Company"),
    );
    feed(
        &s,
        5,
        Event::new("web", "site")
            .field("host", "a.com")
            .field("site", "A Company"),
    );
    let snap = s.snapshot();
    assert_eq!(snap.results[0].listed[0].site, "Python Documentation");
    assert_eq!(snap.pages[0].site, "A Company");
    assert_eq!(snap.sites[0].site, "A Company");
}
