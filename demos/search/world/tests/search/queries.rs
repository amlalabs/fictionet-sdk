//! Retained behavioral coverage.

use super::*;

#[test]
fn generation_events_update_the_card() {
    let s = searches();
    assert!(s.enabled(Interest::Event(
        Metadata {
            source: "web",
            kind: "generation"
        },
        &ConnInfo::default()
    )));
    feed(&s, 1, query(1, "google", "a"));
    let generation = |generate, revision: u64| {
        Event::new("web", "generation")
            .field("generate", generate)
            .field("revision", revision)
    };
    feed(&s, 2, generation(false, 1));
    let off = s.snapshot();
    assert!(!off.generator.generate);
    assert_eq!(off.generator.generation_revision, 1);
    assert_eq!(off.generator.generation_at_ms, 20);
    assert_eq!((off.revision, off.at_ms), (2, 20));
    for event in [
        generation(false, 1),
        generation(true, 0),
        Event::new("web", "generation").field("revision", 2u64),
        Event::new("web", "generation").field("generate", true),
    ] {
        feed(&s, 3, event);
        assert_eq!(s.snapshot(), off);
    }
    feed(&s, 4, generation(true, 2));
    let on = s.snapshot();
    assert!(on.generator.generate);
    assert_eq!(on.generator.generation_revision, 2);
    assert_eq!(on.generator.generation_at_ms, 40);
    assert_eq!((on.revision, on.at_ms), (3, 40));
    assert_eq!(on.queries, off.queries);
    let seed = Seed::builtin("web").unwrap();
    let replay = Pages::open(seed, Store::memory(), None, 0);
    let replay = Searches::of(&replay).snapshot();
    assert!(!replay.generator.generate);
    assert_eq!(replay.generator.kind, GeneratorKind::Replay);
    assert_eq!(replay.generator.model, "replay");
    assert_eq!(replay.generator.generation_revision, 0);
}

#[test]
fn query_lifecycle_and_shared_results() {
    let s = searches();
    feed(&s, 1, query(1, "google", "a"));
    let pending = s.snapshot();
    assert_eq!(pending.queries[0].outcome, Outcome::Pending);
    assert_eq!(
        (pending.revision, pending.at_ms, pending.queries[0].seq),
        (1, 10, 1)
    );
    feed(&s, 2, answer(1, true));
    feed(&s, 3, query(2, "bing", "a"));
    feed(&s, 4, answer(2, false).field("cache", "cached"));
    let state = s.snapshot();
    assert_eq!(state.queries[0].outcome, Outcome::Served);
    assert_eq!(state.queries[1].outcome, Outcome::Undelivered);
    assert_eq!(state.queries[0].answer_seq, Some(2));
    assert_eq!(state.queries[0].answer_at_ms, Some(20));
    assert_eq!(state.queries[0].serve_ms, Some(20));
    assert_eq!(state.results.len(), 1);
    assert_eq!(state.results[0].query_id, 1);
    assert_eq!(state.results[0].cache, Cache::Generated);
    assert_eq!(state.results[0].listed[0].host, "a.com");
    assert_eq!(state.revision, 4);
    feed(&s, 5, answer(2, false));
    feed(&s, 6, query(2, "bing", "a"));
    feed(&s, 7, Event::new("tls", "handshake"));
    feed(&s, 8, Event::new("http", "request"));
    assert_eq!(s.snapshot(), state);
    assert_eq!(
        serde_json::from_slice::<Snapshot>(&serde_json::to_vec(&state).unwrap()).unwrap(),
        state
    );
    assert!(!s.enabled(Interest::Event(
        Metadata {
            source: "http",
            kind: "other"
        },
        &ConnInfo::default()
    )));
    assert!(!s.enabled(Interest::Event(
        Metadata {
            source: "dns",
            kind: "query"
        },
        &ConnInfo::default()
    )));
    assert!(!s.enabled(Interest::Topology(TopologyKind::Link)));
}

#[test]
fn a_list_made_later_replaces_the_empty_one() {
    let s = searches();
    feed(&s, 1, query(1, "google", "a"));
    let empty = answer(1, true)
        .field("cache", "missing")
        .field("results", 0u64)
        .field("listed", field(&json!([])));
    feed(&s, 2, empty);
    let off = s.snapshot();
    assert_eq!(off.queries[0].results, Some(0));
    assert_eq!(off.results.len(), 1);
    assert!(off.results[0].listed.is_empty());
    assert_eq!(off.results[0].cache, Cache::Missing);

    feed(&s, 3, query(2, "bing", "a"));
    feed(&s, 4, answer(2, true));
    let on = s.snapshot();
    assert_eq!(on.results.len(), 1);
    assert_eq!(on.results[0].query_id, 2);
    assert_eq!(on.results[0].cache, Cache::Generated);
    assert_eq!(on.results[0].listed[0].url, "https://a.com/");

    feed(&s, 5, query(3, "google", "a"));
    feed(&s, 6, answer(3, true).field("cache", "cached"));
    assert_eq!(s.snapshot().results, on.results);
}

#[test]
fn failed_queries() {
    let s = searches();
    for (id, why, expected) in [
        (1, "abandoned", Failure::Abandoned),
        (2, "budget", Failure::Budget),
    ] {
        feed(&s, id * 2, query(id, "duckduckgo", "q"));
        let event = Event::new("web", "query_failed")
            .field("query_id", id)
            .field("why", why)
            .field("error", "stopped")
            .field("serve_ms", 8u64);
        feed(&s, id * 2 + 1, event.clone());
        let snapshot = s.snapshot();
        let q = snapshot.queries.last().unwrap();
        assert_eq!(
            q.outcome,
            Outcome::Failed {
                why: expected,
                error: Some("stopped".into())
            }
        );
        assert_eq!(q.serve_ms, Some(8));
        assert_eq!(q.cache, (id == 2).then_some(Cache::Budget));
        feed(&s, 20, event);
        feed(&s, 21, answer(id, true));
        assert_eq!(snapshot, s.snapshot());
    }
}

#[test]
fn page_creation_and_fetches() {
    let s = searches();
    let cases = [
        (
            "generated",
            "stored",
            json!({"via":"search","query":"q","rank":2}),
            Made::FromStore,
            Reason::Search {
                query: "q".into(),
                rank: 2,
            },
        ),
        (
            "prefetched",
            "model",
            json!({"via":"link","from":"https://source.com/"}),
            Made::WrittenLive,
            Reason::Link {
                from: "https://source.com/".into(),
            },
        ),
        (
            "cached",
            "stored",
            json!({"via":"direct"}),
            Made::Stored,
            Reason::Direct,
        ),
        (
            "fixed",
            "",
            json!({"via":"fixed"}),
            Made::Fixed,
            Reason::Fixed,
        ),
        ("missing", "", json!(null), Made::Missing, Reason::Unknown),
        ("budget", "", json!(null), Made::NotMade, Reason::Unknown),
        (
            "new_cache",
            "",
            json!({"via":"future"}),
            Made::Unknown,
            Reason::Unknown,
        ),
    ];
    for (i, (cache, model, reason, made, expected)) in cases.into_iter().enumerate() {
        feed(
            &s,
            i as u64 + 1,
            page(&format!("/{i}"), cache, model, reason),
        );
        let snap = s.snapshot();
        let p = snap.pages.last().unwrap();
        assert_eq!(p.made, made);
        assert_eq!(p.latest, made);
        assert_eq!(p.reason, expected);
    }
    feed(
        &s,
        9,
        page("/0", "cached", "stored", json!({"via":"direct"})).field("serve_ms", 3u64),
    );
    let snap = s.snapshot();
    let p = snap.pages.last().unwrap();
    assert_eq!(p.made, Made::FromStore);
    assert_eq!(p.latest, Made::Stored);
    assert_eq!(p.cache, Cache::Generated);
    assert_eq!(p.seq, 1);
    assert_eq!(p.first_serve_ms, Some(20));
    assert_eq!(
        p.reason,
        Reason::Search {
            query: "q".into(),
            rank: 2
        }
    );
    assert_eq!(
        (p.at_ms, p.fetches, p.serve_ms, p.latest_serve_ms, p.gen_ms),
        (10, 2, Some(20), Some(3), Some(15))
    );
}

#[test]
fn a_page_made_after_a_404_takes_its_reason_from_the_fetch_that_made_it() {
    let s = searches();
    for (seq, cache) in [(1, "missing"), (2, "budget")] {
        feed(
            &s,
            seq,
            page("/later", cache, "", json!(null)).field("status", 404u64),
        );
    }
    let missing = s.snapshot();
    assert_eq!(missing.pages[0].made, Made::Missing);
    assert_eq!(missing.pages[0].latest, Made::NotMade);
    assert_eq!(missing.pages[0].reason, Reason::Unknown);

    feed(
        &s,
        3,
        page("/later", "generated", "stored", json!({"via":"direct"})).field("serve_ms", 5u64),
    );
    let made = s.snapshot();
    let p = &made.pages[0];
    assert_eq!((p.made, p.latest), (Made::FromStore, Made::FromStore));
    assert_eq!(p.reason, Reason::Direct);
    assert_eq!(p.cache, Cache::Generated);
    assert_eq!(p.seq, 1);
    assert_eq!(p.first_serve_ms, Some(20));
    assert_eq!((p.title.as_str(), p.model.as_str()), ("Title", "stored"));
    assert_eq!((p.serve_ms, p.gen_ms), (Some(5), Some(15)));
    assert_eq!((p.at_ms, p.fetches, p.status), (10, 3, Some(200)));

    feed(
        &s,
        4,
        page(
            "/later",
            "cached",
            "stored",
            json!({"via":"link","from":"https://b.com/"}),
        ),
    );
    let p = s.snapshot().pages[0].clone();
    assert_eq!((p.made, p.latest), (Made::FromStore, Made::Stored));
    assert_eq!(p.reason, Reason::Direct);
    assert_eq!(p.fetches, 4);
}

#[test]
fn sites_refusals_and_eviction() {
    let s = searches();
    for (i, (why, reason)) in [
        ("search engine", SiteReason::SearchEngine),
        ("seed", SiteReason::Seed),
        ("recorded", SiteReason::Recorded),
        ("pool", SiteReason::Pool),
    ]
    .into_iter()
    .enumerate()
    {
        let e = Event::new("web", "site")
            .field("host", format!("{i}.com"))
            .field("addr", "1.2.3.4")
            .field("why", why);
        feed(&s, i as u64 + 1, e.clone());
        assert_eq!(s.snapshot().sites[i].reason, reason);
        let before = s.snapshot();
        feed(&s, 10, e);
        assert_eq!(s.snapshot(), before);
    }
    for i in 4..MAX_SITES + 2 {
        feed(
            &s,
            20 + i as u64,
            Event::new("web", "site").field("host", format!("{i}.com")),
        );
    }
    for i in 0..MAX_REFUSED + 2 {
        feed(
            &s,
            200 + i as u64,
            Event::new("web", "refused")
                .field("host", format!("bad{i}"))
                .field("why", "single label"),
        );
    }
    for i in 0..MAX_QUERIES + 2 {
        feed(
            &s,
            300 + i as u64,
            query(i as u64, "google", &format!("q{i}")),
        );
    }
    for i in 0..MAX_PAGES + 2 {
        feed(
            &s,
            400 + i as u64,
            page(
                &format!("/{i}"),
                "cached",
                "stored",
                json!({"via":"direct"}),
            ),
        );
    }
    for i in 0..MAX_RESULTS + 2 {
        let id = 1000 + i as u64;
        feed(&s, id, query(id, "google", &format!("r{i}")));
        feed(&s, id + 1, answer(id, true));
    }
    let snap = s.snapshot();
    assert_eq!(snap.sites.len(), MAX_SITES);
    assert_eq!(snap.sites[0].host, "0.com");
    assert_eq!(snap.omitted.sites, 2);
    assert_eq!(snap.refused.len(), MAX_REFUSED);
    assert_eq!(snap.refused[0].name, "bad2");
    assert_eq!(snap.omitted.refused, 2);
    assert_eq!(snap.queries.len(), MAX_QUERIES);
    assert_eq!(snap.omitted.queries, 2 + MAX_RESULTS as u64 + 2);
    assert_eq!(snap.pages.len(), MAX_PAGES);
    assert_eq!(snap.pages[0].url, "https://a.com/2");
    assert_eq!(snap.omitted.pages, 2);
    assert_eq!(snap.results.len(), MAX_RESULTS);
    assert_eq!(snap.results[0].key, "r2");
    assert_eq!(snap.omitted.results, 2);
}

#[test]
fn strings_and_lists_are_bounded() {
    let long = "é".repeat(STRING_BYTES + 1);
    let s = Searches::new(
        SeedCard {
            name: long.clone(),
            instructions: long.clone(),
            ..SeedCard::default()
        },
        Generator::default(),
    );
    feed(&s, 1, query(1, "google", &long));
    let listed = vec![
        json!({"rank":1,"url":format!("https://a.com/{long}"),"title":long,"site":long});
        MAX_LISTED + 3
    ];
    feed(
        &s,
        2,
        answer(1, true).field("listed", field(&json!(listed))),
    );
    let snap = s.snapshot();
    assert_eq!(snap.seed.name.len(), STRING_BYTES);
    assert_eq!(snap.seed.instructions.len(), STRING_BYTES);
    assert_eq!(snap.queries[0].search.len(), STRING_BYTES);
    assert_eq!(snap.results[0].listed.len(), MAX_LISTED);
    assert_eq!(snap.omitted.listed, 3);
    assert_eq!(snap.results[0].listed[0].title.len(), STRING_BYTES);
    assert_eq!(snap.results[0].listed[0].site.len(), STRING_BYTES);
    feed(
        &s,
        3,
        page("/name", "generated", "stored", json!(null)).field("site", long.clone()),
    );
    feed(
        &s,
        4,
        Event::new("web", "site")
            .field("host", "a.com")
            .field("site", long),
    );
    let snap = s.snapshot();
    assert_eq!(snap.pages[0].site.len(), STRING_BYTES);
    assert_eq!(snap.sites[0].site.len(), STRING_BYTES);
}
