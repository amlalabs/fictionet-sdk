use adaptive_web_world::backend::to_field;
use adaptive_web_world::route::Engine;
use adaptive_web_world::search::*;
use fictionet::events::{
    ConnInfo, Event, Interest, Metadata, Observation, Observer, Stamp, Stream, TopologyKind,
};
use fictionet::time::Instant;
use serde_json::json;

fn feed(s: &Searches, seq: u64, event: Event) {
    s.observe(
        Stamp {
            stream: Stream::Events,
            seq,
            at: Instant::from_since_start(std::time::Duration::from_millis(seq * 10)),
        },
        Observation::Event(&event),
    );
}
fn searches() -> Searches {
    Searches::new(SeedCard::default(), Generator::default())
}

#[test]
fn generation_events_update_the_card() {
    let s = searches();
    assert!(s.enabled(Interest::Event(
        Metadata {
            source: "adaptive",
            kind: "generation"
        },
        &ConnInfo::default()
    )));
    feed(&s, 1, query(1, "google", "a"));
    let generation = |generate, revision: u64| {
        Event::new("adaptive", "generation")
            .field("generate", generate)
            .field("revision", revision)
    };
    feed(&s, 2, generation(false, 1));
    let off = s.snapshot();
    assert!(!off.generator.generate);
    assert_eq!(off.generator.generation_revision, 1);
    assert_eq!((off.revision, off.at_ms), (2, 20));
    for event in [
        generation(false, 1),
        generation(true, 0),
        Event::new("adaptive", "generation").field("revision", 2u64),
        Event::new("adaptive", "generation").field("generate", true),
    ] {
        feed(&s, 3, event);
        assert_eq!(s.snapshot(), off);
    }
    feed(&s, 4, generation(true, 2));
    let on = s.snapshot();
    assert!(on.generator.generate);
    assert_eq!(on.generator.generation_revision, 2);
    assert_eq!((on.revision, on.at_ms), (3, 40));
    assert_eq!(on.queries, off.queries);
    let replay = Searches::from_hello(&json!({"generator":"replay"})).snapshot();
    assert!(!replay.generator.generate);
    assert_eq!(replay.generator.generation_revision, 0);
}

fn query(id: u64, engine: &str, key: &str) -> Event {
    Event::new("adaptive", "query")
        .field("query_id", id)
        .field("engine", engine)
        .field("key", key)
        .field("search", key)
        .field("start", 0u64)
}
fn answer(id: u64, complete: bool) -> Event {
    Event::new("http", "request")
        .field("query_id", id)
        .field("query", "q=a")
        .field("kind", "search")
        .field("cache", "generated")
        .field("complete", complete)
        .field("results", 1u64)
        .field("serve_ms", 20u64)
        .field("gen_ms", 15u64)
        .field(
            "listed",
            to_field(&json!([{"rank":1,"url":"https://a.com/","title":"A"}])),
        )
}
fn page(path: &str, cache: &str, model: &str, reason: serde_json::Value) -> Event {
    Event::new("http", "request")
        .field("kind", "page")
        .field("scheme", "https")
        .field("host", "a.com")
        .field("path", path)
        .field("status", 200u64)
        .field("cache", cache)
        .field("model", model)
        .field("reason", to_field(&reason))
        .field("serve_ms", 20u64)
        .field("gen_ms", 15u64)
        .field("title", "Title")
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
fn failed_queries() {
    let s = searches();
    for (id, why, expected) in [
        (1, "abandoned", Failure::Abandoned),
        (2, "budget", Failure::Budget),
    ] {
        feed(&s, id * 2, query(id, "duckduckgo", "q"));
        let event = Event::new("adaptive", "query_failed")
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
            "stub",
            json!({"via":"search","query":"q","rank":2}),
            Made::Stubbed,
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
            "stub",
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
        page("/0", "cached", "stub", json!({"via":"direct"})).field("serve_ms", 3u64),
    );
    let snap = s.snapshot();
    let p = snap.pages.last().unwrap();
    assert_eq!(p.made, Made::Stubbed);
    assert_eq!(p.latest, Made::Stored);
    assert_eq!(p.cache, Cache::Generated);
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
        let e = Event::new("adaptive", "site")
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
            Event::new("adaptive", "site").field("host", format!("{i}.com")),
        );
    }
    for i in 0..MAX_REFUSED + 2 {
        feed(
            &s,
            200 + i as u64,
            Event::new("adaptive", "refused")
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
            page(&format!("/{i}"), "cached", "stub", json!({"via":"direct"})),
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
            facts: vec![long.clone(); MAX_SEED_ITEMS + 1],
            sites: vec![long.clone(); MAX_SEED_ITEMS + 2],
            ..SeedCard::default()
        },
        Generator::default(),
    );
    feed(&s, 1, query(1, "google", &long));
    let listed =
        vec![json!({"rank":1,"url":format!("https://a.com/{long}"),"title":long}); MAX_LISTED + 3];
    feed(
        &s,
        2,
        answer(1, true).field("listed", to_field(&json!(listed))),
    );
    let snap = s.snapshot();
    assert_eq!(snap.seed.name.len(), STRING_BYTES);
    assert_eq!(snap.seed.facts.len(), MAX_SEED_ITEMS);
    assert_eq!(snap.omitted.seed_facts, 1);
    assert_eq!(snap.omitted.seed_sites, 2);
    assert_eq!(snap.queries[0].search.len(), STRING_BYTES);
    assert_eq!(snap.results[0].listed.len(), MAX_LISTED);
    assert_eq!(snap.omitted.listed, 3);
    assert_eq!(snap.results[0].listed[0].title.len(), STRING_BYTES);
}
#[test]
fn worst_case_snapshot_fits() {
    let t = "\u{0001}".repeat(STRING_BYTES);
    let n = u64::MAX;
    let seed = SeedCard {
        name: t.clone(),
        date: t.clone(),
        question: t.clone(),
        facts: vec![t.clone(); MAX_SEED_ITEMS],
        sites: vec![t.clone(); MAX_SEED_ITEMS],
    };
    let q = Query {
        id: n,
        key: t.clone(),
        search: t.clone(),
        engine: Engine::DuckDuckGo,
        start: n,
        sandbox: Some(t.clone()),
        peer: Some(t.clone()),
        at_ms: n,
        seq: n,
        outcome: Outcome::Failed {
            why: Failure::BackendError,
            error: Some(t.clone()),
        },
        cache: Some(Cache::Prefetched),
        results: Some(n),
        gen_ms: Some(n),
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
                title: t.clone()
            };
            MAX_LISTED
        ],
        cache: Cache::Prefetched,
        query_id: n,
    };
    let p = Page {
        url: t.clone(),
        host: t.clone(),
        at_ms: n,
        fetches: n,
        status: n,
        title: t.clone(),
        model: t.clone(),
        cache: Cache::Prefetched,
        serve_ms: Some(n),
        gen_ms: Some(n),
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
            kind: GeneratorKind::Openrouter,
            model: t,
            prefetch: n,
            generate: false,
            generation_revision: n,
        },
        queries: vec![q; MAX_QUERIES],
        results: vec![list; MAX_RESULTS],
        pages: vec![p; MAX_PAGES],
        sites: vec![site; MAX_SITES],
        refused: vec![refused; MAX_REFUSED],
        omitted: Omitted {
            queries: n,
            results: n,
            listed: n,
            pages: n,
            sites: n,
            refused: n,
            seed_facts: n,
            seed_sites: n,
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
        Event::new("adaptive", "query_failed")
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
