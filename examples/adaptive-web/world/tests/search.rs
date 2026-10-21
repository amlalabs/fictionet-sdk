use adaptive_web_world::pages::model::Provider;
use adaptive_web_world::pages::{GeneratorKind, Pages, Seed, store::Store};
use adaptive_web_world::search::*;
use example_common::events::field;
use fictionet::events::{
    ConnInfo, Event, Interest, Metadata, Observation, Observer, Stamp, Stream, TopologyKind,
};
use fictionet::time::Instant;
use fictionet_extras::search::Engine;
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
    assert_eq!(off.generator.generation_at_ms, 20);
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
    assert_eq!(on.generator.generation_at_ms, 40);
    assert_eq!((on.revision, on.at_ms), (3, 40));
    assert_eq!(on.queries, off.queries);
    let seed = Seed::builtin("halvard-cve").unwrap();
    let replay = Pages::open(seed, Store::memory(), None, 0);
    let replay = Searches::of(&replay).snapshot();
    assert!(!replay.generator.generate);
    assert_eq!(replay.generator.kind, GeneratorKind::Replay);
    assert_eq!(replay.generator.model, "replay");
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
            field(&json!([{"rank":1,"url":"https://a.com/","title":"A"}])),
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
        .field("reason", field(&reason))
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
        page("/later", "generated", "stub", json!({"via":"direct"})).field("serve_ms", 5u64),
    );
    let made = s.snapshot();
    let p = &made.pages[0];
    assert_eq!((p.made, p.latest), (Made::Stubbed, Made::Stubbed));
    assert_eq!(p.reason, Reason::Direct);
    assert_eq!(p.cache, Cache::Generated);
    assert_eq!(p.seq, 1);
    assert_eq!(p.first_serve_ms, Some(20));
    assert_eq!((p.title.as_str(), p.model.as_str()), ("Title", "stub"));
    assert_eq!((p.serve_ms, p.gen_ms), (Some(5), Some(15)));
    assert_eq!((p.at_ms, p.fetches, p.status), (10, 3, Some(200)));

    feed(
        &s,
        4,
        page(
            "/later",
            "cached",
            "stub",
            json!({"via":"link","from":"https://b.com/"}),
        ),
    );
    let p = s.snapshot().pages[0].clone();
    assert_eq!((p.made, p.latest), (Made::Stubbed, Made::Stored));
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
            sites: vec![
                NamedSite {
                    host: long.clone(),
                    site: long.clone()
                };
                MAX_SEED_ITEMS + 2
            ],
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
    assert_eq!(snap.seed.facts.len(), MAX_SEED_ITEMS);
    assert_eq!(snap.omitted.seed_facts, 1);
    assert_eq!(snap.omitted.seed_sites, 2);
    assert_eq!(snap.seed.sites[0].site.len(), STRING_BYTES);
    assert_eq!(snap.queries[0].search.len(), STRING_BYTES);
    assert_eq!(snap.results[0].listed.len(), MAX_LISTED);
    assert_eq!(snap.omitted.listed, 3);
    assert_eq!(snap.results[0].listed[0].title.len(), STRING_BYTES);
    assert_eq!(snap.results[0].listed[0].site.len(), STRING_BYTES);
    feed(
        &s,
        3,
        page("/name", "generated", "stub", json!(null)).field("site", long.clone()),
    );
    feed(
        &s,
        4,
        Event::new("adaptive", "site")
            .field("host", "a.com")
            .field("site", long),
    );
    let snap = s.snapshot();
    assert_eq!(snap.pages[0].site.len(), STRING_BYTES);
    assert_eq!(snap.sites[0].site.len(), STRING_BYTES);
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
        sites: vec![
            NamedSite {
                host: t.clone(),
                site: t.clone()
            };
            MAX_SEED_ITEMS
        ],
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
            canned: false,
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
        query(7, "google", "halvard advisory").field("via", "web_search"),
    );
    feed(
        &s,
        2,
        Event::new("adaptive", "search_answer")
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
        Event::new("adaptive", "planted")
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
        Event::new("adaptive", "restarted").field("revision", 2u64),
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

fn model_world_tools(stream: bool) {
    use adaptive_web_world::pages::{Pages as WorldPages, Seed as WorldSeed};
    use fictionet::stdlib::web::{Body, httpd};
    use fictionet_extras::models::{Credential, Model, Provider, Secret};
    use http_body_util::BodyExt;
    use std::io::{Read, Write};
    use std::sync::Arc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let url = "https://www.halvardsystems.com/security/advisories/HSA-2026-014";
    let words = "Halvard Gateway HG-400 CVE-2026-41877 security advisory";
    let server = std::thread::spawn(move || {
        for content in [
            json!([{"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":words}}]),
            json!([{"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":url}}]),
            json!([{"type":"text","text":"Done."}]),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let size: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; size];
            socket.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(request["tools"][0].get("type").is_none());
            let stop = if content[0]["type"] == "text" {
                "end_turn"
            } else {
                "tool_use"
            };
            let body = json!({"type":"message","id":"msg_page","role":"assistant","model":"claude","content":content,"stop_reason":stop,"usage":{"input_tokens":7,"output_tokens":2}}).to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let state = Arc::new(Searches::from_seed(
        &WorldSeed::builtin("halvard-cve").unwrap(),
    ));
    let observed = state.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(8)).observer(state),
        move |cx| async move {
            let pages = Arc::new(WorldPages::new(WorldSeed::builtin("halvard-cve").unwrap()));
            let credential = Credential::api_key(&cx, Secret::new("ANTHROPIC_API_KEY", "sk-ant-api03-private".into())?);
            let key = credential.placeholder().to_owned();
            let model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?.search(pages);
            let body = json!({"model":"claude","stream":stream,"max_tokens":1000,"messages":[{"role":"user","content":format!("Search for {words}, then read {url}")}],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":8},{"type":"web_fetch_20250910","name":"web_fetch","max_uses":8}]});
            let request = http::Request::post("/v1/messages").header("x-api-key", key).body(Body::from(body.to_string()))?;
            let conn = ConnInfo::default();
            let mut exchange = httpd::Exchange::new(cx.now(), &cx, &conn);
            let httpd::Reply::Later(work) = httpd::Handler::call(&model, request, &mut exchange) else { panic!("expected deferred model reply") };
            let response = work(cx.clone()).await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect().await?;
            let snapshot = observed.snapshot();
            assert_eq!(snapshot.queries.len(), 1, "{snapshot:?}");
            let query = &snapshot.queries[0];
            assert_eq!(serde_json::to_value(query).unwrap()["via"], "web_search");
            assert_eq!(query.search, words);
            assert_eq!(query.engine, Engine::Google);
            assert_eq!(query.outcome, Outcome::Served);
            assert!(query.results.unwrap() > 0);
            assert!(!snapshot.results[0].listed.is_empty());
            assert_eq!(snapshot.results[0].query_id, query.id);
            assert!(snapshot.results[0].listed.iter().any(|result| result.url == url));
            assert_eq!(query.carries, Some(0));
            assert_eq!(snapshot.pages[0].url, url);
            assert!(!snapshot.pages[0].making);
            assert_eq!(snapshot.pages[0].carries, Some(0));
            assert_eq!(serde_json::to_value(&snapshot.pages[0]).unwrap()["via"], "web_fetch");
            Ok(())
        },
    )).unwrap();
    server.join().unwrap();
}

#[test]
fn pages_being_made_finish_with_the_latest_tool_and_reach() {
    let s = searches();
    let making = || {
        Event::new("adaptive", "making")
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
        page("/a", "generated", "stub", json!({"via":"direct"}))
            .field("via", "web_fetch")
            .field("carries", 1u64),
    );
    let first = s.snapshot().pages[0].clone();
    assert!(!first.making);
    assert_eq!(first.via.as_deref(), Some("web_fetch"));
    assert_eq!(first.carries, Some(1));
    assert_eq!(first.status, Some(200));
    assert_eq!(first.fetches, 1);
    assert_eq!(first.made, Made::Stubbed);
    feed(
        &s,
        3,
        page("/a", "cached", "stub", json!(null)).field("carries", 0u64),
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
    assert_eq!(failed.made, Made::Stubbed);
    assert_eq!(failed.fetches, 3);
    feed(&s, 6, making());
    feed(
        &s,
        7,
        Event::new("adaptive", "page_failed")
            .field("url", "https://a.com/a")
            .field("status", 500u64),
    );
    assert!(!s.snapshot().pages[0].making);
    assert_eq!(s.snapshot().pages[0].status, Some(500));
    feed(&s, 8, query(1, "google", "halvard"));
    assert_eq!(s.snapshot().queries[0].carries, None);
    feed(&s, 9, answer(1, true).field("carries", 1u64));
    assert_eq!(s.snapshot().queries[0].carries, Some(1));
    for i in 0..MAX_PAGES {
        feed(
            &s,
            10 + i as u64,
            Event::new("adaptive", "making")
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
                        source: "adaptive",
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
    let pages = Arc::new(Pages::new(Seed::builtin("halvard-cve").unwrap()));
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
            let url = "http://news.example-wire.com/halvard-update";
            pages.clone().fetch(cx.clone(), url.into()).await?;
            let snapshot = searches.snapshot();
            assert_eq!(snapshot.pages.len(), 1);
            assert_eq!(snapshot.pages[0].url, url);
            assert!(!snapshot.pages[0].making);
            assert_eq!(snapshot.pages[0].status, Some(200));
            for i in 0..adaptive_web_world::pages::GENERATION_BUDGET {
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
        Event::new("adaptive", "making")
            .field("url", "https://a.com/new")
            .field("host", "a.com")
            .field("site", "A Company"),
    );
    assert_eq!(s.snapshot().pages[0].site, "A Company");
    feed(
        &s,
        4,
        page("/new", "generated", "stub", json!(null)).field("site", "A Company"),
    );
    feed(
        &s,
        5,
        Event::new("adaptive", "site")
            .field("host", "a.com")
            .field("site", "A Company"),
    );
    let snap = s.snapshot();
    assert_eq!(snap.results[0].listed[0].site, "Python Documentation");
    assert_eq!(snap.pages[0].site, "A Company");
    assert_eq!(snap.sites[0].site, "A Company");
}
