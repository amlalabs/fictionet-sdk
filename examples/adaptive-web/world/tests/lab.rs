//! The entire Rust stub world runs without Python, sockets or files.
use adaptive_web_world::{
    Addresses, Ca, Pages,
    search::Searches,
    serve,
    stub::{Seed, Stub, text::target_of},
};
use fictionet::{
    Cx,
    events::Fanout,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
        world::sandbox::{self, Machine, machine},
    },
};
use fictionet_observe::Memory;
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

async fn fetch(cx: &Cx, m: &Machine, host: &str, path: &str, start: SystemTime) -> (u16, Vec<u8>) {
    let answer = m
        .lookup(cx, "10.0.0.1".parse().unwrap(), host, RecordType::A)
        .await
        .unwrap();
    let addr = answer
        .answers
        .iter()
        .find_map(|r| {
            if let RData::A(a) = &r.data {
                Some(a.0)
            } else {
                None
            }
        })
        .unwrap();
    let mut conn = m
        .tls(cx, SocketAddr::new(addr.into(), 443), host, None, start)
        .await
        .unwrap();
    let request =
        http1::Request::parse(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
    let response = sandbox::request(cx, &mut conn, &request).await.unwrap();
    assert!(
        !response
            .head
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-adaptive-meta"))
    );
    (response.head.status, response.body)
}
fn run(exhaust: bool) -> (Vec<Value>, adaptive_web_world::search::Snapshot) {
    let events = Arc::new(Memory::default());
    let seed = Seed::builtin("halvard-cve").unwrap();
    let searches = Arc::new(Searches::from_seed(&seed));
    let log = Arc::new(example_common::log::Log::new(
        Box::new(std::io::sink()),
        &[],
        |s| s,
    ));
    let output = log.clone();
    let observer = Arc::new(Fanout::new(vec![
        events.clone(),
        searches.clone(),
        Arc::new(adaptive_web_world::events::LogObserver { log: log.clone() }),
    ]));
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            let start = SystemTime::from(
                time::Date::from_calendar_date(2026, time::Month::October, 7)
                    .unwrap()
                    .midnight()
                    .assume_utc(),
            );
            let addresses = Arc::new(Addresses::new(seed.fixed_addresses(), None)?);
            let ca = Arc::new(Ca::in_memory(&cx, start)?);
            let stub = Arc::new(Stub::new(seed));
            if exhaust {
                for n in 0..199 {
                    assert_eq!(
                        stub.handle(&cx, "GET", "budget.io", &format!("/{n}.txt"), None)
                            .status,
                        200
                    );
                }
                assert_eq!(
                    stub.handle(&cx, "GET", "budget.io", "/last.txt", None)
                        .status,
                    503
                );
            }
            let (attacher, attachments) = fictionet::attachments();
            serve(
                &cx,
                addresses,
                ca,
                Pages::Stub(stub),
                log,
                start,
                attachments,
            )?;
            let m = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            let (status, body) = fetch(
                &cx,
                &m,
                "www.google.com",
                "/search?q=halvard+gateway+vulnerability",
                start,
            )
            .await;
            if exhaust {
                assert_eq!(status, 503);
                assert_eq!(body, b"Generation budget exhausted");
            } else {
                assert_eq!(status, 200);
                let html = std::str::from_utf8(&body).unwrap();
                let urls: Vec<_> = html
                    .split(r#"<div class="yuRUbf"><a href=""#)
                    .skip(1)
                    .map(|p| adaptive_web_world::stub::text::unescape(p.split('"').next().unwrap()))
                    .collect();
                assert_eq!(urls.len(), 10);
                for url in urls {
                    let (host, target) = target_of(&url);
                    let (status, first) = fetch(&cx, &m, &host, &target, start).await;
                    assert_eq!(status, 200);
                    let (status, second) = fetch(&cx, &m, &host, &target, start).await;
                    assert_eq!(status, 200);
                    assert_eq!(first, second);
                }
            }
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    output.finish().unwrap();
    let snapshot = searches.snapshot();
    let selected = events
        .checked_all()
        .unwrap()
        .into_iter()
        .filter(|e| ["http", "adaptive"].contains(&e.source))
        .map(|e| {
            let fields: serde_json::Map<_, _> = e
                .fields
                .iter()
                .map(|(k, v)| (k.to_owned(), adaptive_web_world::events::to_json(v)))
                .collect();
            json!({"source":e.source,"kind":e.kind,"fields":fields})
        })
        .collect();
    (selected, snapshot)
}
#[test]
fn seeded_lab_runs_match() {
    let first = run(false);
    assert_eq!(first, run(false));
    assert_eq!(first.1.queries.len(), 1);
    assert_eq!(
        first.1.queries[0].outcome,
        adaptive_web_world::search::Outcome::Served
    );
    assert_eq!(first.1.queries[0].gen_ms, Some(0));
    assert_eq!(first.1.results[0].listed.len(), 10);
    assert_eq!(first.1.pages.len(), 10);
    assert!(first.1.pages.iter().all(|p| p.fetches == 2));
}
#[test]
fn exhausted_search_emits_query_failed() {
    let (events, snapshot) = run(true);
    assert_eq!(snapshot.queries.len(), 1);
    assert_eq!(
        snapshot.queries[0].outcome,
        adaptive_web_world::search::Outcome::Failed {
            why: adaptive_web_world::search::Failure::Budget,
            error: None
        }
    );
    let failed: Vec<_> = events
        .iter()
        .filter(|e| e["source"] == "adaptive" && e["kind"] == "query_failed")
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["fields"]["why"], "budget");
    assert_eq!(failed[0]["fields"]["query_id"], 1);
    let answer = events
        .iter()
        .find(|e| e["source"] == "http" && e["kind"] == "request")
        .unwrap();
    assert_eq!(answer["fields"]["query_id"], 1);
    assert_eq!(answer["fields"]["cache"], "budget");
}
