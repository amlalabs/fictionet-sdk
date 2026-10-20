//! The whole world, with its offline generator, runs in a lab: no sockets
//! or files.
use adaptive_web_world::{
    World,
    pages::{Seed, render::google_results, text::target_of},
    search::Searches,
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
            let world = World::new(&cx, seed, start)?;
            let pages = &world.pages;
            if exhaust {
                // The cast and 199 pages spend the 200 generations.
                for n in 0..199 {
                    let target = format!("/{n}.txt");
                    let page = pages.handle(&cx, "GET", "budget.io", &target, None);
                    assert_eq!(page.await.status, 200);
                }
                let last = pages.handle(&cx, "GET", "budget.io", "/last.txt", None);
                assert_eq!(last.await.status, 503);
            }
            let (attacher, attachments) = fictionet::attachments();
            world.serve(&cx, log, attachments)?;
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
                // A busy server's plain page; the log says why.
                assert_eq!(status, 503);
                let body = String::from_utf8(body.to_vec()).unwrap();
                assert!(body.contains("<h1>503 Service Temporarily Unavailable</h1>"));
                assert!(!body.to_lowercase().contains("generat"));
            } else {
                assert_eq!(status, 200);
                let results = google_results(std::str::from_utf8(&body).unwrap());
                assert_eq!(results.len(), 10);
                for (url, _) in results {
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
                .map(|(k, v)| (k.to_owned(), example_common::events::js(Some(v))))
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

#[test]
fn caller_sites_precede_generated_sites_and_reserved_names_are_refused() {
    let events = Arc::new(Memory::default());
    let observed = events.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(events.clone()),
        move |cx| async move {
            let seed = Seed::builtin("halvard-cve")?;
            let start = adaptive_web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            let tls = world.ca.config(&cx, "forwarded.com")?.0;
            let log = Arc::new(example_common::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world
                .net(&cx, log, move |name| {
                    (name == "forwarded.com").then(|| {
                        fictionet::stdlib::web::Site::handler(
                            fictionet::stdlib::web::httpd::Router::new().get("/", |_, _| {
                                http::Response::new(bytes::Bytes::from_static(b"caller content"))
                            }),
                        )
                        .tls(tls.clone())
                    })
                })
                .start(&cx, attachments)?;
            let m = machine(
                &cx,
                attacher.attach("workstation")?,
                Ipv4Addr::new(10, 0, 0, 2),
            );
            let (status, body) = fetch(&cx, &m, "forwarded.com", "/", start).await;
            assert_eq!(status, 200);
            assert_eq!(body, b"caller content");
            assert_eq!(fetch(&cx, &m, "freshnews.com", "/news", start).await.0, 200);
            let refused = m
                .lookup(&cx, "10.0.0.1".parse()?, "wiki.corp", RecordType::A)
                .await?;
            assert!(refused.answers.is_empty());
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    let sites = observed.checked_of("adaptive", "site").unwrap();
    assert!(sites.iter().any(|e| e.str("host") == Some("freshnews.com")));
    assert!(!sites.iter().any(|e| e.str("host") == Some("forwarded.com")));
    assert!(
        !observed
            .checked_of("adaptive", "cert")
            .unwrap()
            .iter()
            .any(|e| e.str("host") == Some("forwarded.com"))
    );
    assert!(
        observed
            .checked_of("adaptive", "refused")
            .unwrap()
            .iter()
            .any(|e| e.str("host") == Some("wiki.corp"))
    );
}
