//! The whole world, with its offline generator, runs in a lab: no sockets
//! or files.
use adaptive_web_world::{
    World,
    pages::{Seed, text::target_of},
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
use fictionet_extras::search::links;
use fictionet_observe::Memory;
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};

async fn fetch(
    cx: &Cx,
    m: &Machine,
    host: &str,
    path: &str,
    start: SystemTime,
    user_agent: &str,
) -> (u16, Vec<u8>) {
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
    let request = http1::Request::parse(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\r\n")
            .as_bytes(),
    )
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
                "Mozilla/5.0 Firefox/145.0",
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
                let results = links(std::str::from_utf8(&body).unwrap());
                assert_eq!(results.len(), 10);
                for (url, _) in results {
                    let (host, target) = target_of(&url);
                    let (status, first) =
                        fetch(&cx, &m, &host, &target, start, "Mozilla/5.0 Firefox/145.0").await;
                    assert_eq!(status, 200);
                    let (status, second) =
                        fetch(&cx, &m, &host, &target, start, "Mozilla/5.0 Firefox/145.0").await;
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
            let (status, body) = fetch(
                &cx,
                &m,
                "forwarded.com",
                "/",
                start,
                "Mozilla/5.0 Firefox/145.0",
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(body, b"caller content");
            let answer = m
                .lookup(&cx, "10.0.0.1".parse()?, "forwarded.com", RecordType::A)
                .await?;
            let (assigned, why) = world.addresses.assign("forwarded.com")?.unwrap();
            assert_eq!(why, "pool");
            assert!(matches!(
                assigned.octets(),
                [104, 21, _, _] | [172, 67, _, _]
            ));
            assert_eq!(answer.answers.len(), 1);
            assert!(matches!(&answer.answers[0].data, RData::A(a) if a.0 == assigned));
            let sites = events.checked_of("adaptive", "site").unwrap();
            let forwarded: Vec<_> = sites
                .iter()
                .filter(|e| e.str("host") == Some("forwarded.com"))
                .collect();
            assert_eq!(forwarded.len(), 1);
            assert_eq!(
                forwarded[0].str("addr"),
                Some(assigned.to_string().as_str())
            );
            assert_eq!(forwarded[0].str("why"), Some("pool"));
            assert_eq!(
                fetch(
                    &cx,
                    &m,
                    "freshnews.com",
                    "/news",
                    start,
                    "Mozilla/5.0 Firefox/145.0"
                )
                .await
                .0,
                200
            );
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
    assert_eq!(
        sites
            .iter()
            .filter(|e| e.str("host") == Some("forwarded.com"))
            .count(),
        1
    );
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

#[test]
fn guest_fetches_attribute_claude_and_keep_browser_requests_unmarked() {
    let events = Arc::new(Memory::default());
    let seed = Seed::builtin("halvard-cve").unwrap();
    let searches = Arc::new(Searches::from_seed(&seed));
    let observed = events.clone();
    let projection = searches.clone();
    let observer = Arc::new(Fanout::new(vec![events, searches]));
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            let log = Arc::new(example_common::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world.serve(&cx, log, attachments)?;
            let m = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            for (user_agent, via) in [
                (
                    "Claude-User (claude-code/2.1.292; +https://support.anthropic.com/)",
                    Some("web_fetch"),
                ),
                (
                    "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
                    None,
                ),
            ] {
                let (status, _) = fetch(
                    &cx,
                    &m,
                    "www.halvardsystems.com",
                    "/security/advisories/HSA-2026-014",
                    start,
                    user_agent,
                )
                .await;
                assert_eq!(status, 200);
                let requests = observed.checked_of("http", "request").unwrap();
                let request = requests.last().unwrap();
                assert_eq!(request.str("via"), via);
                let snapshot = projection.snapshot();
                assert_eq!(snapshot.pages.len(), 1);
                assert_eq!(snapshot.pages[0].via.as_deref(), via);
                assert_eq!(snapshot.pages[0].status, Some(200));
            }
            assert_eq!(projection.snapshot().pages[0].fetches, 2);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn result_icons_only_contact_the_search_engine() {
    use kuchiki::traits::TendrilSink;

    let events = Arc::new(Memory::default());
    for host in ["www.google.com", "www.bing.com"] {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let searches = Arc::new(Searches::from_seed(&seed));
        let observed = searches.clone();
        let observer = Arc::new(Fanout::new(vec![events.clone(), searches]));
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
                let log = Arc::new(example_common::log::Log::new(
                    Box::new(std::io::sink()),
                    &[],
                    |s| s,
                ));
                let (attacher, attachments) = fictionet::attachments();
                world.serve(&cx, log, attachments)?;
                let machine = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
                let (status, body) = fetch(
                    &cx,
                    &machine,
                    host,
                    "/search?q=halvard+gateway+vulnerability",
                    start,
                    "Mozilla/5.0 Firefox/145.0",
                )
                .await;
                assert_eq!(status, 200);
                let icons = {
                    let dom = kuchiki::parse_html().one(std::str::from_utf8(&body).unwrap());
                    dom.select("img.result-icon")
                        .unwrap()
                        .map(|node| node.attributes.borrow().get("src").unwrap().to_owned())
                        .collect::<Vec<_>>()
                };
                let snapshot = observed.snapshot();
                let listed = &snapshot.results[0].listed;
                assert_eq!(icons.len(), listed.len());
                assert_eq!(icons.len(), 10);
                for (icon, result) in icons.iter().zip(listed) {
                    let (icon_host, target) = target_of(icon);
                    assert_eq!(icon_host, host);
                    let (status, body) = fetch(
                        &cx,
                        &machine,
                        &icon_host,
                        &target,
                        start,
                        "Mozilla/5.0 Firefox/145.0",
                    )
                    .await;
                    assert_eq!(status, 200);
                    assert_eq!(
                        body,
                        adaptive_web_world::pages::render::favicon(&result.host).as_bytes()
                    );
                }
                assert!(observed.snapshot().pages.is_empty());
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
    let requests = events
        .checked_all()
        .unwrap()
        .into_iter()
        .filter(|event| event.source == "http" && event.kind == "request")
        .map(|event| example_common::events::js(event.fields.get("host")))
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 22);
    assert!(
        requests
            .iter()
            .all(|host| host == "www.google.com" || host == "www.bing.com")
    );
}
