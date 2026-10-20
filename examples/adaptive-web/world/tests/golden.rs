//! The world end to end with the offline generator, and its log for a
//! fixed script of agent actions, compared line for line with
//! `tests/golden/halvard-cve.jsonl`.
//!
//! The world runs the offline generator on a fresh store, with a CA made
//! for the test. The script searches, follows results, asks for the same
//! URLs twice, and looks up names the world turns down. Besides the log, it
//! checks what the evals need: the same URL returns the same bytes, every
//! result link resolves and answers 200, and each page's title is the title
//! its search result showed.
//!
//! `ts`, `gen_ms`, `serve_ms` and the certificates' dates change from run to
//! run and are left out. The lines are compared as sorted sets.
//! `ADAPTIVE_WEB_GOLDEN_WRITE=1 cargo test --test golden` records the file
//! again.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use adaptive_web_world::pages::render::google_results;
use adaptive_web_world::pages::text::{escape, target_of};
use adaptive_web_world::pages::{Generator, Pages, Seed, store::Store};
use adaptive_web_world::{Addresses, Ca, serve, world_start};
use bytes::Bytes;
use example_common::log::Log;
use fictionet::Cx;
use fictionet::stdlib::protocols::dns::rr::{RData, RecordType};
use serde_json::Value;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

use fictionet::stdlib::world::sandbox::{Machine, machine};

/// Looks `name` up; returns its A record, or `None` for NXDOMAIN.
async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> Option<Ipv4Addr> {
    let answer = m
        .lookup(fcx, GATEWAY.into(), name, RecordType::A)
        .await
        .unwrap();
    answer.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

/// One HTTP/1.1 request; returns the status and the body.
async fn get<C: fictionet::stdlib::network::Connection>(
    fcx: &Cx,
    io: C,
    host: &str,
    path: &str,
) -> (u16, Bytes) {
    let (status, _, body) = request(fcx, io, host, path).await;
    (status, body)
}

async fn request<C: fictionet::stdlib::network::Connection>(
    fcx: &Cx,
    mut io: C,
    host: &str,
    path: &str,
) -> (u16, String, Bytes) {
    use fictionet::stdlib::{codec::Wire, protocols::http1, world::sandbox};
    let request = http1::Request::parse(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let response = sandbox::request(fcx, &mut io, &request).await.unwrap();
    let date = response
        .head
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("date"))
        .map(|h| String::from_utf8_lossy(&h.value).into_owned())
        .unwrap_or_default();
    (response.head.status, date, Bytes::from(response.body))
}

/// Looks `host` up and fetches `path` from it over HTTPS.
async fn fetch(fcx: &Cx, m: &Machine, host: &str, path: &str) -> (u16, Bytes) {
    let addr = lookup(fcx, m, host)
        .await
        .unwrap_or_else(|| panic!("{host} did not resolve"));
    let stream = m
        .tls(
            fcx,
            SocketAddr::new(addr.into(), 443),
            host,
            None,
            std::time::SystemTime::now(),
        )
        .await
        .unwrap();
    get(fcx, stream, host, path).await
}

#[test]
fn the_log_is_the_recorded_one() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("adaptive-web-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    // A day other than today, to check that the world's clock follows the seed.
    let mut seed = Seed::builtin("halvard-cve").unwrap();
    seed.date = "2026-09-30".into();
    let fixed_pages: Vec<String> = seed.fixed.iter().map(|f| f.url.clone()).collect();
    let root = base.join("store").join(&seed.name);
    let (store, _) = Store::open(&root, &seed, Some(&Generator::Stub.identity())).unwrap();
    let addresses = Arc::new(Addresses::new(seed.fixed_addresses(), Some(&root)).unwrap());
    let start = world_start(&seed.date).unwrap();
    let ca_dir = base.join("ca");
    let pages = Arc::new(Pages::open(seed, store, Some(Generator::Stub), 0));
    let searches = Arc::new(adaptive_web_world::search::Searches::of(&pages));
    let log_path = base.join("log.jsonl");
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(&log_path).unwrap()),
        &[],
        |s| s,
    ));

    let initial = searches.snapshot();
    assert_eq!(initial.revision, 0);
    assert_eq!(initial.seed.name, "halvard-cve");
    assert_eq!(initial.seed.date, "2026-09-30");
    assert!(!initial.seed.facts.is_empty());
    assert!(
        initial
            .seed
            .sites
            .iter()
            .any(|h| h == "www.halvardsystems.com")
    );
    assert_eq!(
        initial.generator.kind,
        adaptive_web_world::search::GeneratorKind::Stub
    );
    assert_eq!(initial.generator.model, "stub");
    assert_eq!(initial.generator.prefetch, 0);
    let projection = searches.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let drain = log.clone();
        let result = fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::random()).observer(Arc::new(
                fictionet_observe::Aggregate::new(Arc::new(fictionet::events::Fanout::new(vec![
                    Arc::new(adaptive_web_world::events::LogObserver { log: log.clone() }),
                    searches.clone(),
                ]))),
            )),
            move |fcx| async move {
                let ca = Arc::new(Ca::new(&fcx, &ca_dir, start).unwrap());
                let (attacher, attachments) = fictionet::attachments();
                serve(&fcx, addresses, ca, pages, log, start, attachments)?;

                let end = attacher.attach("agent").unwrap();
                let m = machine(&fcx, end, ME);

                // Names the world turns down.
                assert_eq!(lookup(&fcx, &m, "rw-desktop").await, None);
                assert_eq!(lookup(&fcx, &m, "printer.local").await, None);
                assert_eq!(
                    lookup(&fcx, &m, "www.google.com").await,
                    Some(Ipv4Addr::new(142, 250, 180, 4))
                );

                // A search, then its results.
                let (status, page) = fetch(
                    &fcx,
                    &m,
                    "www.google.com",
                    "/search?q=halvard+gateway+vulnerability",
                )
                .await;
                assert_eq!(status, 200);
                let found = google_results(std::str::from_utf8(&page).unwrap());
                assert_eq!(found.len(), 10, "ten results");
                // Responses are dated on the seed's day.
                let addr = lookup(&fcx, &m, "www.google.com").await.unwrap();
                let conn = m
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr.into(), 80))
                    .await
                    .unwrap();
                let (_, date, _) = request(&fcx, conn, "www.google.com", "/").await;
                assert!(date.contains("30 Sep 2026"), "Date: {date}");
                for (rank, (url, title)) in found.iter().enumerate() {
                    let (host, path) = target_of(url);
                    let (status, first) = fetch(&fcx, &m, &host, &path).await;
                    assert_eq!(status, 200, "{url}");
                    let snapshot = projection.snapshot();
                    let row = snapshot.pages.iter().find(|p| p.url == *url).unwrap();
                    assert_eq!(
                        row.made,
                        if fixed_pages.contains(url) {
                            adaptive_web_world::search::Made::Fixed
                        } else {
                            adaptive_web_world::search::Made::Stubbed
                        }
                    );
                    assert_eq!(
                        row.reason,
                        if fixed_pages.contains(url) {
                            adaptive_web_world::search::Reason::Fixed
                        } else {
                            adaptive_web_world::search::Reason::Search {
                                query: "halvard gateway vulnerability".into(),
                                rank: rank as u64 + 1,
                            }
                        }
                    );
                    assert_eq!(row.latest, row.made);
                    let first_made = row.made;
                    let (_, again) = fetch(&fcx, &m, &host, &path).await;
                    let snapshot = projection.snapshot();
                    let row = snapshot.pages.iter().find(|p| p.url == *url).unwrap();
                    assert_eq!(row.made, first_made);
                    assert_eq!(
                        row.latest,
                        if fixed_pages.contains(url) {
                            adaptive_web_world::search::Made::Fixed
                        } else {
                            adaptive_web_world::search::Made::Stored
                        }
                    );
                    assert_eq!(
                        row.cache,
                        if fixed_pages.contains(url) {
                            adaptive_web_world::search::Cache::Fixed
                        } else {
                            adaptive_web_world::search::Cache::Generated
                        }
                    );
                    assert_eq!(row.fetches, 2);
                    assert_eq!(first, again, "{url} changed between two requests");
                    let text = String::from_utf8_lossy(&first);
                    assert!(
                        text.contains(&format!("<title>{}</title>", escape(title))),
                        "{url} is not titled {title:?}"
                    );
                }
                // The same query on DuckDuckGo: the result list is shared.
                let (status, ddg) = fetch(
                    &fcx,
                    &m,
                    "html.duckduckgo.com",
                    "/html/?q=Halvard+Gateway+vulnerability",
                )
                .await;
                assert_eq!(status, 200);
                assert!(String::from_utf8_lossy(&ddg).contains(&escape(&found[1].1)));
                // A name nothing pointed at.
                let (status, _) = fetch(&fcx, &m, "totally-new-site.io", "/pricing").await;
                assert_eq!(status, 200);
                // Plain HTTP: a redirect.
                let addr = lookup(&fcx, &m, "totally-new-site.io").await.unwrap();
                let conn = m
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr.into(), 80))
                    .await
                    .unwrap();
                assert_eq!(get(&fcx, conn, "totally-new-site.io", "/").await.0, 301);
                let _ = fcx.sleep(Duration::from_millis(500)).await;
                let snapshot = projection.snapshot();
                assert_eq!(snapshot.queries.len(), 2);
                assert!(
                    snapshot
                        .queries
                        .iter()
                        .all(|q| q.outcome == adaptive_web_world::search::Outcome::Served)
                );
                assert_eq!(snapshot.queries[0].key, snapshot.queries[1].key);
                assert_eq!(snapshot.queries[0].sandbox.as_deref(), Some("agent"));
                assert_eq!(snapshot.queries[0].peer.as_deref(), Some("10.0.0.2"));
                assert_eq!(snapshot.results.len(), 1);
                assert_eq!(snapshot.results[0].listed.len(), 10);
                assert_eq!(snapshot.results[0].query_id, snapshot.queries[0].id);
                for (rank, listed) in snapshot.results[0].listed.iter().enumerate() {
                    assert_eq!(listed.rank, rank as u64 + 1);
                    assert_eq!(listed.url, found[rank].0);
                    assert_eq!(listed.title, found[rank].1);
                }
                assert_eq!(
                    snapshot
                        .pages
                        .iter()
                        .find(|p| p.host == "totally-new-site.io")
                        .unwrap()
                        .reason,
                    adaptive_web_world::search::Reason::Direct
                );
                assert!(snapshot.refused.iter().any(|r| r.name == "printer.local"));
                assert!(snapshot.refused.iter().any(|r| r.name == "rw-desktop"));
                for site in &snapshot.sites {
                    let expected = if [
                        "www.google.com",
                        "google.com",
                        "html.duckduckgo.com",
                        "duckduckgo.com",
                        "lite.duckduckgo.com",
                        "www.bing.com",
                        "bing.com",
                    ]
                    .contains(&site.host.as_str())
                    {
                        adaptive_web_world::search::SiteReason::SearchEngine
                    } else if site.host == "www.halvardsystems.com" {
                        adaptive_web_world::search::SiteReason::Seed
                    } else {
                        adaptive_web_world::search::SiteReason::Pool
                    };
                    assert_eq!(site.reason, expected, "{}", site.host);
                }
                Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
            },
        ));
        drain.finish().unwrap();
        let _ = tx.send(result.err().map(|e| e.to_string()));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(90))
        .expect("the test timed out");
    assert_eq!(result.as_deref(), Some("done"));

    let text = std::fs::read_to_string(&log_path).unwrap();
    // Certificates were issued 30 days before the seed's day (2026-09-30),
    // which is before the host's day, and cover today on the host's clock.
    for line in text.lines().filter(|l| l.contains(r#""type":"cert""#)) {
        assert!(line.contains(r#""not_before":"2026-08-31""#), "{line}");
    }
    let mut got: Vec<String> = text
        .lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).unwrap();
            let fields = v.as_object_mut().unwrap();
            for name in ["ts", "gen_ms", "serve_ms", "not_before", "not_after"] {
                fields.shift_remove(name);
            }
            v.to_string()
        })
        .collect();
    got.sort();
    let _ = std::fs::remove_dir_all(&base);
    let file = here.join("tests/golden/halvard-cve.jsonl");
    if std::env::var_os("ADAPTIVE_WEB_GOLDEN_WRITE").is_some() {
        std::fs::write(&file, got.join("\n") + "\n").unwrap();
        return;
    }
    let want = std::fs::read_to_string(&file).unwrap();
    let want: Vec<&str> = want.lines().collect();
    let got: Vec<&str> = got.iter().map(String::as_str).collect();
    for line in &want {
        assert!(
            got.contains(line),
            "missing from the log now: {line}\n\nthe log now:\n{}",
            got.join("\n")
        );
    }
    for line in &got {
        assert!(
            want.contains(line),
            "new in the log: {line}\n\nrecorded:\n{}",
            want.join("\n")
        );
    }
    assert_eq!(got, want);
}
