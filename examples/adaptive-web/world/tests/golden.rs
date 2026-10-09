//! The world end to end with the offline generator, and its log for a
//! fixed script of agent actions, compared line for line with
//! `tests/golden/halvard-cve.jsonl`.
//!
//! The world runs here with its real Python backend (`backend/backend.py`,
//! which needs only `python3`), the stub generator, a fresh store and a CA
//! made for the test. The script searches, follows results, asks for the
//! same URLs twice, and looks up names the world turns down. Besides the
//! log, it checks what Kai's evals need: the same URL returns the same
//! bytes, every result link resolves and answers 200, and each page's
//! title is the title its search result showed.
//!
//! `ts`, `gen_ms`, `serve_ms` and the certificates' dates change from run to
//! run and are left out. The lines are compared as sorted sets.
//! `ADAPTIVE_WEB_GOLDEN_WRITE=1 cargo test --test golden` records the file
//! again.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use adaptive_web_world::backend::Backend;
use adaptive_web_world::log::Log;
use adaptive_web_world::{Addresses, Args, Ca, fixed_addresses, serve, start_backend, world_start};
use bytes::Bytes;
use fictionet::Cx;
use fictionet::stdlib::dns::rr::{RData, RecordType};
use serde_json::Value;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

use fictionet::stdlib::sandbox::{Machine, machine};

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
async fn get<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    io: C,
    host: &str,
    path: &str,
) -> (u16, Bytes) {
    let (status, _, body) = request(fcx, io, host, path).await;
    (status, body)
}

async fn request<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    mut io: C,
    host: &str,
    path: &str,
) -> (u16, String, Bytes) {
    use fictionet::stdlib::{codec::Wire, http1, sandbox};
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

/// The result links and titles of a Google results page.
fn results(page: &str) -> Vec<(String, String)> {
    page.split(r#"<div class="yuRUbf"><a href=""#)
        .skip(1)
        .map(|chunk| {
            let url = chunk.split('"').next().unwrap().replace("&amp;", "&");
            let title = chunk
                .split("<h3>")
                .nth(1)
                .unwrap()
                .split("</h3>")
                .next()
                .unwrap()
                .to_owned();
            (url, title)
        })
        .collect()
}

fn split_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("https://").unwrap();
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    (
        host.to_owned(),
        if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
    )
}

/// The example's seeds, copied to `base` with the world's date set to
/// `date`, a day other than today, to check that the world's clock follows
/// the seed.
fn seeds_dated(base: &std::path::Path, date: &str) -> PathBuf {
    let from = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../seeds");
    let to = base.join("seeds");
    std::fs::create_dir_all(to.join("fixed")).unwrap();
    for entry in std::fs::read_dir(from.join("fixed")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join("fixed").join(entry.file_name())).unwrap();
    }
    let seed = std::fs::read_to_string(from.join("halvard-cve.md")).unwrap();
    let seed = seed.replace("date = \"2026-10-07\"", &format!("date = \"{date}\""));
    assert!(seed.contains(date), "the seed's date line changed");
    std::fs::write(to.join("halvard-cve.md"), seed).unwrap();
    to
}

#[test]
fn the_log_is_the_recorded_one() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("adaptive-web-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // SAFETY: set before any thread of this test process reads the environment.
    unsafe {
        std::env::set_var("ADAPTIVE_WEB_SEED", "halvard-cve");
        std::env::set_var("ADAPTIVE_WEB_SEEDS", seeds_dated(&base, "2026-09-30"));
        std::env::set_var("ADAPTIVE_WEB_GENERATOR", "stub");
        std::env::set_var("ADAPTIVE_WEB_STORE", base.join("store"));
    }
    let args = Args {
        socket: String::new(),
        ca_dir: base.join("ca"),
        backend: here.join("backend"),
        backend_port: port,
        state_dir: base.clone(),
        ready: base.join("ready"),
    };
    let (backend, mut child) = start_backend(&args).unwrap();
    let store = PathBuf::from(backend["store"].as_str().unwrap());
    let fixed = fixed_addresses(&backend).unwrap();

    let addresses = Arc::new(Addresses::new(fixed, Some(&store.join("addresses.jsonl"))).unwrap());
    let start = world_start(backend["date"].as_str().unwrap()).unwrap();
    let log_path = base.join("log.jsonl");
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(&log_path).unwrap()),
        &[],
        |s| s,
    ));

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(fictionet::run(
            fictionet::Seed::random(),
            move |fcx| async move {
                let ca = Arc::new(Ca::new(&fcx, &args.ca_dir, start).unwrap());
                let (attacher, attachments) = fictionet::attachments();
                serve(
                    &fcx,
                    addresses,
                    ca,
                    Backend::new(port),
                    log,
                    start,
                    attachments,
                )?;

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
                let found = results(std::str::from_utf8(&page).unwrap());
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
                for (url, title) in found.iter().take(4) {
                    let (host, path) = split_url(url);
                    let (status, first) = fetch(&fcx, &m, &host, &path).await;
                    assert_eq!(status, 200, "{url}");
                    let (_, again) = fetch(&fcx, &m, &host, &path).await;
                    assert_eq!(first, again, "{url} changed between two requests");
                    let text = String::from_utf8_lossy(&first);
                    assert!(
                        text.contains(&format!("<title>{title}</title>")),
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
                assert!(String::from_utf8_lossy(&ddg).contains(&found[1].1));
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
                Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
            },
        ));
        let _ = tx.send(result.err().map(|e| e.to_string()));
    });
    let result = rx.recv_timeout(Duration::from_secs(90));
    let _ = child.kill();
    let _ = child.wait();
    let result = result.expect("the test timed out");
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
