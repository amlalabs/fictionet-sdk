//! The request log for a fixed script of agent actions, compared line for
//! line with a recorded log (`tests/golden/`).
//!
//! FakeWiki's eval reads `log.jsonl` after the run, so the same lines mean
//! the same report. The world runs the script in a lab with its embedded
//! pages and a CA made for the test. `ts` is dropped and the lines are
//! compared as sorted sets.
//!

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use example_common::log::Log;
use fakewiki_world::content::Content;
use fakewiki_world::pages::{self, Variant};
use fakewiki_world::tamper::Tampering;
use fakewiki_world::{issue_leaves, serve};
use fictionet::Cx;
use fictionet::stdlib::protocols::dns::rr::RecordType;
use serde_json::Value;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

use fictionet::stdlib::world::sandbox::{Machine, machine};

async fn lookup(fcx: &Cx, m: &Machine, name: &str, kind: RecordType) {
    m.lookup(fcx, GATEWAY.into(), name, kind).await.unwrap();
}

/// One HTTP/1.1 request; returns the status.
async fn get<C: fictionet::stdlib::network::Connection>(
    fcx: &Cx,
    mut io: C,
    method: &str,
    host: &str,
    path: &str,
) -> u16 {
    use fictionet::stdlib::{codec::Wire, protocols::http1, world::sandbox};
    let request = http1::Request::parse(
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let response = sandbox::request(fcx, &mut io, &request).await.unwrap();
    if matches!(response.head.status, 200 | 404) {
        let header = |name: &str| {
            response
                .head
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .unwrap()
                .value
                .as_slice()
        };
        assert_eq!(header("server"), b"nginx");
        assert_eq!(header("content-type"), b"text/html; charset=utf-8");
        assert_eq!(header("cache-control"), b"private, max-age=0");
        assert_eq!(header("date").len(), 29);
        assert!(header("date").ends_with(b" GMT"));
        let length = std::str::from_utf8(header("content-length"))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        if method == "HEAD" {
            assert!(response.body.is_empty());
            assert!(length > 0);
        } else {
            assert_eq!(length, response.body.len());
        }
    }
    if (300..400).contains(&response.head.status) {
        assert!(
            response
                .head
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("location"))
        );
    }
    response.head.status
}

async fn tls(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    sni: &str,
) -> std::io::Result<
    fictionet::stdlib::world::sandbox::TlsClient<fictionet::stdlib::network::tcp::TcpConnection>,
> {
    m.tls(
        fcx,
        SocketAddr::new(addr.into(), 443),
        sni,
        None,
        std::time::SystemTime::now(),
    )
    .await
    .map_err(std::io::Error::other)
}

#[test]
fn the_log_is_the_recorded_one() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let state_dir = std::env::temp_dir().join(format!("fakewiki-golden-{}", std::process::id()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let documents = pages::documents(Variant::AlteredOne)
        .into_iter()
        .map(|d| d.url)
        .collect();
    run_script(&here, &state_dir, pages::host_ips(), documents);
}

async fn script(
    fcx: Cx,
    hosts: HashMap<String, Ipv4Addr>,
    documents: Vec<String>,
    content: Content,
    log: Arc<Log>,
) -> fictionet::Result {
    let (_, leaves) = issue_leaves(&fcx, hosts.keys()).unwrap();
    log.attach(&fcx);
    let (attacher, attachments) = fictionet::attachments();
    serve(&fcx, &hosts, leaves, content, attachments)?;

    let end = attacher.attach("agent").unwrap();
    let m = machine(&fcx, end, ME);
    let wiki = hosts["en.wikipedia.org"];
    lookup(&fcx, &m, "en.wikipedia.org", RecordType::A).await;
    lookup(&fcx, &m, "en.wikipedia.org", RecordType::AAAA).await;
    lookup(&fcx, &m, "example.com", RecordType::A).await;
    lookup(&fcx, &m, "rw-desktop", RecordType::A).await;
    // The first three documents, over HTTPS, and one HEAD.
    for url in documents.iter().take(3) {
        let uri: http::Uri = url.parse().unwrap();
        let host = uri.host().unwrap().to_owned();
        let stream = tls(&fcx, &m, hosts[&host], &host).await.unwrap();
        assert_eq!(
            get(&fcx, stream, "GET", &host, uri.path()).await,
            200,
            "{url}"
        );
    }
    let stream = tls(&fcx, &m, wiki, "en.wikipedia.org").await.unwrap();
    get(&fcx, stream, "HEAD", "en.wikipedia.org", "/wiki/Main_Page").await;
    // A page redirect keeps its Location for the client and the log.
    let stream = tls(&fcx, &m, wiki, "en.wikipedia.org").await.unwrap();
    assert_eq!(
        get(&fcx, stream, "GET", "en.wikipedia.org", "/wiki").await,
        301
    );
    let stream = tls(&fcx, &m, wiki, "en.wikipedia.org").await.unwrap();
    get(&fcx, stream, "GET", "en.wikipedia.org", "/no/such/page?q=1").await;
    // A host at another address, over this connection.
    let stream = tls(&fcx, &m, wiki, "en.wikipedia.org").await.unwrap();
    assert_eq!(get(&fcx, stream, "GET", "www.gov.uk", "/").await, 421);
    // Plain HTTP: a redirect.
    let conn = m
        .tcp
        .connect(&fcx, SocketAddr::new(IpAddr::V4(wiki), 80))
        .await
        .unwrap();
    assert_eq!(
        get(&fcx, conn, "GET", "en.wikipedia.org", "/wiki/X").await,
        301
    );
    // A name the world does not serve.
    assert!(tls(&fcx, &m, wiki, "example.com").await.is_err());
    let _ = fcx.sleep(Duration::from_millis(500)).await;
    Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
}

fn run_script(
    here: &Path,
    state_dir: &Path,
    hosts: HashMap<String, Ipv4Addr>,
    documents: Vec<String>,
) {
    let log_path = state_dir.join("log.jsonl");
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(&log_path).unwrap()),
        &[],
        |s| s,
    ));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let drain = log.clone();
        let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(Arc::new(
            fictionet_observe::Aggregate::new(Arc::new(fakewiki_world::events::LogObserver {
                log: log.clone(),
                hosts: hosts.clone(),
            })),
        ));
        let world = move |fcx: Cx| async move {
            let content = Content::new(Tampering::from(Variant::AlteredOne));
            script(fcx, hosts, documents, content, log).await
        };
        let result = fictionet::block_on(fictionet::lab(options, world));
        drain.finish().unwrap();
        let _ = tx.send(result.err().map(|e| e.to_string()));
    });
    let result = rx
        .recv_timeout(Duration::from_secs(90))
        .expect("the test timed out");
    assert_eq!(result.as_deref(), Some("done"));
    check_log(here, &log_path);
}

fn check_log(here: &Path, log_path: &Path) {
    let text = std::fs::read_to_string(log_path).unwrap();
    let entries: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let head = entries.iter().find(|e| e["method"] == "HEAD").unwrap();
    assert!(head["bytes"].as_u64().unwrap() > 0);
    assert_eq!(head["sent"], 0);
    assert_eq!(head["complete"], true);
    let redirect = entries.iter().find(|e| e["kind"] == "redirect").unwrap();
    assert_eq!(
        redirect["location"],
        "https://en.wikipedia.org/wiki/Main_Page"
    );
    let redirect = entries
        .iter()
        .find(|e| e["kind"] == "http_redirect")
        .unwrap();
    assert_eq!(redirect["location"], "https://en.wikipedia.org/wiki/X");
    let mut got: Vec<String> = text
        .lines()
        .map(|l| {
            let mut v: Value = serde_json::from_str(l).unwrap();
            v.as_object_mut().unwrap().remove("ts");
            v.to_string()
        })
        .collect();
    got.sort();
    let file = here.join("tests/golden/altered_one.jsonl");

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
