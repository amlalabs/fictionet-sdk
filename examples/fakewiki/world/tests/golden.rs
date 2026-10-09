//! The request log for a fixed script of agent actions, compared line for
//! line with a log recorded before the service layer (`tests/golden/`).
//!
//! FakeWiki's eval reads `log.jsonl` after the run, so the same lines mean
//! the same report. The world runs here with its real Python backend
//! (`backend/backend.py`, which needs only `python3`) and a CA made for the
//! test. `ts` is dropped and the lines are compared as sorted sets.
//!
//! `FAKEWIKI_GOLDEN_WRITE=1 cargo test --test golden` records the file again.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use fakewiki_world::content::Content;
use fakewiki_world::log::Log;
use fakewiki_world::{Args, issue_leaves, serve, start_backend};
use fictionet::Cx;
use fictionet::prelude::*;
use fictionet::stdlib::dns::rr::RecordType;
use serde_json::Value;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

use fictionet::stdlib::sandbox::{Machine, machine};

async fn lookup(fcx: &Cx, m: &Machine, name: &str, kind: RecordType) {
    m.lookup(fcx, GATEWAY.into(), name, kind).await.unwrap();
}

/// One HTTP/1.1 request; returns the status.
async fn get<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    io: fictionet::tokio::Compat<C>,
    method: &str,
    host: &str,
    path: &str,
) -> u16 {
    use fictionet::stdlib::{codec::Wire, http1, sandbox};
    let request = http1::Request::parse(
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    sandbox::request(fcx, &mut io.into_inner(), &request)
        .await
        .unwrap()
        .head
        .status
}

async fn tls(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    sni: &str,
) -> std::io::Result<
    fictionet::tokio::Compat<
        fictionet::stdlib::sandbox::TlsClient<fictionet::stdlib::tcp::TcpConnection>,
    >,
> {
    m.tls(
        fcx,
        SocketAddr::new(addr.into(), 443),
        sni,
        None,
        std::time::SystemTime::now(),
    )
    .await
    .map(|conn| conn.into_tokio(fcx))
    .map_err(std::io::Error::other)
}

#[test]
fn the_log_is_the_recorded_one() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let state_dir =
        std::env::temp_dir().join(format!("fakewiki-golden-state-{}", std::process::id()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // SAFETY: set before any thread of this test process reads the environment.
    unsafe {
        std::env::set_var("FAKEWIKI_CORPUS", here.join("../fixtures/corpus.json"));
        std::env::set_var("FAKEWIKI_VARIANT", "altered_one");
    }
    let args = Args {
        socket: String::new(),
        ca_dir: state_dir.join("ca"),
        backend: here.join("backend"),
        backend_port: port,
        state_dir: state_dir.clone(),
        ready: state_dir.join("ready"),
    };
    let (backend, mut child) = start_backend(&args).unwrap();
    let mut hosts = HashMap::new();
    for (name, ip) in backend["hosts"].as_object().unwrap() {
        hosts.insert(
            name.clone(),
            ip.as_str().unwrap().parse::<Ipv4Addr>().unwrap(),
        );
    }
    let documents: Vec<String> = backend["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["url"].as_str().unwrap().to_owned())
        .collect();
    let log_path = state_dir.join("log.jsonl");
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
                let leaves = issue_leaves(&fcx, &args.ca_dir, hosts.keys()).unwrap();
                let (attacher, attachments) = fictionet::attachments();
                serve(&fcx, &hosts, leaves, Content::new(port), log, attachments)?;

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
                    get(
                        &fcx,
                        conn.into_tokio(&fcx),
                        "GET",
                        "en.wikipedia.org",
                        "/wiki/X"
                    )
                    .await,
                    301
                );
                // A name the world does not serve.
                assert!(tls(&fcx, &m, wiki, "example.com").await.is_err());
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
    if std::env::var_os("FAKEWIKI_GOLDEN_WRITE").is_some() {
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
