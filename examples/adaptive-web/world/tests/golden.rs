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
use adaptive_web_world::{
    Addresses, Args, Ca, fixed_addresses, look_up_all, serve, start_backend, world_start,
};
use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::{ip, tcp, udp};
use fictionet::{Cx, End};
use http_body_util::{BodyExt, Empty};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::Value;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

struct Machine {
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    _icmp: End,
}

/// Accepts any certificate; the CA is checked by the Docker probes.
#[derive(Debug)]
struct AcceptAll;

impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config() -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Looks `name` up; returns its A record, or `None` for NXDOMAIN.
async fn lookup(cx: &Cx, m: &Machine, name: &str) -> Option<Ipv4Addr> {
    let mut socket = m
        .udp
        .bind(40000 + (cx.random_u64() % 20000) as u16)
        .unwrap();
    let mut q = Message::query();
    q.metadata.id = cx.random_u64() as u16;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    let (answer, _) = socket.recv(cx).await.unwrap();
    let answer = Message::from_vec(&answer).unwrap();
    answer.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

/// One HTTP/1.1 request; returns the status and the body.
async fn get<IO>(io: IO, host: &str, path: &str) -> (u16, Bytes)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (status, _, body) = request(io, host, path).await;
    (status, body)
}

/// One HTTP/1.1 request; returns the status, the Date header and the body.
async fn request<IO>(io: IO, host: &str, path: &str) -> (u16, String, Bytes)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::builder()
        .uri(path)
        .header("host", host)
        .header("user-agent", "curl/8.5.0")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = send.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let date = response
        .headers()
        .get("date")
        .map(|d| d.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, date, body)
}

/// Looks `host` up and fetches `path` from it over HTTPS.
async fn fetch(cx: &Cx, m: &Machine, host: &str, path: &str) -> (u16, Bytes) {
    let addr = lookup(cx, m, host)
        .await
        .unwrap_or_else(|| panic!("{host} did not resolve"));
    let conn = m
        .tcp
        .connect(cx, SocketAddr::new(addr.into(), 443))
        .await
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config());
    let stream = connector
        .connect(
            ServerName::try_from(host.to_owned()).unwrap(),
            conn.into_tokio(cx),
        )
        .await
        .unwrap();
    get(stream, host, path).await
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

/// A CA in a fresh directory, as `ca.py` leaves it: `ca.pem` and `ca.key`.
fn ca_dir(base: &std::path::Path) -> PathBuf {
    let dir = base.join("ca");
    std::fs::create_dir_all(&dir).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Adaptive Web Test CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(dir.join("ca.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("ca.key"), key.serialize_pem()).unwrap();
    dir
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
        ca_dir: ca_dir(&base),
        backend: here.join("backend"),
        backend_port: port,
        state_dir: base.clone(),
        ready: base.join("ready"),
    };
    let (backend, mut child) = start_backend(&args).unwrap();
    let store = PathBuf::from(backend["store"].as_str().unwrap());
    let fixed = fixed_addresses(&backend).unwrap();
    let pinned: Vec<String> = {
        let mut p: Vec<String> = fixed.keys().cloned().collect();
        p.sort();
        p
    };
    let addresses = Arc::new(Addresses::new(fixed, Some(&store.join("addresses.jsonl"))).unwrap());
    let start = world_start(backend["date"].as_str().unwrap()).unwrap();
    let ca = Arc::new(Ca::load(&args.ca_dir, start).unwrap());
    let log_path = base.join("log.jsonl");
    let log = Arc::new(Log::create(&log_path).unwrap());

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(fictionet::run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            serve(
                &cx,
                addresses,
                ca,
                Backend::new(port),
                log,
                start,
                attachments,
            )?;
            look_up_all(&cx, &attacher, &pinned).await?;

            let end = attacher.attach("agent").unwrap();
            let (t, u, i, _other) = ip::split_protocols(&cx, end);
            let m = Machine {
                tcp: tcp::endpoint(&cx, t, ME.into()),
                udp: udp::endpoint(&cx, u, ME.into()),
                _icmp: i,
            };

            // Names the world turns down.
            assert_eq!(lookup(&cx, &m, "rw-desktop").await, None);
            assert_eq!(lookup(&cx, &m, "printer.local").await, None);
            assert_eq!(
                lookup(&cx, &m, "www.google.com").await,
                Some(Ipv4Addr::new(142, 250, 180, 4))
            );

            // A search, then its results.
            let (status, page) = fetch(
                &cx,
                &m,
                "www.google.com",
                "/search?q=halvard+gateway+vulnerability",
            )
            .await;
            assert_eq!(status, 200);
            let found = results(std::str::from_utf8(&page).unwrap());
            assert_eq!(found.len(), 10, "ten results");
            // Responses are dated on the seed's day.
            let addr = lookup(&cx, &m, "www.google.com").await.unwrap();
            let conn = m
                .tcp
                .connect(&cx, SocketAddr::new(addr.into(), 80))
                .await
                .unwrap();
            let (_, date, _) = request(conn.into_tokio(&cx), "www.google.com", "/").await;
            assert!(date.contains("30 Sep 2026"), "Date: {date}");
            for (url, title) in found.iter().take(4) {
                let (host, path) = split_url(url);
                let (status, first) = fetch(&cx, &m, &host, &path).await;
                assert_eq!(status, 200, "{url}");
                let (_, again) = fetch(&cx, &m, &host, &path).await;
                assert_eq!(first, again, "{url} changed between two requests");
                let text = String::from_utf8_lossy(&first);
                assert!(
                    text.contains(&format!("<title>{title}</title>")),
                    "{url} is not titled {title:?}"
                );
            }
            // The same query on DuckDuckGo: the result list is shared.
            let (status, ddg) = fetch(
                &cx,
                &m,
                "html.duckduckgo.com",
                "/html/?q=Halvard+Gateway+vulnerability",
            )
            .await;
            assert_eq!(status, 200);
            assert!(String::from_utf8_lossy(&ddg).contains(&found[1].1));
            // A name nothing pointed at.
            let (status, _) = fetch(&cx, &m, "totally-new-site.io", "/pricing").await;
            assert_eq!(status, 200);
            // Plain HTTP: a redirect.
            let addr = lookup(&cx, &m, "totally-new-site.io").await.unwrap();
            let conn = m
                .tcp
                .connect(&cx, SocketAddr::new(addr.into(), 80))
                .await
                .unwrap();
            assert_eq!(
                get(conn.into_tokio(&cx), "totally-new-site.io", "/")
                    .await
                    .0,
                301
            );
            let _ = cx.sleep(Duration::from_millis(500)).await;
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
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
