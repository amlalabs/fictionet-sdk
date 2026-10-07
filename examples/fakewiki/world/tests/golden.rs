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

use bytes::Bytes;
use fakewiki_world::content::Content;
use fakewiki_world::log::Log;
use fakewiki_world::{Args, issue_leaves, look_up_all, serve, start_backend};
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RecordType};
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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(alpn: &[u8]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

async fn lookup(cx: &Cx, m: &Machine, name: &str, kind: RecordType) {
    let mut socket = m.udp.bind(40000 + (cx.random_u64() % 20000) as u16).unwrap();
    let mut q = Message::query();
    q.metadata.id = cx.random_u64() as u16;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    socket.recv(cx).await.unwrap();
}

/// One HTTP/1.1 request; returns the status.
async fn get<IO>(io: IO, method: &str, host: &str, path: &str) -> u16
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("user-agent", "curl/8.5.0")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = send.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let _ = response.into_body().collect().await;
    status
}

async fn tls(cx: &Cx, m: &Machine, addr: Ipv4Addr, sni: &str) -> std::io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
    let conn = m.tcp.connect(cx, SocketAddr::new(addr.into(), 443)).await.map_err(std::io::Error::other)?;
    let connector = tokio_rustls::TlsConnector::from(client_config(b"http/1.1"));
    connector.connect(ServerName::try_from(sni.to_owned()).unwrap(), conn.into_tokio(cx)).await
}

/// A CA in a fresh directory, as `ca.py` leaves it: `ca.pem` and `ca.key`.
fn ca_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fakewiki-golden-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, "FakeWiki Test CA");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(dir.join("ca.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("ca.key"), key.serialize_pem()).unwrap();
    dir
}

#[test]
fn the_log_is_the_recorded_one() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let state_dir = std::env::temp_dir().join(format!("fakewiki-golden-state-{}", std::process::id()));
    std::fs::create_dir_all(&state_dir).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    // SAFETY: set before any thread of this test process reads the environment.
    unsafe {
        std::env::set_var("FAKEWIKI_CORPUS", here.join("../fixtures/corpus.json"));
        std::env::set_var("FAKEWIKI_VARIANT", "altered_one");
    }
    let args = Args {
        socket: String::new(),
        ca_dir: ca_dir(),
        backend: here.join("backend"),
        backend_port: port,
        state_dir: state_dir.clone(),
        ready: state_dir.join("ready"),
    };
    let (backend, mut child) = start_backend(&args).unwrap();
    let mut hosts = HashMap::new();
    for (name, ip) in backend["hosts"].as_object().unwrap() {
        hosts.insert(name.clone(), ip.as_str().unwrap().parse::<Ipv4Addr>().unwrap());
    }
    let documents: Vec<String> =
        backend["documents"].as_array().unwrap().iter().map(|d| d["url"].as_str().unwrap().to_owned()).collect();
    let log_path = state_dir.join("log.jsonl");
    let log = Arc::new(Log::create(&log_path).unwrap());
    let leaves = issue_leaves(&args.ca_dir, hosts.keys()).unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let result = rt.block_on(fictionet::run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let host_list: Vec<String> = hosts.keys().cloned().collect();
            serve(&cx, &hosts, leaves, Content::new(port), log, attachments)?;
            look_up_all(&cx, &attacher, &host_list).await?;

            let end = attacher.attach("agent").unwrap();
            let (t, u, i, _other) = ip::split_protocols(&cx, end);
            let m = Machine { tcp: tcp::endpoint(&cx, t, ME.into()), udp: udp::endpoint(&cx, u, ME.into()), _icmp: i };
            let wiki = hosts["en.wikipedia.org"];
            lookup(&cx, &m, "en.wikipedia.org", RecordType::A).await;
            lookup(&cx, &m, "en.wikipedia.org", RecordType::AAAA).await;
            lookup(&cx, &m, "example.com", RecordType::A).await;
            lookup(&cx, &m, "rw-desktop", RecordType::A).await;
            // The first three documents, over HTTPS, and one HEAD.
            for url in documents.iter().take(3) {
                let uri: http::Uri = url.parse().unwrap();
                let host = uri.host().unwrap().to_owned();
                let stream = tls(&cx, &m, hosts[&host], &host).await.unwrap();
                assert_eq!(get(stream, "GET", &host, uri.path()).await, 200, "{url}");
            }
            let stream = tls(&cx, &m, wiki, "en.wikipedia.org").await.unwrap();
            get(stream, "HEAD", "en.wikipedia.org", "/wiki/Main_Page").await;
            let stream = tls(&cx, &m, wiki, "en.wikipedia.org").await.unwrap();
            get(stream, "GET", "en.wikipedia.org", "/no/such/page?q=1").await;
            // A host at another address, over this connection.
            let stream = tls(&cx, &m, wiki, "en.wikipedia.org").await.unwrap();
            assert_eq!(get(stream, "GET", "www.gov.uk", "/").await, 421);
            // Plain HTTP: a redirect.
            let conn = m.tcp.connect(&cx, SocketAddr::new(IpAddr::V4(wiki), 80)).await.unwrap();
            assert_eq!(get(conn.into_tokio(&cx), "GET", "en.wikipedia.org", "/wiki/X").await, 301);
            // A name the world does not serve.
            assert!(tls(&cx, &m, wiki, "example.com").await.is_err());
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
        assert!(got.contains(line), "missing from the log now: {line}\n\nthe log now:\n{}", got.join("\n"));
    }
    for line in &got {
        assert!(want.contains(line), "new in the log: {line}\n\nrecorded:\n{}", want.join("\n"));
    }
    assert_eq!(got, want);
}
