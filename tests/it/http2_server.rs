use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use fictionet::events::Fields;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::http2::{self, Frame};
use fictionet::stdlib::services::serve::Harness;
use fictionet::stdlib::web::httpd::{self, Http2, Router};
use fictionet::stdlib::world::sandbox::TlsClient;
use fictionet::stdlib::{
    network::{Connection, ConnectionExt, filter},
    protocols::hpack,
    services::tls,
    world::{net, sandbox},
};
use fictionet::{Cx, Seed};

const SITE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const DATE: u64 = 1_893_456_000;

fn headers(stream: u32, path: &str, end: bool) -> Vec<u8> {
    let mut fragment = Vec::new();
    for (name, value) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path),
    ] {
        hpack::Field::new(name, value).write(&mut fragment).unwrap();
    }
    http2::Headers {
        stream,
        flags: 4 | u8::from(end),
        fragment,
        priority: None,
        padding: None,
    }
    .to_bytes()
    .unwrap()
}

fn preface() -> Vec<u8> {
    let mut bytes = http2::PREFACE.to_vec();
    http2::Settings {
        flags: 0,
        entries: Vec::new(),
    }
    .write(&mut bytes)
    .unwrap();
    http2::Settings {
        flags: 1,
        entries: Vec::new(),
    }
    .write(&mut bytes)
    .unwrap();
    bytes
}

fn frames(mut bytes: &[u8]) -> Vec<Frame> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let header = http2::FrameHeader::parse(&bytes[..9]).unwrap();
        let end = 9 + header.length;
        result.push(Frame::parse(&bytes[..end]).unwrap());
        bytes = &bytes[end..];
    }
    result
}

async fn read_frame(cx: &Cx, connection: &mut impl Connection) -> Frame {
    let mut bytes = vec![0; 9];
    let mut at = 0;
    while at < bytes.len() {
        let n = connection.read(cx, &mut bytes[at..]).await.unwrap();
        assert_ne!(n, 0, "connection ended inside a frame");
        at += n;
    }
    let header = http2::FrameHeader::parse(&bytes).unwrap();
    bytes.resize(9 + header.length, 0);
    while at < bytes.len() {
        let n = connection.read(cx, &mut bytes[at..]).await.unwrap();
        assert_ne!(n, 0);
        at += n;
    }
    Frame::parse(&bytes).unwrap()
}

#[test]
fn windows_settings_and_concurrent_streams() {
    let router = Router::new().post("/", |_, _| {
        http::Response::new(Bytes::from(vec![b'x'; 100_000]))
    });
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(router), ());
    let mut input = preface();
    http2::Settings {
        flags: 0,
        entries: vec![http2::Setting { id: 4, value: 10 }],
    }
    .write(&mut input)
    .unwrap();
    for id in [1, 3, 5] {
        input.extend(headers(id, "/", true));
    }
    let output = frames(&harness.push(&input).unwrap());
    for id in [1, 3, 5] {
        assert_eq!(
            output
                .iter()
                .filter_map(|frame| match frame {
                    Frame::Data(data) if data.stream == id => Some(data.data.len()),
                    _ => None,
                })
                .sum::<usize>(),
            10
        );
    }
    let mut input = Vec::new();
    http2::Settings {
        flags: 0,
        entries: vec![http2::Setting { id: 4, value: 0 }],
    }
    .write(&mut input)
    .unwrap();
    http2::WindowUpdate {
        stream: 1,
        flags: 0,
        increment: 10,
    }
    .write(&mut input)
    .unwrap();
    assert!(
        !frames(&harness.push(&input).unwrap())
            .iter()
            .any(|f| matches!(f, Frame::Data(_)))
    );
    let input = http2::WindowUpdate {
        stream: 1,
        flags: 0,
        increment: 20,
    }
    .to_bytes()
    .unwrap();
    let output = frames(&harness.push(&input).unwrap());
    assert_eq!(
        output
            .iter()
            .filter_map(|f| match f {
                Frame::Data(d) => Some(d.data.len()),
                _ => None,
            })
            .sum::<usize>(),
        20
    );
    assert_eq!(harness.pending().1, 3);
}

#[test]
fn resets_and_continuations_are_bounded() {
    let router = Router::new();
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(router), ());
    harness.push(&preface()).unwrap();
    let first = http2::Headers {
        stream: 1,
        flags: 1,
        fragment: Vec::new(),
        priority: None,
        padding: None,
    }
    .to_bytes()
    .unwrap();
    harness.push(&first).unwrap();
    let continuation = http2::Continuation {
        stream: 1,
        flags: 0,
        fragment: Vec::new(),
    }
    .to_bytes()
    .unwrap();
    for _ in 0..5 {
        assert!(harness.push(&continuation).unwrap().is_empty());
    }
    let output = frames(&harness.push(&continuation).unwrap());
    assert!(output.iter().any(
        |f| matches!(f, Frame::GoAway(g) if g.code == http2::ErrorCode::EnhanceYourCalm as u32)
    ));
    assert!(harness.closed());
}

#[test]
fn settings_acknowledgment_and_idle_stream_errors() {
    for invalid in [
        http2::Settings {
            flags: 1,
            entries: Vec::new(),
        }
        .to_bytes()
        .unwrap(),
        http2::Reset {
            stream: 1,
            flags: 0,
            code: 8,
        }
        .to_bytes()
        .unwrap(),
        http2::WindowUpdate {
            stream: 1,
            flags: 0,
            increment: 1,
        }
        .to_bytes()
        .unwrap(),
    ] {
        let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
        harness.push(&preface()).unwrap();
        assert!(
            frames(&harness.push(&invalid).unwrap())
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.code == 1))
        );
        assert!(harness.closed());
    }
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    events: Vec<u8>,
    packets: Vec<(bool, Vec<u8>)>,
}

fn replay() -> Trace {
    let trace: Arc<Mutex<Trace>> = Arc::default();
    let packets = trace.clone();
    let log = Log::default();
    let writer = log.clone();
    fictionet::block_on(fictionet::lab(Seed::from_u64(71), move |cx| async move {
        cx.events().to_writer(Box::new(writer));
        let cert = rustls::pki_types::CertificateDer::from(include_bytes!("fixtures/tls/ed25519.cert.der").to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(include_bytes!("fixtures/tls/ed25519.key.der").to_vec()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone())?;
        let date = UNIX_EPOCH + Duration::from_secs(DATE);
        let config = Arc::new(tls::config_builder(&cx, date).with_safe_default_protocol_versions()?.with_no_client_auth().with_single_cert(vec![cert], key)?);
        let router = Router::new().post("/", |ex, _| http::Response::new(Bytes::from(ex.random_u64().to_be_bytes().to_vec())));
        let (attach, arrivals) = fictionet::attachments();
        net::Net::new().ipv4_only().host("site", |host| host.at(SITE).dns_name("localhost").tls_accept(443, "localhost", move |_| config.clone(), httpd::Server::new(router).https())).start(&cx, arrivals)?;
        let cable = filter(&cx, attach.attach("client")?, move |_, direction, packet| {
            packets.lock().unwrap().packets.push((direction == fictionet::stdlib::network::Direction::FromInner, packet.0.clone()));
            true
        });
        let machine = sandbox::machine(&cx, cable, Ipv4Addr::new(10, 0, 0, 2));
        let tcp = machine.tcp.connect(&cx, SocketAddr::new(SITE.into(), 443)).await?;
        let mut conn = TlsClient::new(&cx, tcp, &Arc::new(roots), "localhost", &[b"h2"], date)?;
        conn.handshake(&cx).await?;
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut input = preface();
        input.extend(headers(1, "/", false));
        http2::Reset { stream: 1, flags: 0, code: 8 }.write(&mut input)?;
        input.extend(headers(3, "/", true));
        conn.write_all(&cx, &input).await?;
        loop {
            if matches!(read_frame(&cx, &mut conn).await, Frame::Data(d) if d.stream == 3 && d.flags & 1 != 0) { break }
        }
        // Late frames must be classified by elapsed world time in both replays.
        cx.sleep(Duration::from_millis(1100)).await?;
        let late = http2::Data { stream: 1, flags: 1, data: vec![1, 2, 3], padding: None }.to_bytes()?;
        conn.write_all(&cx, &late).await?;
        loop {
            if matches!(read_frame(&cx, &mut conn).await, Frame::Reset(r) if r.stream == 1) { break }
        }
        // Expiry of the local reset must also follow the world clock: once
        // it expires, HEADERS on the closed stream ends the connection.
        cx.sleep(Duration::from_millis(1100)).await?;
        conn.write_all(&cx, &headers(1, "/", true)).await?;
        loop {
            if let Frame::GoAway(goaway) = read_frame(&cx, &mut conn).await {
                assert_eq!(goaway.code, 1);
                break;
            }
        }
        let events = cx.events().of("http", "request");
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.str("version") == Some("HTTP/2.0")));
        cx.record(fictionet::events::Event::new("test", "complete").fields(Fields::new().with("requests", events.len() as u64)));
        cx.cancel();
        Ok(())
    })).unwrap();
    let mut trace = std::mem::take(&mut *trace.lock().unwrap());
    trace.events = log.0.lock().unwrap().clone();
    trace
}

#[test]
fn reset_late_frames_replay_on_lab_time_over_tls() {
    let first = replay();
    let second = replay();
    assert!(!first.packets.is_empty());
    assert!(!first.events.is_empty());
    assert_eq!(first, second);
}

mod clients {
    use super::*;
    use fictionet::InterfaceExt;
    use fictionet_test_support::hyper_io::Io;
    use hyper_util::rt::TokioIo;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::process::Command;
    use std::task::{Context, Poll};

    struct Interrupted(bool);
    impl http_body::Body for Interrupted {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            if std::mem::replace(&mut self.0, false) {
                Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_static(
                    b"started",
                )))))
            } else {
                Poll::Pending
            }
        }
    }

    struct Site(Router);
    impl httpd::Handler for Site {
        fn call(
            &self,
            request: http::Request<httpd::Body>,
            ex: &mut httpd::Exchange<'_>,
        ) -> httpd::Reply {
            if request.uri().path() == "/cancel" {
                httpd::Reply::Now(
                    http::Response::builder()
                        .header("content-type", "application/octet-stream")
                        .header("x-content-type-options", "nosniff")
                        .body(httpd::Body::new(Interrupted(true)))
                        .unwrap(),
                )
            } else {
                self.0.call(request, ex)
            }
        }
    }

    struct World {
        address: SocketAddr,
        dir: PathBuf,
        stop: Option<fictionet::End>,
        thread: Option<std::thread::JoinHandle<()>>,
        events: Arc<Mutex<Vec<fictionet::events::Event>>>,
    }

    impl World {
        fn start() -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let dir = fictionet_test_support::temp::dir();
            let ca_path = dir.join("ca.pem");
            let (stop, mut stopped) = fictionet::pair();
            let events: Arc<Mutex<Vec<fictionet::events::Event>>> = Arc::default();
            let observed = events.clone();
            let (ready, started) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(fictionet::run(Seed::from_u64(20), move |cx| async move {
                    cx.events().subscribe(move |event| {
                        if event.is("http", "request") { observed.lock().unwrap().push(event.clone()); }
                    });
                    let (ca, leaf) = fictionet_test_support::certs::issue(&cx, "HTTP test CA", &["localhost"])?;
                    std::fs::write(ca_path, ca.cert_pem())?;
                    let config = Arc::new(tls::config_builder(&cx, std::time::SystemTime::now()).with_safe_default_protocol_versions()?.with_no_client_auth().with_single_cert(leaf.chain, leaf.key)?);
                    let page = r#"<!doctype html><html><body><script>
let completed = 0;
const abort = new AbortController();
fetch('/cancel', {signal: abort.signal}).then(r => r.body.getReader().read()).then(() => abort.abort());
window.addEventListener('load', () => {
  const resources = performance.getEntriesByType('resource').filter(r => r.name.includes('/large/'));
  document.body.textContent = completed === 4 && resources.length === 4 && resources.every(r => r.nextHopProtocol === 'h2') ? 'HTTP2 COMPLETE' : 'HTTP2 FAILED';
});
</script><script async src="/large/1"></script><script async src="/large/2"></script><script async src="/large/3"></script><script async src="/large/4"></script><script defer src="/gate"></script></body></html>"#;
                    let router = Router::new()
                        .get("/", move |_, _| http::Response::builder().header("content-type", "text/html").body(Bytes::from_static(page.as_bytes())).unwrap())
                        .get("/large/*", |_, _| {
                            let body = format!("/*{}*/completed++;", "x".repeat(1 << 20));
                            http::Response::builder().header("content-type", "application/javascript").body(Bytes::from(body)).unwrap()
                        })
                        .route_async(Some(http::Method::GET), "/gate", |cx, _| async move {
                            cx.events().wait(&cx, 1, Duration::from_secs(10), |e| e.is("http", "request") && e.str("path") == Some("/cancel")).await.unwrap();
                            http::Response::builder().header("content-type", "application/javascript").body(Bytes::new()).unwrap()
                        });
                    let (attach, arrivals) = fictionet::attachments();
                    net::Net::new().ipv4_only().host("site", |host| host.at(SITE).dns_name("localhost").tls_accept(443, "localhost", move |_| config.clone(), httpd::Server::new(Site(router)).limits(httpd::Limits { body: 1024, ..Default::default() }).https())).start(&cx, arrivals)?;
                    let machine = sandbox::machine(&cx, attach.attach("client")?, Ipv4Addr::new(10, 0, 0, 2));
                    let listener = tokio::net::TcpListener::from_std(listener)?;
                    cx.spawn(move |cx| async move {
                        while let Ok(accepted) = cx.race(None, listener.accept()).await {
                            let (mut host, _) = accepted?;
                            let tcp = machine.tcp.clone();
                            cx.spawn(move |cx| async move {
                                let conn = tcp.connect(&cx, SocketAddr::new(SITE.into(), 443)).await?;
                                let mut simulated = TokioIo::new(Io { fcx: cx.clone(), conn });
                                let _ = tokio::io::copy_bidirectional(&mut host, &mut simulated).await;
                                Ok(())
                            });
                        }
                        Ok(())
                    });
                    ready.send(()).unwrap();
                    let _ = stopped.recv(&cx).await;
                    cx.cancel();
                    Ok(())
                })).unwrap();
            });
            started.recv_timeout(Duration::from_secs(20)).unwrap();
            Self {
                address,
                dir,
                stop: Some(stop),
                thread: Some(thread),
                events,
            }
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            self.stop.take();
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn curl_and_chromium_use_tls_http2() {
        fictionet_test_support::within(Duration::from_secs(60), || {
            let world = World::start();
            let url = format!("https://localhost:{}", world.address.port());
            let output = Command::new("curl")
                .args([
                    "--http2",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "20",
                    "--cacert",
                ])
                .arg(world.dir.join("ca.pem"))
                .args([
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_version} %{size_download}",
                ])
                .arg(format!("{url}/large/curl"))
                .output()
                .expect("curl is installed");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.starts_with("2 "), "{text}");
            assert!(
                text.split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    > 1 << 20
            );
            let upload = world.dir.join("upload");
            std::fs::write(&upload, vec![b'x'; 200_000]).unwrap();
            let output = Command::new("curl")
                .args([
                    "--http2",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "20",
                    "--cacert",
                ])
                .arg(world.dir.join("ca.pem"))
                .args([
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_version} %{http_code}",
                    "--data-binary",
                ])
                .arg(format!("@{}", upload.display()))
                .arg(format!("{url}/upload"))
                .output()
                .expect("curl is installed");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"2 413");
            let chromium = std::env::var_os("CHROMIUM").unwrap_or_else(|| "chromium".into());
            let output = Command::new(chromium)
                .args([
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--password-store=basic",
                    "--no-proxy-server",
                    "--ignore-certificate-errors",
                    "--dump-dom",
                ])
                .arg(format!(
                    "--user-data-dir={}",
                    world.dir.join("browser").display()
                ))
                .arg(&url)
                .output()
                .expect("Chromium is installed");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let page = String::from_utf8(output.stdout).unwrap();
            assert!(
                page.contains("<body>HTTP2 COMPLETE</body>"),
                "{page}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let events = world.events.lock().unwrap();
            assert!(events.iter().all(|e| e.str("version") == Some("HTTP/2.0")));
            let large: Vec<_> = events
                .iter()
                .filter(|e| {
                    e.str("path")
                        .is_some_and(|p| p.starts_with("/large/") && p != "/large/curl")
                })
                .collect();
            assert_eq!(large.len(), 4);
            assert!(large.iter().all(|e| e.u64("sent").unwrap() > 1 << 20));
            assert!(large.iter().all(|e| e.conn.id == large[0].conn.id));
            let latest_start = large
                .iter()
                .map(|e| e.get("started").unwrap().as_f64().unwrap())
                .fold(0.0, f64::max);
            let first_completion = large
                .iter()
                .map(|e| e.at.since_start().as_secs_f64())
                .fold(f64::INFINITY, f64::min);
            assert!(latest_start < first_completion);
            let cancelled = events
                .iter()
                .find(|e| e.str("path") == Some("/cancel"))
                .unwrap();
            assert_eq!(
                cancelled.get("complete").and_then(|v| v.as_bool()),
                Some(false)
            );
        });
    }
}

#[test]
fn rapid_reset_limits_pending_accepts_but_releases_drained_counts() {
    let mut burst = preface();
    for id in (1..=41).step_by(2) {
        burst.extend(headers(id, "/", false));
        http2::Reset {
            stream: id,
            flags: 0,
            code: 8,
        }
        .write(&mut burst)
        .unwrap();
    }
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    let reply = frames(&harness.push(&burst).unwrap());
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
    );
    assert!(harness.closed());

    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    harness.push(&preface()).unwrap();
    for id in (1..=81).step_by(2) {
        harness.push(&headers(id, "/", false)).unwrap();
        harness
            .push(
                &http2::Reset {
                    stream: id,
                    flags: 0,
                    code: 8,
                }
                .to_bytes()
                .unwrap(),
            )
            .unwrap();
    }
    assert!(!harness.closed());
}

#[test]
fn local_protocol_resets_eventually_close_the_connection() {
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    harness.push(&preface()).unwrap();
    for n in 0..1025 {
        let malformed = http2::Headers {
            stream: 2 * n + 1,
            flags: 5,
            fragment: vec![0x88],
            priority: None,
            padding: None,
        }
        .to_bytes()
        .unwrap();
        let reply = frames(&harness.push(&malformed).unwrap());
        assert!(
            reply
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 1))
        );
        assert_eq!(harness.closed(), n == 1024);
        if n == 1024 {
            assert!(
                reply
                    .iter()
                    .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
            );
        }
    }
}

#[test]
fn zero_stream_window_is_a_stream_error_and_large_headers_get_431() {
    let limits = httpd::Limits {
        head: fictionet::stdlib::protocols::http1::Limits {
            head: 256,
            ..Default::default()
        },
        ..Default::default()
    };
    let router = Router::new().post("/", |_, _| http::Response::new(Bytes::from_static(b"ok")));
    let mut harness = Harness::new(Seed::from_u64(1), Http2::with(Arc::new(router), limits), ());
    harness.push(&preface()).unwrap();
    harness.push(&headers(1, "/", false)).unwrap();
    let invalid = [0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let reply = frames(&harness.push(&invalid).unwrap());
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 1))
    );
    assert!(!harness.closed());
    let Frame::Headers(mut oversized) = Frame::parse(&headers(3, "/", true)).unwrap() else {
        unreachable!()
    };
    oversized.fragment.extend_from_slice(&[0xaf; 10]);
    let reply = frames(&harness.push(&oversized.to_bytes().unwrap()).unwrap());
    let mut block = http2::HeaderBlocks::with_limits(Default::default());
    let mut status = None;
    for frame in &reply {
        if let Some(decoded) = block.read_frame(frame).unwrap().block {
            status = decoded
                .headers
                .into_iter()
                .find(|h| h.name.as_deref() == Some(b":status"))
                .and_then(|h| h.value);
        }
    }
    assert_eq!(status.as_deref(), Some(b"431".as_slice()));
    assert!(!harness.closed());
    let reply = frames(&harness.push(&headers(5, "/", true)).unwrap());
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.data == b"ok"))
    );
}

#[test]
fn graceful_goaway_drains_streams_after_the_ping_round_trip() {
    let mut service =
        Http2::new(Router::new().post("/", |_, _| http::Response::new(Bytes::from_static(b"ok"))));
    service.graceful_shutdown();
    let mut harness = Harness::new(Seed::from_u64(1), service, ());
    let mut input = preface();
    input.extend(headers(1, "/", false));
    let initial = frames(&harness.push(&input).unwrap());
    assert!(initial.iter().any(
        |f| matches!(f, Frame::GoAway(g) if g.last_stream == http2::MAX_WINDOW && g.code == 0)
    ));
    let opaque = initial
        .iter()
        .find_map(|f| match f {
            Frame::Ping(p) => Some(p.opaque),
            _ => None,
        })
        .unwrap();
    let reply = frames(
        &harness
            .push(&http2::Ping { flags: 1, opaque }.to_bytes().unwrap())
            .unwrap(),
    );
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == 1 && g.code == 0))
    );
    assert!(!harness.closed());
    let reply = frames(
        &harness
            .push(
                &http2::Data {
                    stream: 1,
                    flags: 1,
                    data: Vec::new(),
                    padding: None,
                }
                .to_bytes()
                .unwrap(),
            )
            .unwrap(),
    );
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.data == b"ok"))
    );
    assert!(harness.closed());
}

fn data(stream: u32, size: usize, end: bool) -> Vec<u8> {
    http2::Data {
        stream,
        flags: u8::from(end),
        data: vec![b'x'; size],
        padding: None,
    }
    .to_bytes()
    .unwrap()
}

fn statuses(output: &[Frame]) -> Vec<(u32, Vec<u8>)> {
    let mut blocks = http2::HeaderBlocks::with_limits(Default::default());
    output
        .iter()
        .filter_map(|frame| {
            let read = blocks.read_frame(frame).unwrap();
            read.block.and_then(|block| {
                block
                    .headers
                    .into_iter()
                    .find(|h| h.name.as_deref() == Some(b":status"))
                    .and_then(|h| h.value)
                    .map(|value| (read.stream, value))
            })
        })
        .collect()
}

// An idle connection holds its frame buffer, its HPACK table at the bound
// it advertises and its full list of recent resets.
pub(crate) const H2_INPUT: usize = http2::DEFAULT_FRAME_SIZE
    + http2::HEADER_LEN
    + 4096
    + 50 * std::mem::size_of::<(u32, fictionet::time::Instant)>();

#[test]
fn immediate_echo_releases_the_request_charge() {
    let router = Router::new().post("/", |_, request| http::Response::new(request.into_body()));
    let budget = fictionet::stdlib::services::serve::Budget::new(H2_INPUT + 8000);
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Http2::new(router),
        (),
        fictionet::stdlib::services::serve::ServeOptions::default().budget(budget.clone()),
    );
    let mut input = preface();
    input.extend(headers(1, "/", false));
    harness.push(&input).unwrap();
    let output = frames(&harness.push(&data(1, 3000, true)).unwrap());
    assert_eq!(statuses(&output), [(1, b"200".to_vec())]);
    assert_eq!(
        output
            .iter()
            .filter_map(|f| match f {
                Frame::Data(d) => Some(d.data.len()),
                _ => None,
            })
            .sum::<usize>(),
        3000
    );
    assert!(!harness.closed());
    assert_eq!(budget.used(), H2_INPUT);
}

#[test]
fn split_echo_releases_the_charged_body() {
    // The budget already holds the body from earlier frames, and an echo
    // moves those bytes into the response, so they count once.
    for parts in [1, 2, 4] {
        let router = Router::new().post("/", |_, request| http::Response::new(request.into_body()));
        let budget = fictionet::stdlib::services::serve::Budget::new(H2_INPUT + 8000);
        let mut harness = Harness::with_options(
            Seed::from_u64(1),
            Http2::new(router),
            (),
            fictionet::stdlib::services::serve::ServeOptions::default().budget(budget.clone()),
        );
        let mut input = preface();
        input.extend(headers(1, "/", false));
        harness.push(&input).unwrap();
        let mut output = Vec::new();
        for n in 0..parts {
            output.extend(
                harness
                    .push(&data(1, 5000 / parts, n + 1 == parts))
                    .unwrap(),
            );
        }
        let output = frames(&output);
        assert_eq!(statuses(&output), [(1, b"200".to_vec())]);
        assert_eq!(
            output
                .iter()
                .filter_map(|f| match f {
                    Frame::Data(d) => Some(d.data.len()),
                    _ => None,
                })
                .sum::<usize>(),
            5000
        );
        assert!(!harness.closed());
        assert_eq!(budget.used(), H2_INPUT);
    }
}

#[test]
fn oversized_response_refuses_only_its_stream() {
    let router = Router::new()
        .post("/small", |_, _| {
            http::Response::new(Bytes::from_static(b"ok"))
        })
        .post("/large", |_, _| {
            http::Response::new(Bytes::from(vec![b'x'; 200_000]))
        });
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Http2::new(router),
        (),
        fictionet::stdlib::services::serve::ServeOptions::default()
            .budget(fictionet::stdlib::services::serve::Budget::new(128 << 10)),
    );
    let mut input = preface();
    input.extend(headers(1, "/small", true));
    input.extend(headers(3, "/large", true));
    let output = frames(&harness.push(&input).unwrap());
    assert_eq!(
        statuses(&output),
        [(1, b"200".to_vec()), (3, b"503".to_vec())]
    );
    for id in [1, 3] {
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Data(d) if d.stream == id && d.flags & 1 != 0))
        );
    }
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.stream == 1 && d.data == b"ok"))
    );
    assert!(!harness.closed());
    assert_eq!(
        statuses(&frames(&harness.push(&headers(5, "/small", true)).unwrap())),
        [(5, b"200".to_vec())]
    );
}

#[test]
fn early_response_ends_with_a_successful_reset() {
    let limits = httpd::Limits {
        body: 10,
        ..Default::default()
    };
    let mut harness = Harness::new(
        Seed::from_u64(1),
        Http2::with(Arc::new(Router::new()), limits),
        (),
    );
    let mut input = preface();
    input.extend(headers(1, "/", false));
    input.extend(data(1, 11, false));
    let output = frames(&harness.push(&input).unwrap());
    assert_eq!(statuses(&output), [(1, b"413".to_vec())]);
    let end = output
        .iter()
        .position(|f| matches!(f, Frame::Data(d) if d.stream == 1 && d.flags & 1 != 0))
        .unwrap();
    let reset = output
        .iter()
        .position(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 0))
        .unwrap();
    assert!(end < reset);
    assert!(!harness.closed());
}

#[test]
fn connection_receive_window_rejects_a_data_burst() {
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    let mut input = preface();
    input.extend(headers(1, "/", false));
    for _ in 0..8 {
        input.extend(data(1, 16_384, false));
    }
    let output = frames(&harness.push(&input).unwrap());
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 3))
    );
    assert!(harness.closed());
}

#[test]
fn stream_receive_window_rejects_only_the_overflowing_stream() {
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    let mut input = preface();
    for id in [1, 3] {
        input.extend(headers(id, "/", false));
        input.extend(data(id, 10_000, false));
        input.extend(data(id, 10_000, false));
    }
    let output = frames(&harness.push(&input).unwrap());
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 0 && w.increment == 40_000))
    );
    assert!(
        !output
            .iter()
            .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream != 0))
    );
    let mut input = Vec::new();
    for size in [16_384, 16_384, 12_768] {
        input.extend(data(1, size, false));
    }
    let output = frames(&harness.push(&input).unwrap());
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 3))
    );
    assert!(!harness.closed());
    let output = frames(&harness.push(&data(3, 0, true)).unwrap());
    assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
}

#[test]
fn tiny_data_frames_release_capacity_in_batches() {
    let limits = httpd::Limits {
        body: 2 << 20,
        ..Default::default()
    };
    let router = Router::new().post("/", |_, r| {
        assert_eq!(r.body().len(), 1 << 20);
        http::Response::new(Bytes::new())
    });
    let mut harness = Harness::new(Seed::from_u64(1), Http2::with(Arc::new(router), limits), ());
    let mut input = preface();
    input.extend(headers(1, "/", false));
    harness.push(&input).unwrap();
    let batch = data(1, 1, false).repeat(32_768);
    for _ in 0..32 {
        let bytes = harness.push(&batch).unwrap();
        assert_eq!(bytes.len(), 26);
        let output = frames(&bytes);
        assert_eq!(output.len(), 2);
        for (frame, id) in output.iter().zip([0, 1]) {
            assert!(
                matches!(frame, Frame::WindowUpdate(w) if w.stream == id && w.increment == 32_768)
            );
        }
    }
    assert_eq!(
        statuses(&frames(&harness.push(&data(1, 0, true)).unwrap())),
        [(1, b"200".to_vec())]
    );
    assert!(!harness.closed());
}

#[test]
fn trailers_after_end_stream_reset_only_that_stream() {
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
    let mut input = preface();
    input.extend(headers(1, "/", true));
    input.extend(headers(1, "/", true));
    input.extend(headers(3, "/", true));
    let output = frames(&harness.push(&input).unwrap());
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 5))
    );
    assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
    assert!(!harness.closed());
}

#[test]
fn headers_on_a_closed_stream_end_the_connection() {
    // HEADERS on a stream that has ended, and on a stream below one already
    // opened (RFC 9113 sections 5.1 and 5.1.1).
    for (open, again) in [(1, 1), (5, 3)] {
        let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
        harness.push(&preface()).unwrap();
        let output = frames(&harness.push(&headers(open, "/", true)).unwrap());
        assert_eq!(statuses(&output), [(open, b"404".to_vec())]);
        let output = frames(&harness.push(&headers(again, "/", true)).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == open && g.code == 1))
        );
        assert!(!output.iter().any(|f| matches!(f, Frame::Reset(_))));
        assert!(harness.closed());
    }
}

#[test]
fn invalid_priority_is_a_stream_error() {
    for (open, invalid, code) in [
        // PRIORITY with a 4-byte payload on an open stream: FRAME_SIZE_ERROR.
        (true, vec![0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0], 6),
        // PRIORITY on open stream 1 that depends on stream 1: PROTOCOL_ERROR.
        (true, vec![0, 0, 5, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0], 1),
        // GET / as HEADERS on stream 1 that depends on stream 1: PROTOCOL_ERROR.
        (
            false,
            vec![
                0, 0, 8, 1, 0x25, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0x83, 0x86, 0x84,
            ],
            1,
        ),
    ] {
        let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
        let mut input = preface();
        if open {
            input.extend(headers(1, "/", false));
        }
        input.extend(invalid);
        input.extend(headers(3, "/", true));
        let output = frames(&harness.push(&input).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == code))
        );
        assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
        assert!(!harness.closed());
    }
}

#[test]
fn invalid_priority_on_an_idle_stream_is_a_connection_error() {
    // RST_STREAM may not name an idle stream (RFC 9113 section 6.4), so
    // these stream errors end the connection, as section 5.4.1 allows,
    // rather than go unanswered.
    for (invalid, code) in [
        // PRIORITY with a 4-byte payload: FRAME_SIZE_ERROR.
        ([0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0].as_slice(), 6),
        // PRIORITY on stream 1 that depends on stream 1: PROTOCOL_ERROR.
        (&[0, 0, 5, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0], 1),
    ] {
        let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Router::new()), ());
        let mut input = preface();
        input.extend(invalid);
        input.extend(headers(1, "/", true));
        let output = frames(&harness.push(&input).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == 0 && g.code == code))
        );
        assert!(!output.iter().any(|f| matches!(f, Frame::Reset(_))));
        assert!(harness.closed());
    }
}

#[test]
fn cookie_crumbs_reach_the_handler_as_one_header() {
    let router = Router::new().get("/", |_, request| {
        let cookies: Vec<&[u8]> = request
            .headers()
            .get_all("cookie")
            .iter()
            .map(|v| v.as_bytes())
            .collect();
        http::Response::new(Bytes::from(cookies.join(b"\n".as_slice())))
    });
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(router), ());
    let mut fragment = Vec::new();
    for (name, value) in [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", "/"),
        ("cookie", "a=1"),
        ("accept", "*/*"),
        ("cookie", "b=2"),
    ] {
        hpack::Field::new(name, value).write(&mut fragment).unwrap();
    }
    let mut input = preface();
    http2::Headers {
        stream: 1,
        flags: 5,
        fragment,
        priority: None,
        padding: None,
    }
    .write(&mut input)
    .unwrap();
    let output = frames(&harness.push(&input).unwrap());
    assert_eq!(statuses(&output), [(1, b"200".to_vec())]);
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.data == b"a=1; b=2"))
    );
}

#[test]
fn failing_response_body_is_an_internal_stream_error() {
    struct Broken;
    impl http_body::Body for Broken {
        type Data = Bytes;
        type Error = fictionet::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            std::task::Poll::Ready(Some(Err(fictionet::Error::msg("body failed"))))
        }
    }
    struct Handler;
    impl httpd::Handler for Handler {
        fn call(&self, _: http::Request<httpd::Body>, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
            httpd::Reply::Now(http::Response::new(httpd::Body::new(Broken)))
        }
    }
    let mut harness = Harness::new(Seed::from_u64(1), Http2::new(Handler), ());
    harness.push(&preface()).unwrap();
    // The failures are the server's, so they never use up the client's
    // allowance of error resets.
    for n in 0..1100 {
        let output = frames(&harness.push(&headers(2 * n + 1, "/", true)).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 2 * n + 1 && r.code == 2))
        );
        assert!(!harness.closed());
    }
}

#[test]
fn repeated_header_refusals_exhaust_the_local_reset_limit() {
    let limits = httpd::Limits {
        head: fictionet::stdlib::protocols::http1::Limits {
            head: 256,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut harness = Harness::new(
        Seed::from_u64(1),
        Http2::with(Arc::new(Router::new()), limits),
        (),
    );
    harness.push(&preface()).unwrap();
    for n in 0..1025 {
        let Frame::Headers(mut h) = Frame::parse(&headers(2 * n + 1, "/", true)).unwrap() else {
            unreachable!()
        };
        h.fragment.extend_from_slice(&[0xaf; 10]);
        let output = frames(&harness.push(&h.to_bytes().unwrap()).unwrap());
        assert_eq!(statuses(&output), [(2 * n + 1, b"431".to_vec())]);
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 7))
        );
        assert_eq!(harness.closed(), n == 1024);
        if n == 1024 {
            assert!(
                output
                    .iter()
                    .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
            );
        }
    }
}

#[test]
fn concurrency_refusals_do_not_exhaust_the_local_reset_limit() {
    let limits = httpd::Limits {
        streams: 1,
        ..Default::default()
    };
    let mut harness = Harness::new(
        Seed::from_u64(1),
        Http2::with(Arc::new(Router::new()), limits),
        (),
    );
    let mut input = preface();
    input.extend(headers(1, "/", false));
    harness.push(&input).unwrap();
    for n in 1..1100 {
        let output = frames(&harness.push(&headers(2 * n + 1, "/", true)).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 2 * n + 1 && r.code == 7))
        );
        assert!(!harness.closed());
    }
}

#[test]
fn streamed_chunk_over_budget_resets_only_its_stream() {
    struct Streamed;
    impl httpd::Handler for Streamed {
        fn call(
            &self,
            request: http::Request<httpd::Body>,
            _: &mut httpd::Exchange<'_>,
        ) -> httpd::Reply {
            let body = if request.uri().path() == "/large" {
                httpd::Body::new(http_body_util::Full::new(Bytes::from(vec![b'x'; 200_000])))
            } else {
                httpd::Body::from("ok")
            };
            httpd::Reply::Now(http::Response::new(body))
        }
    }
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Http2::new(Streamed),
        (),
        fictionet::stdlib::services::serve::ServeOptions::default()
            .budget(fictionet::stdlib::services::serve::Budget::new(128 << 10)),
    );
    let mut input = preface();
    input.extend(headers(1, "/small", true));
    input.extend(headers(3, "/large", true));
    let output = frames(&harness.push(&input).unwrap());
    assert_eq!(
        statuses(&output),
        [(1, b"200".to_vec()), (3, b"200".to_vec())]
    );
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.stream == 1 && d.data == b"ok"))
    );
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 3 && r.code == 2))
    );
    assert!(!harness.closed());
    assert_eq!(
        statuses(&frames(&harness.push(&headers(5, "/small", true)).unwrap())),
        [(5, b"200".to_vec())]
    );
}

#[test]
fn connection_budget_exhaustion_sends_goaway() {
    let budget = fictionet::stdlib::services::serve::Budget::new(H2_INPUT + 1000);
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Http2::new(Router::new()),
        (),
        fictionet::stdlib::services::serve::ServeOptions::default().budget(budget.clone()),
    );
    harness.push(&preface()).unwrap();
    let _other = budget.charge(budget.limit() - budget.used()).unwrap();
    let output = frames(
        &harness
            .push(
                &http2::Ping {
                    flags: 0,
                    opaque: [0; 8],
                }
                .to_bytes()
                .unwrap(),
            )
            .unwrap(),
    );
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
    );
    assert!(harness.closed());
}

#[test]
fn repeated_budget_refusals_exhaust_the_local_reset_limit() {
    let budget = fictionet::stdlib::services::serve::Budget::new(H2_INPUT + 1024);
    let mut harness = Harness::with_options(
        Seed::from_u64(1),
        Http2::new(Router::new()),
        (),
        fictionet::stdlib::services::serve::ServeOptions::default().budget(budget),
    );
    harness.push(&preface()).unwrap();
    for n in 0..1025 {
        let Frame::Headers(mut h) = Frame::parse(&headers(2 * n + 1, "/", true)).unwrap() else {
            unreachable!()
        };
        hpack::Field::new("x-large", "x".repeat(4096))
            .write(&mut h.fragment)
            .unwrap();
        let output = frames(&harness.push(&h.to_bytes().unwrap()).unwrap());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 7))
        );
        assert_eq!(harness.closed(), n == 1024);
        if n == 1024 {
            assert!(
                output
                    .iter()
                    .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
            );
        }
    }
}

#[test]
fn deferred_response_budget_refusal_preserves_other_streams() {
    fictionet::block_on(fictionet::lab(Seed::from_u64(1), |cx| async move {
        let router = Router::new()
            .post("/small", |_, _| {
                http::Response::new(Bytes::from_static(b"ok"))
            })
            .route_async(Some(http::Method::POST), "/large", |_, _| async {
                http::Response::new(Bytes::from(vec![b'x'; 200_000]))
            });
        let mut harness = Harness::with_options(
            Seed::from_u64(1),
            Http2::new(router),
            (),
            fictionet::stdlib::services::serve::ServeOptions::default()
                .budget(fictionet::stdlib::services::serve::Budget::new(128 << 10)),
        )
        .with_fcx(cx.clone());
        let mut input = preface();
        input.extend(headers(1, "/small", true));
        input.extend(headers(3, "/large", true));
        let output = frames(&harness.push(&input).unwrap());
        assert_eq!(
            statuses(&output),
            [(1, b"200".to_vec()), (3, b"503".to_vec())]
        );
        assert!(!harness.closed());
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}
