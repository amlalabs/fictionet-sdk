use fictionet_test_support::sandbox;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::{Budget, Harness};
use fictionet::stdlib::protocols::http2::{self, Frame};
use fictionet::stdlib::services::stack::Polling;
use fictionet::stdlib::web::httpd::{self, Http2Server, Responder};
use fictionet::stdlib::{
    network::{Connection, ConnectionExt, filter},
    protocols::hpack,
    services::tls,
    world::net,
};
use fictionet::{Cx, Seed};
use fictionet_test_support::sandbox::TlsClient;

const SITE: Ipv4Addr = Ipv4Addr::new(104, 18, 0, 1);
const DATE: u64 = 1_893_456_000;

/// An HTTP/2 server in a harness, its work done as it runs.
type H2 = Harness<Http2Server>;

fn server(responder: Responder) -> H2 {
    Harness::new(Seed::from_u64(1), responder.http2()).with_worker(Polling::new())
}

fn budgeted(responder: Responder, budget: Budget) -> H2 {
    Harness::with_budget(Seed::from_u64(1), responder.http2(), budget).with_worker(Polling::new())
}

fn with(handler: Arc<dyn httpd::Handler>, limits: httpd::Limits) -> Responder {
    Responder::shared(handler).limits(limits)
}

/// The client sends `bytes`; what the server wrote back.
fn push(harness: &mut H2, bytes: &[u8]) -> Vec<u8> {
    harness.push(bytes).unwrap();
    harness.take_output()
}

/// What an idle HTTP/2 connection holds once it has read the preface: its
/// frame buffer, its HPACK table at the bound it advertises, its list of
/// recent resets, and its fixed routing state.
pub(crate) fn h2_input() -> usize {
    let budget = Budget::unlimited();
    let mut harness = budgeted(
        Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::new(Bytes::new())
        })),
        budget.clone(),
    );
    push(&mut harness, &preface());
    budget.used()
}

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
fn completion_counts_data_frames_and_distinguishes_cancelled_streams() {
    for length in [0, 7, 20_000] {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collect = seen.clone();
        let handler = fictionet_test_support::handler(
            move |_: &mut httpd::Exchange<'_>, _: http::Request<Bytes>| {
                http::Response::new(Bytes::from(vec![b'x'; length]))
            },
        );
        let mut harness = server(
            Responder::new(handler).observe(Arc::new(move |observation| {
                collect.lock().unwrap().push(observation)
            })),
        );
        let mut input = preface();
        input.extend(headers(1, "/", true));
        let output = frames(&push(&mut harness, &input));
        let delivered: usize = output
            .iter()
            .filter_map(|frame| match frame {
                Frame::Data(data) => Some(data.data.len()),
                _ => None,
            })
            .sum();
        let seen = seen.lock().unwrap();
        let [observation] = seen.as_slice() else {
            panic!("one completion per stream");
        };
        assert!(observation.complete);
        assert_eq!(observation.sent as usize, delivered);
        assert_eq!(delivered, length);
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let collect = seen.clone();
    let handler =
        fictionet_test_support::handler(|_: &mut httpd::Exchange<'_>, _: http::Request<Bytes>| {
            http::Response::new(Bytes::from(vec![b'x'; 100_000]))
        });
    let mut harness = server(
        Responder::new(handler).observe(Arc::new(move |observation| {
            collect.lock().unwrap().push(observation)
        })),
    );
    let mut input = preface();
    input.extend(headers(1, "/", true));
    let output = frames(&push(&mut harness, &input));
    let delivered: usize = output
        .iter()
        .filter_map(|frame| match frame {
            Frame::Data(data) => Some(data.data.len()),
            _ => None,
        })
        .sum();
    assert!(seen.lock().unwrap().is_empty());
    drop(harness);
    let seen = seen.lock().unwrap();
    let [observation] = seen.as_slice() else {
        panic!("one cancellation per stream");
    };
    assert!(!observation.complete);
    assert_eq!(observation.sent as usize, delivered);
}

#[test]
fn response_length_follows_the_body_and_shared_policy() {
    use fictionet_extras::hyper_io::Io;
    use hyper_util::rt::TokioIo;

    fictionet::block_on(fictionet::lab(Seed::from_u64(71), |cx| async move {
        let payload = Bytes::from(vec![b'x'; 20_000]);
        let body = payload.clone();
        let handler = fictionet_test_support::handler(
            move |_: &mut httpd::Exchange<'_>, request: http::Request<Bytes>| {
                http::Response::builder()
                    .status(if request.uri().path() == "/empty" {
                        http::StatusCode::NO_CONTENT
                    } else {
                        http::StatusCode::OK
                    })
                    .header(
                        "content-length",
                        if request.method() == http::Method::HEAD {
                            "invalid".to_owned()
                        } else {
                            (body.len() / 2).to_string()
                        },
                    )
                    .body(body.clone())
                    .unwrap()
            },
        );
        let (attach, arrivals) = fictionet::attachments();
        net::Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("site", |host| {
                host.at(SITE)
                    .dns_name("localhost")
                    .port_server(80, httpd::Server::new(handler))
            })
            .start(&cx, arrivals)?;
        let machine = sandbox::machine(&cx, attach.attach("client")?, Ipv4Addr::new(10, 0, 0, 2));
        let conn = machine
            .tcp
            .connect(&cx, SocketAddr::new(SITE.into(), 80))
            .await?;
        let (mut sender, connection) = h2::client::handshake(TokioIo::new(Io {
            fcx: cx.clone(),
            conn,
        }))
        .await?;
        cx.spawn(move |_| async move {
            connection.await?;
            Ok(())
        });
        for (method, path) in [
            (http::Method::GET, "/"),
            (http::Method::HEAD, "/"),
            (http::Method::GET, "/empty"),
        ] {
            sender = sender.ready().await?;
            let (reply, _) = sender.send_request(
                http::Request::builder()
                    .method(method.clone())
                    .uri(format!("http://localhost{path}"))
                    .body(())?,
                true,
            )?;
            let response = reply.await?;
            if response.status() == http::StatusCode::NO_CONTENT {
                assert!(!response.headers().contains_key("content-length"));
            } else {
                let length: usize = response.headers()["content-length"].to_str()?.parse()?;
                assert_eq!(length, payload.len());
            }
            let mut body = response.into_body();
            let mut received = Vec::new();
            while let Some(chunk) = body.data().await {
                received.extend_from_slice(&chunk?);
            }
            if method == http::Method::HEAD || path == "/empty" {
                assert!(received.is_empty());
            } else {
                assert_eq!(received.len(), payload.len());
            }
        }
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// A 2xx to CONNECT carries no `content-length` and ends the stream on its
/// HEADERS frame: RFC 9110 section 9.3.6 forbids length fields there, and
/// the server tunnels nothing, as native HTTP/1 does.
#[test]
fn connect_success_has_no_length_and_ends_the_stream() {
    let handler = fictionet_test_support::handler(
        |_: &mut httpd::Exchange<'_>, request: http::Request<Bytes>| {
            assert_eq!(request.method(), http::Method::CONNECT);
            http::Response::new(Bytes::from_static(b"tunnel"))
        },
    );
    let mut harness = server(Responder::new(handler));
    let mut input = preface();
    let mut fragment = Vec::new();
    for (name, value) in [(":method", "CONNECT"), (":authority", "a.test:443")] {
        hpack::Field::new(name, value).write(&mut fragment).unwrap();
    }
    http2::Headers {
        stream: 1,
        flags: 5,
        fragment,
        priority: None,
        padding: None,
    }
    .write(&mut input)
    .unwrap();
    let output = frames(&push(&mut harness, &input));
    let mut blocks = http2::HeaderBlocks::with_limits(Default::default());
    let mut answered = false;
    for frame in &output {
        assert!(!matches!(frame, Frame::Data(_)), "{output:?}");
        let read = blocks.read_frame(frame).unwrap();
        let Some(block) = read.block else {
            continue;
        };
        assert_eq!(read.stream, 1);
        assert!(read.end, "{output:?}");
        let fields: Vec<(&[u8], &[u8])> = block
            .headers
            .iter()
            .map(|h| (h.name.as_slice(), h.value.as_slice()))
            .collect();
        assert!(fields.contains(&(b":status", b"200")), "{fields:?}");
        assert!(
            !fields.iter().any(|(name, _)| *name == b"content-length"),
            "{fields:?}"
        );
        answered = true;
    }
    assert!(answered, "{output:?}");
}

/// RFC 9110 sections 8.6, 9.3.2 and 9.3.6 and RFC 9113 section 8.1, for
/// every method, response status, supplied `content-length` and body the
/// shared policy tells apart. The checks are the theorems of
/// verification/http/lean/Http/Framing.lean.
#[test]
fn http2_framing_follows_the_rfcs_for_every_case() {
    let mut lengths = std::collections::HashMap::new();
    for status in [103u16, 200, 204, 304, 404] {
        for supplied in [None, Some("7"), Some("x")] {
            for known in [true, false] {
                for method in ["GET", "HEAD", "CONNECT"] {
                    let mut harness = server(Responder::new(crate::httpd::framing_case(
                        status, supplied, known,
                    )));
                    let mut input = preface();
                    let mut fragment = Vec::new();
                    let request: &[(&str, &str)] = if method == "CONNECT" {
                        &[(":method", "CONNECT"), (":authority", "a.test:443")]
                    } else {
                        &[
                            (":method", method),
                            (":scheme", "https"),
                            (":authority", "a.test"),
                            (":path", "/"),
                        ]
                    };
                    for (name, value) in request {
                        hpack::Field::new(name, value).write(&mut fragment).unwrap();
                    }
                    http2::Headers {
                        stream: 1,
                        flags: 5,
                        fragment,
                        priority: None,
                        padding: None,
                    }
                    .write(&mut input)
                    .unwrap();
                    let output = frames(&push(&mut harness, &input));
                    let case = format!(
                        "{method} answered {status} with content-length {supplied:?} and a \
                         body of {} length: {output:?}",
                        if known { "known" } else { "unknown" }
                    );
                    let mut blocks = http2::HeaderBlocks::with_limits(Default::default());
                    let mut head: Option<(Vec<hpack::Field>, bool)> = None;
                    let mut data = Vec::new();
                    let mut ended_by_data = false;
                    for frame in &output {
                        if let Frame::Data(frame) = frame {
                            if frame.stream != 1 {
                                continue;
                            }
                            // RFC 9113 section 8.1: DATA comes after HEADERS and
                            // nothing follows END_STREAM.
                            let (_, ended) = head.as_ref().expect(&case);
                            assert!(!ended && !ended_by_data, "{case}");
                            data.extend_from_slice(&frame.data);
                            ended_by_data = frame.flags & 1 != 0;
                            continue;
                        }
                        let read = blocks.read_frame(frame).unwrap();
                        if let Some(block) = read.block {
                            assert_eq!(read.stream, 1, "{case}");
                            assert!(head.is_none(), "{case}");
                            head = Some((block.headers, read.end));
                        }
                    }
                    let (fields, end_on_headers) = head.expect(&case);
                    let field = |name: &[u8]| {
                        fields
                            .iter()
                            .find(|f| f.name == name)
                            .map(|f| String::from_utf8(f.value.clone()).unwrap())
                    };
                    assert_eq!(field(b":status"), Some(status.to_string()), "{case}");
                    let length = field(b"content-length");
                    let informational = status < 200;
                    let tunnel = method == "CONNECT" && (200..300).contains(&status);
                    let bodiless =
                        crate::httpd::bodiless_status(status) || tunnel || method == "HEAD";
                    // RFC 9113 section 8.1: every response ends its stream.
                    assert!(end_on_headers || ended_by_data, "{case}");
                    // RFC 9110 section 8.6: no content-length on 1xx or 204.
                    assert!(
                        !(informational || status == 204) || length.is_none(),
                        "{case}"
                    );
                    // RFC 9110 section 9.3.6: a 2xx to CONNECT has no length.
                    assert!(!tunnel || length.is_none(), "{case}");
                    // A response without a body ends the stream on its HEADERS
                    // and sends no DATA; one with a body sends the body.
                    assert_eq!(end_on_headers, bodiless, "{case}");
                    let expected: &[u8] = if bodiless { b"" } else { b"body" };
                    assert_eq!(data, expected, "{case}");
                    // RFC 9113 section 8.1.1: a content-length matches its DATA.
                    if let Some(n) = &length
                        && !bodiless
                    {
                        assert_eq!(n.parse::<usize>().unwrap(), data.len(), "{case}");
                    }
                    // RFC 9110 section 15.4.5: a 304 keeps the length the handler
                    // supplied for the representation.
                    if status == 304 && supplied == Some("7") {
                        assert_eq!(length.as_deref(), Some("7"), "{case}");
                    }
                    // A handler that drops the HEAD body names the GET length
                    // itself, and the server passes it on.
                    if method == "HEAD"
                        && supplied == Some("7")
                        && !crate::httpd::bodiless_status(status)
                    {
                        assert_eq!(length.as_deref(), Some("7"), "{case}");
                    }
                    lengths.insert((status, supplied, known, method), length);
                }
            }
        }
    }
    // RFC 9110 section 9.3.2: HEAD's content-length is GET's when the
    // handler leaves the length to the server.
    for (&(status, supplied, known, method), length) in &lengths {
        if method == "HEAD" && supplied != Some("7") {
            let get = &lengths[&(status, supplied, known, "GET")];
            assert_eq!(
                length, get,
                "HEAD and GET answered {status} with content-length {supplied:?}"
            );
        }
    }
}

#[test]
fn windows_settings_and_concurrent_streams() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from(vec![b'x'; 100_000]))
        },
    );
    let mut harness = server(Responder::new(router));
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
    let output = frames(&push(&mut harness, &input));
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
        !frames(&push(&mut harness, &input))
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
    let output = frames(&push(&mut harness, &input));
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
    assert_eq!(harness.layer().lower().streams(), 3);
}

#[test]
fn resets_and_continuations_are_bounded() {
    let router = fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    });
    let mut harness = server(Responder::new(router));
    push(&mut harness, &preface());
    let first = http2::Headers {
        stream: 1,
        flags: 1,
        fragment: Vec::new(),
        priority: None,
        padding: None,
    }
    .to_bytes()
    .unwrap();
    push(&mut harness, &first);
    let continuation = http2::Continuation {
        stream: 1,
        flags: 0,
        fragment: Vec::new(),
    }
    .to_bytes()
    .unwrap();
    for _ in 0..5 {
        assert!(push(&mut harness, &continuation).is_empty());
    }
    let output = frames(&push(&mut harness, &continuation));
    assert!(output.iter().any(
        |f| matches!(f, Frame::GoAway(g) if g.code == http2::ErrorCode::EnhanceYourCalm as u32)
    ));
    assert!(harness.ended());
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
        let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })));
        push(&mut harness, &preface());
        assert!(
            frames(&push(&mut harness, &invalid))
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.code == 1))
        );
        assert!(harness.ended());
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    packets: Vec<(bool, Vec<u8>)>,
}

fn replay() -> Trace {
    let trace: Arc<Mutex<Trace>> = Arc::default();
    let packets = trace.clone();
    fictionet::block_on(fictionet::lab(Seed::from_u64(71), move |cx| async move {
        let cert = rustls::pki_types::CertificateDer::from(include_bytes!("fixtures/tls/ed25519.cert.der").to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(include_bytes!("fixtures/tls/ed25519.key.der").to_vec()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.clone())?;
        let date = UNIX_EPOCH + Duration::from_secs(DATE);
        let config = Arc::new(tls::config_builder(&cx, date).with_safe_default_protocol_versions()?.with_no_client_auth().with_single_cert(vec![cert], key)?);
        let router = fictionet_test_support::handler(|ex: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| http::Response::new(Bytes::from(ex.random_u64().to_be_bytes().to_vec())));
        let (attach, arrivals) = fictionet::attachments();
        net::Net::new(fictionet_extras::network::cdn_pools()).ipv4_only().host("site", |host| host.at(SITE).dns_name("localhost").tls_accept(443, "localhost", move |_| config.clone(), httpd::Server::new(router).https())).start(&cx, arrivals)?;
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
        cx.cancel();
        Ok(())
    })).unwrap();
    std::mem::take(&mut *trace.lock().unwrap())
}

#[test]
fn reset_late_frames_replay_on_lab_time_over_tls() {
    let first = replay();
    let second = replay();
    assert!(!first.packets.is_empty());
    assert_eq!(first, second);
}

mod clients {
    use super::*;
    use fictionet::InterfaceExt;
    use fictionet_extras::hyper_io::Io;
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

    struct Site {
        handler: Arc<dyn httpd::Handler>,
        facts: Arc<Mutex<Vec<RequestFact>>>,
        cancelled: Arc<tokio::sync::Notify>,
    }
    struct RequestFact {
        path: http::uri::PathAndQuery,
        version: http::Version,
        connection: Option<u64>,
        started: fictionet::time::Instant,
        ended: fictionet::time::Instant,
        sent: usize,
        complete: bool,
    }
    struct RecordedBody {
        inner: httpd::Body,
        cx: Cx,
        fact: Option<RequestFact>,
        facts: Arc<Mutex<Vec<RequestFact>>>,
        cancelled: Arc<tokio::sync::Notify>,
    }
    impl RecordedBody {
        fn finish(&mut self, complete: bool) {
            if let Some(mut fact) = self.fact.take() {
                fact.ended = self.cx.now();
                fact.complete = complete;
                if fact.path.path() == "/cancel" {
                    self.cancelled.notify_one();
                }
                self.facts.lock().unwrap().push(fact);
            }
        }
    }
    impl http_body::Body for RecordedBody {
        type Data = Bytes;
        type Error = fictionet::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            task: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            let result = Pin::new(&mut self.inner).poll_frame(task);
            match &result {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(bytes) = frame.data_ref()
                        && let Some(fact) = &mut self.fact
                    {
                        fact.sent += bytes.len();
                    }
                }
                Poll::Ready(Some(Err(_))) => self.finish(false),
                Poll::Ready(None) => self.finish(true),
                _ => {}
            }
            result
        }
        fn size_hint(&self) -> http_body::SizeHint {
            self.inner.size_hint()
        }
        fn is_end_stream(&self) -> bool {
            self.inner.is_end_stream()
        }
    }
    impl Drop for RecordedBody {
        fn drop(&mut self) {
            self.finish(http_body::Body::is_end_stream(&self.inner));
        }
    }
    impl httpd::Handler for Site {
        fn call(
            &self,
            request: http::Request<httpd::Body>,
            ex: &mut httpd::Exchange<'_>,
        ) -> httpd::Reply {
            let fact = RequestFact {
                path: request.uri().path_and_query().cloned().unwrap(),
                version: request.version(),
                connection: ex.conn().id,
                started: ex.now(),
                ended: ex.now(),
                sent: 0,
                complete: false,
            };
            let reply = if request.uri().path() == "/cancel" {
                httpd::Reply::Now(
                    http::Response::builder()
                        .header("content-type", "application/octet-stream")
                        .header("x-content-type-options", "nosniff")
                        .body(httpd::Body::new(Interrupted(true)))
                        .unwrap(),
                )
            } else {
                self.handler.call(request, ex)
            };
            let facts = self.facts.clone();
            let cancelled = self.cancelled.clone();
            httpd::Reply::Later(Box::new(move |cx| {
                Box::pin(async move {
                    let response = match reply {
                        httpd::Reply::Now(response) => response,
                        httpd::Reply::Later(work) => work(cx.clone()).await?,
                    };
                    Ok(response.map(|inner| {
                        httpd::Body::new(RecordedBody {
                            inner,
                            cx,
                            fact: Some(fact),
                            facts,
                            cancelled,
                        })
                    }))
                })
            }))
        }
    }

    struct World {
        address: SocketAddr,
        dir: PathBuf,
        stop: Option<fictionet::End>,
        thread: Option<std::thread::JoinHandle<()>>,
        facts: Arc<Mutex<Vec<RequestFact>>>,
    }

    impl World {
        fn start() -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let dir = fictionet_test_support::temp::dir();
            let ca_path = dir.join("ca.pem");
            let (stop, mut stopped) = fictionet::pair();
            let facts: Arc<Mutex<Vec<RequestFact>>> = Arc::default();
            let observed = facts.clone();
            let cancelled = Arc::new(tokio::sync::Notify::new());
            let gate = cancelled.clone();
            let (ready, started) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(fictionet::run(Seed::from_u64(20), move |cx| async move {
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
                    let downloads = Arc::new(tokio::sync::Barrier::new(4));
                    let large = || {
                        let body = format!("/*{}*/completed++;", "x".repeat(1 << 20));
                        http::Response::builder().header("content-type", "application/javascript").body(Bytes::from(body)).unwrap()
                    };
                    let router = {
let route_0 = std::sync::Arc::new(move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| http::Response::builder().header("content-type", "text/html").body(Bytes::from_static(page.as_bytes())).unwrap());
let route_1 = std::sync::Arc::new(move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| large());
let route_2 = std::sync::Arc::new(move |_: fictionet::Cx, _: http::Request<bytes::Bytes>| {
                            let downloads = downloads.clone();
                            async move {
                                // Start all browser streams before sending any response.
                                downloads.wait().await;
                                large()
                            }
                        });
let route_3 = std::sync::Arc::new(move |_: fictionet::Cx, _: http::Request<bytes::Bytes>| {
                            let gate = gate.clone();
                            async move {
                                gate.notified().await;
                                http::Response::builder().header("content-type", "application/javascript").body(Bytes::new()).unwrap()
                            }
                        });
fictionet_test_support::reply_handler(move |ex, request| {
use fictionet::stdlib::web::httpd::{Body, Reply};
let (parts, body) = request.into_parts();
let Some(body) = body.bytes() else { return Reply::Now(http::Response::builder().status(400).body(Body::empty()).unwrap()); };
let request = http::Request::from_parts(parts, body);
if request.uri().path() == "/" && (request.method() == http::Method::GET || request.method() == http::Method::HEAD) { return Reply::Now(route_0(ex, request).map(Body::from)); }
if request.uri().path() == "/large/curl" && (request.method() == http::Method::GET || request.method() == http::Method::HEAD) { return Reply::Now(route_1(ex, request).map(Body::from)); }
if (request.uri().path() == "/large" || request.uri().path().starts_with("/large/")) && (request.method() == http::Method::GET || request.method() == http::Method::HEAD) { return { let route = route_2.clone(); Reply::Later(Box::new(move |cx| Box::pin(async move { Ok(route(cx, request).await.map(Body::from)) }))) }; }
if request.uri().path() == "/gate" && (request.method() == http::Method::GET || request.method() == http::Method::HEAD) { return { let route = route_3.clone(); Reply::Later(Box::new(move |cx| Box::pin(async move { Ok(route(cx, request).await.map(Body::from)) }))) }; }
if request.uri().path() == "/" || request.uri().path() == "/large/curl" || (request.uri().path() == "/large" || request.uri().path().starts_with("/large/")) || request.uri().path() == "/gate" { return Reply::Now(http::Response::builder().status(405).body(Body::empty()).unwrap()); }
Reply::Now(http::Response::builder().status(404).body(Body::empty()).unwrap())
})
};
                    let (attach, arrivals) = fictionet::attachments();
                    net::Net::new(fictionet_extras::network::cdn_pools()).ipv4_only().host("site", |host| host.at(SITE).dns_name("localhost").tls_accept(443, "localhost", move |_| config.clone(), httpd::Server::new(Site { handler: Arc::new(router), facts: observed, cancelled }).limits(httpd::Limits { body: 1024, ..Default::default() }).https())).start(&cx, arrivals)?;
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
                facts,
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
            let chromium = "chromium";
            let output = Command::new(chromium)
                .args([
                    "--headless",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--password-store=basic",
                    "--use-mock-keychain",
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
            let facts = world.facts.lock().unwrap();
            assert!(
                facts
                    .iter()
                    .all(|fact| fact.version == http::Version::HTTP_2)
            );
            let large: Vec<_> = facts
                .iter()
                .filter(|fact| {
                    fact.path.path().starts_with("/large/") && fact.path.path() != "/large/curl"
                })
                .collect();
            assert_eq!(large.len(), 4);
            assert!(large.iter().all(|fact| fact.sent > 1 << 20));
            assert!(
                large
                    .iter()
                    .all(|fact| fact.connection == large[0].connection)
            );
            let latest_start = large.iter().map(|fact| fact.started).max().unwrap();
            let first_completion = large.iter().map(|fact| fact.ended).min().unwrap();
            assert!(latest_start < first_completion);
            let cancelled = facts
                .iter()
                .find(|fact| fact.path.path() == "/cancel")
                .unwrap();
            assert!(!cancelled.complete);
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
    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    let reply = frames(&push(&mut harness, &burst));
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
    );
    assert!(harness.ended());

    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    push(&mut harness, &preface());
    for id in (1..=81).step_by(2) {
        push(&mut harness, &headers(id, "/", false));
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
    assert!(!harness.ended());
}

#[test]
fn local_protocol_resets_eventually_close_the_connection() {
    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    push(&mut harness, &preface());
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
        let reply = frames(&push(&mut harness, &malformed));
        assert!(
            reply
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 1))
        );
        assert_eq!(harness.ended(), n == 1024);
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
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from_static(b"ok"))
        },
    );
    let mut harness = server(Responder::shared(Arc::new(router)).limits(limits));
    push(&mut harness, &preface());
    push(&mut harness, &headers(1, "/", false));
    let invalid = [0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let reply = frames(&push(&mut harness, &invalid));
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 1))
    );
    assert!(!harness.ended());
    let Frame::Headers(mut oversized) = Frame::parse(&headers(3, "/", true)).unwrap() else {
        unreachable!()
    };
    oversized.fragment.extend_from_slice(&[0xaf; 10]);
    let reply = frames(&push(&mut harness, &oversized.to_bytes().unwrap()));
    let mut block = http2::HeaderBlocks::with_limits(Default::default());
    let mut status = None;
    for frame in &reply {
        if let Some(decoded) = block.read_frame(frame).unwrap().block {
            status = decoded
                .headers
                .into_iter()
                .find(|h| h.name == b":status")
                .map(|h| h.value);
        }
    }
    assert_eq!(status.as_deref(), Some(b"431".as_slice()));
    assert!(!harness.ended());
    let reply = frames(&push(&mut harness, &headers(5, "/", true)));
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.data == b"ok"))
    );
}

#[test]
fn graceful_goaway_drains_streams_after_the_ping_round_trip() {
    let mut service = Responder::new(fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from_static(b"ok"))
        },
    ))
    .http2();
    service.lower_mut().graceful_shutdown();
    let mut harness = Harness::new(Seed::from_u64(1), service).with_worker(Polling::new());
    let mut input = preface();
    input.extend(headers(1, "/", false));
    let initial = frames(&push(&mut harness, &input));
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
    let reply = frames(&push(
        &mut harness,
        &http2::Ping { flags: 1, opaque }.to_bytes().unwrap(),
    ));
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == 1 && g.code == 0))
    );
    assert!(!harness.ended());
    let reply = frames(&push(
        &mut harness,
        &http2::Data {
            stream: 1,
            flags: 1,
            data: Vec::new(),
            padding: None,
        }
        .to_bytes()
        .unwrap(),
    ));
    assert!(
        reply
            .iter()
            .any(|f| matches!(f, Frame::Data(d) if d.data == b"ok"))
    );
    assert!(harness.ended());
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
                    .find(|h| h.name == b":status")
                    .map(|h| h.value)
                    .map(|value| (read.stream, value))
            })
        })
        .collect()
}

#[test]
fn immediate_echo_releases_the_request_charge() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
         request: http::Request<bytes::Bytes>| http::Response::new(request.into_body()),
    );
    // A frame of the body is charged as it comes up and again as the request
    // copies it, so the room is twice the body's for that moment.
    let budget = fictionet::stdlib::layer::Budget::new(h2_input() + 2 * 8000);
    let mut harness = budgeted(Responder::new(router), budget.clone());
    let mut input = preface();
    input.extend(headers(1, "/", false));
    push(&mut harness, &input);
    let output = frames(&push(&mut harness, &data(1, 3000, true)));
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
    assert!(!harness.ended());
    assert_eq!(budget.used(), h2_input());
}

#[test]
fn split_echo_releases_the_charged_body() {
    // The budget already holds the body from earlier frames, and an echo
    // moves those bytes into the response, so they count once. A frame of
    // the body is charged as it comes up and again as the request copies it,
    // so the room is twice the body's for that moment.
    for parts in [1, 2, 4] {
        let router = fictionet_test_support::handler(
            |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
             request: http::Request<bytes::Bytes>| {
                http::Response::new(request.into_body())
            },
        );
        let budget = fictionet::stdlib::layer::Budget::new(h2_input() + 2 * 8000);
        let mut harness = budgeted(Responder::new(router), budget.clone());
        let mut input = preface();
        input.extend(headers(1, "/", false));
        push(&mut harness, &input);
        let mut output = Vec::new();
        for n in 0..parts {
            output.extend(push(&mut harness, &data(1, 5000 / parts, n + 1 == parts)));
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
        assert!(!harness.ended());
        assert_eq!(budget.used(), h2_input());
    }
}

#[test]
fn oversized_response_refuses_only_its_stream() {
    let router = {
        let route_0 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from_static(b"ok"))
        };
        let route_1 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from(vec![b'x'; 200_000]))
        };
        fictionet_test_support::handler(move |ex, request| {
            if request.uri().path() == "/small" && (request.method() == http::Method::POST) {
                return route_0(ex, request);
            }
            if request.uri().path() == "/large" && (request.method() == http::Method::POST) {
                return route_1(ex, request);
            }
            if request.uri().path() == "/small" || request.uri().path() == "/large" {
                return http::Response::builder()
                    .status(405)
                    .body(bytes::Bytes::new())
                    .unwrap();
            }
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })
    };
    let mut harness = budgeted(
        Responder::new(router),
        fictionet::stdlib::layer::Budget::new(128 << 10),
    );
    let mut input = preface();
    input.extend(headers(1, "/small", true));
    input.extend(headers(3, "/large", true));
    let output = frames(&push(&mut harness, &input));
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
    assert!(!harness.ended());
    assert_eq!(
        statuses(&frames(&push(&mut harness, &headers(5, "/small", true)))),
        [(5, b"200".to_vec())]
    );
}

#[test]
fn early_response_ends_with_a_successful_reset() {
    let limits = httpd::Limits {
        body: 10,
        ..Default::default()
    };
    let mut harness = server(with(
        Arc::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        limits,
    ));
    let mut input = preface();
    input.extend(headers(1, "/", false));
    input.extend(data(1, 11, false));
    let output = frames(&push(&mut harness, &input));
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
    assert!(!harness.ended());
}

#[test]
fn connection_receive_window_rejects_a_data_burst() {
    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    let mut input = preface();
    input.extend(headers(1, "/", false));
    for _ in 0..8 {
        input.extend(data(1, 16_384, false));
    }
    let output = frames(&push(&mut harness, &input));
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 3))
    );
    assert!(harness.ended());
}

#[test]
fn stream_receive_window_rejects_only_the_overflowing_stream() {
    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    let mut input = preface();
    for id in [1, 3] {
        input.extend(headers(id, "/", false));
        input.extend(data(id, 10_000, false));
        input.extend(data(id, 10_000, false));
    }
    let output = frames(&push(&mut harness, &input));
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
    let output = frames(&push(&mut harness, &input));
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 3))
    );
    assert!(!harness.ended());
    let output = frames(&push(&mut harness, &data(3, 0, true)));
    assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
}

#[test]
fn tiny_data_frames_release_capacity_in_batches() {
    let limits = httpd::Limits {
        body: 2 << 20,
        ..Default::default()
    };
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, r: http::Request<bytes::Bytes>| {
            assert_eq!(r.body().len(), 1 << 20);
            http::Response::new(Bytes::new())
        },
    );
    let mut harness = server(Responder::shared(Arc::new(router)).limits(limits));
    let mut input = preface();
    input.extend(headers(1, "/", false));
    push(&mut harness, &input);
    let batch = data(1, 1, false).repeat(32_768);
    for _ in 0..32 {
        let bytes = push(&mut harness, &batch);
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
        statuses(&frames(&push(&mut harness, &data(1, 0, true)))),
        [(1, b"200".to_vec())]
    );
    assert!(!harness.ended());
}

#[test]
fn trailers_after_end_stream_reset_only_that_stream() {
    let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
        http::Response::builder()
            .status(404)
            .body(bytes::Bytes::new())
            .unwrap()
    })));
    let mut input = preface();
    input.extend(headers(1, "/", true));
    input.extend(headers(1, "/", true));
    input.extend(headers(3, "/", true));
    let output = frames(&push(&mut harness, &input));
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == 5))
    );
    assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
    assert!(!harness.ended());
}

#[test]
fn headers_on_a_closed_stream_end_the_connection() {
    // HEADERS on a stream that has ended, and on a stream below one already
    // opened (RFC 9113 sections 5.1 and 5.1.1).
    for (open, again) in [(1, 1), (5, 3)] {
        let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })));
        push(&mut harness, &preface());
        let output = frames(&push(&mut harness, &headers(open, "/", true)));
        assert_eq!(statuses(&output), [(open, b"404".to_vec())]);
        let output = frames(&push(&mut harness, &headers(again, "/", true)));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == open && g.code == 1))
        );
        assert!(!output.iter().any(|f| matches!(f, Frame::Reset(_))));
        assert!(harness.ended());
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
        let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })));
        let mut input = preface();
        if open {
            input.extend(headers(1, "/", false));
        }
        input.extend(invalid);
        input.extend(headers(3, "/", true));
        let output = frames(&push(&mut harness, &input));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1 && r.code == code))
        );
        assert_eq!(statuses(&output), [(3, b"404".to_vec())]);
        assert!(!harness.ended());
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
        let mut harness = server(Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })));
        let mut input = preface();
        input.extend(invalid);
        input.extend(headers(1, "/", true));
        let output = frames(&push(&mut harness, &input));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::GoAway(g) if g.last_stream == 0 && g.code == code))
        );
        assert!(!output.iter().any(|f| matches!(f, Frame::Reset(_))));
        assert!(harness.ended());
    }
}

#[test]
fn cookie_crumbs_reach_the_handler_as_one_header() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
         request: http::Request<bytes::Bytes>| {
            let cookies: Vec<&[u8]> = request
                .headers()
                .get_all("cookie")
                .iter()
                .map(|v| v.as_bytes())
                .collect();
            http::Response::new(Bytes::from(cookies.join(b"\n".as_slice())))
        },
    );
    let mut harness = server(Responder::new(router));
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
    let output = frames(&push(&mut harness, &input));
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
    let mut harness = server(Responder::new(Handler));
    push(&mut harness, &preface());
    // The failures are the server's, so they never use up the client's
    // allowance of error resets.
    for n in 0..1100 {
        let output = frames(&push(&mut harness, &headers(2 * n + 1, "/", true)));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 2 * n + 1 && r.code == 2))
        );
        assert!(!harness.ended());
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
    let mut harness = server(with(
        Arc::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        limits,
    ));
    push(&mut harness, &preface());
    for n in 0..1025 {
        let Frame::Headers(mut h) = Frame::parse(&headers(2 * n + 1, "/", true)).unwrap() else {
            unreachable!()
        };
        h.fragment.extend_from_slice(&[0xaf; 10]);
        let output = frames(&push(&mut harness, &h.to_bytes().unwrap()));
        assert_eq!(statuses(&output), [(2 * n + 1, b"431".to_vec())]);
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 7))
        );
        assert_eq!(harness.ended(), n == 1024);
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
    let mut harness = server(with(
        Arc::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        limits,
    ));
    let mut input = preface();
    input.extend(headers(1, "/", false));
    push(&mut harness, &input);
    for n in 1..1100 {
        let output = frames(&push(&mut harness, &headers(2 * n + 1, "/", true)));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 2 * n + 1 && r.code == 7))
        );
        assert!(!harness.ended());
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
    let mut harness = budgeted(
        Responder::new(Streamed),
        fictionet::stdlib::layer::Budget::new(128 << 10),
    );
    let mut input = preface();
    input.extend(headers(1, "/small", true));
    input.extend(headers(3, "/large", true));
    let output = frames(&push(&mut harness, &input));
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
    assert!(!harness.ended());
    assert_eq!(
        statuses(&frames(&push(&mut harness, &headers(5, "/small", true)))),
        [(5, b"200".to_vec())]
    );
}

#[test]
fn connection_budget_exhaustion_sends_goaway() {
    let budget = fictionet::stdlib::layer::Budget::new(h2_input() + 1000);
    let mut harness = budgeted(
        Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        budget.clone(),
    );
    push(&mut harness, &preface());
    let _other = budget.charge(budget.limit() - budget.used()).unwrap();
    let output = frames(&push(
        &mut harness,
        &http2::Ping {
            flags: 0,
            opaque: [0; 8],
        }
        .to_bytes()
        .unwrap(),
    ));
    assert!(
        output
            .iter()
            .any(|f| matches!(f, Frame::GoAway(g) if g.code == 11))
    );
    assert!(harness.ended());
}

#[test]
fn repeated_budget_refusals_exhaust_the_local_reset_limit() {
    let budget = fictionet::stdlib::layer::Budget::new(h2_input() + 1024);
    let mut harness = budgeted(
        Responder::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        budget,
    );
    push(&mut harness, &preface());
    for n in 0..1025 {
        let Frame::Headers(mut h) = Frame::parse(&headers(2 * n + 1, "/", true)).unwrap() else {
            unreachable!()
        };
        hpack::Field::new("x-large", "x".repeat(4096))
            .write(&mut h.fragment)
            .unwrap();
        let output = frames(&push(&mut harness, &h.to_bytes().unwrap()));
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.code == 7))
        );
        assert_eq!(harness.ended(), n == 1024);
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
        let router = {
            let route_0 = std::sync::Arc::new(
                |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                 _: http::Request<bytes::Bytes>| {
                    http::Response::new(Bytes::from_static(b"ok"))
                },
            );
            let route_1 =
                std::sync::Arc::new(|_: fictionet::Cx, _: http::Request<bytes::Bytes>| async {
                    http::Response::new(Bytes::from(vec![b'x'; 200_000]))
                });
            fictionet_test_support::reply_handler(move |ex, request| {
                use fictionet::stdlib::web::httpd::{Body, Reply};
                let (parts, body) = request.into_parts();
                let Some(body) = body.bytes() else {
                    return Reply::Now(
                        http::Response::builder()
                            .status(400)
                            .body(Body::empty())
                            .unwrap(),
                    );
                };
                let request = http::Request::from_parts(parts, body);
                if request.uri().path() == "/small" && (request.method() == http::Method::POST) {
                    return Reply::Now(route_0(ex, request).map(Body::from));
                }
                if request.uri().path() == "/large" && (request.method() == http::Method::POST) {
                    return {
                        let route = route_1.clone();
                        Reply::Later(Box::new(move |cx| {
                            Box::pin(async move { Ok(route(cx, request).await.map(Body::from)) })
                        }))
                    };
                }
                if request.uri().path() == "/small" || request.uri().path() == "/large" {
                    return Reply::Now(
                        http::Response::builder()
                            .status(405)
                            .body(Body::empty())
                            .unwrap(),
                    );
                }
                Reply::Now(
                    http::Response::builder()
                        .status(404)
                        .body(Body::empty())
                        .unwrap(),
                )
            })
        };
        let mut harness = Harness::with_budget(
            Seed::from_u64(1),
            Responder::new(router).http2(),
            fictionet::stdlib::layer::Budget::new(128 << 10),
        )
        .with_worker(Polling::in_world(cx.clone()));
        let mut input = preface();
        input.extend(headers(1, "/small", true));
        input.extend(headers(3, "/large", true));
        let output = frames(&push(&mut harness, &input));
        assert_eq!(
            statuses(&output),
            [(1, b"200".to_vec()), (3, b"503".to_vec())]
        );
        assert!(!harness.ended());
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// gRPC on the exchange children, `Upgrade: h2c`, and telling the versions
/// apart by the preface.
mod layers;
