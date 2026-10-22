//! The same closed world repeats its event bytes and every agent packet.

use fictionet_extras::hyper_io::Io;

use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::services::serve::{Flow, ServeOptions};
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::{
    network::{Connection, delay, filter},
    services::tls,
    web::httpd,
};
use fictionet::{Cx, Seed, block_on, lab};
use fictionet_test_support::sandbox::TlsClient;
use http::{Request, Response};
use http_body::Frame;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
const DATE: u64 = 1_893_456_000;

const ECHO: Ipv4Addr = Ipv4Addr::new(192, 168, 10, 10);
const HTTPS: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 10);

#[derive(Debug, Default, PartialEq, Eq)]
struct Trace {
    packets: Vec<(bool, Vec<u8>)>,
    losses: [usize; 2],
}

struct Echo;
service_fixture! {
    Echo => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(4096, Ending::LfOrCrlf)
    }
    on_item(self, line: Result<Vec<u8>, LineError>; _, d) -> Flow {
        let line = line.unwrap();
        d.reply().extend_from_slice(&line);
        d.reply().push(b'\n');
        Ok(Flow::Continue)
    }
}

struct BrokenBody;
impl http_body::Body for BrokenBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("reset this stream"))))
    }
}

/// Switches `/upgrade` to a protocol that sends `upgraded\n`.
fn upgrade(_: Request<httpd::Body>) -> httpd::Reply {
    let mut response = Response::builder()
        .status(101)
        .header("connection", "upgrade")
        .header("upgrade", "echo")
        .body(httpd::Body::empty())
        .unwrap();
    response
        .extensions_mut()
        .insert(httpd::UpgradeHandler::new(|cx, mut conn| async move {
            let _ = conn.write_all(&cx, b"upgraded\n").await;
        }));
    httpd::Reply::Now(response)
}

struct Http;
impl httpd::Handler for Http {
    fn call(&self, request: Request<httpd::Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        if request.uri().path() == "/upgrade" {
            return upgrade(request);
        }
        if request.uri().path() == "/reset" {
            return httpd::Reply::Now(Response::new(httpd::Body::new(BrokenBody)));
        }
        let draw = ex.random_u64();
        httpd::Reply::Now(Response::new(
            format!("{} {draw}\n", request.uri().path()).into(),
        ))
    }
}

async fn read_until(cx: &Cx, conn: &mut impl Connection, needle: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    while !result.ends_with(needle) {
        let mut bytes = [0; 4096];
        let n = conn.read(cx, &mut bytes).await.unwrap();
        assert_ne!(n, 0, "{}", String::from_utf8_lossy(&result));
        result.extend_from_slice(&bytes[..n]);
    }
    result
}

async fn world(seed: Seed, trace: Arc<Mutex<Trace>>) -> fictionet::Result {
    let packets = trace.clone();
    let loss_trace = trace.clone();
    lab(seed, move |cx| episode(cx, packets, loss_trace)).await?;
    Ok(())
}

async fn episode(
    cx: Cx,
    packets: Arc<Mutex<Trace>>,
    loss_trace: Arc<Mutex<Trace>>,
) -> fictionet::Result {
    let cert = CertificateDer::from(include_bytes!("fixtures/tls/ed25519.cert.der").to_vec());
    let key =
        PrivateKeyDer::try_from(include_bytes!("fixtures/tls/ed25519.key.der").to_vec()).unwrap();
    let date = UNIX_EPOCH + Duration::from_secs(DATE);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let roots = Arc::new(roots);
    let mut config = tls::config_builder(&cx, date)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let (attacher, attachments) = fictionet::attachments();
    let office = fictionet::stdlib::world::net::Lan::new("office", "192.168.10.0/24".parse()?);
    let web_lan = fictionet::stdlib::world::net::Lan::new("web", "192.168.20.0/24".parse()?);
    Net::new()
        .ipv4_only()
        .lan(&office)
        .lan(&web_lan)
        .host("echo", |h| {
            h.on(&office).at(ECHO).dns_name("echo.test").tcp_with(
                7,
                Arc::new(()),
                || Echo,
                ServeOptions::default().idle(Some(Duration::from_secs(120))),
            )
        })
        .host("https", |h| {
            h.on(&web_lan).at(HTTPS).dns_name("localhost").tls_accept(
                443,
                "localhost",
                move |_| config.clone(),
                httpd::Server::new(Http).https().date(date),
            )
        })
        .start(&cx, attachments)?;
    let agent = attacher.attach("agent")?;
    // Capture next to the agent, before the loss and delay filters.
    let agent = filter(&cx, agent, move |_, direction, p| {
        packets.lock().unwrap().packets.push((
            direction == fictionet::stdlib::network::Direction::FromInner,
            p.0.clone(),
        ));
        true
    });
    let agent = filter(&cx, agent, move |cx, direction, _| {
        let keep = cx.random_f64() >= 0.03;
        if !keep {
            loss_trace.lock().unwrap().losses
                [usize::from(direction == fictionet::stdlib::network::Direction::ToInner)] += 1;
        }
        keep
    });
    let agent = delay(&cx, Duration::from_millis(2), agent);
    let machine = fictionet_test_support::sandbox::machine(&cx, agent, Ipv4Addr::new(10, 0, 0, 2));
    let mut dns = machine.udp.bind(40000)?;
    for (name, expected) in [("echo.test", ECHO), ("localhost", HTTPS)] {
        let mut query = Message::new(cx.random_u64() as u16, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
        // DNS retry uses the lab clock, including when a query or answer is lost.
        let bytes = loop {
            dns.send_to(&query.to_vec()?, "10.0.0.1:53".parse()?);
            if let Ok(answer) = cx
                .race(Some(cx.now() + Duration::from_secs(1)), dns.recv(&cx))
                .await
            {
                break answer?.0;
            }
        };
        let answer = Message::from_vec(&bytes)?;
        assert_eq!(answer.metadata.id, query.metadata.id);
        assert!(
            answer
                .answers
                .iter()
                .any(|r| matches!(&r.data, RData::A(a) if a.0 == expected))
        );
    }
    let mut echo = machine
        .tcp
        .connect(&cx, SocketAddr::new(ECHO.into(), 7))
        .await?;
    for i in 0..64 {
        let line = format!("line {i} {}\n", cx.random_u64());
        echo.write_all(&cx, line.as_bytes()).await?;
        assert_eq!(read_until(&cx, &mut echo, b"\n").await, line.as_bytes());
    }
    echo.shutdown(&cx).await?;
    for h2 in [false, true] {
        let tcp = machine
            .tcp
            .connect(&cx, SocketAddr::new(HTTPS.into(), 443))
            .await?;
        let mut secure = TlsClient::new(
            &cx,
            tcp,
            &roots,
            "localhost",
            &[if h2 { b"h2" } else { b"http/1.1" }],
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        )?;
        secure.handshake(&cx).await.unwrap();
        if h2 {
            let (mut sender, connection) = h2::client::handshake(TokioIo::new(Io {
                fcx: cx.clone(),
                conn: secure,
            }))
            .await?;
            cx.spawn(move |_| async move {
                let _ = connection.await;
                Ok(())
            });
            let mut requests = Vec::new();
            for path in ["/one", "/two", "/reset", "/three"] {
                sender = sender.ready().await?;
                let (reply, _) = sender.send_request(
                    Request::builder()
                        .uri(format!("https://localhost{path}"))
                        .body(())?,
                    true,
                )?;
                requests.push((path, reply));
            }
            for (path, reply) in requests {
                let response = reply.await;
                if path == "/reset" {
                    let error = match response {
                        Err(e) => e,
                        Ok(r) => r.into_body().data().await.unwrap().unwrap_err(),
                    };
                    assert!(error.is_reset(), "{error}");
                } else {
                    let mut body = response?.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        bytes.extend_from_slice(&chunk?);
                    }
                    assert!(bytes.starts_with(path.as_bytes()));
                }
            }
        } else {
            secure
                .write_all(&cx, b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await?;
            let mut response = Vec::new();
            loop {
                let mut bytes = [0; 4096];
                let n = secure.read(&cx, &mut bytes).await?;
                assert!(n > 0);
                response.extend_from_slice(&bytes[..n]);
                if let Some(at) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&response[..at]);
                    let len: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()?;
                    if response.len() == at + 4 + len {
                        break;
                    }
                }
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert!(String::from_utf8_lossy(&response).contains("/plain "));
            secure.write_all(&cx, b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\n").await?;
            let response = read_until(&cx, &mut secure, b"upgraded\n").await;
            assert!(response.starts_with(b"HTTP/1.1 101"));
        }
    }
    cx.idle().await?;
    cx.cancel();
    Ok(())
}

fn replay(seed: u64) -> Trace {
    let trace = Arc::new(Mutex::new(Trace::default()));
    block_on(world(Seed::from_u64(seed), trace.clone())).unwrap();
    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

#[test]
fn https_sites_with_lab_ca_and_axum_repeat() {
    use fictionet::stdlib::{
        codec::Wire,
        protocols::{http1, x509},
        services::ca::Ca,
        web,
    };
    use fictionet_test_support::sandbox;

    let episode = |seed| {
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let replies = bodies.clone();
        block_on(lab(Seed::from_u64(seed), move |cx| async move {
            let date = UNIX_EPOCH + Duration::from_secs(DATE);
            let ca = Ca::new(&cx, "Lab CA")?;
            let leaf = ca.issue(
                &cx,
                &["site.test"],
                x509::Validity {
                    not_before: x509::Time::from_unix(DATE as i64 - 86400)?,
                    not_after: x509::Time::from_unix(DATE as i64 + 86400)?,
                },
            )?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.cert_der())?;
            let roots = Arc::new(roots);
            let mut config = leaf.server_config(&cx, date)?;
            Arc::get_mut(&mut config).unwrap().alpn_protocols = vec![b"http/1.1".to_vec()];
            let handler_cx = cx.clone();
            let app = axum::Router::new().fallback(move || {
                let draw = handler_cx.random_u64();
                async move { format!("hello {draw}") }
            });
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(move |name| {
                (name == "site.test").then(|| web::Site::new(app.clone()).tls(config.clone()))
            })
            .date(date)
            .start(&cx, attachments)?;
            let machine =
                sandbox::machine(&cx, attacher.attach("client")?, Ipv4Addr::new(10, 0, 0, 2));
            let answer = machine
                .lookup(&cx, "10.0.0.1".parse()?, "site.test", RecordType::A)
                .await?;
            let address = answer
                .answers
                .iter()
                .find_map(|r| match r.data {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .unwrap();
            let mut conn = machine
                .tls(&cx, (address, 443).into(), "site.test", Some(&roots), date)
                .await?;
            assert_eq!(conn.tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
            let request = http1::Request::parse(b"GET / HTTP/1.1\r\nHost: site.test\r\n\r\n")?;
            for _ in 0..2 {
                let response = sandbox::request(&cx, &mut conn, &request).await?;
                assert_eq!(response.head.status, 200);
                assert!(response.body.starts_with(b"hello "));
                replies.lock().unwrap().push(response.body);
            }
            cx.cancel();
            Ok(())
        }))
        .unwrap();

        bodies.lock().unwrap().clone()
    };
    let first = episode(41);
    assert_eq!(first.len(), 2);
    assert_eq!(first, episode(41));
    let other = episode(42);
    assert_ne!(first, other);
}

#[test]
fn sequential_labs_repeat_every_event_and_packet() {
    let first = replay(41);
    assert!(!first.packets.is_empty());
    assert!(first.losses.iter().all(|n| *n > 0), "{:?}", first.losses);
    assert_eq!(first, replay(41));
    let other = replay(42);
    assert_ne!(first.packets, other.packets);
}

#[test]
fn interleaved_labs_repeat_every_event_and_packet() {
    let a = Arc::new(Mutex::new(Trace::default()));
    let b = Arc::new(Mutex::new(Trace::default()));
    let mut first = pin!(world(Seed::from_u64(41), a.clone()));
    let mut second = pin!(world(Seed::from_u64(41), b.clone()));
    let mut context = Context::from_waker(Waker::noop());
    let mut interleaved = 0;
    let (mut done_a, mut done_b) = (false, false);
    while !done_a || !done_b {
        if !done_a && !done_b {
            interleaved += 1;
        }
        if !done_a && let Poll::Ready(result) = first.as_mut().poll(&mut context) {
            result.unwrap();
            done_a = true;
        }
        if !done_b && let Poll::Ready(result) = second.as_mut().poll(&mut context) {
            result.unwrap();
            done_b = true;
        }
    }
    assert!(
        interleaved > 1,
        "both labs must stay live across outer polls"
    );
    assert_eq!(*a.lock().unwrap(), *b.lock().unwrap());
}
