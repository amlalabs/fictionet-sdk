//! The same closed world repeats its event bytes and every agent packet.

#[macro_use]
#[path = "common/service_fixture.rs"]
mod service_fixture;

use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use fictionet::events::{Event, Fields};
use fictionet::prelude::*;
use fictionet::stdlib::codec::{ByteFault, Rule, Trigger};
use fictionet::stdlib::codec::{Ending, LineError, Lines};
use fictionet::stdlib::dns::op::{Message, MessageType, OpCode, Query};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::net::Net;
use fictionet::stdlib::sandbox::TlsClient;
use fictionet::stdlib::serve::{FaultPlan, Flow, Plan, ServeOptions};
use fictionet::stdlib::{Connection, delay, filter, httpd, tls};
use fictionet::{Cx, Seed, block_on, lab};
use http::{Request, Response};
use http_body::Frame;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
const DATE: u64 = 1_893_456_000;

const ECHO: Ipv4Addr = Ipv4Addr::new(192, 168, 10, 10);
const HTTPS: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 10);

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
        d.record(Event::new("echo", "line").field("bytes", line.len() as u64));
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

struct Http;
impl httpd::Handler for Http {
    fn call(
        &self,
        mut request: Request<httpd::Body>,
        ex: &mut httpd::Exchange<'_>,
    ) -> httpd::Reply {
        if request.uri().path() == "/upgrade" {
            let upgrade = hyper::upgrade::on(&mut request);
            return httpd::Reply::Later(Box::new(move |cx| {
                Box::pin(async move {
                    cx.spawn(move |_| async move {
                        let mut io = upgrade.await?;
                        std::future::poll_fn(|cx| {
                            hyper::rt::Write::poll_write(Pin::new(&mut io), cx, b"upgraded\n")
                        })
                        .await?;
                        Ok(())
                    });
                    Ok(Response::builder()
                        .status(101)
                        .header("connection", "upgrade")
                        .header("upgrade", "echo")
                        .body(httpd::Body::empty())?)
                })
            }));
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

fn world(seed: Seed, trace: Arc<Mutex<Trace>>) -> impl Future<Output = fictionet::Result> {
    let log = Log::default();
    let output = log.clone();
    async move {
        let packets = trace.clone();
        let loss_trace = trace.clone();
        lab(seed, move |cx| episode(cx, output, packets, loss_trace)).await?;
        trace.lock().unwrap().events = log.0.lock().unwrap().clone();
        Ok(())
    }
}

async fn episode(
    cx: Cx,
    output: Log,
    packets: Arc<Mutex<Trace>>,
    loss_trace: Arc<Mutex<Trace>>,
) -> fictionet::Result {
    cx.events().to_writer(Box::new(output));
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
    Net::new()
        .ipv4_only()
        .start_fields(Fields::new().with("world_date", "2030-01-01"))
        .lan("office", "192.168.10.0/24".parse()?)
        .lan("web", "192.168.20.0/24".parse()?)
        .host("echo", |h| {
            h.on("office").at(ECHO).dns_name("echo.test").tcp_with(
                7,
                Arc::new(()),
                || Echo,
                ServeOptions::default()
                    .idle(Some(Duration::from_secs(120)))
                    .faults(FaultPlan::new(Plan {
                        outbound: vec![Rule {
                            when: Trigger::Chance { take: 1, out_of: 2 },
                            fault: ByteFault::Delay(Duration::from_millis(3)),
                        }],
                        ..Plan::default()
                    })),
            )
        })
        .host("https", |h| {
            h.on("web").at(HTTPS).dns_name("localhost").tls_accept(
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
            direction == fictionet::stdlib::Direction::FromInner,
            p.0.clone(),
        ));
        true
    });
    let agent = filter(&cx, agent, move |cx, direction, _| {
        let keep = cx.random_f64() >= 0.03;
        if !keep {
            loss_trace.lock().unwrap().losses
                [usize::from(direction == fictionet::stdlib::Direction::ToInner)] += 1;
            cx.record(Event::new("link", "loss").field(
                "inbound",
                direction == fictionet::stdlib::Direction::ToInner,
            ));
        }
        keep
    });
    let agent = delay(&cx, Duration::from_millis(2), agent);
    let machine = fictionet::stdlib::sandbox::machine(&cx, agent, Ipv4Addr::new(10, 0, 0, 2));
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
            let (mut sender, connection) = h2::client::handshake(secure.into_tokio(&cx)).await?;
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
                    cx.record(
                        Event::new("client", "reply").field("body", String::from_utf8(bytes)?),
                    );
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
                        .find_map(|line| line.strip_prefix("content-length: "))
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
    cx.sleep(Duration::from_secs(2)).await?;
    assert_eq!(cx.events().lost(), 0);
    cx.cancel();
    Ok(())
}

fn replay(seed: u64) -> Trace {
    let trace = Arc::new(Mutex::new(Trace::default()));
    block_on(world(Seed::from_u64(seed), trace.clone())).unwrap();
    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

#[test]
fn sequential_labs_repeat_every_event_and_packet() {
    let first = replay(41);
    assert!(!first.packets.is_empty());
    assert!(first.losses.iter().all(|n| *n > 0), "{:?}", first.losses);
    assert!(String::from_utf8_lossy(&first.events).contains(r#""kind":"loss""#));
    assert_eq!(first, replay(41));
    let other = replay(42);
    assert_ne!(first.packets, other.packets);
    // Only the different-seed check excludes run.start, whose seed must differ.
    let behavior = |trace: &Trace| {
        String::from_utf8(trace.events.clone())
            .unwrap()
            .lines()
            .filter(|l| !l.contains(r#""source":"run","kind":"start""#))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_ne!(behavior(&first), behavior(&other));
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
