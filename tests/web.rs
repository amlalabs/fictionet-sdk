//! `web::Sites`, in one process. Each test plays one or more sandboxes:
//! raw packets on the attachment's cable, or a machine built from stdlib
//! parts (`split_protocols`, `tcp::endpoint`, `udp::endpoint`) with a
//! rustls client and a hyper client on top.

#[path = "common/certs.rs"]
mod certs;
mod common;
#[path = "common/tls_client.rs"]
mod tls_client;
use tls_client::{TlsClient, TlsError};
#[path = "common/done.rs"]
mod done;
#[path = "common/machine.rs"]
mod machine;
#[path = "common/world.rs"]
mod run_world;
#[path = "common/sandbox.rs"]
mod sandbox;
#[path = "common/timeout.rs"]
mod timeout;
#[path = "common/wait.rs"]
mod wait;

use certs::certs;
use common::within;
use done::Done;
use machine::machine;
use sandbox::Machine;
use timeout::timeout;

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use axum::Extension;
use bytes::Bytes;
use fictionet::events::{Event as Entry, EventLog, Fields, Sandbox};
use fictionet::prelude::*;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::tls;
use fictionet::stdlib::{ConnError, Connection, dhcp, ip, tcp, web};
use fictionet::{Attacher, Cx, End, Interface, Packet, Seed, block_on, lab, run};
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

// ---------------------------------------------------------------------------
// Running a test world

/// Runs a world with the test sites. `f` gets the attacher and plays the
/// sandboxes. When it returns, the world ends with `Done`, which cancels
/// everything.
fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = sites(&fcx).serve_with(&fcx, attachments)?;
        f(fcx, attacher, env).await?;
        Ok(())
    });
}

fn real_world<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::real_world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = sites(&fcx).serve_with(&fcx, attachments)?;
        f(fcx, attacher, env).await?;
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The sites

/// What the tests need to know about the sites.
#[derive(Clone)]
struct Env {
    roots: Arc<RootCertStore>,
    /// How often the callback ran.
    calls: Arc<AtomicUsize>,
    /// Requests the secure site has served.
    served: Arc<AtomicUsize>,
    waiting: Arc<AtomicUsize>,
}

struct TestSites {
    sites: web::Sites,
    env: Env,
}

impl TestSites {
    fn serve_with(self, fcx: &Cx, attachments: fictionet::Attachments) -> fictionet::Result<Env> {
        self.sites.start(fcx, attachments)?;
        Ok(self.env)
    }
}

const SECURE_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const EVENTS_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
const BOTH_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 30);
const DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 40);
const TLS_DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 41);
const DUAL_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 50);
const DUAL_ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x50, 0, 0, 0, 0, 0x10);
const V6ONLY_ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x50, 0, 0, 0, 0, 0x20);

/// What `events.test` adds to its request's event about a page, through the
/// response's extensions.
fn page(kind: &'static str) -> Fields {
    Fields::new().with("page", kind)
}

/// The size of `events.test/big`.
const BIG: usize = 4 << 20;

fn events_site(waiting: Arc<AtomicUsize>) -> axum::Router {
    axum::Router::new()
        .route(
            "/page",
            axum::routing::get(|Extension(t): Extension<web::Target>| async move {
                (Extension(page("article")), format!("page sni={:?}", t.sni))
            }),
        )
        .route("/big", axum::routing::get(|| async { vec![b'x'; BIG] }))
        .route(
            "/wait",
            axum::routing::get(move || {
                let waiting = waiting.clone();
                async move {
                    waiting.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    "never"
                }
            }),
        )
}

/// The test world's sites:
///
/// - `secure.test`: axum, HTTPS, at 203.0.113.10. Echoes its `Target`.
/// - `shared.test`: a plain tower service, HTTP only, at the same address.
/// - `plain.test`: the plain service, HTTP only, an automatic address.
/// - `inside.test`: asks for an address inside the sandboxes' subnet.
/// - `broken.test`: a handler that fails.
/// - `*.wild.test`: the plain service, each name its own automatic address.
/// - `events.test`: axum, HTTPS, at 203.0.113.20. `/page` puts a [`page`]
///   in its response's extensions; `/big` answers with 4 MiB; `/wait`
///   never answers.
/// - `slow.test`: the same handler, HTTP only, an automatic address.
/// - `both.test`: the secure handler, HTTPS and plain HTTP
///   (`plain_http`), at 203.0.113.30.
/// - `default.test`: the plain service, the `default_host` at 203.0.113.40;
///   `other.test`: the plain service at the same address, not the default.
/// - `tls-default.test`: the secure handler, HTTPS, the `default_host` at
///   203.0.113.41.
/// - `dual.test`: the secure handler, HTTPS, at 203.0.113.50 and
///   2001:db8:50::10.
/// - `v4only.test`: the secure handler, HTTPS, IPv4 only, automatic.
/// - `v6only.test`: the secure handler, HTTPS, IPv6 only, at
///   2001:db8:50::20.
/// - `inside6.test`: asks for an address inside the sandboxes' IPv6 subnet.
/// - everything else: NXDOMAIN.
fn sites(fcx: &Cx) -> TestSites {
    let certs = certs(&[
        "secure.test",
        "shared.test",
        "plain.test",
        "nope.test",
        "events.test",
        "both.test",
        "tls-default.test",
        "dual.test",
        "v4only.test",
        "v6only.test",
    ]);
    let config = Arc::new(
        tls::config_builder(fcx, SystemTime::now())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.chain, certs.key)
            .unwrap(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let waiting = Arc::new(AtomicUsize::new(0));
    let handler_waiting = waiting.clone();
    let env = Env {
        roots: Arc::new(certs.roots),
        calls: calls.clone(),
        served: served.clone(),
        waiting,
    };

    let secure = axum::Router::new().fallback(
        move |Extension(t): Extension<web::Target>, version: Version| {
            let n = served.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                format!(
                    "secure {} {} {} {:?} #{n}",
                    t.scheme, t.host, t.port, version
                )
            }
        },
    );
    let sites = web::Sites::new(move |host| {
        calls.fetch_add(1, Ordering::SeqCst);
        match host {
            "secure.test" => Some(web::Site::new(secure.clone()).at(SECURE_ADDR).tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "shared.test" => Some(web::Site::new(Plain("shared")).at(SECURE_ADDR)),
            "plain.test" => Some(web::Site::new(Plain("plain"))),
            "inside.test" => Some(web::Site::new(Plain("inside")).at(Ipv4Addr::new(10, 0, 0, 50))),
            "inside6.test" => Some(
                web::Site::new(Plain("inside")).at("2001:db8::50".parse::<Ipv6Addr>().unwrap()),
            ),
            "dual.test" => Some(
                web::Site::new(secure.clone())
                    .at(DUAL_ADDR)
                    .at(DUAL_ADDR6)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    }),
            ),
            "v4only.test" => Some(web::Site::new(secure.clone()).ipv4_only().tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "v6only.test" => Some(
                web::Site::new(secure.clone())
                    .ipv6_only()
                    .at(V6ONLY_ADDR6)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    }),
            ),
            "broken.test" => Some(web::Site::new(Broken)),
            h if h.ends_with(".wild.test") => Some(web::Site::new(Plain("wild"))),
            "slow.test" => Some(web::Site::new(events_site(handler_waiting.clone()))),
            "events.test" => Some(
                web::Site::new(events_site(handler_waiting.clone()))
                    .at(EVENTS_ADDR)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    }),
            ),
            "both.test" => Some(
                web::Site::new(secure.clone())
                    .at(BOTH_ADDR)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    })
                    .plain_http(),
            ),
            "default.test" => Some(
                web::Site::new(Plain("default"))
                    .at(DEFAULT_ADDR)
                    .default_host(),
            ),
            "other.test" => Some(web::Site::new(Plain("other")).at(DEFAULT_ADDR)),
            "tls-default.test" => Some(
                web::Site::new(secure.clone())
                    .at(TLS_DEFAULT_ADDR)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    })
                    .default_host(),
            ),
            _ => None,
        }
    });
    TestSites { sites, env }
}

/// A handler written by hand as a tower service: answers with its name,
/// the `Target`, and the HTTP version.
#[derive(Clone)]
struct Plain(&'static str);

impl tower_service::Service<Request<web::Body>> for Plain {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<web::Body>) -> Self::Future {
        let t = request
            .extensions()
            .get::<web::Target>()
            .expect("serve sets a Target");
        let body = format!(
            "{} {} {} {} {:?} {}",
            self.0,
            t.scheme,
            t.host,
            t.port,
            request.version(),
            request.uri().path()
        );
        std::future::ready(Ok(Response::new(Full::new(Bytes::from(body)))))
    }
}

/// A handler that always fails.
#[derive(Clone)]
struct Broken;

impl tower_service::Service<Request<web::Body>> for Broken {
    type Response = Response<Full<Bytes>>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, std::io::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<web::Body>) -> Self::Future {
        std::future::ready(Err(std::io::Error::other("broken on purpose")))
    }
}

// ---------------------------------------------------------------------------
// A sandbox built from stdlib parts

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Asks the gateway's DNS over UDP. Returns the response code and the A
/// records.
async fn dns(fcx: &Cx, m: &Machine, name: &str, kind: RecordType) -> (ResponseCode, Vec<Ipv4Addr>) {
    let mut socket = m
        .udp
        .bind(40000 + (fcx.random_u64() % 20000) as u16)
        .unwrap();
    let mut q = Message::new(fcx.random_u64() as u16, MessageType::Query, OpCode::Query);
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, from) = timeout(fcx, Duration::from_secs(5), socket.recv(fcx))
        .await
        .expect("a DNS answer")
        .unwrap();
    assert_eq!(from, SocketAddr::new(GATEWAY.into(), 53));
    parse_dns(&bytes, q.metadata.id)
}

fn parse_dns(bytes: &[u8], id: u16) -> (ResponseCode, Vec<Ipv4Addr>) {
    let r = Message::from_vec(bytes).unwrap();
    assert_eq!(r.metadata.id, id);
    assert_eq!(r.metadata.message_type, MessageType::Response);
    assert_eq!(r.metadata.op_code, OpCode::Query);
    let addrs = r
        .answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect();
    (r.metadata.response_code, addrs)
}

async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> Ipv4Addr {
    let (code, addrs) = dns(fcx, m, name, RecordType::A).await;
    assert_eq!(code, ResponseCode::NoError, "{name}");
    assert_eq!(addrs.len(), 1, "{name}");
    addrs[0]
}

// ---------------------------------------------------------------------------
// A hyper client over a Connection

struct Io<C> {
    fcx: Cx,
    conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = vec![0u8; buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.fcx, cx, &mut tmp) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&tmp[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn
            .poll_write(&this.fcx, cx, data)
            .map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn
            .poll_shutdown(&this.fcx, cx)
            .map_err(std::io::Error::other)
    }
}

#[derive(Clone)]
struct Exec(Cx);

impl<F: Future<Output = ()> + Send + 'static> hyper::rt::Executor<F> for Exec {
    fn execute(&self, fut: F) {
        self.0.spawn(move |_| async move {
            fut.await;
            Ok(())
        });
    }
}

/// One HTTP client connection, HTTP/1.1 or HTTP/2.
enum Client {
    H1(hyper::client::conn::http1::SendRequest<Empty<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Empty<Bytes>>),
}

struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    version: Version,
}

impl Client {
    async fn new<C: Connection + Unpin>(fcx: &Cx, conn: C, h2: bool) -> Client {
        let io = Io {
            fcx: fcx.clone(),
            conn,
        };
        if h2 {
            let (send, conn) = hyper::client::conn::http2::handshake(Exec(fcx.clone()), io)
                .await
                .unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H2(send)
        } else {
            let (send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            fcx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H1(send)
        }
    }

    /// GETs `path` from `host`. For HTTP/2 the URI carries the host as its
    /// authority; for HTTP/1.1 the `Host` header does.
    async fn get(&mut self, scheme: &str, host: &str, path: &str) -> Got {
        self.send(http::Method::GET, scheme, host, path).await
    }

    /// Sends a `method` request for `path` to `host`, as [`Client::get`] does.
    async fn send(&mut self, method: http::Method, scheme: &str, host: &str, path: &str) -> Got {
        let response = match self {
            Client::H1(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", host)
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
            Client::H2(s) => {
                s.ready().await.unwrap();
                let r = Request::builder()
                    .method(method)
                    .uri(format!("{scheme}://{host}{path}"))
                    .body(Empty::new())
                    .unwrap();
                s.send_request(r).await.unwrap()
            }
        };
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Got {
            status,
            headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
            version,
        }
    }
}

/// Opens a TLS connection from `m` to `addr:443` with `sni` and `alpn`.
async fn tls_connect(
    fcx: &Cx,
    m: &Machine,
    env: &Env,
    addr: impl Into<IpAddr>,
    sni: &str,
    alpn: &[&[u8]],
) -> Result<TlsClient<tcp::TcpConnection>, TlsError> {
    let tcp = m
        .tcp
        .connect(fcx, SocketAddr::new(addr.into(), 443))
        .await
        .map_err(TlsError::Conn)?;
    let mut client = TlsClient::new(fcx, tcp, &env.roots, sni, alpn);
    client.handshake(fcx).await?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// Tests: DNS

#[test]
fn dns_answers_sites_nodata_and_nxdomain() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));

        // A site with `at` gets that address; the same answer every time.
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "secure.test.").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "SeCuRe.TeSt").await, SECURE_ADDR);
        // Without `at`, an address from 198.18.0.0/15.
        let plain = lookup(&fcx, &m, "plain.test").await;
        assert_eq!(plain, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(
            lookup(&fcx, &m, "broken.test").await,
            Ipv4Addr::new(198, 18, 0, 2)
        );
        assert_eq!(lookup(&fcx, &m, "plain.test").await, plain);

        // Other types of a site's name: NODATA. (AAAA is in the IPv6 tests.)
        assert_eq!(
            dns(&fcx, &m, "secure.test", RecordType::MX).await,
            (ResponseCode::NoError, vec![])
        );
        // Names the callback turned down: NXDOMAIN, for every type.
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::A).await,
            (ResponseCode::NXDomain, vec![])
        );
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::AAAA).await,
            (ResponseCode::NXDomain, vec![])
        );
        // A site that asks for an address inside the sandboxes' subnet.
        assert_eq!(
            dns(&fcx, &m, "inside.test", RecordType::A).await,
            (ResponseCode::NXDomain, vec![])
        );

        // The callback ran once per name: secure, plain, broken, nope, inside.
        assert_eq!(env.calls.load(Ordering::SeqCst), 5);

        // DNS over TCP, two queries on one connection.
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY.into(), 53))
            .await
            .unwrap();
        for (name, id) in [("secure.test", 7u16), ("nope.test", 8)] {
            let mut q = Message::new(id, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            let bytes = q.to_vec().unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            conn.write_all(&fcx, &framed).await.unwrap();
            let mut len = [0u8; 2];
            read_exact(&fcx, &mut conn, &mut len).await;
            let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
            read_exact(&fcx, &mut conn, &mut reply).await;
            let got = parse_dns(&reply, id);
            if name == "secure.test" {
                assert_eq!(got, (ResponseCode::NoError, vec![SECURE_ADDR]));
            } else {
                assert_eq!(got, (ResponseCode::NXDomain, vec![]));
            }
        }
        assert_eq!(env.calls.load(Ordering::SeqCst), 5);
        Ok(())
    });
}

async fn read_exact<C: Connection>(fcx: &Cx, conn: &mut C, buf: &mut [u8]) {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(fcx, &mut buf[at..]).await.unwrap();
        assert!(n > 0, "the stream ended early");
        at += n;
    }
}

// ---------------------------------------------------------------------------
// Tests: HTTPS, HTTP/2 and HTTP/1.1

#[test]
fn https_with_http2_and_http11() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;

        // A client that offers h2 gets HTTP/2.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2", b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&fcx, conn, true).await;
        let got = client.get("https", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/2.0 #1");

        // Many streams at once on the one connection.
        let Client::H2(send) = &client else {
            unreachable!()
        };
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let mut c = Client::H2(send.clone());
            tasks.push(fcx.spawn(move |_| async move {
                let got = c.get("https", "secure.test", "/x").await;
                assert_eq!(got.status, StatusCode::OK);
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        assert_eq!(env.served.load(Ordering::SeqCst), 21);

        // A client that offers only http/1.1 gets it.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "secure.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_11);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #22");
        // Keep-alive: a second request on the same connection.
        let got = client.get("https", "secure.test:443", "/").await;
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #23");

        // A client that offers no ALPN at all gets HTTP/1.1.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[])
            .await
            .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), None);
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}

/// `Date` headers come from the world's date, over HTTP/1.1 and HTTP/2,
/// and never from the host's clock: without a world date there is none.
#[test]
fn dates_come_from_the_world() {
    // 2019-06-01T00:00:00Z.
    let june_2019 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_559_347_200);
    for date in [Some(june_2019), None] {
        let result = within(Duration::from_secs(60), move || {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                let site = axum::Router::new()
                    .route(
                        "/own",
                        axum::routing::get(|| async {
                            ([("date", "Mon, 01 Jan 2001 00:00:00 GMT")], "own")
                        }),
                    )
                    .fallback(|| async { "hello" });
                let mut sites = web::Sites::new(move |name: &str| {
                    (name == "dated.test").then(|| web::Site::new(site.clone()))
                });
                if let Some(date) = date {
                    sites = sites.date(date);
                }
                sites.start(&fcx, attachments)?;
                let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
                let addr = lookup(&fcx, &m, "dated.test").await;
                for h2 in [false, true] {
                    let conn = m
                        .tcp
                        .connect(&fcx, SocketAddr::new(addr.into(), 80))
                        .await
                        .unwrap();
                    let mut client = Client::new(&fcx, conn, h2).await;
                    let got = client.get("http", "dated.test", "/").await;
                    assert_eq!(got.body, "hello");
                    assert_eq!(
                        got.version,
                        if h2 {
                            Version::HTTP_2
                        } else {
                            Version::HTTP_11
                        }
                    );
                    let header = got
                        .headers
                        .get("date")
                        .map(|v| v.to_str().unwrap().to_owned());
                    match date {
                        Some(_) => {
                            let header = header.expect("a Date header");
                            assert!(
                                header.starts_with("Sat, 01 Jun 2019 00:0"),
                                "h2 {h2}: {header}"
                            );
                        }
                        None => assert_eq!(header, None, "h2 {h2}: no world date, so no Date"),
                    }
                    // A Date the handler sets is kept.
                    let got = client.get("http", "dated.test", "/own").await;
                    assert_eq!(
                        got.headers.get_all("date").iter().collect::<Vec<_>>(),
                        ["Mon, 01 Jan 2001 00:00:00 GMT"]
                    );
                }
                Err(fictionet::Error::from(Done))
            }))
        });
        assert!(result.is_err_and(|e| e.downcast_ref::<Done>().is_some()));
    }
}

#[test]
fn port_80_redirects_tls_sites_and_serves_the_others() {
    world(|fcx, attacher, _env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        assert_eq!(lookup(&fcx, &m, "shared.test").await, addr);
        let plain = lookup(&fcx, &m, "plain.test").await;

        // A site with TLS: 301 to https, with the path and query.
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("http", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://secure.test/a/b?c=d");
        // The site without TLS at the same address, on the same connection.
        let got = client.get("http", "shared.test", "/p").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.body, "shared http shared.test 80 HTTP/1.1 /p");

        // A site with its own address, over HTTP/1.1 and HTTP/2 with prior
        // knowledge.
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "plain.test", "/q").await.body,
            "plain http plain.test 80 HTTP/1.1 /q"
        );
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        let got = client.get("http", "plain.test", "/r").await;
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "plain http plain.test 80 HTTP/2.0 /r");

        // Port 443 is closed on a machine with no TLS site.
        assert_eq!(
            m.tcp
                .connect(&fcx, SocketAddr::new(plain.into(), 443))
                .await
                .err(),
            Some(ConnError::Refused)
        );
        Ok(())
    });
}

#[test]
fn a_tls_site_with_plain_http_answers_port_80_itself() {
    world_events(|fcx, attacher, env, log| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&fcx, &m, "both.test").await, BOTH_ADDR);

        // Port 80: the handler answers, with an http Target, over HTTP/1.1
        // and HTTP/2 with prior knowledge. No redirect.
        for h2 in [false, true] {
            let conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(BOTH_ADDR.into(), 80))
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            let got = client.get("http", "both.test", "/a?b=c").await;
            assert_eq!(got.status, StatusCode::OK);
            assert!(got.headers.get("location").is_none());
            let version = if h2 { "HTTP/2.0" } else { "HTTP/1.1" };
            assert!(
                got.body
                    .starts_with(&format!("secure http both.test 80 {version} #")),
                "{}",
                got.body
            );
        }

        // Port 443 still serves it over TLS.
        let conn = tls_connect(&fcx, &m, &env, BOTH_ADDR, "both.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "both.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(
            got.body
                .starts_with("secure https both.test 443 HTTP/1.1 #"),
            "{}",
            got.body
        );

        // Each plain request is a Handler event on port 80, with no SNI.
        let seen = wait_for(&fcx, &log, 3, http_seen).await;
        let plain: Vec<_> = seen.iter().filter(|h| local(h).port() == 80).collect();
        assert_eq!(plain.len(), 2);
        for h in plain {
            assert_eq!(
                (h.str("answer"), h.str("scheme"), h.str("sni")),
                (Some("handler"), Some("http"), None)
            );
            assert_eq!((h.u64("status"), h.str("path")), (Some(200), Some("/a")));
        }

        // A TLS site without it still redirects, at the same time.
        let secure = lookup(&fcx, &m, "secure.test").await;
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(secure.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/").await.status,
            StatusCode::MOVED_PERMANENTLY
        );
        Ok(())
    });
}

#[test]
fn a_host_that_is_not_this_site_gets_421() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        lookup(&fcx, &m, "shared.test").await;
        let plain = lookup(&fcx, &m, "plain.test").await;

        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            // A name with no site at all.
            assert_eq!(
                client.get("https", "nope.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // A site at another address.
            assert_eq!(
                client.get("https", "plain.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // A site at this address, but without TLS.
            assert_eq!(
                client.get("https", "shared.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            // The connection still works.
            assert_eq!(
                client.get("https", "secure.test", "/").await.status,
                StatusCode::OK
            );
        }

        // Plain HTTP too.
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            client.get("http", "198.18.0.1", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        Ok(())
    });
}

#[test]
fn a_failing_handler_gets_500() {
    world(|fcx, attacher, _env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "broken.test").await;
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "broken.test", "/").await.status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        Ok(())
    });
}

#[test]
fn an_unknown_tls_name_is_rejected_with_unrecognized_name() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        lookup(&fcx, &m, "shared.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        // A name with no site; a site here without TLS; a site elsewhere.
        for sni in ["nope.test", "shared.test", "plain.test"] {
            match tls_connect(&fcx, &m, &env, addr, sni, &[b"h2"]).await {
                Err(TlsError::Tls(rustls::Error::AlertReceived(
                    rustls::AlertDescription::UnrecognisedName,
                ))) => {}
                Err(e) => panic!("{sni}: expected unrecognized_name, got {e:?}"),
                Ok(_) => panic!("{sni}: the handshake should fail"),
            }
        }
        // Names seen in a handshake do not run the callback.
        assert_eq!(env.calls.load(Ordering::SeqCst), calls);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Raw packets

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Packet {
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, proto, 0, 0];
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = ip::checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    Packet(p)
}

fn ping(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Packet {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fictionet");
    let c = ip::checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 1, &icmp)
}

fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let c = ip::transport_checksum(src.into(), dst.into(), 17, &u);
    u[6..8].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 17, &u)
}

/// (src, dst, protocol, payload) of an IPv4 packet.
fn parse(p: &Packet) -> (Ipv4Addr, Ipv4Addr, u8, Vec<u8>) {
    let b = &p.0;
    assert_eq!(b[0] >> 4, 4);
    assert_eq!(ip::checksum(&b[..20]), 0, "IPv4 header checksum");
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    (src, dst, b[9], b[20..].to_vec())
}

async fn recv_within(fcx: &Cx, end: &mut End, d: Duration) -> Option<Packet> {
    timeout(fcx, d, end.recv(fcx)).await.map(|r| r.unwrap())
}

const SHORT: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Tests: routing, unreachable, isolation, binding

#[test]
fn unknown_addresses_get_host_unreachable_and_sites_appear_on_lookup() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();

        // An address that no site has: ICMP host unreachable, at once, from
        // the gateway, quoting the packet.
        let sent = ping(me, Ipv4Addr::new(192, 0, 2, 1), 1);
        raw.send(sent.clone());
        let reply = recv_within(&fcx, &mut raw, Duration::from_secs(2))
            .await
            .expect("host unreachable");
        let (src, dst, proto, icmp) = parse(&reply);
        assert_eq!((src, dst, proto), (GATEWAY, me, 1));
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        assert_eq!(ip::checksum(&icmp), 0, "ICMP checksum");
        assert_eq!(&icmp[8..], &sent.0[..]);

        // A site's address before its name was looked up: unreachable too.
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 2));
        let (_, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((icmp[0], icmp[1]), (3, 1));

        // Look the name up (raw DNS over UDP), then the address answers.
        let mut q = Message::new(99, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::A,
        ));
        raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (src, _, proto, u) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, proto), (GATEWAY, 17));
        assert_eq!(
            parse_dns(&u[8..], 99),
            (ResponseCode::NoError, vec![Ipv4Addr::new(198, 18, 0, 1)])
        );
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 3));
        let (src, dst, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!(
            (src, dst, icmp[0]),
            (Ipv4Addr::new(198, 18, 0, 1), me, 0),
            "an echo reply from the site"
        );

        // The gateway answers pings.
        raw.send(ping(me, GATEWAY, 4));
        let (src, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (GATEWAY, 0));

        // UDP to a site: port unreachable, so clients fail at once.
        raw.send(udp(me, 5000, Ipv4Addr::new(198, 18, 0, 1), 9999, b"x"));
        let (_, _, proto, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((proto, icmp[0], icmp[1]), (1, 3, 3));

        // An ICMP error gets no ICMP error back. IPv6 to the unspecified
        // address is dropped.
        let mut err = vec![3, 1, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..28]);
        let c = ip::checksum(&err);
        err[2..4].copy_from_slice(&c.to_be_bytes());
        raw.send(ipv4(me, Ipv4Addr::new(192, 0, 2, 1), 1, &err));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        v6.extend_from_slice(&[0; 32]);
        raw.send(Packet(v6));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn sandboxes_cannot_reach_each_other() {
    world(|fcx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();
        // Both bind their addresses with a ping to the gateway.
        a.send(ping(a_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        b.send(ping(b_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );

        // a to b: nothing arrives at b, and a hears nothing back.
        a.send(ping(a_addr, b_addr, 2));
        a.send(udp(a_addr, 1000, b_addr, 2000, b"hello"));
        // Nor to the subnet's broadcast address, or 255.255.255.255.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 255), 3));
        a.send(udp(a_addr, 1000, Ipv4Addr::BROADCAST, 2000, b"hello"));
        // Nor to an address in the subnet that no one has.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 77), 4));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(10))
                .await
                .is_none()
        );

        // Both still reach the gateway.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );
        Ok(())
    });
}

#[test]
fn spoofed_and_taken_sources_are_dropped() {
    world(|fcx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();

        // Sources a sandbox can never bind: outside the subnet, the
        // gateway, the network and broadcast addresses, 0.0.0.0.
        for src in [
            Ipv4Addr::new(192, 168, 1, 5),
            GATEWAY,
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ] {
            a.send(ping(src, GATEWAY, 1));
        }
        a.send(ping(Ipv4Addr::UNSPECIFIED, GATEWAY, 1));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());

        // a binds 10.0.0.2.
        a.send(ping(a_addr, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        // b cannot take it.
        b.send(ping(a_addr, GATEWAY, 3));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(10))
                .await
                .is_none()
        );
        // a cannot send from any other address now.
        a.send(ping(b_addr, GATEWAY, 4));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());
        // b binds 10.0.0.3, which a just tried to use.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );

        // When a detaches, its address is free again.
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        let mut freed = false;
        for seq in 0..50 {
            c.send(ping(a_addr, GATEWAY, seq));
            if recv_within(&fcx, &mut c, Duration::from_millis(50))
                .await
                .is_some()
            {
                freed = true;
                break;
            }
        }
        assert!(freed, "10.0.0.2 should be free once a detached");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: DHCP

fn dhcp_msg(kind: u8, xid: u32, mac: u8) -> dhcp::Message {
    let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, xid);
    m.chaddr[..6].copy_from_slice(&[2, 0, 0, 0, 0, mac]);
    m.push(dhcp::opt::MESSAGE_TYPE, [kind]);
    m
}

/// Sends a DHCP message from `src` to `dst` and returns the reply's IP
/// destination and message.
async fn dhcp_ask(
    fcx: &Cx,
    end: &mut End,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    m: &dhcp::Message,
) -> Option<(Ipv4Addr, dhcp::Message)> {
    end.send(udp(src, 68, dst, 67, &m.to_bytes().unwrap()));
    let p = recv_within(fcx, end, SHORT).await?;
    let (from, to, proto, u) = parse(&p);
    assert_eq!((from, proto), (GATEWAY, 17));
    assert_eq!(&u[..4], &[0, 67, 0, 68]);
    let reply = dhcp::Message::parse(&u[8..]).expect("a DHCP message");
    assert_eq!(reply.op, dhcp::BOOTREPLY);
    assert_eq!(reply.xid, m.xid);
    assert_eq!(reply.chaddr, m.chaddr);
    Some((to, reply))
}

#[test]
fn dhcp_lease_renewal_and_restart() {
    world(|fcx, attacher, _env| async move {
        let any = Ipv4Addr::UNSPECIFIED;
        let bc = Ipv4Addr::BROADCAST;
        let mut a = attacher.attach("a").unwrap();

        // DISCOVER from 0.0.0.0: OFFER of the lowest free address, with the
        // settings.
        let (to, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1))
            .await
            .expect("an offer");
        assert_eq!(to, bc);
        assert_eq!(offer.message_type(), Some(dhcp::OFFER));
        let addr = offer.yiaddr;
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(offer.option_addr(dhcp::opt::SERVER_ID), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::ROUTER), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        assert_eq!(
            offer.option_addr(dhcp::opt::SUBNET_MASK),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(offer.option_u32(dhcp::opt::LEASE_TIME), Some(3600));

        // The offer is held: another sandbox cannot bind it statically.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(addr, GATEWAY, 1));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        // b's own DISCOVER gets the next address, even if it asks for a's.
        let mut discover = dhcp_msg(dhcp::DISCOVER, 2, 2);
        discover.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, offer_b) = dhcp_ask(&fcx, &mut b, any, bc, &discover).await.unwrap();
        assert_eq!(offer_b.yiaddr, Ipv4Addr::new(10, 0, 0, 3));
        // b asking to bind a's address: NAK.
        let mut request = dhcp_msg(dhcp::REQUEST, 3, 2);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, nak) = dhcp_ask(&fcx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));

        // a takes its offer.
        let mut request = dhcp_msg(dhcp::REQUEST, 4, 1);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (to, ack) = dhcp_ask(&fcx, &mut a, any, bc, &request).await.unwrap();
        assert_eq!(to, bc);
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        assert_eq!(ack.yiaddr, addr);

        // Bound: pings from the address work, from others do not.
        a.send(ping(addr, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        a.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());

        // Renewal: unicast from the address, with ciaddr. ACK to the address.
        let mut renew = dhcp_msg(dhcp::REQUEST, 5, 1);
        renew.ciaddr = addr;
        let (to, ack) = dhcp_ask(&fcx, &mut a, addr, GATEWAY, &renew).await.unwrap();
        assert_eq!(
            (to, ack.message_type(), ack.yiaddr),
            (addr, Some(dhcp::ACK), addr)
        );
        // Rebinding: broadcast from the address.
        let (_, ack) = dhcp_ask(&fcx, &mut a, addr, bc, &renew).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        // DHCP from an address that is not a's: dropped.
        let mut other = dhcp_msg(dhcp::REQUEST, 6, 1);
        other.ciaddr = Ipv4Addr::new(10, 0, 0, 9);
        assert!(
            dhcp_ask(&fcx, &mut a, Ipv4Addr::new(10, 0, 0, 9), GATEWAY, &other)
                .await
                .is_none()
        );

        // Restart: from 0.0.0.0 again, the same address.
        let (_, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 7, 1))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, addr);
        // INIT-REBOOT for another address: NAK; for its own: ACK.
        let mut reboot = dhcp_msg(dhcp::REQUEST, 8, 1);
        reboot.push(
            dhcp::opt::REQUESTED_IP,
            Ipv4Addr::new(10, 0, 0, 20).octets(),
        );
        let (_, nak) = dhcp_ask(&fcx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));
        let mut reboot = dhcp_msg(dhcp::REQUEST, 9, 1);
        reboot.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!((ack.message_type(), ack.yiaddr), (Some(dhcp::ACK), addr));
        // The agent changing its MAC does not get it a second address.
        let (_, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 10, 99))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, addr);

        // A REQUEST naming another server is ignored.
        let mut elsewhere = dhcp_msg(dhcp::REQUEST, 11, 3);
        elsewhere.push(
            dhcp::opt::REQUESTED_IP,
            Ipv4Addr::new(10, 0, 0, 30).octets(),
        );
        elsewhere.push(dhcp::opt::SERVER_ID, Ipv4Addr::new(10, 0, 0, 254).octets());
        assert!(dhcp_ask(&fcx, &mut b, any, bc, &elsewhere).await.is_none());

        // b takes its offer; then a detaches, and a new sandbox asking for
        // a's old address gets it.
        let mut request = dhcp_msg(dhcp::REQUEST, 12, 2);
        request.push(dhcp::opt::REQUESTED_IP, offer_b.yiaddr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        let mut got = None;
        for xid in 100..150 {
            let mut d = dhcp_msg(dhcp::DISCOVER, xid, 4);
            d.push(dhcp::opt::REQUESTED_IP, addr.octets());
            let (_, offer) = dhcp_ask(&fcx, &mut c, any, bc, &d).await.unwrap();
            if offer.yiaddr == addr {
                got = Some(offer.yiaddr);
                break;
            }
            fcx.sleep(Duration::from_millis(20)).await?;
        }
        assert_eq!(got, Some(addr), "a's address is free once a detached");

        // INFORM from a static address: an ACK with the settings and no lease.
        let mut d = attacher.attach("d").unwrap();
        let d_addr = Ipv4Addr::new(10, 0, 0, 40);
        d.send(ping(d_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut d, Duration::from_secs(2))
                .await
                .is_some()
        );
        let mut inform = dhcp_msg(dhcp::INFORM, 13, 5);
        inform.ciaddr = d_addr;
        let (to, ack) = dhcp_ask(&fcx, &mut d, d_addr, GATEWAY, &inform)
            .await
            .unwrap();
        assert_eq!(
            (to, ack.message_type(), ack.yiaddr),
            (d_addr, Some(dhcp::ACK), Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(ack.option_u32(dhcp::opt::LEASE_TIME), None);
        assert_eq!(ack.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        // And DHCP to the server from a static sandbox asking for a lease
        // gets its static address.
        let (_, offer) = dhcp_ask(&fcx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 14, 5))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, d_addr);
        Ok(())
    });
}

#[test]
fn dhcp_messages_round_trip() {
    let mut m = dhcp_msg(dhcp::REQUEST, 0xdeadbeef, 7);
    m.ciaddr = Ipv4Addr::new(10, 0, 0, 5);
    m.push(dhcp::opt::REQUESTED_IP, [10, 0, 0, 5]);
    m.push(200, vec![1; 300]); // longer than one option entry
    let bytes = m.to_bytes().unwrap();
    assert!(bytes.len() >= 300);
    assert_eq!(dhcp::Message::parse(&bytes), Ok(m));
    assert_eq!(dhcp::Message::parse(&bytes[..239]), Err(dhcp::Error::Short));
}

#[test]
fn a_subnet_that_cannot_work_is_an_error() {
    let result = within(Duration::from_secs(10), || {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            for bad in [
                "10.0.0.0/31",
                "10.0.0.0/4",
                "fe80::/64",
                "ff00::/8",
                "::/8",
                "2001:db8::/127",
                "2001:db8::/4",
            ] {
                let (_attacher, attachments) = fictionet::attachments();
                let r = web::Sites::new(|_| None)
                    .subnet(bad.parse()?)
                    .start(&fcx, attachments);
                assert!(r.is_err(), "{bad}");
            }
            // Another subnet works, with its gateway at .1.
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|_| None)
                .subnet("172.16.5.0/24".parse()?)
                .start(&fcx, attachments)?;
            let mut a = attacher.attach("a").unwrap();
            let gw = Ipv4Addr::new(172, 16, 5, 1);
            a.send(ping(Ipv4Addr::new(172, 16, 5, 9), gw, 1));
            let (src, _, _, icmp) = parse(
                &recv_within(&fcx, &mut a, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!((src, icmp[0]), (gw, 0));
            Err(fictionet::Error::from(Done))
        }))
    });
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

#[test]
fn the_sites_keep_running_after_the_world_returns() {
    // The world returns Ok at once; the test plays the sandbox from a
    // thread of its own.
    let (attacher, attachments) = fictionet::attachments();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = block_on(run(fictionet::Seed::random(), move |fcx| async move {
            web::Sites::new(|h| (h == "plain.test").then(|| web::Site::new(Plain("plain"))))
                .start(&fcx, attachments)?;
            let _ = tx.send(fcx.clone());
            Ok(())
        }));
        let _ = r;
    });
    let fcx = rx.recv().unwrap();
    let mut a = attacher.attach("a").unwrap();
    let me = Ipv4Addr::new(10, 0, 0, 2);
    a.send(ping(me, GATEWAY, 1));
    let reply = within(Duration::from_secs(5), move || {
        block_on(async move { timeout(&fcx, Duration::from_secs(2), a.recv(&fcx)).await })
    });
    let (src, _, _, icmp) = parse(&reply.expect("a reply").unwrap());
    assert_eq!((src, icmp[0]), (GATEWAY, 0));
}

#[test]
fn the_target_is_from_the_connection_not_the_headers() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        let Client::H1(mut send) = Client::new(&fcx, conn, false).await else {
            unreachable!()
        };
        // An absolute URI with another scheme and port, and forwarding
        // headers: the Target still says https, secure.test, 443.
        send.ready().await.unwrap();
        let request = Request::get("http://secure.test:8080/")
            .header("host", "secure.test:8080")
            .header("x-forwarded-proto", "http")
            .header("forwarded", "proto=http;host=evil.test")
            .body(Empty::new())
            .unwrap();
        let response = send.send_request(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).starts_with("secure https secure.test 443 HTTP/1.1"),
            "{body:?}"
        );
        let _ = IpAddr::from(addr);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The proxy (feature tokio)

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_answers_502_when_the_real_site_cannot_be_reached() {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run(fictionet::Seed::random(), |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let upstream = web::proxy(&fcx)?;
            web::Sites::new(move |h| {
                (h == "nowhere.invalid").then(|| web::Site::new(upstream.clone()))
            })
            .start(&fcx, attachments)?;
            let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
            let addr = lookup(&fcx, &m, "nowhere.invalid").await;
            let conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 80))
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, false).await;
            let got = client.get("http", "nowhere.invalid", "/").await;
            assert_eq!(got.status, StatusCode::BAD_GATEWAY, "{}", got.body);
            assert!(got.body.contains("nowhere.invalid"), "{}", got.body);
            Err(fictionet::Error::from(Done))
        }),
    )
    .await
    .expect("timed out");
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// An axum handler that echoes WebSocket text messages.
#[cfg(feature = "tokio")]
fn echo_socket() -> axum::Router {
    use axum::extract::ws::{Message as Ws, WebSocketUpgrade};
    axum::Router::new().route(
        "/echo",
        axum::routing::get(|ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut socket| async move {
                while let Some(Ok(message)) = socket.recv().await {
                    if let Ws::Text(t) = message {
                        let _ = socket
                            .send(Ws::Text(format!("echo: {}", t.as_str()).into()))
                            .await;
                    }
                }
            })
        }),
    )
}

/// Makes a client's WebSocket handshake on `conn` for `host`, then sends
/// `text` and returns the first message back.
#[cfg(feature = "tokio")]
async fn websocket_echo<C: Connection>(
    fcx: &Cx,
    conn: &mut C,
    host: &str,
    text: &str,
) -> fictionet::stdlib::websocket::Message {
    use fictionet::stdlib::codec::{Stream, Wire};
    use fictionet::stdlib::websocket::{Message as Ws, Messages};
    let request = format!(
        "GET /echo HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    conn.write_all(fcx, request.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = conn.read(fcx, &mut buf).await.unwrap();
        assert!(
            n > 0,
            "the server closed during the handshake: {:?}",
            String::from_utf8_lossy(&got)
        );
        got.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8_lossy(&got[..head_end]).to_lowercase();
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(
        head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "{head}"
    );
    let frame = Ws::Text(text.to_owned())
        .to_frame(Some([1, 2, 3, 4]))
        .unwrap();
    conn.write_all(fcx, &frame.to_bytes().unwrap())
        .await
        .unwrap();
    let mut stream = Stream::new(Messages::new(fictionet::stdlib::codec::Side::Client));
    assert_eq!(stream.push(&got[head_end..]), got.len() - head_end);
    loop {
        if let Some(m) = stream.next() {
            return m.unwrap();
        }
        let n = conn.read(fcx, &mut buf).await.unwrap();
        assert!(n > 0, "the server closed the WebSocket");
        assert_eq!(stream.push(&buf[..n]), n);
    }
}

/// An axum `WebSocketUpgrade` handler on `web::Sites`: the handshake, then
/// messages both ways.
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websockets_work_through_sites() {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run(fictionet::Seed::random(), |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|h| (h == "ws.test").then(|| web::Site::new(echo_socket())))
                .start(&fcx, attachments)?;
            let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
            let addr = lookup(&fcx, &m, "ws.test").await;
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 80))
                .await
                .unwrap();
            let reply = websocket_echo(&fcx, &mut conn, "ws.test", "hello").await;
            assert_eq!(
                reply,
                fictionet::stdlib::websocket::Message::Text("echo: hello".into())
            );
            Err(fictionet::Error::from(Done))
        }),
    )
    .await
    .expect("timed out");
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

// ---------------------------------------------------------------------------
// Tests: an agent trying to wear the world down

/// An IPv4 fragment: `data` at byte `offset` of packet `id`.
fn fragment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    offset: usize,
    more: bool,
    data: &[u8],
) -> Packet {
    let mut p = ipv4(src, dst, proto, data);
    p.0[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    p.0[6..8].copy_from_slice(&flags.to_be_bytes());
    p.0[10..12].copy_from_slice(&[0, 0]);
    let c = ip::checksum(&p.0[..20]);
    p.0[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// Tens of thousands of first fragments that never complete, each a
/// different packet, must not stall the gateway for everyone else.
#[test]
fn a_flood_of_unfinished_fragments_does_not_stall_the_gateway() {
    real_world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );
        let started = std::time::Instant::now();
        for i in 0..60_000u32 {
            let proto = [17u8, 6, 1][(i % 3) as usize];
            raw.send(fragment(
                me,
                GATEWAY,
                proto,
                (i / 3) as u16,
                0,
                true,
                &[0; 8],
            ));
        }
        // A ping sent after the flood is answered once the gateway has gone
        // through every fragment before it. That must be quick.
        raw.send(ping(me, GATEWAY, 2));
        let reply = recv_within(&fcx, &mut raw, Duration::from_secs(5)).await;
        assert!(
            reply.is_some(),
            "no ping reply {:?} after the flood started",
            started.elapsed()
        );
        eprintln!("60,000 fragments went through in {:?}", started.elapsed());
        Ok(())
    });
}

/// A TCP segment with a good checksum.
#[allow(clippy::too_many_arguments)]
fn tcp_seg(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data: &[u8],
) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(data);
    let c = ip::transport_checksum(src.into(), dst.into(), 6, &t);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 6, &t)
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const RST: u8 = 0x04;
const FIN: u8 = 0x01;

/// Opens `n` TCP connections from `me` to `to`, in batches, by hand: SYN,
/// then an ACK for each SYN-ACK. Returns how many were set up, and the
/// ports (ours) of those the other side closed (FIN or RST) while the rest
/// were being opened. They then sit idle; the raw end never answers again
/// unless asked.
async fn open_idle(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    to: SocketAddr,
    n: u16,
) -> (usize, std::collections::BTreeSet<u16>) {
    let IpAddr::V4(dst) = to.ip() else {
        unreachable!()
    };
    let mut open = 0;
    let mut opened = std::collections::HashSet::new();
    let mut closed = std::collections::BTreeSet::new();
    for batch in (0..n).collect::<Vec<_>>().chunks(256) {
        for &i in batch {
            raw.send(tcp_seg(me, 10_000 + i, dst, to.port(), 1000, 0, SYN, &[]));
        }
        let mut left = batch.len();
        while left > 0 {
            let Some(p) = recv_within(fcx, raw, Duration::from_secs(5)).await else {
                break;
            };
            let (_, _, proto, t) = parse(&p);
            if proto != 6 {
                continue;
            }
            let sport = u16::from_be_bytes([t[2], t[3]]);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            if t[13] & (SYN | ACK) == SYN | ACK {
                raw.send(tcp_seg(
                    me,
                    sport,
                    dst,
                    to.port(),
                    1001,
                    seq.wrapping_add(1),
                    ACK,
                    &[],
                ));
                opened.insert(sport);
                open += 1;
                left -= 1;
            } else if t[13] & (FIN | RST) != 0 && opened.contains(&sport) {
                closed.insert(sport);
            } else if t[13] & RST != 0 {
                left -= 1;
            }
        }
    }
    (open, closed)
}

/// Measures thread CPU time for one HTTPS request from a fresh connection.
async fn timed_get(fcx: &Cx, m: &Machine, env: &Env) -> Duration {
    let started = fictionet::stdlib::test_support::thread_cpu_time();
    let conn = tls_connect(fcx, m, env, SECURE_ADDR, "secure.test", &[b"http/1.1"])
        .await
        .unwrap();
    let mut client = Client::new(fcx, conn, false).await;
    assert_eq!(
        client.get("https", "secure.test", "/").await.status,
        StatusCode::OK
    );
    fictionet::stdlib::test_support::thread_cpu_time() - started
}

/// Ports (ours) of the connections the other side closed (FIN or RST)
/// within `d`, counting each port once.
async fn closed_ports(fcx: &Cx, raw: &mut End, d: Duration) -> std::collections::BTreeSet<u16> {
    let mut closed = std::collections::BTreeSet::new();
    let until = std::time::Instant::now() + d;
    while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
        let Some(p) = recv_within(fcx, raw, left).await else {
            break;
        };
        let (_, _, proto, t) = parse(&p);
        if proto == 6 && t[13] & (FIN | RST) != 0 {
            closed.insert(u16::from_be_bytes([t[2], t[3]]));
        }
    }
    closed
}

/// One sandbox may hold only so many connections open at a machine the
/// others share. Past that, the machine resets new ones at once.
#[test]
fn one_sandbox_cannot_hold_thousands_of_connections_open() {
    real_world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        let (open, mut closed) = open_idle(
            &fcx,
            &mut raw,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            1000,
        )
        .await;
        assert_eq!(open, 1000);
        closed.extend(closed_ports(&fcx, &mut raw, Duration::from_secs(1)).await);
        assert_eq!(
            closed.len(),
            1000 - 256,
            "all past the first 256 are closed"
        );
        // The other sandbox is served as before.
        timed_get(&fcx, &b, &env).await;
        Ok(())
    });
}

/// One HTTP/1.0 request on a fresh connection. Reads to the end, and
/// gives back the connection without closing this side, so it stays in
/// CLOSE_WAIT. Returns the connection error if the request fails.
async fn get_and_hold(
    fcx: &Cx,
    m: &Machine,
    to: Ipv4Addr,
) -> Result<(String, tcp::TcpConnection), ConnError> {
    let mut conn = m.tcp.connect(fcx, SocketAddr::new(to.into(), 80)).await?;
    conn.write_all(fcx, b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n")
        .await?;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match conn.read(fcx, &mut buf).await {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e),
        }
    }
    Ok((String::from_utf8_lossy(&got).into_owned(), conn))
}

/// A connection the server closed but the sandbox never closed on its side
/// still counts against the sandbox's 256, so the sandbox cannot pile up
/// closing sockets on a machine the others share. Once it closes them,
/// it may connect again.
#[test]
fn connections_left_half_open_still_count() {
    real_world(|fcx, attacher, _env| async move {
        let a = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let to = lookup(&fcx, &a, "plain.test").await;
        let mut held = Vec::new();
        for i in 0..256 {
            let (text, conn) = get_and_hold(&fcx, &a, to)
                .await
                .unwrap_or_else(|e| panic!("connection {i} failed: {e}"));
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
            held.push(conn);
        }
        // The server closed all 256; the sandbox did not.
        for _ in 0..20 {
            assert!(
                get_and_hold(&fcx, &a, to)
                    .await
                    .is_err_and(|e| e == ConnError::Reset),
                "a connection past the 256 was served"
            );
        }
        // Another sandbox is served as before.
        let b = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&fcx, &b, "plain.test").await, to);
        let (text, _conn) = get_and_hold(&fcx, &b, to)
            .await
            .expect("the other sandbox is served");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        // Closing them frees the count.
        drop(held);
        let (text, _conn) = timeout(&fcx, Duration::from_secs(10), async {
            loop {
                match get_and_hold(&fcx, &a, to).await {
                    Ok(reply) => break reply,
                    Err(ConnError::Reset) => fcx.sleep(Duration::from_millis(10)).await.unwrap(),
                    Err(e) => panic!("the readiness request failed: {e}"),
                }
            }
        })
        .await
        .expect("the connection count was not freed");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        for _ in 0..20 {
            let (text, _conn) = get_and_hold(&fcx, &a, to)
                .await
                .expect("served again after closing");
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        }
        Ok(())
    });
}

/// A connection that never finishes its TLS handshake, never sends a
/// request on port 80, or sits idle on DNS over TCP, is closed after one
/// second.
#[test]
fn connections_that_send_nothing_are_closed() {
    run_world::real_world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        sites(&fcx)
            .sites
            .into_net()
            .limits(fictionet::stdlib::net::Limits {
                handshake: Duration::from_secs(1),
                dns_tcp_idle: Duration::from_secs(1),
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let plain = Ipv4Addr::new(198, 18, 0, 1);
        // Look the names up, over raw DNS, so their machines exist.
        for name in ["secure.test", "plain.test"] {
            let mut q = Message::new(7, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
            assert!(
                recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .is_some()
            );
        }
        let mut opened = std::collections::BTreeMap::new();
        for (n, to) in [
            SocketAddr::new(SECURE_ADDR.into(), 443),
            SocketAddr::new(plain.into(), 80),
            SocketAddr::new(GATEWAY.into(), 53),
        ]
        .into_iter()
        .enumerate()
        {
            let n = n as u16;
            // Ports 10000, 11000 and 12000.
            opened.insert(10_000 + n * 1000, std::time::Instant::now());
            raw.send(tcp_seg(
                me,
                10_000 + n * 1000,
                match to.ip() {
                    IpAddr::V4(a) => a,
                    _ => unreachable!(),
                },
                to.port(),
                1000,
                0,
                SYN,
                &[],
            ));
            let p = recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("a SYN-ACK");
            let (_, _, _, t) = parse(&p);
            assert_eq!(t[13] & (SYN | ACK), SYN | ACK);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            let IpAddr::V4(dst) = to.ip() else {
                unreachable!()
            };
            raw.send(tcp_seg(
                me,
                10_000 + n * 1000,
                dst,
                to.port(),
                1001,
                seq.wrapping_add(1),
                ACK,
                &[],
            ));
        }
        let deadline = fcx.now() + Duration::from_secs(10);
        let mut closed = std::collections::BTreeSet::new();
        while closed.len() < opened.len() {
            let packet = fcx
                .race(Some(deadline), raw.recv(&fcx))
                .await
                .expect("idle connections did not close")
                .unwrap();
            let (_, _, proto, t) = parse(&packet);
            if proto == 6 && t[13] & (FIN | RST) != 0 {
                let port = u16::from_be_bytes([t[2], t[3]]);
                let took = opened.get(&port).expect("an opened port").elapsed();
                assert!(
                    took >= Duration::from_secs(1),
                    "port {port} closed too early: {took:?}"
                );
                assert!(
                    took < Duration::from_secs(10),
                    "port {port} closed too late: {took:?}"
                );
                closed.insert(port);
            }
        }
        assert_eq!(
            closed.into_iter().collect::<Vec<_>>(),
            vec![10_000, 11_000, 12_000]
        );
        Ok(())
    });
}

/// One sandbox that sends SYNs and never finishes the handshakes must not
/// lock the others out of a site they share.
#[test]
fn a_syn_flood_from_one_sandbox_does_not_lock_out_the_others() {
    real_world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        for i in 0..2000u16 {
            raw.send(tcp_seg(me, 10_000 + i, SECURE_ADDR, 443, 1000, 0, SYN, &[]));
        }
        let mut synacks = 0;
        while let Some(p) = recv_within(&fcx, &mut raw, Duration::from_millis(500)).await {
            let (_, _, _, t) = parse(&p);
            if t[13] & (SYN | ACK) == SYN | ACK {
                synacks += 1;
            }
        }
        // Some got through, but not all: one address has a share of the
        // backlog, not all of it.
        assert!(synacks > 0 && synacks < 2000, "{synacks} SYN-ACKs");
        let r = timeout(&fcx, Duration::from_secs(5), timed_get(&fcx, &b, &env)).await;
        assert!(r.is_some(), "the other sandbox could not reach the site");
        Ok(())
    });
}

/// The median thread CPU time of five HTTPS requests from fresh connections.
async fn median_get(fcx: &Cx, m: &Machine, env: &Env) -> Duration {
    let mut times = Vec::new();
    for _ in 0..5 {
        times.push(timed_get(fcx, m, env).await);
    }
    times.sort();
    times[2]
}

/// A world whose callback opens a whole domain (`*.wild.test`, like the
/// `*.github.com` of the module docs) gets a machine and a route for every
/// name the agent tries. Ten thousand of them must not slow the network
/// down: lookups stay quick, and so does every other request.
#[test]
fn ten_thousand_sites_do_not_slow_the_network() {
    real_world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        let before = median_get(&fcx, &b, &env).await;
        let n = 10_000u32;
        for i in 0..n {
            let mut q = Message::new(i as u16, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(
                Name::from_ascii(format!("n{i}.wild.test")).unwrap(),
                RecordType::A,
            ));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        }
        let mut answers = 0;
        while answers < n
            && recv_within(&fcx, &mut raw, Duration::from_secs(10))
                .await
                .is_some()
        {
            answers += 1;
        }
        assert_eq!(answers, n);
        // The last site answers.
        let last = Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + n);
        raw.send(ping(me, last, 1));
        let (src, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (last, 0));
        let after = median_get(&fcx, &b, &env).await;
        assert!(
            after < before * 3,
            "a request took {before:?} before and {after:?} after"
        );
        Ok(())
    });
}

/// A name the callback would accept, but that was never looked up, is
/// not served anywhere: not by Host, not by `:authority`, not by SNI. And
/// asking does not run the callback.
#[test]
fn a_name_never_looked_up_is_not_served_by_host_or_sni() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        let wild = lookup(&fcx, &m, "one.wild.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            assert_eq!(
                client.get("https", "two.wild.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
        }
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(wild.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "one.wild.test", "/").await.body,
            "wild http one.wild.test 80 HTTP/1.1 /"
        );
        assert_eq!(
            client.get("http", "two.wild.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        match tls_connect(&fcx, &m, &env, addr, "two.wild.test", &[b"h2"]).await {
            Err(TlsError::Tls(rustls::Error::AlertReceived(
                rustls::AlertDescription::UnrecognisedName,
            ))) => {}
            Err(e) => panic!("expected unrecognized_name, got {e:?}"),
            Ok(_) => panic!("the handshake should fail"),
        }
        assert_eq!(
            env.calls.load(Ordering::SeqCst),
            calls,
            "the callback ran for a name seen only in HTTP or TLS"
        );
        Ok(())
    });
}

/// A thousand requests at once on one HTTP/2 connection, more than the
/// 200 streams the server allows at a time, and streams the client
/// cancels as soon as it opens them.
#[test]
fn http2_with_a_thousand_streams_and_cancelled_ones() {
    real_world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2"])
            .await
            .unwrap();
        let client = Client::new(&fcx, conn, true).await;
        let Client::H2(send) = &client else {
            unreachable!()
        };
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for i in 0..1000 {
            let mut c = Client::H2(send.clone());
            tasks.push(fcx.spawn(move |fcx| async move {
                if i % 10 == 0 {
                    // Opened and dropped at once: the client resets it.
                    let Client::H2(s) = &mut c else {
                        unreachable!()
                    };
                    s.ready().await.unwrap();
                    let r = Request::get("https://secure.test/x")
                        .body(Empty::new())
                        .unwrap();
                    let fut = s.send_request(r);
                    let _ = timeout(&fcx, Duration::from_micros(1), fut).await;
                } else {
                    let got = c.get("https", "secure.test", "/x").await;
                    assert_eq!(got.status, StatusCode::OK);
                }
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        eprintln!("1,000 streams in {:?}", started.elapsed());
        assert!(env.served.load(Ordering::SeqCst) >= 900);
        // The connection still works.
        let mut c = Client::H2(send.clone());
        assert_eq!(
            c.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}

/// DNS messages an agent might send to break the server: garbage, cut-off
/// headers, a pointer loop, counts that lie, a response, a huge query in
/// fragments, the same over TCP with lengths that lie. The server stays up
/// and answers a good query after each.
#[test]
fn malformed_dns_does_not_break_the_server() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let good = {
            let mut q = Message::new(4242, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(
                Name::from_ascii("secure.test").unwrap(),
                RecordType::A,
            ));
            q.to_vec().unwrap()
        };
        let mut bad: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x12],
            vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01],
            // A question whose name points at itself.
            vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1],
            // 65,535 questions claimed, one given.
            {
                let mut m = good.clone();
                m[4..6].copy_from_slice(&[0xff, 0xff]);
                m
            },
            // A response, not a query.
            {
                let mut m = good.clone();
                m[2] |= 0x80;
                m
            },
            // A label of 63 bytes, repeated past 255.
            {
                let mut m = vec![0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                for _ in 0..8 {
                    m.push(63);
                    m.extend_from_slice(&[b'a'; 63]);
                }
                m.extend_from_slice(&[0, 0, 1, 0, 1]);
                m
            },
        ];
        for _ in 0..200 {
            let len = (fcx.random_u64() % 600) as usize;
            bad.push((0..len).map(|_| fcx.random_u64() as u8).collect());
        }
        for m in &bad {
            raw.send(udp(me, 5353, GATEWAY, 53, m));
        }
        // A 29,000-byte query in fragments: the question, then a TXT
        // record of padding.
        let mut big = good.clone();
        big[11] = 1; // one additional record
        big.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0]); // root, TXT, IN, TTL 0
        big.extend_from_slice(&29_000u16.to_be_bytes());
        big.extend(std::iter::repeat_n(b'x', 29_000));
        let whole = udp(me, 5354, GATEWAY, 53, &big);
        let payload = &whole.0[20..];
        let mut at = 0;
        while at < payload.len() {
            let n = 1480.min(payload.len() - at);
            raw.send(fragment(
                me,
                GATEWAY,
                17,
                777,
                at,
                at + n < payload.len(),
                &payload[at..at + n],
            ));
            at += n;
        }
        // Then the good query: its answer must come.
        raw.send(udp(me, 5355, GATEWAY, 53, &good));
        let mut answered = false;
        while let Some(p) = recv_within(&fcx, &mut raw, Duration::from_secs(2)).await {
            let (_, _, proto, u) = parse(&p);
            if proto == 17 && u16::from_be_bytes([u[2], u[3]]) == 5355 {
                assert_eq!(
                    parse_dns(&u[8..], 4242),
                    (ResponseCode::NoError, vec![SECURE_ADDR])
                );
                answered = true;
                break;
            }
        }
        assert!(answered, "no answer to a good query after the bad ones");

        // Over TCP: a length that promises more than comes, then garbage,
        // on separate connections; then a good query on a new one.
        let b = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        let dns_tcp = SocketAddr::new(GATEWAY.into(), 53);
        let mut c1 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        c1.write_all(&fcx, &[0xff, 0xff, 1, 2, 3]).await.unwrap();
        let mut c2 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        c2.write_all(&fcx, &[0, 3, 1, 2, 3, 0, 0]).await.unwrap();
        let mut c3 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        let mut framed = (good.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&good);
        c3.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut c3, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&fcx, &mut c3, &mut reply).await;
        assert_eq!(
            parse_dns(&reply, 4242),
            (ResponseCode::NoError, vec![SECURE_ADDR])
        );
        Ok(())
    });
}

/// When a sandbox detaches, what the sites still had for it must not reach
/// the next sandbox that takes its address: the connections are ended.
#[test]
fn a_detached_sandboxs_traffic_does_not_reach_the_next_holder_of_its_address() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // a looks plain.test up and opens a connection by hand.
        let mut q = Message::new(1, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::A,
        ));
        a.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (_, _, _, u) = parse(
            &recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        let plain = parse_dns(&u[8..], 1).1[0];
        a.send(tcp_seg(me, 40_000, plain, 80, 1000, 0, SYN, &[]));
        let (_, _, _, t) = parse(
            &recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        // The request, then a detaches before taking the answer.
        let request = b"GET /secret HTTP/1.1\r\nHost: plain.test\r\n\r\n";
        a.send(tcp_seg(
            me,
            40_000,
            plain,
            80,
            1001,
            seq.wrapping_add(1),
            ACK,
            request,
        ));
        let sent = fcx
            .events()
            .wait(&fcx, 1, Duration::from_secs(10), |e| {
                e.is("http", "request") && e.str("path") == Some("/secret")
            })
            .await?;
        assert_eq!(sent.len(), 1, "the request was served before detaching");
        drop(a);

        // b takes the same address as soon as it is free.
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for i in 0..100 {
            b.send(ping(me, GATEWAY, i));
            if recv_within(&fcx, &mut b, Duration::from_millis(20))
                .await
                .is_some()
            {
                bound = true;
                break;
            }
        }
        assert!(bound);
        // Nothing of a's answer reaches b, even after retransmissions.
        while let Some(p) = recv_within(&fcx, &mut b, Duration::from_secs(3)).await {
            let (src, _, proto, t) = parse(&p);
            if proto == 6 {
                let data = &t[((t[12] >> 4) as usize) * 4..];
                assert!(
                    data.is_empty(),
                    "b got {} bytes of a's answer from {src}: {:?}",
                    data.len(),
                    String::from_utf8_lossy(data)
                );
            }
        }
        Ok(())
    });
}

/// A TLS hello that never ends, or is garbage, closes that connection and
/// nothing else.
#[test]
fn a_huge_or_garbage_tls_hello_closes_only_that_connection() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&fcx, &m, "secure.test").await;
        let to = SocketAddr::new(addr.into(), 443);
        // A handshake record header that promises 16 KiB, repeated: a hello
        // far larger than any real one.
        let mut huge = m.tcp.connect(&fcx, to).await.unwrap();
        let mut record = vec![22, 3, 1, 0x40, 0];
        record.extend(std::iter::repeat_n(0u8, 0x4000));
        let mut closed = false;
        for _ in 0..32 {
            if huge.write_all(&fcx, &record).await.is_err() {
                closed = true;
                break;
            }
        }
        let mut buf = [0u8; 64];
        let end = timeout(&fcx, Duration::from_secs(2), huge.read(&fcx, &mut buf)).await;
        assert!(
            closed || matches!(end, Some(Ok(0)) | Some(Err(_))),
            "the huge hello was not refused: {end:?}"
        );
        // Plain garbage.
        let mut junk = m.tcp.connect(&fcx, to).await.unwrap();
        junk.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            .await
            .unwrap();
        let end = timeout(&fcx, Duration::from_secs(2), junk.read(&fcx, &mut buf)).await;
        assert!(
            matches!(end, Some(Ok(0)) | Some(Err(_))),
            "garbage was not refused: {end:?}"
        );
        // A real client is still served.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: fix round 1

/// Runs a world whose sites use `subnet`, with every `.test` name a plain
/// site at an automatic address.
fn world_on_subnet<F, Fut>(subnet: &str, f: F)
where
    F: FnOnce(Cx, Attacher) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let subnet: fictionet::stdlib::route::Prefix = subnet.parse().unwrap();
    run_world::world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet(subnet)
        .start(&fcx, attachments)?;
        f(fcx, attacher).await?;
        Ok(())
    });
}

/// A DNS A query from `me` to `gw` on a raw attachment: the answer's code
/// and addresses, or `None` if none came within 2 s.
async fn raw_dns(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    gw: Ipv4Addr,
    name: &str,
    id: u16,
) -> Option<(ResponseCode, Vec<Ipv4Addr>)> {
    let mut q = Message::new(id, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    raw.send(udp(me, 5353, gw, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2)).await?;
        let (src, _, proto, u) = parse(&p);
        if src == gw && proto == 17 {
            return Some(parse_dns(&u[8..], id));
        }
    }
}

/// A subnet inside `198.18.0.0/15`: automatic addresses skip it, so the
/// first site does not take the gateway's address and DNS keeps answering.
#[test]
fn automatic_addresses_skip_the_sandboxes_subnet() {
    world_on_subnet("198.18.0.0/24", |fcx, attacher| async move {
        let gw = Ipv4Addr::new(198, 18, 0, 1);
        let me = Ipv4Addr::new(198, 18, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (code, first) = raw_dns(&fcx, &mut raw, me, gw, "one.test", 1)
            .await
            .expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(first, vec![Ipv4Addr::new(198, 18, 1, 0)]);
        let (_, second) = raw_dns(&fcx, &mut raw, me, gw, "two.test", 2)
            .await
            .expect("DNS still answers");
        assert_eq!(second, vec![Ipv4Addr::new(198, 18, 1, 1)]);
        // The gateway still answers pings, and so does the site.
        for (to, seq) in [(gw, 1), (first[0], 2)] {
            raw.send(ping(me, to, seq));
            let p = recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("an echo reply");
            let (from, _, proto, icmp) = parse(&p);
            assert_eq!((from, proto, icmp[0]), (to, 1, 0));
        }
        Ok(())
    });
}

/// A sandbox with a static address whose first packet is a DHCPINFORM gets
/// the settings, and the INFORM binds nothing.
#[test]
fn dhcp_inform_as_the_first_packet_is_answered() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 9);
        let mut a = attacher.attach("a").unwrap();
        let mut m = dhcp_msg(dhcp::INFORM, 7, 1);
        m.ciaddr = me;
        let (to, reply) = dhcp_ask(&fcx, &mut a, me, GATEWAY, &m)
            .await
            .expect("an answer to INFORM");
        assert_eq!(to, me);
        assert_eq!(reply.message_type(), Some(dhcp::ACK));
        assert_eq!(reply.option_addr(dhcp::opt::DNS), Some(GATEWAY));

        // Not bound: another sandbox can still take 10.0.0.9.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_some(),
            "b binds 10.0.0.9"
        );
        // Now a's INFORM from 10.0.0.9 is not answered, and neither is its ping.
        assert!(dhcp_ask(&fcx, &mut a, me, GATEWAY, &m).await.is_none());
        a.send(ping(me, GATEWAY, 2));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());
        Ok(())
    });
}

/// Reads `conn` to its end.
async fn read_all<C: Connection>(fcx: &Cx, conn: &mut C) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match timeout(fcx, Duration::from_secs(5), conn.read(fcx, &mut buf))
            .await
            .expect("the response ends")
        {
            Ok(0) | Err(_) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
        }
    }
}

/// A body whose length the handler knows goes out with `content-length`;
/// one that streams goes out chunked on HTTP/1.1.
#[test]
fn a_known_length_is_sent_as_content_length() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&fcx, &m, "plain.test").await;
        let events = lookup(&fcx, &m, "events.test").await;
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        conn.write_all(
            &fcx,
            b"GET /len HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let got = String::from_utf8(read_all(&fcx, &mut conn).await)
            .unwrap()
            .to_lowercase();
        let body = "plain http plain.test 80 HTTP/1.1 /len";
        assert!(
            got.contains(&format!("content-length: {}\r\n", body.len())),
            "{got:?}"
        );
        assert!(!got.contains("transfer-encoding"), "{got:?}");
        // axum's 4 MiB Vec has a known length too, over TLS.
        let conn = tls_connect(&fcx, &m, &env, events, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("https", "events.test", "/big").await;
        assert_eq!(got.headers["content-length"], BIG.to_string());
        assert_eq!(got.body.len(), BIG);
        Ok(())
    });
}

/// A `HEAD` request gets the headers a `GET` would, `content-length`
/// included, and no body, over HTTP/2 as well as HTTP/1.1. hyper sends a
/// handler's body on HTTP/2 even for `HEAD`, which breaks the stream.
#[test]
fn head_gets_the_headers_and_no_body_on_both_versions() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let secure = lookup(&fcx, &m, "secure.test").await;
        let events = lookup(&fcx, &m, "events.test").await;
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, secure, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            let get = client.get("https", "secure.test", "/x").await;
            let head = client
                .send(http::Method::HEAD, "https", "secure.test", "/x")
                .await;
            assert_eq!(
                (head.status, head.body.as_str()),
                (StatusCode::OK, ""),
                "h2 {h2}"
            );
            // The page ends with a request count, #1 then #2: same length.
            assert_eq!(
                head.headers["content-length"],
                get.body.len().to_string(),
                "h2 {h2}"
            );
            // A whole 4 MiB body is left out too, and so is Sites' own 421.
            let conn = tls_connect(&fcx, &m, &env, events, "events.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            let big = client
                .send(http::Method::HEAD, "https", "events.test", "/big")
                .await;
            assert_eq!((big.status, big.body.len()), (StatusCode::OK, 0), "h2 {h2}");
            assert_eq!(big.headers["content-length"], BIG.to_string(), "h2 {h2}");
            let other = client
                .send(http::Method::HEAD, "https", "secure.test", "/")
                .await;
            assert_eq!(
                (other.status, other.body.len()),
                (StatusCode::MISDIRECTED_REQUEST, 0),
                "h2 {h2}"
            );
            // The connection still works after them.
            assert_eq!(
                client.get("https", "events.test", "/page").await.status,
                StatusCode::OK,
                "h2 {h2}"
            );
        }
        Ok(())
    });
}

/// A request whose host names no site at the address goes to the
/// address's `default_host`, if it has one: an address typed as the host,
/// or any other name. A site that has its own name there keeps it.
#[test]
fn the_default_host_answers_hosts_with_no_site_of_their_own() {
    world(|fcx, attacher, _env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&fcx, &m, "default.test").await, DEFAULT_ADDR);
        assert_eq!(lookup(&fcx, &m, "other.test").await, DEFAULT_ADDR);
        let ask =
            |host: &str| format!("GET /p HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        for (host, want) in [
            ("203.0.113.40", "default http 203.0.113.40 80 HTTP/1.1 /p"),
            ("unknown.test", "default http unknown.test 80 HTTP/1.1 /p"),
            ("default.test", "default http default.test 80 HTTP/1.1 /p"),
            ("other.test", "other http other.test 80 HTTP/1.1 /p"),
        ] {
            let got =
                String::from_utf8(raw_http(&fcx, &m, DEFAULT_ADDR, ask(host).as_bytes()).await)
                    .unwrap();
            assert!(
                got.starts_with("HTTP/1.1 200 OK") && got.ends_with(want),
                "{host}: {got:?}"
            );
        }
        // A TLS site that is the default redirects plain HTTP to https, at
        // the host the client named.
        assert_eq!(lookup(&fcx, &m, "tls-default.test").await, TLS_DEFAULT_ADDR);
        let got = String::from_utf8(
            raw_http(&fcx, &m, TLS_DEFAULT_ADDR, ask("203.0.113.41").as_bytes()).await,
        )
        .unwrap();
        assert!(got.starts_with("HTTP/1.1 301"), "{got:?}");
        assert!(
            got.to_lowercase()
                .contains("location: https://203.0.113.41/p\r\n"),
            "{got:?}"
        );
        // Without a default, the same request gets 421.
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let got = String::from_utf8(
            raw_http(&fcx, &m, SECURE_ADDR, ask("203.0.113.10").as_bytes()).await,
        )
        .unwrap();
        assert!(got.starts_with("HTTP/1.1 421"), "{got:?}");
        Ok(())
    });
}

/// A client that sends its request and then shuts down its side (as
/// `nc -N` and HTTP/1.0 scripts do) still gets the response, over plain
/// HTTP and over TLS.
#[test]
fn a_client_that_half_closes_after_its_request_gets_the_response() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&fcx, &m, "plain.test").await;
        let secure = lookup(&fcx, &m, "secure.test").await;
        let requests: [&[u8]; 2] = [
            b"GET /h HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
            b"GET /h HTTP/1.0\r\nHost: plain.test\r\n\r\n",
        ];
        for request in requests {
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(plain.into(), 80))
                .await
                .unwrap();
            conn.write_all(&fcx, request).await.unwrap();
            conn.shutdown(&fcx).await.unwrap();
            let got = String::from_utf8(read_all(&fcx, &mut conn).await).unwrap();
            assert!(
                got.starts_with("HTTP/1.") && got.contains(" 200 OK"),
                "{request:?} got {got:?}"
            );
            assert!(got.contains("plain http plain.test 80"), "{got:?}");
        }
        let mut conn = tls_connect(&fcx, &m, &env, secure, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        conn.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        conn.shutdown(&fcx).await.unwrap();
        let got = String::from_utf8(read_all(&fcx, &mut conn).await).unwrap();
        assert!(got.starts_with("HTTP/1.1 200 OK"), "{got:?}");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: events

/// A test world's event log, read from a mark the test moves past the
/// events it has checked.
#[derive(Clone)]
struct Log {
    events: EventLog,
    from: Arc<AtomicU64>,
}

impl Log {
    fn new(fcx: &Cx) -> Log {
        Log {
            events: fcx.events(),
            from: Arc::default(),
        }
    }

    /// Moves the mark past every event so far.
    fn clear(&self) {
        self.from.store(self.events.recorded(), Ordering::SeqCst);
    }
}

/// [`world`], with the run's event log.
fn world_events<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let t = sites(&fcx);
        let env = t.serve_with(&fcx, attachments)?;
        let log = Log::new(&fcx);
        f(fcx, attacher, env, log).await?;
        Ok(())
    });
}

/// The events after the log's mark that `pick` keeps.
fn picked<T>(log: &Log, pick: impl FnMut(&Entry) -> Option<T>) -> Vec<T> {
    log.events
        .after(log.from.load(Ordering::SeqCst), usize::MAX)
        .iter()
        .filter_map(pick)
        .collect()
}

/// Waits up to 5 s until `pick` keeps `n` events after the log's mark,
/// and returns them.
async fn wait_for<T>(
    fcx: &Cx,
    log: &Log,
    n: usize,
    mut pick: impl FnMut(&Entry) -> Option<T>,
) -> Vec<T> {
    let from = log.from.load(Ordering::SeqCst);
    let got = log
        .events
        .wait(fcx, n, Duration::from_secs(5), |e| {
            e.seq > from && pick(e).is_some()
        })
        .await
        .expect("the world stopped");
    if got.len() < n {
        panic!("fewer than {n} such events: {:#?}", log.events.all());
    }
    got.iter().filter_map(pick).collect()
}

fn is(s: &Sandbox, name: &str, addr: Option<Ipv4Addr>) -> bool {
    &*s.name == name && s.addr == addr
}

/// The sandbox an event names.
fn sandbox_of(e: &Entry) -> Option<&Sandbox> {
    e.conn.sandbox.as_ref()
}

/// Picks the events of `source`'s `kind`.
fn seen(source: &'static str, kind: &'static str) -> impl FnMut(&Entry) -> Option<Entry> {
    move |e| e.is(source, kind).then(|| e.clone())
}

fn dns_seen(e: &Entry) -> Option<Entry> {
    seen("dns", "query")(e)
}

fn tls_seen(e: &Entry) -> Option<Entry> {
    seen("tls", "handshake")(e)
}

fn http_seen(e: &Entry) -> Option<Entry> {
    seen("http", "request")(e)
}

fn error_seen(e: &Entry) -> Option<Entry> {
    seen("http", "error")(e)
}

fn blocked_seen(e: &Entry) -> Option<Entry> {
    seen("net", "blocked")(e)
}

/// The field `name` as an address.
fn addr(e: &Entry, name: &str) -> Option<IpAddr> {
    e.str(name)?.parse().ok()
}

/// Whether the field `name` is true.
fn flag(e: &Entry, name: &str) -> bool {
    e.get(name).and_then(|v| v.as_bool()) == Some(true)
}

/// The address and port an event's connection arrived on.
fn local(e: &Entry) -> SocketAddr {
    e.conn
        .local
        .expect("a connection's event names its address")
}

/// A DNS event's answer, as `addr 192.0.2.1`, `nodata`, `nxdomain`,
/// `error 1` or `none`.
fn answer(e: &Entry) -> String {
    match e.str("answer") {
        Some("addr") => format!("addr {}", e.str("addr").unwrap_or_default()),
        Some("error") => format!("error {}", e.u64("rcode").unwrap_or_default()),
        Some(other) => other.to_owned(),
        None => "none".to_owned(),
    }
}

/// A TLS event's outcome, with its `alpn`, `alert_code` or nothing after a
/// space: `accepted h2`, `alert 48`, `rejected`.
fn outcome(e: &Entry) -> String {
    match e.str("outcome") {
        Some("accepted") => format!("accepted {}", e.str("alpn").unwrap_or("-")),
        Some("alert") => format!("alert {}", e.u64("alert_code").unwrap_or_default()),
        Some(other) => other.to_owned(),
        None => "none".to_owned(),
    }
}

/// How many fields a handler added to an HTTP event.
fn extra(e: &Entry) -> usize {
    let standard = [
        "scheme", "sni", "host", "method", "uri", "path", "query", "version", "headers", "started",
        "answer", "status", "sent", "complete",
    ];
    e.fields
        .iter()
        .filter(|(n, _)| !standard.contains(n))
        .count()
}

/// A `net.blocked` event's `why`, sandbox address, protocol, source,
/// destination and destination port.
type BlockedRow<'a> = (
    &'a str,
    Option<Ipv4Addr>,
    Option<u64>,
    Option<IpAddr>,
    Option<IpAddr>,
    Option<u64>,
);

fn blocked_row(e: &Entry) -> BlockedRow<'_> {
    (
        e.str("why").unwrap_or_default(),
        sandbox_of(e).and_then(|s| s.addr),
        e.u64("protocol"),
        addr(e, "src"),
        addr(e, "dst"),
        e.u64("dst_port"),
    )
}

#[test]
fn events_attach_bind_and_detach() {
    world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        a.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );

        // A sandbox that gets its address from DHCP.
        let (any, bc) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let mut d = attacher.attach("d").unwrap();
        let (_, offer) = dhcp_ask(&fcx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1))
            .await
            .expect("an offer");
        let got = offer.yiaddr;
        let mut request = dhcp_msg(dhcp::REQUEST, 1, 1);
        request.push(dhcp::opt::REQUESTED_IP, got.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut d, any, bc, &request)
            .await
            .expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        // A renewal binds nothing new.
        let mut renew = dhcp_msg(dhcp::REQUEST, 2, 1);
        renew.ciaddr = got;
        let (_, ack) = dhcp_ask(&fcx, &mut d, got, GATEWAY, &renew)
            .await
            .expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;

        let of = |name: &str| {
            picked(&log, |e| {
                (e.source == "net" && &*sandbox_of(e)?.name == name).then(|| e.clone())
            })
        };
        let a_events = of("a");
        let kinds: Vec<_> = a_events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["attached", "bound", "detached"], "{a_events:#?}");
        let sandbox = |e: &Entry| sandbox_of(e).unwrap().clone();
        assert!(is(&sandbox(&a_events[0]), "a", None) && sandbox(&a_events[0]).id == 1);
        assert!(is(&sandbox(&a_events[1]), "a", Some(me)) && !flag(&a_events[1], "by_dhcp"));
        assert!(is(&sandbox(&a_events[2]), "a", Some(me)) && sandbox(&a_events[2]).id == 1);

        let d_events = of("d");
        assert!(
            d_events[0].is("net", "attached")
                && is(&sandbox(&d_events[0]), "d", None)
                && sandbox(&d_events[0]).id == 2
        );
        let bound: Vec<_> = d_events.iter().filter(|e| e.kind == "bound").collect();
        assert_eq!(bound.len(), 1, "{d_events:#?}");
        assert!(is(&sandbox(bound[0]), "d", Some(got)) && flag(bound[0], "by_dhcp"));
        Ok(())
    });
}

/// Opens a TCP connection by hand from a raw sandbox to `to`, and sends
/// `data` on it. Returns our port and the next sequence numbers (ours,
/// theirs).
async fn raw_connect(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    to: SocketAddr,
    port: u16,
    data: &[u8],
) -> (u32, u32) {
    let IpAddr::V4(dst) = to.ip() else {
        unreachable!()
    };
    raw.send(tcp_seg(me, port, dst, to.port(), 1000, 0, SYN, &[]));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2))
            .await
            .expect("a SYN-ACK");
        let (_, _, proto, t) = parse(&p);
        if proto == 6 && t[13] & (SYN | ACK) == SYN | ACK {
            let theirs = u32::from_be_bytes([t[4], t[5], t[6], t[7]]).wrapping_add(1);
            raw.send(tcp_seg(me, port, dst, to.port(), 1001, theirs, ACK, &[]));
            if !data.is_empty() {
                raw.send(tcp_seg(me, port, dst, to.port(), 1001, theirs, ACK, data));
            }
            return (1001 + data.len() as u32, theirs);
        }
    }
}

#[test]
fn events_name_each_attachment_by_id() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&fcx, &mut a, me, GATEWAY, "slow.test", 1)
            .await
            .unwrap();
        let slow = addrs[0];
        let _ = raw_dns(&fcx, &mut a, me, GATEWAY, "secure.test", 2)
            .await
            .unwrap();
        // A request whose handler never answers, and a TLS handshake that
        // never starts, both still open when the sandbox detaches.
        raw_connect(
            &fcx,
            &mut a,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            30_001,
            &[],
        )
        .await;
        raw_connect(
            &fcx,
            &mut a,
            me,
            SocketAddr::new(slow.into(), 80),
            30_000,
            b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n",
        )
        .await;
        wait::until(&fcx, Duration::from_secs(10), || {
            env.waiting.load(Ordering::SeqCst) == 1
        })
        .await;
        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;

        // The same name and address again: a new id.
        let mut a = attacher.attach("a").unwrap();
        let _ = raw_dns(&fcx, &mut a, me, GATEWAY, "secure.test", 3)
            .await
            .unwrap();

        let http = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                http[0].str("answer"),
                http[0].u64("status"),
                flag(&http[0], "complete")
            ),
            (Some("cancelled"), None, false)
        );
        assert_eq!(
            (
                sandbox_of(&http[0]).unwrap().id,
                http[0].str("host"),
                http[0].str("path")
            ),
            (1, Some("slow.test"), Some("/wait"))
        );
        assert_eq!(local(&http[0]), SocketAddr::from((slow, 80)));
        let tls = wait_for(&fcx, &log, 1, tls_seen).await;
        assert_eq!(
            (sandbox_of(&tls[0]).unwrap().id, outcome(&tls[0])),
            (1, "detached".to_owned())
        );
        let dns = wait_for(&fcx, &log, 3, dns_seen).await;
        let ids: Vec<u64> = dns.iter().map(|d| sandbox_of(d).unwrap().id).collect();
        assert_eq!(ids, vec![1, 1, 2]);
        assert!(
            dns.iter()
                .all(|d| is(sandbox_of(d).unwrap(), "a", Some(me)))
        );
        let attached = picked(&log, |e| {
            e.is("net", "attached").then(|| sandbox_of(e).unwrap().id)
        });
        assert_eq!(attached, vec![1, 2]);
        Ok(())
    });
}

#[test]
fn events_for_dns_queries() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, &attacher, "a", me);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "Secure.Test.").await, SECURE_ADDR);
        assert_eq!(
            dns(&fcx, &m, "secure.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::A).await.0,
            ResponseCode::NXDomain
        );

        // Over TCP.
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY.into(), 53))
            .await
            .unwrap();
        let mut q = Message::new(7, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("nope.test").unwrap(),
            RecordType::A,
        ));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut conn, &mut len).await;

        let mut socket = m.udp.bind(4444).unwrap();
        let gw = SocketAddr::new(GATEWAY.into(), 53);
        // A message with a header but nothing readable after it: FORMERR.
        socket.send_to(&[0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff], gw);
        let (reply, _) = timeout(&fcx, Duration::from_secs(2), socket.recv(&fcx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Two questions in one message: FORMERR, and no name.
        let mut q = Message::new(10, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("secure.test").unwrap(),
            RecordType::A,
        ));
        q.add_query(Query::query(
            Name::from_ascii("nope.test").unwrap(),
            RecordType::A,
        ));
        socket.send_to(&q.to_vec().unwrap(), gw);
        let (reply, _) = timeout(&fcx, Duration::from_secs(2), socket.recv(&fcx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Too short to answer at all.
        socket.send_to(b"xx", gw);

        let got = wait_for(&fcx, &log, 8, dns_seen).await;
        assert!(
            got.iter()
                .all(|d| is(sandbox_of(d).unwrap(), "a", Some(me))),
            "{got:#?}"
        );
        let summary: Vec<_> = got
            .iter()
            .map(|d| (flag(d, "tcp"), d.str("name"), d.u64("qtype"), answer(d)))
            .collect();
        let a = |s: &str| s.to_owned();
        assert_eq!(
            summary,
            vec![
                (
                    false,
                    Some("secure.test"),
                    Some(1),
                    format!("addr {SECURE_ADDR}")
                ),
                // Seen before: the callback does not run, the query is still an event.
                (
                    false,
                    Some("secure.test"),
                    Some(1),
                    format!("addr {SECURE_ADDR}")
                ),
                (false, Some("secure.test"), Some(28), a("addr 2001:2::1")),
                (false, Some("nope.test"), Some(1), a("nxdomain")),
                (true, Some("nope.test"), Some(1), a("nxdomain")),
                (false, None, None, a("error 1")),
                (false, None, None, a("error 1")),
                (false, None, None, a("none")),
            ]
        );
        assert_eq!(env.calls.load(Ordering::SeqCst), 2);
        Ok(())
    });
}

/// A rustls client config that trusts `roots`.
fn client_config(roots: &Arc<RootCertStore>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(tls::crypto_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

#[test]
fn events_for_tls_handshakes() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, &attacher, "a", me);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "shared.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);
        let to = |addr: Ipv4Addr| SocketAddr::new(addr.into(), 443);

        // 1. Accepted, with h2.
        let conn = tls_connect(
            &fcx,
            &m,
            &env,
            SECURE_ADDR,
            "secure.test",
            &[b"h2", b"http/1.1"],
        )
        .await
        .unwrap();
        drop(conn);
        // 2. No SNI (a client that connected to a bare address).
        assert!(
            tls_connect(&fcx, &m, &env, SECURE_ADDR, "203.0.113.10", &[])
                .await
                .is_err()
        );
        // 3. A name with no TLS site at this address.
        assert!(
            tls_connect(&fcx, &m, &env, SECURE_ADDR, "shared.test", &[])
                .await
                .is_err()
        );
        // 4. A client that does not trust the world's CA: it sends unknown_ca.
        let mut other_ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        other_ca
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Another CA");
        let other_ca = other_ca.self_signed(&KeyPair::generate().unwrap()).unwrap();
        let mut other = RootCertStore::empty();
        other.add(other_ca.der().clone()).unwrap();
        let other = Arc::new(other);
        let tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        let mut client = TlsClient::new(&fcx, tcp, &other, "secure.test", &[]);
        assert!(client.handshake(&fcx).await.is_err());
        // 5. A hello split over several segments.
        let mut tcp = m.tcp.connect(&fcx, to(EVENTS_ADDR)).await.unwrap();
        let mut tls = tls::with_context(&fcx, || {
            ClientConnection::new(
                client_config(&env.roots, &[b"http/1.1"]),
                ServerName::try_from("events.test".to_owned()).unwrap(),
            )
        })
        .unwrap();
        let mut hello = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut hello).unwrap();
        }
        assert!(hello.len() > 100);
        for chunk in hello.chunks(hello.len() / 3 + 1) {
            tcp.write_all(&fcx, chunk).await.unwrap();
            let _ = fcx.sleep(Duration::from_millis(30)).await;
        }
        let mut client = TlsClient::with(tcp, tls);
        client.handshake(&fcx).await.unwrap();
        drop(client);
        // 6. Closed before a hello.
        let mut tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        tcp.shutdown(&fcx).await.unwrap();
        // 7. Not TLS at all.
        let mut tcp = m.tcp.connect(&fcx, to(SECURE_ADDR)).await.unwrap();
        tcp.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            .await
            .unwrap();

        let got = wait_for(&fcx, &log, 7, tls_seen).await;
        assert!(
            got.iter()
                .all(|t| is(sandbox_of(t).unwrap(), "a", Some(me))),
            "{got:#?}"
        );
        let summary: Vec<_> = got
            .iter()
            .map(|t| (addr(t, "addr"), t.str("sni"), outcome(t)))
            .collect();
        let (secure, events) = (Some(IpAddr::V4(SECURE_ADDR)), Some(IpAddr::V4(EVENTS_ADDR)));
        assert_eq!(
            summary[0],
            (secure, Some("secure.test"), "accepted h2".to_owned())
        );
        assert_eq!(summary[1], (secure, None, "rejected".to_owned()));
        assert_eq!(
            summary[2],
            (secure, Some("shared.test"), "rejected".to_owned())
        );
        assert_eq!(
            summary[3],
            (secure, Some("secure.test"), "alert 48".to_owned())
        );
        assert_eq!(got[3].str("alert"), Some("unknown_ca"));
        assert_eq!(got[3].u64("alert_code"), Some(48));
        assert_eq!(
            summary[4],
            (events, Some("events.test"), "accepted http/1.1".to_owned())
        );
        assert_eq!(summary[5], (secure, None, "closed".to_owned()));
        assert_eq!(
            (summary[6].1, summary[6].2.as_str()),
            (None, "failed"),
            "{:?}",
            summary[6]
        );
        assert!(!got[6].str("detail").unwrap_or_default().is_empty());
        // Connections are numbered in order, from 1.
        let conns: Vec<u64> = got.iter().map(|t| t.conn.id.unwrap()).collect();
        assert_eq!(conns, (1..=7).collect::<Vec<u64>>());
        Ok(())
    });
}

/// Sends `request` on a new connection to `addr:80` and reads until the
/// server closes it.
async fn raw_http(fcx: &Cx, m: &Machine, addr: Ipv4Addr, request: &[u8]) -> Vec<u8> {
    let mut conn = m
        .tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap();
    conn.write_all(fcx, request).await.unwrap();
    read_all(fcx, &mut conn).await
}

#[test]
fn events_for_http_requests() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&fcx, &attacher, "a", me);
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let broken = lookup(&fcx, &m, "broken.test").await;

        // Three HTTP/2 requests on one connection, from a handler that puts
        // a Page in its response's extensions.
        let before = fcx.now();
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        for path in ["/page", "/page?x=1", "/page"] {
            let got = client.get("https", "events.test", path).await;
            assert_eq!(got.status, StatusCode::OK);
            assert_eq!(got.body, "page sni=Some(\"events.test\")");
        }
        let tls = wait_for(&fcx, &log, 1, tls_seen).await.remove(0);
        let pages = wait_for(&fcx, &log, 3, http_seen).await;
        let mut last = before.since_start().as_secs_f64();
        for (h, path) in pages.iter().zip(["/page", "/page?x=1", "/page"]) {
            assert!(is(sandbox_of(h).unwrap(), "a", Some(me)));
            assert_eq!(h.conn.id, tls.conn.id, "one connection");
            assert_eq!(
                (h.str("answer"), h.u64("status"), h.str("version")),
                (Some("handler"), Some(200), Some("HTTP/2.0"))
            );
            let uri: http::Uri = h.str("uri").unwrap().parse().unwrap();
            assert_eq!(
                (h.str("method"), uri.path_and_query().unwrap().as_str()),
                (Some("GET"), path)
            );
            assert_eq!(h.str("page"), Some("article"));
            assert_eq!(extra(h), 1);
            assert_eq!(
                (h.u64("sent"), flag(h, "complete")),
                (Some("page sni=Some(\"events.test\")".len() as u64), true)
            );
            assert_eq!(
                (h.str("scheme"), h.str("host"), h.str("sni")),
                (Some("https"), Some("events.test"), Some("events.test"))
            );
            assert_eq!(local(h), SocketAddr::from((EVENTS_ADDR, 443)));
            let started = h.get("started").and_then(|v| v.as_f64()).unwrap();
            assert!(started >= last, "requests started in order");
            last = started;
        }
        // The connection's TLS event came first.
        let order = picked(&log, |e| match (e.source, e.kind) {
            ("tls", "handshake") => Some("tls"),
            ("http", "request") => Some("http"),
            _ => None,
        });
        assert_eq!(order, vec!["tls", "http", "http", "http"]);
        log.clear();

        // Answers from Sites itself, on port 80.
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, tcp, false).await;
        assert_eq!(
            client.get("http", "secure.test", "/x?y=1").await.status,
            StatusCode::MOVED_PERMANENTLY
        );
        assert_eq!(
            client.get("http", "unknown.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(broken.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, tcp, false).await;
        assert_eq!(
            client.get("http", "broken.test", "/").await.status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let reply = raw_http(&fcx, &m, SECURE_ADDR, b"GET / HTTP/1.0\r\n\r\n").await;
        assert!(
            reply.starts_with(b"HTTP/1.0 400"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        let got = wait_for(&fcx, &log, 4, http_seen).await;
        let summary: Vec<_> = got
            .iter()
            .map(|h| {
                (
                    h.str("answer"),
                    h.u64("status"),
                    h.str("host"),
                    local(h).port(),
                    h.str("sni"),
                    extra(h),
                    flag(h, "complete"),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    Some("redirect"),
                    Some(301),
                    Some("secure.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (
                    Some("misdirected"),
                    Some(421),
                    Some("unknown.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (
                    Some("error"),
                    Some(500),
                    Some("broken.test"),
                    80,
                    None,
                    0,
                    true
                ),
                (Some("no_host"), Some(400), None, 80, None, 0, true),
            ]
        );
        assert_eq!(got[0].str("uri"), Some("/x?y=1"));
        let headers = got[0].get("headers").and_then(|v| v.as_array()).unwrap();
        let host = headers
            .iter()
            .filter_map(|p| p.as_array())
            .find(|p| p[0].as_str() == Some("host"))
            .unwrap();
        assert_eq!(host[1].as_str(), Some("secure.test"));
        assert_eq!(got[0].conn.id, got[1].conn.id);
        assert_ne!(got[1].conn.id, got[2].conn.id);
        log.clear();

        // HEAD: no body, complete once sent.
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        let Client::H1(mut send) = Client::new(&fcx, conn, false).await else {
            unreachable!()
        };
        send.ready().await.unwrap();
        let r = send
            .send_request(
                Request::head("/page")
                    .header("host", "events.test")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        drop(r);
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                got[0].str("method"),
                got[0].u64("sent"),
                flag(&got[0], "complete")
            ),
            (Some("HEAD"), Some(0), true)
        );
        log.clear();

        // A whole download, then one the client cuts short.
        let conn = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "events.test", "/big").await.body.len(),
            BIG
        );
        let Client::H2(send) = &mut client else {
            unreachable!()
        };
        send.ready().await.unwrap();
        let response = send
            .send_request(
                Request::get("https://events.test/big")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let first = body.frame().await.unwrap().unwrap();
        assert!(first.is_data());
        // Dropping the body resets the stream.
        drop(body);
        let got = wait_for(&fcx, &log, 2, http_seen).await;
        assert_eq!(
            (got[0].u64("sent"), flag(&got[0], "complete")),
            (Some(BIG as u64), true)
        );
        assert!(!flag(&got[1], "complete"), "{:?}", got[1]);
        let sent = got[1].u64("sent").unwrap();
        assert!(sent < BIG as u64, "{sent}");
        assert_eq!(got[1].u64("status"), Some(200));
        eprintln!("cut short after {sent} of {BIG} bytes");
        log.clear();

        // A request the client cancels while the handler waits: the stream
        // is reset, and the connection goes on.
        send.ready().await.unwrap();
        let waiting = send.send_request(
            Request::get("https://events.test/wait")
                .body(Empty::new())
                .unwrap(),
        );
        assert!(
            timeout(&fcx, Duration::from_millis(200), waiting)
                .await
                .is_none(),
            "no answer to /wait"
        );
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        let g = &got[0];
        assert_eq!(
            (
                g.str("answer"),
                g.u64("status"),
                g.u64("sent"),
                flag(g, "complete")
            ),
            (Some("cancelled"), None, Some(0), false)
        );
        assert_eq!(g.str("path"), Some("/wait"));
        assert_eq!(
            client.get("https", "events.test", "/page").await.status,
            StatusCode::OK
        );
        assert_eq!(wait_for(&fcx, &log, 2, http_seen).await.len(), 2);
        Ok(())
    });
}

#[test]
fn events_for_a_client_that_resets_mid_request() {
    world_events(|fcx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "slow.test", 1)
            .await
            .unwrap();
        let slow = addrs[0];
        let to = SocketAddr::new(slow.into(), 80);
        // HTTP/1.1, the handler never answers, the client resets.
        let (seq, ack) = raw_connect(
            &fcx,
            &mut raw,
            me,
            to,
            30_000,
            b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n",
        )
        .await;
        wait::until(&fcx, Duration::from_secs(10), || {
            env.waiting.load(Ordering::SeqCst) == 1
        })
        .await;
        assert!(picked(&log, http_seen).is_empty());
        raw.send(tcp_seg(me, 30_000, slow, 80, seq, ack, RST, &[]));
        let got = wait_for(&fcx, &log, 1, http_seen).await;
        assert_eq!(
            (
                got[0].str("answer"),
                got[0].u64("status"),
                flag(&got[0], "complete")
            ),
            (Some("cancelled"), None, false)
        );
        assert_eq!(
            (got[0].str("version"), got[0].str("host")),
            (Some("HTTP/1.1"), Some("slow.test"))
        );
        // A reset is the client going away, not an HTTP error.
        let _ = fcx.sleep(Duration::from_millis(100)).await;
        assert!(picked(&log, error_seen).is_empty());
        assert_eq!(picked(&log, http_seen).len(), 1, "exactly one event");
        Ok(())
    });
}

/// Sets its flag when dropped.
struct SetOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A world without an event callback: an HTTP/1.1 client that resets while
/// the handler works ends the handler at once, instead of leaving it
/// running for a client that is gone.
#[test]
fn a_reset_mid_request_drops_the_handler_without_events() {
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = dropped.clone();
    let result = within(Duration::from_secs(30), move || {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (seen, set) = (started.clone(), flag.clone());
            let app = axum::Router::new().route(
                "/hang",
                axum::routing::get(move || {
                    let (seen, set) = (seen.clone(), set.clone());
                    async move {
                        let _guard = SetOnDrop(set);
                        seen.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                        "never"
                    }
                }),
            );
            web::Sites::new(move |host| (host == "hang.test").then(|| web::Site::new(app.clone())))
                .start(&fcx, attachments)?;

            let me = Ipv4Addr::new(10, 0, 0, 2);
            let mut raw = attacher.attach("a").unwrap();
            let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "hang.test", 1)
                .await
                .unwrap();
            let to = SocketAddr::new(addrs[0].into(), 80);
            let (seq, ack) = raw_connect(
                &fcx,
                &mut raw,
                me,
                to,
                30_000,
                b"GET /hang HTTP/1.1\r\nHost: hang.test\r\n\r\n",
            )
            .await;
            wait::until(&fcx, Duration::from_secs(10), || {
                started.load(Ordering::SeqCst)
            })
            .await;
            assert!(started.load(Ordering::SeqCst), "the handler started");
            assert!(!flag.load(Ordering::SeqCst));
            raw.send(tcp_seg(me, 30_000, addrs[0], 80, seq, ack, RST, &[]));
            wait::until(&fcx, Duration::from_secs(10), || {
                flag.load(Ordering::SeqCst)
            })
            .await;
            // Checked here: stopping the world would drop the handler too.
            assert!(
                flag.load(Ordering::SeqCst),
                "the handler was dropped after the reset"
            );
            Err(fictionet::Error::from(Done))
        }))
    });
    assert!(
        matches!(&result, Err(e) if e.downcast_ref::<Done>().is_some()),
        "{:?}",
        result.err().map(|e| e.to_string())
    );
    assert!(dropped.load(Ordering::SeqCst));
}

/// A world stops while HTTP/1.1 and HTTP/2 handlers wait on something
/// outside the world, with their connections still open.
#[test]
fn the_world_stops_while_handlers_wait() {
    world_events(|fcx, attacher, env, log| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let slow = lookup(&fcx, &m, "slow.test").await;
        let to = SocketAddr::new(slow.into(), 80);
        let mut h1 = m.tcp.connect(&fcx, to).await.unwrap();
        h1.write_all(&fcx, b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n")
            .await
            .unwrap();
        // HTTP/2 with prior knowledge: the preface, empty SETTINGS, and one
        // GET /wait on stream 1 (HPACK: :method GET, :scheme http, then
        // :path and :authority as literals).
        let mut h2 = m.tcp.connect(&fcx, to).await.unwrap();
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        let mut block = vec![0x82, 0x86, 0x04, 5];
        block.extend_from_slice(b"/wait");
        block.extend_from_slice(&[0x01, 9]);
        block.extend_from_slice(b"slow.test");
        bytes.extend_from_slice(&[0, 0, block.len() as u8, 1, 0x05, 0, 0, 0, 1]);
        bytes.extend_from_slice(&block);
        h2.write_all(&fcx, &bytes).await.unwrap();
        wait::until(&fcx, Duration::from_secs(10), || {
            env.waiting.load(Ordering::SeqCst) == 2
        })
        .await;
        assert!(
            picked(&log, http_seen).is_empty(),
            "both handlers still wait"
        );
        // Keep both connections open while the world stops.
        let _keep = (h1, h2);
        Err(fictionet::Error::from(Done))
    });
}

#[test]
fn events_for_bytes_that_are_not_http() {
    world_events(|fcx, attacher, env, log| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&fcx, &m, "plain.test").await;
        assert_eq!(lookup(&fcx, &m, "events.test").await, EVENTS_ADDR);

        // Garbage on port 80.
        raw_http(&fcx, &m, plain, b"\x16\x03\x01\x00\x05hello\r\n\r\n").await;
        // HTTP/2 with prior knowledge, then a SETTINGS frame of a size no
        // SETTINGS frame can have.
        let mut bad = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bad.extend_from_slice(&[0, 0, 5, 4, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5]);
        raw_http(&fcx, &m, plain, &bad).await;
        // Clean closes make no event: a whole request, and nothing at all.
        let ok = raw_http(
            &fcx,
            &m,
            plain,
            b"GET / HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(ok.starts_with(b"HTTP/1.1 200"));
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain.into(), 80))
            .await
            .unwrap();
        conn.shutdown(&fcx).await.unwrap();
        let _ = read_all(&fcx, &mut conn).await;
        // After a TLS handshake, a record that does not decrypt.
        let mut client = tls_connect(&fcx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"])
            .await
            .unwrap();
        // First a request, so the server has finished its handshake.
        client
            .write_all(&fcx, b"GET /page HTTP/1.1\r\nHost: events.test\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        read_exact(&fcx, &mut client, &mut buf).await;
        let mut record = vec![23, 3, 3, 0, 40];
        record.extend_from_slice(&[0x55; 40]);
        client.conn.write_all(&fcx, &record).await.unwrap();

        let got = wait_for(&fcx, &log, 3, error_seen).await;
        let _ = fcx.sleep(Duration::from_millis(200)).await;
        assert_eq!(
            picked(&log, error_seen).len(),
            3,
            "{:#?}",
            picked(&log, error_seen)
        );
        let summary: Vec<_> = got.iter().map(|b| (local(b), b.str("cause"))).collect();
        assert_eq!(
            summary,
            vec![
                (SocketAddr::from((plain, 80)), Some("protocol")),
                (SocketAddr::from((plain, 80)), Some("protocol")),
                (SocketAddr::from((EVENTS_ADDR, 443)), Some("transport")),
            ]
        );
        let me = Some(Ipv4Addr::new(10, 0, 0, 2));
        assert!(got.iter().all(|b| is(sandbox_of(b).unwrap(), "a", me)
            && !b.str("detail").unwrap_or_default().is_empty()));
        assert_ne!(got[0].conn.id, got[1].conn.id);
        Ok(())
    });
}

/// A client that connects and sends nothing reaches the configured timeout.
#[test]
fn events_for_clients_that_send_nothing() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        sites(&fcx)
            .sites
            .into_net()
            .limits(fictionet::stdlib::net::Limits {
                handshake: Duration::from_secs(1),
                dns_tcp_idle: Duration::from_secs(1),
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let log = Log::new(&fcx);
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let started = fcx.now();
        let _quiet_80 = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 80))
            .await
            .unwrap();
        let _quiet_443 = m
            .tcp
            .connect(&fcx, SocketAddr::new(SECURE_ADDR.into(), 443))
            .await
            .unwrap();
        let tls = wait_for_long(&fcx, &log, tls_seen).await;
        let took = fcx.now().since_start() - started.since_start();
        assert_eq!(took, Duration::from_secs(1));
        assert_eq!(
            (tls.str("sni"), outcome(&tls)),
            (None, "timed_out".to_owned())
        );
        let bad = wait_for(&fcx, &log, 1, error_seen).await;
        assert_eq!(
            (local(&bad[0]).port(), bad[0].str("cause")),
            (80, Some("timeout"))
        );
        Ok(())
    });
}

/// Waits up to 10 s for the first event `pick` keeps.
async fn wait_for_long<T>(fcx: &Cx, log: &Log, mut pick: impl FnMut(&Entry) -> Option<T>) -> T {
    let from = log.from.load(Ordering::SeqCst);
    let got = log
        .events
        .wait(fcx, 1, Duration::from_secs(10), |e| {
            e.seq > from && pick(e).is_some()
        })
        .await
        .expect("the world stopped");
    got.iter().find_map(pick).expect("no such event")
}

#[test]
fn events_for_blocked_packets() {
    world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();

        // Before binding: not IP, and IPv6 to the unspecified address.
        raw.send(Packet(vec![1, 2, 3]));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend_from_slice(&[0; 32]);
        v6.extend_from_slice(&[0, 1, 0, 53, 0, 8, 0, 0]);
        raw.send(Packet(v6));
        // A source that cannot be bound.
        raw.send(ping(Ipv4Addr::new(192, 168, 1, 5), GATEWAY, 1));
        // DHCP that cannot be read: dropped, not reported.
        raw.send(udp(
            Ipv4Addr::UNSPECIFIED,
            68,
            Ipv4Addr::BROADCAST,
            67,
            b"not dhcp",
        ));
        // Bind, then break the rules.
        raw.send(ping(me, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );
        raw.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        raw.send(ping(me, Ipv4Addr::new(10, 0, 0, 3), 4));
        raw.send(udp(me, 1000, Ipv4Addr::BROADCAST, 2000, b"hi"));
        // No machine there: host unreachable.
        raw.send(ping(me, Ipv4Addr::new(192, 0, 2, 1), 5));
        let (_, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        // Closed ports at a machine and at the gateway.
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "plain.test", 5)
            .await
            .unwrap();
        let plain = addrs[0];
        for (dst, port) in [(plain, 22), (plain, 443), (GATEWAY, 80)] {
            raw.send(tcp_seg(me, 30_000, dst, port, 1, 0, SYN, &[]));
            let (_, _, proto, t) = parse(
                &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!((proto, t[13] & RST), (6, RST), "a RST from {dst}:{port}");
        }
        for (dst, port) in [(plain, 9999), (GATEWAY, 5000)] {
            raw.send(udp(me, 1000, dst, port, b"hi"));
            let (_, _, proto, icmp) = parse(
                &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!(
                (proto, icmp[0], icmp[1]),
                (1, 3, 3),
                "port unreachable from {dst}:{port}"
            );
        }
        // UDP with a bad checksum is dropped below Sites, unreported.
        let mut bad = udp(me, 1000, plain, 9999, b"hi");
        let n = bad.0.len();
        bad.0[n - 1] ^= 0xff;
        raw.send(bad);
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        // Open ports make no event.
        raw.send(tcp_seg(me, 30_001, plain, 80, 1, 0, SYN, &[]));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );

        // Each is recorded as it comes, except a repeat within a second:
        // the second closed TCP port at the same machine is counted, and
        // its count recorded a second later.
        let got = wait_for(&fcx, &log, 12, blocked_seen).await;
        let summary: Vec<_> = got.iter().map(blocked_row).collect();
        let v4 = |a: Ipv4Addr| Some(IpAddr::V4(a));
        assert_eq!(
            summary,
            vec![
                ("Malformed", None, None, None, None, None),
                (
                    "Broadcast",
                    None,
                    Some(17),
                    Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                    Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                    Some(53)
                ),
                (
                    "NotItsAddress",
                    None,
                    Some(1),
                    v4(Ipv4Addr::new(192, 168, 1, 5)),
                    v4(GATEWAY),
                    None
                ),
                (
                    "NotItsAddress",
                    Some(me),
                    Some(1),
                    v4(Ipv4Addr::new(10, 0, 0, 9)),
                    v4(GATEWAY),
                    None
                ),
                (
                    "OtherSandbox",
                    Some(me),
                    Some(1),
                    v4(me),
                    v4(Ipv4Addr::new(10, 0, 0, 3)),
                    None
                ),
                (
                    "Broadcast",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(Ipv4Addr::BROADCAST),
                    Some(2000)
                ),
                (
                    "NoRoute",
                    Some(me),
                    Some(1),
                    v4(me),
                    v4(Ipv4Addr::new(192, 0, 2, 1)),
                    None
                ),
                ("ClosedPort", Some(me), Some(6), v4(me), v4(plain), Some(22)),
                (
                    "ClosedPort",
                    Some(me),
                    Some(6),
                    v4(me),
                    v4(GATEWAY),
                    Some(80)
                ),
                (
                    "ClosedPort",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(plain),
                    Some(9999)
                ),
                (
                    "ClosedPort",
                    Some(me),
                    Some(17),
                    v4(me),
                    v4(GATEWAY),
                    Some(5000)
                ),
                // The count: the port's lowest and highest.
                ("ClosedPort", Some(me), Some(6), v4(me), v4(plain), None),
            ]
        );
        let counts: Vec<_> = got.iter().map(|b| b.u64("count")).collect();
        assert_eq!(
            counts,
            [Some(1); 11]
                .into_iter()
                .chain([Some(1)])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            got[11].get("dst_port"),
            Some(&fictionet::stdlib::json::Value::Array(vec![
                443u64.into(),
                443u64.into()
            ]))
        );
        assert!(
            got.iter()
                .all(|b| sandbox_of(b).is_some_and(|s| &*s.name == "a" && s.id == 1))
        );
        log.clear();

        // Past the limit of connections to one machine: the first refused
        // is recorded, and the rest counted.
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "secure.test", 6)
            .await
            .unwrap();
        assert_eq!(addrs, vec![SECURE_ADDR]);
        let (open, _) = open_idle(
            &fcx,
            &mut raw,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            300,
        )
        .await;
        assert_eq!(open, 300);
        let got = wait_for(&fcx, &log, 2, blocked_seen).await;
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].u64("count"), got[0].u64("dst_port")),
            (Some(1), Some(443))
        );
        assert_eq!(got[1].u64("count"), Some(43));
        assert!(got.iter().all(
            |b| b.str("why") == Some("TooManyConnections") && addr(b, "dst") == v4(SECURE_ADDR)
        ));
        assert!(
            got.iter()
                .all(|b| is(sandbox_of(b).unwrap(), "a", Some(me)))
        );
        Ok(())
    });
}

/// A sandbox scans more closed ports than the log holds events. The
/// refusals are counted, not kept one by one, so the events a grader reads
/// all stay in the log, and a file sink loses nothing.
#[test]
fn a_port_scan_cannot_push_out_the_events_a_grader_reads() {
    const SCAN: u16 = 55_000;
    let path = std::env::temp_dir().join(format!("fictionet-scan-{}.jsonl", std::process::id()));
    let kept: Arc<std::sync::Mutex<Option<EventLog>>> = Arc::default();
    let (keep, file) = (kept.clone(), path.clone());
    world_events(move |fcx, attacher, env, log| async move {
        log.events.to_file(&file)?;
        // What a grader reads: a lookup, a TLS handshake and a request.
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        let conn = tls_connect(&fcx, &m, &env, SECURE_ADDR, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );

        // The scan, from another sandbox: every port but the open ones.
        let me = Ipv4Addr::new(10, 0, 0, 3);
        let mut raw = attacher.attach("b").unwrap();
        raw.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );
        let (_, addrs) = raw_dns(&fcx, &mut raw, me, GATEWAY, "plain.test", 2)
            .await
            .unwrap();
        let plain = addrs[0];
        let ports: Vec<u16> = (1..)
            .filter(|p| ![80, 443].contains(p))
            .take(usize::from(SCAN))
            .collect();
        for batch in ports.chunks(500) {
            for &port in batch {
                raw.send(tcp_seg(me, 40_000, plain, port, 1, 0, SYN, &[]));
            }
            for _ in batch {
                let (_, _, _, t) = parse(
                    &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                        .await
                        .expect("a RST"),
                );
                assert_eq!(t[13] & RST, RST);
            }
        }
        *keep.lock().unwrap() = Some(log.events.clone());
        Ok(())
    });
    // The run is over: every count is recorded, and the file is written.
    let events = kept.lock().unwrap().take().unwrap();
    fn from(e: &Entry, name: &str) -> bool {
        sandbox_of(e).is_some_and(|s| &*s.name == name)
    }
    let all = events.all();
    let graders: Vec<_> = all
        .iter()
        .filter(|e| from(e, "a") && e.source != "net")
        .map(|e| format!("{}.{}", e.source, e.kind))
        .collect();
    for want in ["dns.query", "tls.handshake", "http.request"] {
        assert!(
            graders.iter().any(|g| g == want),
            "{want} is gone: {graders:?}"
        );
    }
    assert_eq!(events.dropped(), 0);
    let blocked: Vec<_> = all
        .iter()
        .filter(|e| e.is("net", "blocked") && from(e, "b"))
        .collect();
    assert_eq!(
        blocked.iter().map(|e| e.u64("count").unwrap()).sum::<u64>(),
        u64::from(SCAN)
    );
    assert!(blocked.len() < 100, "{} events for the scan", blocked.len());
    assert_eq!(events.lost(), 0);
    let text = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(text.lines().count() as u64, events.recorded());
    assert!(
        text.lines()
            .any(|l| l.contains(r#""source":"http","kind":"request""#))
    );
}

// ---------------------------------------------------------------------------
// Tests: IPv6

const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const ME6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// An address no site has, outside the sandboxes' subnet.
const NOWHERE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x99, 0, 0, 0, 0, 1);

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Packet {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    Packet(p)
}

/// An IPv6 packet carrying `data`, with its checksum at `at` filled in.
fn checksummed6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, mut data: Vec<u8>, at: usize) -> Packet {
    let c = ip::transport_checksum(src.into(), dst.into(), next, &data);
    data[at..at + 2].copy_from_slice(&c.to_be_bytes());
    ipv6(src, dst, next, &data)
}

fn ping6(src: Ipv6Addr, dst: Ipv6Addr, seq: u16) -> Packet {
    let mut icmp = vec![128, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fictionet");
    checksummed6(src, dst, 58, icmp, 2)
}

fn udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    checksummed6(src, dst, 17, u, 6)
}

fn syn6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&1000u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&[0x50, SYN, 0xff, 0xff, 0, 0, 0, 0]);
    checksummed6(src, dst, 6, t, 16)
}

/// (src, dst, next header, payload) of an IPv6 packet with no extension
/// headers, checking the upper layer's checksum.
fn parse6(p: &Packet) -> (Ipv6Addr, Ipv6Addr, u8, Vec<u8>) {
    let b = &p.0;
    assert_eq!(b[0] >> 4, 6);
    let len = u16::from_be_bytes([b[4], b[5]]) as usize;
    assert_eq!(b.len(), 40 + len, "the payload length");
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap());
    let payload = b[40..].to_vec();
    assert_eq!(
        ip::transport_checksum(src.into(), dst.into(), b[6], &payload),
        0,
        "the checksum"
    );
    (src, dst, b[6], payload)
}

/// A DNS query for `name` from `me` to `server` on a raw attachment, over
/// IPv6: the answer's code and addresses, or `None` if none came within
/// 2 s.
async fn raw_dns6(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv6Addr,
    server: Ipv6Addr,
    name: &str,
    kind: RecordType,
) -> Option<(ResponseCode, Vec<IpAddr>)> {
    let id = fcx.random_u64() as u16;
    let mut q = Message::new(id, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    raw.send(udp6(me, 5353, server, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2)).await?;
        let (src, _, next, u) = parse6(&p);
        if src == server && next == 17 {
            return Some(parse_dns_all(&u[8..], id));
        }
    }
}

/// Like [`parse_dns`], with AAAA records too.
fn parse_dns_all(bytes: &[u8], id: u16) -> (ResponseCode, Vec<IpAddr>) {
    let r = Message::from_vec(bytes).unwrap();
    assert_eq!(r.metadata.id, id);
    assert_eq!(r.metadata.message_type, MessageType::Response);
    let addrs = r
        .answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    (r.metadata.response_code, addrs)
}

/// Asks `server`'s DNS over UDP from `m`, over either IP version. Returns
/// the response code and the A and AAAA records.
async fn dns_at(
    fcx: &Cx,
    m: &Machine,
    server: IpAddr,
    name: &str,
    kind: RecordType,
) -> (ResponseCode, Vec<IpAddr>) {
    let mut socket = m
        .udp
        .bind(40000 + (fcx.random_u64() % 20000) as u16)
        .unwrap();
    let mut q = Message::new(fcx.random_u64() as u16, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(server, 53));
    let (bytes, from) = timeout(fcx, Duration::from_secs(5), socket.recv(fcx))
        .await
        .expect("a DNS answer")
        .unwrap();
    assert_eq!(from, SocketAddr::new(server, 53));
    parse_dns_all(&bytes, q.metadata.id)
}

#[test]
fn dns_answers_aaaa_for_each_family_a_site_has() {
    world(|fcx, attacher, env| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        let ok = |addrs: &[IpAddr]| (ResponseCode::NoError, addrs.to_vec());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());

        // A site with only an IPv4 `at` gets an automatic IPv6 address,
        // from 2001:2::/48, and keeps it.
        assert_eq!(
            dns_at(&fcx, &m, gw, "secure.test", RecordType::AAAA).await,
            ok(&[v6("2001:2::1")])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "secure.test", RecordType::A).await,
            ok(&[SECURE_ADDR.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "SECURE.test.", RecordType::AAAA).await,
            ok(&[v6("2001:2::1")])
        );
        // A site at two addresses of its own.
        assert_eq!(
            dns_at(&fcx, &m, gw, "dual.test", RecordType::A).await,
            ok(&[DUAL_ADDR.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "dual.test", RecordType::AAAA).await,
            ok(&[DUAL_ADDR6.into()])
        );
        // Sites of one family: NODATA for the other.
        assert_eq!(
            dns_at(&fcx, &m, gw, "v4only.test", RecordType::AAAA).await,
            ok(&[])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v4only.test", RecordType::A).await,
            ok(&[Ipv4Addr::new(198, 18, 0, 1).into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v6only.test", RecordType::A).await,
            ok(&[])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v6only.test", RecordType::AAAA).await,
            ok(&[V6ONLY_ADDR6.into()])
        );
        // An address inside the sandboxes' IPv6 subnet, and a name with no
        // site: NXDOMAIN for both types.
        for name in ["inside6.test", "nope.test"] {
            for kind in [RecordType::A, RecordType::AAAA] {
                assert_eq!(
                    dns_at(&fcx, &m, gw, name, kind).await,
                    (ResponseCode::NXDomain, vec![]),
                    "{name} {kind}"
                );
            }
        }
        // The callback ran once per name.
        assert_eq!(env.calls.load(Ordering::SeqCst), 6);

        // DNS also answers at the gateway's IPv6 address, over UDP and TCP.
        let m6 = machine(&fcx, &attacher, "b", ME6);
        assert_eq!(
            dns_at(&fcx, &m6, GATEWAY6.into(), "dual.test", RecordType::AAAA).await,
            ok(&[DUAL_ADDR6.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m6, GATEWAY6.into(), "dual.test", RecordType::A).await,
            ok(&[DUAL_ADDR.into()])
        );
        let mut conn = m6
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY6.into(), 53))
            .await
            .unwrap();
        let mut q = Message::new(77, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("v6only.test").unwrap(),
            RecordType::AAAA,
        ));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut conn, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&fcx, &mut conn, &mut reply).await;
        assert_eq!(parse_dns_all(&reply, 77), ok(&[V6ONLY_ADDR6.into()]));
        Ok(())
    });
}

#[test]
fn https_http2_and_plain_http_over_ipv6() {
    world_events(|fcx, attacher, env, log| async move {
        let m = machine(&fcx, &attacher, "a", ME6);
        let (_, addrs) = dns_at(&fcx, &m, GATEWAY6.into(), "dual.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(DUAL_ADDR6)]);

        // HTTP/2 and HTTP/1.1 over TLS, to the site's IPv6 address.
        let conn = tls_connect(
            &fcx,
            &m,
            &env,
            DUAL_ADDR6,
            "dual.test",
            &[b"h2", b"http/1.1"],
        )
        .await
        .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&fcx, conn, true).await;
        let got = client.get("https", "dual.test", "/").await;
        assert_eq!((got.status, got.version), (StatusCode::OK, Version::HTTP_2));
        assert_eq!(got.body, "secure https dual.test 443 HTTP/2.0 #1");
        let conn = tls_connect(&fcx, &m, &env, DUAL_ADDR6, "dual.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("https", "dual.test", "/").await.body,
            "secure https dual.test 443 HTTP/1.1 #2"
        );

        // The site keeps its state across families: it is one site.
        let m4 = machine(&fcx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 2));
        let conn = tls_connect(&fcx, &m4, &env, DUAL_ADDR, "dual.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "dual.test", "/").await.body,
            "secure https dual.test 443 HTTP/2.0 #3"
        );

        // An IPv6-only site.
        let (_, addrs) = dns_at(&fcx, &m, GATEWAY6.into(), "v6only.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(V6ONLY_ADDR6)]);
        let conn = tls_connect(&fcx, &m, &env, V6ONLY_ADDR6, "v6only.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "v6only.test", "/").await.body,
            "secure https v6only.test 443 HTTP/2.0 #4"
        );

        // Port 80: a TLS site redirects to https. A plain site at its
        // automatic IPv6 address answers. A request that names the bare
        // address in brackets gets 421, as it would over IPv4.
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(DUAL_ADDR6.into(), 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        let got = client.get("http", "dual.test", "/a?b").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://dual.test/a?b");
        let (_, plain) = dns_at(&fcx, &m, GATEWAY6.into(), "plain.test", RecordType::AAAA).await;
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain[0], 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "plain.test", "/q").await.body,
            "plain http plain.test 80 HTTP/1.1 /q"
        );
        let got = client.get("http", &format!("[{}]", plain[0]), "/q").await;
        assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST);

        // A TLS handshake to the bare address carries no SNI, and is
        // rejected.
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(DUAL_ADDR6.into(), 443))
            .await
            .unwrap();
        let mut bare = TlsClient::new(&fcx, tcp, &env.roots, &DUAL_ADDR6.to_string(), &[]);
        assert!(bare.handshake(&fcx).await.is_err());

        // The events name the IPv6 addresses.
        let tls = wait_for(&fcx, &log, 5, tls_seen).await;
        assert_eq!(addr(&tls[0], "addr"), Some(IpAddr::V6(DUAL_ADDR6)));
        assert_eq!(sandbox_of(&tls[0]).unwrap().addr_v6, Some(ME6));
        assert_eq!(sandbox_of(&tls[0]).unwrap().addr, None);
        assert_eq!(
            (addr(&tls[4], "addr"), outcome(&tls[4])),
            (Some(IpAddr::V6(DUAL_ADDR6)), "rejected".to_owned())
        );
        let http = wait_for(&fcx, &log, 7, http_seen).await;
        assert_eq!(local(&http[0]), SocketAddr::new(DUAL_ADDR6.into(), 443));
        assert_eq!(local(&http[2]), SocketAddr::new(DUAL_ADDR.into(), 443));
        assert_eq!(
            sandbox_of(&http[2]).unwrap().addr,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        let dns = wait_for(&fcx, &log, 3, dns_seen).await;
        assert_eq!(answer(&dns[0]), format!("addr {DUAL_ADDR6}"));
        assert_eq!(dns[0].u64("qtype"), Some(28));
        Ok(())
    });
}

#[test]
fn ipv6_pings_closed_ports_and_unknown_addresses() {
    world(|fcx, attacher, _env| async move {
        let mut raw = attacher.attach("a").unwrap();
        let reply = |p: Packet| parse6(&p);

        // The gateway answers pings.
        raw.send(ping6(ME6, GATEWAY6, 1));
        let (src, dst, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, dst, next, icmp[0]), (GATEWAY6, ME6, 58, 129));

        // An address that no site has: ICMPv6 address unreachable, at once,
        // from the gateway, quoting the packet.
        let sent = ping6(ME6, NOWHERE6, 2);
        raw.send(sent.clone());
        let (src, dst, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("unreachable"),
        );
        assert_eq!((src, dst, next), (GATEWAY6, ME6, 58));
        assert_eq!((icmp[0], icmp[1]), (1, 3));
        assert_eq!(&icmp[8..], &sent.0[..]);

        // Once its name is looked up, a site's IPv6 address answers pings.
        let (code, addrs) = raw_dns6(
            &fcx,
            &mut raw,
            ME6,
            GATEWAY6,
            "plain.test",
            RecordType::AAAA,
        )
        .await
        .expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        let IpAddr::V6(plain) = addrs[0] else {
            panic!("{addrs:?}")
        };
        raw.send(ping6(ME6, plain, 3));
        let (src, _, _, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (plain, 129));

        // A closed TCP port gets a RST; UDP gets port unreachable.
        raw.send(syn6(ME6, 30_000, plain, 22));
        let (_, _, next, t) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, t[13] & RST), (6, RST));
        raw.send(udp6(ME6, 1000, plain, 9999, b"hi"));
        let (_, _, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, icmp[0], icmp[1]), (58, 1, 4));
        // Port 80 is open.
        raw.send(syn6(ME6, 30_001, plain, 80));
        let (_, _, next, t) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, t[13] & (SYN | ACK)), (6, SYN | ACK));

        // No error for an ICMPv6 error, or for a router solicitation from a
        // link-local address to all routers.
        let mut err = vec![1, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..48]);
        raw.send(checksummed6(ME6, NOWHERE6, 58, err, 2));
        let rs = checksummed6(
            "fe80::1".parse().unwrap(),
            "ff02::2".parse().unwrap(),
            58,
            vec![133, 0, 0, 0, 0, 0, 0, 0],
            2,
        );
        raw.send(rs);
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn ipv6_addresses_are_bound_to_one_sandbox() {
    world_events(|fcx, attacher, _env, log| async move {
        let me4 = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // What a Linux sandbox sends first: a router solicitation from its
        // link-local address. It is dropped, and binds nothing.
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        a.send(checksummed6(
            link_local,
            "ff02::2".parse().unwrap(),
            58,
            vec![133, 0, 0, 0, 0, 0, 0, 0],
            2,
        ));
        // Then its global address: bound. Then its IPv4 address: bound too.
        a.send(ping6(ME6, GATEWAY6, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        a.send(ping(me4, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        // Another source, another sandbox, an address with no site.
        a.send(ping6("2001:db8::9".parse().unwrap(), GATEWAY6, 3));
        a.send(ping6(ME6, "2001:db8::3".parse().unwrap(), 4));
        a.send(ping6(link_local, GATEWAY6, 5));
        a.send(ping6(ME6, NOWHERE6, 6));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some(),
            "unreachable"
        );

        // A second sandbox cannot take the first one's address, the
        // gateway's, the subnet's first address, or one outside the subnet.
        let mut b = attacher.attach("b").unwrap();
        for src in [
            ME6,
            GATEWAY6,
            "2001:db8::".parse().unwrap(),
            "2001:db8:1::5".parse().unwrap(),
        ] {
            b.send(ping6(src, GATEWAY6, 7));
        }
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());

        let got = wait_for(&fcx, &log, 9, blocked_seen).await;
        let summary: Vec<_> = got
            .iter()
            .map(|b| {
                (
                    &*sandbox_of(b).unwrap().name,
                    b.str("why").unwrap(),
                    sandbox_of(b).unwrap().addr_v6,
                    addr(b, "src"),
                    addr(b, "dst"),
                )
            })
            .collect();
        let v6 = |a: Ipv6Addr| Some(IpAddr::V6(a));
        assert_eq!(
            summary,
            vec![
                (
                    "a",
                    "Broadcast",
                    None,
                    v6(link_local),
                    v6("ff02::2".parse().unwrap())
                ),
                (
                    "a",
                    "NotItsAddress",
                    Some(ME6),
                    v6("2001:db8::9".parse().unwrap()),
                    v6(GATEWAY6)
                ),
                (
                    "a",
                    "OtherSandbox",
                    Some(ME6),
                    v6(ME6),
                    v6("2001:db8::3".parse().unwrap())
                ),
                (
                    "a",
                    "NotItsAddress",
                    Some(ME6),
                    v6(link_local),
                    v6(GATEWAY6)
                ),
                ("a", "NoRoute", Some(ME6), v6(ME6), v6(NOWHERE6)),
                ("b", "NotItsAddress", None, v6(ME6), v6(GATEWAY6)),
                ("b", "NotItsAddress", None, v6(GATEWAY6), v6(GATEWAY6)),
                (
                    "b",
                    "NotItsAddress",
                    None,
                    v6("2001:db8::".parse().unwrap()),
                    v6(GATEWAY6)
                ),
                (
                    "b",
                    "NotItsAddress",
                    None,
                    v6("2001:db8:1::5".parse().unwrap()),
                    v6(GATEWAY6)
                ),
            ]
        );
        assert_eq!(got.len(), 9, "{got:#?}");

        // One `bound` for each family, and a `detached` that names both.
        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;
        let a_events = picked(&log, |e| {
            (e.source == "net" && e.kind != "blocked" && &*sandbox_of(e)?.name == "a")
                .then(|| e.clone())
        });
        let kinds: Vec<_> = a_events.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            ["attached", "bound", "bound", "detached"],
            "{a_events:#?}"
        );
        let at = |e: &Entry| sandbox_of(e).map(|s| (s.addr, s.addr_v6));
        assert!(!flag(&a_events[1], "by_dhcp"));
        assert_eq!(at(&a_events[1]), Some((None, Some(ME6))));
        assert_eq!(at(&a_events[2]), Some((Some(me4), Some(ME6))));
        assert_eq!(at(&a_events[3]), Some((Some(me4), Some(ME6))));

        // Now the address is free, and the second sandbox can take it.
        b.send(ping6(ME6, GATEWAY6, 8));
        let (src, dst, _, icmp) = parse6(
            &recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, dst, icmp[0]), (GATEWAY6, ME6, 129));
        Ok(())
    });
}

/// Runs a world whose network `make` builds, with every event kept.
fn world_of<F, Fut>(make: impl FnOnce() -> web::Sites + Send + 'static, f: F)
where
    F: FnOnce(Cx, Attacher, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        make().start(&fcx, attachments)?;
        let log = Log::new(&fcx);
        f(fcx, attacher, log).await?;
        Ok(())
    });
}

#[test]
fn an_ipv4_only_network_drops_ipv6_and_answers_aaaa_with_nodata() {
    let make = || {
        web::Sites::new(|host| match host {
            "six.test" => Some(web::Site::new(Plain("six")).ipv6_only()),
            h => h
                .ends_with(".test")
                .then(|| web::Site::new(Plain("auto")).at(DUAL_ADDR6)),
        })
        .ipv4_only()
    };
    world_of(make, |fcx, attacher, log| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        // An IPv6 `at` is not used: the site gets an automatic IPv4 address.
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::A).await,
            (
                ResponseCode::NoError,
                vec![Ipv4Addr::new(198, 18, 0, 1).into()]
            )
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        // An IPv6-only site has no address at all.
        assert_eq!(
            dns_at(&fcx, &m, gw, "six.test", RecordType::AAAA).await,
            (ResponseCode::NXDomain, vec![])
        );

        let mut raw = attacher.attach("b").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        let got = wait_for(&fcx, &log, 1, blocked_seen).await;
        assert_eq!(
            (got[0].str("why"), addr(&got[0], "dst")),
            (Some("Ipv6"), Some(IpAddr::V6(GATEWAY6)))
        );
        Ok(())
    });
}

#[test]
fn automatic_ipv6_addresses_skip_the_sandboxes_subnet() {
    // A subnet inside 2001:2::/48: automatic addresses jump past it.
    let make = || {
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet("2001:2::/64".parse().unwrap())
    };
    world_of(make, |fcx, attacher, _log| async move {
        let (gw, me): (Ipv6Addr, Ipv6Addr) =
            ("2001:2::1".parse().unwrap(), "2001:2::2".parse().unwrap());
        let mut raw = attacher.attach("a").unwrap();
        let (_, first) = raw_dns6(&fcx, &mut raw, me, gw, "one.test", RecordType::AAAA)
            .await
            .expect("DNS answers");
        assert_eq!(first, vec![IpAddr::V6("2001:2:0:1::".parse().unwrap())]);
        let (_, second) = raw_dns6(&fcx, &mut raw, me, gw, "two.test", RecordType::AAAA)
            .await
            .expect("DNS answers");
        assert_eq!(second, vec![IpAddr::V6("2001:2:0:1::1".parse().unwrap())]);
        let IpAddr::V6(site) = first[0] else {
            unreachable!()
        };
        raw.send(ping6(me, site, 1));
        let (src, _, _, icmp) = parse6(
            &recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, icmp[0]), (site, 129));
        Ok(())
    });

    // A subnet that covers all of 2001:2::/48 leaves no automatic IPv6
    // addresses. Sites then have IPv4 only.
    let make = || {
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet("2001::/16".parse().unwrap())
    };
    world_of(make, |fcx, attacher, _log| async move {
        let m = machine(&fcx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::A).await,
            (
                ResponseCode::NoError,
                vec![Ipv4Addr::new(198, 18, 0, 1).into()]
            )
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: IPv6 fragments, extension headers and checksums from the agent

/// An IPv6 fragment: `data` at byte `offset` of packet `id`, whose
/// fragment header names `next`.
fn fragment6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u32,
    offset: u16,
    more: bool,
    next: u8,
    data: &[u8],
) -> Packet {
    let mut body = vec![next, 0];
    body.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(data);
    ipv6(src, dst, 44, &body)
}

/// An echo request to the gateway with 16 bytes of data, `data`, whole.
fn echo6_with(data: &[u8; 16]) -> Packet {
    let mut echo = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1];
    echo.extend_from_slice(data);
    checksummed6(ME6, GATEWAY6, 58, echo, 2)
}

/// `packet` with `header` (an extension header) put in front of its
/// payload. `header[0]` must name the payload's protocol.
fn with_header(packet: &Packet, next: u8, header: &[u8]) -> Packet {
    let mut body = header.to_vec();
    body.extend_from_slice(&packet.0[40..]);
    ipv6(ME6, GATEWAY6, next, &body)
}

/// A sandbox that sent the first fragment of a packet and detached leaves
/// nothing behind: the next sandbox to take its address cannot complete
/// that packet and read its data.
#[test]
fn fragments_do_not_outlive_their_sandbox() {
    world(|fcx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(fragment6(
            ME6,
            GATEWAY6,
            12345,
            0,
            true,
            58,
            &whole.0[40..56],
        ));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(20))
                .await
                .is_none()
        );
        drop(a);
        // b takes the address once a's filter has let it go.
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for seq in 0..100 {
            b.send(ping6(ME6, GATEWAY6, seq));
            if recv_within(&fcx, &mut b, Duration::from_millis(20))
                .await
                .is_some()
            {
                bound = true;
                break;
            }
        }
        assert!(bound);
        b.send(fragment6(
            ME6,
            GATEWAY6,
            12345,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_none(),
            "a's fragment completed b's packet"
        );
        // b's own fragments still make a packet.
        let mine = echo6_with(b"b's own packet!!");
        b.send(fragment6(ME6, GATEWAY6, 777, 0, true, 58, &mine.0[40..56]));
        b.send(fragment6(ME6, GATEWAY6, 777, 16, false, 58, &mine.0[56..]));
        let reply = recv_within(&fcx, &mut b, SHORT)
            .await
            .expect("an echo reply");
        let (_, dst, next, body) = parse6(&reply);
        assert_eq!((dst, next, body[0]), (ME6, 58, 129));
        assert_eq!(&body[8..], b"b's own packet!!");
        Ok(())
    });
}

/// A fragment at the same place as one already waiting, with other bytes,
/// drops the whole packet (RFC 5722), and its later fragments cannot start
/// it again.
#[test]
fn conflicting_fragments_drop_the_packet() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let whole = echo6_with(b"abcdefghABCDEFGH");
        let first = &whole.0[40..56];
        let mut conflicting = first.to_vec();
        conflicting[8] ^= 0xff;
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, &conflicting));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9876,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a packet with conflicting fragments was delivered"
        );
        // The same fragments again, without the conflict: still dropped.
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9876,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a dropped packet was started again"
        );
        // An exact copy of a fragment is not a conflict.
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9877,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("an echo reply");
        let (_, _, next, body) = parse6(&reply);
        assert_eq!((next, body[0]), (58, 129));
        assert_eq!(&body[8..], b"abcdefghABCDEFGH");
        Ok(())
    });
}

/// TCP behind extension headers that ask nothing of the host is accepted,
/// at the gateway and at a site.
#[test]
fn tcp_behind_extension_headers_is_accepted() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let headers: [(u8, [u8; 8]); 3] = [
            (60, [6, 0, 0, 0, 0, 0, 0, 0]),    // Destination Options: Pad1 only.
            (0, [6, 0, 1, 4, 0, 0, 0, 0]),     // Hop-by-Hop: PadN.
            (60, [6, 0, 0x1e, 4, 1, 2, 3, 4]), // An unknown option to skip.
        ];
        for (i, (next, header)) in headers.into_iter().enumerate() {
            let syn = syn6(ME6, 40000 + i as u16, GATEWAY6, 53);
            raw.send(with_header(&syn, next, &header));
            let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("a reply");
            let (_, dst, proto, body) = parse6(&reply);
            assert_eq!((dst, proto), (ME6, 6), "header {i}");
            assert_eq!(u16::from_be_bytes([body[2], body[3]]), 40000 + i as u16);
            assert_eq!(body[13], SYN | ACK, "header {i}: the flags");
        }
        // A site's machine: look one up, then send it a SYN behind
        // Destination Options.
        let (_, addrs) = raw_dns6(
            &fcx,
            &mut raw,
            ME6,
            GATEWAY6,
            "plain.test",
            RecordType::AAAA,
        )
        .await
        .unwrap();
        let IpAddr::V6(site) = addrs[0] else {
            panic!("an AAAA record")
        };
        let syn = syn6(ME6, 41000, site, 80);
        let mut body = vec![6, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&syn.0[40..]);
        raw.send(ipv6(ME6, site, 60, &body));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a reply from the site");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[13]), (site, 6, SYN | ACK));
        Ok(())
    });
}

/// Extension headers a host must not accept are not delivered (RFC 8200,
/// sections 4.1 to 4.4). Where the RFC asks for it, the sender gets an
/// ICMPv6 "parameter problem" that points at the byte at fault.
#[test]
fn extension_headers_a_host_must_refuse_are_refused() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let ping = ping6(ME6, GATEWAY6, 7);
        // An unknown option whose type says to discard: nothing comes back.
        raw.send(with_header(&ping, 60, &[58, 0, 0x40, 0, 0, 0, 0, 0]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a discard option was delivered"
        );
        // (next header, header, code, pointer)
        let refused: [(u8, Vec<u8>, u8, u32); 4] = [
            // An unknown routing type with a segment left: points at the type.
            (43, vec![58, 0, 250, 1, 0, 0, 0, 0], 0, 42),
            // An unknown option whose type says to answer: points at it.
            (60, vec![58, 0, 1, 0, 0x80, 0, 0, 0], 2, 44),
            (60, vec![58, 0, 0xc2, 4, 0, 0, 0, 0], 2, 42),
            // Hop-by-Hop after Destination Options: points at the byte that
            // names it.
            (
                60,
                vec![0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0],
                1,
                40,
            ),
        ];
        for (next, header, code, pointer) in refused {
            let sent = with_header(&ping, next, &header);
            raw.send(sent.clone());
            let reply = recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("a parameter problem");
            let (src, dst, proto, body) = parse6(&reply);
            assert_eq!((src, dst, proto), (GATEWAY6, ME6, 58));
            assert_eq!((body[0], body[1]), (4, code), "{header:?}");
            assert_eq!(
                u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                pointer,
                "{header:?}"
            );
            assert_eq!(&body[8..], &sent.0[..], "the packet is quoted");
            assert!(
                recv_within(&fcx, &mut raw, Duration::from_millis(50))
                    .await
                    .is_none(),
                "{header:?} was delivered too"
            );
        }
        // A routing header with no segments left asks nothing of the host.
        raw.send(with_header(&ping, 43, &[58, 0, 250, 0, 0, 0, 0, 0]));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("an echo reply");
        assert_eq!(parse6(&reply).3[0], 129);
        Ok(())
    });
}

/// A UDP checksum field of zero means "no checksum" only over IPv4. Over
/// IPv6, DNS drops it, even when the sum over the datagram comes out right.
#[test]
fn dns_drops_a_zero_udp_checksum_over_ipv6() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::AAAA,
        ));
        let mut bytes = q.to_vec().unwrap();
        let mut u = vec![0x14, 0xe9, 0, 53];
        u.extend_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(&bytes);
        // Choose the DNS id so that the sum over the datagram, with the
        // checksum field zero, is right.
        let id = ip::transport_checksum(ME6.into(), GATEWAY6.into(), 17, &u);
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        u[8..].copy_from_slice(&bytes);
        assert_eq!(
            ip::transport_checksum(ME6.into(), GATEWAY6.into(), 17, &u),
            0
        );
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a zero UDP checksum was accepted over IPv6"
        );
        // The same datagram as a sender must send it: 0xffff for a sum of
        // zero. That is answered.
        u[6..8].copy_from_slice(&[0xff, 0xff]);
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a DNS answer");
        let (_, _, next, body) = parse6(&reply);
        assert_eq!(next, 17);
        let answer = Message::from_vec(&body[8..]).unwrap();
        assert_eq!((answer.metadata.id, answer.answers.len()), (id, 1));
        Ok(())
    });
}

/// A callback that gives every name a site makes no more than
/// `max_sites` of them. Past that, a new name gets SERVFAIL and no machine,
/// and the names that have sites keep working.
#[test]
fn dns_makes_no_more_sites_than_the_limit() {
    let make =
        || web::Sites::new(|_| Some(web::Site::new(Plain("wildcard")).ipv6_only())).max_sites(8);
    world_of(make, |fcx, attacher, log| async move {
        let mut raw = attacher.attach("a").unwrap();
        for i in 0..8 {
            // A questions make the site too, and get NODATA.
            let answer = raw_dns6(
                &fcx,
                &mut raw,
                ME6,
                GATEWAY6,
                &format!("n{i}.test"),
                RecordType::A,
            )
            .await
            .unwrap();
            assert_eq!(answer, (ResponseCode::NoError, vec![]));
        }
        for name in ["n8.test", "n9.test", "n8.test"] {
            let answer = raw_dns6(&fcx, &mut raw, ME6, GATEWAY6, name, RecordType::AAAA)
                .await
                .unwrap();
            assert_eq!(answer, (ResponseCode::ServFail, vec![]), "{name}");
        }
        assert_eq!(
            picked(&log, dns_seen)
                .iter()
                .filter(|d| answer(d) == "error 2")
                .count(),
            3
        );
        // The first eight still answer, and have machines.
        let site0 = Ipv6Addr::from(u128::from("2001:2::".parse::<Ipv6Addr>().unwrap()) + 1);
        let answer = raw_dns6(&fcx, &mut raw, ME6, GATEWAY6, "n0.test", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(answer, (ResponseCode::NoError, vec![site0.into()]));
        let base = u128::from("2001:2::".parse::<Ipv6Addr>().unwrap());
        for i in 1..=9u16 {
            let addr = Ipv6Addr::from(base + u128::from(i));
            raw.send(ping6(ME6, addr, i));
            let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("a reply");
            let (src, _, _, body) = parse6(&reply);
            if i <= 8 {
                assert_eq!((src, body[0]), (addr, 129), "site {i} answers pings");
            } else {
                // No ninth machine: the gateway says "address unreachable".
                assert_eq!((src, body[0], body[1]), (GATEWAY6, 1, 3));
            }
        }
        Ok(())
    });
}

/// An atomic fragment (offset 0, no more) that holds `inner`, itself a
/// fragment.
fn nested6(outer_id: u32, inner: &Packet) -> Packet {
    let mut body = vec![44, 0, 0, 0];
    body.extend_from_slice(&outer_id.to_be_bytes());
    body.extend_from_slice(&inner.0[40..]);
    ipv6(ME6, GATEWAY6, 44, &body)
}

/// A fragment inside a fragment is dropped, so it never waits anywhere a
/// later sandbox could complete it.
#[test]
fn a_fragment_inside_a_fragment_is_dropped() {
    world(|fcx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(nested6(
            1,
            &fragment6(ME6, GATEWAY6, 4242, 0, true, 58, &whole.0[40..56]),
        ));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(20))
                .await
                .is_none()
        );
        drop(a);
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for seq in 0..100 {
            b.send(ping6(ME6, GATEWAY6, seq));
            if recv_within(&fcx, &mut b, Duration::from_millis(20))
                .await
                .is_some()
            {
                bound = true;
                break;
            }
        }
        assert!(bound);
        b.send(nested6(
            2,
            &fragment6(ME6, GATEWAY6, 4242, 16, false, 58, &whole.0[56..]),
        ));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_none(),
            "a nested fragment completed a's packet"
        );
        Ok(())
    });
}

/// The headers in front of every fragment are checked, not only the first
/// fragment's, and a first fragment must hold the whole chain (RFC 7112).
#[test]
fn every_fragments_headers_are_checked() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        // The last fragment behind Hop-by-Hop with an option that says to
        // discard: the packet is never delivered.
        let whole = echo6_with(b"0123456789abcdef");
        raw.send(fragment6(ME6, GATEWAY6, 31, 0, true, 58, &whole.0[40..56]));
        let last = fragment6(ME6, GATEWAY6, 31, 16, false, 58, &whole.0[56..]);
        let mut body = vec![44, 0, 0x40, 0, 0, 0, 0, 0];
        body.extend_from_slice(&last.0[40..]);
        raw.send(ipv6(ME6, GATEWAY6, 0, &body));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a discard option on a later fragment was ignored"
        );
        // A Destination Options header cut in two by the fragments: the
        // first fragment gets "parameter problem" code 3, pointer 0.
        let mut dest = vec![58, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        dest.extend_from_slice(&whole.0[40..]);
        let first = fragment6(ME6, GATEWAY6, 32, 0, true, 60, &dest[..8]);
        raw.send(first.clone());
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a parameter problem");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 4, 3));
        assert_eq!(&body[4..8], &[0, 0, 0, 0]);
        raw.send(fragment6(ME6, GATEWAY6, 32, 8, false, 60, &dest[8..]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a split chain was delivered"
        );
        Ok(())
    });
}

/// A redirect gets no "parameter problem", whatever its headers say
/// (RFC 4443, section 2.4).
#[test]
fn a_redirect_gets_no_parameter_problem() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_some());
        let redirect = checksummed6(
            ME6,
            GATEWAY6,
            58,
            [vec![137, 0, 0, 0], vec![0; 36]].concat(),
            2,
        );
        raw.send(with_header(&redirect, 60, &[58, 0, 0x80, 0, 0, 0, 0, 0]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a redirect got an error"
        );
        Ok(())
    });
}

/// A packet to an address no machine has gets "address unreachable" from
/// the gateway, whatever its extension headers say: there is no host there
/// to answer "parameter problem".
#[test]
fn refused_headers_to_nowhere_get_address_unreachable() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_some());
        let ping = ping6(ME6, NOWHERE6, 2);
        let mut body = vec![58, 0, 250, 1, 0, 0, 0, 0];
        body.extend_from_slice(&ping.0[40..]);
        raw.send(ipv6(ME6, NOWHERE6, 43, &body));
        let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("an answer");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 1, 3));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_millis(50))
                .await
                .is_none()
        );
        Ok(())
    });
}
