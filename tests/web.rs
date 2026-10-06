//! `web::Sites`, in one process. Each test plays one or more sandboxes:
//! raw packets on the attachment's cable, or a machine built from stdlib
//! parts (`split_protocols`, `tcp::endpoint`, `udp::endpoint`) with a
//! rustls client and a hyper client on top.

use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use axum::Extension;
use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::tls;
use fictionet::stdlib::journal::{Entry, Fields, Journal};
use fictionet::stdlib::{ConnError, Connection, dhcp, ip, tcp, udp, web};
use fictionet::{Attacher, Cx, End, Interface, Packet, block_on, run};
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

// ---------------------------------------------------------------------------
// Running a test world

fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}

#[derive(Debug)]
struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

/// Runs a world with the test sites. `f` gets the attacher and plays the
/// sandboxes. When it returns, the world ends with `Done`, which cancels
/// everything.
fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let result = within(Duration::from_secs(60), move || {
        block_on(run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let env = sites(&cx).serve_with(&cx, attachments)?;
            f(cx, attacher, env).await?;
            Err(Box::new(Done) as fictionet::Error)
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// Waits for `fut` at most `d`.
async fn timeout<T>(cx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
    let mut fut = pin!(fut);
    let mut sleep = pin!(cx.sleep(d));
    poll_fn(|task| {
        if let Poll::Ready(v) = fut.as_mut().poll(task) {
            return Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
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
}

struct TestSites {
    sites: web::Sites,
    env: Env,
}

impl TestSites {
    fn serve_with(self, cx: &Cx, attachments: fictionet::Attachments) -> fictionet::Result<Env> {
        self.sites.serve(cx, attachments)?;
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

/// What `events.test` tells the journal about a page, through the
/// response's extensions.
fn page(kind: &'static str) -> Fields {
    Fields::new().with("page", kind)
}

/// The size of `events.test/big`.
const BIG: usize = 4 << 20;

fn events_site() -> axum::Router {
    axum::Router::new()
        .route(
            "/page",
            axum::routing::get(|Extension(t): Extension<web::Target>| async move {
                (Extension(page("article")), format!("page sni={:?}", t.sni))
            }),
        )
        .route("/big", axum::routing::get(|| async { vec![b'x'; BIG] }))
        .route("/wait", axum::routing::get(|| async {
            std::future::pending::<()>().await;
            "never"
        }))
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
fn sites(cx: &Cx) -> TestSites {
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
        tls::config_builder(cx, SystemTime::now(), rustls::crypto::ring::default_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.chain, certs.key)
            .unwrap(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let env = Env { roots: Arc::new(certs.roots), calls: calls.clone(), served: served.clone() };

    let secure = axum::Router::new().fallback(move |Extension(t): Extension<web::Target>, version: Version| {
        let n = served.fetch_add(1, Ordering::SeqCst) + 1;
        async move { format!("secure {} {} {} {:?} #{n}", t.scheme, t.host, t.port, version) }
    });
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
            "inside6.test" => Some(web::Site::new(Plain("inside")).at("2001:db8::50".parse::<Ipv6Addr>().unwrap())),
            "dual.test" => Some(web::Site::new(secure.clone()).at(DUAL_ADDR).at(DUAL_ADDR6).tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "v4only.test" => Some(web::Site::new(secure.clone()).ipv4_only().tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "v6only.test" => Some(web::Site::new(secure.clone()).ipv6_only().at(V6ONLY_ADDR6).tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "broken.test" => Some(web::Site::new(Broken)),
            h if h.ends_with(".wild.test") => Some(web::Site::new(Plain("wild"))),
            "slow.test" => Some(web::Site::new(events_site())),
            "events.test" => Some(web::Site::new(events_site()).at(EVENTS_ADDR).tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "both.test" => Some(
                web::Site::new(secure.clone())
                    .at(BOTH_ADDR)
                    .tls({
                        let c = config.clone();
                        move |_| c.clone()
                    })
                    .plain_http(),
            ),
            "default.test" => Some(web::Site::new(Plain("default")).at(DEFAULT_ADDR).default_host()),
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
        let t = request.extensions().get::<web::Target>().expect("serve sets a Target");
        let body = format!("{} {} {} {} {:?} {}", self.0, t.scheme, t.host, t.port, request.version(), request.uri().path());
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

struct Certs {
    roots: RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn certs(names: &[&str]) -> Certs {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Certs {
        roots,
        chain: vec![leaf.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

// ---------------------------------------------------------------------------
// A sandbox built from stdlib parts

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

struct Machine {
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    _icmp: End,
}

fn machine(cx: &Cx, attacher: &Attacher, name: &str, addr: impl Into<IpAddr>) -> Machine {
    let end = attacher.attach(name).unwrap();
    let (tcp, udp, icmp, _other) = ip::split_protocols(cx, end);
    let addr = addr.into();
    Machine { tcp: tcp::endpoint(cx, tcp, addr), udp: udp::endpoint(cx, udp, addr), _icmp: icmp }
}

/// Asks the gateway's DNS over UDP. Returns the response code and the A
/// records.
async fn dns(cx: &Cx, m: &Machine, name: &str, kind: RecordType) -> (ResponseCode, Vec<Ipv4Addr>) {
    let mut socket = m.udp.bind(40000 + (cx.random_u64() % 20000) as u16).unwrap();
    let mut q = Message::query();
    q.metadata.id = cx.random_u64() as u16;
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, from) = timeout(cx, Duration::from_secs(5), socket.recv(cx)).await.expect("a DNS answer").unwrap();
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

async fn lookup(cx: &Cx, m: &Machine, name: &str) -> Ipv4Addr {
    let (code, addrs) = dns(cx, m, name, RecordType::A).await;
    assert_eq!(code, ResponseCode::NoError, "{name}");
    assert_eq!(addrs.len(), 1, "{name}");
    addrs[0]
}

// ---------------------------------------------------------------------------
// A rustls client as a Connection

struct TlsClient<C> {
    conn: C,
    tls: ClientConnection,
    out: Vec<u8>,
    inbuf: Box<[u8]>,
    /// Bytes read from `conn` that rustls could not take yet, because its
    /// plaintext buffer was full.
    pending: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
enum TlsError {
    Conn(ConnError),
    Tls(rustls::Error),
}

impl<C: Connection + Unpin> TlsClient<C> {
    fn new(conn: C, roots: &Arc<RootCertStore>, name: &str, alpn: &[&[u8]]) -> Self {
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let tls = ClientConnection::new(Arc::new(config), ServerName::try_from(name.to_owned()).unwrap()).unwrap();
        TlsClient::with(conn, tls)
    }

    fn with(conn: C, tls: ClientConnection) -> Self {
        TlsClient { conn, tls, out: Vec::new(), inbuf: vec![0; 4096].into_boxed_slice(), pending: Vec::new() }
    }

    fn poll_flush(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        loop {
            if self.out.is_empty() {
                if !self.tls.wants_write() {
                    return Poll::Ready(Ok(()));
                }
                self.tls.write_tls(&mut self.out).unwrap();
            }
            match self.conn.poll_write(cx, task, &self.out) {
                Poll::Ready(Ok(n)) => {
                    self.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Reads from the connection into rustls once. `Ok(false)` at the end
    /// of the stream.
    fn poll_fill(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<bool, TlsError>> {
        let fresh;
        let mut data: &[u8] = if !self.pending.is_empty() {
            fresh = std::mem::take(&mut self.pending);
            &fresh
        } else {
            let n = match self.conn.poll_read(cx, task, &mut self.inbuf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(TlsError::Conn(e))),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                let _ = self.tls.read_tls(&mut &[][..]);
            }
            &self.inbuf[..n]
        };
        let n = data.len();
        loop {
            if !data.is_empty() && self.tls.read_tls(&mut data).is_err() {
                // The plaintext buffer is full: the reader must take some
                // first.
                self.pending = data.to_vec();
                return Poll::Ready(Ok(true));
            }
            let r = self.tls.process_new_packets();
            if let Err(e) = r {
                // Send our alert, best effort.
                let _ = self.poll_flush(cx, task);
                return Poll::Ready(Err(TlsError::Tls(e)));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(n > 0));
            }
        }
    }

    async fn handshake(&mut self, cx: &Cx) -> Result<(), TlsError> {
        poll_fn(|task| {
            loop {
                match self.poll_flush(cx, task) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(TlsError::Conn(e))),
                    Poll::Pending => return Poll::Pending,
                }
                if !self.tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                match self.poll_fill(cx, task) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) => return Poll::Ready(Err(TlsError::Conn(ConnError::Closed))),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }
}

impl<C: Connection + Unpin> Connection for TlsClient<C> {
    fn poll_read(&mut self, cx: &Cx, task: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, ConnError>> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Poll::Ready(Ok(0)),
                Err(_) => return Poll::Ready(Err(ConnError::Broken)),
            }
            if let Poll::Ready(Err(e)) = self.poll_flush(cx, task) {
                return Poll::Ready(Err(e));
            }
            match self.poll_fill(cx, task) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => {
                    return match self.tls.reader().read(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(_) => Poll::Ready(Ok(0)),
                    };
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(ConnError::Broken)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        if let Poll::Ready(Err(e)) = self.poll_flush(cx, task) {
            return Poll::Ready(Err(e));
        }
        let n = self.tls.writer().write(data).unwrap();
        let _ = self.poll_flush(cx, task);
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.tls.send_close_notify();
        match self.poll_flush(cx, task) {
            Poll::Ready(Ok(())) => self.conn.poll_shutdown(cx, task),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// A hyper client over a Connection

struct Io<C> {
    cx: Cx,
    conn: C,
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut tmp = vec![0u8; buf.remaining().min(16 * 1024)];
        match this.conn.poll_read(&this.cx, task, &mut tmp) {
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
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn.poll_write(&this.cx, task, data).map_err(std::io::Error::other)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.poll_shutdown(&this.cx, task).map_err(std::io::Error::other)
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
    async fn new<C: Connection + Unpin>(cx: &Cx, conn: C, h2: bool) -> Client {
        let io = Io { cx: cx.clone(), conn };
        if h2 {
            let (send, conn) = hyper::client::conn::http2::handshake(Exec(cx.clone()), io).await.unwrap();
            cx.spawn(move |_| async move {
                let _ = conn.await;
                Ok(())
            });
            Client::H2(send)
        } else {
            let (send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            cx.spawn(move |_| async move {
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
                let r = Request::builder().method(method).uri(path).header("host", host).body(Empty::new()).unwrap();
                s.send_request(r).await.unwrap()
            }
            Client::H2(s) => {
                s.ready().await.unwrap();
                let r = Request::builder().method(method).uri(format!("{scheme}://{host}{path}")).body(Empty::new()).unwrap();
                s.send_request(r).await.unwrap()
            }
        };
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Got { status, headers, body: String::from_utf8(body.to_vec()).unwrap(), version }
    }
}

/// Opens a TLS connection from `m` to `addr:443` with `sni` and `alpn`.
async fn tls_connect(
    cx: &Cx,
    m: &Machine,
    env: &Env,
    addr: impl Into<IpAddr>,
    sni: &str,
    alpn: &[&[u8]],
) -> Result<TlsClient<tcp::TcpConnection>, TlsError> {
    let tcp = m.tcp.connect(cx, SocketAddr::new(addr.into(), 443)).await.map_err(TlsError::Conn)?;
    let mut client = TlsClient::new(tcp, &env.roots, sni, alpn);
    client.handshake(cx).await?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// Tests: DNS

#[test]
fn dns_answers_sites_nodata_and_nxdomain() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));

        // A site with `at` gets that address; the same answer every time.
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&cx, &m, "secure.test.").await, SECURE_ADDR);
        assert_eq!(lookup(&cx, &m, "SeCuRe.TeSt").await, SECURE_ADDR);
        // Without `at`, an address from 198.18.0.0/15.
        let plain = lookup(&cx, &m, "plain.test").await;
        assert_eq!(plain, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(lookup(&cx, &m, "broken.test").await, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(lookup(&cx, &m, "plain.test").await, plain);

        // Other types of a site's name: NODATA. (AAAA is in the IPv6 tests.)
        assert_eq!(dns(&cx, &m, "secure.test", RecordType::MX).await, (ResponseCode::NoError, vec![]));
        // Names the callback turned down: NXDOMAIN, for every type.
        assert_eq!(dns(&cx, &m, "nope.test", RecordType::A).await, (ResponseCode::NXDomain, vec![]));
        assert_eq!(dns(&cx, &m, "nope.test", RecordType::AAAA).await, (ResponseCode::NXDomain, vec![]));
        // A site that asks for an address inside the sandboxes' subnet.
        assert_eq!(dns(&cx, &m, "inside.test", RecordType::A).await, (ResponseCode::NXDomain, vec![]));

        // The callback ran once per name: secure, plain, broken, nope, inside.
        assert_eq!(env.calls.load(Ordering::SeqCst), 5);

        // DNS over TCP, two queries on one connection.
        let mut conn = m.tcp.connect(&cx, SocketAddr::new(GATEWAY.into(), 53)).await.unwrap();
        for (name, id) in [("secure.test", 7u16), ("nope.test", 8)] {
            let mut q = Message::query();
            q.metadata.id = id;
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            let bytes = q.to_vec().unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            conn.write_all(&cx, &framed).await.unwrap();
            let mut len = [0u8; 2];
            read_exact(&cx, &mut conn, &mut len).await;
            let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
            read_exact(&cx, &mut conn, &mut reply).await;
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

async fn read_exact<C: Connection>(cx: &Cx, conn: &mut C, buf: &mut [u8]) {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(cx, &mut buf[at..]).await.unwrap();
        assert!(n > 0, "the stream ended early");
        at += n;
    }
}

// ---------------------------------------------------------------------------
// Tests: HTTPS, HTTP/2 and HTTP/1.1

#[test]
fn https_with_http2_and_http11() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;

        // A client that offers h2 gets HTTP/2.
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[b"h2", b"http/1.1"]).await.unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&cx, conn, true).await;
        let got = client.get("https", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/2.0 #1");

        // Many streams at once on the one connection.
        let Client::H2(send) = &client else { unreachable!() };
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let mut c = Client::H2(send.clone());
            tasks.push(cx.spawn(move |_| async move {
                let got = c.get("https", "secure.test", "/x").await;
                assert_eq!(got.status, StatusCode::OK);
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&cx).await?;
        }
        assert_eq!(env.served.load(Ordering::SeqCst), 21);

        // A client that offers only http/1.1 gets it.
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[b"http/1.1"]).await.unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"http/1.1".as_slice()));
        let mut client = Client::new(&cx, conn, false).await;
        let got = client.get("https", "secure.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.version, Version::HTTP_11);
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #22");
        // Keep-alive: a second request on the same connection.
        let got = client.get("https", "secure.test:443", "/").await;
        assert_eq!(got.body, "secure https secure.test 443 HTTP/1.1 #23");

        // A client that offers no ALPN at all gets HTTP/1.1.
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[]).await.unwrap();
        assert_eq!(conn.tls.alpn_protocol(), None);
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("https", "secure.test", "/").await.status, StatusCode::OK);
        Ok(())
    });
}

#[test]
fn port_80_redirects_tls_sites_and_serves_the_others() {
    world(|cx, attacher, _env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        assert_eq!(lookup(&cx, &m, "shared.test").await, addr);
        let plain = lookup(&cx, &m, "plain.test").await;

        // A site with TLS: 301 to https, with the path and query.
        let conn = m.tcp.connect(&cx, SocketAddr::new(addr.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        let got = client.get("http", "secure.test", "/a/b?c=d").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://secure.test/a/b?c=d");
        // The site without TLS at the same address, on the same connection.
        let got = client.get("http", "shared.test", "/p").await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.body, "shared http shared.test 80 HTTP/1.1 /p");

        // A site with its own address, over HTTP/1.1 and HTTP/2 with prior
        // knowledge.
        let conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "plain.test", "/q").await.body, "plain http plain.test 80 HTTP/1.1 /q");
        let conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        let got = client.get("http", "plain.test", "/r").await;
        assert_eq!(got.version, Version::HTTP_2);
        assert_eq!(got.body, "plain http plain.test 80 HTTP/2.0 /r");

        // Port 443 is closed on a machine with no TLS site.
        assert_eq!(m.tcp.connect(&cx, SocketAddr::new(plain.into(), 443)).await.err(), Some(ConnError::Refused));
        Ok(())
    });
}

#[test]
fn a_tls_site_with_plain_http_answers_port_80_itself() {
    world_events(|cx, attacher, env, log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&cx, &m, "both.test").await, BOTH_ADDR);

        // Port 80: the handler answers, with an http Target, over HTTP/1.1
        // and HTTP/2 with prior knowledge. No redirect.
        for h2 in [false, true] {
            let conn = m.tcp.connect(&cx, SocketAddr::new(BOTH_ADDR.into(), 80)).await.unwrap();
            let mut client = Client::new(&cx, conn, h2).await;
            let got = client.get("http", "both.test", "/a?b=c").await;
            assert_eq!(got.status, StatusCode::OK);
            assert!(got.headers.get("location").is_none());
            let version = if h2 { "HTTP/2.0" } else { "HTTP/1.1" };
            assert!(got.body.starts_with(&format!("secure http both.test 80 {version} #")), "{}", got.body);
        }

        // Port 443 still serves it over TLS.
        let conn = tls_connect(&cx, &m, &env, BOTH_ADDR, "both.test", &[b"http/1.1"]).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        let got = client.get("https", "both.test", "/").await;
        assert_eq!(got.status, StatusCode::OK);
        assert!(got.body.starts_with("secure https both.test 443 HTTP/1.1 #"), "{}", got.body);

        // Each plain request is a Handler event on port 80, with no SNI.
        let seen = wait_for(&cx, &log, 3, http_seen).await;
        let plain: Vec<_> = seen.iter().filter(|h| h.local.port() == 80).collect();
        assert_eq!(plain.len(), 2);
        for h in plain {
            assert_eq!(h.answer, HttpAnswer::Handler);
            assert_eq!(h.scheme, http::uri::Scheme::HTTP);
            assert_eq!(h.sni, None);
            assert_eq!(h.status, Some(StatusCode::OK));
            assert_eq!(h.uri.path(), "/a");
        }

        // A TLS site without it still redirects, at the same time.
        let secure = lookup(&cx, &m, "secure.test").await;
        let conn = m.tcp.connect(&cx, SocketAddr::new(secure.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "secure.test", "/").await.status, StatusCode::MOVED_PERMANENTLY);
        Ok(())
    });
}

#[test]
fn a_host_that_is_not_this_site_gets_421() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        lookup(&cx, &m, "shared.test").await;
        let plain = lookup(&cx, &m, "plain.test").await;

        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&cx, &m, &env, addr, "secure.test", alpn).await.unwrap();
            let mut client = Client::new(&cx, conn, h2).await;
            // A name with no site at all.
            assert_eq!(client.get("https", "nope.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
            // A site at another address.
            assert_eq!(client.get("https", "plain.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
            // A site at this address, but without TLS.
            assert_eq!(client.get("https", "shared.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
            // The connection still works.
            assert_eq!(client.get("https", "secure.test", "/").await.status, StatusCode::OK);
        }

        // Plain HTTP too.
        let conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "secure.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(client.get("http", "198.18.0.1", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
        Ok(())
    });
}

#[test]
fn a_failing_handler_gets_500() {
    world(|cx, attacher, _env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "broken.test").await;
        let conn = m.tcp.connect(&cx, SocketAddr::new(addr.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "broken.test", "/").await.status, StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    });
}

#[test]
fn an_unknown_tls_name_is_rejected_with_unrecognized_name() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        lookup(&cx, &m, "shared.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        // A name with no site; a site here without TLS; a site elsewhere.
        for sni in ["nope.test", "shared.test", "plain.test"] {
            match tls_connect(&cx, &m, &env, addr, sni, &[b"h2"]).await {
                Err(TlsError::Tls(rustls::Error::AlertReceived(rustls::AlertDescription::UnrecognisedName))) => {}
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

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum()
}

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Packet {
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, proto, 0, 0];
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = fold(sum16(&p));
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    Packet(p)
}

fn ping(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Packet {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fictionet");
    let c = fold(sum16(&icmp));
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
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(u.len() as u16).to_be_bytes());
    let c = fold(sum16(&pseudo) + sum16(&u));
    u[6..8].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 17, &u)
}

/// (src, dst, protocol, payload) of an IPv4 packet.
fn parse(p: &Packet) -> (Ipv4Addr, Ipv4Addr, u8, Vec<u8>) {
    let b = &p.0;
    assert_eq!(b[0] >> 4, 4);
    assert_eq!(fold(sum16(&b[..20])), 0, "IPv4 header checksum");
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    (src, dst, b[9], b[20..].to_vec())
}

async fn recv_within(cx: &Cx, end: &mut End, d: Duration) -> Option<Packet> {
    timeout(cx, d, end.recv(cx)).await.map(|r| r.unwrap())
}

const SHORT: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Tests: routing, unreachable, isolation, binding

#[test]
fn unknown_addresses_get_host_unreachable_and_sites_appear_on_lookup() {
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();

        // An address that no site has: ICMP host unreachable, at once, from
        // the gateway, quoting the packet.
        let sent = ping(me, Ipv4Addr::new(192, 0, 2, 1), 1);
        raw.send(sent.clone());
        let reply = recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("host unreachable");
        let (src, dst, proto, icmp) = parse(&reply);
        assert_eq!((src, dst, proto), (GATEWAY, me, 1));
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        assert_eq!(fold(sum16(&icmp)), 0, "ICMP checksum");
        assert_eq!(&icmp[8..], &sent.0[..]);

        // A site's address before its name was looked up: unreachable too.
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 2));
        let (_, _, _, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((icmp[0], icmp[1]), (3, 1));

        // Look the name up (raw DNS over UDP), then the address answers.
        let mut q = Message::query();
        q.metadata.id = 99;
        q.add_query(Query::query(Name::from_ascii("plain.test").unwrap(), RecordType::A));
        raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (src, _, proto, u) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((src, proto), (GATEWAY, 17));
        assert_eq!(parse_dns(&u[8..], 99), (ResponseCode::NoError, vec![Ipv4Addr::new(198, 18, 0, 1)]));
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 3));
        let (src, dst, _, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((src, dst, icmp[0]), (Ipv4Addr::new(198, 18, 0, 1), me, 0), "an echo reply from the site");

        // The gateway answers pings.
        raw.send(ping(me, GATEWAY, 4));
        let (src, _, _, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((src, icmp[0]), (GATEWAY, 0));

        // UDP to a site: port unreachable, so clients fail at once.
        raw.send(udp(me, 5000, Ipv4Addr::new(198, 18, 0, 1), 9999, b"x"));
        let (_, _, proto, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((proto, icmp[0], icmp[1]), (1, 3, 3));

        // An ICMP error gets no ICMP error back. IPv6 to the unspecified
        // address is dropped.
        let mut err = vec![3, 1, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..28]);
        let c = fold(sum16(&err));
        err[2..4].copy_from_slice(&c.to_be_bytes());
        raw.send(ipv4(me, Ipv4Addr::new(192, 0, 2, 1), 1, &err));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        v6.extend_from_slice(&[0; 32]);
        raw.send(Packet(v6));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn sandboxes_cannot_reach_each_other() {
    world(|cx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();
        // Both bind their addresses with a ping to the gateway.
        a.send(ping(a_addr, GATEWAY, 1));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());
        b.send(ping(b_addr, GATEWAY, 1));
        assert!(recv_within(&cx, &mut b, Duration::from_secs(2)).await.is_some());

        // a to b: nothing arrives at b, and a hears nothing back.
        a.send(ping(a_addr, b_addr, 2));
        a.send(udp(a_addr, 1000, b_addr, 2000, b"hello"));
        // Nor to the subnet's broadcast address, or 255.255.255.255.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 255), 3));
        a.send(udp(a_addr, 1000, Ipv4Addr::BROADCAST, 2000, b"hello"));
        // Nor to an address in the subnet that no one has.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 77), 4));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none());
        assert!(recv_within(&cx, &mut a, Duration::from_millis(10)).await.is_none());

        // Both still reach the gateway.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(recv_within(&cx, &mut b, Duration::from_secs(2)).await.is_some());
        Ok(())
    });
}

#[test]
fn spoofed_and_taken_sources_are_dropped() {
    world(|cx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();

        // Sources a sandbox can never bind: outside the subnet, the
        // gateway, the network and broadcast addresses, 0.0.0.0.
        for src in [Ipv4Addr::new(192, 168, 1, 5), GATEWAY, Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)] {
            a.send(ping(src, GATEWAY, 1));
        }
        a.send(ping(Ipv4Addr::UNSPECIFIED, GATEWAY, 1));
        assert!(recv_within(&cx, &mut a, SHORT).await.is_none());

        // a binds 10.0.0.2.
        a.send(ping(a_addr, GATEWAY, 2));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());
        // b cannot take it.
        b.send(ping(a_addr, GATEWAY, 3));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none());
        assert!(recv_within(&cx, &mut a, Duration::from_millis(10)).await.is_none());
        // a cannot send from any other address now.
        a.send(ping(b_addr, GATEWAY, 4));
        assert!(recv_within(&cx, &mut a, SHORT).await.is_none());
        // b binds 10.0.0.3, which a just tried to use.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(recv_within(&cx, &mut b, Duration::from_secs(2)).await.is_some());

        // When a detaches, its address is free again.
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        let mut freed = false;
        for seq in 0..50 {
            c.send(ping(a_addr, GATEWAY, seq));
            if recv_within(&cx, &mut c, Duration::from_millis(50)).await.is_some() {
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
async fn dhcp_ask(cx: &Cx, end: &mut End, src: Ipv4Addr, dst: Ipv4Addr, m: &dhcp::Message) -> Option<(Ipv4Addr, dhcp::Message)> {
    end.send(udp(src, 68, dst, 67, &m.to_bytes()));
    let p = recv_within(cx, end, SHORT).await?;
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
    world(|cx, attacher, _env| async move {
        let any = Ipv4Addr::UNSPECIFIED;
        let bc = Ipv4Addr::BROADCAST;
        let mut a = attacher.attach("a").unwrap();

        // DISCOVER from 0.0.0.0: OFFER of the lowest free address, with the
        // settings.
        let (to, offer) = dhcp_ask(&cx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1)).await.expect("an offer");
        assert_eq!(to, bc);
        assert_eq!(offer.message_type(), Some(dhcp::OFFER));
        let addr = offer.yiaddr;
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(offer.option_addr(dhcp::opt::SERVER_ID), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::ROUTER), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::SUBNET_MASK), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(offer.option_u32(dhcp::opt::LEASE_TIME), Some(3600));

        // The offer is held: another sandbox cannot bind it statically.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(addr, GATEWAY, 1));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none());
        // b's own DISCOVER gets the next address, even if it asks for a's.
        let mut discover = dhcp_msg(dhcp::DISCOVER, 2, 2);
        discover.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, offer_b) = dhcp_ask(&cx, &mut b, any, bc, &discover).await.unwrap();
        assert_eq!(offer_b.yiaddr, Ipv4Addr::new(10, 0, 0, 3));
        // b asking to bind a's address: NAK.
        let mut request = dhcp_msg(dhcp::REQUEST, 3, 2);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, nak) = dhcp_ask(&cx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));

        // a takes its offer.
        let mut request = dhcp_msg(dhcp::REQUEST, 4, 1);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (to, ack) = dhcp_ask(&cx, &mut a, any, bc, &request).await.unwrap();
        assert_eq!(to, bc);
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        assert_eq!(ack.yiaddr, addr);

        // Bound: pings from the address work, from others do not.
        a.send(ping(addr, GATEWAY, 2));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());
        a.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        assert!(recv_within(&cx, &mut a, SHORT).await.is_none());

        // Renewal: unicast from the address, with ciaddr. ACK to the address.
        let mut renew = dhcp_msg(dhcp::REQUEST, 5, 1);
        renew.ciaddr = addr;
        let (to, ack) = dhcp_ask(&cx, &mut a, addr, GATEWAY, &renew).await.unwrap();
        assert_eq!((to, ack.message_type(), ack.yiaddr), (addr, Some(dhcp::ACK), addr));
        // Rebinding: broadcast from the address.
        let (_, ack) = dhcp_ask(&cx, &mut a, addr, bc, &renew).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        // DHCP from an address that is not a's: dropped.
        let mut other = dhcp_msg(dhcp::REQUEST, 6, 1);
        other.ciaddr = Ipv4Addr::new(10, 0, 0, 9);
        assert!(dhcp_ask(&cx, &mut a, Ipv4Addr::new(10, 0, 0, 9), GATEWAY, &other).await.is_none());

        // Restart: from 0.0.0.0 again, the same address.
        let (_, offer) = dhcp_ask(&cx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 7, 1)).await.unwrap();
        assert_eq!(offer.yiaddr, addr);
        // INIT-REBOOT for another address: NAK; for its own: ACK.
        let mut reboot = dhcp_msg(dhcp::REQUEST, 8, 1);
        reboot.push(dhcp::opt::REQUESTED_IP, Ipv4Addr::new(10, 0, 0, 20).octets());
        let (_, nak) = dhcp_ask(&cx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));
        let mut reboot = dhcp_msg(dhcp::REQUEST, 9, 1);
        reboot.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, ack) = dhcp_ask(&cx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!((ack.message_type(), ack.yiaddr), (Some(dhcp::ACK), addr));
        // The agent changing its MAC does not get it a second address.
        let (_, offer) = dhcp_ask(&cx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 10, 99)).await.unwrap();
        assert_eq!(offer.yiaddr, addr);

        // A REQUEST naming another server is ignored.
        let mut elsewhere = dhcp_msg(dhcp::REQUEST, 11, 3);
        elsewhere.push(dhcp::opt::REQUESTED_IP, Ipv4Addr::new(10, 0, 0, 30).octets());
        elsewhere.push(dhcp::opt::SERVER_ID, Ipv4Addr::new(10, 0, 0, 254).octets());
        assert!(dhcp_ask(&cx, &mut b, any, bc, &elsewhere).await.is_none());

        // b takes its offer; then a detaches, and a new sandbox asking for
        // a's old address gets it.
        let mut request = dhcp_msg(dhcp::REQUEST, 12, 2);
        request.push(dhcp::opt::REQUESTED_IP, offer_b.yiaddr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&cx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        let mut got = None;
        for xid in 100..150 {
            let mut d = dhcp_msg(dhcp::DISCOVER, xid, 4);
            d.push(dhcp::opt::REQUESTED_IP, addr.octets());
            let (_, offer) = dhcp_ask(&cx, &mut c, any, bc, &d).await.unwrap();
            if offer.yiaddr == addr {
                got = Some(offer.yiaddr);
                break;
            }
            cx.sleep(Duration::from_millis(20)).await?;
        }
        assert_eq!(got, Some(addr), "a's address is free once a detached");

        // INFORM from a static address: an ACK with the settings and no lease.
        let mut d = attacher.attach("d").unwrap();
        let d_addr = Ipv4Addr::new(10, 0, 0, 40);
        d.send(ping(d_addr, GATEWAY, 1));
        assert!(recv_within(&cx, &mut d, Duration::from_secs(2)).await.is_some());
        let mut inform = dhcp_msg(dhcp::INFORM, 13, 5);
        inform.ciaddr = d_addr;
        let (to, ack) = dhcp_ask(&cx, &mut d, d_addr, GATEWAY, &inform).await.unwrap();
        assert_eq!((to, ack.message_type(), ack.yiaddr), (d_addr, Some(dhcp::ACK), Ipv4Addr::UNSPECIFIED));
        assert_eq!(ack.option_u32(dhcp::opt::LEASE_TIME), None);
        assert_eq!(ack.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        // And DHCP to the server from a static sandbox asking for a lease
        // gets its static address.
        let (_, offer) = dhcp_ask(&cx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 14, 5)).await.unwrap();
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
    let bytes = m.to_bytes();
    assert!(bytes.len() >= 300);
    assert_eq!(dhcp::Message::parse(&bytes), Some(m));
    assert_eq!(dhcp::Message::parse(&bytes[..239]), None);
}

#[test]
fn a_subnet_that_cannot_work_is_an_error() {
    let result = within(Duration::from_secs(10), || {
        block_on(run(|cx| async move {
            for bad in ["10.0.0.0/31", "10.0.0.0/4", "fe80::/64", "ff00::/8", "::/8", "2001:db8::/127", "2001:db8::/4"] {
                let (_attacher, attachments) = fictionet::attachments();
                let r = web::Sites::new(|_| None).subnet(bad.parse()?).serve(&cx, attachments);
                assert!(r.is_err(), "{bad}");
            }
            // Another subnet works, with its gateway at .1.
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|_| None).subnet("172.16.5.0/24".parse()?).serve(&cx, attachments)?;
            let mut a = attacher.attach("a").unwrap();
            let gw = Ipv4Addr::new(172, 16, 5, 1);
            a.send(ping(Ipv4Addr::new(172, 16, 5, 9), gw, 1));
            let (src, _, _, icmp) = parse(&recv_within(&cx, &mut a, Duration::from_secs(2)).await.unwrap());
            assert_eq!((src, icmp[0]), (gw, 0));
            Err(Box::new(Done) as fictionet::Error)
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
        let r = block_on(run(move |cx| async move {
            web::Sites::new(|h| (h == "plain.test").then(|| web::Site::new(Plain("plain")))).serve(&cx, attachments)?;
            let _ = tx.send(cx.clone());
            Ok(())
        }));
        let _ = r;
    });
    let cx = rx.recv().unwrap();
    let mut a = attacher.attach("a").unwrap();
    let me = Ipv4Addr::new(10, 0, 0, 2);
    a.send(ping(me, GATEWAY, 1));
    let reply = within(Duration::from_secs(5), move || {
        block_on(async move { timeout(&cx, Duration::from_secs(2), a.recv(&cx)).await })
    });
    let (src, _, _, icmp) = parse(&reply.expect("a reply").unwrap());
    assert_eq!((src, icmp[0]), (GATEWAY, 0));
}

#[test]
fn the_target_is_from_the_connection_not_the_headers() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[b"http/1.1"]).await.unwrap();
        let Client::H1(mut send) = Client::new(&cx, conn, false).await else { unreachable!() };
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
        assert!(String::from_utf8_lossy(&body).starts_with("secure https secure.test 443 HTTP/1.1"), "{body:?}");
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
        run(|cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|h| (h == "nowhere.invalid").then(|| web::Site::new(web::proxy()))).serve(&cx, attachments)?;
            let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
            let addr = lookup(&cx, &m, "nowhere.invalid").await;
            let conn = m.tcp.connect(&cx, SocketAddr::new(addr.into(), 80)).await.unwrap();
            let mut client = Client::new(&cx, conn, false).await;
            let got = client.get("http", "nowhere.invalid", "/").await;
            assert_eq!(got.status, StatusCode::BAD_GATEWAY, "{}", got.body);
            assert!(got.body.contains("nowhere.invalid"), "{}", got.body);
            Err(Box::new(Done) as fictionet::Error)
        }),
    )
    .await
    .expect("timed out");
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

// ---------------------------------------------------------------------------
// Tests: an agent trying to wear the world down

/// An IPv4 fragment: `data` at byte `offset` of packet `id`.
fn fragment(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, offset: usize, more: bool, data: &[u8]) -> Packet {
    let mut p = ipv4(src, dst, proto, data);
    p.0[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    p.0[6..8].copy_from_slice(&flags.to_be_bytes());
    p.0[10..12].copy_from_slice(&[0, 0]);
    let c = fold(sum16(&p.0[..20]));
    p.0[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// Tens of thousands of first fragments that never complete, each a
/// different packet, must not stall the gateway for everyone else.
#[test]
fn a_flood_of_unfinished_fragments_does_not_stall_the_gateway() {
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping(me, GATEWAY, 1));
        assert!(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.is_some());
        let started = std::time::Instant::now();
        for i in 0..60_000u32 {
            let proto = [17u8, 6, 1][(i % 3) as usize];
            raw.send(fragment(me, GATEWAY, proto, (i / 3) as u16, 0, true, &[0; 8]));
        }
        // A ping sent after the flood is answered once the gateway has gone
        // through every fragment before it. That must be quick.
        raw.send(ping(me, GATEWAY, 2));
        let reply = recv_within(&cx, &mut raw, Duration::from_secs(5)).await;
        assert!(reply.is_some(), "no ping reply {:?} after the flood started", started.elapsed());
        eprintln!("60,000 fragments went through in {:?}", started.elapsed());
        Ok(())
    });
}

/// A TCP segment with a good checksum.
#[allow(clippy::too_many_arguments)]
fn tcp_seg(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(data);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(t.len() as u16).to_be_bytes());
    let c = fold(sum16(&pseudo) + sum16(&t));
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
async fn open_idle(cx: &Cx, raw: &mut End, me: Ipv4Addr, to: SocketAddr, n: u16) -> (usize, std::collections::BTreeSet<u16>) {
    let IpAddr::V4(dst) = to.ip() else { unreachable!() };
    let mut open = 0;
    let mut opened = std::collections::HashSet::new();
    let mut closed = std::collections::BTreeSet::new();
    for batch in (0..n).collect::<Vec<_>>().chunks(256) {
        for &i in batch {
            raw.send(tcp_seg(me, 10_000 + i, dst, to.port(), 1000, 0, SYN, &[]));
        }
        let mut left = batch.len();
        while left > 0 {
            let Some(p) = recv_within(cx, raw, Duration::from_secs(5)).await else { break };
            let (_, _, proto, t) = parse(&p);
            if proto != 6 {
                continue;
            }
            let sport = u16::from_be_bytes([t[2], t[3]]);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            if t[13] & (SYN | ACK) == SYN | ACK {
                raw.send(tcp_seg(me, sport, dst, to.port(), 1001, seq.wrapping_add(1), ACK, &[]));
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

/// Times one HTTPS request from a fresh connection.
async fn timed_get(cx: &Cx, m: &Machine, env: &Env) -> Duration {
    let started = std::time::Instant::now();
    let conn = tls_connect(cx, m, env, SECURE_ADDR, "secure.test", &[b"http/1.1"]).await.unwrap();
    let mut client = Client::new(cx, conn, false).await;
    assert_eq!(client.get("https", "secure.test", "/").await.status, StatusCode::OK);
    started.elapsed()
}

/// Ports (ours) of the connections the other side closed (FIN or RST)
/// within `d`, counting each port once.
async fn closed_ports(cx: &Cx, raw: &mut End, d: Duration) -> std::collections::BTreeSet<u16> {
    let mut closed = std::collections::BTreeSet::new();
    let until = std::time::Instant::now() + d;
    while let Some(left) = until.checked_duration_since(std::time::Instant::now()) {
        let Some(p) = recv_within(cx, raw, left).await else { break };
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
    world(|cx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&cx, &b, "secure.test").await, SECURE_ADDR);
        let (open, mut closed) = open_idle(&cx, &mut raw, me, SocketAddr::new(SECURE_ADDR.into(), 443), 1000).await;
        assert_eq!(open, 1000);
        closed.extend(closed_ports(&cx, &mut raw, Duration::from_secs(1)).await);
        assert_eq!(closed.len(), 1000 - 256, "all past the first 256 are closed");
        // The other sandbox is served as before.
        let took = timed_get(&cx, &b, &env).await;
        assert!(took < Duration::from_secs(1), "{took:?}");
        Ok(())
    });
}

/// One HTTP/1.0 request on a fresh connection. Reads to the end, and
/// gives back the connection without closing this side, so it stays in
/// CLOSE_WAIT. `None` if the machine reset it.
async fn get_and_hold(cx: &Cx, m: &Machine, to: Ipv4Addr) -> Option<(String, tcp::TcpConnection)> {
    let mut conn = m.tcp.connect(cx, SocketAddr::new(to.into(), 80)).await.ok()?;
    conn.write_all(cx, b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n").await.ok()?;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match conn.read(cx, &mut buf).await {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some((String::from_utf8_lossy(&got).into_owned(), conn))
}

/// A connection the server closed but the sandbox never closed on its side
/// still counts against the sandbox's 256, so the sandbox cannot pile up
/// closing sockets on a machine the others share. Once it closes them,
/// it may connect again.
#[test]
fn connections_left_half_open_still_count() {
    world(|cx, attacher, _env| async move {
        let a = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let to = lookup(&cx, &a, "plain.test").await;
        let mut held = Vec::new();
        for i in 0..256 {
            let (text, conn) = get_and_hold(&cx, &a, to).await.unwrap_or_else(|| panic!("connection {i} was reset"));
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
            held.push(conn);
        }
        // The server closed all 256; the sandbox did not.
        for _ in 0..20 {
            assert!(get_and_hold(&cx, &a, to).await.is_none(), "a connection past the 256 was served");
        }
        // Another sandbox is served as before.
        let b = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&cx, &b, "plain.test").await, to);
        let (text, _conn) = get_and_hold(&cx, &b, to).await.expect("the other sandbox is served");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        // Closing them frees the count.
        drop(held);
        cx.sleep(Duration::from_millis(200)).await?;
        for _ in 0..20 {
            let (text, _conn) = get_and_hold(&cx, &a, to).await.expect("served again after closing");
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        }
        Ok(())
    });
}

/// A connection that never finishes its TLS handshake, never sends a
/// request on port 80, or sits idle on DNS over TCP, is closed after ten
/// seconds.
#[test]
fn connections_that_send_nothing_are_closed() {
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let plain = Ipv4Addr::new(198, 18, 0, 1);
        // Look the names up, over raw DNS, so their machines exist.
        for name in ["secure.test", "plain.test"] {
            let mut q = Message::query();
            q.metadata.id = 7;
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
            assert!(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.is_some());
        }
        for (n, to) in [SocketAddr::new(SECURE_ADDR.into(), 443), SocketAddr::new(plain.into(), 80), SocketAddr::new(GATEWAY.into(), 53)].into_iter().enumerate() {
            let n = n as u16;
            // Ports 10000, 11000 and 12000.
            raw.send(tcp_seg(me, 10_000 + n * 1000, match to.ip() { IpAddr::V4(a) => a, _ => unreachable!() }, to.port(), 1000, 0, SYN, &[]));
            let p = recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("a SYN-ACK");
            let (_, _, _, t) = parse(&p);
            assert_eq!(t[13] & (SYN | ACK), SYN | ACK);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            let IpAddr::V4(dst) = to.ip() else { unreachable!() };
            raw.send(tcp_seg(me, 10_000 + n * 1000, dst, to.port(), 1001, seq.wrapping_add(1), ACK, &[]));
        }
        let started = std::time::Instant::now();
        assert!(closed_ports(&cx, &mut raw, Duration::from_secs(8)).await.is_empty(), "closed too early");
        let closed = closed_ports(&cx, &mut raw, Duration::from_secs(4)).await;
        assert_eq!(closed.into_iter().collect::<Vec<_>>(), vec![10_000, 11_000, 12_000], "after {:?}", started.elapsed());
        Ok(())
    });
}

/// One sandbox that sends SYNs and never finishes the handshakes must not
/// lock the others out of a site they share.
#[test]
fn a_syn_flood_from_one_sandbox_does_not_lock_out_the_others() {
    world(|cx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&cx, &b, "secure.test").await, SECURE_ADDR);
        for i in 0..2000u16 {
            raw.send(tcp_seg(me, 10_000 + i, SECURE_ADDR, 443, 1000, 0, SYN, &[]));
        }
        let mut synacks = 0;
        while let Some(p) = recv_within(&cx, &mut raw, Duration::from_millis(500)).await {
            let (_, _, _, t) = parse(&p);
            if t[13] & (SYN | ACK) == SYN | ACK {
                synacks += 1;
            }
        }
        // Some got through, but not all: one address has a share of the
        // backlog, not all of it.
        assert!(synacks > 0 && synacks < 2000, "{synacks} SYN-ACKs");
        let r = timeout(&cx, Duration::from_secs(5), timed_get(&cx, &b, &env)).await;
        assert!(r.is_some(), "the other sandbox could not reach the site");
        Ok(())
    });
}

/// The median of five HTTPS requests from fresh connections.
async fn median_get(cx: &Cx, m: &Machine, env: &Env) -> Duration {
    let mut times = Vec::new();
    for _ in 0..5 {
        times.push(timed_get(cx, m, env).await);
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
    world(|cx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(lookup(&cx, &b, "secure.test").await, SECURE_ADDR);
        let before = median_get(&cx, &b, &env).await;
        let n = 10_000u32;
        let started = std::time::Instant::now();
        for i in 0..n {
            let mut q = Message::query();
            q.metadata.id = i as u16;
            q.add_query(Query::query(Name::from_ascii(format!("n{i}.wild.test")).unwrap(), RecordType::A));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        }
        let mut answers = 0;
        while answers < n && recv_within(&cx, &mut raw, Duration::from_secs(10)).await.is_some() {
            answers += 1;
        }
        let took = started.elapsed();
        assert_eq!(answers, n);
        assert!(took < Duration::from_secs(4), "{n} lookups took {took:?}");
        // The last site answers.
        let last = Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + n);
        raw.send(ping(me, last, 1));
        let (src, _, _, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((src, icmp[0]), (last, 0));
        let after = median_get(&cx, &b, &env).await;
        assert!(after < before * 3, "a request took {before:?} before and {after:?} after");
        Ok(())
    });
}

/// A name the callback would accept, but that was never looked up, is
/// not served anywhere: not by Host, not by `:authority`, not by SNI. And
/// asking does not run the callback.
#[test]
fn a_name_never_looked_up_is_not_served_by_host_or_sni() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        let wild = lookup(&cx, &m, "one.wild.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&cx, &m, &env, addr, "secure.test", alpn).await.unwrap();
            let mut client = Client::new(&cx, conn, h2).await;
            assert_eq!(client.get("https", "two.wild.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
        }
        let conn = m.tcp.connect(&cx, SocketAddr::new(wild.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "one.wild.test", "/").await.body, "wild http one.wild.test 80 HTTP/1.1 /");
        assert_eq!(client.get("http", "two.wild.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
        match tls_connect(&cx, &m, &env, addr, "two.wild.test", &[b"h2"]).await {
            Err(TlsError::Tls(rustls::Error::AlertReceived(rustls::AlertDescription::UnrecognisedName))) => {}
            Err(e) => panic!("expected unrecognized_name, got {e:?}"),
            Ok(_) => panic!("the handshake should fail"),
        }
        assert_eq!(env.calls.load(Ordering::SeqCst), calls, "the callback ran for a name seen only in HTTP or TLS");
        Ok(())
    });
}

/// A thousand requests at once on one HTTP/2 connection, more than the
/// 200 streams the server allows at a time, and streams the client
/// cancels as soon as it opens them.
#[test]
fn http2_with_a_thousand_streams_and_cancelled_ones() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[b"h2"]).await.unwrap();
        let client = Client::new(&cx, conn, true).await;
        let Client::H2(send) = &client else { unreachable!() };
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for i in 0..1000 {
            let mut c = Client::H2(send.clone());
            tasks.push(cx.spawn(move |cx| async move {
                if i % 10 == 0 {
                    // Opened and dropped at once: the client resets it.
                    let Client::H2(s) = &mut c else { unreachable!() };
                    s.ready().await.unwrap();
                    let r = Request::get("https://secure.test/x").body(Empty::new()).unwrap();
                    let fut = s.send_request(r);
                    let _ = timeout(&cx, Duration::from_micros(1), fut).await;
                } else {
                    let got = c.get("https", "secure.test", "/x").await;
                    assert_eq!(got.status, StatusCode::OK);
                }
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&cx).await?;
        }
        eprintln!("1,000 streams in {:?}", started.elapsed());
        assert!(env.served.load(Ordering::SeqCst) >= 900);
        // The connection still works.
        let mut c = Client::H2(send.clone());
        assert_eq!(c.get("https", "secure.test", "/").await.status, StatusCode::OK);
        Ok(())
    });
}

/// DNS messages an agent might send to break the server: garbage, cut-off
/// headers, a pointer loop, counts that lie, a response, a huge query in
/// fragments, the same over TCP with lengths that lie. The server stays up
/// and answers a good query after each.
#[test]
fn malformed_dns_does_not_break_the_server() {
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let good = {
            let mut q = Message::query();
            q.metadata.id = 4242;
            q.add_query(Query::query(Name::from_ascii("secure.test").unwrap(), RecordType::A));
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
            let len = (cx.random_u64() % 600) as usize;
            bad.push((0..len).map(|_| cx.random_u64() as u8).collect());
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
            raw.send(fragment(me, GATEWAY, 17, 777, at, at + n < payload.len(), &payload[at..at + n]));
            at += n;
        }
        // Then the good query: its answer must come.
        raw.send(udp(me, 5355, GATEWAY, 53, &good));
        let mut answered = false;
        while let Some(p) = recv_within(&cx, &mut raw, Duration::from_secs(2)).await {
            let (_, _, proto, u) = parse(&p);
            if proto == 17 && u16::from_be_bytes([u[2], u[3]]) == 5355 {
                assert_eq!(parse_dns(&u[8..], 4242), (ResponseCode::NoError, vec![SECURE_ADDR]));
                answered = true;
                break;
            }
        }
        assert!(answered, "no answer to a good query after the bad ones");

        // Over TCP: a length that promises more than comes, then garbage,
        // on separate connections; then a good query on a new one.
        let b = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 3));
        let dns_tcp = SocketAddr::new(GATEWAY.into(), 53);
        let mut c1 = b.tcp.connect(&cx, dns_tcp).await.unwrap();
        c1.write_all(&cx, &[0xff, 0xff, 1, 2, 3]).await.unwrap();
        let mut c2 = b.tcp.connect(&cx, dns_tcp).await.unwrap();
        c2.write_all(&cx, &[0, 3, 1, 2, 3, 0, 0]).await.unwrap();
        let mut c3 = b.tcp.connect(&cx, dns_tcp).await.unwrap();
        let mut framed = (good.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&good);
        c3.write_all(&cx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&cx, &mut c3, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&cx, &mut c3, &mut reply).await;
        assert_eq!(parse_dns(&reply, 4242), (ResponseCode::NoError, vec![SECURE_ADDR]));
        Ok(())
    });
}

/// When a sandbox detaches, what the sites still had for it must not reach
/// the next sandbox that takes its address: the connections are ended.
#[test]
fn a_detached_sandboxs_traffic_does_not_reach_the_next_holder_of_its_address() {
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // a looks plain.test up and opens a connection by hand.
        let mut q = Message::query();
        q.metadata.id = 1;
        q.add_query(Query::query(Name::from_ascii("plain.test").unwrap(), RecordType::A));
        a.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (_, _, _, u) = parse(&recv_within(&cx, &mut a, Duration::from_secs(2)).await.unwrap());
        let plain = parse_dns(&u[8..], 1).1[0];
        a.send(tcp_seg(me, 40_000, plain, 80, 1000, 0, SYN, &[]));
        let (_, _, _, t) = parse(&recv_within(&cx, &mut a, Duration::from_secs(2)).await.unwrap());
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        // The request, then a detaches before taking the answer.
        let request = b"GET /secret HTTP/1.1\r\nHost: plain.test\r\n\r\n";
        a.send(tcp_seg(me, 40_000, plain, 80, 1001, seq.wrapping_add(1), ACK, request));
        cx.sleep(Duration::from_millis(50)).await?;
        drop(a);

        // b takes the same address as soon as it is free.
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for i in 0..100 {
            b.send(ping(me, GATEWAY, i));
            if recv_within(&cx, &mut b, Duration::from_millis(20)).await.is_some() {
                bound = true;
                break;
            }
        }
        assert!(bound);
        // Nothing of a's answer reaches b, even after retransmissions.
        while let Some(p) = recv_within(&cx, &mut b, Duration::from_secs(3)).await {
            let (src, _, proto, t) = parse(&p);
            if proto == 6 {
                let data = &t[((t[12] >> 4) as usize) * 4..];
                assert!(data.is_empty(), "b got {} bytes of a's answer from {src}: {:?}", data.len(), String::from_utf8_lossy(data));
            }
        }
        Ok(())
    });
}

/// A TLS hello that never ends, or is garbage, closes that connection and
/// nothing else.
#[test]
fn a_huge_or_garbage_tls_hello_closes_only_that_connection() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let addr = lookup(&cx, &m, "secure.test").await;
        let to = SocketAddr::new(addr.into(), 443);
        // A handshake record header that promises 16 KiB, repeated: a hello
        // far larger than any real one.
        let mut huge = m.tcp.connect(&cx, to).await.unwrap();
        let mut record = vec![22, 3, 1, 0x40, 0];
        record.extend(std::iter::repeat_n(0u8, 0x4000));
        let mut closed = false;
        for _ in 0..32 {
            if huge.write_all(&cx, &record).await.is_err() {
                closed = true;
                break;
            }
        }
        let mut buf = [0u8; 64];
        let end = timeout(&cx, Duration::from_secs(2), huge.read(&cx, &mut buf)).await;
        assert!(closed || matches!(end, Some(Ok(0)) | Some(Err(_))), "the huge hello was not refused: {end:?}");
        // Plain garbage.
        let mut junk = m.tcp.connect(&cx, to).await.unwrap();
        junk.write_all(&cx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n").await.unwrap();
        let end = timeout(&cx, Duration::from_secs(2), junk.read(&cx, &mut buf)).await;
        assert!(matches!(end, Some(Ok(0)) | Some(Err(_))), "garbage was not refused: {end:?}");
        // A real client is still served.
        let conn = tls_connect(&cx, &m, &env, addr, "secure.test", &[b"h2"]).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        assert_eq!(client.get("https", "secure.test", "/").await.status, StatusCode::OK);
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
    let result = within(Duration::from_secs(60), move || {
        block_on(run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|host| host.ends_with(".test").then(|| web::Site::new(Plain("auto"))))
                .subnet(subnet)
                .serve(&cx, attachments)?;
            f(cx, attacher).await?;
            Err(Box::new(Done) as fictionet::Error)
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// A DNS A query from `me` to `gw` on a raw attachment: the answer's code
/// and addresses, or `None` if none came within 2 s.
async fn raw_dns(cx: &Cx, raw: &mut End, me: Ipv4Addr, gw: Ipv4Addr, name: &str, id: u16) -> Option<(ResponseCode, Vec<Ipv4Addr>)> {
    let mut q = Message::query();
    q.metadata.id = id;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    raw.send(udp(me, 5353, gw, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(cx, raw, Duration::from_secs(2)).await?;
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
    world_on_subnet("198.18.0.0/24", |cx, attacher| async move {
        let gw = Ipv4Addr::new(198, 18, 0, 1);
        let me = Ipv4Addr::new(198, 18, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (code, first) = raw_dns(&cx, &mut raw, me, gw, "one.test", 1).await.expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(first, vec![Ipv4Addr::new(198, 18, 1, 0)]);
        let (_, second) = raw_dns(&cx, &mut raw, me, gw, "two.test", 2).await.expect("DNS still answers");
        assert_eq!(second, vec![Ipv4Addr::new(198, 18, 1, 1)]);
        // The gateway still answers pings, and so does the site.
        for (to, seq) in [(gw, 1), (first[0], 2)] {
            raw.send(ping(me, to, seq));
            let p = recv_within(&cx, &mut raw, SHORT).await.expect("an echo reply");
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
    world(|cx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 9);
        let mut a = attacher.attach("a").unwrap();
        let mut m = dhcp_msg(dhcp::INFORM, 7, 1);
        m.ciaddr = me;
        let (to, reply) = dhcp_ask(&cx, &mut a, me, GATEWAY, &m).await.expect("an answer to INFORM");
        assert_eq!(to, me);
        assert_eq!(reply.message_type(), Some(dhcp::ACK));
        assert_eq!(reply.option_addr(dhcp::opt::DNS), Some(GATEWAY));

        // Not bound: another sandbox can still take 10.0.0.9.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(me, GATEWAY, 1));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_some(), "b binds 10.0.0.9");
        // Now a's INFORM from 10.0.0.9 is not answered, and neither is its ping.
        assert!(dhcp_ask(&cx, &mut a, me, GATEWAY, &m).await.is_none());
        a.send(ping(me, GATEWAY, 2));
        assert!(recv_within(&cx, &mut a, SHORT).await.is_none());
        Ok(())
    });
}

/// Reads `conn` to its end.
async fn read_all<C: Connection>(cx: &Cx, conn: &mut C) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match timeout(cx, Duration::from_secs(5), conn.read(cx, &mut buf)).await.expect("the response ends") {
            Ok(0) | Err(_) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
        }
    }
}

/// A body whose length the handler knows goes out with `content-length`;
/// one that streams goes out chunked on HTTP/1.1.
#[test]
fn a_known_length_is_sent_as_content_length() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&cx, &m, "plain.test").await;
        let events = lookup(&cx, &m, "events.test").await;
        let mut conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
        conn.write_all(&cx, b"GET /len HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n").await.unwrap();
        let got = String::from_utf8(read_all(&cx, &mut conn).await).unwrap().to_lowercase();
        let body = "plain http plain.test 80 HTTP/1.1 /len";
        assert!(got.contains(&format!("content-length: {}\r\n", body.len())), "{got:?}");
        assert!(!got.contains("transfer-encoding"), "{got:?}");
        // axum's 4 MiB Vec has a known length too, over TLS.
        let conn = tls_connect(&cx, &m, &env, events, "events.test", &[b"http/1.1"]).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
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
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let secure = lookup(&cx, &m, "secure.test").await;
        let events = lookup(&cx, &m, "events.test").await;
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&cx, &m, &env, secure, "secure.test", alpn).await.unwrap();
            let mut client = Client::new(&cx, conn, h2).await;
            let get = client.get("https", "secure.test", "/x").await;
            let head = client.send(http::Method::HEAD, "https", "secure.test", "/x").await;
            assert_eq!((head.status, head.body.as_str()), (StatusCode::OK, ""), "h2 {h2}");
            // The page ends with a request count, #1 then #2: same length.
            assert_eq!(head.headers["content-length"], get.body.len().to_string(), "h2 {h2}");
            // A whole 4 MiB body is left out too, and so is Sites' own 421.
            let conn = tls_connect(&cx, &m, &env, events, "events.test", alpn).await.unwrap();
            let mut client = Client::new(&cx, conn, h2).await;
            let big = client.send(http::Method::HEAD, "https", "events.test", "/big").await;
            assert_eq!((big.status, big.body.len()), (StatusCode::OK, 0), "h2 {h2}");
            assert_eq!(big.headers["content-length"], BIG.to_string(), "h2 {h2}");
            let other = client.send(http::Method::HEAD, "https", "secure.test", "/").await;
            assert_eq!((other.status, other.body.len()), (StatusCode::MISDIRECTED_REQUEST, 0), "h2 {h2}");
            // The connection still works after them.
            assert_eq!(client.get("https", "events.test", "/page").await.status, StatusCode::OK, "h2 {h2}");
        }
        Ok(())
    });
}

/// A request whose host names no site at the address goes to the
/// address's `default_host`, if it has one: an address typed as the host,
/// or any other name. A site that has its own name there keeps it.
#[test]
fn the_default_host_answers_hosts_with_no_site_of_their_own() {
    world(|cx, attacher, _env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&cx, &m, "default.test").await, DEFAULT_ADDR);
        assert_eq!(lookup(&cx, &m, "other.test").await, DEFAULT_ADDR);
        let ask = |host: &str| format!("GET /p HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        for (host, want) in [
            ("203.0.113.40", "default http 203.0.113.40 80 HTTP/1.1 /p"),
            ("unknown.test", "default http unknown.test 80 HTTP/1.1 /p"),
            ("default.test", "default http default.test 80 HTTP/1.1 /p"),
            ("other.test", "other http other.test 80 HTTP/1.1 /p"),
        ] {
            let got = String::from_utf8(raw_http(&cx, &m, DEFAULT_ADDR, ask(host).as_bytes()).await).unwrap();
            assert!(got.starts_with("HTTP/1.1 200 OK") && got.ends_with(want), "{host}: {got:?}");
        }
        // A TLS site that is the default redirects plain HTTP to https, at
        // the host the client named.
        assert_eq!(lookup(&cx, &m, "tls-default.test").await, TLS_DEFAULT_ADDR);
        let got = String::from_utf8(raw_http(&cx, &m, TLS_DEFAULT_ADDR, ask("203.0.113.41").as_bytes()).await).unwrap();
        assert!(got.starts_with("HTTP/1.1 301"), "{got:?}");
        assert!(got.to_lowercase().contains("location: https://203.0.113.41/p\r\n"), "{got:?}");
        // Without a default, the same request gets 421.
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        let got = String::from_utf8(raw_http(&cx, &m, SECURE_ADDR, ask("203.0.113.10").as_bytes()).await).unwrap();
        assert!(got.starts_with("HTTP/1.1 421"), "{got:?}");
        Ok(())
    });
}

/// A client that sends its request and then shuts down its side (as
/// `nc -N` and HTTP/1.0 scripts do) still gets the response, over plain
/// HTTP and over TLS.
#[test]
fn a_client_that_half_closes_after_its_request_gets_the_response() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&cx, &m, "plain.test").await;
        let secure = lookup(&cx, &m, "secure.test").await;
        let requests: [&[u8]; 2] = [
            b"GET /h HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
            b"GET /h HTTP/1.0\r\nHost: plain.test\r\n\r\n",
        ];
        for request in requests {
            let mut conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
            conn.write_all(&cx, request).await.unwrap();
            conn.shutdown(&cx).await.unwrap();
            let got = String::from_utf8(read_all(&cx, &mut conn).await).unwrap();
            assert!(got.starts_with("HTTP/1.") && got.contains(" 200 OK"), "{request:?} got {got:?}");
            assert!(got.contains("plain http plain.test 80"), "{got:?}");
        }
        let mut conn = tls_connect(&cx, &m, &env, secure, "secure.test", &[b"http/1.1"]).await.unwrap();
        conn.write_all(&cx, b"GET / HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n").await.unwrap();
        conn.shutdown(&cx).await.unwrap();
        let got = String::from_utf8(read_all(&cx, &mut conn).await).unwrap();
        assert!(got.starts_with("HTTP/1.1 200 OK"), "{got:?}");
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: events

/// The log of events a test world keeps.
type Log = Arc<std::sync::Mutex<Vec<Ev>>>;

// The journal's entries, read back into the shape the old `web::Event`
// had, so each test states what it checks the same way.

#[derive(Clone, Debug, PartialEq, Eq)]
struct Sandbox {
    id: u64,
    name: Arc<str>,
    addr: Option<Ipv4Addr>,
    addr_v6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsAnswer {
    Addr(IpAddr),
    NoData,
    NxDomain,
    Error(u16),
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Dns {
    sandbox: Sandbox,
    tcp: bool,
    name: Option<String>,
    qtype: Option<u16>,
    answer: DnsAnswer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TlsOutcome {
    Accepted { alpn: Option<Vec<u8>> },
    Rejected,
    Alert(u8),
    Failed(String),
    Closed,
    TimedOut,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Tls {
    sandbox: Sandbox,
    conn: u64,
    addr: IpAddr,
    sni: Option<String>,
    outcome: TlsOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpAnswer {
    Handler,
    Error,
    Redirect,
    Misdirected,
    NoHost,
    Cancelled,
}

#[derive(Clone, Debug)]
struct Http {
    sandbox: Sandbox,
    conn: u64,
    local: SocketAddr,
    scheme: http::uri::Scheme,
    sni: Option<String>,
    host: Option<String>,
    started: f64,
    method: http::Method,
    uri: http::Uri,
    version: Version,
    headers: HeaderMap,
    answer: HttpAnswer,
    status: Option<StatusCode>,
    sent: u64,
    complete: bool,
    /// The `page` field a handler added.
    page: Option<String>,
    /// How many fields the handler added.
    extra: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpErrorCause {
    Protocol,
    Timeout,
    Transport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpError {
    sandbox: Sandbox,
    conn: u64,
    local: SocketAddr,
    cause: HttpErrorCause,
    detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockedWhy {
    NotItsAddress,
    OtherSandbox,
    Broadcast,
    Ipv6,
    Malformed,
    NoRoute,
    ClosedPort,
    TooManyConnections,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Blocked {
    sandbox: Sandbox,
    why: BlockedWhy,
    protocol: Option<u8>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    dst_port: Option<u16>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum Ev {
    Attached { sandbox: Sandbox },
    Bound { sandbox: Sandbox, by_dhcp: bool },
    Detached { sandbox: Sandbox },
    Dns(Dns),
    Tls(Tls),
    Http(Http),
    HttpError(HttpError),
    Blocked(Blocked),
}

/// A journal that keeps every entry in `log`, as an [`Ev`].
fn keeping(log: Log) -> Journal {
    let journal = Journal::new();
    journal.subscribe(move |e| {
        if let Some(ev) = ev(e) {
            log.lock().unwrap_or_else(|p| p.into_inner()).push(ev);
        }
    });
    journal
}

fn ev(e: &Entry) -> Option<Ev> {
    let s = e.conn.sandbox.as_ref()?;
    let sandbox = Sandbox { id: s.id, name: s.name.clone(), addr: s.addr, addr_v6: s.addr_v6 };
    let text = |n: &str| e.str(n).map(str::to_owned);
    let num = |n: &str| e.u64(n);
    let conn = e.conn.id.unwrap_or(0);
    let local = e.conn.local.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    Some(match (e.event.service, e.event.kind) {
        ("net", "attached") => Ev::Attached { sandbox },
        ("net", "bound") => Ev::Bound { sandbox, by_dhcp: e.get("by_dhcp").and_then(|v| v.as_bool()) == Some(true) },
        ("net", "detached") => Ev::Detached { sandbox },
        ("dns", "query") => Ev::Dns(Dns {
            sandbox,
            tcp: e.get("tcp").and_then(|v| v.as_bool()) == Some(true),
            name: text("name"),
            qtype: num("qtype").map(|q| q as u16),
            answer: match e.str("answer")? {
                "addr" => DnsAnswer::Addr(e.str("addr")?.parse().ok()?),
                "nodata" => DnsAnswer::NoData,
                "nxdomain" => DnsAnswer::NxDomain,
                "error" => DnsAnswer::Error(num("rcode")? as u16),
                _ => DnsAnswer::None,
            },
        }),
        ("tls", "handshake") => Ev::Tls(Tls {
            sandbox,
            conn,
            addr: e.str("addr")?.parse().ok()?,
            sni: text("sni"),
            outcome: match e.str("outcome")? {
                "accepted" => TlsOutcome::Accepted { alpn: text("alpn").map(String::into_bytes) },
                "rejected" => TlsOutcome::Rejected,
                "alert" => TlsOutcome::Alert(num("alert")? as u8),
                "failed" => TlsOutcome::Failed(text("detail").unwrap_or_default()),
                "closed" => TlsOutcome::Closed,
                "timed_out" => TlsOutcome::TimedOut,
                _ => TlsOutcome::Aborted,
            },
        }),
        ("http", "request") => {
            let mut headers = HeaderMap::new();
            for pair in e.get("headers")?.as_array()? {
                let pair = pair.as_array()?;
                let name = http::HeaderName::from_bytes(pair[0].as_str()?.as_bytes()).ok()?;
                headers.append(name, pair[1].as_str()?.parse().ok()?);
            }
            let standard = [
                "scheme", "sni", "host", "method", "uri", "path", "query", "version", "headers", "started", "answer", "status",
                "sent", "complete",
            ];
            Ev::Http(Http {
                sandbox,
                conn,
                local,
                scheme: e.str("scheme")?.parse().ok()?,
                sni: text("sni"),
                host: text("host"),
                started: e.get("started")?.as_f64()?,
                method: e.str("method")?.parse().ok()?,
                uri: e.str("uri")?.parse().ok()?,
                version: match e.str("version")? {
                    "HTTP/2.0" => Version::HTTP_2,
                    "HTTP/1.0" => Version::HTTP_10,
                    _ => Version::HTTP_11,
                },
                headers,
                answer: match e.str("answer")? {
                    "handler" => HttpAnswer::Handler,
                    "error" => HttpAnswer::Error,
                    "redirect" => HttpAnswer::Redirect,
                    "misdirected" => HttpAnswer::Misdirected,
                    "no_host" => HttpAnswer::NoHost,
                    _ => HttpAnswer::Cancelled,
                },
                status: num("status").and_then(|s| StatusCode::from_u16(s as u16).ok()),
                sent: num("sent")?,
                complete: e.get("complete").and_then(|v| v.as_bool()) == Some(true),
                page: text("page"),
                extra: e.event.fields.iter().filter(|(n, _)| !standard.contains(n)).count(),
            })
        }
        ("http", "error") => Ev::HttpError(HttpError {
            sandbox,
            conn,
            local,
            cause: match e.str("cause")? {
                "protocol" => HttpErrorCause::Protocol,
                "timeout" => HttpErrorCause::Timeout,
                _ => HttpErrorCause::Transport,
            },
            detail: text("detail").unwrap_or_default(),
        }),
        ("net", "blocked") => Ev::Blocked(Blocked {
            sandbox,
            why: match e.str("why")? {
                "NotItsAddress" => BlockedWhy::NotItsAddress,
                "OtherSandbox" => BlockedWhy::OtherSandbox,
                "Broadcast" => BlockedWhy::Broadcast,
                "Ipv6" => BlockedWhy::Ipv6,
                "Malformed" => BlockedWhy::Malformed,
                "NoRoute" => BlockedWhy::NoRoute,
                "ClosedPort" => BlockedWhy::ClosedPort,
                _ => BlockedWhy::TooManyConnections,
            },
            protocol: num("protocol").map(|p| p as u8),
            src: text("src").and_then(|a| a.parse().ok()),
            dst: text("dst").and_then(|a| a.parse().ok()),
            dst_port: num("dst_port").map(|p| p as u16),
        }),
        _ => return None,
    })
}

/// [`world`], with an event callback that keeps every event in a [`Log`].
fn world_events<F, Fut>(f: F)
where
    F: FnOnce(Cx, Attacher, Env, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let log: Log = Arc::default();
    let result = within(Duration::from_secs(60), move || {
        block_on(run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let mut t = sites(&cx);
            let keep = log.clone();
            t.sites = t.sites.journal(keeping(keep));
            let env = t.serve_with(&cx, attachments)?;
            f(cx, attacher, env, log).await?;
            Err(Box::new(Done) as fictionet::Error)
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// The events so far that `pick` keeps.
fn picked<T>(log: &Log, pick: impl FnMut(&Ev) -> Option<T>) -> Vec<T> {
    log.lock().unwrap_or_else(|p| p.into_inner()).iter().filter_map(pick).collect()
}

/// Waits up to 5 s until `pick` keeps `n` events, and returns them.
async fn wait_for<T>(cx: &Cx, log: &Log, n: usize, mut pick: impl FnMut(&Ev) -> Option<T>) -> Vec<T> {
    for _ in 0..500 {
        let got = picked(log, &mut pick);
        if got.len() >= n {
            return got;
        }
        let _ = cx.sleep(Duration::from_millis(10)).await;
    }
    panic!("fewer than {n} such events: {:#?}", log.lock().unwrap());
}

fn is(s: &Sandbox, name: &str, addr: Option<Ipv4Addr>) -> bool {
    &*s.name == name && s.addr == addr
}

fn sandbox_of(e: &Ev) -> Option<&Sandbox> {
    Some(match e {
        Ev::Attached { sandbox, .. } | Ev::Bound { sandbox, .. } | Ev::Detached { sandbox, .. } => sandbox,
        Ev::Dns(d) => &d.sandbox,
        Ev::Tls(t) => &t.sandbox,
        Ev::Http(h) => &h.sandbox,
        Ev::HttpError(b) => &b.sandbox,
        Ev::Blocked(b) => &b.sandbox,
    })
}

fn dns_seen(e: &Ev) -> Option<Dns> {
    match e {
        Ev::Dns(d) => Some(d.clone()),
        _ => None,
    }
}

fn tls_seen(e: &Ev) -> Option<Tls> {
    match e {
        Ev::Tls(t) => Some(t.clone()),
        _ => None,
    }
}

fn http_seen(e: &Ev) -> Option<Http> {
    match e {
        Ev::Http(h) => Some(h.clone()),
        _ => None,
    }
}

fn error_seen(e: &Ev) -> Option<HttpError> {
    match e {
        Ev::HttpError(b) => Some(b.clone()),
        _ => None,
    }
}

fn blocked_seen(e: &Ev) -> Option<Blocked> {
    match e {
        Ev::Blocked(b) => Some(b.clone()),
        _ => None,
    }
}

#[test]
fn events_attach_bind_and_detach() {
    world_events(|cx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        a.send(ping(me, GATEWAY, 1));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());

        // A sandbox that gets its address from DHCP.
        let (any, bc) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST);
        let mut d = attacher.attach("d").unwrap();
        let (_, offer) = dhcp_ask(&cx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1)).await.expect("an offer");
        let got = offer.yiaddr;
        let mut request = dhcp_msg(dhcp::REQUEST, 1, 1);
        request.push(dhcp::opt::REQUESTED_IP, got.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&cx, &mut d, any, bc, &request).await.expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        // A renewal binds nothing new.
        let mut renew = dhcp_msg(dhcp::REQUEST, 2, 1);
        renew.ciaddr = got;
        let (_, ack) = dhcp_ask(&cx, &mut d, got, GATEWAY, &renew).await.expect("an ack");
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        drop(a);
        wait_for(&cx, &log, 1, |e| matches!(e, Ev::Detached { .. }).then_some(())).await;

        let of = |name: &str| picked(&log, |e| (&*sandbox_of(e)?.name == name).then(|| e.clone()));
        let a_events = of("a");
        assert_eq!(a_events.len(), 3, "{a_events:#?}");
        assert!(matches!(&a_events[0], Ev::Attached { sandbox, .. } if is(sandbox, "a", None) && sandbox.id == 1));
        assert!(matches!(&a_events[1], Ev::Bound { sandbox, by_dhcp: false, .. } if is(sandbox, "a", Some(me))));
        assert!(matches!(&a_events[2], Ev::Detached { sandbox, .. } if is(sandbox, "a", Some(me)) && sandbox.id == 1));

        let d_events = of("d");
        assert!(matches!(&d_events[0], Ev::Attached { sandbox, .. } if is(sandbox, "d", None) && sandbox.id == 2));
        let bound: Vec<_> = d_events.iter().filter(|e| matches!(e, Ev::Bound { .. })).collect();
        assert_eq!(bound.len(), 1, "{d_events:#?}");
        assert!(matches!(bound[0], Ev::Bound { sandbox, by_dhcp: true, .. } if is(sandbox, "d", Some(got))));
        Ok(())
    });
}

/// Opens a TCP connection by hand from a raw sandbox to `to`, and sends
/// `data` on it. Returns our port and the next sequence numbers (ours,
/// theirs).
async fn raw_connect(cx: &Cx, raw: &mut End, me: Ipv4Addr, to: SocketAddr, port: u16, data: &[u8]) -> (u32, u32) {
    let IpAddr::V4(dst) = to.ip() else { unreachable!() };
    raw.send(tcp_seg(me, port, dst, to.port(), 1000, 0, SYN, &[]));
    loop {
        let p = recv_within(cx, raw, Duration::from_secs(2)).await.expect("a SYN-ACK");
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
    world_events(|cx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&cx, &mut a, me, GATEWAY, "slow.test", 1).await.unwrap();
        let slow = addrs[0];
        let _ = raw_dns(&cx, &mut a, me, GATEWAY, "secure.test", 2).await.unwrap();
        // A request whose handler never answers, and a TLS handshake that
        // never starts, both still open when the sandbox detaches.
        raw_connect(&cx, &mut a, me, SocketAddr::new(slow.into(), 80), 30_000, b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n").await;
        raw_connect(&cx, &mut a, me, SocketAddr::new(SECURE_ADDR.into(), 443), 30_001, &[]).await;
        let _ = cx.sleep(Duration::from_millis(100)).await;
        drop(a);
        wait_for(&cx, &log, 1, |e| matches!(e, Ev::Detached { .. }).then_some(())).await;

        // The same name and address again: a new id.
        let mut a = attacher.attach("a").unwrap();
        let _ = raw_dns(&cx, &mut a, me, GATEWAY, "secure.test", 3).await.unwrap();

        let http = wait_for(&cx, &log, 1, http_seen).await;
        assert_eq!((http[0].answer, http[0].status, http[0].complete), (HttpAnswer::Cancelled, None, false));
        assert_eq!((http[0].sandbox.id, http[0].host.as_deref(), http[0].uri.path()), (1, Some("slow.test"), "/wait"));
        assert_eq!(http[0].local, SocketAddr::from((slow, 80)));
        let tls = wait_for(&cx, &log, 1, tls_seen).await;
        assert_eq!((tls[0].sandbox.id, tls[0].outcome.clone()), (1, TlsOutcome::Aborted));
        let dns = wait_for(&cx, &log, 3, dns_seen).await;
        let ids: Vec<u64> = dns.iter().map(|d| d.sandbox.id).collect();
        assert_eq!(ids, vec![1, 1, 2]);
        assert!(dns.iter().all(|d| is(&d.sandbox, "a", Some(me))));
        let attached = picked(&log, |e| match e {
            Ev::Attached { sandbox, .. } => Some(sandbox.id),
            _ => None,
        });
        assert_eq!(attached, vec![1, 2]);
        Ok(())
    });
}

#[test]
fn events_for_dns_queries() {
    world_events(|cx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&cx, &attacher, "a", me);
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&cx, &m, "Secure.Test.").await, SECURE_ADDR);
        assert_eq!(dns(&cx, &m, "secure.test", RecordType::AAAA).await, (ResponseCode::NoError, vec![]));
        assert_eq!(dns(&cx, &m, "nope.test", RecordType::A).await.0, ResponseCode::NXDomain);

        // Over TCP.
        let mut conn = m.tcp.connect(&cx, SocketAddr::new(GATEWAY.into(), 53)).await.unwrap();
        let mut q = Message::query();
        q.metadata.id = 7;
        q.add_query(Query::query(Name::from_ascii("nope.test").unwrap(), RecordType::A));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&cx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&cx, &mut conn, &mut len).await;

        let mut socket = m.udp.bind(4444).unwrap();
        let gw = SocketAddr::new(GATEWAY.into(), 53);
        // A message with a header but nothing readable after it: FORMERR.
        socket.send_to(&[0, 9, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff], gw);
        let (reply, _) = timeout(&cx, Duration::from_secs(2), socket.recv(&cx)).await.unwrap().unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Two questions in one message: FORMERR, and no name.
        let mut q = Message::query();
        q.metadata.id = 10;
        q.add_query(Query::query(Name::from_ascii("secure.test").unwrap(), RecordType::A));
        q.add_query(Query::query(Name::from_ascii("nope.test").unwrap(), RecordType::A));
        socket.send_to(&q.to_vec().unwrap(), gw);
        let (reply, _) = timeout(&cx, Duration::from_secs(2), socket.recv(&cx)).await.unwrap().unwrap();
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");
        // Too short to answer at all.
        socket.send_to(b"xx", gw);

        let got = wait_for(&cx, &log, 8, dns_seen).await;
        assert!(got.iter().all(|d| is(&d.sandbox, "a", Some(me))), "{got:#?}");
        let summary: Vec<_> = got.iter().map(|d| (d.tcp, d.name.as_deref(), d.qtype, d.answer.clone())).collect();
        assert_eq!(
            summary,
            vec![
                (false, Some("secure.test"), Some(1), DnsAnswer::Addr(SECURE_ADDR.into())),
                // Seen before: the callback does not run, the query is still an event.
                (false, Some("secure.test"), Some(1), DnsAnswer::Addr(SECURE_ADDR.into())),
                (false, Some("secure.test"), Some(28), DnsAnswer::Addr("2001:2::1".parse().unwrap())),
                (false, Some("nope.test"), Some(1), DnsAnswer::NxDomain),
                (true, Some("nope.test"), Some(1), DnsAnswer::NxDomain),
                (false, None, None, DnsAnswer::Error(1)),
                (false, None, None, DnsAnswer::Error(1)),
                (false, None, None, DnsAnswer::None),
            ]
        );
        assert_eq!(env.calls.load(Ordering::SeqCst), 2);
        Ok(())
    });
}

/// A rustls client config that trusts `roots`.
fn client_config(roots: &Arc<RootCertStore>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

#[test]
fn events_for_tls_handshakes() {
    world_events(|cx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&cx, &attacher, "a", me);
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&cx, &m, "shared.test").await, SECURE_ADDR);
        assert_eq!(lookup(&cx, &m, "events.test").await, EVENTS_ADDR);
        let to = |addr: Ipv4Addr| SocketAddr::new(addr.into(), 443);

        // 1. Accepted, with h2.
        let conn = tls_connect(&cx, &m, &env, SECURE_ADDR, "secure.test", &[b"h2", b"http/1.1"]).await.unwrap();
        drop(conn);
        // 2. No SNI (a client that connected to a bare address).
        assert!(tls_connect(&cx, &m, &env, SECURE_ADDR, "203.0.113.10", &[]).await.is_err());
        // 3. A name with no TLS site at this address.
        assert!(tls_connect(&cx, &m, &env, SECURE_ADDR, "shared.test", &[]).await.is_err());
        // 4. A client that does not trust the world's CA: it sends unknown_ca.
        let mut other_ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        other_ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        other_ca.distinguished_name.push(rcgen::DnType::CommonName, "Another CA");
        let other_ca = other_ca.self_signed(&KeyPair::generate().unwrap()).unwrap();
        let mut other = RootCertStore::empty();
        other.add(other_ca.der().clone()).unwrap();
        let other = Arc::new(other);
        let tcp = m.tcp.connect(&cx, to(SECURE_ADDR)).await.unwrap();
        let mut client = TlsClient::new(tcp, &other, "secure.test", &[]);
        assert!(client.handshake(&cx).await.is_err());
        // 5. A hello split over several segments.
        let mut tcp = m.tcp.connect(&cx, to(EVENTS_ADDR)).await.unwrap();
        let mut tls = ClientConnection::new(
            client_config(&env.roots, &[b"http/1.1"]),
            ServerName::try_from("events.test".to_owned()).unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut hello).unwrap();
        }
        assert!(hello.len() > 100);
        for chunk in hello.chunks(hello.len() / 3 + 1) {
            tcp.write_all(&cx, chunk).await.unwrap();
            let _ = cx.sleep(Duration::from_millis(30)).await;
        }
        let mut client = TlsClient::with(tcp, tls);
        client.handshake(&cx).await.unwrap();
        drop(client);
        // 6. Closed before a hello.
        let mut tcp = m.tcp.connect(&cx, to(SECURE_ADDR)).await.unwrap();
        tcp.shutdown(&cx).await.unwrap();
        // 7. Not TLS at all.
        let mut tcp = m.tcp.connect(&cx, to(SECURE_ADDR)).await.unwrap();
        tcp.write_all(&cx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n").await.unwrap();

        let got = wait_for(&cx, &log, 7, tls_seen).await;
        assert!(got.iter().all(|t| is(&t.sandbox, "a", Some(me))), "{got:#?}");
        let summary: Vec<_> = got.iter().map(|t| (t.addr, t.sni.as_deref(), t.outcome.clone())).collect();
        assert_eq!(summary[0], (IpAddr::V4(SECURE_ADDR), Some("secure.test"), TlsOutcome::Accepted { alpn: Some(b"h2".to_vec()) }));
        assert_eq!(summary[1], (IpAddr::V4(SECURE_ADDR), None, TlsOutcome::Rejected));
        assert_eq!(summary[2], (IpAddr::V4(SECURE_ADDR), Some("shared.test"), TlsOutcome::Rejected));
        assert_eq!(summary[3], (IpAddr::V4(SECURE_ADDR), Some("secure.test"), TlsOutcome::Alert(48)));
        assert_eq!(summary[4], (IpAddr::V4(EVENTS_ADDR), Some("events.test"), TlsOutcome::Accepted { alpn: Some(b"http/1.1".to_vec()) }));
        assert_eq!(summary[5], (IpAddr::V4(SECURE_ADDR), None, TlsOutcome::Closed));
        assert!(matches!(&summary[6], (_, None, TlsOutcome::Failed(_))), "{:?}", summary[6]);
        // Connections are numbered in order, from 1.
        let conns: Vec<u64> = got.iter().map(|t| t.conn).collect();
        assert_eq!(conns, (1..=7).collect::<Vec<u64>>());
        Ok(())
    });
}

/// Sends `request` on a new connection to `addr:80` and reads until the
/// server closes it.
async fn raw_http(cx: &Cx, m: &Machine, addr: Ipv4Addr, request: &[u8]) -> Vec<u8> {
    let mut conn = m.tcp.connect(cx, SocketAddr::new(addr.into(), 80)).await.unwrap();
    conn.write_all(cx, request).await.unwrap();
    read_all(cx, &mut conn).await
}

#[test]
fn events_for_http_requests() {
    world_events(|cx, attacher, env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let m = machine(&cx, &attacher, "a", me);
        assert_eq!(lookup(&cx, &m, "events.test").await, EVENTS_ADDR);
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        let broken = lookup(&cx, &m, "broken.test").await;

        // Three HTTP/2 requests on one connection, from a handler that puts
        // a Page in its response's extensions.
        let before = cx.now();
        let conn = tls_connect(&cx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"]).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        for path in ["/page", "/page?x=1", "/page"] {
            let got = client.get("https", "events.test", path).await;
            assert_eq!(got.status, StatusCode::OK);
            assert_eq!(got.body, "page sni=Some(\"events.test\")");
        }
        let tls = wait_for(&cx, &log, 1, tls_seen).await.remove(0);
        let pages = wait_for(&cx, &log, 3, http_seen).await;
        let mut last = before.since_start().as_secs_f64();
        for (h, path) in pages.iter().zip(["/page", "/page?x=1", "/page"]) {
            assert!(is(&h.sandbox, "a", Some(me)));
            assert_eq!(h.conn, tls.conn, "one connection");
            assert_eq!((h.answer, h.status, h.version), (HttpAnswer::Handler, Some(StatusCode::OK), Version::HTTP_2));
            assert_eq!((h.method.clone(), h.uri.path_and_query().unwrap().as_str()), (http::Method::GET, path));
            assert_eq!(h.page.as_deref(), Some("article"));
            assert_eq!(h.extra, 1);
            assert_eq!((h.sent, h.complete), ("page sni=Some(\"events.test\")".len() as u64, true));
            assert_eq!((h.scheme.as_str(), h.host.as_deref(), h.sni.as_deref()), ("https", Some("events.test"), Some("events.test")));
            assert_eq!(h.local, SocketAddr::from((EVENTS_ADDR, 443)));
            assert!(h.started >= last, "requests started in order");
            last = h.started;
        }
        // The connection's Tls event came first.
        let order = picked(&log, |e| match e {
            Ev::Tls(_) => Some("tls"),
            Ev::Http(_) => Some("http"),
            _ => None,
        });
        assert_eq!(order, vec!["tls", "http", "http", "http"]);
        log.lock().unwrap().clear();

        // Answers from Sites itself, on port 80.
        let tcp = m.tcp.connect(&cx, SocketAddr::new(SECURE_ADDR.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, tcp, false).await;
        assert_eq!(client.get("http", "secure.test", "/x?y=1").await.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(client.get("http", "unknown.test", "/").await.status, StatusCode::MISDIRECTED_REQUEST);
        let tcp = m.tcp.connect(&cx, SocketAddr::new(broken.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, tcp, false).await;
        assert_eq!(client.get("http", "broken.test", "/").await.status, StatusCode::INTERNAL_SERVER_ERROR);
        let reply = raw_http(&cx, &m, SECURE_ADDR, b"GET / HTTP/1.0\r\n\r\n").await;
        assert!(reply.starts_with(b"HTTP/1.0 400"), "{}", String::from_utf8_lossy(&reply));
        let got = wait_for(&cx, &log, 4, http_seen).await;
        let summary: Vec<_> = got
            .iter()
            .map(|h| (h.answer, h.status.map(|s| s.as_u16()), h.host.clone(), h.local.port(), h.sni.clone(), h.extra, h.complete))
            .collect();
        assert_eq!(
            summary,
            vec![
                (HttpAnswer::Redirect, Some(301), Some("secure.test".into()), 80, None, 0, true),
                (HttpAnswer::Misdirected, Some(421), Some("unknown.test".into()), 80, None, 0, true),
                (HttpAnswer::Error, Some(500), Some("broken.test".into()), 80, None, 0, true),
                (HttpAnswer::NoHost, Some(400), None, 80, None, 0, true),
            ]
        );
        assert_eq!(got[0].uri, "/x?y=1");
        assert_eq!(got[0].headers.get("host").unwrap(), "secure.test");
        assert_eq!(got[0].conn, got[1].conn);
        assert_ne!(got[1].conn, got[2].conn);
        log.lock().unwrap().clear();

        // HEAD: no body, complete once sent.
        let conn = tls_connect(&cx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"]).await.unwrap();
        let Client::H1(mut send) = Client::new(&cx, conn, false).await else { unreachable!() };
        send.ready().await.unwrap();
        let r = send.send_request(Request::head("/page").header("host", "events.test").body(Empty::new()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        drop(r);
        let got = wait_for(&cx, &log, 1, http_seen).await;
        assert_eq!((got[0].method.clone(), got[0].sent, got[0].complete), (http::Method::HEAD, 0, true));
        log.lock().unwrap().clear();

        // A whole download, then one the client cuts short.
        let conn = tls_connect(&cx, &m, &env, EVENTS_ADDR, "events.test", &[b"h2"]).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        assert_eq!(client.get("https", "events.test", "/big").await.body.len(), BIG);
        let Client::H2(send) = &mut client else { unreachable!() };
        send.ready().await.unwrap();
        let response = send.send_request(Request::get("https://events.test/big").body(Empty::new()).unwrap()).await.unwrap();
        let mut body = response.into_body();
        let first = body.frame().await.unwrap().unwrap();
        assert!(first.is_data());
        // Dropping the body resets the stream.
        drop(body);
        let got = wait_for(&cx, &log, 2, http_seen).await;
        assert_eq!((got[0].sent, got[0].complete), (BIG as u64, true));
        assert!(!got[1].complete, "{:?}", got[1]);
        assert!(got[1].sent < BIG as u64, "{}", got[1].sent);
        assert_eq!(got[1].status, Some(StatusCode::OK));
        eprintln!("cut short after {} of {BIG} bytes", got[1].sent);
        log.lock().unwrap().clear();

        // A request the client cancels while the handler waits: the stream
        // is reset, and the connection goes on.
        send.ready().await.unwrap();
        let waiting = send.send_request(Request::get("https://events.test/wait").body(Empty::new()).unwrap());
        assert!(timeout(&cx, Duration::from_millis(200), waiting).await.is_none(), "no answer to /wait");
        let got = wait_for(&cx, &log, 1, http_seen).await;
        assert_eq!((got[0].answer, got[0].status, got[0].sent, got[0].complete), (HttpAnswer::Cancelled, None, 0, false));
        assert_eq!(got[0].uri.path(), "/wait");
        assert_eq!(client.get("https", "events.test", "/page").await.status, StatusCode::OK);
        assert_eq!(wait_for(&cx, &log, 2, http_seen).await.len(), 2);
        Ok(())
    });
}

#[test]
fn events_for_a_client_that_resets_mid_request() {
    world_events(|cx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (_, addrs) = raw_dns(&cx, &mut raw, me, GATEWAY, "slow.test", 1).await.unwrap();
        let slow = addrs[0];
        let to = SocketAddr::new(slow.into(), 80);
        // HTTP/1.1, the handler never answers, the client resets.
        let (seq, ack) = raw_connect(&cx, &mut raw, me, to, 30_000, b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n").await;
        let _ = cx.sleep(Duration::from_millis(100)).await;
        assert!(picked(&log, http_seen).is_empty());
        raw.send(tcp_seg(me, 30_000, slow, 80, seq, ack, RST, &[]));
        let got = wait_for(&cx, &log, 1, http_seen).await;
        assert_eq!((got[0].answer, got[0].status, got[0].complete), (HttpAnswer::Cancelled, None, false));
        assert_eq!((got[0].version, got[0].host.as_deref()), (Version::HTTP_11, Some("slow.test")));
        // A reset is the client going away, not an HTTP error.
        let _ = cx.sleep(Duration::from_millis(100)).await;
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
        block_on(run(move |cx| async move {
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
            web::Sites::new(move |host| (host == "hang.test").then(|| web::Site::new(app.clone()))).serve(&cx, attachments)?;

            let me = Ipv4Addr::new(10, 0, 0, 2);
            let mut raw = attacher.attach("a").unwrap();
            let (_, addrs) = raw_dns(&cx, &mut raw, me, GATEWAY, "hang.test", 1).await.unwrap();
            let to = SocketAddr::new(addrs[0].into(), 80);
            let (seq, ack) = raw_connect(&cx, &mut raw, me, to, 30_000, b"GET /hang HTTP/1.1\r\nHost: hang.test\r\n\r\n").await;
            for _ in 0..100 {
                if started.load(Ordering::SeqCst) {
                    break;
                }
                let _ = cx.sleep(Duration::from_millis(10)).await;
            }
            assert!(started.load(Ordering::SeqCst), "the handler started");
            assert!(!flag.load(Ordering::SeqCst));
            raw.send(tcp_seg(me, 30_000, addrs[0], 80, seq, ack, RST, &[]));
            for _ in 0..100 {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                let _ = cx.sleep(Duration::from_millis(10)).await;
            }
            // Checked here: stopping the world would drop the handler too.
            assert!(flag.load(Ordering::SeqCst), "the handler was dropped within 1 s of the reset");
            Err(Box::new(Done) as fictionet::Error)
        }))
    });
    assert!(matches!(&result, Err(e) if e.downcast_ref::<Done>().is_some()), "{:?}", result.err().map(|e| e.to_string()));
    assert!(dropped.load(Ordering::SeqCst));
}

/// A world stops while HTTP/1.1 and HTTP/2 handlers wait on something
/// outside the world, with their connections still open.
#[test]
fn the_world_stops_while_handlers_wait() {
    let started = std::time::Instant::now();
    world_events(|cx, attacher, _env, log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let slow = lookup(&cx, &m, "slow.test").await;
        let to = SocketAddr::new(slow.into(), 80);
        let mut h1 = m.tcp.connect(&cx, to).await.unwrap();
        h1.write_all(&cx, b"GET /wait HTTP/1.1\r\nHost: slow.test\r\n\r\n").await.unwrap();
        // HTTP/2 with prior knowledge: the preface, empty SETTINGS, and one
        // GET /wait on stream 1 (HPACK: :method GET, :scheme http, then
        // :path and :authority as literals).
        let mut h2 = m.tcp.connect(&cx, to).await.unwrap();
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        let mut block = vec![0x82, 0x86, 0x04, 5];
        block.extend_from_slice(b"/wait");
        block.extend_from_slice(&[0x01, 9]);
        block.extend_from_slice(b"slow.test");
        bytes.extend_from_slice(&[0, 0, block.len() as u8, 1, 0x05, 0, 0, 0, 1]);
        bytes.extend_from_slice(&block);
        h2.write_all(&cx, &bytes).await.unwrap();
        let _ = cx.sleep(Duration::from_millis(300)).await;
        assert!(picked(&log, http_seen).is_empty(), "both handlers still wait");
        // Keep both connections open while the world stops.
        let _keep = (h1, h2);
        Err(Box::new(Done) as fictionet::Error)
    });
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

#[test]
fn events_for_bytes_that_are_not_http() {
    world_events(|cx, attacher, env, log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let plain = lookup(&cx, &m, "plain.test").await;
        assert_eq!(lookup(&cx, &m, "events.test").await, EVENTS_ADDR);

        // Garbage on port 80.
        raw_http(&cx, &m, plain, b"\x16\x03\x01\x00\x05hello\r\n\r\n").await;
        // HTTP/2 with prior knowledge, then a SETTINGS frame of a size no
        // SETTINGS frame can have.
        let mut bad = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bad.extend_from_slice(&[0, 0, 5, 4, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5]);
        raw_http(&cx, &m, plain, &bad).await;
        // Clean closes make no event: a whole request, and nothing at all.
        let ok = raw_http(&cx, &m, plain, b"GET / HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n").await;
        assert!(ok.starts_with(b"HTTP/1.1 200"));
        let mut conn = m.tcp.connect(&cx, SocketAddr::new(plain.into(), 80)).await.unwrap();
        conn.shutdown(&cx).await.unwrap();
        let _ = read_all(&cx, &mut conn).await;
        // After a TLS handshake, a record that does not decrypt.
        let mut client = tls_connect(&cx, &m, &env, EVENTS_ADDR, "events.test", &[b"http/1.1"]).await.unwrap();
        // First a request, so the server has finished its handshake.
        client.write_all(&cx, b"GET /page HTTP/1.1\r\nHost: events.test\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 16];
        read_exact(&cx, &mut client, &mut buf).await;
        let mut record = vec![23, 3, 3, 0, 40];
        record.extend_from_slice(&[0x55; 40]);
        client.conn.write_all(&cx, &record).await.unwrap();

        let got = wait_for(&cx, &log, 3, error_seen).await;
        let _ = cx.sleep(Duration::from_millis(200)).await;
        assert_eq!(picked(&log, error_seen).len(), 3, "{:#?}", picked(&log, error_seen));
        let summary: Vec<_> = got.iter().map(|b| (b.local, b.cause)).collect();
        assert_eq!(
            summary,
            vec![
                (SocketAddr::from((plain, 80)), HttpErrorCause::Protocol),
                (SocketAddr::from((plain, 80)), HttpErrorCause::Protocol),
                (SocketAddr::from((EVENTS_ADDR, 443)), HttpErrorCause::Transport),
            ]
        );
        assert!(got.iter().all(|b| is(&b.sandbox, "a", Some(Ipv4Addr::new(10, 0, 0, 2))) && !b.detail.is_empty()));
        assert_ne!(got[0].conn, got[1].conn);
        Ok(())
    });
}

/// Takes 10 seconds: a client that connects and sends nothing.
#[test]
fn events_for_clients_that_send_nothing() {
    world_events(|cx, attacher, _env, log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(lookup(&cx, &m, "secure.test").await, SECURE_ADDR);
        let started = std::time::Instant::now();
        let _quiet_80 = m.tcp.connect(&cx, SocketAddr::new(SECURE_ADDR.into(), 80)).await.unwrap();
        let _quiet_443 = m.tcp.connect(&cx, SocketAddr::new(SECURE_ADDR.into(), 443)).await.unwrap();
        let tls = wait_for_long(&cx, &log, tls_seen).await;
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(10) && took < Duration::from_millis(10_500), "{took:?}");
        assert_eq!((tls.sni.clone(), tls.outcome.clone()), (None, TlsOutcome::TimedOut));
        let bad = wait_for(&cx, &log, 1, error_seen).await;
        assert_eq!((bad[0].local.port(), bad[0].cause), (80, HttpErrorCause::Timeout));
        Ok(())
    });
}

/// Waits up to 12 s for the first event `pick` keeps.
async fn wait_for_long<T>(cx: &Cx, log: &Log, mut pick: impl FnMut(&Ev) -> Option<T>) -> T {
    for _ in 0..1200 {
        if let Some(t) = picked(log, &mut pick).into_iter().next() {
            return t;
        }
        let _ = cx.sleep(Duration::from_millis(10)).await;
    }
    panic!("no such event: {:#?}", log.lock().unwrap());
}

#[test]
fn events_for_blocked_packets() {
    world_events(|cx, attacher, _env, log| async move {
        use BlockedWhy::*;
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
        raw.send(udp(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67, b"not dhcp"));
        // Bind, then break the rules.
        raw.send(ping(me, GATEWAY, 2));
        assert!(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.is_some());
        raw.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        raw.send(ping(me, Ipv4Addr::new(10, 0, 0, 3), 4));
        raw.send(udp(me, 1000, Ipv4Addr::BROADCAST, 2000, b"hi"));
        // No machine there: host unreachable.
        raw.send(ping(me, Ipv4Addr::new(192, 0, 2, 1), 5));
        let (_, _, _, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        // Closed ports at a machine and at the gateway.
        let (_, addrs) = raw_dns(&cx, &mut raw, me, GATEWAY, "plain.test", 5).await.unwrap();
        let plain = addrs[0];
        for (dst, port) in [(plain, 22), (plain, 443), (GATEWAY, 80)] {
            raw.send(tcp_seg(me, 30_000, dst, port, 1, 0, SYN, &[]));
            let (_, _, proto, t) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
            assert_eq!((proto, t[13] & RST), (6, RST), "a RST from {dst}:{port}");
        }
        for (dst, port) in [(plain, 9999), (GATEWAY, 5000)] {
            raw.send(udp(me, 1000, dst, port, b"hi"));
            let (_, _, proto, icmp) = parse(&recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
            assert_eq!((proto, icmp[0], icmp[1]), (1, 3, 3), "port unreachable from {dst}:{port}");
        }
        // UDP with a bad checksum is dropped below Sites, unreported.
        let mut bad = udp(me, 1000, plain, 9999, b"hi");
        let n = bad.0.len();
        bad.0[n - 1] ^= 0xff;
        raw.send(bad);
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none());
        // Open ports make no event.
        raw.send(tcp_seg(me, 30_001, plain, 80, 1, 0, SYN, &[]));
        assert!(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.is_some());

        let got = wait_for(&cx, &log, 12, blocked_seen).await;
        let summary: Vec<_> =
            got.iter().map(|b| (b.why, b.sandbox.addr, b.protocol, b.src, b.dst, b.dst_port)).collect();
        let v4 = |a: Ipv4Addr| Some(IpAddr::V4(a));
        assert_eq!(
            summary,
            vec![
                (Malformed, None, None, None, None, None),
                (Broadcast, None, Some(17), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), Some(53)),
                (NotItsAddress, None, Some(1), v4(Ipv4Addr::new(192, 168, 1, 5)), v4(GATEWAY), None),
                (NotItsAddress, Some(me), Some(1), v4(Ipv4Addr::new(10, 0, 0, 9)), v4(GATEWAY), None),
                (OtherSandbox, Some(me), Some(1), v4(me), v4(Ipv4Addr::new(10, 0, 0, 3)), None),
                (Broadcast, Some(me), Some(17), v4(me), v4(Ipv4Addr::BROADCAST), Some(2000)),
                (NoRoute, Some(me), Some(1), v4(me), v4(Ipv4Addr::new(192, 0, 2, 1)), None),
                (ClosedPort, Some(me), Some(6), v4(me), v4(plain), Some(22)),
                (ClosedPort, Some(me), Some(6), v4(me), v4(plain), Some(443)),
                (ClosedPort, Some(me), Some(6), v4(me), v4(GATEWAY), Some(80)),
                (ClosedPort, Some(me), Some(17), v4(me), v4(plain), Some(9999)),
                (ClosedPort, Some(me), Some(17), v4(me), v4(GATEWAY), Some(5000)),
            ]
        );
        assert!(got.iter().all(|b| &*b.sandbox.name == "a" && b.sandbox.id == 1));
        log.lock().unwrap().clear();

        // Past the limit of connections to one machine.
        let (_, addrs) = raw_dns(&cx, &mut raw, me, GATEWAY, "secure.test", 6).await.unwrap();
        assert_eq!(addrs, vec![SECURE_ADDR]);
        let (open, _) = open_idle(&cx, &mut raw, me, SocketAddr::new(SECURE_ADDR.into(), 443), 300).await;
        assert_eq!(open, 300);
        let got = wait_for(&cx, &log, 44, blocked_seen).await;
        assert_eq!(got.len(), 44);
        assert!(got.iter().all(|b| b.why == TooManyConnections && b.dst == v4(SECURE_ADDR) && b.dst_port == Some(443)));
        assert!(got.iter().all(|b| is(&b.sandbox, "a", Some(me))));
        Ok(())
    });
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

/// The checksum of `data` over the IPv6 pseudo-header. Over data whose
/// checksum is filled in, a correct one gives 0.
fn sum6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, data: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(data.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next]);
    fold(sum16(&pseudo) + sum16(data))
}

/// An IPv6 packet carrying `data`, with its checksum at `at` filled in.
fn checksummed6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, mut data: Vec<u8>, at: usize) -> Packet {
    let c = sum6(src, dst, next, &data);
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
    assert_eq!(sum6(src, dst, b[6], &payload), 0, "the checksum");
    (src, dst, b[6], payload)
}

/// A DNS query for `name` from `me` to `server` on a raw attachment, over
/// IPv6: the answer's code and addresses, or `None` if none came within
/// 2 s.
async fn raw_dns6(cx: &Cx, raw: &mut End, me: Ipv6Addr, server: Ipv6Addr, name: &str, kind: RecordType) -> Option<(ResponseCode, Vec<IpAddr>)> {
    let id = cx.random_u64() as u16;
    let mut q = Message::query();
    q.metadata.id = id;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    raw.send(udp6(me, 5353, server, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(cx, raw, Duration::from_secs(2)).await?;
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
async fn dns_at(cx: &Cx, m: &Machine, server: IpAddr, name: &str, kind: RecordType) -> (ResponseCode, Vec<IpAddr>) {
    let mut socket = m.udp.bind(40000 + (cx.random_u64() % 20000) as u16).unwrap();
    let mut q = Message::query();
    q.metadata.id = cx.random_u64() as u16;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(server, 53));
    let (bytes, from) = timeout(cx, Duration::from_secs(5), socket.recv(cx)).await.expect("a DNS answer").unwrap();
    assert_eq!(from, SocketAddr::new(server, 53));
    parse_dns_all(&bytes, q.metadata.id)
}

#[test]
fn dns_answers_aaaa_for_each_family_a_site_has() {
    world(|cx, attacher, env| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        let ok = |addrs: &[IpAddr]| (ResponseCode::NoError, addrs.to_vec());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());

        // A site with only an IPv4 `at` gets an automatic IPv6 address,
        // from 2001:2::/48, and keeps it.
        assert_eq!(dns_at(&cx, &m, gw, "secure.test", RecordType::AAAA).await, ok(&[v6("2001:2::1")]));
        assert_eq!(dns_at(&cx, &m, gw, "secure.test", RecordType::A).await, ok(&[SECURE_ADDR.into()]));
        assert_eq!(dns_at(&cx, &m, gw, "SECURE.test.", RecordType::AAAA).await, ok(&[v6("2001:2::1")]));
        // A site at two addresses of its own.
        assert_eq!(dns_at(&cx, &m, gw, "dual.test", RecordType::A).await, ok(&[DUAL_ADDR.into()]));
        assert_eq!(dns_at(&cx, &m, gw, "dual.test", RecordType::AAAA).await, ok(&[DUAL_ADDR6.into()]));
        // Sites of one family: NODATA for the other.
        assert_eq!(dns_at(&cx, &m, gw, "v4only.test", RecordType::AAAA).await, ok(&[]));
        assert_eq!(dns_at(&cx, &m, gw, "v4only.test", RecordType::A).await, ok(&[Ipv4Addr::new(198, 18, 0, 1).into()]));
        assert_eq!(dns_at(&cx, &m, gw, "v6only.test", RecordType::A).await, ok(&[]));
        assert_eq!(dns_at(&cx, &m, gw, "v6only.test", RecordType::AAAA).await, ok(&[V6ONLY_ADDR6.into()]));
        // An address inside the sandboxes' IPv6 subnet, and a name with no
        // site: NXDOMAIN for both types.
        for name in ["inside6.test", "nope.test"] {
            for kind in [RecordType::A, RecordType::AAAA] {
                assert_eq!(dns_at(&cx, &m, gw, name, kind).await, (ResponseCode::NXDomain, vec![]), "{name} {kind}");
            }
        }
        // The callback ran once per name.
        assert_eq!(env.calls.load(Ordering::SeqCst), 6);

        // DNS also answers at the gateway's IPv6 address, over UDP and TCP.
        let m6 = machine(&cx, &attacher, "b", ME6);
        assert_eq!(dns_at(&cx, &m6, GATEWAY6.into(), "dual.test", RecordType::AAAA).await, ok(&[DUAL_ADDR6.into()]));
        assert_eq!(dns_at(&cx, &m6, GATEWAY6.into(), "dual.test", RecordType::A).await, ok(&[DUAL_ADDR.into()]));
        let mut conn = m6.tcp.connect(&cx, SocketAddr::new(GATEWAY6.into(), 53)).await.unwrap();
        let mut q = Message::query();
        q.metadata.id = 77;
        q.add_query(Query::query(Name::from_ascii("v6only.test").unwrap(), RecordType::AAAA));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&cx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&cx, &mut conn, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&cx, &mut conn, &mut reply).await;
        assert_eq!(parse_dns_all(&reply, 77), ok(&[V6ONLY_ADDR6.into()]));
        Ok(())
    });
}

#[test]
fn https_http2_and_plain_http_over_ipv6() {
    world_events(|cx, attacher, env, log| async move {
        let m = machine(&cx, &attacher, "a", ME6);
        let (_, addrs) = dns_at(&cx, &m, GATEWAY6.into(), "dual.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(DUAL_ADDR6)]);

        // HTTP/2 and HTTP/1.1 over TLS, to the site's IPv6 address.
        let conn = tls_connect(&cx, &m, &env, DUAL_ADDR6, "dual.test", &[b"h2", b"http/1.1"]).await.unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&cx, conn, true).await;
        let got = client.get("https", "dual.test", "/").await;
        assert_eq!((got.status, got.version), (StatusCode::OK, Version::HTTP_2));
        assert_eq!(got.body, "secure https dual.test 443 HTTP/2.0 #1");
        let conn = tls_connect(&cx, &m, &env, DUAL_ADDR6, "dual.test", &[b"http/1.1"]).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("https", "dual.test", "/").await.body, "secure https dual.test 443 HTTP/1.1 #2");

        // The site keeps its state across families: it is one site.
        let m4 = machine(&cx, &attacher, "b", Ipv4Addr::new(10, 0, 0, 2));
        let conn = tls_connect(&cx, &m4, &env, DUAL_ADDR, "dual.test", &[b"h2"]).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        assert_eq!(client.get("https", "dual.test", "/").await.body, "secure https dual.test 443 HTTP/2.0 #3");

        // An IPv6-only site.
        let (_, addrs) = dns_at(&cx, &m, GATEWAY6.into(), "v6only.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(V6ONLY_ADDR6)]);
        let conn = tls_connect(&cx, &m, &env, V6ONLY_ADDR6, "v6only.test", &[b"h2"]).await.unwrap();
        let mut client = Client::new(&cx, conn, true).await;
        assert_eq!(client.get("https", "v6only.test", "/").await.body, "secure https v6only.test 443 HTTP/2.0 #4");

        // Port 80: a TLS site redirects to https. A plain site at its
        // automatic IPv6 address answers. A request that names the bare
        // address in brackets gets 421, as it would over IPv4.
        let conn = m.tcp.connect(&cx, SocketAddr::new(DUAL_ADDR6.into(), 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        let got = client.get("http", "dual.test", "/a?b").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://dual.test/a?b");
        let (_, plain) = dns_at(&cx, &m, GATEWAY6.into(), "plain.test", RecordType::AAAA).await;
        let conn = m.tcp.connect(&cx, SocketAddr::new(plain[0], 80)).await.unwrap();
        let mut client = Client::new(&cx, conn, false).await;
        assert_eq!(client.get("http", "plain.test", "/q").await.body, "plain http plain.test 80 HTTP/1.1 /q");
        let got = client.get("http", &format!("[{}]", plain[0]), "/q").await;
        assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST);

        // A TLS handshake to the bare address carries no SNI, and is
        // rejected.
        let tcp = m.tcp.connect(&cx, SocketAddr::new(DUAL_ADDR6.into(), 443)).await.unwrap();
        let mut bare = TlsClient::new(tcp, &env.roots, &DUAL_ADDR6.to_string(), &[]);
        assert!(bare.handshake(&cx).await.is_err());

        // The events name the IPv6 addresses.
        let tls = wait_for(&cx, &log, 5, tls_seen).await;
        assert_eq!(tls[0].addr, IpAddr::V6(DUAL_ADDR6));
        assert_eq!(tls[0].sandbox.addr_v6, Some(ME6));
        assert_eq!(tls[0].sandbox.addr, None);
        assert_eq!((tls[4].addr, &tls[4].outcome), (IpAddr::V6(DUAL_ADDR6), &TlsOutcome::Rejected));
        let http = wait_for(&cx, &log, 7, http_seen).await;
        assert_eq!(http[0].local, SocketAddr::new(DUAL_ADDR6.into(), 443));
        assert_eq!(http[2].local, SocketAddr::new(DUAL_ADDR.into(), 443));
        assert_eq!(http[2].sandbox.addr, Some(Ipv4Addr::new(10, 0, 0, 2)));
        let dns = wait_for(&cx, &log, 3, dns_seen).await;
        assert_eq!(dns[0].answer, DnsAnswer::Addr(DUAL_ADDR6.into()));
        assert_eq!(dns[0].qtype, Some(28));
        Ok(())
    });
}

#[test]
fn ipv6_pings_closed_ports_and_unknown_addresses() {
    world(|cx, attacher, _env| async move {
        let mut raw = attacher.attach("a").unwrap();
        let reply = |p: Packet| parse6(&p);

        // The gateway answers pings.
        raw.send(ping6(ME6, GATEWAY6, 1));
        let (src, dst, next, icmp) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("an echo reply"));
        assert_eq!((src, dst, next, icmp[0]), (GATEWAY6, ME6, 58, 129));

        // An address that no site has: ICMPv6 address unreachable, at once,
        // from the gateway, quoting the packet.
        let sent = ping6(ME6, NOWHERE6, 2);
        raw.send(sent.clone());
        let (src, dst, next, icmp) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.expect("unreachable"));
        assert_eq!((src, dst, next), (GATEWAY6, ME6, 58));
        assert_eq!((icmp[0], icmp[1]), (1, 3));
        assert_eq!(&icmp[8..], &sent.0[..]);

        // Once its name is looked up, a site's IPv6 address answers pings.
        let (code, addrs) = raw_dns6(&cx, &mut raw, ME6, GATEWAY6, "plain.test", RecordType::AAAA).await.expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        let IpAddr::V6(plain) = addrs[0] else { panic!("{addrs:?}") };
        raw.send(ping6(ME6, plain, 3));
        let (src, _, _, icmp) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((src, icmp[0]), (plain, 129));

        // A closed TCP port gets a RST; UDP gets port unreachable.
        raw.send(syn6(ME6, 30_000, plain, 22));
        let (_, _, next, t) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((next, t[13] & RST), (6, RST));
        raw.send(udp6(ME6, 1000, plain, 9999, b"hi"));
        let (_, _, next, icmp) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((next, icmp[0], icmp[1]), (58, 1, 4));
        // Port 80 is open.
        raw.send(syn6(ME6, 30_001, plain, 80));
        let (_, _, next, t) = reply(recv_within(&cx, &mut raw, Duration::from_secs(2)).await.unwrap());
        assert_eq!((next, t[13] & (SYN | ACK)), (6, SYN | ACK));

        // No error for an ICMPv6 error, or for a router solicitation from a
        // link-local address to all routers.
        let mut err = vec![1, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..48]);
        raw.send(checksummed6(ME6, NOWHERE6, 58, err, 2));
        let rs = checksummed6("fe80::1".parse().unwrap(), "ff02::2".parse().unwrap(), 58, vec![133, 0, 0, 0, 0, 0, 0, 0], 2);
        raw.send(rs);
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn ipv6_addresses_are_bound_to_one_sandbox() {
    world_events(|cx, attacher, _env, log| async move {
        use BlockedWhy::*;
        let me4 = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // What a Linux sandbox sends first: a router solicitation from its
        // link-local address. It is dropped, and binds nothing.
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        a.send(checksummed6(link_local, "ff02::2".parse().unwrap(), 58, vec![133, 0, 0, 0, 0, 0, 0, 0], 2));
        // Then its global address: bound. Then its IPv4 address: bound too.
        a.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());
        a.send(ping(me4, GATEWAY, 2));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some());
        // Another source, another sandbox, an address with no site.
        a.send(ping6("2001:db8::9".parse().unwrap(), GATEWAY6, 3));
        a.send(ping6(ME6, "2001:db8::3".parse().unwrap(), 4));
        a.send(ping6(link_local, GATEWAY6, 5));
        a.send(ping6(ME6, NOWHERE6, 6));
        assert!(recv_within(&cx, &mut a, Duration::from_secs(2)).await.is_some(), "unreachable");

        // A second sandbox cannot take the first one's address, the
        // gateway's, the subnet's first address, or one outside the subnet.
        let mut b = attacher.attach("b").unwrap();
        for src in [ME6, GATEWAY6, "2001:db8::".parse().unwrap(), "2001:db8:1::5".parse().unwrap()] {
            b.send(ping6(src, GATEWAY6, 7));
        }
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none());

        let got = wait_for(&cx, &log, 9, blocked_seen).await;
        let summary: Vec<_> = got.iter().map(|b| (&*b.sandbox.name, b.why, b.sandbox.addr_v6, b.src, b.dst)).collect();
        let v6 = |a: Ipv6Addr| Some(IpAddr::V6(a));
        assert_eq!(
            summary,
            vec![
                ("a", Broadcast, None, v6(link_local), v6("ff02::2".parse().unwrap())),
                ("a", NotItsAddress, Some(ME6), v6("2001:db8::9".parse().unwrap()), v6(GATEWAY6)),
                ("a", OtherSandbox, Some(ME6), v6(ME6), v6("2001:db8::3".parse().unwrap())),
                ("a", NotItsAddress, Some(ME6), v6(link_local), v6(GATEWAY6)),
                ("a", NoRoute, Some(ME6), v6(ME6), v6(NOWHERE6)),
                ("b", NotItsAddress, None, v6(ME6), v6(GATEWAY6)),
                ("b", NotItsAddress, None, v6(GATEWAY6), v6(GATEWAY6)),
                ("b", NotItsAddress, None, v6("2001:db8::".parse().unwrap()), v6(GATEWAY6)),
                ("b", NotItsAddress, None, v6("2001:db8:1::5".parse().unwrap()), v6(GATEWAY6)),
            ]
        );
        assert_eq!(got.len(), 9, "{got:#?}");

        // One Bound for each family, and a Detached that names both.
        drop(a);
        wait_for(&cx, &log, 1, |e| matches!(e, Ev::Detached { .. }).then_some(())).await;
        let a_events = picked(&log, |e| (&*sandbox_of(e)?.name == "a" && !matches!(e, Ev::Blocked(_))).then(|| e.clone()));
        assert_eq!(a_events.len(), 4, "{a_events:#?}");
        let at = |e: &Ev| sandbox_of(e).map(|s| (s.addr, s.addr_v6));
        assert!(matches!(&a_events[1], Ev::Bound { by_dhcp: false, .. }));
        assert_eq!(at(&a_events[1]), Some((None, Some(ME6))));
        assert_eq!(at(&a_events[2]), Some((Some(me4), Some(ME6))));
        assert!(matches!(&a_events[3], Ev::Detached { .. }));
        assert_eq!(at(&a_events[3]), Some((Some(me4), Some(ME6))));

        // Now the address is free, and the second sandbox can take it.
        b.send(ping6(ME6, GATEWAY6, 8));
        let (src, dst, _, icmp) = parse6(&recv_within(&cx, &mut b, Duration::from_secs(2)).await.expect("an echo reply"));
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
    let log: Log = Arc::default();
    let result = within(Duration::from_secs(60), move || {
        block_on(run(move |cx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let keep = log.clone();
            make().journal(keeping(keep)).serve(&cx, attachments)?;
            f(cx, attacher, log).await?;
            Err(Box::new(Done) as fictionet::Error)
        }))
    });
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

#[test]
fn an_ipv4_only_network_drops_ipv6_and_answers_aaaa_with_nodata() {
    let make = || {
        web::Sites::new(|host| match host {
            "six.test" => Some(web::Site::new(Plain("six")).ipv6_only()),
            h => h.ends_with(".test").then(|| web::Site::new(Plain("auto")).at(DUAL_ADDR6)),
        })
        .ipv4_only()
    };
    world_of(make, |cx, attacher, log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        // An IPv6 `at` is not used: the site gets an automatic IPv4 address.
        assert_eq!(dns_at(&cx, &m, gw, "one.test", RecordType::A).await, (ResponseCode::NoError, vec![Ipv4Addr::new(198, 18, 0, 1).into()]));
        assert_eq!(dns_at(&cx, &m, gw, "one.test", RecordType::AAAA).await, (ResponseCode::NoError, vec![]));
        // An IPv6-only site has no address at all.
        assert_eq!(dns_at(&cx, &m, gw, "six.test", RecordType::AAAA).await, (ResponseCode::NXDomain, vec![]));

        let mut raw = attacher.attach("b").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none());
        let got = wait_for(&cx, &log, 1, blocked_seen).await;
        assert_eq!((got[0].why, got[0].dst), (BlockedWhy::Ipv6, Some(IpAddr::V6(GATEWAY6))));
        Ok(())
    });
}

#[test]
fn automatic_ipv6_addresses_skip_the_sandboxes_subnet() {
    // A subnet inside 2001:2::/48: automatic addresses jump past it.
    let make = || {
        web::Sites::new(|host| host.ends_with(".test").then(|| web::Site::new(Plain("auto"))))
            .subnet("2001:2::/64".parse().unwrap())
    };
    world_of(make, |cx, attacher, _log| async move {
        let (gw, me): (Ipv6Addr, Ipv6Addr) = ("2001:2::1".parse().unwrap(), "2001:2::2".parse().unwrap());
        let mut raw = attacher.attach("a").unwrap();
        let (_, first) = raw_dns6(&cx, &mut raw, me, gw, "one.test", RecordType::AAAA).await.expect("DNS answers");
        assert_eq!(first, vec![IpAddr::V6("2001:2:0:1::".parse().unwrap())]);
        let (_, second) = raw_dns6(&cx, &mut raw, me, gw, "two.test", RecordType::AAAA).await.expect("DNS answers");
        assert_eq!(second, vec![IpAddr::V6("2001:2:0:1::1".parse().unwrap())]);
        let IpAddr::V6(site) = first[0] else { unreachable!() };
        raw.send(ping6(me, site, 1));
        let (src, _, _, icmp) = parse6(&recv_within(&cx, &mut raw, SHORT).await.expect("an echo reply"));
        assert_eq!((src, icmp[0]), (site, 129));
        Ok(())
    });

    // A subnet that covers all of 2001:2::/48 leaves no automatic IPv6
    // addresses. Sites then have IPv4 only.
    let make = || {
        web::Sites::new(|host| host.ends_with(".test").then(|| web::Site::new(Plain("auto"))))
            .subnet("2001::/16".parse().unwrap())
    };
    world_of(make, |cx, attacher, _log| async move {
        let m = machine(&cx, &attacher, "a", Ipv4Addr::new(10, 0, 0, 2));
        let gw = IpAddr::V4(GATEWAY);
        assert_eq!(dns_at(&cx, &m, gw, "one.test", RecordType::AAAA).await, (ResponseCode::NoError, vec![]));
        assert_eq!(dns_at(&cx, &m, gw, "one.test", RecordType::A).await, (ResponseCode::NoError, vec![Ipv4Addr::new(198, 18, 0, 1).into()]));
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: IPv6 fragments, extension headers and checksums from the agent

/// An IPv6 fragment: `data` at byte `offset` of packet `id`, whose
/// fragment header names `next`.
fn fragment6(src: Ipv6Addr, dst: Ipv6Addr, id: u32, offset: u16, more: bool, next: u8, data: &[u8]) -> Packet {
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
    world(|cx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(fragment6(ME6, GATEWAY6, 12345, 0, true, 58, &whole.0[40..56]));
        assert!(recv_within(&cx, &mut a, Duration::from_millis(20)).await.is_none());
        drop(a);
        // b takes the address once a's filter has let it go.
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for seq in 0..100 {
            b.send(ping6(ME6, GATEWAY6, seq));
            if recv_within(&cx, &mut b, Duration::from_millis(20)).await.is_some() {
                bound = true;
                break;
            }
        }
        assert!(bound);
        b.send(fragment6(ME6, GATEWAY6, 12345, 16, false, 58, &whole.0[56..]));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none(), "a's fragment completed b's packet");
        // b's own fragments still make a packet.
        let mine = echo6_with(b"b's own packet!!");
        b.send(fragment6(ME6, GATEWAY6, 777, 0, true, 58, &mine.0[40..56]));
        b.send(fragment6(ME6, GATEWAY6, 777, 16, false, 58, &mine.0[56..]));
        let reply = recv_within(&cx, &mut b, SHORT).await.expect("an echo reply");
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
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let whole = echo6_with(b"abcdefghABCDEFGH");
        let first = &whole.0[40..56];
        let mut conflicting = first.to_vec();
        conflicting[8] ^= 0xff;
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, &conflicting));
        raw.send(fragment6(ME6, GATEWAY6, 9876, 16, false, 58, &whole.0[56..]));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a packet with conflicting fragments was delivered");
        // The same fragments again, without the conflict: still dropped.
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9876, 16, false, 58, &whole.0[56..]));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a dropped packet was started again");
        // An exact copy of a fragment is not a conflict.
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9877, 16, false, 58, &whole.0[56..]));
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("an echo reply");
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
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let headers: [(u8, [u8; 8]); 3] = [
            (60, [6, 0, 0, 0, 0, 0, 0, 0]),       // Destination Options: Pad1 only.
            (0, [6, 0, 1, 4, 0, 0, 0, 0]),        // Hop-by-Hop: PadN.
            (60, [6, 0, 0x1e, 4, 1, 2, 3, 4]),    // An unknown option to skip.
        ];
        for (i, (next, header)) in headers.into_iter().enumerate() {
            let syn = syn6(ME6, 40000 + i as u16, GATEWAY6, 53);
            raw.send(with_header(&syn, next, &header));
            let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a reply");
            let (_, dst, proto, body) = parse6(&reply);
            assert_eq!((dst, proto), (ME6, 6), "header {i}");
            assert_eq!(u16::from_be_bytes([body[2], body[3]]), 40000 + i as u16);
            assert_eq!(body[13], SYN | ACK, "header {i}: the flags");
        }
        // A site's machine: look one up, then send it a SYN behind
        // Destination Options.
        let (_, addrs) = raw_dns6(&cx, &mut raw, ME6, GATEWAY6, "plain.test", RecordType::AAAA).await.unwrap();
        let IpAddr::V6(site) = addrs[0] else { panic!("an AAAA record") };
        let syn = syn6(ME6, 41000, site, 80);
        let mut body = vec![6, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&syn.0[40..]);
        raw.send(ipv6(ME6, site, 60, &body));
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a reply from the site");
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
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let ping = ping6(ME6, GATEWAY6, 7);
        // An unknown option whose type says to discard: nothing comes back.
        raw.send(with_header(&ping, 60, &[58, 0, 0x40, 0, 0, 0, 0, 0]));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a discard option was delivered");
        // (next header, header, code, pointer)
        let refused: [(u8, Vec<u8>, u8, u32); 4] = [
            // An unknown routing type with a segment left: points at the type.
            (43, vec![58, 0, 250, 1, 0, 0, 0, 0], 0, 42),
            // An unknown option whose type says to answer: points at it.
            (60, vec![58, 0, 1, 0, 0x80, 0, 0, 0], 2, 44),
            (60, vec![58, 0, 0xc2, 4, 0, 0, 0, 0], 2, 42),
            // Hop-by-Hop after Destination Options: points at the byte that
            // names it.
            (60, vec![0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0], 1, 40),
        ];
        for (next, header, code, pointer) in refused {
            let sent = with_header(&ping, next, &header);
            raw.send(sent.clone());
            let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a parameter problem");
            let (src, dst, proto, body) = parse6(&reply);
            assert_eq!((src, dst, proto), (GATEWAY6, ME6, 58));
            assert_eq!((body[0], body[1]), (4, code), "{header:?}");
            assert_eq!(u32::from_be_bytes([body[4], body[5], body[6], body[7]]), pointer, "{header:?}");
            assert_eq!(&body[8..], &sent.0[..], "the packet is quoted");
            assert!(recv_within(&cx, &mut raw, Duration::from_millis(50)).await.is_none(), "{header:?} was delivered too");
        }
        // A routing header with no segments left asks nothing of the host.
        raw.send(with_header(&ping, 43, &[58, 0, 250, 0, 0, 0, 0, 0]));
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("an echo reply");
        assert_eq!(parse6(&reply).3[0], 129);
        Ok(())
    });
}

/// A UDP checksum field of zero means "no checksum" only over IPv4. Over
/// IPv6, DNS drops it, even when the sum over the datagram comes out right.
#[test]
fn dns_drops_a_zero_udp_checksum_over_ipv6() {
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let mut q = Message::query();
        q.metadata.id = 0;
        q.add_query(Query::query(Name::from_ascii("plain.test").unwrap(), RecordType::AAAA));
        let mut bytes = q.to_vec().unwrap();
        let mut u = vec![0x14, 0xe9, 0, 53];
        u.extend_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(&bytes);
        // Choose the DNS id so that the sum over the datagram, with the
        // checksum field zero, is right.
        let id = sum6(ME6, GATEWAY6, 17, &u);
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        u[8..].copy_from_slice(&bytes);
        assert_eq!(sum6(ME6, GATEWAY6, 17, &u), 0);
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a zero UDP checksum was accepted over IPv6");
        // The same datagram as a sender must send it: 0xffff for a sum of
        // zero. That is answered.
        u[6..8].copy_from_slice(&[0xff, 0xff]);
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a DNS answer");
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
    let make = || web::Sites::new(|_| Some(web::Site::new(Plain("wildcard")).ipv6_only())).max_sites(8);
    world_of(make, |cx, attacher, log| async move {
        let mut raw = attacher.attach("a").unwrap();
        for i in 0..8 {
            // A questions make the site too, and get NODATA.
            let answer = raw_dns6(&cx, &mut raw, ME6, GATEWAY6, &format!("n{i}.test"), RecordType::A).await.unwrap();
            assert_eq!(answer, (ResponseCode::NoError, vec![]));
        }
        for name in ["n8.test", "n9.test", "n8.test"] {
            let answer = raw_dns6(&cx, &mut raw, ME6, GATEWAY6, name, RecordType::AAAA).await.unwrap();
            assert_eq!(answer, (ResponseCode::ServFail, vec![]), "{name}");
        }
        assert_eq!(picked(&log, dns_seen).iter().filter(|d| d.answer == DnsAnswer::Error(2)).count(), 3);
        // The first eight still answer, and have machines.
        let site0 = Ipv6Addr::from(u128::from("2001:2::".parse::<Ipv6Addr>().unwrap()) + 1);
        let answer = raw_dns6(&cx, &mut raw, ME6, GATEWAY6, "n0.test", RecordType::AAAA).await.unwrap();
        assert_eq!(answer, (ResponseCode::NoError, vec![site0.into()]));
        let base = u128::from("2001:2::".parse::<Ipv6Addr>().unwrap());
        for i in 1..=9u16 {
            let addr = Ipv6Addr::from(base + u128::from(i));
            raw.send(ping6(ME6, addr, i));
            let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a reply");
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
    world(|cx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(nested6(1, &fragment6(ME6, GATEWAY6, 4242, 0, true, 58, &whole.0[40..56])));
        assert!(recv_within(&cx, &mut a, Duration::from_millis(20)).await.is_none());
        drop(a);
        let mut b = attacher.attach("b").unwrap();
        let mut bound = false;
        for seq in 0..100 {
            b.send(ping6(ME6, GATEWAY6, seq));
            if recv_within(&cx, &mut b, Duration::from_millis(20)).await.is_some() {
                bound = true;
                break;
            }
        }
        assert!(bound);
        b.send(nested6(2, &fragment6(ME6, GATEWAY6, 4242, 16, false, 58, &whole.0[56..])));
        assert!(recv_within(&cx, &mut b, SHORT).await.is_none(), "a nested fragment completed a's packet");
        Ok(())
    });
}

/// The headers in front of every fragment are checked, not only the first
/// fragment's, and a first fragment must hold the whole chain (RFC 7112).
#[test]
fn every_fragments_headers_are_checked() {
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        // The last fragment behind Hop-by-Hop with an option that says to
        // discard: the packet is never delivered.
        let whole = echo6_with(b"0123456789abcdef");
        raw.send(fragment6(ME6, GATEWAY6, 31, 0, true, 58, &whole.0[40..56]));
        let last = fragment6(ME6, GATEWAY6, 31, 16, false, 58, &whole.0[56..]);
        let mut body = vec![44, 0, 0x40, 0, 0, 0, 0, 0];
        body.extend_from_slice(&last.0[40..]);
        raw.send(ipv6(ME6, GATEWAY6, 0, &body));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a discard option on a later fragment was ignored");
        // A Destination Options header cut in two by the fragments: the
        // first fragment gets "parameter problem" code 3, pointer 0.
        let mut dest = vec![58, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        dest.extend_from_slice(&whole.0[40..]);
        let first = fragment6(ME6, GATEWAY6, 32, 0, true, 60, &dest[..8]);
        raw.send(first.clone());
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("a parameter problem");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 4, 3));
        assert_eq!(&body[4..8], &[0, 0, 0, 0]);
        raw.send(fragment6(ME6, GATEWAY6, 32, 8, false, 60, &dest[8..]));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a split chain was delivered");
        Ok(())
    });
}

/// A redirect gets no "parameter problem", whatever its headers say
/// (RFC 4443, section 2.4).
#[test]
fn a_redirect_gets_no_parameter_problem() {
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_some());
        let redirect = checksummed6(ME6, GATEWAY6, 58, [vec![137, 0, 0, 0], vec![0; 36]].concat(), 2);
        raw.send(with_header(&redirect, 60, &[58, 0, 0x80, 0, 0, 0, 0, 0]));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_none(), "a redirect got an error");
        Ok(())
    });
}

/// A packet to an address no machine has gets "address unreachable" from
/// the gateway, whatever its extension headers say: there is no host there
/// to answer "parameter problem".
#[test]
fn refused_headers_to_nowhere_get_address_unreachable() {
    world(|cx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&cx, &mut raw, SHORT).await.is_some());
        let ping = ping6(ME6, NOWHERE6, 2);
        let mut body = vec![58, 0, 250, 1, 0, 0, 0, 0];
        body.extend_from_slice(&ping.0[40..]);
        raw.send(ipv6(ME6, NOWHERE6, 43, &body));
        let reply = recv_within(&cx, &mut raw, SHORT).await.expect("an answer");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 1, 3));
        assert!(recv_within(&cx, &mut raw, Duration::from_millis(50)).await.is_none());
        Ok(())
    });
}
