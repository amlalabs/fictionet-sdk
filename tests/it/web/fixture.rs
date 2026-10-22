use super::ipv6::{parse6, ping6};
use super::*;

// The default sandbox fixture.
pub(super) fn default_machine(fcx: &Cx, attacher: &Attacher) -> Machine {
    machine(
        fcx,
        attacher.attach("a").unwrap(),
        Ipv4Addr::new(10, 0, 0, 2),
    )
}

pub(super) async fn plain_client(
    fcx: &Cx,
    m: &Machine,
    addr: impl Into<IpAddr>,
    h2: bool,
) -> Client {
    let conn = m
        .tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap();
    Client::new(fcx, conn, h2).await
}

// ---------------------------------------------------------------------------
// Running a test world

/// Runs a world with the test sites. `f` gets the attacher and plays the
/// sandboxes. When it returns, the world ends with `Done`, which cancels
/// everything.
pub(super) fn world<F, Fut>(f: F)
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

// ---------------------------------------------------------------------------
// The sites

/// What the tests need to know about the sites.
#[derive(Clone)]
pub(super) struct Env {
    pub(super) roots: Arc<RootCertStore>,
    /// How often the callback ran.
    pub(super) calls: Arc<AtomicUsize>,
    /// Requests the secure site has served.
    pub(super) served: Arc<AtomicUsize>,
}

pub(super) struct TestSites {
    pub(super) sites: web::Sites,
    env: Env,
}

impl TestSites {
    pub(super) fn serve_with(
        self,
        fcx: &Cx,
        attachments: fictionet::Attachments,
    ) -> fictionet::Result<Env> {
        self.sites.start(fcx, attachments)?;
        Ok(self.env)
    }
}

pub(super) const SECURE_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
pub(super) const EVENTS_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
pub(super) const BOTH_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 30);
pub(super) const DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 40);
pub(super) const TLS_DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 41);
pub(super) const DUAL_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 50);
pub(super) const DUAL_ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x50, 0, 0, 0, 0, 0x10);
pub(super) const V6ONLY_ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x50, 0, 0, 0, 0, 0x20);

/// The size of `events.test/big`.
pub(super) const BIG: usize = 4 << 20;

fn events_site(waiting: Arc<AtomicUsize>) -> axum::Router {
    axum::Router::new()
        .route(
            "/page",
            axum::routing::get(|Extension(t): Extension<web::Target>| async move {
                format!("page sni={:?}", t.sni)
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
pub(super) fn sites(fcx: &Cx) -> TestSites {
    let certs = certs(
        fcx,
        &[
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
        ],
    );
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
            "secure.test" => Some(
                web::Site::new(secure.clone())
                    .at(SECURE_ADDR)
                    .tls(config.clone()),
            ),
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
                    .tls(config.clone()),
            ),
            "v4only.test" => Some(
                web::Site::new(secure.clone())
                    .ipv4_only()
                    .tls(config.clone()),
            ),
            "v6only.test" => Some(
                web::Site::new(secure.clone())
                    .ipv6_only()
                    .at(V6ONLY_ADDR6)
                    .tls(config.clone()),
            ),
            "broken.test" => Some(web::Site::new(Broken)),
            h if h.ends_with(".wild.test") => Some(web::Site::new(Plain("wild"))),
            "slow.test" => Some(web::Site::new(events_site(handler_waiting.clone()))),
            "events.test" => Some(
                web::Site::new(events_site(handler_waiting.clone()))
                    .at(EVENTS_ADDR)
                    .tls(config.clone()),
            ),
            "both.test" => Some(
                web::Site::new(secure.clone())
                    .at(BOTH_ADDR)
                    .tls(config.clone())
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
                    .tls(config.clone())
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
pub(super) struct Plain(pub(super) &'static str);

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

pub(super) const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Asks the gateway's DNS over UDP. Returns the response code and the A
/// records.
pub(super) async fn dns(
    fcx: &Cx,
    m: &Machine,
    name: &str,
    kind: RecordType,
) -> (ResponseCode, Vec<Ipv4Addr>) {
    let reply = timeout(
        fcx,
        Duration::from_secs(5),
        m.lookup(fcx, GATEWAY.into(), name, kind),
    )
    .await
    .expect("a DNS answer")
    .unwrap();
    parse_dns(&reply.to_vec().unwrap(), reply.metadata.id)
}

pub(super) fn parse_dns(bytes: &[u8], id: u16) -> (ResponseCode, Vec<Ipv4Addr>) {
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

pub(super) async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> Ipv4Addr {
    let (code, addrs) = dns(fcx, m, name, RecordType::A).await;
    assert_eq!(code, ResponseCode::NoError, "{name}");
    assert_eq!(addrs.len(), 1, "{name}");
    addrs[0]
}

// ---------------------------------------------------------------------------
// A hyper client over a Connection

/// One HTTP client connection, HTTP/1.1 or HTTP/2.
pub(super) enum Client {
    H1(hyper::client::conn::http1::SendRequest<Empty<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Empty<Bytes>>),
}

pub(super) struct Got {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: String,
    pub(super) version: Version,
}

impl Client {
    pub(super) async fn new<C: Connection + Unpin>(fcx: &Cx, conn: C, h2: bool) -> Client {
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
    pub(super) async fn get(&mut self, scheme: &str, host: &str, path: &str) -> Got {
        self.send(http::Method::GET, scheme, host, path).await
    }

    /// Sends a `method` request for `path` to `host`, as [`Client::get`] does.
    pub(super) async fn send(
        &mut self,
        method: http::Method,
        scheme: &str,
        host: &str,
        path: &str,
    ) -> Got {
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
pub(super) async fn tls_connect(
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
    let mut client = TlsClient::new(
        fcx,
        tcp,
        &env.roots,
        sni,
        alpn,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
    )
    .unwrap();
    client.handshake(fcx).await?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// Raw packets

pub(super) fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Packet {
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, proto, 0, 0];
    p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = ip::checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    Packet(p)
}

pub(super) fn ping(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Packet {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fictionet");
    let c = ip::checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 1, &icmp)
}

pub(super) fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
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
pub(super) fn parse(p: &Packet) -> (Ipv4Addr, Ipv4Addr, u8, Vec<u8>) {
    let b = &p.0;
    assert_eq!(b[0] >> 4, 4);
    assert_eq!(ip::checksum(&b[..20]), 0, "IPv4 header checksum");
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    (src, dst, b[9], b[20..].to_vec())
}

pub(super) async fn recv_within(fcx: &Cx, end: &mut End, d: Duration) -> Option<Packet> {
    timeout(fcx, d, end.recv(fcx)).await.map(|r| r.unwrap())
}

/// Wait for an echo reply to establish the binding, keeping other packets
/// for the caller to check.
pub(super) async fn bind_by_ping(
    fcx: &Cx,
    end: &mut End,
    me: IpAddr,
    gateway: IpAddr,
) -> Vec<Packet> {
    let mut other = Vec::new();
    for i in 0..100 {
        end.send(match (me, gateway) {
            (IpAddr::V4(me), IpAddr::V4(gateway)) => ping(me, gateway, i),
            (IpAddr::V6(me), IpAddr::V6(gateway)) => ping6(me, gateway, i),
            _ => panic!("the sandbox and gateway must use the same address family"),
        });
        if let Some(p) = recv_within(fcx, end, Duration::from_millis(20)).await {
            let (src, dst, proto, icmp) = match p.0[0] >> 4 {
                4 => {
                    let (src, dst, proto, body) = parse(&p);
                    (IpAddr::V4(src), IpAddr::V4(dst), proto, body)
                }
                6 => {
                    let (src, dst, proto, body) = parse6(&p);
                    (IpAddr::V6(src), IpAddr::V6(dst), proto, body)
                }
                _ => panic!("expected an IP packet while binding {me}: {p:?}"),
            };
            if src == gateway
                && dst == me
                && icmp.len() >= 8
                && matches!(
                    (me, proto, icmp[0]),
                    (IpAddr::V4(_), 1, 0) | (IpAddr::V6(_), 58, 129)
                )
                && icmp[1] == 0
                && icmp[4..6] == [0x12, 0x34]
                && u16::from_be_bytes([icmp[6], icmp[7]]) <= i
            {
                return other;
            }
            other.push(p);
        }
    }
    panic!("no matching echo reply from {gateway} to bind {me} after 100 pings: {other:?}");
}

pub(super) const SHORT: Duration = Duration::from_millis(300);

pub(super) async fn raw_http(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    request: &[u8],
) -> Result<Vec<u8>, ConnError> {
    let mut conn = m
        .tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap();
    conn.write_all(fcx, request).await.unwrap();
    let mut output = Vec::new();
    let mut bytes = [0; 4096];
    loop {
        let n = conn.read(fcx, &mut bytes).await?;
        if n == 0 {
            return Ok(output);
        }
        output.extend_from_slice(&bytes[..n]);
    }
}
