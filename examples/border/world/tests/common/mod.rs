//! A Border world in one process, and a sandbox built from stdlib parts
//! that plays the agent: DNS, TLS with rustls, HTTP with hyper, BGP, and
//! raw packets.

#![allow(dead_code)]

use std::future::{Future, poll_fn};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use border_world::log::Log;
use border_world::scenario::{Scenario, Task, Variant, parse_prefix};
use fictionet::prelude::*;
use fictionet::stdlib::bgp;
use fictionet::stdlib::ca::Ca;
use fictionet::stdlib::codec::{Frames, Stream, Wire};
use fictionet::stdlib::dns::op::ResponseCode;
use fictionet::stdlib::dns::rr::{RData, RecordType};
use fictionet::stdlib::sandbox::Machine;
use fictionet::stdlib::{ConnError, ip, tcp};
use fictionet::{Attacher, Cx, End, Packet};
use http::{HeaderMap, StatusCode};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;

pub const AGENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// The log, kept in memory.
#[derive(Clone, Default)]
pub struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    pub fn lines(&self) -> Vec<Value> {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The lines of `kind` so far.
    pub fn of(&self, kind: &str) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|l| l["type"] == kind)
            .collect()
    }

    /// Waits up to 5 s for `n` lines of `kind` that `keep` keeps.
    pub async fn wait(
        &self,
        fcx: &Cx,
        kind: &str,
        n: usize,
        keep: impl Fn(&Value) -> bool,
    ) -> Vec<Value> {
        for _ in 0..500 {
            let got: Vec<Value> = self.of(kind).into_iter().filter(|l| keep(l)).collect();
            if got.len() >= n {
                return got;
            }
            let _ = fcx.sleep(fictionet::time::Duration::from_millis(10)).await;
        }
        panic!("fewer than {n} {kind} lines: {:#?}", self.lines());
    }
}

/// What a test gets.
pub struct Env {
    /// The roots the agent trusts: the world's CA.
    pub roots: Arc<RootCertStore>,
    pub log: Buf,
    pub scenario: Arc<Scenario>,
}

#[derive(Debug)]
struct Done;
impl std::fmt::Display for Done {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("done")
    }
}
impl std::error::Error for Done {}

/// Runs a Border world for `variant` and `task`, on a tokio runtime. `f`
/// plays the sandboxes. When it returns, the world ends.
pub fn world<F, Fut>(variant: Variant, task: Task, f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
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
                let scenario = Arc::new(Scenario::new(
                    variant,
                    task,
                    parse_prefix("10.0.0.0/24").unwrap(),
                ));
                let (ids, root) = {
                    let ca = Ca::new(&fcx, "Test Root CA")?;
                    (
                        border_world::identities(&fcx, &scenario, &ca)?,
                        ca.cert_der(),
                    )
                };
                let mut roots = RootCertStore::empty();
                roots.add(root)?;
                let buf = Buf::default();
                let log = Log::start(Box::new(buf.clone()), scenario.clone());
                let (attacher, attachments) = fictionet::attachments();
                border_world::start(&fcx, scenario.clone(), ids, log, attachments)?;
                f(
                    fcx,
                    attacher,
                    Env {
                        roots: Arc::new(roots),
                        log: buf,
                        scenario,
                    },
                )
                .await?;
                Err(fictionet::Error::from(Done))
            },
        ));
        let _ = tx.send(result);
    });
    match rx
        .recv_timeout(Duration::from_secs(90))
        .expect("the test timed out")
    {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// Waits for `fut` at most `d`.
pub async fn timeout<T>(fcx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
    let mut fut = pin!(fut);
    let mut sleep = pin!(fcx.sleep(d));
    poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

pub fn machine(fcx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Machine {
    fictionet::stdlib::sandbox::machine(fcx, attacher.attach(name).unwrap(), addr)
}

/// Looks `name` up at the gateway. Returns the response code and the
/// addresses.
pub async fn lookup(fcx: &Cx, m: &Machine, name: &str) -> (ResponseCode, Vec<Ipv4Addr>) {
    let r = timeout(
        fcx,
        Duration::from_secs(5),
        m.lookup(fcx, GATEWAY.into(), name, RecordType::A),
    )
    .await
    .expect("a DNS answer")
    .unwrap();
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

/// Connects to the site's TLS port.
pub async fn tls(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
    sni: &str,
    config: Arc<ClientConfig>,
) -> fictionet::Result<
    fictionet::tokio::Compat<fictionet::stdlib::sandbox::TlsClient<tcp::TcpConnection>>,
> {
    Ok(
        m.tls_with_config(fcx, SocketAddr::new(addr.into(), 443), sni, config)
            .await?
            .into_tokio(fcx),
    )
}

/// The answer to one HTTP/1.1 request.
pub struct Got {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

/// Sends one HTTP/1.1 request over `io`.
#[allow(clippy::too_many_arguments)]
pub async fn request<C: fictionet::stdlib::Connection>(
    fcx: &Cx,
    io: fictionet::tokio::Compat<C>,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Got {
    use fictionet::stdlib::{codec::Wire, http1, sandbox};
    let mut bytes = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers {
        bytes.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        bytes.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    bytes.push_str("\r\n");
    bytes.push_str(body);
    let request = http1::Request::parse(bytes.as_bytes()).unwrap();
    let response = sandbox::request(fcx, &mut io.into_inner(), &request)
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    for header in response.head.headers {
        headers.append(
            http::HeaderName::from_bytes(header.name.as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(&header.value).unwrap(),
        );
    }
    Got {
        status: StatusCode::from_u16(response.head.status).unwrap(),
        headers,
        body: String::from_utf8_lossy(&response.body).into_owned(),
    }
}

/// Opens plain TCP to `addr:80`, for [`request`].
pub async fn plain(
    fcx: &Cx,
    m: &Machine,
    addr: Ipv4Addr,
) -> fictionet::tokio::Compat<tcp::TcpConnection> {
    m.tcp
        .connect(fcx, SocketAddr::new(addr.into(), 80))
        .await
        .unwrap()
        .into_tokio(fcx)
}

/// Writes a message with two-octet AS numbers.
pub fn bgp_bytes(message: bgp::Message) -> Vec<u8> {
    message
        .to_frame(&bgp::Context::default())
        .and_then(|frame| frame.to_bytes())
        .unwrap()
}

/// Reads one whole BGP message: its kind and body.
pub async fn bgp_read(
    fcx: &Cx,
    conn: &mut tcp::TcpConnection,
    stream: &mut Stream<Frames<bgp::Frame>>,
) -> Result<(u8, Vec<u8>), ConnError> {
    loop {
        if let Some(frame) = stream.next() {
            let frame = frame.expect("a good frame");
            bgp::Message::decode(&frame, &bgp::Context::default()).expect("a good message");
            return Ok((frame.kind, frame.body));
        }
        let n = conn.read(fcx, stream.spare()).await?;
        if n == 0 {
            return Err(ConnError::Closed);
        }
        stream.commit(n);
    }
}

// ---------------------------------------------------------------------------
// Raw packets

pub use fictionet::stdlib::ip::checksum;

/// An IPv4 packet with `ttl`.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, payload: &[u8]) -> Packet {
    let total = 20 + payload.len();
    let mut p = vec![
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        1,
        0,
        0,
        ttl,
        proto,
        0,
        0,
    ];
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let sum = checksum(&p);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(payload);
    Packet(p)
}

/// A UDP datagram, as traceroute sends them.
pub fn udp_probe(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, ttl: u8) -> Packet {
    let data = b"probe";
    let len = 8 + data.len();
    let mut u = Vec::new();
    u.extend_from_slice(&40000u16.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&(len as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let sum = ip::transport_checksum(src.into(), dst.into(), 17, &u);
    u[6..8].copy_from_slice(&sum.to_be_bytes());
    ipv4(src, dst, 17, ttl, &u)
}

/// A ping.
pub fn ping(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, seq: u16) -> Packet {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"border");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv4(src, dst, 1, ttl, &icmp)
}

/// The next packet on `end`, within `d`.
pub async fn recv_within(fcx: &Cx, end: &mut End, d: Duration) -> Option<Packet> {
    timeout(fcx, d, end.recv(fcx)).await.and_then(|r| r.ok())
}

/// Source, TTL, protocol and payload of an IPv4 packet; the header checksum
/// must be right.
pub fn parse(p: &Packet) -> (Ipv4Addr, u8, u8, Vec<u8>) {
    let b = &p.0;
    let ihl = usize::from(b[0] & 0x0f) * 4;
    assert_eq!(checksum(&b[..ihl]), 0, "a bad header checksum");
    (
        Ipv4Addr::new(b[12], b[13], b[14], b[15]),
        b[8],
        b[9],
        b[ihl..].to_vec(),
    )
}
