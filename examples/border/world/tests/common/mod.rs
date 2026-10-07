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

use border_world::bgp;
use border_world::certs::Ca;
use border_world::log::Log;
use border_world::scenario::{Prefix, Scenario, Task, Variant};
use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::{ConnError, ip, tcp, udp};
use fictionet::{Attacher, Cx, End, Packet};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
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
        text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    /// The lines of `kind` so far.
    pub fn of(&self, kind: &str) -> Vec<Value> {
        self.lines().into_iter().filter(|l| l["type"] == kind).collect()
    }

    /// Waits up to 5 s for `n` lines of `kind` that `keep` keeps.
    pub async fn wait(&self, cx: &Cx, kind: &str, n: usize, keep: impl Fn(&Value) -> bool) -> Vec<Value> {
        for _ in 0..500 {
            let got: Vec<Value> = self.of(kind).into_iter().filter(|l| keep(l)).collect();
            if got.len() >= n {
                return got;
            }
            let _ = cx.sleep(fictionet::time::Duration::from_millis(10)).await;
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
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let result = rt.block_on(fictionet::run(move |cx| async move {
            let scenario = Arc::new(Scenario::new(variant, task, Prefix::parse("10.0.0.0/24").unwrap()));
            let (ids, root) = {
                let ca = Ca::root("Test Root CA")?;
                (border_world::identities(&scenario, &ca)?, ca.der().clone())
            };
            let mut roots = RootCertStore::empty();
            roots.add(root)?;
            let buf = Buf::default();
            let log = Log::start(Box::new(buf.clone()), scenario.clone());
            let (attacher, attachments) = fictionet::attachments();
            let lookups = border_world::start(&cx, scenario.clone(), ids, log, attachments)?;
            border_world::look_up_all(&cx, &lookups, &scenario).await?;
            f(cx, attacher, Env { roots: Arc::new(roots), log: buf, scenario }).await?;
            Err(Box::new(Done) as fictionet::Error)
        }));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(Duration::from_secs(90)).expect("the test timed out") {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("the world failed: {e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}

/// Waits for `fut` at most `d`.
pub async fn timeout<T>(cx: &Cx, d: Duration, fut: impl Future<Output = T>) -> Option<T> {
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

/// A sandbox's machine: TCP and UDP at its address.
pub struct Machine {
    pub tcp: tcp::Endpoint,
    pub udp: udp::Endpoint,
    pub icmp: End,
}

pub fn machine(cx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Machine {
    let end = attacher.attach(name).unwrap();
    let (tcp, udp, icmp, _other) = ip::split_protocols(cx, end);
    Machine { tcp: tcp::endpoint(cx, tcp, addr.into()), udp: udp::endpoint(cx, udp, addr.into()), icmp }
}

/// Looks `name` up at the gateway. Returns the response code and the
/// addresses.
pub async fn lookup(cx: &Cx, m: &Machine, name: &str) -> (ResponseCode, Vec<Ipv4Addr>) {
    let mut socket = m.udp.bind(40000 + (cx.random_u64() % 20000) as u16).unwrap();
    let mut q = Message::query();
    q.metadata.id = cx.random_u64() as u16;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, _) = timeout(cx, Duration::from_secs(5), socket.recv(cx)).await.expect("a DNS answer").unwrap();
    let r = Message::from_vec(&bytes).unwrap();
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

/// Accepts any certificate: an agent that runs `curl -k`.
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// The client's TLS: verify against `roots`, or not at all.
pub fn client_config(roots: Option<&Arc<RootCertStore>>) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut config = match roots {
        Some(roots) => builder.with_root_certificates(roots.clone()).with_no_client_auth(),
        None => builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAll)).with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub type TlsStream = tokio_rustls::client::TlsStream<fictionet::tokio::Compat<tcp::TcpConnection>>;

/// Connects to `addr:443` and shakes hands for `sni`.
pub async fn tls(cx: &Cx, m: &Machine, addr: Ipv4Addr, sni: &str, config: Arc<ClientConfig>) -> std::io::Result<TlsStream> {
    let conn = m.tcp.connect(cx, SocketAddr::new(addr.into(), 443)).await.map_err(std::io::Error::other)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    connector.connect(ServerName::try_from(sni.to_owned()).unwrap(), conn.into_tokio(cx)).await
}

/// The answer to one HTTP/1.1 request.
pub struct Got {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

/// Sends one HTTP/1.1 request over `io`.
pub async fn request<IO>(io: IO, method: &str, host: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Got
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut r = Request::builder().method(method).uri(path).header("host", host);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    let response = send.send_request(r.body(Full::new(Bytes::from(body.to_owned()))).unwrap()).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Got { status, headers, body: String::from_utf8_lossy(&body).into_owned() }
}

/// Opens plain TCP to `addr:80`, for [`request`].
pub async fn plain(cx: &Cx, m: &Machine, addr: Ipv4Addr) -> fictionet::tokio::Compat<tcp::TcpConnection> {
    m.tcp.connect(cx, SocketAddr::new(addr.into(), 80)).await.unwrap().into_tokio(cx)
}

/// Reads one whole BGP message: its kind and body.
pub async fn bgp_read(cx: &Cx, conn: &mut tcp::TcpConnection, buf: &mut Vec<u8>) -> Result<(bgp::Kind, Vec<u8>), ConnError> {
    loop {
        if buf.len() >= bgp::HEADER {
            let (kind, len) = bgp::parse_header(buf).expect("a good header");
            if buf.len() >= bgp::HEADER + len {
                let body = buf[bgp::HEADER..bgp::HEADER + len].to_vec();
                buf.drain(..bgp::HEADER + len);
                return Ok((kind, body));
            }
        }
        let mut chunk = [0u8; 4096];
        let n = conn.read(cx, &mut chunk).await?;
        if n == 0 {
            return Err(ConnError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

// ---------------------------------------------------------------------------
// Raw packets

pub use fictionet::stdlib::ip::checksum;

/// An IPv4 packet with `ttl`.
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, ttl: u8, payload: &[u8]) -> Packet {
    let total = 20 + payload.len();
    let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0, 0, ttl, proto, 0, 0];
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
pub async fn recv_within(cx: &Cx, end: &mut End, d: Duration) -> Option<Packet> {
    timeout(cx, d, end.recv(cx)).await.and_then(|r| r.ok())
}

/// Source, TTL, protocol and payload of an IPv4 packet; the header checksum
/// must be right.
pub fn parse(p: &Packet) -> (Ipv4Addr, u8, u8, Vec<u8>) {
    let b = &p.0;
    let ihl = usize::from(b[0] & 0x0f) * 4;
    assert_eq!(checksum(&b[..ihl]), 0, "a bad header checksum");
    (Ipv4Addr::new(b[12], b[13], b[14], b[15]), b[8], b[9], b[ihl..].to_vec())
}
