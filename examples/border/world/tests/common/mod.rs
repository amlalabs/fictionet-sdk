//! A Border world in one process, and a sandbox built from stdlib parts
//! that plays the agent: DNS, TLS with rustls, HTTP, BGP, and
//! raw packets.

#![allow(dead_code)]

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use border_world::log::Log;
use border_world::scenario::{Scenario, Task, Variant, parse_prefix};
use fictionet::prelude::*;
use fictionet::stdlib::bgp;
use fictionet::stdlib::ca::Ca;
use fictionet::stdlib::codec::{Frames, Stream, Wire};
use fictionet::stdlib::{ConnError, ip, tcp};
use fictionet::{Attacher, Cx, End, Packet};
use rustls::RootCertStore;

#[path = "../../../../common/harness.rs"]
mod harness;
pub use harness::*;

/// What a test gets.
pub struct Env {
    /// The roots the agent trusts: the world's CA.
    pub roots: Arc<RootCertStore>,
    pub log: Buf,
    pub scenario: Arc<Scenario>,
}

/// Runs a Border world for `variant` and `task`, on a tokio runtime. `f`
/// plays the sandboxes. When it returns, the world ends.
pub fn run_variant<F, Fut>(variant: Variant, task: Task, f: F)
where
    F: FnOnce(Cx, Attacher, Env) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    harness::run(fictionet::Seed::random(), move |fcx| async move {
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
        .await
    });
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
