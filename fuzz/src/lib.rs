//! Helpers that the fuzz targets share: packet builders, an in-memory
//! [`Connection`], a way to run a world for one input, and the proxy's
//! modules from the `fictionet` binary.

use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::pin::pin;
use std::task::{Context, Poll};

use fictionet::stdlib::ip::{self, transport_checksum};
use fictionet::stdlib::{ConnError, Connection};
use fictionet::{Cx, block_on, run};

/// The proxy's modules, compiled from the binary's own source files.
#[allow(dead_code, unused_imports)]
pub mod proxy;

pub mod doors;
pub mod web;

#[allow(dead_code)]
#[path = "../../src/bin/fictionet/world.rs"]
mod world;

/// Runs a world for one input. `f` gets the world's `Cx`. When `f`
/// returns, the world is cancelled, and every task in it stops.
pub fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = ()> + Send + 'static,
{
    world_seeded(0, f)
}

/// [`world`], with the world's random numbers drawn from `seed`, so that
/// its random choices repeat from run to run of an input.
pub fn world_seeded<F, Fut>(seed: u64, f: F)
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = ()> + Send + 'static,
{
    fictionet::fuzzing::seed_random(seed);
    let result = block_on(run(move |cx| {
        let fut = f(cx);
        async move {
            fut.await;
            Err::<(), fictionet::Error>("done".into())
        }
    }));
    assert_eq!(result.unwrap_err().to_string(), "done", "the world failed on its own");
}

/// Lets the world's other tasks run `n` turns.
pub async fn settle(cx: &Cx, n: usize) {
    for _ in 0..n {
        let _ = cx.yield_now().await;
    }
}

/// Polls `fut` once. `None` if it is not done yet.
pub async fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    poll_fn(|task| Poll::Ready(match fut.as_mut().poll(task) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }))
    .await
}

/// The fields of a TCP segment to build.
#[derive(Clone, Debug)]
pub struct Segment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Options, padded with NOPs to a multiple of 4 and cut to 40 bytes.
    pub options: &'a [u8],
    pub data: &'a [u8],
    /// Spoil the checksum.
    pub bad_checksum: bool,
}

/// A TCP segment in an IP packet.
pub fn tcp_packet(src: IpAddr, dst: IpAddr, s: &Segment<'_>) -> Vec<u8> {
    let mut options = s.options[..s.options.len().min(40)].to_vec();
    while !options.len().is_multiple_of(4) {
        options.push(1);
    }
    let mut t = Vec::with_capacity(20 + options.len() + s.data.len());
    t.extend_from_slice(&s.sport.to_be_bytes());
    t.extend_from_slice(&s.dport.to_be_bytes());
    t.extend_from_slice(&s.seq.to_be_bytes());
    t.extend_from_slice(&s.ack.to_be_bytes());
    t.push((((20 + options.len()) / 4) as u8) << 4);
    t.push(s.flags);
    t.extend_from_slice(&s.window.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0]);
    t.extend_from_slice(&options);
    t.extend_from_slice(s.data);
    let mut sum = transport_checksum(src, dst, 6, &t);
    if s.bad_checksum {
        sum ^= 0x5a5a;
    }
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    ip::packet(src, dst, 6, &t).0
}

/// A UDP datagram in an IP packet.
pub fn udp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + data.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let mut sum = transport_checksum(src, dst, 17, &u);
    if sum == 0 {
        sum = 0xffff;
    }
    u[6..8].copy_from_slice(&sum.to_be_bytes());
    ip::packet(src, dst, 17, &u).0
}

/// A [`Connection`] that reads `input` in pieces of the given sizes, then
/// reads the end, and keeps what is written to it.
pub struct MemConn {
    input: Vec<u8>,
    at: usize,
    pieces: Vec<usize>,
    piece: usize,
    pub output: Vec<u8>,
    pub shut: bool,
}

impl MemConn {
    pub fn new(input: Vec<u8>, pieces: Vec<usize>) -> MemConn {
        MemConn { input, at: 0, pieces, piece: 0, output: Vec::new(), shut: false }
    }
}

impl Connection for MemConn {
    fn poll_read(&mut self, _cx: &Cx, _task: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, ConnError>> {
        let want = match self.pieces.get(self.piece) {
            Some(&n) => n.max(1),
            None => usize::MAX,
        };
        self.piece += 1;
        let n = want.min(buf.len()).min(self.input.len() - self.at);
        buf[..n].copy_from_slice(&self.input[self.at..self.at + n]);
        self.at += n;
        Poll::Ready(Ok(n))
    }

    fn poll_write(&mut self, _cx: &Cx, _task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        if self.shut {
            return Poll::Ready(Err(ConnError::Closed));
        }
        self.output.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_shutdown(&mut self, _cx: &Cx, _task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.shut = true;
        Poll::Ready(Ok(()))
    }
}

/// Makes the checksums of an IP packet right, where it can be read: the
/// IPv4 header's, and the TCP, UDP or ICMP one after the fixed header. So
/// a fuzzer's packet reaches the code past the checksum checks.
pub fn fix_checksums(p: &mut [u8]) {
    let (src, dst, proto, at, end): (IpAddr, IpAddr, u8, usize, usize) = match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => {
            let ihl = ((p[0] & 15) as usize * 4).max(20).min(p.len());
            ip::set_header_checksum(&mut p[..ihl]);
            let total = (u16::from_be_bytes([p[2], p[3]]) as usize).clamp(ihl, p.len());
            let src = std::net::Ipv4Addr::new(p[12], p[13], p[14], p[15]).into();
            let dst = std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]).into();
            (src, dst, p[9], ihl, total)
        }
        Some(6) if p.len() >= 40 => {
            let end = (40 + u16::from_be_bytes([p[4], p[5]]) as usize).min(p.len());
            let src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()).into();
            let dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()).into();
            (src, dst, p[6], 40, end)
        }
        _ => return,
    };
    let at_sum = match proto {
        6 => 16,
        17 => 6,
        1 | 58 => 2,
        _ => return,
    };
    if end < at + at_sum + 2 {
        return;
    }
    let t = &mut p[at..end];
    t[at_sum] = 0;
    t[at_sum + 1] = 0;
    let sum = if proto == 1 { ip::checksum(t) } else { transport_checksum(src, dst, proto, t) };
    t[at_sum..at_sum + 2].copy_from_slice(&sum.to_be_bytes());
}
