//! The TCP endpoint's state machine (`tcp::endpoint`: smoltcp and the
//! stdlib's code around it), driven by an agent that sends any segments
//! it likes, in any order, while the world's side accepts, connects,
//! reads, writes, shuts down and drops connections.
//!
//! The input is structured: sequence and acknowledgment numbers are
//! mostly chosen relative to what each side expects, so the fuzzer gets
//! past the handshake and reaches every state, including wraparound
//! (the agent's initial sequence number is any `u32`).
#![no_main]

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use arbitrary::Arbitrary;
use fictionet::prelude::*;
use fictionet::stdlib::ConnError;
use fictionet::stdlib::tcp::{self, TcpConnection};
use fictionet::{End, Packet, pair};
use fictionet::Interface;
use fictionet::stdlib::ip::transport_checksum;
use fictionet_fuzz::{Segment, poll_once, settle, tcp_packet, world_seeded};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    v6: bool,
    /// The agent's initial sequence number. It also seeds the world's
    /// random numbers (its initial sequence numbers and ports), so they
    /// repeat from run to run of an input.
    isn: u32,
    ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Rel {
    /// What the other side expects next, plus this.
    Next(i16),
    /// Any number.
    Raw(u32),
}

#[derive(Arbitrary, Debug)]
enum Op {
    Seg { flow: u8, flags: u8, seq: Rel, ack: Rel, window: u16, options: Vec<u8>, len: u16, bad_checksum: bool },
    Pump(u8),
    Sleep(u8),
    Accept,
    Connect(u8),
    Read { conn: u8, len: u16 },
    Write { conn: u8, len: u16 },
    Shutdown(u8),
    Drop(u8),
    DropListener,
}

/// One connection as the agent sees it: its port, the world's port, the
/// next sequence number it sends, and the next it expects.
struct Flow {
    mine: u16,
    theirs: u16,
    next: u32,
    expect: Option<u32>,
}

type Connecting = Pin<Box<dyn Future<Output = Result<TcpConnection, ConnError>> + Send>>;

/// How many milliseconds one input may sleep in all, from
/// `FICTIONET_FUZZ_SLEEP_MS`. 0 by default: sleeping reaches the timers
/// (delayed ACKs, TIME-WAIT) but makes each run slower by far.
fn sleep_budget() -> u64 {
    static BUDGET: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(|| std::env::var("FICTIONET_FUZZ_SLEEP_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Reads what the world sent: checks each segment, and learns the world's
/// sequence numbers and the connections it opened.
fn drain(fcx: &fictionet::Cx, raw: &mut End, flows: &mut Vec<Flow>, me: IpAddr, world_addr: IpAddr, isn: u32) {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    while let std::task::Poll::Ready(Ok(p)) = raw.poll_recv(fcx, &mut cx) {
        let p = p.0;
        let (at, end) = if me.is_ipv4() {
            assert_eq!(p[0] >> 4, 4);
            assert_eq!(u16::from_be_bytes([p[2], p[3]]) as usize, p.len(), "IPv4 length");
            (((p[0] & 15) * 4) as usize, p.len())
        } else {
            assert_eq!(p[0] >> 4, 6);
            assert_eq!(40 + u16::from_be_bytes([p[4], p[5]]) as usize, p.len(), "IPv6 length");
            (40, p.len())
        };
        if p[if me.is_ipv4() { 9 } else { 6 }] != 6 {
            continue;
        }
        let t = &p[at..end];
        assert_eq!(transport_checksum(world_addr, me, 6, t), 0, "a segment from the world has a bad checksum");
        let off = (t[12] >> 4) as usize * 4;
        assert!(off >= 20 && off <= t.len());
        let (sport, dport) = (u16::from_be_bytes([t[0], t[1]]), u16::from_be_bytes([t[2], t[3]]));
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let flags = t[13];
        let end_seq = seq.wrapping_add((t.len() - off) as u32).wrapping_add((flags & 1) as u32).wrapping_add((flags >> 1 & 1) as u32);
        let n = flows.len();
        match flows.iter_mut().find(|f| f.mine == dport && f.theirs == sport) {
            Some(f) => {
                if f.expect.is_none_or(|e| seq_lt(e, end_seq)) {
                    f.expect = Some(end_seq);
                }
            }
            // The world connecting out: a new flow, from our ISN.
            None if flags & 0x12 == 0x02 && n < 16 => {
                flows.push(Flow { mine: dport, theirs: sport, next: isn, expect: Some(end_seq) });
            }
            None => {}
        }
    }
}

fuzz_target!(|input: Input| {
    world_seeded(input.isn as u64, move |fcx| async move {
        let (world_addr, me): (IpAddr, IpAddr) = if input.v6 {
            ("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap())
        } else {
            ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap())
        };
        let (mut raw, side) = pair();
        let endpoint = tcp::endpoint(&fcx, side, world_addr);
        let mut listener = Some(endpoint.listen(80).unwrap());
        let mut flows: Vec<Flow> = (0..3).map(|i| Flow { mine: 1000 + i, theirs: if i == 2 { 81 } else { 80 }, next: input.isn, expect: None }).collect();
        let mut conns: Vec<TcpConnection> = Vec::new();
        let mut connecting: Vec<Connecting> = Vec::new();
        let mut slept = 0u64;
        let data = |len: u16| -> Vec<u8> { (0..len as usize % 1460).map(|i| i as u8).collect() };
        for op in input.ops {
            match op {
                Op::Seg { flow, flags, seq, ack, window, options, len, bad_checksum } => {
                    let n = flows.len();
                    let f = &mut flows[flow as usize % n];
                    let payload = data(len);
                    let s = match seq {
                        Rel::Next(d) => f.next.wrapping_add(d as i32 as u32),
                        Rel::Raw(n) => n,
                    };
                    let a = match ack {
                        Rel::Next(d) => f.expect.unwrap_or(0).wrapping_add(d as i32 as u32),
                        Rel::Raw(n) => n,
                    };
                    if s == f.next && !bad_checksum {
                        f.next = s.wrapping_add(payload.len() as u32).wrapping_add((flags & 1) as u32).wrapping_add((flags >> 1 & 1) as u32);
                    }
                    let seg = Segment { sport: f.mine, dport: f.theirs, seq: s, ack: a, flags, window, options: &options, data: &payload, bad_checksum };
                    raw.send(Packet(tcp_packet(me, world_addr, &seg)));
                }
                Op::Pump(n) => {
                    settle(&fcx, 1 + n as usize % 8).await;
                    let mut i = 0;
                    while i < connecting.len() {
                        match poll_once(connecting[i].as_mut()).await {
                            Some(r) => {
                                drop(connecting.swap_remove(i));
                                if let Ok(c) = r {
                                    conns.push(c);
                                }
                            }
                            None => i += 1,
                        }
                    }
                }
                Op::Sleep(ms) => {
                    let ms = (ms as u64 % 12).min(sleep_budget() - slept);
                    slept += ms;
                    let _ = fcx.sleep(std::time::Duration::from_millis(ms)).await;
                }
                Op::Accept => {
                    if let Some(l) = &mut listener
                        && let Some(Ok(c)) = poll_once(l.accept(&fcx)).await
                    {
                        conns.push(c);
                    }
                }
                Op::Connect(port) => {
                    if connecting.len() < 4 {
                        let endpoint = endpoint.clone();
                        let fcx2 = fcx.clone();
                        let to = std::net::SocketAddr::new(me, 2000 + port as u16 % 4);
                        let mut fut: Connecting = Box::pin(async move { endpoint.connect(&fcx2, to).await });
                        if let Some(r) = poll_once(fut.as_mut()).await {
                            if let Ok(c) = r {
                                conns.push(c);
                            }
                        } else {
                            connecting.push(fut);
                        }
                    }
                }
                Op::Read { conn, len } => {
                    if !conns.is_empty() {
                        let i = conn as usize % conns.len();
                        let mut buf = vec![0u8; len as usize % 70_000];
                        let _ = poll_once(conns[i].read(&fcx, &mut buf)).await;
                    }
                }
                Op::Write { conn, len } => {
                    if !conns.is_empty() {
                        let i = conn as usize % conns.len();
                        let d: Vec<u8> = (0..len as usize * 4).map(|i| i as u8).collect();
                        let _ = poll_once(conns[i].write(&fcx, &d)).await;
                    }
                }
                Op::Shutdown(conn) => {
                    if !conns.is_empty() {
                        let i = conn as usize % conns.len();
                        let _ = poll_once(conns[i].shutdown(&fcx)).await;
                    }
                }
                Op::Drop(conn) => {
                    if !conns.is_empty() {
                        let i = conn as usize % conns.len();
                        drop(conns.swap_remove(i));
                    }
                }
                Op::DropListener => drop(listener.take()),
            }
            drain(&fcx, &mut raw, &mut flows, me, world_addr, input.isn);
        }
        drop(conns);
        drop(connecting);
        drop(listener);
        settle(&fcx, 4).await;
        drain(&fcx, &mut raw, &mut flows, me, world_addr, input.isn);
    });
});
