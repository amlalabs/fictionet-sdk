//! One sandbox floods `web::Sites` with everything at once: made-up DNS
//! names, names under a wildcard site, unfinished fragments, SYNs it never
//! completes, and HTTP connections it holds open. The world's memory must
//! stay bounded, the limits must hold, and another sandbox must still be
//! served.
//!
//! In its own test binary, because it measures the process's memory. The
//! tests take turns, so one does not count the other's memory.

#[path = "common/timeout.rs"]
mod timeout;
#[path = "common/sandbox.rs"]
mod sandbox;
#[path = "common/wait.rs"]
mod wait;
#[path = "common/machine.rs"]
mod machine;

use sandbox::Machine;
use machine::machine;
use timeout::timeout;

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::{ip, web};
use fictionet::{Cx, End, Interface, Packet, block_on, run};
use http::{Request, Response};
use http_body_util::Full;

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const OTHER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

#[derive(Clone)]
struct Hello;

impl tower_service::Service<Request<fictionet::stdlib::web::Body>> for Hello {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<fictionet::stdlib::web::Body>) -> Self::Future {
        std::future::ready(Ok(Response::new(Full::new(Bytes::from_static(b"hello\n")))))
    }
}

/// The process's resident memory, in bytes.
fn rss() -> usize {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: usize = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

fn mib(n: usize) -> f64 {
    n as f64 / (1 << 20) as f64
}

/// An IPv4 packet; `frag` is the flags and offset field.
fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, frag: u16, payload: &[u8]) -> Packet {
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&frag.to_be_bytes());
    p.extend_from_slice(&[64, proto, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    ip::set_header_checksum(&mut p);
    p.extend_from_slice(payload);
    Packet(p)
}

fn udp(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let sum = ip::transport_checksum(src.into(), dst.into(), 17, &u);
    u[6..8].copy_from_slice(&sum.to_be_bytes());
    ipv4(src, dst, 17, 0, 0x4000, &u)
}

#[allow(clippy::too_many_arguments)]
fn tcp_seg(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(data);
    let sum = ip::transport_checksum(src.into(), dst.into(), 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    ipv4(src, dst, 6, 0, 0x4000, &t)
}

fn query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Message::query();
    q.metadata.id = id;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    q.to_vec().unwrap()
}

/// Every packet that arrives on `raw` until it stays quiet for `quiet`.
async fn drain(fcx: &Cx, raw: &mut End, quiet: Duration) -> Vec<Packet> {
    let mut got = Vec::new();
    while let Some(Ok(p)) = timeout(fcx, quiet, raw.recv(fcx)).await {
        got.push(p);
    }
    got
}

/// The TCP header of a packet from the world, if it carries TCP.
fn tcp_of(p: &Packet) -> Option<&[u8]> {
    let ihl = (p.0[0] & 15) as usize * 4;
    (p.0[9] == 6).then(|| &p.0[ihl..])
}

impl Machine {
    async fn lookup(&self, fcx: &Cx, name: &str) -> Ipv4Addr {
        let mut socket = self.udp.bind(5353).unwrap();
        socket.send_to(&query(name, 1), SocketAddr::new(GATEWAY.into(), 53));
        let (reply, _) = socket.recv(fcx).await.unwrap();
        let reply = Message::from_vec(&reply).unwrap();
        reply
            .answers
            .iter()
            .find_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .unwrap()
    }

    /// One HTTP/1.0 request for `host` at `to`. How long it took.
    async fn get(&self, fcx: &Cx, to: Ipv4Addr, host: &str) -> Duration {
        let started = fcx.now();
        let mut conn = self.tcp.connect(fcx, SocketAddr::new(to.into(), 80)).await.expect("the other sandbox connects");
        conn.write_all(fcx, format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(fcx, &mut buf).await.unwrap() {
                0 => break,
                n => got.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.0 200") && text.ends_with("hello\n"), "{text}");
        let now = fcx.now();
        now.since_start() - started.since_start()
    }
}

/// One test at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn one_sandbox_flooding_everything_stays_bounded_and_others_are_served() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = block_on(run(|fcx| async move {
            let sites = web::Sites::new(|host| match host {
                "plain.test" => Some(web::Site::new(Hello)),
                h if h.ends_with(".wild.test") => Some(web::Site::new(Hello)),
                _ => None,
            })
            .max_sites(1_000);
            let (attacher, attachments) = fictionet::attachments();
            sites.serve(&fcx, attachments)?;
            let mut raw = attacher.attach("agent").unwrap();
            let other = machine(&fcx, &attacher, "other", OTHER);
            let plain = other.lookup(&fcx, "plain.test").await;
            let wild = other.lookup(&fcx, "first.wild.test").await;
            other.get(&fcx, plain, "plain.test").await;
            // The agent binds its address with its first packet.
            raw.send(udp(ME, 5353, GATEWAY, 53, &query("plain.test", 1)));
            drain(&fcx, &mut raw, Duration::from_millis(200)).await;
            let start = rss();
            let mut report = Vec::new();

            // 1. Names: 150,000 made up, past the 100,000 kept; 5,000 under
            //    the wildcard, past the 1,000 sites this world allows.
            for i in 0..155_000u32 {
                let name = if i < 150_000 { format!("n{i}.made-up.test") } else { format!("w{i}.wild.test") };
                raw.send(udp(ME, 5353, GATEWAY, 53, &query(&name, i as u16)));
                if i % 256 == 255 {
                    drain(&fcx, &mut raw, Duration::from_millis(1)).await;
                }
            }
            drain(&fcx, &mut raw, Duration::from_millis(300)).await;
            report.push(("names", rss()));
            other.get(&fcx, plain, "plain.test").await;

            // 2. Fragments: 20,000 first halves of 1,400 bytes that never
            //    finish, 27 MiB in all, past the 4 MiB that may wait.
            let data = [0xab; 1400];
            for id in 0..20_000u16 {
                raw.send(ipv4(ME, plain, 17, id, 0x2000, &data));
                if id % 256 == 255 {
                    drain(&fcx, &mut raw, Duration::from_millis(1)).await;
                }
            }
            drain(&fcx, &mut raw, Duration::from_millis(200)).await;
            report.push(("fragments", rss()));
            other.get(&fcx, plain, "plain.test").await;

            // 3. SYNs: 20,000 that are never completed, to one machine.
            //    Every SYN-ACK is counted, from every drain.
            let mut synacks = std::collections::BTreeSet::new();
            let mut count = |got: Vec<Packet>| {
                for p in got {
                    if let Some(t) = tcp_of(&p)
                        && p.0[12..16] == wild.octets()
                        && t[13] & (SYN | ACK) == SYN | ACK
                    {
                        synacks.insert(u16::from_be_bytes([t[2], t[3]]));
                    }
                }
            };
            for port in 0..20_000u16 {
                raw.send(tcp_seg(ME, 20_000 + port, wild, 80, 1000, 0, SYN, &[]));
                if port % 256 == 255 {
                    count(drain(&fcx, &mut raw, Duration::from_millis(1)).await);
                }
            }
            count(drain(&fcx, &mut raw, Duration::from_millis(300)).await);
            report.push(("SYNs", rss()));
            // One address has its share of the backlog: 256 waiting.
            assert!(!synacks.is_empty() && synacks.len() <= 256, "{} SYN-ACKs", synacks.len());
            other.get(&fcx, wild, "first.wild.test").await;

            // 4. HTTP connections: 1,000 complete handshakes and requests,
            //    held open. The machine serves 256 and resets the rest. A
            //    SYN past the sandbox's share of the backlog gets no answer,
            //    so it is sent again, as a client would.
            let request = b"GET / HTTP/1.1\r\nHost: plain.test\r\n\r\n";
            let mut answered = std::collections::BTreeSet::new();
            let mut served = std::collections::BTreeSet::new();
            let mut reset = std::collections::BTreeSet::new();
            for _round in 0..50 {
                let mut sent = 0;
                for port in 50_000..51_000u16 {
                    if !answered.contains(&port) {
                        raw.send(tcp_seg(ME, port, plain, 80, 1000, 0, SYN, &[]));
                        sent += 1;
                    }
                }
                if sent == 0 {
                    break;
                }
                let mut pending = drain(&fcx, &mut raw, Duration::from_millis(300)).await;
                while !pending.is_empty() {
                    for p in std::mem::take(&mut pending) {
                        // Only this flood's answers: SYN-ACKs from the SYN
                        // flood's machine may still come.
                        let Some(t) = tcp_of(&p) else { continue };
                        let port = u16::from_be_bytes([t[2], t[3]]);
                        if p.0[12..16] != plain.octets() || !(50_000..51_000).contains(&port) {
                            continue;
                        }
                        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
                        let off = (t[12] >> 4) as usize * 4;
                        if t[13] & (SYN | ACK) == SYN | ACK {
                            if answered.insert(port) {
                                raw.send(tcp_seg(ME, port, plain, 80, 1001, seq.wrapping_add(1), ACK, request));
                            }
                        } else if t[13] & 0x04 != 0 {
                            reset.insert(port);
                        } else if t.len() > off {
                            served.insert(port);
                        }
                    }
                    pending = drain(&fcx, &mut raw, Duration::from_millis(300)).await;
                }
            }
            report.push(("connections", rss()));
            assert_eq!(served.len(), 256, "connections served");
            assert_eq!(reset.len(), 1000 - 256, "connections reset");
            other.get(&fcx, plain, "plain.test").await;

            let mut last = start;
            for (what, at) in &report {
                eprintln!("{what}: +{:.1} MiB", mib(at.saturating_sub(last)));
                last = *at;
            }
            let grew = last.saturating_sub(start);
            eprintln!("in all: +{:.1} MiB", mib(grew));
            // The names turned down cost about 35 MB at most. Sites are
            // capped at 1,000 here, each with two machines (IPv4 and IPv6) of
            // about 11 KiB, so about 22 MiB; the other 4,000 wildcard names
            // get SERVFAIL. Fragments and sockets are capped too. Measured:
            // names +31 MiB, fragments +7 MiB, connections +136 MiB.
            assert!(grew < 200 << 20, "the world grew by {:.1} MiB", mib(grew));
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        let _ = tx.send(result.map_err(|e| e.to_string()));
    });
    let result = rx.recv_timeout(Duration::from_secs(180)).expect("timed out");
    assert_eq!(result, Err("done".to_owned()));
}

/// Several sandboxes attached through real sockets, each sending packets
/// as fast as its socket takes them, send faster than the router forwards.
/// The links between them drop what does not fit, so the world's memory
/// stays bounded, and another sandbox is still served. Found while writing
/// the first test: without the cap, four such sandboxes grew the world by
/// about 240 MiB a second.
#[test]
fn sandboxes_sending_as_fast_as_they_can_do_not_grow_the_world() {
    use fictionet::relay::{self, Hello, Message, unix};
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let path = format!("{}/fictionet-test-{}-flood.sock", std::env::temp_dir().display(), std::process::id());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher.clone()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let world_sent = sent.clone();
    let attached = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let world_attached = attached.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let world_stop = stop.clone();
    let world_path = path.clone();
    std::thread::spawn(move || {
        let result = block_on(run(move |fcx| async move {
            let sites = web::Sites::new(|host| (host == "plain.test").then(|| web::Site::new(Hello)));
            sites.serve(&fcx, attachments)?;
            let other = machine(&fcx, &attacher, "other", Ipv4Addr::new(10, 0, 0, 100));
            let plain = other.lookup(&fcx, "plain.test").await;
            // Four sandboxes, each a thread with a socket: UDP to the
            // gateway's closed port 9, so each packet gets an ICMP answer
            // and the links carry traffic both ways.
            let senders: Vec<_> = (0..4u8)
                .map(|i| {
                    let (path, stop, sent) = (world_path.clone(), world_stop.clone(), world_sent.clone());
                    let attached = world_attached.clone();
                    std::thread::spawn(move || {
                        let fd = unix::connect(&path).unwrap();
                        let hello = Hello { version: relay::VERSION, mtu: 1500, kind: "tun".into(), name: format!("s{i}") };
                        unix::send(fd.as_raw_fd(), &Message::Hello(hello).encode(), false).unwrap();
                        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
                        let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
                        assert_eq!(&buf[..n], &[relay::ACCEPT]);
                        attached.fetch_add(1, Ordering::Relaxed);
                        let p = udp(Ipv4Addr::new(10, 0, 0, 2 + i), 5000, GATEWAY, 9, &[0; 100]);
                        while !stop.load(Ordering::Relaxed) {
                            if unix::send_parts(fd.as_raw_fd(), &[&[relay::PACKET], &p.0], false).is_err() {
                                return;
                            }
                            sent.fetch_add(1, Ordering::Relaxed);
                            while let Ok(n) = unix::recv(fd.as_raw_fd(), &mut buf, true) {
                                if n == 0 {
                                    return;
                                }
                            }
                        }
                    })
                })
                .collect();
            // The queues fill in the first moments. After that, the world
            // must not keep growing.
            let start = rss();
            let sent_before = world_sent.load(Ordering::Relaxed);
            wait::until(&fcx, Duration::from_secs(30), || {
                world_attached.load(Ordering::Relaxed) == 4 && world_sent.load(Ordering::Relaxed) - sent_before > 100_000
            }).await;
            let middle = rss();
            let sent_middle = world_sent.load(Ordering::Relaxed);
            wait::until(&fcx, Duration::from_secs(30), || {
                world_sent.load(Ordering::Relaxed) - sent_middle > 100_000
            }).await;
            let end = rss();
            let took = timeout(&fcx, Duration::from_secs(10), other.get(&fcx, plain, "plain.test")).await;
            world_stop.store(true, Ordering::Relaxed);
            // The flood ran: the senders kept sending while memory was read.
            let flooded = world_sent.load(Ordering::Relaxed) - sent_before;
            assert!(flooded > 100_000, "only {flooded} packets were sent");
            assert_eq!(world_attached.load(Ordering::Relaxed), 4, "a sender was not attached");
            let (first, second) = (middle.saturating_sub(start), end.saturating_sub(middle));
            eprintln!("four sandboxes flooding: +{:.1} MiB, then +{:.1} MiB", mib(first), mib(second));
            assert!(second < 16 << 20, "the world kept growing: +{:.1} MiB, then +{:.1} MiB", mib(first), mib(second));
            assert!(first + second < 64 << 20, "the world grew by {:.1} MiB", mib(first + second));
            assert!(took.is_some(), "the other sandbox was not served");
            // Joined outside the world: a sender may wait on its socket
            // until the world reads it.
            drop(senders);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        let _ = tx.send(result.map_err(|e| e.to_string()));
    });
    let result = rx.recv_timeout(Duration::from_secs(60)).expect("timed out");
    stop.store(true, Ordering::Relaxed);
    let _ = std::fs::remove_file(&path);
    assert_eq!(result, Err("done".to_owned()));
}
