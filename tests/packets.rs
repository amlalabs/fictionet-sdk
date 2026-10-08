//! The packet stdlib: delay, bottleneck, the IP splits with reassembly, the
//! router and echo replies. Every test wires cables made with `pair()` and
//! runs under `run()` in real time, so timing checks leave room.

mod common;
#[path = "common/wait.rs"]
mod wait;

use common::within;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use etherparse::PacketBuilder;
use fictionet::prelude::*;
use fictionet::stdlib::route::{Prefix, lan, router};
use fictionet::stdlib::{bottleneck, delay, icmp, ip};
use fictionet::time::ms;
use fictionet::{Cx, End, Interface, Packet, RecvError, block_on, pair, run};

/// Runs a world to the end, within 10 seconds.
fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    within(Duration::from_secs(10), move || block_on(run(f))).unwrap();
}

/// Waits up to 5 s for a packet on `end`.
async fn recv_soon(fcx: &Cx, end: &mut End) -> Packet {
    recv_within(fcx, end, ms(5000))
        .await
        .expect("no packet arrived")
}

/// Waits up to `limit` for a packet. `None` if none came.
async fn recv_within(fcx: &Cx, end: &mut End, limit: Duration) -> Option<Packet> {
    let deadline = fcx.now() + limit;
    let mut sleep = Box::pin(fcx.sleep_until(deadline));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(r) = end.poll_recv(fcx, cx) {
            return Poll::Ready(r.ok());
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

use std::future::Future;

/// A cable that records when its owner has removed it.
struct Removed {
    end: End,
    removed: Arc<AtomicBool>,
}

impl Interface for Removed {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        self.end.poll_recv(fcx, cx)
    }

    fn send(&mut self, packet: Packet) {
        self.end.send(packet);
    }
}

impl Drop for Removed {
    fn drop(&mut self) {
        self.removed.store(true, Ordering::SeqCst);
    }
}

/// Wraps a cable and returns a flag set when its owner removes it.
fn removed(end: End) -> (Removed, Arc<AtomicBool>) {
    let removed = Arc::new(AtomicBool::new(false));
    (
        Removed {
            end,
            removed: removed.clone(),
        },
        removed,
    )
}

/// A tagged packet: a byte to tell it apart, then `len - 1` filler bytes.
fn tagged(tag: u8, len: usize) -> Packet {
    let mut v = vec![0xee; len];
    v[0] = tag;
    Packet(v)
}

// ---------------------------------------------------------------- delay

#[test]
fn delay_holds_every_packet_both_ways_and_keeps_order() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        let mut link = delay(&fcx, ms(50), world_side);

        // Ten packets sent together arrive together, 50 ms later, in order.
        let sent = fcx.now();
        for i in 0..10 {
            sandbox.send(tagged(i, 100));
        }
        for i in 0..10 {
            let p = recv_soon(&fcx, &mut link).await;
            assert_eq!(p.0[0], i, "order kept");
            let waited = fcx.now().since_start() - sent.since_start();
            assert!(waited >= ms(50), "packet {i} came after {waited:?}");
            assert!(waited < ms(5000), "packet {i} came after {waited:?}");
        }

        // The other direction too.
        let sent = fcx.now();
        for i in 0..10 {
            link.send(tagged(100 + i, 100));
        }
        for i in 0..10 {
            let p = recv_soon(&fcx, &mut sandbox).await;
            assert_eq!(p.0[0], 100 + i);
            let waited = fcx.now().since_start() - sent.since_start();
            assert!(waited >= ms(50) && waited < ms(5000), "{waited:?}");
        }

        // Packets sent apart stay apart: each is held for 50 ms from when
        // it was sent, not from when the one before it left.
        let t0 = fcx.now();
        sandbox.send(tagged(1, 10));
        fcx.sleep(ms(30)).await?;
        sandbox.send(tagged(2, 10));
        recv_soon(&fcx, &mut link).await;
        let first = fcx.now().since_start() - t0.since_start();
        recv_soon(&fcx, &mut link).await;
        let second = fcx.now().since_start() - t0.since_start();
        assert!(first >= ms(50) && first < ms(5000), "{first:?}");
        assert!(second >= ms(80) && second < ms(5000), "{second:?}");
        Ok(())
    });
}

#[test]
fn delay_ends_when_either_cable_closes() {
    world(|fcx| async move {
        let (sandbox, world_side) = pair();
        let mut link = delay(&fcx, ms(10), world_side);
        drop(sandbox);
        assert_eq!(link.recv(&fcx).await, Err(RecvError::Closed));

        let (mut sandbox, world_side) = pair();
        let link = delay(&fcx, ms(10), world_side);
        drop(link);
        assert_eq!(sandbox.recv(&fcx).await, Err(RecvError::Closed));
        Ok(())
    });
}

// ----------------------------------------------------------- bottleneck

#[test]
fn bottleneck_sends_at_the_rate() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        // 1 Mbit/s: a 1,250-byte packet takes 10 ms.
        let mut link = bottleneck(&fcx, 1_000_000, 100, world_side);
        let t0 = fcx.now();
        for i in 0..20 {
            sandbox.send(tagged(i, 1250));
        }
        let mut times = Vec::new();
        for i in 0..20 {
            let p = recv_soon(&fcx, &mut link).await;
            assert_eq!(p.0[0], i);
            times.push(fcx.now().since_start() - t0.since_start());
        }
        assert!(times[0] >= ms(10), "first after {:?}", times[0]);
        assert!(times[19] >= ms(200), "last after {:?}", times[19]);
        assert!(times[19] < ms(5000), "last after {:?}", times[19]);
        // Each packet leaves at least 10 ms after the one before, so they
        // are spread out, not sent in a lump.
        assert!(
            times[9] >= ms(100) && times[9] < ms(5000),
            "tenth after {:?}",
            times[9]
        );

        // The other direction has its own rate and queue.
        let t0 = fcx.now();
        for i in 0..5 {
            link.send(tagged(i, 1250));
        }
        for i in 0..5 {
            assert_eq!(recv_soon(&fcx, &mut sandbox).await.0[0], i);
        }
        let took = fcx.now().since_start() - t0.since_start();
        assert!(took >= ms(50) && took < ms(5000), "{took:?}");
        Ok(())
    });
}

#[test]
fn bottleneck_queue_of_ten_drops_the_eleventh_of_a_burst() {
    world(|fcx| async move {
        for direction in 0..2 {
            let (mut sandbox, world_side) = pair();
            let mut link = bottleneck(&fcx, 1_000_000, 10, world_side);
            let (from, to) = if direction == 0 {
                (&mut sandbox, &mut link)
            } else {
                (&mut link, &mut sandbox)
            };
            for i in 0..11 {
                from.send(tagged(i, 1250));
            }
            for i in 0..10 {
                assert_eq!(recv_soon(&fcx, to).await.0[0], i);
            }
            assert!(
                recv_within(&fcx, to, ms(100)).await.is_none(),
                "the 11th was not dropped"
            );

            // Once the queue has drained, packets pass again.
            from.send(tagged(42, 1250));
            assert_eq!(recv_soon(&fcx, to).await.0[0], 42);
        }
        Ok(())
    });
}

// ------------------------------------------------------------ the splits

fn v4_udp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64).udp(1000, 53);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

fn v4_tcp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64).tcp(1000, 443, 1, 1000);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

fn v6_udp(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(src, dst, 64).udp(1000, 53);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

fn v6_tcp(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(src, dst, 64).tcp(1000, 443, 1, 1000);
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

const A4: [u8; 4] = [10, 0, 0, 2];
const B4: [u8; 4] = [1, 1, 1, 1];
const A6: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const B6: [u8; 16] = [
    0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
];

#[test]
fn split_versions_sorts_by_version_and_merges_back() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        let (mut v4, mut v6, mut other) = ip::split_versions(&fcx, world_side);
        let p4 = v4_udp(A4, B4, b"four");
        let p6 = v6_udp(A6, B6, b"six");
        sandbox.send(Packet(p4.clone()));
        sandbox.send(Packet(p6.clone()));
        sandbox.send(Packet(vec![]));
        sandbox.send(Packet(vec![0x50, 1, 2]));
        assert_eq!(recv_soon(&fcx, &mut v4).await.0, p4);
        assert_eq!(recv_soon(&fcx, &mut v6).await.0, p6);
        assert_eq!(recv_soon(&fcx, &mut other).await.0, Vec::<u8>::new());
        assert_eq!(recv_soon(&fcx, &mut other).await.0, vec![0x50, 1, 2]);

        // Packets sent into any end go out on the cable being split.
        v6.send(Packet(p6.clone()));
        other.send(Packet(vec![9]));
        v4.send(Packet(p4.clone()));
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(recv_soon(&fcx, &mut sandbox).await.0);
        }
        got.sort();
        let mut want = vec![p6, vec![9], p4];
        want.sort();
        assert_eq!(got, want);

        // Closing the split cable closes all three ends.
        drop(sandbox);
        assert_eq!(v4.recv(&fcx).await, Err(RecvError::Closed));
        assert_eq!(v6.recv(&fcx).await, Err(RecvError::Closed));
        assert_eq!(other.recv(&fcx).await, Err(RecvError::Closed));
        Ok(())
    });
}

/// An ICMPv4 error of `type_`/`code` about `quoted` (its first 28 bytes).
fn icmp4_error(type_: u8, code: u8, quoted: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv4(B4, A4, 64).icmpv4_raw(type_, code, [0; 4]);
    let mut v = Vec::new();
    b.write(&mut v, &quoted[..28.min(quoted.len())]).unwrap();
    v
}

/// An ICMPv6 error of `type_`/`code` about `quoted`.
fn icmp6_error(type_: u8, code: u8, rest: [u8; 4], quoted: &[u8]) -> Vec<u8> {
    let b = PacketBuilder::ipv6(B6, A6, 64).icmpv6_raw(type_, code, rest);
    let mut v = Vec::new();
    b.write(&mut v, quoted).unwrap();
    v
}

#[test]
fn split_protocols_sorts_by_protocol_and_icmp_errors_by_the_quoted_packet() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        let (mut tcp, mut udp, mut icmp_end, mut other) = ip::split_protocols(&fcx, world_side);

        let tcp4 = v4_tcp(A4, B4, b"hello");
        let udp4 = v4_udp(A4, B4, b"query");
        let tcp6 = v6_tcp(A6, B6, b"hello");
        let udp6 = v6_udp(A6, B6, b"query");
        let mut ping4 = Vec::new();
        PacketBuilder::ipv4(A4, B4, 64)
            .icmpv4_echo_request(1, 1)
            .write(&mut ping4, b"ping")
            .unwrap();
        let mut ping6 = Vec::new();
        PacketBuilder::ipv6(A6, B6, 64)
            .icmpv6_echo_request(1, 1)
            .write(&mut ping6, b"ping")
            .unwrap();
        // GRE (47) is neither.
        let mut gre = udp4.clone();
        gre[9] = 47;
        // A UDP packet behind a hop-by-hop extension header.
        let mut hbh = udp6[..40].to_vec();
        hbh[6] = 0; // next header: hop-by-hop
        hbh[5] += 8; // payload length grows by the 8-byte header
        hbh.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        hbh.extend_from_slice(&udp6[40..]);

        // ICMP errors about TCP and UDP packets.
        let port_unreachable = icmp4_error(3, 3, &udp4);
        let frag_needed = icmp4_error(3, 4, &tcp4);
        let too_big = icmp6_error(2, 0, [0, 0, 5, 0x78], &tcp6);
        let unreachable6 = icmp6_error(1, 4, [0; 4], &udp6);
        // An error about a ping stays with ICMP.
        let about_ping = icmp4_error(11, 0, &ping4);

        for p in [
            &tcp4,
            &udp4,
            &tcp6,
            &udp6,
            &ping4,
            &ping6,
            &gre,
            &hbh,
            &port_unreachable,
            &frag_needed,
            &too_big,
            &unreachable6,
            &about_ping,
        ] {
            sandbox.send(Packet(p.clone()));
        }
        assert_eq!(recv_soon(&fcx, &mut tcp).await.0, tcp4);
        assert_eq!(recv_soon(&fcx, &mut tcp).await.0, tcp6);
        assert_eq!(recv_soon(&fcx, &mut tcp).await.0, frag_needed);
        assert_eq!(recv_soon(&fcx, &mut tcp).await.0, too_big);
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, udp4);
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, udp6);
        // The hop-by-hop header asks nothing of the host, and is taken out.
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, udp6);
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, port_unreachable);
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, unreachable6);
        assert_eq!(recv_soon(&fcx, &mut icmp_end).await.0, ping4);
        assert_eq!(recv_soon(&fcx, &mut icmp_end).await.0, ping6);
        assert_eq!(recv_soon(&fcx, &mut icmp_end).await.0, about_ping);
        assert_eq!(recv_soon(&fcx, &mut other).await.0, gre);
        for end in [&mut tcp, &mut udp, &mut icmp_end, &mut other] {
            assert!(
                recv_within(&fcx, end, ms(30)).await.is_none(),
                "an extra packet"
            );
        }

        // Everything sent into the ends goes out on the split cable.
        tcp.send(Packet(tcp4.clone()));
        udp.send(Packet(udp4.clone()));
        icmp_end.send(Packet(ping4.clone()));
        other.send(Packet(gre.clone()));
        for _ in 0..4 {
            recv_soon(&fcx, &mut sandbox).await;
        }
        Ok(())
    });
}

/// The Internet checksum, written here apart from the crate's own.
fn internet_checksum(pseudo: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for i in (0..bytes.len()).step_by(2) {
            let hi = bytes[i] as u32;
            let lo = if i + 1 < bytes.len() {
                bytes[i + 1] as u32
            } else {
                0
            };
            sum += (hi << 8) | lo;
        }
    };
    add(pseudo);
    add(data);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Splits an IPv4 packet into fragments of the given data sizes (multiples
/// of 8), then one more for the rest. Clears "don't fragment" first, and
/// returns the packet as it should come back.
fn fragment_v4(packet: &[u8], sizes: &[usize]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut whole = packet.to_vec();
    whole[6] = 0;
    whole[7] = 0;
    whole[10] = 0;
    whole[11] = 0;
    let c = internet_checksum(&[], &whole[..20]);
    whole[10..12].copy_from_slice(&c.to_be_bytes());
    let data = &whole[20..];
    let mut frags = Vec::new();
    let mut offset = 0;
    for n in 0..=sizes.len() {
        let last = n == sizes.len();
        let size = if last { data.len() - offset } else { sizes[n] };
        let mut f = whole[..20].to_vec();
        f[2..4].copy_from_slice(&((20 + size) as u16).to_be_bytes());
        let flags = if last { 0 } else { 0x2000 };
        f[6..8].copy_from_slice(&((offset / 8) as u16 | flags).to_be_bytes());
        f[10] = 0;
        f[11] = 0;
        let c = internet_checksum(&[], &f[..20]);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        f.extend_from_slice(&data[offset..offset + size]);
        frags.push(f);
        offset += size;
    }
    (whole, frags)
}

/// Splits an IPv6 packet with no extension headers into fragments of the
/// given sizes, then one more for the rest.
fn fragment_v6(packet: &[u8], sizes: &[usize], id: u32) -> Vec<Vec<u8>> {
    let next = packet[6];
    let data = &packet[40..];
    let mut frags = Vec::new();
    let mut offset = 0;
    for n in 0..=sizes.len() {
        let last = n == sizes.len();
        let size = if last { data.len() - offset } else { sizes[n] };
        let mut f = packet[..40].to_vec();
        f[4..6].copy_from_slice(&((8 + size) as u16).to_be_bytes());
        f[6] = 44;
        f.push(next);
        f.push(0);
        f.extend_from_slice(&((offset as u16) | if last { 0 } else { 1 }).to_be_bytes());
        f.extend_from_slice(&id.to_be_bytes());
        f.extend_from_slice(&data[offset..offset + size]);
        frags.push(f);
        offset += size;
    }
    frags
}

#[test]
fn split_protocols_reassembles_fragments_that_arrive_out_of_order() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        let (_tcp, mut udp, _icmp, mut other) = ip::split_protocols(&fcx, world_side);

        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let (whole, frags) = fragment_v4(&v4_udp(A4, B4, &payload), &[1480, 1480]);
        assert_eq!(frags.len(), 3);
        // Last, first, middle. Only the first names UDP's port numbers.
        for i in [2, 0, 1] {
            sandbox.send(Packet(frags[i].clone()));
        }
        let got = recv_soon(&fcx, &mut udp).await.0;
        assert_eq!(got, whole);
        assert_eq!(internet_checksum(&[], &got[..20]), 0, "header checksum");

        // IPv6, middle first.
        let whole6 = v6_udp(A6, B6, &payload);
        let frags6 = fragment_v6(&whole6, &[1232, 1232], 77);
        for i in [1, 2, 0] {
            sandbox.send(Packet(frags6[i].clone()));
        }
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, whole6);

        // Two packets whose fragments arrive interleaved.
        let (whole_a, frags_a) = fragment_v4(&v4_udp(A4, B4, &payload[..1000]), &[504]);
        let mut other_id = v4_udp(A4, B4, &payload[..1200]);
        other_id[5] ^= 0x55; // a different identification
        let (whole_b, frags_b) = fragment_v4(&other_id, &[400, 400]);
        for f in [
            &frags_b[2],
            &frags_a[1],
            &frags_b[0],
            &frags_a[0],
            &frags_b[1],
        ] {
            sandbox.send(Packet(f.clone()));
        }
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, whole_a);
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, whole_b);

        // Overlapping fragments drop the whole packet.
        let mut bad_id = v4_udp(A4, B4, &payload[..1600]);
        bad_id[5] ^= 0x33;
        let (_, frags_c) = fragment_v4(&bad_id, &[800]);
        let (_, overlap) = fragment_v4(&bad_id, &[400, 800]);
        sandbox.send(Packet(frags_c[0].clone()));
        sandbox.send(Packet(overlap[1].clone())); // bytes 400..1200 overlap 0..800
        sandbox.send(Packet(frags_c[1].clone()));
        assert!(
            recv_within(&fcx, &mut udp, ms(50)).await.is_none(),
            "overlapping fragments were joined"
        );
        assert!(recv_within(&fcx, &mut other, ms(10)).await.is_none());

        // A packet in one fragment (an atomic fragment) passes at once.
        let atomic = fragment_v6(&whole6, &[], 5);
        assert_eq!(atomic.len(), 1);
        sandbox.send(Packet(atomic[0].clone()));
        assert_eq!(recv_soon(&fcx, &mut udp).await.0, whole6);
        Ok(())
    });
}

// --------------------------------------------------------------- router

fn to4(dst: [u8; 4], tag: u8) -> Packet {
    Packet(v4_udp(A4, dst, &[tag]))
}

#[test]
fn prefixes_parse() {
    let p: Prefix = "10.0.0.0/8".parse().unwrap();
    assert_eq!(
        p,
        Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            len: 8
        }
    );
    let p: Prefix = "::/0".parse().unwrap();
    assert_eq!(
        p,
        Prefix {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            len: 0
        }
    );
    let p: Prefix = "10.1.2.3/8".parse().unwrap();
    assert_eq!(p.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    let p: Prefix = "1.1.1.1".parse().unwrap();
    assert_eq!(p.len, 32);
    let p: Prefix = "fd00::1/64".parse().unwrap();
    assert_eq!(p.addr, "fd00::".parse::<IpAddr>().unwrap());
    for bad in [
        "",
        "10.0.0.0/33",
        "::/129",
        "10.0.0.0/",
        "10.0.0.0/x",
        "10.0.0/8",
        "10.0.0.0/-1",
        "10.0.0.0/+8",
    ] {
        assert!(bad.parse::<Prefix>().is_err(), "{bad:?} parsed");
    }
}

#[test]
fn router_longest_prefix_add_replace_and_removal_on_close() {
    world(|fcx| async move {
        let (a_router, mut a) = pair();
        let (b_router, mut b) = pair();
        let (c_router, mut c) = pair();
        let (c_router, c_removed) = removed(c_router);
        let (d_router, mut d) = pair();
        let routes: Vec<(Prefix, Box<dyn Interface>)> = vec![
            ("10.0.0.0/8".parse()?, Box::new(a_router)),
            ("10.1.0.0/16".parse()?, Box::new(b_router)),
            ("0.0.0.0/0".parse()?, Box::new(c_router)),
            ("::/0".parse()?, Box::new(d_router)),
        ];
        let r = router(&fcx, routes);

        // Longest prefix wins, from any cable. The router lowers the TTL.
        let hop = |src, dst, payload: &[u8]| {
            let mut v = Vec::new();
            PacketBuilder::ipv4(src, dst, 63)
                .udp(1000, 53)
                .write(&mut v, payload)
                .unwrap();
            v
        };
        c.send(to4([10, 1, 2, 3], 1));
        assert_eq!(
            recv_soon(&fcx, &mut b).await.0,
            hop(A4, [10, 1, 2, 3], &[1])
        );
        c.send(to4([10, 2, 0, 1], 2));
        assert_eq!(
            recv_soon(&fcx, &mut a).await.0,
            hop(A4, [10, 2, 0, 1], &[2])
        );
        a.send(to4([8, 8, 8, 8], 3));
        assert_eq!(recv_soon(&fcx, &mut c).await.0[28], 3);
        // Back out the cable it came in on, when that is the best route.
        c.send(to4([9, 9, 9, 9], 4));
        assert_eq!(recv_soon(&fcx, &mut c).await.0[28], 4);
        // IPv6 matches IPv6 prefixes only.
        a.send(Packet(v6_udp(A6, B6, &[5])));
        assert_eq!(recv_soon(&fcx, &mut d).await.0[48], 5);
        // Junk is dropped.
        a.send(Packet(vec![0x45, 0]));
        a.send(Packet(vec![]));

        // Add a longer prefix.
        let (e_router, mut e) = pair();
        let (e_router, e_removed) = removed(e_router);
        r.add("10.1.2.0/24".parse()?, Box::new(e_router));
        c.send(to4([10, 1, 2, 3], 6));
        assert_eq!(recv_soon(&fcx, &mut e).await.0[28], 6);
        c.send(to4([10, 1, 3, 3], 7));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 7);

        // Replace 10.1.0.0/16: the old cable is dropped.
        let (f_router, mut f) = pair();
        r.add("10.1.0.0/16".parse()?, Box::new(f_router));
        assert_eq!(b.recv(&fcx).await, Err(RecvError::Closed));
        c.send(to4([10, 1, 3, 3], 8));
        assert_eq!(recv_soon(&fcx, &mut f).await.0[28], 8);

        // A closed cable loses its route: the next best one takes over.
        drop(e);
        wait::until(&fcx, Duration::from_secs(10), || {
            e_removed.load(Ordering::SeqCst)
        })
        .await;
        c.send(to4([10, 1, 2, 3], 9));
        assert_eq!(recv_soon(&fcx, &mut f).await.0[28], 9);
        // And with no route left for an address, packets are dropped.
        drop(c);
        wait::until(&fcx, Duration::from_secs(10), || {
            c_removed.load(Ordering::SeqCst)
        })
        .await;
        a.send(to4([8, 8, 8, 8], 10));
        for end in [&mut a, &mut d, &mut f] {
            assert!(recv_within(&fcx, end, ms(30)).await.is_none());
        }

        // The router ends once its last cable has closed and the handle is
        // gone. The run then ends, which `world` checks.
        drop(r);
        drop((a, d, f));
        Ok(())
    });
}

#[test]
fn router_keeps_running_while_the_handle_can_add_routes() {
    world(|fcx| async move {
        let (a_router, a) = pair();
        let (a_router, a_removed) = removed(a_router);
        let r = router(
            &fcx,
            vec![(
                "10.0.0.0/8".parse()?,
                Box::new(a_router) as Box<dyn Interface>,
            )],
        );
        drop(a);
        wait::until(&fcx, Duration::from_secs(10), || {
            a_removed.load(Ordering::SeqCst)
        })
        .await;
        // Every cable is closed, but the handle is alive: a new route works.
        let (b_router, mut b) = pair();
        let (c_router, mut c) = pair();
        r.add("10.0.0.0/8".parse()?, Box::new(b_router));
        r.add("0.0.0.0/0".parse()?, Box::new(c_router));
        c.send(to4([10, 0, 0, 1], 1));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 1);
        drop(r);
        drop((b, c));
        Ok(())
    });
}

#[test]
fn lan_forwards_unicast_and_floods_ip_group_traffic() {
    world(|fcx| async move {
        let network: Prefix = "192.168.56.0/24".parse()?;
        let lan = lan::<Box<dyn Interface>, _>(&fcx, network, |event| event);
        let (a_lan, mut a) = pair();
        let (b_lan, mut b) = pair();
        let (c_lan, mut c) = pair();
        lan.add("192.168.56.10".parse()?, Box::new(a_lan), None)?;
        lan.add("192.168.56.11".parse()?, Box::new(b_lan), None)?;
        lan.add("192.168.56.22".parse()?, Box::new(c_lan), None)?;

        // Unicast goes only to the member that owns the destination.
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[1])));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 1);
        assert!(recv_within(&fcx, &mut c, ms(20)).await.is_none());

        // The subnet broadcast, limited broadcast and multicast are copied
        // to every member except the sender.
        for (dst, tag) in [
            ([192, 168, 56, 255], 2),
            ([255, 255, 255, 255], 3),
            ([224, 0, 0, 252], 4),
        ] {
            a.send(Packet(v4_udp([192, 168, 56, 10], dst, &[tag])));
            assert_eq!(recv_soon(&fcx, &mut b).await.0[28], tag);
            assert_eq!(recv_soon(&fcx, &mut c).await.0[28], tag);
            assert!(recv_within(&fcx, &mut a, ms(20)).await.is_none());
        }

        // Reconnecting an address replaces the old member.
        let (new_b_lan, mut new_b) = pair();
        lan.add("192.168.56.11".parse()?, Box::new(new_b_lan), None)?;
        assert_eq!(b.recv(&fcx).await, Err(RecvError::Closed));
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[5])));
        assert_eq!(recv_soon(&fcx, &mut new_b).await.0[28], 5);

        let (outside_lan, _outside) = pair();
        assert!(
            lan.add("192.168.57.1".parse()?, Box::new(outside_lan), None)
                .is_err()
        );

        drop(lan);
        drop((a, b, c, new_b));
        Ok(())
    });
}

#[test]
fn lan_sends_off_subnet_unicast_to_the_gateway_or_drops_it() {
    world(|fcx| async move {
        let lan = lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
        let (a_lan, mut a) = pair();
        let (b_lan, mut b) = pair();
        lan.add("192.168.56.10".parse()?, Box::new(a_lan), None)?;
        lan.add("192.168.56.11".parse()?, Box::new(b_lan), None)?;

        // With no gateway, a packet for another subnet goes nowhere, and
        // the LAN carries on.
        a.send(Packet(v4_udp([192, 168, 56, 10], [10, 0, 0, 1], &[1])));
        assert!(recv_within(&fcx, &mut b, ms(20)).await.is_none());
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[2])));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 2);

        // With one, it goes there. The gateway's packets come in like a
        // member's: unicast to the owner, broadcast to everyone.
        let (gw_lan, mut gw) = pair();
        lan.gateway(Box::new(gw_lan))?;
        a.send(Packet(v4_udp([192, 168, 56, 10], [10, 0, 0, 1], &[3])));
        assert_eq!(recv_soon(&fcx, &mut gw).await.0[28], 3);
        gw.send(Packet(v4_udp([10, 0, 0, 1], [192, 168, 56, 11], &[4])));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 4);
        assert!(recv_within(&fcx, &mut a, ms(20)).await.is_none());
        gw.send(Packet(v4_udp([10, 0, 0, 1], [192, 168, 56, 255], &[5])));
        assert_eq!(recv_soon(&fcx, &mut a).await.0[28], 5);
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 5);

        // Members' broadcasts and multicasts stay among the members.
        a.send(Packet(v4_udp(
            [192, 168, 56, 10],
            [192, 168, 56, 255],
            &[6],
        )));
        a.send(Packet(v4_udp([192, 168, 56, 10], [224, 0, 0, 252], &[7])));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 6);
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 7);
        assert!(recv_within(&fcx, &mut gw, ms(20)).await.is_none());

        // A packet from the gateway for another subnet is dropped, not
        // sent back.
        gw.send(Packet(v4_udp([10, 0, 0, 1], [10, 0, 0, 2], &[8])));
        assert!(recv_within(&fcx, &mut gw, ms(20)).await.is_none());

        // A new gateway replaces the old one, which is closed.
        let (gw2_lan, mut gw2) = pair();
        let (gw2_lan, gw2_removed) = removed(gw2_lan);
        lan.gateway(Box::new(gw2_lan))?;
        assert_eq!(gw.recv(&fcx).await, Err(RecvError::Closed));
        a.send(Packet(v4_udp([192, 168, 56, 10], [10, 0, 0, 1], &[9])));
        assert_eq!(recv_soon(&fcx, &mut gw2).await.0[28], 9);

        // When the gateway closes, the LAN is sealed again.
        drop(gw2);
        wait::until(&fcx, Duration::from_secs(10), || {
            gw2_removed.load(Ordering::SeqCst)
        })
        .await;
        a.send(Packet(v4_udp([192, 168, 56, 10], [10, 0, 0, 1], &[10])));
        for end in [&mut a, &mut b] {
            assert!(recv_within(&fcx, end, ms(20)).await.is_none());
        }

        drop(lan);
        drop((a, b));
        Ok(())
    });
}

const LL_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const LLMNR6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3];

#[test]
fn lan_carries_one_address_family() {
    world(|fcx| async move {
        // IPv6 on an IPv4 LAN is dropped: link-local multicast and unicast
        // alike, gateway or not. IPv4 still flows.
        let lan4 = lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
        let (a_lan, mut a) = pair();
        let (b_lan, mut b) = pair();
        let (gw_lan, mut gw) = pair();
        lan4.add("192.168.56.10".parse()?, Box::new(a_lan), None)?;
        lan4.add("192.168.56.11".parse()?, Box::new(b_lan), None)?;
        lan4.gateway(Box::new(gw_lan))?;
        a.send(Packet(v6_udp(LL_A, LLMNR6, &[1])));
        a.send(Packet(v6_udp(LL_A, B6, &[2])));
        // IPv4 link-local stays on the LAN too: no member, so dropped.
        a.send(Packet(v4_udp([192, 168, 56, 10], [169, 254, 1, 1], &[3])));
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[4])));
        assert_eq!(recv_soon(&fcx, &mut b).await.0[28], 4);
        for end in [&mut a, &mut b, &mut gw] {
            assert!(recv_within(&fcx, end, ms(20)).await.is_none());
        }

        // An IPv6 LAN forwards unicast, floods multicast, takes no IPv4
        // member and drops IPv4 packets. Link-local unicast is on the LAN,
        // so it never reaches the gateway.
        let lan6 = lan::<Box<dyn Interface>, _>(&fcx, "fd00::/64".parse()?, |event| event);
        let fd = |host: u8| -> [u8; 16] { [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, host] };
        let (c_lan, mut c) = pair();
        let (d_lan, mut d) = pair();
        let (e_lan, mut e) = pair();
        let (gw6_lan, mut gw6) = pair();
        lan6.add("fd00::10".parse()?, Box::new(c_lan), None)?;
        lan6.add("fd00::11".parse()?, Box::new(d_lan), None)?;
        lan6.add("fd00::22".parse()?, Box::new(e_lan), None)?;
        lan6.gateway(Box::new(gw6_lan))?;
        let (x_lan, _x) = pair();
        assert!(
            lan6.add("192.168.56.10".parse()?, Box::new(x_lan), None)
                .is_err()
        );
        c.send(Packet(v6_udp(fd(0x10), fd(0x11), &[5])));
        assert_eq!(recv_soon(&fcx, &mut d).await.0[48], 5);
        assert!(recv_within(&fcx, &mut e, ms(20)).await.is_none());
        c.send(Packet(v6_udp(fd(0x10), LLMNR6, &[6])));
        assert_eq!(recv_soon(&fcx, &mut d).await.0[48], 6);
        assert_eq!(recv_soon(&fcx, &mut e).await.0[48], 6);
        c.send(Packet(v6_udp(fd(0x10), B6, &[7])));
        assert_eq!(recv_soon(&fcx, &mut gw6).await.0[48], 7);
        c.send(Packet(v6_udp(
            LL_A,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11],
            &[8],
        )));
        c.send(Packet(v4_udp(A4, B4, &[9])));
        for end in [&mut c, &mut d, &mut e, &mut gw6] {
            assert!(recv_within(&fcx, end, ms(20)).await.is_none());
        }

        drop((lan4, lan6));
        drop((a, b, gw, c, d, e, gw6));
        Ok(())
    });
}

#[test]
fn lan_forgets_a_member_whose_interface_closed() {
    world(|fcx| async move {
        let lan = lan::<Box<dyn Interface>, _>(&fcx, "192.168.56.0/24".parse()?, |event| event);
        let (a_lan, mut a) = pair();
        let (b_lan, b) = pair();
        let (b_lan, b_removed) = removed(b_lan);
        let (c_lan, mut c) = pair();
        lan.add("192.168.56.10".parse()?, Box::new(a_lan), None)?;
        lan.add("192.168.56.11".parse()?, Box::new(b_lan), None)?;
        lan.add("192.168.56.22".parse()?, Box::new(c_lan), None)?;
        drop(b);
        wait::until(&fcx, Duration::from_secs(10), || {
            b_removed.load(Ordering::SeqCst)
        })
        .await;

        // Unicast for it goes nowhere. Broadcast still reaches the rest.
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[1])));
        assert!(recv_within(&fcx, &mut c, ms(20)).await.is_none());
        a.send(Packet(v4_udp(
            [192, 168, 56, 10],
            [192, 168, 56, 255],
            &[2],
        )));
        assert_eq!(recv_soon(&fcx, &mut c).await.0[28], 2);

        // The address is free for a new member.
        let (b2_lan, mut b2) = pair();
        lan.add("192.168.56.11".parse()?, Box::new(b2_lan), None)?;
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[3])));
        assert_eq!(recv_soon(&fcx, &mut b2).await.0[28], 3);

        // The LAN ends once every member has closed and the handle is
        // gone. The run then ends, which `world` checks.
        drop(lan);
        drop((a, b2, c));
        Ok(())
    });
}

/// Wraps a cable end and logs `s` for every packet the task sends to it.
struct LoggedSend {
    inner: End,
    log: Arc<Mutex<Vec<char>>>,
}

impl Interface for LoggedSend {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        self.inner.poll_recv(fcx, cx)
    }
    fn send(&mut self, packet: Packet) {
        self.log.lock().unwrap().push('s');
        self.inner.send(packet)
    }
}

/// A broadcast to seven members is seven sends, and the LAN counts each
/// of them toward its budget, so it yields after eight broadcasts, not
/// after 64.
#[test]
fn lan_fan_out_counts_toward_the_budget() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let l = log.clone();
    world(move |fcx| async move {
        let done = Arc::new(AtomicBool::new(false));
        let lan = lan::<Box<dyn Interface>, _>(&fcx, "10.0.0.0/24".parse()?, |event| event);
        let (sender_lan, mut sender) = pair();
        lan.add("10.0.0.1".parse()?, Box::new(sender_lan), None)?;
        let mut members = Vec::new();
        for i in 0..7u8 {
            let (lan_side, far) = pair();
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10 + i));
            lan.add(
                addr,
                Box::new(LoggedSend {
                    inner: lan_side,
                    log: l.clone(),
                }),
                None,
            )?;
            members.push(far);
        }
        for i in 0..200u32 {
            sender.send(Packet(v4_udp(
                [10, 0, 0, 1],
                [10, 0, 0, 255],
                &i.to_be_bytes(),
            )));
        }
        ticker(&fcx, l.clone(), done.clone());
        for far in &mut members {
            for _ in 0..200 {
                recv_soon(&fcx, far).await;
            }
        }
        done.store(true, Ordering::SeqCst);
        drop(lan);
        drop((sender, members));
        Ok(())
    });
    let log = log.lock().unwrap();
    assert_eq!(log.iter().filter(|c| **c == 's').count(), 1400);
    let longest = longest_run(&log);
    assert!(longest <= 64, "the LAN sent {longest} packets in a row");
    assert!(longest >= 16, "the test did not load the LAN ({longest})");
}

#[test]
fn a_router_with_no_routes_and_no_handle_ends() {
    world(|fcx| async move {
        drop(router::<End>(&fcx, Vec::new()));
        Ok(())
    });
}

// -------------------------------------------------------------- yielding

/// Wraps a cable end and logs `p` for every packet the task takes from it.
struct Logged {
    inner: End,
    log: Arc<Mutex<Vec<char>>>,
}

impl Interface for Logged {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        let r = self.inner.poll_recv(fcx, cx);
        if let Poll::Ready(Ok(_)) = r {
            self.log.lock().unwrap().push('p');
        }
        r
    }
    fn send(&mut self, packet: Packet) {
        self.inner.send(packet)
    }
}

/// Starts a ticker that logs `t` once per turn of the run until `done`.
fn ticker(fcx: &Cx, log: Arc<Mutex<Vec<char>>>, done: Arc<AtomicBool>) {
    fcx.spawn(move |fcx| async move {
        while !done.load(Ordering::SeqCst) {
            log.lock().unwrap().push('t');
            fcx.yield_now().await?;
        }
        Ok(())
    });
}

/// The longest run of packets taken with no tick in between.
fn longest_run(log: &[char]) -> usize {
    log.split(|c| *c == 't').map(|s| s.len()).max().unwrap_or(0)
}

#[test]
fn each_task_yields_after_64_packets_in_a_row() {
    for which in [
        "split_versions",
        "split_protocols",
        "router",
        "delay",
        "bottleneck",
    ] {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        world(move |fcx| async move {
            let done = Arc::new(AtomicBool::new(false));
            let (mut sandbox, world_side) = pair();
            for i in 0..1000u32 {
                sandbox.send(Packet(v4_udp(A4, B4, &i.to_be_bytes())));
            }
            ticker(&fcx, l.clone(), done.clone());
            let inner = Logged {
                inner: world_side,
                log: l.clone(),
            };
            let mut out: End = match which {
                "split_versions" => ip::split_versions(&fcx, inner).0,
                "split_protocols" => ip::split_protocols(&fcx, inner).1,
                "delay" => delay(&fcx, ms(1), inner),
                "bottleneck" => bottleneck(&fcx, u64::MAX, 2000, inner),
                _ => {
                    let (out_router, out) = pair();
                    let r = router(
                        &fcx,
                        vec![
                            ("0.0.0.0/0".parse()?, Box::new(inner) as Box<dyn Interface>),
                            ("1.1.1.1/32".parse()?, Box::new(out_router)),
                        ],
                    );
                    drop(r);
                    out
                }
            };
            for _ in 0..1000 {
                recv_soon(&fcx, &mut out).await;
            }
            done.store(true, Ordering::SeqCst);
            Ok(())
        });
        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|c| **c == 'p').count(), 1000, "{which}");
        let longest = longest_run(&log);
        assert!(longest <= 64, "{which} took {longest} packets in a row");
        assert!(
            longest >= 16,
            "{which}: the test did not load the task ({longest})"
        );
    }
}

// ----------------------------------------------------------- echo reply

#[test]
fn echo_reply_v4_has_correct_checksums() {
    let addr = Ipv4Addr::new(1, 1, 1, 1);
    let mut req = Vec::new();
    PacketBuilder::ipv4(A4, addr.octets(), 64)
        .icmpv4_echo_request(0x1234, 7)
        .write(&mut req, b"abcdefghij")
        .unwrap();
    let reply = icmp::echo_reply(&Packet(req.clone()), IpAddr::V4(addr))
        .expect("a reply")
        .0;

    // IPv4 header: from the address, to the sender, checksum good.
    assert_eq!(reply[0], 0x45);
    assert_eq!(
        u16::from_be_bytes([reply[2], reply[3]]) as usize,
        reply.len()
    );
    assert_eq!(reply[9], 1);
    assert_eq!(&reply[12..16], &addr.octets());
    assert_eq!(&reply[16..20], &A4);
    assert_eq!(
        internet_checksum(&[], &reply[..20]),
        0,
        "IPv4 header checksum"
    );
    // ICMP: echo reply, same id, sequence and data, checksum good.
    let icmp = &reply[20..];
    assert_eq!(icmp[0], 0);
    assert_eq!(icmp[1], 0);
    assert_eq!(&icmp[4..], &req[24..]);
    assert_eq!(internet_checksum(&[], icmp), 0, "ICMP checksum");

    // etherparse reads it as an echo reply with the same fields.
    let parsed = etherparse::SlicedPacket::from_ip(&reply).unwrap();
    match parsed.transport {
        Some(etherparse::TransportSlice::Icmpv4(s)) => match s.icmp_type() {
            etherparse::Icmpv4Type::EchoReply(h) => {
                assert_eq!((h.id, h.seq), (0x1234, 7));
                assert_eq!(s.payload(), b"abcdefghij");
            }
            t => panic!("not an echo reply: {t:?}"),
        },
        t => panic!("not ICMPv4: {t:?}"),
    }

    // No reply to another address, to a reply, or to a bad checksum.
    assert!(
        icmp::echo_reply(&Packet(req.clone()), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))).is_none()
    );
    assert!(icmp::echo_reply(&Packet(req.clone()), IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
    assert!(icmp::echo_reply(&Packet(reply.clone()), IpAddr::V4(Ipv4Addr::from(A4))).is_none());
    let mut bad = req.clone();
    bad[30] ^= 1;
    assert!(icmp::echo_reply(&Packet(bad), IpAddr::V4(addr)).is_none());
    assert!(icmp::echo_reply(&Packet(vec![0x45; 10]), IpAddr::V4(addr)).is_none());
    assert!(icmp::echo_reply(&Packet(v4_udp(A4, addr.octets(), b"x")), IpAddr::V4(addr)).is_none());
}

#[test]
fn echo_reply_v6_has_correct_checksums() {
    let addr = Ipv6Addr::from(B6);
    let mut req = Vec::new();
    PacketBuilder::ipv6(A6, B6, 64)
        .icmpv6_echo_request(0x4321, 9)
        .write(&mut req, b"0123456789abc")
        .unwrap();
    let reply = icmp::echo_reply(&Packet(req.clone()), IpAddr::V6(addr))
        .expect("a reply")
        .0;

    assert_eq!(reply[0] >> 4, 6);
    assert_eq!(
        u16::from_be_bytes([reply[4], reply[5]]) as usize,
        reply.len() - 40
    );
    assert_eq!(reply[6], 58);
    assert_eq!(&reply[8..24], &B6);
    assert_eq!(&reply[24..40], &A6);
    let icmp = &reply[40..];
    assert_eq!(icmp[0], 129);
    assert_eq!(&icmp[4..], &req[44..]);
    // The checksum covers the pseudo-header: source, destination, length
    // and next header.
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&B6);
    pseudo.extend_from_slice(&A6);
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    assert_eq!(internet_checksum(&pseudo, icmp), 0, "ICMPv6 checksum");

    let parsed = etherparse::SlicedPacket::from_ip(&reply).unwrap();
    match parsed.transport {
        Some(etherparse::TransportSlice::Icmpv6(s)) => {
            assert!(
                s.is_checksum_valid(B6, A6),
                "etherparse says the checksum is wrong"
            );
            match s.icmp_type() {
                etherparse::Icmpv6Type::EchoReply(h) => assert_eq!((h.id, h.seq), (0x4321, 9)),
                t => panic!("not an echo reply: {t:?}"),
            }
        }
        t => panic!("not ICMPv6: {t:?}"),
    }

    let mut bad = req.clone();
    bad[50] ^= 1;
    assert!(icmp::echo_reply(&Packet(bad), IpAddr::V6(addr)).is_none());
    assert!(icmp::echo_reply(&Packet(req.clone()), IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
    assert!(icmp::echo_reply(&Packet(reply.clone()), IpAddr::V6(Ipv6Addr::from(A6))).is_none());
}

#[test]
fn a_ping_loop_answers_through_split_protocols() {
    world(|fcx| async move {
        let (mut sandbox, world_side) = pair();
        let (_tcp, _udp, mut icmp_end, _other) = ip::split_protocols(&fcx, world_side);
        let addr = IpAddr::V4(Ipv4Addr::from(B4));
        fcx.spawn(move |fcx| async move {
            while let Ok(packet) = icmp_end.recv(&fcx).await {
                if let Some(reply) = icmp::echo_reply(&packet, addr) {
                    icmp_end.send(reply);
                }
            }
            Ok(())
        });
        let mut req = Vec::new();
        PacketBuilder::ipv4(A4, B4, 64)
            .icmpv4_echo_request(1, 1)
            .write(&mut req, &[7u8; 3000])
            .unwrap();
        // A ping too big for one packet, fragmented: the reply comes back
        // whole.
        let (whole, frags) = fragment_v4(&req, &[1480, 1480]);
        for f in frags.iter().rev() {
            sandbox.send(Packet(f.clone()));
        }
        let reply = recv_soon(&fcx, &mut sandbox).await.0;
        assert_eq!(reply.len(), whole.len());
        assert_eq!(reply[20], 0);
        assert_eq!(internet_checksum(&[], &reply[20..]), 0);
        drop(sandbox);
        Ok(())
    });
}

#[test]
fn every_task_stops_when_its_region_is_cancelled() {
    // The world fails while every kind of task is running with its cables
    // still open. The run then ends with the error instead of waiting.
    let result = within(Duration::from_secs(5), || {
        block_on(run(|fcx| async move {
            let mut keep = Vec::new();
            let (a, b) = pair();
            keep.push(a);
            keep.push(delay(&fcx, ms(10), b));
            let (a, b) = pair();
            keep.push(a);
            keep.push(bottleneck(&fcx, 1000, 10, b));
            let (a, b) = pair();
            keep.push(a);
            let (x, y, z) = ip::split_versions(&fcx, b);
            keep.extend([x, y, z]);
            let (a, b) = pair();
            keep.push(a);
            let (w, x, y, z) = ip::split_protocols(&fcx, b);
            keep.extend([w, x, y, z]);
            let (a, b) = pair();
            keep.push(a);
            let r = router(
                &fcx,
                vec![("0.0.0.0/0".parse()?, Box::new(b) as Box<dyn Interface>)],
            );
            let (a, b) = pair();
            keep.push(a);
            let l = lan::<Box<dyn Interface>, _>(&fcx, "10.0.0.0/24".parse()?, |event| event);
            l.add("10.0.0.2".parse()?, Box::new(b), None)?;
            fcx.sleep(ms(20)).await?;
            let _keep = (keep, r, l);
            Err(fictionet::Error::msg("stop"))
        }))
    });
    assert_eq!(result.unwrap_err().to_string(), "stop");
}

#[test]
fn lan_drop_identity_comes_from_ingress_registration() {
    world(|fcx| async move {
        let lan = lan(&fcx, "10.0.0.0/24".parse()?, |event| {
            event.field("lan", "test")
        });
        let identity = fictionet::events::Sandbox {
            id: 17,
            name: Arc::from("member"),
            addr: Some(Ipv4Addr::new(10, 0, 0, 2)),
            addr_v6: None,
        };
        let (member, mut peer) = pair();
        lan.add("10.0.0.2".parse()?, member, Some(identity.clone()))?;
        // The packet claims another member's source address.
        peer.send(ip::packet(
            "10.0.0.3".parse()?,
            "10.0.0.99".parse()?,
            253,
            &[],
        ));
        peer.send(Packet(vec![1, 2, 3]));
        let events = fcx.events();
        let drops = events
            .wait(&fcx, 2, Duration::from_secs(10), |e| e.is("lan", "drop"))
            .await?;
        assert_eq!(drops.len(), 2);
        assert!(events.of("net", "blocked").is_empty());
        for event in &drops {
            assert_eq!(event.conn.sandbox.as_ref(), Some(&identity));
            assert_eq!(event.str("lan"), Some("test"));
            assert_eq!(event.u64("count"), Some(1));
        }
        assert_eq!(drops[0].str("src"), Some("10.0.0.3"));
        assert_eq!(drops[1].str("why"), Some("not an IP packet"));
        // Replacing the interface also replaces its registered identity.
        let (member, mut peer) = pair();
        lan.add("10.0.0.2".parse()?, member, None)?;
        peer.send(Packet(vec![1, 2, 3]));
        let drops = fcx
            .events()
            .wait(&fcx, 3, Duration::from_secs(10), |e| e.is("lan", "drop"))
            .await?;
        assert_eq!(drops.len(), 3);
        assert!(drops[2].conn.sandbox.is_none());
        Ok(())
    });
}
