//! The packet stdlib: delay, bottleneck, the IP splits with reassembly, the
//! router and echo replies. Every test wires cables made with `pair()` and
//! runs under `run()` in real time, so timing checks leave room.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use etherparse::PacketBuilder;
use fictionet::prelude::*;
use fictionet::stdlib::route::{Prefix, lan, router};
use fictionet::stdlib::{bottleneck, delay, icmp, ip};
use fictionet::time::ms;
use fictionet::{Cx, End, Interface, Packet, RecvError, block_on, pair, run};

/// Runs `f` on its own thread and fails the test if it takes longer than
/// `limit`, instead of hanging.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}

/// Runs a world to the end, within 10 seconds.
fn world<F, Fut>(f: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    within(Duration::from_secs(10), move || block_on(run(f))).unwrap();
}

/// Waits up to 1 s for a packet on `end`.
async fn recv_soon(cx: &Cx, end: &mut End) -> Packet {
    recv_within(cx, end, ms(1000)).await.expect("no packet arrived")
}

/// Waits up to `limit` for a packet. `None` if none came.
async fn recv_within(cx: &Cx, end: &mut End, limit: Duration) -> Option<Packet> {
    let deadline = cx.now() + limit;
    let mut sleep = Box::pin(cx.sleep_until(deadline));
    std::future::poll_fn(|task| {
        if let Poll::Ready(r) = end.poll_recv(cx, task) {
            return Poll::Ready(r.ok());
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

use std::future::Future;

/// A tagged packet: a byte to tell it apart, then `len - 1` filler bytes.
fn tagged(tag: u8, len: usize) -> Packet {
    let mut v = vec![0xee; len];
    v[0] = tag;
    Packet(v)
}

// ---------------------------------------------------------------- delay

#[test]
fn delay_holds_every_packet_both_ways_and_keeps_order() {
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        let mut link = delay(&cx, ms(50), world_side);

        // Ten packets sent together arrive together, 50 ms later, in order.
        let sent = cx.now();
        for i in 0..10 {
            sandbox.send(tagged(i, 100));
        }
        for i in 0..10 {
            let p = recv_soon(&cx, &mut link).await;
            assert_eq!(p.0[0], i, "order kept");
            let waited = cx.now().since_start() - sent.since_start();
            assert!(waited >= ms(50), "packet {i} came after {waited:?}");
            assert!(waited < ms(150), "packet {i} came after {waited:?}");
        }

        // The other direction too.
        let sent = cx.now();
        for i in 0..10 {
            link.send(tagged(100 + i, 100));
        }
        for i in 0..10 {
            let p = recv_soon(&cx, &mut sandbox).await;
            assert_eq!(p.0[0], 100 + i);
            let waited = cx.now().since_start() - sent.since_start();
            assert!(waited >= ms(50) && waited < ms(150), "{waited:?}");
        }

        // Packets sent apart stay apart: each is held for 50 ms from when
        // it was sent, not from when the one before it left.
        let t0 = cx.now();
        sandbox.send(tagged(1, 10));
        cx.sleep(ms(30)).await?;
        sandbox.send(tagged(2, 10));
        recv_soon(&cx, &mut link).await;
        let first = cx.now().since_start() - t0.since_start();
        recv_soon(&cx, &mut link).await;
        let second = cx.now().since_start() - t0.since_start();
        assert!(first >= ms(50) && first < ms(75), "{first:?}");
        assert!(second >= ms(80) && second < ms(105), "{second:?}");
        Ok(())
    });
}

#[test]
fn delay_ends_when_either_cable_closes() {
    world(|cx| async move {
        let (sandbox, world_side) = pair();
        let mut link = delay(&cx, ms(10), world_side);
        drop(sandbox);
        assert_eq!(link.recv(&cx).await, Err(RecvError::Closed));

        let (mut sandbox, world_side) = pair();
        let link = delay(&cx, ms(10), world_side);
        drop(link);
        assert_eq!(sandbox.recv(&cx).await, Err(RecvError::Closed));
        Ok(())
    });
}

// ----------------------------------------------------------- bottleneck

#[test]
fn bottleneck_sends_at_the_rate() {
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        // 1 Mbit/s: a 1,250-byte packet takes 10 ms.
        let mut link = bottleneck(&cx, 1_000_000, 100, world_side);
        let t0 = cx.now();
        for i in 0..20 {
            sandbox.send(tagged(i, 1250));
        }
        let mut times = Vec::new();
        for i in 0..20 {
            let p = recv_soon(&cx, &mut link).await;
            assert_eq!(p.0[0], i);
            times.push(cx.now().since_start() - t0.since_start());
        }
        assert!(times[0] >= ms(10), "first after {:?}", times[0]);
        assert!(times[19] >= ms(200), "last after {:?}", times[19]);
        assert!(times[19] < ms(300), "last after {:?}", times[19]);
        // Each packet leaves at least 10 ms after the one before, so they
        // are spread out, not sent in a lump.
        assert!(times[9] >= ms(100) && times[9] < ms(200), "tenth after {:?}", times[9]);

        // The other direction has its own rate and queue.
        let t0 = cx.now();
        for i in 0..5 {
            link.send(tagged(i, 1250));
        }
        for i in 0..5 {
            assert_eq!(recv_soon(&cx, &mut sandbox).await.0[0], i);
        }
        let took = cx.now().since_start() - t0.since_start();
        assert!(took >= ms(50) && took < ms(150), "{took:?}");
        Ok(())
    });
}

#[test]
fn bottleneck_queue_of_ten_drops_the_eleventh_of_a_burst() {
    world(|cx| async move {
        for direction in 0..2 {
            let (mut sandbox, world_side) = pair();
            let mut link = bottleneck(&cx, 1_000_000, 10, world_side);
            let (from, to) = if direction == 0 { (&mut sandbox, &mut link) } else { (&mut link, &mut sandbox) };
            for i in 0..11 {
                from.send(tagged(i, 1250));
            }
            for i in 0..10 {
                assert_eq!(recv_soon(&cx, to).await.0[0], i);
            }
            assert!(recv_within(&cx, to, ms(100)).await.is_none(), "the 11th was not dropped");

            // Once the queue has drained, packets pass again.
            from.send(tagged(42, 1250));
            assert_eq!(recv_soon(&cx, to).await.0[0], 42);
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
const B6: [u8; 16] = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11];

#[test]
fn split_versions_sorts_by_version_and_merges_back() {
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        let (mut v4, mut v6, mut other) = ip::split_versions(&cx, world_side);
        let p4 = v4_udp(A4, B4, b"four");
        let p6 = v6_udp(A6, B6, b"six");
        sandbox.send(Packet(p4.clone()));
        sandbox.send(Packet(p6.clone()));
        sandbox.send(Packet(vec![]));
        sandbox.send(Packet(vec![0x50, 1, 2]));
        assert_eq!(recv_soon(&cx, &mut v4).await.0, p4);
        assert_eq!(recv_soon(&cx, &mut v6).await.0, p6);
        assert_eq!(recv_soon(&cx, &mut other).await.0, Vec::<u8>::new());
        assert_eq!(recv_soon(&cx, &mut other).await.0, vec![0x50, 1, 2]);

        // Packets sent into any end go out on the cable being split.
        v6.send(Packet(p6.clone()));
        other.send(Packet(vec![9]));
        v4.send(Packet(p4.clone()));
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(recv_soon(&cx, &mut sandbox).await.0);
        }
        got.sort();
        let mut want = vec![p6, vec![9], p4];
        want.sort();
        assert_eq!(got, want);

        // Closing the split cable closes all three ends.
        drop(sandbox);
        assert_eq!(v4.recv(&cx).await, Err(RecvError::Closed));
        assert_eq!(v6.recv(&cx).await, Err(RecvError::Closed));
        assert_eq!(other.recv(&cx).await, Err(RecvError::Closed));
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
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        let (mut tcp, mut udp, mut icmp_end, mut other) = ip::split_protocols(&cx, world_side);

        let tcp4 = v4_tcp(A4, B4, b"hello");
        let udp4 = v4_udp(A4, B4, b"query");
        let tcp6 = v6_tcp(A6, B6, b"hello");
        let udp6 = v6_udp(A6, B6, b"query");
        let mut ping4 = Vec::new();
        PacketBuilder::ipv4(A4, B4, 64).icmpv4_echo_request(1, 1).write(&mut ping4, b"ping").unwrap();
        let mut ping6 = Vec::new();
        PacketBuilder::ipv6(A6, B6, 64).icmpv6_echo_request(1, 1).write(&mut ping6, b"ping").unwrap();
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

        for p in [&tcp4, &udp4, &tcp6, &udp6, &ping4, &ping6, &gre, &hbh, &port_unreachable, &frag_needed, &too_big, &unreachable6, &about_ping] {
            sandbox.send(Packet(p.clone()));
        }
        assert_eq!(recv_soon(&cx, &mut tcp).await.0, tcp4);
        assert_eq!(recv_soon(&cx, &mut tcp).await.0, tcp6);
        assert_eq!(recv_soon(&cx, &mut tcp).await.0, frag_needed);
        assert_eq!(recv_soon(&cx, &mut tcp).await.0, too_big);
        assert_eq!(recv_soon(&cx, &mut udp).await.0, udp4);
        assert_eq!(recv_soon(&cx, &mut udp).await.0, udp6);
        // The hop-by-hop header asks nothing of the host, and is taken out.
        assert_eq!(recv_soon(&cx, &mut udp).await.0, udp6);
        assert_eq!(recv_soon(&cx, &mut udp).await.0, port_unreachable);
        assert_eq!(recv_soon(&cx, &mut udp).await.0, unreachable6);
        assert_eq!(recv_soon(&cx, &mut icmp_end).await.0, ping4);
        assert_eq!(recv_soon(&cx, &mut icmp_end).await.0, ping6);
        assert_eq!(recv_soon(&cx, &mut icmp_end).await.0, about_ping);
        assert_eq!(recv_soon(&cx, &mut other).await.0, gre);
        for end in [&mut tcp, &mut udp, &mut icmp_end, &mut other] {
            assert!(recv_within(&cx, end, ms(30)).await.is_none(), "an extra packet");
        }

        // Everything sent into the ends goes out on the split cable.
        tcp.send(Packet(tcp4.clone()));
        udp.send(Packet(udp4.clone()));
        icmp_end.send(Packet(ping4.clone()));
        other.send(Packet(gre.clone()));
        for _ in 0..4 {
            recv_soon(&cx, &mut sandbox).await;
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
            let lo = if i + 1 < bytes.len() { bytes[i + 1] as u32 } else { 0 };
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
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        let (_tcp, mut udp, _icmp, mut other) = ip::split_protocols(&cx, world_side);

        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let (whole, frags) = fragment_v4(&v4_udp(A4, B4, &payload), &[1480, 1480]);
        assert_eq!(frags.len(), 3);
        // Last, first, middle. Only the first names UDP's port numbers.
        for i in [2, 0, 1] {
            sandbox.send(Packet(frags[i].clone()));
        }
        let got = recv_soon(&cx, &mut udp).await.0;
        assert_eq!(got, whole);
        assert_eq!(internet_checksum(&[], &got[..20]), 0, "header checksum");

        // IPv6, middle first.
        let whole6 = v6_udp(A6, B6, &payload);
        let frags6 = fragment_v6(&whole6, &[1232, 1232], 77);
        for i in [1, 2, 0] {
            sandbox.send(Packet(frags6[i].clone()));
        }
        assert_eq!(recv_soon(&cx, &mut udp).await.0, whole6);

        // Two packets whose fragments arrive interleaved.
        let (whole_a, frags_a) = fragment_v4(&v4_udp(A4, B4, &payload[..1000]), &[504]);
        let mut other_id = v4_udp(A4, B4, &payload[..1200]);
        other_id[5] ^= 0x55; // a different identification
        let (whole_b, frags_b) = fragment_v4(&other_id, &[400, 400]);
        for f in [&frags_b[2], &frags_a[1], &frags_b[0], &frags_a[0], &frags_b[1]] {
            sandbox.send(Packet(f.clone()));
        }
        assert_eq!(recv_soon(&cx, &mut udp).await.0, whole_a);
        assert_eq!(recv_soon(&cx, &mut udp).await.0, whole_b);

        // Overlapping fragments drop the whole packet.
        let mut bad_id = v4_udp(A4, B4, &payload[..1600]);
        bad_id[5] ^= 0x33;
        let (_, frags_c) = fragment_v4(&bad_id, &[800]);
        let (_, overlap) = fragment_v4(&bad_id, &[400, 800]);
        sandbox.send(Packet(frags_c[0].clone()));
        sandbox.send(Packet(overlap[1].clone())); // bytes 400..1200 overlap 0..800
        sandbox.send(Packet(frags_c[1].clone()));
        assert!(recv_within(&cx, &mut udp, ms(50)).await.is_none(), "overlapping fragments were joined");
        assert!(recv_within(&cx, &mut other, ms(10)).await.is_none());

        // A packet in one fragment (an atomic fragment) passes at once.
        let atomic = fragment_v6(&whole6, &[], 5);
        assert_eq!(atomic.len(), 1);
        sandbox.send(Packet(atomic[0].clone()));
        assert_eq!(recv_soon(&cx, &mut udp).await.0, whole6);
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
    assert_eq!(p, Prefix { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), len: 8 });
    let p: Prefix = "::/0".parse().unwrap();
    assert_eq!(p, Prefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), len: 0 });
    let p: Prefix = "10.1.2.3/8".parse().unwrap();
    assert_eq!(p.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    let p: Prefix = "1.1.1.1".parse().unwrap();
    assert_eq!(p.len, 32);
    let p: Prefix = "fd00::1/64".parse().unwrap();
    assert_eq!(p.addr, "fd00::".parse::<IpAddr>().unwrap());
    for bad in ["", "10.0.0.0/33", "::/129", "10.0.0.0/", "10.0.0.0/x", "10.0.0/8", "10.0.0.0/-1", "10.0.0.0/+8"] {
        assert!(bad.parse::<Prefix>().is_err(), "{bad:?} parsed");
    }
}

#[test]
fn router_longest_prefix_add_replace_and_removal_on_close() {
    world(|cx| async move {
        let (a_router, mut a) = pair();
        let (b_router, mut b) = pair();
        let (c_router, mut c) = pair();
        let (d_router, mut d) = pair();
        let routes: Vec<(Prefix, Box<dyn Interface>)> = vec![
            ("10.0.0.0/8".parse()?, Box::new(a_router)),
            ("10.1.0.0/16".parse()?, Box::new(b_router)),
            ("0.0.0.0/0".parse()?, Box::new(c_router)),
            ("::/0".parse()?, Box::new(d_router)),
        ];
        let r = router(&cx, routes);

        // Longest prefix wins, from any cable.
        c.send(to4([10, 1, 2, 3], 1));
        assert_eq!(recv_soon(&cx, &mut b).await.0, v4_udp(A4, [10, 1, 2, 3], &[1]));
        c.send(to4([10, 2, 0, 1], 2));
        assert_eq!(recv_soon(&cx, &mut a).await.0, v4_udp(A4, [10, 2, 0, 1], &[2]));
        a.send(to4([8, 8, 8, 8], 3));
        assert_eq!(recv_soon(&cx, &mut c).await.0[28], 3);
        // Back out the cable it came in on, when that is the best route.
        c.send(to4([9, 9, 9, 9], 4));
        assert_eq!(recv_soon(&cx, &mut c).await.0[28], 4);
        // IPv6 matches IPv6 prefixes only.
        a.send(Packet(v6_udp(A6, B6, &[5])));
        assert_eq!(recv_soon(&cx, &mut d).await.0[48], 5);
        // Junk is dropped.
        a.send(Packet(vec![0x45, 0]));
        a.send(Packet(vec![]));

        // Add a longer prefix.
        let (e_router, mut e) = pair();
        r.add("10.1.2.0/24".parse()?, Box::new(e_router));
        c.send(to4([10, 1, 2, 3], 6));
        assert_eq!(recv_soon(&cx, &mut e).await.0[28], 6);
        c.send(to4([10, 1, 3, 3], 7));
        assert_eq!(recv_soon(&cx, &mut b).await.0[28], 7);

        // Replace 10.1.0.0/16: the old cable is dropped.
        let (f_router, mut f) = pair();
        r.add("10.1.0.0/16".parse()?, Box::new(f_router));
        assert_eq!(b.recv(&cx).await, Err(RecvError::Closed));
        c.send(to4([10, 1, 3, 3], 8));
        assert_eq!(recv_soon(&cx, &mut f).await.0[28], 8);

        // A closed cable loses its route: the next best one takes over.
        drop(e);
        cx.sleep(ms(20)).await?;
        c.send(to4([10, 1, 2, 3], 9));
        assert_eq!(recv_soon(&cx, &mut f).await.0[28], 9);
        // And with no route left for an address, packets are dropped.
        drop(c);
        cx.sleep(ms(20)).await?;
        a.send(to4([8, 8, 8, 8], 10));
        for end in [&mut a, &mut d, &mut f] {
            assert!(recv_within(&cx, end, ms(30)).await.is_none());
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
    world(|cx| async move {
        let (a_router, a) = pair();
        let r = router(&cx, vec![("10.0.0.0/8".parse()?, Box::new(a_router) as Box<dyn Interface>)]);
        drop(a);
        cx.sleep(ms(20)).await?;
        // Every cable is closed, but the handle is alive: a new route works.
        let (b_router, mut b) = pair();
        let (c_router, mut c) = pair();
        r.add("10.0.0.0/8".parse()?, Box::new(b_router));
        r.add("0.0.0.0/0".parse()?, Box::new(c_router));
        c.send(to4([10, 0, 0, 1], 1));
        assert_eq!(recv_soon(&cx, &mut b).await.0[28], 1);
        drop(r);
        drop((b, c));
        Ok(())
    });
}

#[test]
fn lan_forwards_unicast_and_floods_ip_group_traffic() {
    world(|cx| async move {
        let network: Prefix = "192.168.56.0/24".parse()?;
        let lan = lan(&cx, network);
        let (a_lan, mut a) = pair();
        let (b_lan, mut b) = pair();
        let (c_lan, mut c) = pair();
        lan.add("192.168.56.10".parse()?, Box::new(a_lan))?;
        lan.add("192.168.56.11".parse()?, Box::new(b_lan))?;
        lan.add("192.168.56.22".parse()?, Box::new(c_lan))?;

        // Unicast goes only to the member that owns the destination.
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[1])));
        assert_eq!(recv_soon(&cx, &mut b).await.0[28], 1);
        assert!(recv_within(&cx, &mut c, ms(20)).await.is_none());

        // The subnet broadcast, limited broadcast and multicast are copied
        // to every member except the sender.
        for (dst, tag) in [
            ([192, 168, 56, 255], 2),
            ([255, 255, 255, 255], 3),
            ([224, 0, 0, 252], 4),
        ] {
            a.send(Packet(v4_udp([192, 168, 56, 10], dst, &[tag])));
            assert_eq!(recv_soon(&cx, &mut b).await.0[28], tag);
            assert_eq!(recv_soon(&cx, &mut c).await.0[28], tag);
            assert!(recv_within(&cx, &mut a, ms(20)).await.is_none());
        }

        // Reconnecting an address replaces the old member.
        let (new_b_lan, mut new_b) = pair();
        lan.add("192.168.56.11".parse()?, Box::new(new_b_lan))?;
        assert_eq!(b.recv(&cx).await, Err(RecvError::Closed));
        a.send(Packet(v4_udp([192, 168, 56, 10], [192, 168, 56, 11], &[5])));
        assert_eq!(recv_soon(&cx, &mut new_b).await.0[28], 5);

        let (outside_lan, _outside) = pair();
        assert!(lan.add("192.168.57.1".parse()?, Box::new(outside_lan)).is_err());

        drop(lan);
        drop((a, b, c, new_b));
        Ok(())
    });
}

#[test]
fn a_router_with_no_routes_and_no_handle_ends() {
    world(|cx| async move {
        drop(router(&cx, Vec::new()));
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
    fn poll_recv(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        let r = self.inner.poll_recv(cx, task);
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
fn ticker(cx: &Cx, log: Arc<Mutex<Vec<char>>>, done: Arc<AtomicBool>) {
    cx.spawn(move |cx| async move {
        while !done.load(Ordering::SeqCst) {
            log.lock().unwrap().push('t');
            cx.yield_now().await?;
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
    for which in ["split_versions", "split_protocols", "router", "delay", "bottleneck"] {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        world(move |cx| async move {
            let done = Arc::new(AtomicBool::new(false));
            let (mut sandbox, world_side) = pair();
            for i in 0..1000u32 {
                sandbox.send(Packet(v4_udp(A4, B4, &i.to_be_bytes())));
            }
            ticker(&cx, l.clone(), done.clone());
            let inner = Logged { inner: world_side, log: l.clone() };
            let mut out: End = match which {
                "split_versions" => ip::split_versions(&cx, inner).0,
                "split_protocols" => ip::split_protocols(&cx, inner).1,
                "delay" => delay(&cx, ms(1), inner),
                "bottleneck" => bottleneck(&cx, u64::MAX, 2000, inner),
                _ => {
                    let (out_router, out) = pair();
                    let r = router(&cx, vec![
                        ("0.0.0.0/0".parse()?, Box::new(inner) as Box<dyn Interface>),
                        ("1.1.1.1/32".parse()?, Box::new(out_router)),
                    ]);
                    drop(r);
                    out
                }
            };
            for _ in 0..1000 {
                recv_soon(&cx, &mut out).await;
            }
            done.store(true, Ordering::SeqCst);
            Ok(())
        });
        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|c| **c == 'p').count(), 1000, "{which}");
        let longest = longest_run(&log);
        assert!(longest <= 64, "{which} took {longest} packets in a row");
        assert!(longest >= 16, "{which}: the test did not load the task ({longest})");
    }
}

// ----------------------------------------------------------- echo reply

#[test]
fn echo_reply_v4_has_correct_checksums() {
    let addr = Ipv4Addr::new(1, 1, 1, 1);
    let mut req = Vec::new();
    PacketBuilder::ipv4(A4, addr.octets(), 64).icmpv4_echo_request(0x1234, 7).write(&mut req, b"abcdefghij").unwrap();
    let reply = icmp::echo_reply(&Packet(req.clone()), IpAddr::V4(addr)).expect("a reply").0;

    // IPv4 header: from the address, to the sender, checksum good.
    assert_eq!(reply[0], 0x45);
    assert_eq!(u16::from_be_bytes([reply[2], reply[3]]) as usize, reply.len());
    assert_eq!(reply[9], 1);
    assert_eq!(&reply[12..16], &addr.octets());
    assert_eq!(&reply[16..20], &A4);
    assert_eq!(internet_checksum(&[], &reply[..20]), 0, "IPv4 header checksum");
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
    assert!(icmp::echo_reply(&Packet(req.clone()), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))).is_none());
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
    PacketBuilder::ipv6(A6, B6, 64).icmpv6_echo_request(0x4321, 9).write(&mut req, b"0123456789abc").unwrap();
    let reply = icmp::echo_reply(&Packet(req.clone()), IpAddr::V6(addr)).expect("a reply").0;

    assert_eq!(reply[0] >> 4, 6);
    assert_eq!(u16::from_be_bytes([reply[4], reply[5]]) as usize, reply.len() - 40);
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
            assert!(s.is_checksum_valid(B6, A6), "etherparse says the checksum is wrong");
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
    world(|cx| async move {
        let (mut sandbox, world_side) = pair();
        let (_tcp, _udp, mut icmp_end, _other) = ip::split_protocols(&cx, world_side);
        let addr = IpAddr::V4(Ipv4Addr::from(B4));
        cx.spawn(move |cx| async move {
            while let Ok(packet) = icmp_end.recv(&cx).await {
                if let Some(reply) = icmp::echo_reply(&packet, addr) {
                    icmp_end.send(reply);
                }
            }
            Ok(())
        });
        let mut req = Vec::new();
        PacketBuilder::ipv4(A4, B4, 64).icmpv4_echo_request(1, 1).write(&mut req, &[7u8; 3000]).unwrap();
        // A ping too big for one packet, fragmented: the reply comes back
        // whole.
        let (whole, frags) = fragment_v4(&req, &[1480, 1480]);
        for f in frags.iter().rev() {
            sandbox.send(Packet(f.clone()));
        }
        let reply = recv_soon(&cx, &mut sandbox).await.0;
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
        block_on(run(|cx| async move {
            let mut keep = Vec::new();
            let (a, b) = pair();
            keep.push(a);
            keep.push(delay(&cx, ms(10), b));
            let (a, b) = pair();
            keep.push(a);
            keep.push(bottleneck(&cx, 1000, 10, b));
            let (a, b) = pair();
            keep.push(a);
            let (x, y, z) = ip::split_versions(&cx, b);
            keep.extend([x, y, z]);
            let (a, b) = pair();
            keep.push(a);
            let (w, x, y, z) = ip::split_protocols(&cx, b);
            keep.extend([w, x, y, z]);
            let (a, b) = pair();
            keep.push(a);
            let r = router(&cx, vec![("0.0.0.0/0".parse()?, Box::new(b) as Box<dyn Interface>)]);
            cx.sleep(ms(20)).await?;
            let _keep = (keep, r);
            Err("stop".into())
        }))
    });
    assert_eq!(result.unwrap_err().to_string(), "stop");
}
