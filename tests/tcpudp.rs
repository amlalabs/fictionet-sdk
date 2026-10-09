//! TCP and UDP endpoints, two machines joined by a `pair()` cable.

mod common;
#[path = "common/done.rs"]
mod done;
#[path = "common/world.rs"]
mod world;

use done::Done;
use world::world;

use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use fictionet::prelude::*;
use fictionet::stdlib::ip::{
    Fields, checksum, destination, packet_with, source, transport_checksum,
};
use fictionet::stdlib::test_support::thread_cpu_time;
use fictionet::stdlib::{ConnError, Connection, tcp, udp};
use fictionet::{Cx, Interface, Packet, RecvError, pair, run};

const A: &str = "10.0.0.1";
const B: &str = "10.0.0.2";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Two TCP machines on one cable.
fn two_tcp(fcx: &Cx, a: &str, b: &str) -> (tcp::Endpoint, tcp::Endpoint) {
    let (ca, cb) = pair();
    (tcp::endpoint(fcx, ca, ip(a)), tcp::endpoint(fcx, cb, ip(b)))
}

async fn read_to_end(fcx: &Cx, conn: &mut impl Connection) -> Result<Vec<u8>, ConnError> {
    let mut out = Vec::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Sends `data` and reads until EOF at the same time, on one connection.
/// Shuts down after the last byte. Returns what it read.
async fn duplex(fcx: &Cx, conn: &mut impl Connection, data: &[u8]) -> Result<Vec<u8>, ConnError> {
    let mut sent = 0;
    let mut shut = false;
    let mut got = Vec::new();
    let mut eof = false;
    let mut buf = vec![0; 64 * 1024];
    poll_fn(|cx| {
        loop {
            let mut progress = false;
            if sent < data.len() {
                match conn.poll_write(fcx, cx, &data[sent..]) {
                    Poll::Ready(Ok(n)) => {
                        assert!(n > 0, "poll_write must never return Ok(0)");
                        sent += n;
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            } else if !shut {
                match conn.poll_shutdown(fcx, cx) {
                    Poll::Ready(Ok(())) => {
                        shut = true;
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            if !eof {
                match conn.poll_read(fcx, cx, &mut buf) {
                    Poll::Ready(Ok(0)) => {
                        eof = true;
                        progress = true;
                    }
                    Poll::Ready(Ok(n)) => {
                        got.extend_from_slice(&buf[..n]);
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            if eof && shut {
                return Poll::Ready(Ok(std::mem::take(&mut got)));
            }
            if !progress {
                return Poll::Pending;
            }
        }
    })
    .await
}

#[path = "common/pattern.rs"]
mod payload;
use payload::pattern;

#[test]
fn connect_accept_echo_and_addresses() {
    for (a, b) in [(A, B), ("fd00::1", "fd00::2")] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (ea, eb) = two_tcp(&fcx, a, b);
            assert_eq!(ea.addr(), ip(a));
            let mut listener = eb.listen(80)?;
            assert!(eb.listen(80).is_err(), "a second listener on the same port");
            let server = fcx.spawn(move |fcx| async move {
                let mut conn = listener.accept(&fcx).await?;
                assert_eq!(conn.local_addr(), SocketAddr::new(ip(b), 80));
                assert_eq!(conn.peer_addr().ip(), ip(a));
                let data = read_to_end(&fcx, &mut conn).await?;
                conn.write_all(&fcx, &data).await?;
                conn.shutdown(&fcx).await?;
                Ok(())
            });
            let mut conn = ea.connect(&fcx, SocketAddr::new(ip(b), 80)).await?;
            assert_eq!(conn.peer_addr(), SocketAddr::new(ip(b), 80));
            assert_eq!(conn.local_addr().ip(), ip(a));
            assert!(conn.local_addr().port() >= 49152);
            conn.write_all(&fcx, b"hello, world").await?;
            conn.shutdown(&fcx).await?;
            assert_eq!(read_to_end(&fcx, &mut conn).await?, b"hello, world");
            server.join(&fcx).await?;
            Ok(())
        });
    }
}

#[test]
fn ten_megabytes_both_ways() {
    const LEN: usize = 10 * 1024 * 1024;
    let elapsed = Arc::new(Mutex::new(Duration::ZERO));
    let e = elapsed.clone();
    world::real_world(Duration::from_secs(120), move |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(9000)?;
        let up = pattern(LEN, 1);
        let down = pattern(LEN, 2);
        let (up2, down2) = (up.clone(), down.clone());
        let started = Instant::now();
        let server = fcx.spawn(move |fcx| async move {
            let mut conn = listener.accept(&fcx).await?;
            let got = duplex(&fcx, &mut conn, &down2).await?;
            assert!(got == up2, "the server got different bytes");
            Ok(())
        });
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 9000)).await?;
        let got = duplex(&fcx, &mut conn, &up).await?;
        assert!(got == down, "the client got different bytes");
        server.join(&fcx).await?;
        *e.lock().unwrap() = started.elapsed();
        Ok(())
    });
    let t = *elapsed.lock().unwrap();
    let mbps = 2.0 * LEN as f64 * 8.0 / t.as_secs_f64() / 1e6;
    eprintln!("10 MiB each way in {t:?}: {mbps:.0} Mbit/s in total");
}

#[test]
fn a_closed_port_refuses_at_once() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let _open = eb.listen(80)?;
        assert_eq!(
            ea.connect(&fcx, SocketAddr::new(ip(B), 22)).await.err(),
            Some(ConnError::Refused)
        );
        // Time the machine's answer alone: a SYN in, the RST out.
        let (mut raw, b) = pair();
        let _eb = tcp::endpoint(&fcx, b, ip(B));
        let mut times = Vec::new();
        for port in 1..=200u16 {
            let started = fcx.now();
            raw.send(tcp_syn(ip(A), 40000 + port, ip(B), port));
            let p = raw.recv(&fcx).await?;
            times.push(fcx.now().since_start() - started.since_start());
            assert_eq!(p.0[20 + 13] & 0x04, 0x04, "a RST for port {port}");
        }
        times.sort();
        let (median, max) = (times[times.len() / 2], times[times.len() - 1]);
        assert_eq!((median, max), (Duration::ZERO, Duration::ZERO));
        Ok(())
    });
}

#[test]
fn five_hundred_closed_ports_are_refused() {
    world(Duration::from_secs(20), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let _open = eb.listen(80)?;
        let started = fcx.now();
        for port in 1000..1500 {
            let r = ea.connect(&fcx, SocketAddr::new(ip(B), port)).await;
            assert_eq!(r.err(), Some(ConnError::Refused), "port {port}");
        }
        let t = fcx.now().since_start() - started.since_start();
        assert_eq!(t, Duration::ZERO);
        // The open port still works.
        let conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        drop(conn);
        Ok(())
    });
}

#[test]
fn two_hundred_concurrent_connections() {
    world(Duration::from_secs(60), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(7)?;
        fcx.spawn(move |fcx| async move {
            loop {
                let mut conn = match listener.accept(&fcx).await {
                    Ok(c) => c,
                    Err(ConnError::Cancelled) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                fcx.spawn(move |fcx| async move {
                    let data = read_to_end(&fcx, &mut conn).await?;
                    conn.write_all(&fcx, &data).await?;
                    conn.shutdown(&fcx).await?;
                    Ok(())
                });
            }
        });
        let started = fcx.now();
        let mut clients = Vec::new();
        for i in 0..200u64 {
            let ea = ea.clone();
            clients.push(fcx.spawn(move |fcx| async move {
                let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 7)).await?;
                let data = pattern(20_000 + i as usize * 100, i + 10);
                let got = duplex(&fcx, &mut conn, &data).await?;
                assert!(got == data, "connection {i} got different bytes");
                Ok(())
            }));
        }
        for c in clients {
            c.join(&fcx).await?;
        }
        eprintln!(
            "200 concurrent echoes took {:?}",
            (fcx.now().since_start() - started.since_start())
        );
        Ok(())
    });
}

#[test]
fn shutdown_half_closes() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        let server = fcx.spawn(move |fcx| async move {
            let mut conn = listener.accept(&fcx).await?;
            // The client's FIN: everything, then EOF, and EOF again.
            assert_eq!(read_to_end(&fcx, &mut conn).await?, b"request");
            let mut buf = [0; 16];
            assert_eq!(conn.read(&fcx, &mut buf).await?, 0);
            // This side can still send after the peer's FIN.
            conn.write_all(&fcx, b"response").await?;
            conn.shutdown(&fcx).await?;
            // Writing after shutdown fails.
            assert_eq!(conn.write(&fcx, b"x").await.err(), Some(ConnError::Closed));
            Ok(())
        });
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        // An empty write takes nothing and does not wait.
        assert_eq!(conn.write(&fcx, b"").await?, 0);
        conn.write_all(&fcx, b"request").await?;
        conn.shutdown(&fcx).await?;
        assert_eq!(
            conn.write(&fcx, b"more").await.err(),
            Some(ConnError::Closed)
        );
        // Shutting down twice is fine.
        conn.shutdown(&fcx).await?;
        // Reading still works after this side's shutdown.
        assert_eq!(read_to_end(&fcx, &mut conn).await?, b"response");
        server.join(&fcx).await?;
        Ok(())
    });
}

#[test]
fn write_waits_for_room_and_never_takes_zero() {
    world(Duration::from_secs(20), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        // The server does not read, so the client fills the window and its
        // own buffer, then waits.
        let mut written = 0usize;
        let data = vec![7u8; 64 * 1024];
        loop {
            let r = poll_fn(|cx| match conn.poll_write(&fcx, cx, &data) {
                Poll::Pending => Poll::Ready(None),
                Poll::Ready(r) => Poll::Ready(Some(r)),
            })
            .await;
            match r {
                Some(Ok(n)) => {
                    assert!(n > 0);
                    written += n;
                }
                Some(Err(e)) => return Err(e.into()),
                None => {
                    // Let the endpoints move what they can, then try once more.
                    fcx.sleep(Duration::from_millis(20)).await?;
                    let again = poll_fn(|cx| Poll::Ready(conn.poll_write(&fcx, cx, &data))).await;
                    if again.is_pending() {
                        break;
                    }
                    if let Poll::Ready(Ok(n)) = again {
                        written += n;
                    }
                }
            }
            assert!(written < 10 * 1024 * 1024, "writes never waited");
        }
        assert!(written >= 256 * 1024, "only {written} bytes fit");
        // Reading on the server makes room, and write_all finishes.
        let reader = fcx.spawn(move |fcx| async move {
            let got = read_to_end(&fcx, &mut server).await?;
            assert_eq!(got.len(), written + 100_000);
            Ok(())
        });
        conn.write_all(&fcx, &vec![1u8; 100_000]).await?;
        conn.shutdown(&fcx).await?;
        reader.join(&fcx).await?;
        Ok(())
    });
}

#[test]
fn reset_reaches_reads_and_writes() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        conn.write_all(&fcx, b"never read").await?;
        let mut first = [0];
        assert_eq!(server.read(&fcx, &mut first).await?, 1);
        assert_eq!(first, [b'n']);
        // Dropping a connection with unread bytes resets it.
        drop(server);
        let mut buf = [0; 16];
        assert_eq!(
            conn.read(&fcx, &mut buf).await.err(),
            Some(ConnError::Reset)
        );
        assert_eq!(conn.write(&fcx, b"x").await.err(), Some(ConnError::Reset));
        assert_eq!(conn.shutdown(&fcx).await.err(), Some(ConnError::Reset));
        Ok(())
    });
}

#[test]
fn dropping_a_connection_sends_fin() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        server.write_all(&fcx, b"bye").await?;
        drop(server);
        assert_eq!(read_to_end(&fcx, &mut conn).await?, b"bye");
        Ok(())
    });
}

#[test]
fn dropping_a_listener_frees_the_port_and_refuses() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let listener = eb.listen(80)?;
        drop(listener);
        let r = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await;
        assert_eq!(r.err(), Some(ConnError::Refused));
        let _again = eb.listen(80)?;
        Ok(())
    });
}

#[test]
fn connect_checks_its_target() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, _eb) = two_tcp(&fcx, A, B);
        assert_eq!(
            ea.connect(&fcx, "[fd00::2]:80".parse().unwrap())
                .await
                .err(),
            Some(ConnError::Refused)
        );
        assert_eq!(
            ea.connect(&fcx, SocketAddr::new(ip(B), 0)).await.err(),
            Some(ConnError::Refused)
        );
        Ok(())
    });
}

#[test]
fn cancellation_ends_accept_read_write_and_connect() {
    let results = Arc::new(Mutex::new(Vec::new()));
    let r = results.clone();
    world(Duration::from_secs(10), move |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        // One connection where nothing is sent, so the server's read waits,
        // and one where the server never reads, so the client's write waits.
        let _quiet = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let _not_reading = listener.accept(&fcx).await?;
        let r1 = r.clone();
        fcx.spawn(move |fcx| async move {
            let res = listener.accept(&fcx).await.err();
            r1.lock().unwrap().push(("accept", res));
            Ok(())
        });
        let r2 = r.clone();
        fcx.spawn(move |fcx| async move {
            let mut buf = [0; 8];
            let res = server.read(&fcx, &mut buf).await.err();
            r2.lock().unwrap().push(("read", res));
            Ok(())
        });
        let r3 = r.clone();
        fcx.spawn(move |fcx| async move {
            // Fills the window, since the server never reads, then waits.
            let res = conn.write_all(&fcx, &vec![0; 4 * 1024 * 1024]).await.err();
            r3.lock().unwrap().push(("write", res));
            Ok(())
        });
        // A machine that never answers, so connect waits.
        let (silent, _keep) = pair();
        let ec = tcp::endpoint(&fcx, silent, ip("10.0.0.3"));
        let r4 = r.clone();
        fcx.spawn(move |fcx| async move {
            let res = ec.connect(&fcx, SocketAddr::new(ip(B), 80)).await.err();
            r4.lock().unwrap().push(("connect", res));
            Ok(())
        });
        fcx.sleep(Duration::from_millis(100)).await?;
        assert!(
            r.lock().unwrap().is_empty(),
            "nothing should have ended yet: {:?}",
            r.lock().unwrap()
        );
        Ok(())
    });
    let mut got = results.lock().unwrap().clone();
    got.sort_by_key(|(name, _)| *name);
    assert_eq!(
        got,
        [
            ("accept", Some(ConnError::Cancelled)),
            ("connect", Some(ConnError::Cancelled)),
            ("read", Some(ConnError::Cancelled)),
            ("write", Some(ConnError::Cancelled)),
        ]
    );
}

#[test]
fn a_closed_cable_stops_the_endpoint() {
    world(Duration::from_secs(10), |fcx| async move {
        let (a, b) = pair();
        let (c, d) = pair();
        let ea = tcp::endpoint(&fcx, a, ip(A));
        // Relay b <-> c by hand, so the test can cut the cable.
        let relay = fcx.spawn(move |fcx| async move {
            let (mut b, mut c) = (b, c);
            loop {
                let p = poll_fn(|cx| {
                    if let Poll::Ready(r) = b.poll_recv(&fcx, cx) {
                        return Poll::Ready(r.map(|p| (true, p)));
                    }
                    c.poll_recv(&fcx, cx).map(|r| r.map(|p| (false, p)))
                })
                .await;
                match p {
                    Ok((true, p)) => c.send(p),
                    Ok((false, p)) => b.send(p),
                    Err(_) => return Ok(()),
                }
                if cut_now() {
                    return Ok(());
                }
            }
        });
        let eb = tcp::endpoint(&fcx, d, ip(B));
        let mut listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        CUT.store(true, std::sync::atomic::Ordering::SeqCst);
        // One more packet makes the relay notice and drop both cables.
        conn.write_all(&fcx, b"x").await?;
        relay.join(&fcx).await?;
        assert_eq!(listener.accept(&fcx).await.err(), Some(ConnError::Closed));
        let mut buf = [0; 8];
        assert_eq!(
            server.read(&fcx, &mut buf).await.err(),
            Some(ConnError::Closed)
        );
        assert_eq!(
            conn.read(&fcx, &mut buf).await.err(),
            Some(ConnError::Closed)
        );
        assert_eq!(
            ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await.err(),
            Some(ConnError::Closed)
        );
        Ok(())
    });
}

static CUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn cut_now() -> bool {
    CUT.load(std::sync::atomic::Ordering::SeqCst)
}

#[test]
fn packets_for_other_addresses_are_dropped() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, b) = pair();
        let _eb = tcp::endpoint(&fcx, b, ip(B));
        // A SYN to 10.0.0.9, not B: no answer.
        raw.send(tcp_syn(ip(A), 4000, ip("10.0.0.9"), 80));
        // A SYN to B on a closed port: a RST.
        raw.send(tcp_syn(ip(A), 4001, ip(B), 81));
        let p = raw.recv(&fcx).await?;
        let flags = p.0[20 + 13];
        assert_eq!(flags & 0x04, 0x04, "a RST");
        assert_eq!(u16::from_be_bytes([p.0[22], p.0[23]]), 4001);
        let next = poll_fn(|cx| Poll::Ready(raw.poll_recv(&fcx, cx))).await;
        assert!(next.is_pending(), "only one answer");
        Ok(())
    });
}

// UDP

#[test]
fn udp_echo() {
    for (a, b) in [(A, B), ("fd00::1", "fd00::2")] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (ca, cb) = pair();
            let ua = udp::endpoint(&fcx, ca, ip(a));
            let ub = udp::endpoint(&fcx, cb, ip(b));
            let mut server = ub.bind(53)?;
            assert!(ub.bind(53).is_err(), "a second socket on the same port");
            fcx.spawn(move |fcx| async move {
                loop {
                    let (data, from) = match server.recv(&fcx).await {
                        Ok(d) => d,
                        Err(_) => return Ok(()),
                    };
                    server.send_to(&data, from);
                }
            });
            let mut client = ua.bind(5000)?;
            for i in 0..100u32 {
                let msg = format!("datagram {i}").into_bytes();
                client.send_to(&msg, SocketAddr::new(ip(b), 53));
                let (data, from) = client.recv(&fcx).await?;
                assert_eq!(data, msg);
                assert_eq!(from, SocketAddr::new(ip(b), 53));
            }
            // A big one and an empty one.
            let big = pattern(8000, 3);
            client.send_to(&big, SocketAddr::new(ip(b), 53));
            assert_eq!(client.recv(&fcx).await?.0, big);
            client.send_to(b"", SocketAddr::new(ip(b), 53));
            assert_eq!(client.recv(&fcx).await?.0, b"");
            Ok(())
        });
    }
}

/// The largest datagram that fits in one IP packet is sent, and one byte
/// more is dropped: 65,507 bytes over IPv4 (the total length counts the
/// 20-byte header) and 65,527 over IPv6 (the payload length does not).
#[test]
fn udp_the_largest_datagrams_that_fit_are_sent() {
    for (a, b, max) in [(A, B, 65_507usize), ("fd00::1", "fd00::2", 65_527)] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (ca, mut raw) = pair();
            let ua = udp::endpoint(&fcx, ca, ip(a));
            let mut s = ua.bind(1000)?;
            let to = SocketAddr::new(ip(b), 2000);
            s.send_to(&pattern(max, 5), to);
            let p = raw.recv(&fcx).await?;
            let header = if ip(a).is_ipv4() { 20 } else { 40 };
            assert_eq!(p.0.len(), header + 8 + max);
            assert_eq!(&p.0[header + 8..], &pattern(max, 5)[..]);
            if ip(a).is_ipv4() {
                assert_eq!(u16::from_be_bytes([p.0[2], p.0[3]]), 65_535, "total length");
                assert_eq!(checksum(&p.0[..20]), 0);
            } else {
                assert_eq!(
                    u16::from_be_bytes([p.0[4], p.0[5]]),
                    65_535,
                    "payload length"
                );
            }
            s.send_to(&pattern(max + 1, 5), to);
            s.send_to(b"after", to);
            let p = raw.recv(&fcx).await?;
            assert_eq!(&p.0[header + 8..], b"after", "one byte more is dropped");
            Ok(())
        });
    }
}

#[test]
fn udp_closed_port_gets_port_unreachable() {
    for (a, b) in [(A, B), ("fd00::1", "fd00::2")] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (mut raw, cb) = pair();
            let ub = udp::endpoint(&fcx, cb, ip(b));
            let _open = ub.bind(53)?;
            let sent = udp_packet(ip(a), 4000, ip(b), 99, b"anyone?");
            raw.send(sent.clone());
            let reply = raw.recv(&fcx).await?;
            let r = &reply.0;
            if ip(a).is_ipv4() {
                assert_eq!(r[9], 1, "ICMP");
                assert_eq!(
                    &r[12..16],
                    &ip(b)
                        .to_string()
                        .parse::<std::net::Ipv4Addr>()
                        .unwrap()
                        .octets()
                );
                assert_eq!((r[20], r[21]), (3, 3), "port unreachable");
                assert_eq!(&r[28..], &sent.0[..], "quotes the datagram");
                assert_eq!(checksum(&r[..20]), 0);
                assert_eq!(checksum(&r[20..]), 0);
            } else {
                assert_eq!(r[6], 58, "ICMPv6");
                assert_eq!((r[40], r[41]), (1, 4), "port unreachable");
                assert_eq!(&r[48..], &sent.0[..], "quotes the datagram");
                assert_eq!(
                    transport_checksum(source(r).unwrap(), destination(r).unwrap(), 58, &r[40..]),
                    0
                );
            }
            // An open port gets no ICMP, and a datagram for another address
            // gets nothing at all.
            raw.send(udp_packet(ip(a), 4000, ip(b), 53, b"hi"));
            let other = if ip(b).is_ipv4() {
                "10.9.9.9"
            } else {
                "fd00::99"
            };
            raw.send(udp_packet(ip(a), 4000, ip(other), 99, b"hi"));
            fcx.sleep(Duration::from_millis(20)).await?;
            let next = poll_fn(|cx| Poll::Ready(raw.poll_recv(&fcx, cx))).await;
            assert!(next.is_pending(), "no more answers");
            Ok(())
        });
    }
}

#[test]
fn udp_packets_have_good_checksums_and_bad_ones_are_dropped() {
    world(Duration::from_secs(10), |fcx| async move {
        let (mut raw, cb) = pair();
        let ub = udp::endpoint(&fcx, cb, ip(B));
        let mut sock = ub.bind(53)?;
        let mut bad = udp_packet(ip(A), 4000, ip(B), 53, b"bad");
        let n = bad.0.len();
        bad.0[n - 1] ^= 0xff;
        raw.send(bad);
        raw.send(udp_packet(ip(A), 4000, ip(B), 53, b"good"));
        let (data, from) = sock.recv(&fcx).await?;
        assert_eq!(data, b"good");
        assert_eq!(from, SocketAddr::new(ip(A), 4000));
        sock.send_to(b"answer", from);
        let p = raw.recv(&fcx).await?;
        assert_eq!(checksum(&p.0[..20]), 0);
        assert_eq!(
            transport_checksum(
                source(&p.0).unwrap(),
                destination(&p.0).unwrap(),
                17,
                &p.0[20..]
            ),
            0
        );
        assert_eq!(&p.0[28..], b"answer");
        Ok(())
    });
}

#[test]
fn udp_recv_ends_on_cancel_and_on_close() {
    let results = Arc::new(Mutex::new(Vec::new()));
    let r = results.clone();
    world(Duration::from_secs(10), move |fcx| async move {
        let (ca, _keep) = pair();
        let ua = udp::endpoint(&fcx, ca, ip(A));
        let mut sock = ua.bind(1)?;
        let r1 = r.clone();
        fcx.spawn(move |fcx| async move {
            let res = sock.recv(&fcx).await.err();
            r1.lock().unwrap().push(res);
            Ok(())
        });
        let (cb, gone) = pair();
        drop(gone);
        let ub = udp::endpoint(&fcx, cb, ip(B));
        let mut sock = ub.bind(1)?;
        assert_eq!(sock.recv(&fcx).await.err(), Some(RecvError::Closed));
        Ok(())
    });
    assert_eq!(*results.lock().unwrap(), [Some(RecvError::Cancelled)]);
}

// Hand-made packets.

fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, mut payload: Vec<u8>, sum_at: usize) -> Packet {
    let sum = transport_checksum(src, dst, proto, &payload);
    payload[sum_at..sum_at + 2].copy_from_slice(&sum.to_be_bytes());
    packet_with(
        src,
        dst,
        proto,
        Fields {
            id: 1,
            ..Fields::default()
        },
        &payload,
    )
}

fn udp_packet(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    ip_packet(src, dst, 17, u, 6)
}

fn tcp_syn(src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&1000u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    ip_packet(src, dst, 6, t, 16)
}

/// A connection handed to tokio code with `into_tokio`, served from tokio
/// tasks on other threads while a tokio runtime polls the run. It has no
/// wall-clock limit of its own, so a loaded machine cannot fail it;
/// nextest's slow-timeout (`.config/nextest.toml`) stops a run that hangs.
#[test]
fn tcp_through_tokio_io() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(async {
        run(fictionet::Seed::random(), |fcx| async move {
            let (ea, eb) = two_tcp(&fcx, A, B);
            let mut listener = eb.listen(80)?;
            let server_fcx = fcx.clone();
            let server = tokio::spawn(async move {
                let conn = listener.accept(&server_fcx).await.unwrap();
                let mut io = conn.into_tokio(&server_fcx);
                let mut data = Vec::new();
                io.read_to_end(&mut data).await.unwrap();
                io.write_all(&data).await.unwrap();
                io.shutdown().await.unwrap();
            });
            let conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
            let client_fcx = fcx.clone();
            let client = tokio::spawn(async move {
                let mut io = conn.into_tokio(&client_fcx);
                let data = pattern(1_000_000, 9);
                io.write_all(&data).await.unwrap();
                io.shutdown().await.unwrap();
                let mut back = Vec::new();
                io.read_to_end(&mut back).await.unwrap();
                assert!(back == data);
            });
            server.await?;
            client.await?;
            Err(fictionet::Error::from(Done))
        })
        .await
    });
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

/// Relays packets between two cables, dropping the ones `drop_it` picks.
fn lossy_relay(
    fcx: &Cx,
    mut b: impl Interface,
    mut c: impl Interface,
    mut drop_it: impl FnMut(&Packet) -> bool + Send + 'static,
) {
    fcx.spawn(move |fcx| async move {
        loop {
            let p = poll_fn(|cx| {
                if let Poll::Ready(r) = b.poll_recv(&fcx, cx) {
                    return Poll::Ready(r.map(|p| (true, p)));
                }
                c.poll_recv(&fcx, cx).map(|r| r.map(|p| (false, p)))
            })
            .await;
            match p {
                Ok((_, p)) if drop_it(&p) => {}
                Ok((true, p)) => c.send(p),
                Ok((false, p)) => b.send(p),
                Err(_) => return Ok(()),
            }
        }
    });
}

#[test]
fn a_fin_is_acked_before_a_dropped_connection_is_forgotten() {
    // The client closes first. The server answers with data and its own
    // FIN, in one segment or, a moment apart, in two. The client reads to
    // the end and drops its handle at once. Its socket is in TIME-WAIT
    // then, and is forgotten: it must ACK the server's FIN first.
    // Otherwise the server keeps its socket until it sends the FIN again,
    // a second later, and gets a RST. A server that counts open
    // connections per client (web::Sites) then counts this one for that
    // second.
    fin_then_drop(Duration::ZERO);
    fin_then_drop(Duration::from_millis(3));
}

/// See [`a_fin_is_acked_before_a_dropped_connection_is_forgotten`]. The
/// server waits `gap` between its data and its FIN.
fn fin_then_drop(gap: Duration) {
    let seen: Arc<Mutex<Vec<(IpAddr, u8)>>> = Arc::default();
    let log = seen.clone();
    world(Duration::from_secs(10), move |fcx| async move {
        let (a, b) = pair();
        let (c, d) = pair();
        lossy_relay(&fcx, b, c, move |p| {
            let v = &p.0;
            if v.len() >= 40 && v[9] == 6 {
                log.lock()
                    .unwrap()
                    .push((IpAddr::from([v[12], v[13], v[14], v[15]]), v[33]));
            }
            false
        });
        let ea = tcp::endpoint(&fcx, a, ip(A));
        let eb = tcp::endpoint(&fcx, d, ip(B));
        let mut listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let mut server = listener.accept(&fcx).await?;
        conn.shutdown(&fcx).await?;
        assert_eq!(read_to_end(&fcx, &mut server).await?, b"");
        server.write_all(&fcx, b"bye").await?;
        if !gap.is_zero() {
            fcx.sleep(gap).await?;
        }
        drop(server);
        assert_eq!(read_to_end(&fcx, &mut conn).await?, b"bye");
        drop(conn);
        // Longer than the server's first retransmission timeout.
        fcx.sleep(Duration::from_millis(1500)).await?;
        Ok(())
    });
    let seen = seen.lock().unwrap();
    const FIN: u8 = 1;
    const RST: u8 = 4;
    let server_fins = seen
        .iter()
        .filter(|(src, f)| *src == ip(B) && f & FIN != 0)
        .count();
    let resets = seen.iter().filter(|(_, f)| f & RST != 0).count();
    assert_eq!(
        (server_fins, resets),
        (1, 0),
        "gap {gap:?}: the server's FIN went unanswered: {seen:?}"
    );
}

#[test]
fn transfers_survive_lost_packets() {
    let elapsed = Arc::new(Mutex::new(Duration::ZERO));
    let e = elapsed.clone();
    world(Duration::from_secs(60), move |fcx| async move {
        let (a, b) = pair();
        let (c, d) = pair();
        // Drop one packet in 50, SYNs and FINs included.
        let mut n = 0u64;
        lossy_relay(&fcx, b, c, move |_| {
            n += 1;
            n % 50 == 7
        });
        let ea = tcp::endpoint(&fcx, a, ip(A));
        let eb = tcp::endpoint(&fcx, d, ip(B));
        let mut listener = eb.listen(80)?;
        let up = pattern(512 * 1024, 4);
        let down = pattern(256 * 1024, 5);
        let (up2, down2) = (up.clone(), down.clone());
        let started = fcx.now();
        let server = fcx.spawn(move |fcx| async move {
            let mut conn = listener.accept(&fcx).await?;
            let got = duplex(&fcx, &mut conn, &down2).await?;
            assert!(got == up2, "the server got different bytes");
            Ok(())
        });
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        let got = duplex(&fcx, &mut conn, &up).await?;
        assert!(got == down, "the client got different bytes");
        server.join(&fcx).await?;
        *e.lock().unwrap() = fcx.now().since_start() - started.since_start();
        Ok(())
    });
    eprintln!(
        "512 KiB up and 256 KiB down with 2% loss took {:?}",
        elapsed.lock().unwrap()
    );
}

#[test]
fn every_closed_port_is_refused() {
    world(Duration::from_secs(120), |fcx| async move {
        let (mut raw, b) = pair();
        let eb = tcp::endpoint(&fcx, b, ip(B));
        let _open = eb.listen(443)?;
        let started = fcx.now();
        // Many SYNs in flight at once, as from a port scan.
        let mut answered = 0u32;
        let mut open_seen = false;
        for chunk in (1..=65535u16).collect::<Vec<_>>().chunks(512) {
            for &port in chunk {
                raw.send(tcp_syn(ip(A), 50000, ip(B), port));
            }
            for _ in chunk {
                let p = raw.recv(&fcx).await?;
                let flags = p.0[20 + 13];
                let port = u16::from_be_bytes([p.0[20], p.0[21]]);
                if port == 443 {
                    assert_eq!(flags & 0x12, 0x12, "a SYN-ACK from the open port");
                    open_seen = true;
                } else {
                    assert_eq!(flags & 0x04, 0x04, "a RST from port {port}");
                }
                answered += 1;
            }
        }
        assert_eq!(answered, 65535);
        assert!(open_seen);
        eprintln!(
            "65,535 ports answered in {:?}",
            (fcx.now().since_start() - started.since_start())
        );
        Ok(())
    });
}

#[test]
fn dropping_a_listener_resets_connections_not_yet_accepted() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let listener = eb.listen(80)?;
        let mut conn = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        drop(listener);
        let mut buf = [0; 8];
        assert_eq!(
            conn.read(&fcx, &mut buf).await.err(),
            Some(ConnError::Reset)
        );
        Ok(())
    });
}

/// A connection that breaks the `poll_write` contract.
struct TakesNothing;

impl Connection for TakesNothing {
    fn poll_read(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(0))
    }
    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        Poll::Ready(Ok(0))
    }
    fn poll_shutdown(
        &mut self,
        _: &Cx,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), ConnError>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn boxed_connections_and_write_all() {
    world(Duration::from_secs(10), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        let client: Box<dyn Connection> =
            Box::new(ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?);
        let server: Box<dyn Connection> = Box::new(listener.accept(&fcx).await?);
        let mut conns = [client, server];
        conns[0].write_all(&fcx, b"through a box").await?;
        conns[0].shutdown(&fcx).await?;
        assert_eq!(read_to_end(&fcx, &mut conns[1]).await?, b"through a box");
        // write_all stops instead of looping when nothing is taken.
        let mut broken: Box<dyn Connection> = Box::new(TakesNothing);
        assert_eq!(
            broken.write_all(&fcx, b"x").await.err(),
            Some(ConnError::Closed)
        );
        assert_eq!(broken.write_all(&fcx, b"").await.err(), None);
        Ok(())
    });
}

/// Endpoints with connections in many states use no CPU while nothing
/// happens.
#[test]
fn idle_endpoints_stay_idle() {
    world::real_world(Duration::from_secs(20), |fcx| async move {
        let (ea, eb) = two_tcp(&fcx, A, B);
        let mut listener = eb.listen(80)?;
        // Open, half-closed, closed and dropped connections, and one
        // waiting in the accept queue.
        let mut keep = Vec::new();
        for i in 0..6 {
            let mut c = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
            let mut s = listener.accept(&fcx).await?;
            c.write_all(&fcx, b"hello").await?;
            match i {
                0 => {}
                1 => c.shutdown(&fcx).await?,
                2 => {
                    c.shutdown(&fcx).await?;
                    s.shutdown(&fcx).await?;
                }
                _ => {}
            }
            if i == 4 {
                drop(c);
                let mut buf = [0; 5];
                s.read(&fcx, &mut buf).await?;
                keep.push(s);
                continue;
            }
            if i == 5 {
                drop(s);
                keep.push(c);
                continue;
            }
            keep.push(c);
            keep.push(s);
        }
        let _waiting = ea.connect(&fcx, SocketAddr::new(ip(B), 80)).await?;
        fcx.sleep(Duration::from_millis(100)).await?;
        let before = thread_cpu_time();
        fcx.sleep(Duration::from_secs(1)).await?;
        let used = thread_cpu_time() - before;
        eprintln!("one idle second used {used:?} of CPU");
        assert!(
            used < Duration::from_millis(20),
            "idle endpoints used {used:?}"
        );
        Ok(())
    });
}
