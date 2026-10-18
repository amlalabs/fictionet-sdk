use super::dns_dhcp::read_exact;
use super::*;

// ---------------------------------------------------------------------------
// Tests: an agent trying to wear the world down

/// An IPv4 fragment: `data` at byte `offset` of packet `id`.
fn fragment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    offset: usize,
    more: bool,
    data: &[u8],
) -> Packet {
    let mut p = ipv4(src, dst, proto, data);
    p.0[4..6].copy_from_slice(&id.to_be_bytes());
    let flags = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    p.0[6..8].copy_from_slice(&flags.to_be_bytes());
    p.0[10..12].copy_from_slice(&[0, 0]);
    let c = ip::checksum(&p.0[..20]);
    p.0[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

/// Tens of thousands of first fragments that never complete, each a
/// different packet, must not stall the gateway for everyone else.
#[test]
fn a_flood_of_unfinished_fragments_does_not_stall_the_gateway() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .is_some()
        );
        let started = fictionet::stdlib::test_support::thread_cpu_time();
        for i in 0..60_000u32 {
            let proto = [17u8, 6, 1][(i % 3) as usize];
            raw.send(fragment(
                me,
                GATEWAY,
                proto,
                (i / 3) as u16,
                0,
                true,
                &[0; 8],
            ));
        }
        // A ping sent after the flood is answered once the gateway has gone
        // through every fragment before it. That must be quick.
        raw.send(ping(me, GATEWAY, 2));
        let reply = recv_within(&fcx, &mut raw, Duration::from_secs(5)).await;
        let elapsed = fictionet::stdlib::test_support::thread_cpu_time() - started;
        assert!(
            reply.is_some(),
            "no ping reply after {elapsed:?} of CPU time"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "flood and ping reply used {elapsed:?} of CPU time"
        );
        eprintln!("60,000 fragments went through in {elapsed:?} of CPU time");
        Ok(())
    });
}

/// A TCP segment with a good checksum.
#[allow(clippy::too_many_arguments)]
pub(super) fn tcp_seg(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data: &[u8],
) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(data);
    let c = ip::transport_checksum(src.into(), dst.into(), 6, &t);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    ipv4(src, dst, 6, &t)
}

pub(super) const SYN: u8 = 0x02;
pub(super) const ACK: u8 = 0x10;
pub(super) const RST: u8 = 0x04;
const FIN: u8 = 0x01;

/// Opens `n` TCP connections from `me` to `to`, in batches, by hand: SYN,
/// then an ACK for each SYN-ACK. Returns how many were set up, and the
/// ports (ours) of those the other side closed (FIN or RST) while the rest
/// were being opened. They then sit idle; the raw end never answers again
/// unless asked.
pub(super) async fn open_idle(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    to: SocketAddr,
    n: u16,
) -> (usize, std::collections::BTreeSet<u16>) {
    let IpAddr::V4(dst) = to.ip() else {
        unreachable!()
    };
    let mut open = 0;
    let mut opened = std::collections::HashSet::new();
    let mut closed = std::collections::BTreeSet::new();
    for batch in (0..n).collect::<Vec<_>>().chunks(256) {
        for &i in batch {
            raw.send(tcp_seg(me, 10_000 + i, dst, to.port(), 1000, 0, SYN, &[]));
        }
        let mut left = batch.len();
        while left > 0 {
            let Some(p) = recv_within(fcx, raw, Duration::from_secs(5)).await else {
                break;
            };
            let (_, _, proto, t) = parse(&p);
            if proto != 6 {
                continue;
            }
            let sport = u16::from_be_bytes([t[2], t[3]]);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            if t[13] & (SYN | ACK) == SYN | ACK {
                raw.send(tcp_seg(
                    me,
                    sport,
                    dst,
                    to.port(),
                    1001,
                    seq.wrapping_add(1),
                    ACK,
                    &[],
                ));
                opened.insert(sport);
                open += 1;
                left -= 1;
            } else if t[13] & (FIN | RST) != 0 && opened.contains(&sport) {
                closed.insert(sport);
            } else if t[13] & RST != 0 {
                left -= 1;
            }
        }
    }
    (open, closed)
}

/// Measures thread CPU time for one HTTPS request from a fresh connection.
async fn timed_get(fcx: &Cx, m: &Machine, env: &Env) -> Duration {
    let started = fictionet::stdlib::test_support::thread_cpu_time();
    let conn = tls_connect(fcx, m, env, SECURE_ADDR, "secure.test", &[b"http/1.1"])
        .await
        .unwrap();
    let mut client = Client::new(fcx, conn, false).await;
    assert_eq!(
        client.get("https", "secure.test", "/").await.status,
        StatusCode::OK
    );
    fictionet::stdlib::test_support::thread_cpu_time() - started
}

/// Ports (ours) of the connections the other side closed (FIN or RST)
/// within `d`, counting each port once.
async fn closed_ports(fcx: &Cx, raw: &mut End, d: Duration) -> std::collections::BTreeSet<u16> {
    let mut closed = std::collections::BTreeSet::new();
    let until = fcx.now().since_start() + d;
    while let Some(left) = until.checked_sub(fcx.now().since_start()) {
        let Some(p) = recv_within(fcx, raw, left).await else {
            break;
        };
        let (_, _, proto, t) = parse(&p);
        if proto == 6 && t[13] & (FIN | RST) != 0 {
            closed.insert(u16::from_be_bytes([t[2], t[3]]));
        }
    }
    closed
}

/// One sandbox may hold only so many connections open at a machine the
/// others share. Past that, the machine resets new ones at once.
#[test]
fn one_sandbox_cannot_hold_thousands_of_connections_open() {
    world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        let (open, mut closed) = open_idle(
            &fcx,
            &mut raw,
            me,
            SocketAddr::new(SECURE_ADDR.into(), 443),
            1000,
        )
        .await;
        assert_eq!(open, 1000);
        closed.extend(closed_ports(&fcx, &mut raw, Duration::from_secs(1)).await);
        assert_eq!(
            closed.len(),
            1000 - 256,
            "all past the first 256 are closed"
        );
        // The other sandbox is served as before.
        timed_get(&fcx, &b, &env).await;
        Ok(())
    });
}

/// One HTTP/1.0 request on a fresh connection. Reads to the end, and
/// gives back the connection without closing this side, so it stays in
/// CLOSE_WAIT. Returns the connection error if the request fails.
async fn get_and_hold(
    fcx: &Cx,
    m: &Machine,
    to: Ipv4Addr,
) -> Result<(String, tcp::TcpConnection), ConnError> {
    let mut conn = m.tcp.connect(fcx, SocketAddr::new(to.into(), 80)).await?;
    conn.write_all(fcx, b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n")
        .await?;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match conn.read(fcx, &mut buf).await {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e),
        }
    }
    Ok((String::from_utf8_lossy(&got).into_owned(), conn))
}

/// A connection the server closed but the sandbox never closed on its side
/// still counts against the sandbox's 256, so the sandbox cannot pile up
/// closing sockets on a machine the others share. Once it closes them,
/// it may connect again.
#[test]
fn connections_left_half_open_still_count() {
    world(|fcx, attacher, _env| async move {
        let a = default_machine(&fcx, &attacher);
        let to = lookup(&fcx, &a, "plain.test").await;
        let mut held = Vec::new();
        for i in 0..256 {
            let (text, conn) = get_and_hold(&fcx, &a, to)
                .await
                .unwrap_or_else(|e| panic!("connection {i} failed: {e}"));
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
            held.push(conn);
        }
        // The server closed all 256; the sandbox did not.
        for _ in 0..20 {
            assert!(
                get_and_hold(&fcx, &a, to)
                    .await
                    .is_err_and(|e| e == ConnError::Reset),
                "a connection past the 256 was served"
            );
        }
        // Another sandbox is served as before.
        let b = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        assert_eq!(lookup(&fcx, &b, "plain.test").await, to);
        let (text, _conn) = get_and_hold(&fcx, &b, to)
            .await
            .expect("the other sandbox is served");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        // Closing them frees the count.
        drop(held);
        fcx.idle().await?;
        let (text, _conn) = get_and_hold(&fcx, &a, to)
            .await
            .expect("the connection count was not freed");
        assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        for _ in 0..20 {
            let (text, _conn) = get_and_hold(&fcx, &a, to)
                .await
                .expect("served again after closing");
            assert!(text.starts_with("HTTP/1.0 200"), "{text}");
        }
        Ok(())
    });
}

/// A connection that never finishes its TLS handshake, never sends a
/// request on port 80, or sits idle on DNS over TCP, is closed after one
/// second.
#[test]
fn connections_that_send_nothing_are_closed() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        sites(&fcx)
            .sites
            .into_net()
            .limits(fictionet::stdlib::world::net::Limits {
                handshake: Duration::from_secs(1),
                dns_tcp_idle: Duration::from_secs(1),
                ..Default::default()
            })
            .start(&fcx, attachments)?;
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let plain = Ipv4Addr::new(198, 18, 0, 1);
        // Look the names up, over raw DNS, so their machines exist.
        for name in ["secure.test", "plain.test"] {
            let mut q = Message::new(7, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
            assert!(
                recv_within(&fcx, &mut raw, Duration::from_secs(2))
                    .await
                    .is_some()
            );
        }
        let mut opened = std::collections::BTreeMap::new();
        for (n, to) in [
            SocketAddr::new(SECURE_ADDR.into(), 443),
            SocketAddr::new(plain.into(), 80),
            SocketAddr::new(GATEWAY.into(), 53),
        ]
        .into_iter()
        .enumerate()
        {
            let n = n as u16;
            // Ports 10000, 11000 and 12000.
            opened.insert(10_000 + n * 1000, fcx.now());
            raw.send(tcp_seg(
                me,
                10_000 + n * 1000,
                match to.ip() {
                    IpAddr::V4(a) => a,
                    _ => unreachable!(),
                },
                to.port(),
                1000,
                0,
                SYN,
                &[],
            ));
            let p = recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("a SYN-ACK");
            let (_, _, _, t) = parse(&p);
            assert_eq!(t[13] & (SYN | ACK), SYN | ACK);
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            let IpAddr::V4(dst) = to.ip() else {
                unreachable!()
            };
            raw.send(tcp_seg(
                me,
                10_000 + n * 1000,
                dst,
                to.port(),
                1001,
                seq.wrapping_add(1),
                ACK,
                &[],
            ));
        }
        let deadline = fcx.now() + Duration::from_secs(10);
        let mut closed = std::collections::BTreeSet::new();
        while closed.len() < opened.len() {
            let packet = fcx
                .race(Some(deadline), raw.recv(&fcx))
                .await
                .expect("idle connections did not close")
                .unwrap();
            let (_, _, proto, t) = parse(&packet);
            if proto == 6 && t[13] & (FIN | RST) != 0 {
                let port = u16::from_be_bytes([t[2], t[3]]);
                let took = fcx.now().since_start()
                    - opened.get(&port).expect("an opened port").since_start();
                assert!(
                    took >= Duration::from_secs(1),
                    "port {port} closed too early: {took:?}"
                );
                assert!(
                    took < Duration::from_secs(10),
                    "port {port} closed too late: {took:?}"
                );
                closed.insert(port);
            }
        }
        assert_eq!(
            closed.into_iter().collect::<Vec<_>>(),
            vec![10_000, 11_000, 12_000]
        );
        Ok(())
    });
}

/// One sandbox that sends SYNs and never finishes the handshakes must not
/// lock the others out of a site they share.
#[test]
fn a_syn_flood_from_one_sandbox_does_not_lock_out_the_others() {
    world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        for i in 0..2000u16 {
            raw.send(tcp_seg(me, 10_000 + i, SECURE_ADDR, 443, 1000, 0, SYN, &[]));
        }
        let mut synacks = 0;
        while let Some(p) = recv_within(&fcx, &mut raw, Duration::from_millis(500)).await {
            let (_, _, _, t) = parse(&p);
            if t[13] & (SYN | ACK) == SYN | ACK {
                synacks += 1;
            }
        }
        // Some got through, but not all: one address has a share of the
        // backlog, not all of it.
        assert!(synacks > 0 && synacks < 2000, "{synacks} SYN-ACKs");
        let r = timeout(&fcx, Duration::from_secs(5), timed_get(&fcx, &b, &env)).await;
        assert!(r.is_some(), "the other sandbox could not reach the site");
        Ok(())
    });
}

/// The median thread CPU time of five HTTPS requests from fresh connections.
async fn median_get(fcx: &Cx, m: &Machine, env: &Env) -> Duration {
    let mut times = Vec::new();
    for _ in 0..5 {
        times.push(timed_get(fcx, m, env).await);
    }
    times.sort();
    times[2]
}

/// A world whose callback opens a whole domain (`*.wild.test`, like the
/// `*.github.com` of the module docs) gets a machine and a route for every
/// name the agent tries. Ten thousand of them must not slow the network
/// down: lookups stay quick, and so does every other request.
#[test]
fn ten_thousand_sites_do_not_slow_the_network() {
    world(|fcx, attacher, env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let b = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        assert_eq!(lookup(&fcx, &b, "secure.test").await, SECURE_ADDR);
        let before = median_get(&fcx, &b, &env).await;
        let n = 10_000u32;
        for i in 0..n {
            let mut q = Message::new(i as u16, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(
                Name::from_ascii(format!("n{i}.wild.test")).unwrap(),
                RecordType::A,
            ));
            raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        }
        let mut answers = 0;
        while answers < n
            && recv_within(&fcx, &mut raw, Duration::from_secs(10))
                .await
                .is_some()
        {
            answers += 1;
        }
        assert_eq!(answers, n);
        // The last site answers.
        let last = Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + n);
        raw.send(ping(me, last, 1));
        let (src, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (last, 0));
        let after = median_get(&fcx, &b, &env).await;
        assert!(
            after < before * 3,
            "a request took {before:?} before and {after:?} after"
        );
        Ok(())
    });
}

/// A name the callback would accept, but that was never looked up, is
/// not served anywhere: not by Host, not by `:authority`, not by SNI. And
/// asking does not run the callback.
#[test]
fn a_name_never_looked_up_is_not_served_by_host_or_sni() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        let wild = lookup(&fcx, &m, "one.wild.test").await;
        let calls = env.calls.load(Ordering::SeqCst);
        for h2 in [true, false] {
            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
            let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", alpn)
                .await
                .unwrap();
            let mut client = Client::new(&fcx, conn, h2).await;
            assert_eq!(
                client.get("https", "two.wild.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
        }
        let mut client = plain_client(&fcx, &m, wild, false).await;
        assert_eq!(
            client.get("http", "one.wild.test", "/").await.body,
            "wild http one.wild.test 80 HTTP/1.1 /"
        );
        assert_eq!(
            client.get("http", "two.wild.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        match tls_connect(&fcx, &m, &env, addr, "two.wild.test", &[b"h2"]).await {
            Err(TlsError::Tls(rustls::Error::AlertReceived(
                rustls::AlertDescription::UnrecognisedName,
            ))) => {}
            Err(e) => panic!("expected unrecognized_name, got {e:?}"),
            Ok(_) => panic!("the handshake should fail"),
        }
        assert_eq!(
            env.calls.load(Ordering::SeqCst),
            calls,
            "the callback ran for a name seen only in HTTP or TLS"
        );
        Ok(())
    });
}

/// A thousand requests at once on one HTTP/2 connection, more than the
/// 200 streams the server allows at a time, and streams the client
/// cancels as soon as it opens them.
#[test]
fn http2_with_a_thousand_streams_and_cancelled_ones() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2"])
            .await
            .unwrap();
        let client = Client::new(&fcx, conn, true).await;
        let Client::H2(send) = &client else {
            unreachable!()
        };
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for i in 0..1000 {
            let mut c = Client::H2(send.clone());
            tasks.push(fcx.spawn(move |fcx| async move {
                if i % 10 == 0 {
                    // Opened and dropped at once: the client resets it.
                    let Client::H2(s) = &mut c else {
                        unreachable!()
                    };
                    s.ready().await.unwrap();
                    let r = Request::get("https://secure.test/x")
                        .body(Empty::new())
                        .unwrap();
                    let fut = s.send_request(r);
                    let _ = timeout(&fcx, Duration::from_micros(1), fut).await;
                } else {
                    let got = c.get("https", "secure.test", "/x").await;
                    assert_eq!(got.status, StatusCode::OK);
                }
                Ok(())
            }));
        }
        for t in tasks {
            t.join(&fcx).await?;
        }
        eprintln!("1,000 streams in {:?}", started.elapsed());
        assert!(env.served.load(Ordering::SeqCst) >= 900);
        // The connection still works.
        let mut c = Client::H2(send.clone());
        assert_eq!(
            c.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}

/// DNS messages an agent might send to break the server: garbage, cut-off
/// headers, a pointer loop, counts that lie, a response, a huge query in
/// fragments, the same over TCP with lengths that lie. The server stays up
/// and answers a good query after each.
#[test]
fn malformed_dns_does_not_break_the_server() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let good = {
            let mut q = Message::new(4242, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(
                Name::from_ascii("secure.test").unwrap(),
                RecordType::A,
            ));
            q.to_vec().unwrap()
        };
        let mut bad: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x12],
            vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01],
            // A question whose name points at itself.
            vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1],
            // 65,535 questions claimed, one given.
            {
                let mut m = good.clone();
                m[4..6].copy_from_slice(&[0xff, 0xff]);
                m
            },
            // A response, not a query.
            {
                let mut m = good.clone();
                m[2] |= 0x80;
                m
            },
            // A label of 63 bytes, repeated past 255.
            {
                let mut m = vec![0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                for _ in 0..8 {
                    m.push(63);
                    m.extend_from_slice(&[b'a'; 63]);
                }
                m.extend_from_slice(&[0, 0, 1, 0, 1]);
                m
            },
        ];
        for _ in 0..200 {
            let len = (fcx.random_u64() % 600) as usize;
            bad.push((0..len).map(|_| fcx.random_u64() as u8).collect());
        }
        for m in &bad {
            raw.send(udp(me, 5353, GATEWAY, 53, m));
        }
        // A 29,000-byte query in fragments: the question, then a TXT
        // record of padding.
        let mut big = good.clone();
        big[11] = 1; // one additional record
        big.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 0]); // root, TXT, IN, TTL 0
        big.extend_from_slice(&29_000u16.to_be_bytes());
        big.extend(std::iter::repeat_n(b'x', 29_000));
        let whole = udp(me, 5354, GATEWAY, 53, &big);
        let payload = &whole.0[20..];
        let mut at = 0;
        while at < payload.len() {
            let n = 1480.min(payload.len() - at);
            raw.send(fragment(
                me,
                GATEWAY,
                17,
                777,
                at,
                at + n < payload.len(),
                &payload[at..at + n],
            ));
            at += n;
        }
        // Then the good query: its answer must come.
        raw.send(udp(me, 5355, GATEWAY, 53, &good));
        let mut answered = false;
        while let Some(p) = recv_within(&fcx, &mut raw, Duration::from_secs(2)).await {
            let (_, _, proto, u) = parse(&p);
            if proto == 17 && u16::from_be_bytes([u[2], u[3]]) == 5355 {
                assert_eq!(
                    parse_dns(&u[8..], 4242),
                    (ResponseCode::NoError, vec![SECURE_ADDR])
                );
                answered = true;
                break;
            }
        }
        assert!(answered, "no answer to a good query after the bad ones");

        // Over TCP: a length that promises more than comes, then garbage,
        // on separate connections; then a good query on a new one.
        let b = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3),
        );
        let dns_tcp = SocketAddr::new(GATEWAY.into(), 53);
        let mut c1 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        c1.write_all(&fcx, &[0xff, 0xff, 1, 2, 3]).await.unwrap();
        let mut c2 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        c2.write_all(&fcx, &[0, 3, 1, 2, 3, 0, 0]).await.unwrap();
        let mut c3 = b.tcp.connect(&fcx, dns_tcp).await.unwrap();
        let mut framed = (good.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&good);
        c3.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut c3, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&fcx, &mut c3, &mut reply).await;
        assert_eq!(
            parse_dns(&reply, 4242),
            (ResponseCode::NoError, vec![SECURE_ADDR])
        );
        Ok(())
    });
}

/// When a sandbox detaches, what the sites still had for it must not reach
/// the next sandbox that takes its address: the connections are ended.
#[test]
fn a_detached_sandboxs_traffic_does_not_reach_the_next_holder_of_its_address() {
    super::events::world_events(|fcx, attacher, _env, log| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // a looks plain.test up and opens a connection by hand.
        let mut q = Message::new(1, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::A,
        ));
        a.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (_, _, _, u) = parse(
            &recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        let plain = parse_dns(&u[8..], 1).1[0];
        a.send(tcp_seg(me, 40_000, plain, 80, 1000, 0, SYN, &[]));
        let (_, _, _, t) = parse(
            &recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        // The request, then a detaches before taking the answer.
        let request = b"GET /secret HTTP/1.1\r\nHost: plain.test\r\n\r\n";
        a.send(tcp_seg(
            me,
            40_000,
            plain,
            80,
            1001,
            seq.wrapping_add(1),
            ACK,
            request,
        ));
        let sent = log
            .events
            .wait(&fcx, 0, 1, Duration::from_secs(10), |e| {
                e.is("http", "request") && e.str("path") == Some("/secret")
            })
            .await?;
        assert_eq!(sent.len(), 1, "the request was served before detaching");
        drop(a);

        // b takes the same address as soon as it is free.
        let mut b = attacher.attach("b").unwrap();
        for p in bind_by_ping(&fcx, &mut b, me.into(), GATEWAY.into()).await {
            let (src, _, proto, t) = parse(&p);
            assert_eq!(
                proto, 6,
                "unexpected packet while b took a's address: {p:?}"
            );
            let data = &t[((t[12] >> 4) as usize) * 4..];
            assert!(
                data.is_empty(),
                "b got {} bytes of a's answer from {src}: {:?}",
                data.len(),
                String::from_utf8_lossy(data)
            );
        }
        // Nothing of a's answer reaches b, even after retransmissions.
        while let Some(p) = recv_within(&fcx, &mut b, Duration::from_secs(3)).await {
            let (src, _, proto, t) = parse(&p);
            if proto == 6 {
                let data = &t[((t[12] >> 4) as usize) * 4..];
                assert!(
                    data.is_empty(),
                    "b got {} bytes of a's answer from {src}: {:?}",
                    data.len(),
                    String::from_utf8_lossy(data)
                );
            }
        }
        Ok(())
    });
}

/// A TLS hello that never ends, or is garbage, closes that connection and
/// nothing else.
#[test]
fn a_huge_or_garbage_tls_hello_closes_only_that_connection() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        let to = SocketAddr::new(addr.into(), 443);
        // A handshake record header that promises 16 KiB, repeated: a hello
        // far larger than any real one.
        let mut huge = m.tcp.connect(&fcx, to).await.unwrap();
        let mut record = vec![22, 3, 1, 0x40, 0];
        record.extend(std::iter::repeat_n(0u8, 0x4000));
        let mut closed = false;
        for _ in 0..32 {
            if huge.write_all(&fcx, &record).await.is_err() {
                closed = true;
                break;
            }
        }
        let mut buf = [0u8; 64];
        let end = timeout(&fcx, Duration::from_secs(2), huge.read(&fcx, &mut buf)).await;
        assert!(
            closed || matches!(end, Some(Ok(0)) | Some(Err(_))),
            "the huge hello was not refused: {end:?}"
        );
        // Plain garbage.
        let mut junk = m.tcp.connect(&fcx, to).await.unwrap();
        junk.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: secure.test\r\n\r\n")
            .await
            .unwrap();
        let end = timeout(&fcx, Duration::from_secs(2), junk.read(&fcx, &mut buf)).await;
        assert!(
            matches!(end, Some(Ok(0)) | Some(Err(_))),
            "garbage was not refused: {end:?}"
        );
        // A real client is still served.
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "secure.test", "/").await.status,
            StatusCode::OK
        );
        Ok(())
    });
}
