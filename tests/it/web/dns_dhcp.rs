use super::*;
use fictionet::stdlib::world::net::Limits;

// ---------------------------------------------------------------------------
// Tests: DNS

#[test]
fn dns_answers_sites_nodata_and_nxdomain() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);

        // A site with `at` gets that address; the same answer every time.
        assert_eq!(lookup(&fcx, &m, "secure.test").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "secure.test.").await, SECURE_ADDR);
        assert_eq!(lookup(&fcx, &m, "SeCuRe.TeSt").await, SECURE_ADDR);
        // Without `at`, an address from 104.18.0.0/15.
        let plain = lookup(&fcx, &m, "plain.test").await;
        assert_eq!(plain, Ipv4Addr::new(104, 18, 0, 1));
        assert_eq!(
            lookup(&fcx, &m, "broken.test").await,
            Ipv4Addr::new(104, 18, 0, 2)
        );
        assert_eq!(lookup(&fcx, &m, "plain.test").await, plain);

        // Other types of a site's name: NODATA. (AAAA is in the IPv6 tests.)
        assert_eq!(
            dns(&fcx, &m, "secure.test", RecordType::MX).await,
            (ResponseCode::NoError, vec![])
        );
        // Names the callback turned down: NXDOMAIN, for every type.
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::A).await,
            (ResponseCode::NXDomain, vec![])
        );
        assert_eq!(
            dns(&fcx, &m, "nope.test", RecordType::AAAA).await,
            (ResponseCode::NXDomain, vec![])
        );
        // A site that asks for an address inside the sandboxes' subnet.
        assert_eq!(
            dns(&fcx, &m, "inside.test", RecordType::A).await,
            (ResponseCode::NXDomain, vec![])
        );

        // The callback ran for the name of each lookup no placed site
        // answered, and never for `test` above it: once for each of
        // secure, plain, and broken, and on every lookup of nope (twice)
        // and inside, which it turned down or which could not be placed,
        // and which are not kept.
        assert_eq!(env.calls.load(Ordering::SeqCst), 3 + 3);

        // DNS over TCP, two queries on one connection.
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY.into(), 53))
            .await
            .unwrap();
        for (name, id) in [("secure.test", 7u16), ("nope.test", 8)] {
            let mut q = Message::new(id, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            let bytes = q.to_vec().unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            conn.write_all(&fcx, &framed).await.unwrap();
            let mut len = [0u8; 2];
            read_exact(&fcx, &mut conn, &mut len).await;
            let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
            read_exact(&fcx, &mut conn, &mut reply).await;
            let got = parse_dns(&reply, id);
            if name == "secure.test" {
                assert_eq!(got, (ResponseCode::NoError, vec![SECURE_ADDR]));
            } else {
                assert_eq!(got, (ResponseCode::NXDomain, vec![]));
            }
        }
        // secure.test has its site; nope.test is asked about again.
        assert_eq!(env.calls.load(Ordering::SeqCst), 6 + 1);
        Ok(())
    });
}

/// A site is placed the first time its name is looked up, and a second
/// name under a top-level domain a placed site already uses still reaches
/// the callback.
#[test]
fn sites_are_placed_on_first_lookup_even_under_a_used_top_level_domain() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let record = asked.clone();
        let net = web::Sites::new(move |host| {
            record.lock().unwrap().push(host.to_owned());
            match host {
                "a.test" => Some(web::Site::new(Plain("a"))),
                "b.test" => Some(web::Site::new(Plain("b"))),
                _ => None,
            }
        })
        .into_net();
        let handle = net.handle();
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let m = default_machine(&fcx, &attacher);
        let first = Ipv4Addr::new(104, 18, 0, 1);
        assert!(!handle.has_machine(first.into()), "no site before a lookup");

        assert_eq!(lookup(&fcx, &m, "a.test").await, first);
        assert!(handle.has_machine(first.into()));
        let b = lookup(&fcx, &m, "b.test").await;
        assert_ne!(b, first);
        assert!(handle.has_machine(b.into()));
        let page = plain_client(&fcx, &m, b, false)
            .await
            .get("http", "b.test", "/")
            .await
            .body;
        assert!(page.starts_with("b "), "{page}");

        // Only the looked-up names are asked about, never `test` above
        // them, and a placed site's name is answered without asking again.
        assert_eq!(lookup(&fcx, &m, "a.test").await, first);
        assert_eq!(*asked.lock().unwrap(), ["a.test", "b.test"]);
        Ok(())
    });
}

/// One lookup places at most one site: a callback that opens a whole
/// domain is asked about the looked-up name alone, and the names above
/// it get no machine until they are looked up themselves.
#[test]
fn one_lookup_places_one_site() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let record = asked.clone();
        let net = web::Sites::new(move |host| {
            record.lock().unwrap().push(host.to_owned());
            host.ends_with(".wild.test")
                .then(|| web::Site::new(Plain("wild")))
        })
        .into_net();
        let handle = net.handle();
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let m = default_machine(&fcx, &attacher);
        let first = Ipv4Addr::new(104, 18, 0, 1);
        assert_eq!(lookup(&fcx, &m, "a.b.c.wild.test").await, first);
        assert_eq!(*asked.lock().unwrap(), ["a.b.c.wild.test"]);
        assert!(!handle.has_machine(Ipv4Addr::new(104, 18, 0, 2).into()));

        // A name above it exists, and gets its own site when looked up.
        assert_eq!(
            lookup(&fcx, &m, "c.wild.test").await,
            Ipv4Addr::new(104, 18, 0, 2)
        );
        assert_eq!(*asked.lock().unwrap(), ["a.b.c.wild.test", "c.wild.test"]);
        Ok(())
    });
}

/// A name the callback turned down, with a site below it, is asked about
/// again on each lookup, so it can come into being as the world runs.
#[test]
fn a_name_above_a_site_can_get_a_site_later() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (record, opened) = (asked.clone(), open.clone());
        let net = web::Sites::new(move |host| {
            record.lock().unwrap().push(host.to_owned());
            match host {
                "www.shop.test" => Some(web::Site::new(Plain("www"))),
                "shop.test" if opened.load(Ordering::SeqCst) => Some(web::Site::new(Plain("shop"))),
                _ => None,
            }
        })
        .into_net();
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let m = default_machine(&fcx, &attacher);
        lookup(&fcx, &m, "www.shop.test").await;
        assert_eq!(
            dns(&fcx, &m, "shop.test", RecordType::A).await,
            (ResponseCode::NoError, vec![]),
            "an empty non-terminal while the callback turns it down"
        );
        open.store(true, Ordering::SeqCst);
        // A new case, so the resolver's own cache does not answer it.
        assert_eq!(
            lookup(&fcx, &m, "SHOP.test").await,
            Ipv4Addr::new(104, 18, 0, 2)
        );
        assert_eq!(
            *asked.lock().unwrap(),
            ["www.shop.test", "shop.test", "shop.test"]
        );
        Ok(())
    });
}

/// A name another host declares below a site's name hides neither the
/// site nor the names above it.
#[test]
fn a_declared_name_below_a_site_leaves_the_site_to_the_callback() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let record = asked.clone();
        let net = web::Sites::new(move |host| {
            record.lock().unwrap().push(host.to_owned());
            (host == "shop.test").then(|| web::Site::new(Plain("shop")))
        })
        .into_net()
        .host("api", |h| h.dns_name("api.shop.test"));
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let m = default_machine(&fcx, &attacher);
        let api = lookup(&fcx, &m, "api.shop.test").await;
        let shop = lookup(&fcx, &m, "shop.test").await;
        assert_ne!(api, shop);
        // `test` has names below it, so it exists, without a site.
        assert_eq!(
            dns(&fcx, &m, "test", RecordType::NS).await,
            (ResponseCode::NoError, vec![])
        );
        assert_eq!(*asked.lock().unwrap(), ["shop.test", "test"]);
        Ok(())
    });
}

/// The callback decides names under the resolver's default zones too,
/// such as `home.arpa`.
#[test]
fn the_callback_decides_names_under_home_arpa() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let record = asked.clone();
        let net = web::Sites::new(move |host| {
            record.lock().unwrap().push(host.to_owned());
            (host == "nas.home.arpa").then(|| web::Site::new(Plain("nas")))
        })
        .into_net();
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let m = default_machine(&fcx, &attacher);
        lookup(&fcx, &m, "nas.home.arpa").await;
        assert!(asked.lock().unwrap().contains(&"nas.home.arpa".to_owned()));
        Ok(())
    });
}

/// The gateway answers pings, and its DNS connections count toward the
/// connections a peer may have open across the network.
#[test]
fn the_gateway_answers_pings_and_counts_toward_the_peer_limit() {
    run_world::world(Duration::from_secs(60), |fcx| async move {
        let net = web::Sites::new(|host| (host == "a.test").then(|| web::Site::new(Plain("a"))))
            .into_net()
            .limits(Limits {
                connections_per_peer: 2,
                ..Limits::default()
            });
        let (attacher, attachments) = fictionet::attachments();
        net.start(&fcx, attachments)?;
        let pinger = Ipv4Addr::new(10, 0, 0, 3);
        let mut raw = attacher.attach("pinger")?;
        raw.send(ping(pinger, GATEWAY, 1));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a ping reply");
        let (src, dst, protocol, body) = parse(&reply);
        assert_eq!((src, dst, protocol, body[0]), (GATEWAY, pinger, 1, 0));

        let m = default_machine(&fcx, &attacher);
        let site = lookup(&fcx, &m, "a.test").await;
        // Two DNS connections to the gateway, each answering a query.
        let mut connections = Vec::new();
        for id in [1u16, 2] {
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(GATEWAY.into(), 53))
                .await?;
            let mut q = Message::new(id, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(Name::from_ascii("a.test")?, RecordType::A));
            let bytes = q.to_vec()?;
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            conn.write_all(&fcx, &framed).await?;
            let mut len = [0u8; 2];
            read_exact(&fcx, &mut conn, &mut len).await;
            let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
            read_exact(&fcx, &mut conn, &mut reply).await;
            assert_eq!(parse_dns(&reply, id), (ResponseCode::NoError, vec![site]));
            connections.push(conn);
        }
        // They are the peer's two: a third connection, to the site, is
        // reset.
        let mut third = m
            .tcp
            .connect(&fcx, SocketAddr::new(site.into(), 80))
            .await?;
        let read = timeout(&fcx, Duration::from_secs(2), third.read(&fcx, &mut [0; 1]))
            .await
            .expect("an answer");
        assert!(matches!(read, Err(ConnError::Reset) | Ok(0)), "{read:?}");
        Ok(())
    });
}

pub(super) async fn read_exact<C: Connection>(fcx: &Cx, conn: &mut C, buf: &mut [u8]) {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(fcx, &mut buf[at..]).await.unwrap();
        assert!(n > 0, "the stream ended early");
        at += n;
    }
}

// ---------------------------------------------------------------------------
// Tests: DHCP

pub(super) fn dhcp_msg(kind: u8, xid: u32, mac: u8) -> dhcp::Message {
    let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, xid);
    m.chaddr[..6].copy_from_slice(&[2, 0, 0, 0, 0, mac]);
    m.push(dhcp::opt::MESSAGE_TYPE, [kind]);
    m
}

/// Sends a DHCP message from `src` to `dst` and returns the reply's IP
/// destination and message.
pub(super) async fn dhcp_ask(
    fcx: &Cx,
    end: &mut End,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    m: &dhcp::Message,
) -> Option<(Ipv4Addr, dhcp::Message)> {
    end.send(udp(src, 68, dst, 67, &m.to_bytes().unwrap()));
    let p = recv_within(fcx, end, SHORT).await?;
    let (from, to, proto, u) = parse(&p);
    assert_eq!((from, proto), (GATEWAY, 17));
    assert_eq!(&u[..4], &[0, 67, 0, 68]);
    let reply = dhcp::Message::parse(&u[8..]).expect("a DHCP message");
    assert_eq!(reply.op, dhcp::BOOTREPLY);
    assert_eq!(reply.xid, m.xid);
    assert_eq!(reply.chaddr, m.chaddr);
    Some((to, reply))
}

#[test]
fn dhcp_reply_bytes() {
    world(|fcx, attacher, _env| async move {
        let mut raw = attacher.attach("dhcp bytes").unwrap();
        for (kind, ciaddr, wanted, reply_kind, assigned) in [
            (dhcp::DISCOVER, [0; 4], None, 2, [10, 0, 0, 2]),
            (dhcp::REQUEST, [0; 4], Some([10, 0, 0, 2]), 5, [10, 0, 0, 2]),
            (dhcp::REQUEST, [10, 0, 0, 2], None, 5, [10, 0, 0, 2]),
            (dhcp::INFORM, [10, 0, 0, 2], None, 5, [0; 4]),
            (dhcp::REQUEST, [10, 0, 0, 2], Some([10, 0, 0, 1]), 6, [0; 4]),
        ] {
            let mut request = dhcp_msg(kind, 0x1234_5678, 1);
            request.htype = 7;
            request.hlen = 9;
            request.flags = 0x8000;
            request.ciaddr = ciaddr.into();
            request.giaddr = Ipv4Addr::new(10, 0, 0, 254);
            if let Some(wanted) = wanted {
                request.push(dhcp::opt::REQUESTED_IP, wanted);
            }
            raw.send(udp(
                ciaddr.into(),
                68,
                GATEWAY,
                67,
                &request.to_bytes().unwrap(),
            ));
            let packet = recv_within(&fcx, &mut raw, SHORT).await.unwrap();
            let (from, to, proto, datagram) = parse(&packet);
            assert_eq!((from, proto), (GATEWAY, 17));
            assert_eq!(
                to,
                if ciaddr == [0; 4] || reply_kind == 6 {
                    Ipv4Addr::BROADCAST
                } else {
                    ciaddr.into()
                }
            );
            let mut expected = vec![0; 240];
            expected[..12].copy_from_slice(&[2, 7, 9, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0x80, 0]);
            if kind == dhcp::INFORM {
                expected[12..16].copy_from_slice(&ciaddr);
            }
            expected[16..20].copy_from_slice(&assigned);
            expected[24..28].copy_from_slice(&[10, 0, 0, 254]);
            expected[28..44].copy_from_slice(&request.chaddr);
            expected[236..240].copy_from_slice(&[99, 130, 83, 99]);
            expected.extend_from_slice(&[53, 1, reply_kind, 54, 4, 10, 0, 0, 1]);
            if reply_kind != 6 {
                if kind != dhcp::INFORM {
                    expected.extend_from_slice(&[
                        51, 4, 0, 0, 14, 16, 58, 4, 0, 0, 7, 8, 59, 4, 0, 0, 12, 78,
                    ]);
                }
                expected.extend_from_slice(&[
                    1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 6, 4, 10, 0, 0, 1,
                ]);
            }
            expected.push(255);
            expected.resize(300, 0);
            assert_eq!(&datagram[8..], expected, "{kind}");
        }
        Ok(())
    });
}

#[test]
fn dhcp_rejects_bad_udp_checksum() {
    dhcp_rejects_udp(|u| {
        let checksum = u16::from_be_bytes([u[6], u[7]]);
        let bad = if checksum == 1 { 2 } else { checksum ^ 1 };
        u[6..8].copy_from_slice(&bad.to_be_bytes());
    });
}

#[test]
fn dhcp_rejects_bad_udp_length() {
    for len in [0u16, 7, u16::MAX] {
        dhcp_rejects_udp(move |u| {
            u[4..6].copy_from_slice(&len.to_be_bytes());
            // Isolate the length check from the checksum check.
            u[6..8].fill(0);
        });
    }
}

#[test]
fn dhcp_rejects_short_udp_header() {
    dhcp_rejects_udp(|u| u.truncate(7));
}

fn dhcp_rejects_udp(mutate: impl Fn(&mut Vec<u8>) + Copy + Send + 'static) {
    for dst in [Ipv4Addr::BROADCAST, GATEWAY] {
        for kind in [dhcp::DISCOVER, dhcp::REQUEST] {
            world(move |fcx, attacher, _env| async move {
                let any = Ipv4Addr::UNSPECIFIED;
                let addr = Ipv4Addr::new(10, 0, 0, 2);
                let mut a = attacher.attach("a").unwrap();
                let mut m = dhcp_msg(kind, 1, 1);
                m.push(dhcp::opt::REQUESTED_IP, addr.octets());
                let mut u = parse(&udp(any, 68, dst, 67, &m.to_bytes().unwrap())).3;
                mutate(&mut u);
                a.send(ipv4(any, dst, 17, &u));
                assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());
                // A malformed request with a static source must not fall
                // through to first-packet address binding either.
                a.send(ipv4(addr, dst, 17, &u));
                assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());

                // Keep a attached: rejection must neither hold an offer nor
                // bind the address. Another sandbox can claim it immediately.
                let mut b = attacher.attach("b").unwrap();
                let mut request = dhcp_msg(dhcp::REQUEST, 2, 2);
                request.push(dhcp::opt::REQUESTED_IP, addr.octets());
                let (_, ack) = dhcp_ask(&fcx, &mut b, any, dst, &request).await.unwrap();
                assert_eq!((ack.message_type(), ack.yiaddr), (Some(dhcp::ACK), addr));
                b.send(ping(addr, GATEWAY, 1));
                assert!(recv_within(&fcx, &mut b, SHORT).await.is_some());
                Ok(())
            });
        }
    }
}

#[test]
fn dhcp_accepts_zero_udp_checksum() {
    for dst in [Ipv4Addr::BROADCAST, GATEWAY] {
        world(move |fcx, attacher, _env| async move {
            let any = Ipv4Addr::UNSPECIFIED;
            let addr = Ipv4Addr::new(10, 0, 0, 2);
            let mut a = attacher.attach("a").unwrap();
            for (kind, reply_kind) in [(dhcp::DISCOVER, dhcp::OFFER), (dhcp::REQUEST, dhcp::ACK)] {
                let mut m = dhcp_msg(kind, kind.into(), 1);
                m.push(dhcp::opt::REQUESTED_IP, addr.octets());
                let mut u = parse(&udp(any, 68, dst, 67, &m.to_bytes().unwrap())).3;
                u[6..8].fill(0);
                a.send(ipv4(any, dst, 17, &u));
                let p = recv_within(&fcx, &mut a, SHORT).await.expect("a reply");
                let (from, to, proto, u) = parse(&p);
                assert_eq!((from, to, proto), (GATEWAY, Ipv4Addr::BROADCAST, 17));
                assert!(ip::udp_checksum_ok(from.into(), to.into(), &u));
                let reply = dhcp::Message::parse(&u[8..]).unwrap();
                assert_eq!(reply.xid, m.xid);
                assert_eq!(
                    (reply.message_type(), reply.yiaddr),
                    (Some(reply_kind), addr)
                );
            }
            a.send(ping(addr, GATEWAY, 1));
            assert!(recv_within(&fcx, &mut a, SHORT).await.is_some());
            Ok(())
        });
    }
}

#[test]
fn dhcp_lease_renewal_and_restart() {
    world(|fcx, attacher, _env| async move {
        let any = Ipv4Addr::UNSPECIFIED;
        let bc = Ipv4Addr::BROADCAST;
        let mut a = attacher.attach("a").unwrap();

        // DISCOVER from 0.0.0.0: OFFER of the lowest free address, with the
        // settings.
        let (to, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 1, 1))
            .await
            .expect("an offer");
        assert_eq!(to, bc);
        assert_eq!(offer.message_type(), Some(dhcp::OFFER));
        let addr = offer.yiaddr;
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(offer.option_addr(dhcp::opt::SERVER_ID), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::ROUTER), Some(GATEWAY));
        assert_eq!(offer.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        assert_eq!(
            offer.option_addr(dhcp::opt::SUBNET_MASK),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(offer.option_u32(dhcp::opt::LEASE_TIME), Some(3600));

        // The offer is held: another sandbox cannot bind it statically.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(addr, GATEWAY, 1));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        // b's own DISCOVER gets the next address, even if it asks for a's.
        let mut discover = dhcp_msg(dhcp::DISCOVER, 2, 2);
        discover.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, offer_b) = dhcp_ask(&fcx, &mut b, any, bc, &discover).await.unwrap();
        assert_eq!(offer_b.yiaddr, Ipv4Addr::new(10, 0, 0, 3));
        // b asking to bind a's address: NAK.
        let mut request = dhcp_msg(dhcp::REQUEST, 3, 2);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, nak) = dhcp_ask(&fcx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));

        // a takes its offer.
        let mut request = dhcp_msg(dhcp::REQUEST, 4, 1);
        request.push(dhcp::opt::REQUESTED_IP, addr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (to, ack) = dhcp_ask(&fcx, &mut a, any, bc, &request).await.unwrap();
        assert_eq!(to, bc);
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        assert_eq!(ack.yiaddr, addr);

        // Bound: pings from the address work, from others do not.
        a.send(ping(addr, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        a.send(ping(Ipv4Addr::new(10, 0, 0, 9), GATEWAY, 3));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());

        // Renewal: unicast from the address, with ciaddr. ACK to the address.
        let mut renew = dhcp_msg(dhcp::REQUEST, 5, 1);
        renew.ciaddr = addr;
        let (to, ack) = dhcp_ask(&fcx, &mut a, addr, GATEWAY, &renew).await.unwrap();
        assert_eq!(
            (to, ack.message_type(), ack.yiaddr),
            (addr, Some(dhcp::ACK), addr)
        );
        // Rebinding: broadcast from the address.
        let (_, ack) = dhcp_ask(&fcx, &mut a, addr, bc, &renew).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));

        // DHCP from an address that is not a's: dropped.
        let mut other = dhcp_msg(dhcp::REQUEST, 6, 1);
        other.ciaddr = Ipv4Addr::new(10, 0, 0, 9);
        assert!(
            dhcp_ask(&fcx, &mut a, Ipv4Addr::new(10, 0, 0, 9), GATEWAY, &other)
                .await
                .is_none()
        );

        // Restart: from 0.0.0.0 again, the same address.
        let (_, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 7, 1))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, addr);
        // INIT-REBOOT for another address: NAK; for its own: ACK.
        let mut reboot = dhcp_msg(dhcp::REQUEST, 8, 1);
        reboot.push(
            dhcp::opt::REQUESTED_IP,
            Ipv4Addr::new(10, 0, 0, 20).octets(),
        );
        let (_, nak) = dhcp_ask(&fcx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!(nak.message_type(), Some(dhcp::NAK));
        let mut reboot = dhcp_msg(dhcp::REQUEST, 9, 1);
        reboot.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut a, any, bc, &reboot).await.unwrap();
        assert_eq!((ack.message_type(), ack.yiaddr), (Some(dhcp::ACK), addr));
        // The agent changing its MAC does not get it a second address.
        let (_, offer) = dhcp_ask(&fcx, &mut a, any, bc, &dhcp_msg(dhcp::DISCOVER, 10, 99))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, addr);

        // A REQUEST naming another server is ignored.
        let mut elsewhere = dhcp_msg(dhcp::REQUEST, 11, 3);
        elsewhere.push(
            dhcp::opt::REQUESTED_IP,
            Ipv4Addr::new(10, 0, 0, 30).octets(),
        );
        elsewhere.push(dhcp::opt::SERVER_ID, Ipv4Addr::new(10, 0, 0, 254).octets());
        assert!(dhcp_ask(&fcx, &mut b, any, bc, &elsewhere).await.is_none());

        // b takes its offer; then a detaches, and a new sandbox asking for
        // a's old address gets it.
        let mut request = dhcp_msg(dhcp::REQUEST, 12, 2);
        request.push(dhcp::opt::REQUESTED_IP, offer_b.yiaddr.octets());
        request.push(dhcp::opt::SERVER_ID, GATEWAY.octets());
        let (_, ack) = dhcp_ask(&fcx, &mut b, any, bc, &request).await.unwrap();
        assert_eq!(ack.message_type(), Some(dhcp::ACK));
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        fcx.idle().await?;
        let mut d = dhcp_msg(dhcp::DISCOVER, 100, 4);
        d.push(dhcp::opt::REQUESTED_IP, addr.octets());
        let (_, offer) = dhcp_ask(&fcx, &mut c, any, bc, &d).await.unwrap();
        assert_eq!(offer.yiaddr, addr, "a's address is free once a detached");

        // INFORM from a static address: an ACK with the settings and no lease.
        let mut d = attacher.attach("d").unwrap();
        let d_addr = Ipv4Addr::new(10, 0, 0, 40);
        d.send(ping(d_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut d, Duration::from_secs(2))
                .await
                .is_some()
        );
        let mut inform = dhcp_msg(dhcp::INFORM, 13, 5);
        inform.ciaddr = d_addr;
        let (to, ack) = dhcp_ask(&fcx, &mut d, d_addr, GATEWAY, &inform)
            .await
            .unwrap();
        assert_eq!(
            (to, ack.message_type(), ack.yiaddr),
            (d_addr, Some(dhcp::ACK), Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(ack.option_u32(dhcp::opt::LEASE_TIME), None);
        assert_eq!(ack.option_addr(dhcp::opt::DNS), Some(GATEWAY));
        // And DHCP to the server from a static sandbox asking for a lease
        // gets its static address.
        let (_, offer) = dhcp_ask(&fcx, &mut d, any, bc, &dhcp_msg(dhcp::DISCOVER, 14, 5))
            .await
            .unwrap();
        assert_eq!(offer.yiaddr, d_addr);
        Ok(())
    });
}

#[test]
fn dhcp_messages_round_trip() {
    let mut m = dhcp_msg(dhcp::REQUEST, 0xdeadbeef, 7);
    m.ciaddr = Ipv4Addr::new(10, 0, 0, 5);
    m.push(dhcp::opt::REQUESTED_IP, [10, 0, 0, 5]);
    m.push(200, vec![1; 300]); // longer than one option entry
    let bytes = m.to_bytes().unwrap();
    assert!(bytes.len() >= 300);
    assert_eq!(dhcp::Message::parse(&bytes), Ok(m));
    assert_eq!(dhcp::Message::parse(&bytes[..239]), Err(dhcp::Error::Short));
}

/// A sandbox with a static address whose first packet is a DHCPINFORM gets
/// the settings, and the INFORM binds nothing.
#[test]
fn dhcp_inform_as_the_first_packet_is_answered() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 9);
        let mut a = attacher.attach("a").unwrap();
        let mut m = dhcp_msg(dhcp::INFORM, 7, 1);
        m.ciaddr = me;
        let (to, reply) = dhcp_ask(&fcx, &mut a, me, GATEWAY, &m)
            .await
            .expect("an answer to INFORM");
        assert_eq!(to, me);
        assert_eq!(reply.message_type(), Some(dhcp::ACK));
        assert_eq!(reply.option_addr(dhcp::opt::DNS), Some(GATEWAY));

        // Not bound: another sandbox can still take 10.0.0.9.
        let mut b = attacher.attach("b").unwrap();
        b.send(ping(me, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_some(),
            "b binds 10.0.0.9"
        );
        // Now a's INFORM from 10.0.0.9 is not answered, and neither is its ping.
        assert!(dhcp_ask(&fcx, &mut a, me, GATEWAY, &m).await.is_none());
        a.send(ping(me, GATEWAY, 2));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());
        Ok(())
    });
}
