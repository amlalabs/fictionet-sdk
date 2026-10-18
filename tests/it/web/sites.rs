use super::*;
use fictionet::RunOptions;

// ---------------------------------------------------------------------------
// Tests: routing, unreachable, isolation, binding

#[test]
fn unknown_addresses_get_host_unreachable_and_sites_appear_on_lookup() {
    world(|fcx, attacher, _env| async move {
        let me = Ipv4Addr::new(10, 0, 0, 2);
        let mut raw = attacher.attach("a").unwrap();

        // An address that no site has: ICMP host unreachable, at once, from
        // the gateway, quoting the packet.
        let sent = ping(me, Ipv4Addr::new(192, 0, 2, 1), 1);
        raw.send(sent.clone());
        let reply = recv_within(&fcx, &mut raw, Duration::from_secs(2))
            .await
            .expect("host unreachable");
        let (src, dst, proto, icmp) = parse(&reply);
        assert_eq!((src, dst, proto), (GATEWAY, me, 1));
        assert_eq!((icmp[0], icmp[1]), (3, 1));
        assert_eq!(ip::checksum(&icmp), 0, "ICMP checksum");
        assert_eq!(&icmp[8..], &sent.0[..]);

        // A site's address before its name was looked up: unreachable too.
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 2));
        let (_, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((icmp[0], icmp[1]), (3, 1));

        // Look the name up (raw DNS over UDP), then the address answers.
        let mut q = Message::new(99, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::A,
        ));
        raw.send(udp(me, 5353, GATEWAY, 53, &q.to_vec().unwrap()));
        let (src, _, proto, u) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, proto), (GATEWAY, 17));
        assert_eq!(
            parse_dns(&u[8..], 99),
            (ResponseCode::NoError, vec![Ipv4Addr::new(198, 18, 0, 1)])
        );
        raw.send(ping(me, Ipv4Addr::new(198, 18, 0, 1), 3));
        let (src, dst, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!(
            (src, dst, icmp[0]),
            (Ipv4Addr::new(198, 18, 0, 1), me, 0),
            "an echo reply from the site"
        );

        // The gateway answers pings.
        raw.send(ping(me, GATEWAY, 4));
        let (src, _, _, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (GATEWAY, 0));

        // UDP to a site: port unreachable, so clients fail at once.
        raw.send(udp(me, 5000, Ipv4Addr::new(198, 18, 0, 1), 9999, b"x"));
        let (_, _, proto, icmp) = parse(
            &recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((proto, icmp[0], icmp[1]), (1, 3, 3));

        // An ICMP error gets no ICMP error back. IPv6 to the unspecified
        // address is dropped.
        let mut err = vec![3, 1, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..28]);
        let c = ip::checksum(&err);
        err[2..4].copy_from_slice(&c.to_be_bytes());
        raw.send(ipv4(me, Ipv4Addr::new(192, 0, 2, 1), 1, &err));
        let mut v6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        v6.extend_from_slice(&[0; 32]);
        raw.send(Packet(v6));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn sandboxes_cannot_reach_each_other() {
    world(|fcx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();
        // Both bind their addresses with a ping to the gateway.
        a.send(ping(a_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        b.send(ping(b_addr, GATEWAY, 1));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );

        // a to b: nothing arrives at b, and a hears nothing back.
        a.send(ping(a_addr, b_addr, 2));
        a.send(udp(a_addr, 1000, b_addr, 2000, b"hello"));
        // Nor to the subnet's broadcast address, or 255.255.255.255.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 255), 3));
        a.send(udp(a_addr, 1000, Ipv4Addr::BROADCAST, 2000, b"hello"));
        // Nor to an address in the subnet that no one has.
        a.send(ping(a_addr, Ipv4Addr::new(10, 0, 0, 77), 4));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(10))
                .await
                .is_none()
        );

        // Both still reach the gateway.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );
        Ok(())
    });
}

#[test]
fn spoofed_and_taken_sources_are_dropped() {
    world(|fcx, attacher, _env| async move {
        let (a_addr, b_addr) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3));
        let mut a = attacher.attach("a").unwrap();
        let mut b = attacher.attach("b").unwrap();

        // Sources a sandbox can never bind: outside the subnet, the
        // gateway, the network and broadcast addresses, 0.0.0.0.
        for src in [
            Ipv4Addr::new(192, 168, 1, 5),
            GATEWAY,
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
        ] {
            a.send(ping(src, GATEWAY, 1));
        }
        a.send(ping(Ipv4Addr::UNSPECIFIED, GATEWAY, 1));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());

        // a binds 10.0.0.2.
        a.send(ping(a_addr, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        // b cannot take it.
        b.send(ping(a_addr, GATEWAY, 3));
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(10))
                .await
                .is_none()
        );
        // a cannot send from any other address now.
        a.send(ping(b_addr, GATEWAY, 4));
        assert!(recv_within(&fcx, &mut a, SHORT).await.is_none());
        // b binds 10.0.0.3, which a just tried to use.
        b.send(ping(b_addr, GATEWAY, 5));
        assert!(
            recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .is_some()
        );

        // When a detaches, its address is free again.
        drop(a);
        let mut c = attacher.attach("c").unwrap();
        let mut freed = false;
        for seq in 0..50 {
            c.send(ping(a_addr, GATEWAY, seq));
            if recv_within(&fcx, &mut c, Duration::from_millis(50))
                .await
                .is_some()
            {
                freed = true;
                break;
            }
        }
        assert!(freed, "10.0.0.2 should be free once a detached");
        Ok(())
    });
}

#[test]
fn a_subnet_that_cannot_work_is_an_error() {
    let result = within(Duration::from_secs(10), || {
        block_on(lab(RunOptions::new(Seed::from_u64(1)), |fcx| async move {
            for bad in [
                "10.0.0.0/31",
                "10.0.0.0/4",
                "fe80::/64",
                "ff00::/8",
                "::/8",
                "2001:db8::/127",
                "2001:db8::/4",
            ] {
                let (_attacher, attachments) = fictionet::attachments();
                let r = web::Sites::new(|_| None)
                    .subnet(bad.parse()?)
                    .start(&fcx, attachments);
                assert!(r.is_err(), "{bad}");
            }
            // Another subnet works, with its gateway at .1.
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(|_| None)
                .subnet("172.16.5.0/24".parse()?)
                .start(&fcx, attachments)?;
            let mut a = attacher.attach("a").unwrap();
            let gw = Ipv4Addr::new(172, 16, 5, 1);
            a.send(ping(Ipv4Addr::new(172, 16, 5, 9), gw, 1));
            let (src, _, _, icmp) = parse(
                &recv_within(&fcx, &mut a, Duration::from_secs(2))
                    .await
                    .unwrap(),
            );
            assert_eq!((src, icmp[0]), (gw, 0));
            Err(fictionet::Error::from(Done))
        }))
    });
    assert!(result.unwrap_err().downcast_ref::<Done>().is_some());
}

#[test]
fn the_sites_keep_running_after_the_world_returns() {
    // The world returns Ok at once; the test plays the sandbox from a
    // thread of its own.
    let (attacher, attachments) = fictionet::attachments();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = block_on(run(
            RunOptions::new(fictionet::Seed::random()),
            move |fcx| async move {
                web::Sites::new(|h| (h == "plain.test").then(|| web::Site::new(Plain("plain"))))
                    .start(&fcx, attachments)?;
                let _ = tx.send(fcx.clone());
                Ok(())
            },
        ));
        let _ = r;
    });
    let fcx = rx.recv().unwrap();
    let mut a = attacher.attach("a").unwrap();
    let me = Ipv4Addr::new(10, 0, 0, 2);
    a.send(ping(me, GATEWAY, 1));
    let reply = within(Duration::from_secs(5), move || {
        block_on(async move { timeout(&fcx, Duration::from_secs(2), a.recv(&fcx)).await })
    });
    let (src, _, _, icmp) = parse(&reply.expect("a reply").unwrap());
    assert_eq!((src, icmp[0]), (GATEWAY, 0));
}

#[test]
fn the_target_is_from_the_connection_not_the_headers() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let addr = lookup(&fcx, &m, "secure.test").await;
        let conn = tls_connect(&fcx, &m, &env, addr, "secure.test", &[b"http/1.1"])
            .await
            .unwrap();
        let Client::H1(mut send) = Client::new(&fcx, conn, false).await else {
            unreachable!()
        };
        // An absolute URI with another scheme and port, and forwarding
        // headers: the Target still says https, secure.test, 443.
        send.ready().await.unwrap();
        let request = Request::get("http://secure.test:8080/")
            .header("host", "secure.test:8080")
            .header("x-forwarded-proto", "http")
            .header("forwarded", "proto=http;host=evil.test")
            .body(Empty::new())
            .unwrap();
        let response = send.send_request(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).starts_with("secure https secure.test 443 HTTP/1.1"),
            "{body:?}"
        );
        let _ = IpAddr::from(addr);
        Ok(())
    });
}

/// Runs a world whose sites use `subnet`, with every `.test` name a plain
/// site at an automatic address.
fn world_on_subnet<F, Fut>(subnet: &str, f: F)
where
    F: FnOnce(Cx, Attacher) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    let subnet: fictionet::stdlib::network::route::Prefix = subnet.parse().unwrap();
    run_world::world(Duration::from_secs(60), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet(subnet)
        .start(&fcx, attachments)?;
        f(fcx, attacher).await?;
        Ok(())
    });
}

/// A DNS A query from `me` to `gw` on a raw attachment: the answer's code
/// and addresses, or `None` if none came within 2 s.
pub(super) async fn raw_dns(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv4Addr,
    gw: Ipv4Addr,
    name: &str,
    id: u16,
) -> Option<(ResponseCode, Vec<Ipv4Addr>)> {
    let mut q = Message::new(id, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    raw.send(udp(me, 5353, gw, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2)).await?;
        let (src, _, proto, u) = parse(&p);
        if src == gw && proto == 17 {
            return Some(parse_dns(&u[8..], id));
        }
    }
}

/// A subnet inside `198.18.0.0/15`: automatic addresses skip it, so the
/// first site does not take the gateway's address and DNS keeps answering.
#[test]
fn automatic_addresses_skip_the_sandboxes_subnet() {
    world_on_subnet("198.18.0.0/24", |fcx, attacher| async move {
        let gw = Ipv4Addr::new(198, 18, 0, 1);
        let me = Ipv4Addr::new(198, 18, 0, 2);
        let mut raw = attacher.attach("a").unwrap();
        let (code, first) = raw_dns(&fcx, &mut raw, me, gw, "one.test", 1)
            .await
            .expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(first, vec![Ipv4Addr::new(198, 18, 1, 0)]);
        let (_, second) = raw_dns(&fcx, &mut raw, me, gw, "two.test", 2)
            .await
            .expect("DNS still answers");
        assert_eq!(second, vec![Ipv4Addr::new(198, 18, 1, 1)]);
        // The gateway still answers pings, and so does the site.
        for (to, seq) in [(gw, 1), (first[0], 2)] {
            raw.send(ping(me, to, seq));
            let p = recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("an echo reply");
            let (from, _, proto, icmp) = parse(&p);
            assert_eq!((from, proto, icmp[0]), (to, 1, 0));
        }
        Ok(())
    });
}
