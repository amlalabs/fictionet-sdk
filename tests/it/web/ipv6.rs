use super::admission::{ACK, RST, SYN};
use super::dns_dhcp::read_exact;
use super::events::{
    Log, addr, answer, blocked_seen, dns_seen, flag, http_seen, local, outcome, picked, sandbox_of,
    seen, tls_seen, wait_for, world_events,
};
use super::*;

// ---------------------------------------------------------------------------
// Tests: IPv6

const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const ME6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// An address no site has, outside the sandboxes' subnet.
const NOWHERE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x99, 0, 0, 0, 0, 1);

fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Packet {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    Packet(p)
}

/// An IPv6 packet carrying `data`, with its checksum at `at` filled in.
fn checksummed6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, mut data: Vec<u8>, at: usize) -> Packet {
    let c = ip::transport_checksum(src.into(), dst.into(), next, &data);
    data[at..at + 2].copy_from_slice(&c.to_be_bytes());
    ipv6(src, dst, next, &data)
}

pub(super) fn ping6(src: Ipv6Addr, dst: Ipv6Addr, seq: u16) -> Packet {
    let mut icmp = vec![128, 0, 0, 0, 0x12, 0x34];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"fictionet");
    checksummed6(src, dst, 58, icmp, 2)
}

fn udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    checksummed6(src, dst, 17, u, 6)
}

fn syn6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16) -> Packet {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&dport.to_be_bytes());
    t.extend_from_slice(&1000u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&[0x50, SYN, 0xff, 0xff, 0, 0, 0, 0]);
    checksummed6(src, dst, 6, t, 16)
}

/// (src, dst, next header, payload) of an IPv6 packet with no extension
/// headers, checking the upper layer's checksum.
pub(super) fn parse6(p: &Packet) -> (Ipv6Addr, Ipv6Addr, u8, Vec<u8>) {
    let b = &p.0;
    assert_eq!(b[0] >> 4, 6);
    let len = u16::from_be_bytes([b[4], b[5]]) as usize;
    assert_eq!(b.len(), 40 + len, "the payload length");
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap());
    let payload = b[40..].to_vec();
    assert_eq!(
        ip::transport_checksum(src.into(), dst.into(), b[6], &payload),
        0,
        "the checksum"
    );
    (src, dst, b[6], payload)
}

/// A DNS query for `name` from `me` to `server` on a raw attachment, over
/// IPv6: the answer's code and addresses, or `None` if none came within
/// 2 s.
async fn raw_dns6(
    fcx: &Cx,
    raw: &mut End,
    me: Ipv6Addr,
    server: Ipv6Addr,
    name: &str,
    kind: RecordType,
) -> Option<(ResponseCode, Vec<IpAddr>)> {
    let id = fcx.random_u64() as u16;
    let mut q = Message::new(id, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    raw.send(udp6(me, 5353, server, 53, &q.to_vec().unwrap()));
    loop {
        let p = recv_within(fcx, raw, Duration::from_secs(2)).await?;
        let (src, _, next, u) = parse6(&p);
        if src == server && next == 17 {
            return Some(parse_dns_all(&u[8..], id));
        }
    }
}

/// Like [`parse_dns`], with AAAA records too.
fn parse_dns_all(bytes: &[u8], id: u16) -> (ResponseCode, Vec<IpAddr>) {
    let r = Message::from_vec(bytes).unwrap();
    assert_eq!(r.metadata.id, id);
    assert_eq!(r.metadata.message_type, MessageType::Response);
    let addrs = r
        .answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect();
    (r.metadata.response_code, addrs)
}

/// Asks `server`'s DNS over UDP from `m`, over either IP version. Returns
/// the response code and the A and AAAA records.
async fn dns_at(
    fcx: &Cx,
    m: &Machine,
    server: IpAddr,
    name: &str,
    kind: RecordType,
) -> (ResponseCode, Vec<IpAddr>) {
    let mut socket = m.udp.bind(0).unwrap();
    let mut q = Message::new(fcx.random_u64() as u16, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(server, 53));
    let (bytes, from) = timeout(fcx, Duration::from_secs(5), socket.recv(fcx))
        .await
        .expect("a DNS answer")
        .unwrap();
    assert_eq!(from, SocketAddr::new(server, 53));
    parse_dns_all(&bytes, q.metadata.id)
}

#[test]
fn dns_answers_aaaa_for_each_family_a_site_has() {
    world(|fcx, attacher, env| async move {
        let m = default_machine(&fcx, &attacher);
        let gw = IpAddr::V4(GATEWAY);
        let ok = |addrs: &[IpAddr]| (ResponseCode::NoError, addrs.to_vec());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());

        // A site with only an IPv4 `at` gets an automatic IPv6 address,
        // from 2001:2::/48, and keeps it.
        assert_eq!(
            dns_at(&fcx, &m, gw, "secure.test", RecordType::AAAA).await,
            ok(&[v6("2001:2::1")])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "secure.test", RecordType::A).await,
            ok(&[SECURE_ADDR.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "SECURE.test.", RecordType::AAAA).await,
            ok(&[v6("2001:2::1")])
        );
        // A site at two addresses of its own.
        assert_eq!(
            dns_at(&fcx, &m, gw, "dual.test", RecordType::A).await,
            ok(&[DUAL_ADDR.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "dual.test", RecordType::AAAA).await,
            ok(&[DUAL_ADDR6.into()])
        );
        // Sites of one family: NODATA for the other.
        assert_eq!(
            dns_at(&fcx, &m, gw, "v4only.test", RecordType::AAAA).await,
            ok(&[])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v4only.test", RecordType::A).await,
            ok(&[Ipv4Addr::new(198, 18, 0, 1).into()])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v6only.test", RecordType::A).await,
            ok(&[])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "v6only.test", RecordType::AAAA).await,
            ok(&[V6ONLY_ADDR6.into()])
        );
        // An address inside the sandboxes' IPv6 subnet, and a name with no
        // site: NXDOMAIN for both types.
        for name in ["inside6.test", "nope.test"] {
            for kind in [RecordType::A, RecordType::AAAA] {
                assert_eq!(
                    dns_at(&fcx, &m, gw, name, kind).await,
                    (ResponseCode::NXDomain, vec![]),
                    "{name} {kind}"
                );
            }
        }
        // The callback ran once per name.
        assert_eq!(env.calls.load(Ordering::SeqCst), 6);

        // DNS also answers at the gateway's IPv6 address, over UDP and TCP.
        let m6 = machine(&fcx, attacher.attach("b").unwrap(), ME6);
        assert_eq!(
            dns_at(&fcx, &m6, GATEWAY6.into(), "dual.test", RecordType::AAAA).await,
            ok(&[DUAL_ADDR6.into()])
        );
        assert_eq!(
            dns_at(&fcx, &m6, GATEWAY6.into(), "dual.test", RecordType::A).await,
            ok(&[DUAL_ADDR.into()])
        );
        let mut conn = m6
            .tcp
            .connect(&fcx, SocketAddr::new(GATEWAY6.into(), 53))
            .await
            .unwrap();
        let mut q = Message::new(77, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("v6only.test").unwrap(),
            RecordType::AAAA,
        ));
        let bytes = q.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&fcx, &framed).await.unwrap();
        let mut len = [0u8; 2];
        read_exact(&fcx, &mut conn, &mut len).await;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        read_exact(&fcx, &mut conn, &mut reply).await;
        assert_eq!(parse_dns_all(&reply, 77), ok(&[V6ONLY_ADDR6.into()]));
        Ok(())
    });
}

fn endpoint_scoped_sites(shared_v6: bool, defaults: bool) {
    for distinct in [false, true] {
        run_world::world(Duration::from_secs(60), move |fcx| async move {
            let v4: IpAddr = "203.0.113.8".parse()?;
            let v6: IpAddr = "2001:db8:1::8".parse()?;
            let (shared, other, separate) = if shared_v6 {
                (v6, v4, "203.0.113.9".parse::<IpAddr>()?)
            } else {
                (v4, v6, "2001:db8:1::9".parse::<IpAddr>()?)
            };
            let date = SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000);
            let certs = certs(&fcx, &["a.test", "b.test", "c.test"]);
            let roots = Arc::new(certs.roots);
            let config = Arc::new(
                tls::config_builder(&fcx, date)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(certs.chain, certs.key)
                    .unwrap(),
            );
            let (attacher, attachments) = fictionet::attachments();
            web::Sites::new(move |name| {
                let site = match name {
                    "a.test" => web::Site::new(Plain("a")).at(shared).at(other),
                    "b.test" => {
                        let site = web::Site::new(Plain("b")).at(shared);
                        let site = if distinct {
                            site.at(separate)
                        } else if shared_v6 {
                            site.ipv6_only()
                        } else {
                            site.ipv4_only()
                        };
                        if defaults { site.default_host() } else { site }
                    }
                    "c.test" if defaults => {
                        let site = web::Site::new(Plain("c")).at(other).default_host();
                        if shared_v6 {
                            site.ipv4_only()
                        } else {
                            site.ipv6_only()
                        }
                    }
                    _ => return None,
                };
                Some(site.tls(config.clone()).plain_http())
            })
            .start(&fcx, attachments)?;
            let m4 = default_machine(&fcx, &attacher);
            let m6 = machine(&fcx, attacher.attach("b")?, ME6);
            assert_eq!(
                dns_at(&fcx, &m4, GATEWAY.into(), "a.test", RecordType::A)
                    .await
                    .0,
                ResponseCode::NoError
            );
            let m = if shared_v6 { &m6 } else { &m4 };
            let mut existing = plain_client(&fcx, m, shared, false).await;
            assert_eq!(
                existing.get("http", "b.test", "/").await.status,
                StatusCode::MISDIRECTED_REQUEST
            );
            for name in ["b.test", "c.test"]
                .into_iter()
                .take(if defaults { 2 } else { 1 })
            {
                assert_eq!(
                    dns_at(&fcx, &m4, GATEWAY.into(), name, RecordType::A)
                        .await
                        .0,
                    ResponseCode::NoError
                );
            }
            assert!(
                existing
                    .get("http", "b.test", "/")
                    .await
                    .body
                    .starts_with("b ")
            );
            for addr in [shared, other, separate]
                .into_iter()
                .take(if distinct { 3 } else { 2 })
            {
                let m = if addr.is_ipv4() { &m4 } else { &m6 };
                for secure in [false, true] {
                    for h2 in [false, true] {
                        let (mut client, scheme) = if secure {
                            let tcp = m.tcp.connect(&fcx, SocketAddr::new(addr, 443)).await?;
                            let sni = if addr == separate { "b.test" } else { "a.test" };
                            let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
                            let conn = TlsClient::new(&fcx, tcp, &roots, sni, alpn, date)?;
                            (Client::new(&fcx, conn, h2).await, "https")
                        } else {
                            (plain_client(&fcx, m, addr, h2).await, "http")
                        };
                        for name in ["a.test", "b.test", "B.TeSt.", "unknown.test"] {
                            let exact = match name {
                                "a.test" if addr != separate => Some("a"),
                                "b.test" | "B.TeSt." if addr != other => Some("b"),
                                _ => None,
                            };
                            let expected = exact.or_else(|| {
                                defaults.then_some(if addr == other { "c" } else { "b" })
                            });
                            let got = client.get(scheme, name, "/").await;
                            match expected {
                                Some(label) => {
                                    assert_eq!(
                                        got.status,
                                        StatusCode::OK,
                                        "{addr} {scheme} {name}"
                                    );
                                    assert!(
                                        got.body.starts_with(&format!("{label} ")),
                                        "{addr} {scheme} {name}: {}",
                                        got.body
                                    );
                                }
                                None => assert_eq!(
                                    got.status,
                                    StatusCode::MISDIRECTED_REQUEST,
                                    "{addr} {scheme} {name}"
                                ),
                            }
                        }
                    }
                }
            }
            Ok(())
        });
    }
}

#[test]
fn late_host_failure_keeps_http_defaults_names_and_tls_unchanged() {
    use fictionet::stdlib::codec::{Ending, LineError, Lines};
    use fictionet::stdlib::services::serve::{Driver, Flow, Service};
    use fictionet::stdlib::web::httpd;
    use fictionet::stdlib::world::net::{Host, Net};

    struct Quiet;
    impl Service for Quiet {
        type Decoder = Lines;
        type State = ();
        type Error = Infallible;
        fn decoder(&self) -> Lines {
            Lines::new(64, Ending::LfOrCrlf)
        }
        fn on_item(
            &mut self,
            _: Result<Vec<u8>, LineError>,
            _: &(),
            _: &mut Driver<'_, Lines>,
        ) -> Result<Flow, Infallible> {
            Ok(Flow::Continue)
        }
    }

    run_world::world(Duration::from_secs(60), |fcx| async move {
        let v4: IpAddr = "203.0.113.8".parse()?;
        let v6: IpAddr = "2001:db8:1::8".parse()?;
        let date = SystemTime::UNIX_EPOCH + Duration::from_secs(1_893_456_000);
        let certs = certs(&fcx, &["first.test", "bad.test", "good.test"]);
        let roots = Arc::new(certs.roots);
        let config = Arc::new(
            tls::config_builder(&fcx, date)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs.chain, certs.key)
                .unwrap(),
        );
        let site = |label: &'static str, default| {
            let config = config.clone();
            let server = httpd::Server::new(
                httpd::Router::new().get("/", move |_, _| Response::new(label.into())),
            )
            .tls_with(move |_| config.clone())
            .plain_http();
            if default {
                server.default_host()
            } else {
                server
            }
        };
        let first =
            site("first", false).served_by(Host::new("first").dns_name("first.test").at(v4).at(v6));
        // Only IPv6 has an ephemeral socket at 49152. IPv4 preparation
        // succeeds before the rejected declaration reaches that conflict.
        let occupied = Host::new("occupied")
            .at(v6)
            .ipv6_only()
            .udp(0, Arc::new(()), || Quiet);
        let bad = site("bad", true)
            .served_by(Host::new("bad").at(v4).at(v6))
            .udp(49152, Arc::new(()), || Quiet);
        let good = site("good", false).served_by(Host::new("good").at(v4).at(v6));
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .add_host(first)
            .add_host(occupied)
            .resolve(move |name| match name {
                "bad.test" => Some(bad.clone()),
                "good.test" => Some(good.clone()),
                _ => None,
            })
            .start(&fcx, attachments)?;
        let m4 = default_machine(&fcx, &attacher);
        let m6 = machine(&fcx, attacher.attach("b")?, ME6);
        let mut existing = plain_client(&fcx, &m4, v4, false).await;
        assert_eq!(existing.get("http", "first.test", "/").await.body, "first");
        assert_eq!(
            dns(&fcx, &m4, "bad.test", RecordType::A).await.0,
            ResponseCode::NXDomain
        );
        assert_eq!(
            existing.get("http", "bad.test", "/").await.status,
            StatusCode::MISDIRECTED_REQUEST
        );
        for (m, addr) in [(&m4, v4), (&m6, v6)] {
            for secure in [false, true] {
                let (mut client, scheme) = if secure {
                    let tcp = m.tcp.connect(&fcx, SocketAddr::new(addr, 443)).await?;
                    let conn =
                        TlsClient::new(&fcx, tcp, &roots, "first.test", &[b"http/1.1"], date)?;
                    (Client::new(&fcx, conn, false).await, "https")
                } else {
                    (plain_client(&fcx, m, addr, false).await, "http")
                };
                assert_eq!(client.get(scheme, "first.test", "/").await.body, "first");
                for name in ["bad.test", "unknown.test"] {
                    assert_eq!(
                        client.get(scheme, name, "/").await.status,
                        StatusCode::MISDIRECTED_REQUEST
                    );
                }
            }
            let tcp = m.tcp.connect(&fcx, SocketAddr::new(addr, 443)).await?;
            let mut conn = TlsClient::new(&fcx, tcp, &roots, "bad.test", &[b"http/1.1"], date)?;
            assert!(conn.handshake(&fcx).await.is_err());
        }
        assert_eq!(lookup(&fcx, &m4, "good.test").await, v4);
        assert_eq!(existing.get("http", "good.test", "/").await.body, "good");
        Ok(())
    });
}

#[test]
fn shared_ipv4_keeps_ipv6_virtual_hosts_local() {
    endpoint_scoped_sites(false, false);
}

#[test]
fn shared_ipv6_keeps_ipv4_virtual_hosts_local() {
    endpoint_scoped_sites(true, false);
}

#[test]
fn shared_ipv4_keeps_defaults_local() {
    endpoint_scoped_sites(false, true);
}

#[test]
fn shared_ipv6_keeps_defaults_local() {
    endpoint_scoped_sites(true, true);
}

#[test]
fn https_http2_and_plain_http_over_ipv6() {
    world_events(|fcx, attacher, env, log| async move {
        let m = machine(&fcx, attacher.attach("a").unwrap(), ME6);
        let (_, addrs) = dns_at(&fcx, &m, GATEWAY6.into(), "dual.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(DUAL_ADDR6)]);

        // HTTP/2 and HTTP/1.1 over TLS, to the site's IPv6 address.
        let conn = tls_connect(
            &fcx,
            &m,
            &env,
            DUAL_ADDR6,
            "dual.test",
            &[b"h2", b"http/1.1"],
        )
        .await
        .unwrap();
        assert_eq!(conn.tls.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Client::new(&fcx, conn, true).await;
        let got = client.get("https", "dual.test", "/").await;
        assert_eq!((got.status, got.version), (StatusCode::OK, Version::HTTP_2));
        assert_eq!(got.body, "secure https dual.test 443 HTTP/2.0 #1");
        let conn = tls_connect(&fcx, &m, &env, DUAL_ADDR6, "dual.test", &[b"http/1.1"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("https", "dual.test", "/").await.body,
            "secure https dual.test 443 HTTP/1.1 #2"
        );

        // The site keeps its state across families: it is one site.
        let m4 = machine(
            &fcx,
            attacher.attach("b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let conn = tls_connect(&fcx, &m4, &env, DUAL_ADDR, "dual.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "dual.test", "/").await.body,
            "secure https dual.test 443 HTTP/2.0 #3"
        );

        // An IPv6-only site.
        let (_, addrs) = dns_at(&fcx, &m, GATEWAY6.into(), "v6only.test", RecordType::AAAA).await;
        assert_eq!(addrs, vec![IpAddr::V6(V6ONLY_ADDR6)]);
        let conn = tls_connect(&fcx, &m, &env, V6ONLY_ADDR6, "v6only.test", &[b"h2"])
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, true).await;
        assert_eq!(
            client.get("https", "v6only.test", "/").await.body,
            "secure https v6only.test 443 HTTP/2.0 #4"
        );

        // Port 80: a TLS site redirects to https. A plain site at its
        // automatic IPv6 address answers. A request that names the bare
        // address in brackets gets 421, as it would over IPv4.
        let mut client = plain_client(&fcx, &m, DUAL_ADDR6, false).await;
        let got = client.get("http", "dual.test", "/a?b").await;
        assert_eq!(got.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(got.headers["location"], "https://dual.test/a?b");
        let (_, plain) = dns_at(&fcx, &m, GATEWAY6.into(), "plain.test", RecordType::AAAA).await;
        let conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(plain[0], 80))
            .await
            .unwrap();
        let mut client = Client::new(&fcx, conn, false).await;
        assert_eq!(
            client.get("http", "plain.test", "/q").await.body,
            "plain http plain.test 80 HTTP/1.1 /q"
        );
        let got = client.get("http", &format!("[{}]", plain[0]), "/q").await;
        assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST);

        // A TLS handshake to the bare address carries no SNI, and is
        // rejected.
        let tcp = m
            .tcp
            .connect(&fcx, SocketAddr::new(DUAL_ADDR6.into(), 443))
            .await
            .unwrap();
        let mut bare = TlsClient::new(
            &fcx,
            tcp,
            &env.roots,
            &DUAL_ADDR6.to_string(),
            &[],
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_893_456_000),
        )
        .unwrap();
        assert!(bare.handshake(&fcx).await.is_err());

        // The events name the IPv6 addresses.
        let tls = wait_for(&fcx, &log, 5, tls_seen).await;
        assert_eq!(addr(&tls[0], "addr"), Some(IpAddr::V6(DUAL_ADDR6)));
        assert_eq!(sandbox_of(&tls[0]).unwrap().addr_v6, Some(ME6));
        assert_eq!(sandbox_of(&tls[0]).unwrap().addr, None);
        assert_eq!(
            (addr(&tls[4], "addr"), outcome(&tls[4])),
            (Some(IpAddr::V6(DUAL_ADDR6)), "rejected".to_owned())
        );
        let http = wait_for(&fcx, &log, 7, http_seen).await;
        assert_eq!(local(&http[0]), SocketAddr::new(DUAL_ADDR6.into(), 443));
        assert_eq!(local(&http[2]), SocketAddr::new(DUAL_ADDR.into(), 443));
        assert_eq!(
            sandbox_of(&http[2]).unwrap().addr,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        let dns = wait_for(&fcx, &log, 3, dns_seen).await;
        assert_eq!(answer(&dns[0]), format!("addr {DUAL_ADDR6}"));
        assert_eq!(dns[0].u64("qtype"), Some(28));
        Ok(())
    });
}

#[test]
fn ipv6_pings_closed_ports_and_unknown_addresses() {
    world(|fcx, attacher, _env| async move {
        let mut raw = attacher.attach("a").unwrap();
        let reply = |p: Packet| parse6(&p);

        // The gateway answers pings.
        raw.send(ping6(ME6, GATEWAY6, 1));
        let (src, dst, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, dst, next, icmp[0]), (GATEWAY6, ME6, 58, 129));

        // An address that no site has: ICMPv6 address unreachable, at once,
        // from the gateway, quoting the packet.
        let sent = ping6(ME6, NOWHERE6, 2);
        raw.send(sent.clone());
        let (src, dst, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .expect("unreachable"),
        );
        assert_eq!((src, dst, next), (GATEWAY6, ME6, 58));
        assert_eq!((icmp[0], icmp[1]), (1, 3));
        assert_eq!(&icmp[8..], &sent.0[..]);

        // Once its name is looked up, a site's IPv6 address answers pings.
        let (code, addrs) = raw_dns6(
            &fcx,
            &mut raw,
            ME6,
            GATEWAY6,
            "plain.test",
            RecordType::AAAA,
        )
        .await
        .expect("DNS answers");
        assert_eq!(code, ResponseCode::NoError);
        let IpAddr::V6(plain) = addrs[0] else {
            panic!("{addrs:?}")
        };
        raw.send(ping6(ME6, plain, 3));
        let (src, _, _, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((src, icmp[0]), (plain, 129));

        // A closed TCP port gets a RST; UDP gets port unreachable.
        raw.send(syn6(ME6, 30_000, plain, 22));
        let (_, _, next, t) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, t[13] & RST), (6, RST));
        raw.send(udp6(ME6, 1000, plain, 9999, b"hi"));
        let (_, _, next, icmp) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, icmp[0], icmp[1]), (58, 1, 4));
        // Port 80 is open.
        raw.send(syn6(ME6, 30_001, plain, 80));
        let (_, _, next, t) = reply(
            recv_within(&fcx, &mut raw, Duration::from_secs(2))
                .await
                .unwrap(),
        );
        assert_eq!((next, t[13] & (SYN | ACK)), (6, SYN | ACK));

        // No error for an ICMPv6 error, or for a router solicitation from a
        // link-local address to all routers.
        let mut err = vec![1, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(&sent.0[..48]);
        raw.send(checksummed6(ME6, NOWHERE6, 58, err, 2));
        let rs = checksummed6(
            "fe80::1".parse().unwrap(),
            "ff02::2".parse().unwrap(),
            58,
            vec![133, 0, 0, 0, 0, 0, 0, 0],
            2,
        );
        raw.send(rs);
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        Ok(())
    });
}

#[test]
fn ipv6_addresses_are_bound_to_one_sandbox() {
    world_events(|fcx, attacher, _env, log| async move {
        let me4 = Ipv4Addr::new(10, 0, 0, 2);
        let mut a = attacher.attach("a").unwrap();
        // What a Linux sandbox sends first: a router solicitation from its
        // link-local address. It is dropped, and binds nothing.
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        a.send(checksummed6(
            link_local,
            "ff02::2".parse().unwrap(),
            58,
            vec![133, 0, 0, 0, 0, 0, 0, 0],
            2,
        ));
        // Then its global address: bound. Then its IPv4 address: bound too.
        a.send(ping6(ME6, GATEWAY6, 1));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        a.send(ping(me4, GATEWAY, 2));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some()
        );
        // Another source, another sandbox, an address with no site.
        a.send(ping6("2001:db8::9".parse().unwrap(), GATEWAY6, 3));
        a.send(ping6(ME6, "2001:db8::3".parse().unwrap(), 4));
        a.send(ping6(link_local, GATEWAY6, 5));
        a.send(ping6(ME6, NOWHERE6, 6));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_secs(2))
                .await
                .is_some(),
            "unreachable"
        );

        // A second sandbox cannot take the first one's address, the
        // gateway's, the subnet's first address, or one outside the subnet.
        let mut b = attacher.attach("b").unwrap();
        for src in [
            ME6,
            GATEWAY6,
            "2001:db8::".parse().unwrap(),
            "2001:db8:1::5".parse().unwrap(),
        ] {
            b.send(ping6(src, GATEWAY6, 7));
        }
        assert!(recv_within(&fcx, &mut b, SHORT).await.is_none());

        let got = wait_for(&fcx, &log, 9, blocked_seen).await;
        let summary: Vec<_> = got
            .iter()
            .map(|b| {
                (
                    &*sandbox_of(b).unwrap().name,
                    b.str("why").unwrap(),
                    sandbox_of(b).unwrap().addr_v6,
                    addr(b, "src"),
                    addr(b, "dst"),
                )
            })
            .collect();
        let v6 = |a: Ipv6Addr| Some(IpAddr::V6(a));
        assert_eq!(
            summary,
            vec![
                (
                    "a",
                    "Broadcast",
                    None,
                    v6(link_local),
                    v6("ff02::2".parse().unwrap())
                ),
                (
                    "a",
                    "NotItsAddress",
                    Some(ME6),
                    v6("2001:db8::9".parse().unwrap()),
                    v6(GATEWAY6)
                ),
                (
                    "a",
                    "OtherSandbox",
                    Some(ME6),
                    v6(ME6),
                    v6("2001:db8::3".parse().unwrap())
                ),
                (
                    "a",
                    "NotItsAddress",
                    Some(ME6),
                    v6(link_local),
                    v6(GATEWAY6)
                ),
                ("a", "NoRoute", Some(ME6), v6(ME6), v6(NOWHERE6)),
                ("b", "NotItsAddress", None, v6(ME6), v6(GATEWAY6)),
                ("b", "NotItsAddress", None, v6(GATEWAY6), v6(GATEWAY6)),
                (
                    "b",
                    "NotItsAddress",
                    None,
                    v6("2001:db8::".parse().unwrap()),
                    v6(GATEWAY6)
                ),
                (
                    "b",
                    "NotItsAddress",
                    None,
                    v6("2001:db8:1::5".parse().unwrap()),
                    v6(GATEWAY6)
                ),
            ]
        );
        assert_eq!(got.len(), 9, "{got:#?}");

        // One `bound` for each family, and a `detached` that names both.
        drop(a);
        wait_for(&fcx, &log, 1, seen("net", "detached")).await;
        let a_events = picked(&log, |e| {
            (e.source == "net" && e.kind != "blocked" && &*sandbox_of(e)?.name == "a")
                .then(|| e.clone())
        });
        let kinds: Vec<_> = a_events.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            ["attached", "bound", "bound", "detached"],
            "{a_events:#?}"
        );
        let at = |e: &Entry| sandbox_of(e).map(|s| (s.addr, s.addr_v6));
        assert!(!flag(&a_events[1], "by_dhcp"));
        assert_eq!(at(&a_events[1]), Some((None, Some(ME6))));
        assert_eq!(at(&a_events[2]), Some((Some(me4), Some(ME6))));
        assert_eq!(at(&a_events[3]), Some((Some(me4), Some(ME6))));

        // Now the address is free, and the second sandbox can take it.
        b.send(ping6(ME6, GATEWAY6, 8));
        let (src, dst, _, icmp) = parse6(
            &recv_within(&fcx, &mut b, Duration::from_secs(2))
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, dst, icmp[0]), (GATEWAY6, ME6, 129));
        Ok(())
    });
}

/// Runs a world whose network `make` builds, with every event kept.
fn world_of<F, Fut>(make: impl FnOnce() -> web::Sites + Send + 'static, f: F)
where
    F: FnOnce(Cx, Attacher, Log) -> Fut + Send + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    run_world::observed_world(Duration::from_secs(60), move |fcx, evidence| async move {
        let (attacher, attachments) = fictionet::attachments();
        make().start(&fcx, attachments)?;
        let log = Log::new(evidence);
        f(fcx, attacher, log).await?;
        Ok(())
    });
}

#[test]
fn an_ipv4_only_network_drops_ipv6_and_answers_aaaa_with_nodata() {
    let make = || {
        web::Sites::new(|host| match host {
            "six.test" => Some(web::Site::new(Plain("six")).ipv6_only()),
            h => h
                .ends_with(".test")
                .then(|| web::Site::new(Plain("auto")).at(DUAL_ADDR6)),
        })
        .ipv4_only()
    };
    world_of(make, |fcx, attacher, log| async move {
        let m = default_machine(&fcx, &attacher);
        let gw = IpAddr::V4(GATEWAY);
        // An IPv6 `at` is not used: the site gets an automatic IPv4 address.
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::A).await,
            (
                ResponseCode::NoError,
                vec![Ipv4Addr::new(198, 18, 0, 1).into()]
            )
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        // An IPv6-only site has no address at all.
        assert_eq!(
            dns_at(&fcx, &m, gw, "six.test", RecordType::AAAA).await,
            (ResponseCode::NXDomain, vec![])
        );

        let mut raw = attacher.attach("b").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_none());
        let got = wait_for(&fcx, &log, 1, blocked_seen).await;
        assert_eq!(
            (got[0].str("why"), addr(&got[0], "dst")),
            (Some("Ipv6"), Some(IpAddr::V6(GATEWAY6)))
        );
        Ok(())
    });
}

#[test]
fn automatic_ipv6_addresses_skip_the_sandboxes_subnet() {
    // A subnet inside 2001:2::/48: automatic addresses jump past it.
    let make = || {
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet("2001:2::/64".parse().unwrap())
    };
    world_of(make, |fcx, attacher, _log| async move {
        let (gw, me): (Ipv6Addr, Ipv6Addr) =
            ("2001:2::1".parse().unwrap(), "2001:2::2".parse().unwrap());
        let mut raw = attacher.attach("a").unwrap();
        let (_, first) = raw_dns6(&fcx, &mut raw, me, gw, "one.test", RecordType::AAAA)
            .await
            .expect("DNS answers");
        assert_eq!(first, vec![IpAddr::V6("2001:2:0:1::".parse().unwrap())]);
        let (_, second) = raw_dns6(&fcx, &mut raw, me, gw, "two.test", RecordType::AAAA)
            .await
            .expect("DNS answers");
        assert_eq!(second, vec![IpAddr::V6("2001:2:0:1::1".parse().unwrap())]);
        let IpAddr::V6(site) = first[0] else {
            unreachable!()
        };
        raw.send(ping6(me, site, 1));
        let (src, _, _, icmp) = parse6(
            &recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("an echo reply"),
        );
        assert_eq!((src, icmp[0]), (site, 129));
        Ok(())
    });

    // A subnet that covers all of 2001:2::/48 leaves no automatic IPv6
    // addresses. Sites then have IPv4 only.
    let make = || {
        web::Sites::new(|host| {
            host.ends_with(".test")
                .then(|| web::Site::new(Plain("auto")))
        })
        .subnet("2001::/16".parse().unwrap())
    };
    world_of(make, |fcx, attacher, _log| async move {
        let m = default_machine(&fcx, &attacher);
        let gw = IpAddr::V4(GATEWAY);
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::AAAA).await,
            (ResponseCode::NoError, vec![])
        );
        assert_eq!(
            dns_at(&fcx, &m, gw, "one.test", RecordType::A).await,
            (
                ResponseCode::NoError,
                vec![Ipv4Addr::new(198, 18, 0, 1).into()]
            )
        );
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Tests: IPv6 fragments, extension headers and checksums from the agent

/// An IPv6 fragment: `data` at byte `offset` of packet `id`, whose
/// fragment header names `next`.
fn fragment6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u32,
    offset: u16,
    more: bool,
    next: u8,
    data: &[u8],
) -> Packet {
    let mut body = vec![next, 0];
    body.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(data);
    ipv6(src, dst, 44, &body)
}

/// An echo request to the gateway with 16 bytes of data, `data`, whole.
fn echo6_with(data: &[u8; 16]) -> Packet {
    let mut echo = vec![128, 0, 0, 0, 0x12, 0x34, 0, 1];
    echo.extend_from_slice(data);
    checksummed6(ME6, GATEWAY6, 58, echo, 2)
}

/// `packet` with `header` (an extension header) put in front of its
/// payload. `header[0]` must name the payload's protocol.
fn with_header(packet: &Packet, next: u8, header: &[u8]) -> Packet {
    let mut body = header.to_vec();
    body.extend_from_slice(&packet.0[40..]);
    ipv6(ME6, GATEWAY6, next, &body)
}

/// A sandbox that sent the first fragment of a packet and detached leaves
/// nothing behind: the next sandbox to take its address cannot complete
/// that packet and read its data.
#[test]
fn fragments_do_not_outlive_their_sandbox() {
    world(|fcx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(fragment6(
            ME6,
            GATEWAY6,
            12345,
            0,
            true,
            58,
            &whole.0[40..56],
        ));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(20))
                .await
                .is_none()
        );
        drop(a);
        // b takes the address once a's filter has let it go.
        let mut b = attacher.attach("b").unwrap();
        let other = bind_by_ping(&fcx, &mut b, ME6.into(), GATEWAY6.into()).await;
        assert!(other.is_empty(), "packets arrived while b bound: {other:?}");
        b.send(fragment6(
            ME6,
            GATEWAY6,
            12345,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_none(),
            "a's fragment completed b's packet"
        );
        // b's own fragments still make a packet.
        let mine = echo6_with(b"b's own packet!!");
        b.send(fragment6(ME6, GATEWAY6, 777, 0, true, 58, &mine.0[40..56]));
        b.send(fragment6(ME6, GATEWAY6, 777, 16, false, 58, &mine.0[56..]));
        let reply = recv_within(&fcx, &mut b, SHORT)
            .await
            .expect("an echo reply");
        let (_, dst, next, body) = parse6(&reply);
        assert_eq!((dst, next, body[0]), (ME6, 58, 129));
        assert_eq!(&body[8..], b"b's own packet!!");
        Ok(())
    });
}

/// A fragment at the same place as one already waiting, with other bytes,
/// drops the whole packet (RFC 5722), and its later fragments cannot start
/// it again.
#[test]
fn conflicting_fragments_drop_the_packet() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let whole = echo6_with(b"abcdefghABCDEFGH");
        let first = &whole.0[40..56];
        let mut conflicting = first.to_vec();
        conflicting[8] ^= 0xff;
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, &conflicting));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9876,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a packet with conflicting fragments was delivered"
        );
        // The same fragments again, without the conflict: still dropped.
        raw.send(fragment6(ME6, GATEWAY6, 9876, 0, true, 58, first));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9876,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a dropped packet was started again"
        );
        // An exact copy of a fragment is not a conflict.
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(ME6, GATEWAY6, 9877, 0, true, 58, first));
        raw.send(fragment6(
            ME6,
            GATEWAY6,
            9877,
            16,
            false,
            58,
            &whole.0[56..],
        ));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("an echo reply");
        let (_, _, next, body) = parse6(&reply);
        assert_eq!((next, body[0]), (58, 129));
        assert_eq!(&body[8..], b"abcdefghABCDEFGH");
        Ok(())
    });
}

/// TCP behind extension headers that ask nothing of the host is accepted,
/// at the gateway and at a site.
#[test]
fn tcp_behind_extension_headers_is_accepted() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let headers: [(u8, [u8; 8]); 3] = [
            (60, [6, 0, 0, 0, 0, 0, 0, 0]),    // Destination Options: Pad1 only.
            (0, [6, 0, 1, 4, 0, 0, 0, 0]),     // Hop-by-Hop: PadN.
            (60, [6, 0, 0x1e, 4, 1, 2, 3, 4]), // An unknown option to skip.
        ];
        for (i, (next, header)) in headers.into_iter().enumerate() {
            let syn = syn6(ME6, 40000 + i as u16, GATEWAY6, 53);
            raw.send(with_header(&syn, next, &header));
            let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("a reply");
            let (_, dst, proto, body) = parse6(&reply);
            assert_eq!((dst, proto), (ME6, 6), "header {i}");
            assert_eq!(u16::from_be_bytes([body[2], body[3]]), 40000 + i as u16);
            assert_eq!(body[13], SYN | ACK, "header {i}: the flags");
        }
        // A site's machine: look one up, then send it a SYN behind
        // Destination Options.
        let (_, addrs) = raw_dns6(
            &fcx,
            &mut raw,
            ME6,
            GATEWAY6,
            "plain.test",
            RecordType::AAAA,
        )
        .await
        .unwrap();
        let IpAddr::V6(site) = addrs[0] else {
            panic!("an AAAA record")
        };
        let syn = syn6(ME6, 41000, site, 80);
        let mut body = vec![6, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&syn.0[40..]);
        raw.send(ipv6(ME6, site, 60, &body));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a reply from the site");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[13]), (site, 6, SYN | ACK));
        Ok(())
    });
}

/// Extension headers a host must not accept are not delivered (RFC 8200,
/// sections 4.1 to 4.4). Where the RFC asks for it, the sender gets an
/// ICMPv6 "parameter problem" that points at the byte at fault.
#[test]
fn extension_headers_a_host_must_refuse_are_refused() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let ping = ping6(ME6, GATEWAY6, 7);
        // An unknown option whose type says to discard: nothing comes back.
        raw.send(with_header(&ping, 60, &[58, 0, 0x40, 0, 0, 0, 0, 0]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a discard option was delivered"
        );
        // (next header, header, code, pointer)
        let refused: [(u8, Vec<u8>, u8, u32); 4] = [
            // An unknown routing type with a segment left: points at the type.
            (43, vec![58, 0, 250, 1, 0, 0, 0, 0], 0, 42),
            // An unknown option whose type says to answer: points at it.
            (60, vec![58, 0, 1, 0, 0x80, 0, 0, 0], 2, 44),
            (60, vec![58, 0, 0xc2, 4, 0, 0, 0, 0], 2, 42),
            // Hop-by-Hop after Destination Options: points at the byte that
            // names it.
            (
                60,
                vec![0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0],
                1,
                40,
            ),
        ];
        for (next, header, code, pointer) in refused {
            let sent = with_header(&ping, next, &header);
            raw.send(sent.clone());
            let reply = recv_within(&fcx, &mut raw, SHORT)
                .await
                .expect("a parameter problem");
            let (src, dst, proto, body) = parse6(&reply);
            assert_eq!((src, dst, proto), (GATEWAY6, ME6, 58));
            assert_eq!((body[0], body[1]), (4, code), "{header:?}");
            assert_eq!(
                u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                pointer,
                "{header:?}"
            );
            assert_eq!(&body[8..], &sent.0[..], "the packet is quoted");
            assert!(
                recv_within(&fcx, &mut raw, Duration::from_millis(50))
                    .await
                    .is_none(),
                "{header:?} was delivered too"
            );
        }
        // A routing header with no segments left asks nothing of the host.
        raw.send(with_header(&ping, 43, &[58, 0, 250, 0, 0, 0, 0, 0]));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("an echo reply");
        assert_eq!(parse6(&reply).3[0], 129);
        Ok(())
    });
}

/// A UDP checksum field of zero means "no checksum" only over IPv4. Over
/// IPv6, DNS drops it, even when the sum over the datagram comes out right.
#[test]
fn dns_drops_a_zero_udp_checksum_over_ipv6() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("plain.test").unwrap(),
            RecordType::AAAA,
        ));
        let mut bytes = q.to_vec().unwrap();
        let mut u = vec![0x14, 0xe9, 0, 53];
        u.extend_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(&bytes);
        // Choose the DNS id so that the sum over the datagram, with the
        // checksum field zero, is right.
        let id = ip::transport_checksum(ME6.into(), GATEWAY6.into(), 17, &u);
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        u[8..].copy_from_slice(&bytes);
        assert_eq!(
            ip::transport_checksum(ME6.into(), GATEWAY6.into(), 17, &u),
            0
        );
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a zero UDP checksum was accepted over IPv6"
        );
        // The same datagram as a sender must send it: 0xffff for a sum of
        // zero. That is answered.
        u[6..8].copy_from_slice(&[0xff, 0xff]);
        raw.send(ipv6(ME6, GATEWAY6, 17, &u));
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a DNS answer");
        let (_, _, next, body) = parse6(&reply);
        assert_eq!(next, 17);
        let answer = Message::from_vec(&body[8..]).unwrap();
        assert_eq!((answer.metadata.id, answer.answers.len()), (id, 1));
        Ok(())
    });
}

/// A callback that gives every name a site makes no more than
/// `max_sites` of them. Past that, a new name gets SERVFAIL and no machine,
/// and the names that have sites keep working.
#[test]
fn dns_makes_no_more_sites_than_the_limit() {
    let make =
        || web::Sites::new(|_| Some(web::Site::new(Plain("wildcard")).ipv6_only())).max_sites(8);
    world_of(make, |fcx, attacher, log| async move {
        let mut raw = attacher.attach("a").unwrap();
        for i in 0..8 {
            // A questions make the site too, and get NODATA.
            let answer = raw_dns6(
                &fcx,
                &mut raw,
                ME6,
                GATEWAY6,
                &format!("n{i}.test"),
                RecordType::A,
            )
            .await
            .unwrap();
            assert_eq!(answer, (ResponseCode::NoError, vec![]));
        }
        for name in ["n8.test", "n9.test", "n8.test"] {
            let answer = raw_dns6(&fcx, &mut raw, ME6, GATEWAY6, name, RecordType::AAAA)
                .await
                .unwrap();
            assert_eq!(answer, (ResponseCode::ServFail, vec![]), "{name}");
        }
        assert_eq!(
            picked(&log, dns_seen)
                .iter()
                .filter(|d| answer(d) == "error 2")
                .count(),
            3
        );
        // The first eight still answer, and have machines.
        let site0 = Ipv6Addr::from(u128::from("2001:2::".parse::<Ipv6Addr>().unwrap()) + 1);
        let answer = raw_dns6(&fcx, &mut raw, ME6, GATEWAY6, "n0.test", RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(answer, (ResponseCode::NoError, vec![site0.into()]));
        let base = u128::from("2001:2::".parse::<Ipv6Addr>().unwrap());
        for i in 1..=9u16 {
            let addr = Ipv6Addr::from(base + u128::from(i));
            raw.send(ping6(ME6, addr, i));
            let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("a reply");
            let (src, _, _, body) = parse6(&reply);
            if i <= 8 {
                assert_eq!((src, body[0]), (addr, 129), "site {i} answers pings");
            } else {
                // No ninth machine: the gateway says "address unreachable".
                assert_eq!((src, body[0], body[1]), (GATEWAY6, 1, 3));
            }
        }
        Ok(())
    });
}

/// An atomic fragment (offset 0, no more) that holds `inner`, itself a
/// fragment.
fn nested6(outer_id: u32, inner: &Packet) -> Packet {
    let mut body = vec![44, 0, 0, 0];
    body.extend_from_slice(&outer_id.to_be_bytes());
    body.extend_from_slice(&inner.0[40..]);
    ipv6(ME6, GATEWAY6, 44, &body)
}

/// A fragment inside a fragment is dropped, so it never waits anywhere a
/// later sandbox could complete it.
#[test]
fn a_fragment_inside_a_fragment_is_dropped() {
    world(|fcx, attacher, _| async move {
        let mut a = attacher.attach("a").unwrap();
        let whole = echo6_with(b"SECRET-Atailtail");
        a.send(nested6(
            1,
            &fragment6(ME6, GATEWAY6, 4242, 0, true, 58, &whole.0[40..56]),
        ));
        assert!(
            recv_within(&fcx, &mut a, Duration::from_millis(20))
                .await
                .is_none()
        );
        drop(a);
        let mut b = attacher.attach("b").unwrap();
        let other = bind_by_ping(&fcx, &mut b, ME6.into(), GATEWAY6.into()).await;
        assert!(other.is_empty(), "packets arrived while b bound: {other:?}");
        b.send(nested6(
            2,
            &fragment6(ME6, GATEWAY6, 4242, 16, false, 58, &whole.0[56..]),
        ));
        assert!(
            recv_within(&fcx, &mut b, SHORT).await.is_none(),
            "a nested fragment completed a's packet"
        );
        Ok(())
    });
}

/// The headers in front of every fragment are checked, not only the first
/// fragment's, and a first fragment must hold the whole chain (RFC 7112).
#[test]
fn every_fragments_headers_are_checked() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        // The last fragment behind Hop-by-Hop with an option that says to
        // discard: the packet is never delivered.
        let whole = echo6_with(b"0123456789abcdef");
        raw.send(fragment6(ME6, GATEWAY6, 31, 0, true, 58, &whole.0[40..56]));
        let last = fragment6(ME6, GATEWAY6, 31, 16, false, 58, &whole.0[56..]);
        let mut body = vec![44, 0, 0x40, 0, 0, 0, 0, 0];
        body.extend_from_slice(&last.0[40..]);
        raw.send(ipv6(ME6, GATEWAY6, 0, &body));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a discard option on a later fragment was ignored"
        );
        // A Destination Options header cut in two by the fragments: the
        // first fragment gets "parameter problem" code 3, pointer 0.
        let mut dest = vec![58, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        dest.extend_from_slice(&whole.0[40..]);
        let first = fragment6(ME6, GATEWAY6, 32, 0, true, 60, &dest[..8]);
        raw.send(first.clone());
        let reply = recv_within(&fcx, &mut raw, SHORT)
            .await
            .expect("a parameter problem");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 4, 3));
        assert_eq!(&body[4..8], &[0, 0, 0, 0]);
        raw.send(fragment6(ME6, GATEWAY6, 32, 8, false, 60, &dest[8..]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a split chain was delivered"
        );
        Ok(())
    });
}

/// A redirect gets no "parameter problem", whatever its headers say
/// (RFC 4443, section 2.4).
#[test]
fn a_redirect_gets_no_parameter_problem() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_some());
        let redirect = checksummed6(
            ME6,
            GATEWAY6,
            58,
            [vec![137, 0, 0, 0], vec![0; 36]].concat(),
            2,
        );
        raw.send(with_header(&redirect, 60, &[58, 0, 0x80, 0, 0, 0, 0, 0]));
        assert!(
            recv_within(&fcx, &mut raw, SHORT).await.is_none(),
            "a redirect got an error"
        );
        Ok(())
    });
}

/// A packet to an address no machine has gets "address unreachable" from
/// the gateway, whatever its extension headers say: there is no host there
/// to answer "parameter problem".
#[test]
fn refused_headers_to_nowhere_get_address_unreachable() {
    world(|fcx, attacher, _| async move {
        let mut raw = attacher.attach("a").unwrap();
        raw.send(ping6(ME6, GATEWAY6, 1));
        assert!(recv_within(&fcx, &mut raw, SHORT).await.is_some());
        let ping = ping6(ME6, NOWHERE6, 2);
        let mut body = vec![58, 0, 250, 1, 0, 0, 0, 0];
        body.extend_from_slice(&ping.0[40..]);
        raw.send(ipv6(ME6, NOWHERE6, 43, &body));
        let reply = recv_within(&fcx, &mut raw, SHORT).await.expect("an answer");
        let (src, _, proto, body) = parse6(&reply);
        assert_eq!((src, proto, body[0], body[1]), (GATEWAY6, 58, 1, 3));
        assert!(
            recv_within(&fcx, &mut raw, Duration::from_millis(50))
                .await
                .is_none()
        );
        Ok(())
    });
}
