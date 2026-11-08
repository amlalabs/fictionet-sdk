use super::*;
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::op::{Edns, OpCode, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Record, RecordSet};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode};
use fictionet::stdlib::services::dns::authority::{ServerConfig, Zones};
use fictionet::stdlib::services::dns::resolver::{Config, LocalZone};
use fictionet::stdlib::services::dns::zone::Zone;
use fictionet::stdlib::services::dns::{Client, Event, Looked, Lookup, WallClock};
use fictionet::stdlib::world::net::dns::{
    Authoritative, Namespace, Only, Recursive, ResolverHandle, Upstream,
};
use fictionet::stdlib::world::net::{Lan, Pools};
use fictionet_test_support::ended_with_done;
use fictionet_test_support::lookup_authority::LookupAuthority;

// ---------------------------------------------------------------------------
// A network: a PLC and a web server

const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PLC_ADDR: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 5);

async fn lookup(fcx: &Cx, s: &Machine, name: &str) -> Option<Ipv4Addr> {
    let mut socket = s.udp.bind(0).ok()?;
    let mut q = Message::query();
    q.metadata.id = 5;
    q.add_query(Query::query(Name::from_ascii(name).ok()?, RecordType::A));
    socket.send_to(&q.to_vec().ok()?, SocketAddr::new(GATEWAY.into(), 53));
    let (bytes, _) = timeout(fcx, Duration::from_secs(2), socket.recv(fcx))
        .await?
        .ok()?;
    let r = Message::from_vec(&bytes).ok()?;
    r.answers.iter().find_map(|a| match &a.data {
        RData::A(a) => Some(a.0),
        _ => None,
    })
}

type Registrations = Vec<(SocketAddr, Vec<String>)>;

#[derive(Clone, Default)]
struct Sharing {
    installed: Arc<Mutex<Registrations>>,
    reject: Option<SocketAddr>,
}

impl PortServer for Sharing {
    fn serve(&self, _: Cx, _: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }

    fn prepare_share(
        &self,
        local: SocketAddr,
        names: &[String],
        _: &Arc<dyn PortServer>,
    ) -> Option<PreparedShare> {
        if self.reject == Some(local) && names.iter().any(|n| n == "bad.test") {
            return None;
        }
        let installed = self.installed.clone();
        let names = names.to_vec();
        Some(PreparedShare::new(move || {
            installed.lock().unwrap().push((local, names));
        }))
    }
}

#[test]
fn port_sharing_prepares_without_mutation_and_defaults_to_identity() {
    let local = "203.0.113.8:80".parse().unwrap();
    let first: Arc<dyn PortServer> = Arc::new(Spy::default());
    let other: Arc<dyn PortServer> = Arc::new(Spy::default());
    first.prepare_share(local, &[], &first).unwrap().commit();
    assert!(first.prepare_share(local, &[], &other).is_none());

    let server = Sharing::default();
    let names = vec!["one.test".to_owned()];
    let cancelled = server.prepare_share(local, &names, &other).unwrap();
    let committed = server.prepare_share(local, &names, &other).unwrap();
    assert!(server.installed.lock().unwrap().is_empty());
    drop(cancelled);
    assert!(server.installed.lock().unwrap().is_empty());
    committed.commit();
    assert_eq!(*server.installed.lock().unwrap(), [(local, names)]);
}

/// A name declared inside one of the gateway's default zones, such as
/// `home.arpa`, answers, as Unbound puts the operator's data into its
/// default zone; the zone's other names still do not exist. The rest of
/// `arpa` stays out of the declared zones: with no internet, a public
/// reverse lookup fails as it does in any world.
#[test]
fn a_name_declared_under_home_arpa_answers() {
    world(Duration::from_secs(60), move |fcx| async move {
        let nas = Ipv4Addr::new(10, 30, 0, 5);
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("nas", |h| h.at(nas).dns_name("nas.home.arpa"))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        assert_eq!(lookup(&fcx, &m, "nas.home.arpa").await, Some(nas));
        assert_eq!(lookup(&fcx, &m, "printer.home.arpa").await, None);
        let gateway = SocketAddr::new(GATEWAY.into(), 53);
        for (id, name, kind) in [
            (6, "8.8.8.8.in-addr.arpa", RecordType::PTR),
            (7, "arpa", RecordType::SOA),
            (8, "ip6.arpa", RecordType::SOA),
        ] {
            let reply = ask(&fcx, &m, gateway, &dns_query(id, name, kind, true))
                .await
                .expect("the gateway answers");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::ServFail,
                "{name}"
            );
            assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY], "{name}");
        }
        Ok(())
    });
}

#[test]
fn rejected_port_sharing_discards_preparations_at_every_endpoint() {
    for reject in ["203.0.113.8:8", "[2001:db8:1::8]:7"] {
        let reject: SocketAddr = reject.parse().unwrap();
        world(Duration::from_secs(60), move |fcx| async move {
            let v4 = Ipv4Addr::new(203, 0, 113, 8);
            let v6: Ipv6Addr = "2001:db8:1::8".parse()?;
            let server = Sharing {
                reject: Some(reject),
                ..Sharing::default()
            };
            let host = |name: &str| {
                Host::new(name)
                    .dns_name(name)
                    .at(v4)
                    .at(v6)
                    .port_server(7, server.clone())
                    .port_server(8, server.clone())
            };
            let first = host("first.test");
            let (bad, good) = (host("bad.test"), host("good.test"));
            let (attacher, attachments) = fictionet::attachments();
            let net = Net::new(fictionet_extras::network::cdn_pools()).add_host(first);
            let handle = net.handle();
            net.start(&fcx, attachments)?;
            let endpoints = [
                SocketAddr::new(v4.into(), 7),
                SocketAddr::new(v4.into(), 8),
                SocketAddr::new(v6.into(), 7),
                SocketAddr::new(v6.into(), 8),
            ];
            let expected: Vec<_> = endpoints
                .into_iter()
                .map(|local| (local, vec!["first.test".to_owned()]))
                .collect();
            assert_eq!(*server.installed.lock().unwrap(), expected);
            let m = machine(&fcx, attacher.attach("client")?, ME);
            assert!(handle.add_host(bad).is_err());
            assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
            assert_eq!(*server.installed.lock().unwrap(), expected);
            handle.add_host(good)?;
            assert_eq!(lookup(&fcx, &m, "good.test").await, Some(v4));
            let good: Vec<_> = endpoints
                .into_iter()
                .map(|local| (local, vec!["good.test".to_owned()]))
                .collect();
            assert_eq!(server.installed.lock().unwrap()[4..], good);
            Ok(())
        });
    }
}

#[test]
fn zero_port_host_serves_a_conversation() {
    world(Duration::from_secs(60), move |fcx| async move {
        let addr = Ipv4Addr::new(203, 0, 113, 8);
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("console", |h| h.at(addr).tcp_stack(0, |_| Echo::stack()))
            .start(&fcx, attachments)?;
        let machine = machine(&fcx, attacher.attach("client")?, ME);
        let target = SocketAddr::new(addr.into(), 0);
        let mut stream = machine.tcp.connect(&fcx, target).await?;
        assert_eq!(stream.peer_addr(), target);
        let greeting = read_some(&fcx, &mut stream, 6).await;
        assert!(!greeting.is_empty());
        stream.write_all(&fcx, &greeting).await?;
        let reply = read_some(&fcx, &mut stream, greeting.len()).await;
        assert_eq!(reply, greeting);
        Ok(())
    });
}

#[test]
fn failed_host_binding_leaves_no_route_service_or_registration() {
    for failure in [
        "bind",
        "zero-duplicate",
        "udp-duplicate",
        "tcp-duplicate",
        "tls-plain",
        "sni-duplicate",
    ] {
        world(Duration::from_secs(60), move |fcx| async move {
            let addr = Ipv4Addr::new(203, 0, 113, 8);
            let server = Sharing::default();
            let started = Arc::new(AtomicUsize::new(0));
            let count = started.clone();
            // Port zero binds 49152, so the final bind fails after TCP sharing
            // and two UDP sockets have been prepared.
            let bad = Host::new("bad")
                .ipv4_only()
                .at(addr)
                .port_server(80, server.clone())
                .udp_stack(9, Budget::unlimited(), move |info| {
                    count.fetch_add(1, Ordering::SeqCst);
                    echo_datagrams(info)
                });
            let config = |_: &Cx| -> Arc<fictionet::stdlib::services::tls::ServerConfig> {
                panic!("no handshake for a rejected host")
            };
            let bad = match failure {
                "bind" => bad
                    .udp_stack(0, Budget::unlimited(), echo_datagrams)
                    .udp_stack(49152, Budget::unlimited(), echo_datagrams),
                "zero-duplicate" => bad
                    .tcp_stack(0, |_| Echo::stack())
                    .tcp_stack(0, |_| Echo::stack()),
                "udp-duplicate" => bad.udp_stack(9, Budget::unlimited(), echo_datagrams),
                "tcp-duplicate" => bad
                    .tcp_stack(81, |_| Echo::stack())
                    .tcp_stack(81, |_| Echo::stack()),
                "tls-plain" => bad.tls_accept(80, Sni::Any, config, Spy::default()),
                "sni-duplicate" => bad
                    .tls_accept(443, Sni::Any, config, Spy::default())
                    .tls_accept(443, Sni::Any, config, Spy::default()),
                _ => unreachable!(),
            };
            let good = Host::new("good")
                .dns_name("good.test")
                .ipv4_only()
                .at(addr)
                .tcp_stack(80, |_| Echo::stack())
                .udp_stack(9, Budget::unlimited(), echo_datagrams)
                .udp_stack(49152, Budget::unlimited(), echo_datagrams);
            let (attacher, attachments) = fictionet::attachments();
            let net = Net::new(fictionet_extras::network::cdn_pools());
            let handle = net.handle();
            net.start(&fcx, attachments)?;
            let m = machine(&fcx, attacher.attach("client")?, ME);
            assert!(handle.add_host(bad.dns_name("bad.test")).is_err());
            assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert!(server.installed.lock().unwrap().is_empty());
            assert!(matches!(
                m.tcp.connect(&fcx, SocketAddr::new(addr.into(), 80)).await,
                Err(ConnError::Unreachable(_))
            ));
            handle.add_host(good)?;
            assert_eq!(lookup(&fcx, &m, "good.test").await, Some(addr));
            let mut conn = m
                .tcp
                .connect(&fcx, SocketAddr::new(addr.into(), 80))
                .await?;
            assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
            Ok(())
        });
    }
}

#[test]
fn failed_lan_join_or_missing_tls_names_does_not_commit_services() {
    for lan in [false, true] {
        world(Duration::from_secs(60), move |fcx| async move {
            let server = Sharing::default();
            let started = Arc::new(AtomicUsize::new(0));
            let count = started.clone();
            let host = Host::new("bad").port_server(80, server.clone()).udp_stack(
                9,
                Budget::unlimited(),
                move |info| {
                    count.fetch_add(1, Ordering::SeqCst);
                    echo_datagrams(info)
                },
            );
            let net = if lan {
                let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
                Net::new(fictionet_extras::network::cdn_pools())
                    .lan(&corp)
                    .add_host(host.on(&corp).at(Ipv4Addr::new(192, 168, 56, 255)))
            } else {
                Net::new(fictionet_extras::network::cdn_pools()).add_host(host.tls_accept(
                    443,
                    Sni::Names,
                    |_| panic!("no handshake"),
                    Spy::default(),
                ))
            };
            let (_attacher, attachments) = fictionet::attachments();
            assert!(net.start(&fcx, attachments).is_err());
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert!(server.installed.lock().unwrap().is_empty());
            Ok(())
        });
    }
}

#[test]
fn a_second_family_bind_failure_preserves_existing_services() {
    for existing_v4 in [false, true] {
        world(Duration::from_secs(60), move |fcx| async move {
            let v4 = Ipv4Addr::new(203, 0, 113, 8);
            let v6: Ipv6Addr = "2001:db8:1::8".parse()?;
            let server = Sharing::default();
            let first = Host::new("first")
                .dns_name("first.test")
                .at(v6)
                .ipv6_only()
                .port_server(80, server.clone())
                .udp_stack(0, Budget::unlimited(), echo_datagrams);
            let mut net = Net::new(fictionet_extras::network::cdn_pools()).add_host(first);
            if existing_v4 {
                net = net.add_host(
                    Host::new("first4")
                        .dns_name("first4.test")
                        .at(v4)
                        .ipv4_only()
                        .port_server(80, server.clone())
                        .tcp_stack(7, |_| Echo::stack()),
                );
            }
            let bad = Host::new("bad")
                .at(v4)
                .at(v6)
                .port_server(80, server.clone())
                .tcp_stack(81, |_| Echo::stack())
                .udp_stack(9, Budget::unlimited(), echo_datagrams)
                .udp_stack(49152, Budget::unlimited(), echo_datagrams);
            let good = Host::new("good")
                .at(v4)
                .at(v6)
                .port_server(80, server.clone())
                .tcp_stack(81, |_| Echo::stack())
                .udp_stack(9, Budget::unlimited(), echo_datagrams);
            let (attacher, attachments) = fictionet::attachments();
            let handle = net.handle();
            net.start(&fcx, attachments)?;
            let before = server.installed.lock().unwrap().clone();
            let m = machine(&fcx, attacher.attach("client")?, ME);
            let mut existing = if existing_v4 {
                Some(m.tcp.connect(&fcx, SocketAddr::new(v4.into(), 7)).await?)
            } else {
                None
            };
            assert!(handle.add_host(bad.dns_name("bad.test")).is_err());
            assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
            assert_eq!(*server.installed.lock().unwrap(), before);
            let closed = m.tcp.connect(&fcx, SocketAddr::new(v4.into(), 81)).await;
            if let Some(conn) = &mut existing {
                assert!(matches!(closed, Err(ConnError::Refused)));
                conn.write_all(&fcx, b"still here\n").await?;
                assert_eq!(read_some(&fcx, conn, 17).await, b"hello\nstill here\n");
            } else {
                assert!(matches!(closed, Err(ConnError::Unreachable(_))));
            }
            handle.add_host(good.dns_name("good.test"))?;
            assert_eq!(lookup(&fcx, &m, "good.test").await, Some(v4));
            let mut conn = m.tcp.connect(&fcx, SocketAddr::new(v4.into(), 81)).await?;
            assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
            Ok(())
        });
    }
}

#[test]
fn a_rejected_host_does_not_install_http_names_or_a_default() {
    world(Duration::from_secs(60), |fcx| async move {
        let addr = Ipv4Addr::new(203, 0, 113, 8);
        let server = || {
            httpd::Server::new(fictionet_test_support::handler(
                |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                 _: http::Request<bytes::Bytes>| {
                    http::Response::new("hello".into())
                },
            ))
        };
        let first = Host::new("first")
            .dns_name("first.test")
            .at(addr)
            .ipv4_only()
            .port_server(80, server())
            .port_server(81, Spy::default());
        let bad = Host::new("bad")
            .dns_name("bad.test")
            .at(addr)
            .ipv4_only()
            .port_server(80, server().default_host())
            .port_server(81, Spy::default());
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools()).add_host(first);
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        assert!(handle.add_host(bad).is_err());
        assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
        let mut conn = m
            .tcp
            .connect(&fcx, SocketAddr::new(addr.into(), 80))
            .await?;
        for (name, status) in [
            ("first.test", 200),
            ("bad.test", 421),
            ("unknown.test", 421),
        ] {
            let request = fictionet::stdlib::protocols::http1::Request::parse(
                format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").as_bytes(),
            )?;
            assert_eq!(
                fictionet_test_support::sandbox::request(&fcx, &mut conn, &request)
                    .await?
                    .head
                    .status,
                status
            );
        }
        Ok(())
    });
}

#[test]
fn a_plc_and_a_web_server_on_one_net_with_observe_decoding_both() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let plant = Arc::new(Plant {
            limit: 1000,
            ..Plant::default()
        });
        plant.registers.lock().unwrap()[3] = 451;
        let hmi = fictionet_test_support::handler({
            let plant = plant.clone();
            move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                http::Response::new(Bytes::from(format!(
                    "setpoint {}\n",
                    plant.registers.lock().unwrap()[0]
                )))
            }
        });
        // Every packet between the sandbox and the network, for the
        // dashboard's decoder below.
        let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("plc", |h| {
                let plant = plant.clone();
                h.at(PLC_ADDR)
                    .dns_name("plc1.plant.test")
                    .tcp_stack(modbus::PORT, move |_| Plc::stack(plant.clone()))
            })
            .host("hmi", |h| {
                h.dns_name("hmi.plant.test")
                    .port_server(80, httpd::Server::new(hmi))
            })
            .start(&fcx, attachments)?;

        let captured = packets.clone();
        let end = fictionet::stdlib::network::filter(
            &fcx,
            attacher.attach("operator")?,
            move |_, _, p| {
                captured.lock().unwrap().push(p.0.clone());
                true
            },
        );
        let s = fictionet_test_support::sandbox::machine(&fcx, end, ME);
        assert_eq!(lookup(&fcx, &s, "plc1.plant.test").await, Some(PLC_ADDR));
        let hmi_addr = lookup(&fcx, &s, "hmi.plant.test")
            .await
            .expect("the HMI has an address");
        assert_eq!(lookup(&fcx, &s, "nope.plant.test").await, None);

        // Modbus: read, then an unsafe write.
        let mut conn = s
            .tcp
            .connect(&fcx, SocketAddr::new(PLC_ADDR.into(), modbus::PORT))
            .await?;
        conn.write_all(
            &fcx,
            &mb(
                1,
                MbRequest::ReadHoldingRegisters {
                    address: 3,
                    quantity: 1,
                },
            ),
        )
        .await?;
        let reply = read_some(&fcx, &mut conn, 11).await;
        assert_eq!(reply, [0, 1, 0, 0, 0, 5, 1, 3, 2, 0x01, 0xc3]);
        conn.write_all(
            &fcx,
            &mb(
                2,
                MbRequest::WriteSingleRegister {
                    address: 0,
                    value: 1500,
                },
            ),
        )
        .await?;
        assert_eq!(read_some(&fcx, &mut conn, 12).await.len(), 12);
        // HTTP: the HMI shows the new setpoint.
        let mut web = s
            .tcp
            .connect(&fcx, SocketAddr::new(hmi_addr.into(), 80))
            .await?;
        web.write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: hmi.plant.test\r\nConnection: close\r\n\r\n",
        )
        .await?;
        let page = String::from_utf8(read_some(&fcx, &mut web, 1 << 16).await).unwrap();
        assert!(
            page.starts_with("HTTP/1.1 200 OK") && page.ends_with("setpoint 1500\n"),
            "{page}"
        );
        // A port with no service: refused, and recorded as blocked.
        assert_eq!(
            s.tcp
                .connect(&fcx, SocketAddr::new(PLC_ADDR.into(), 102))
                .await
                .err(),
            Some(ConnError::Refused)
        );

        assert_eq!(plant.unsafe_writes.load(Ordering::SeqCst), 1);

        // The dashboard's decoder reads both protocols from the packets.
        let mut dissector = Dissector::with_registry(Registry::default());
        let decoded: Vec<_> = packets
            .lock()
            .unwrap()
            .iter()
            .map(|p| dissector.decode(p, &[]))
            .collect();
        let layer_names: BTreeSet<String> = decoded
            .iter()
            .flat_map(|d| d.layers.iter().map(|l| l.name.clone()))
            .collect();
        assert!(
            layer_names.iter().any(|n| n.contains("Modbus")),
            "{layer_names:?}"
        );
        assert!(
            layer_names.iter().any(|n| n.contains("HTTP")),
            "{layer_names:?}"
        );
        assert!(
            decoded
                .iter()
                .any(|d| d.info.contains("Write Single Register")
                    || d.layers.iter().any(|l| l.summary.contains("1500"))),
            "{:?}",
            decoded.iter().map(|d| &d.info).collect::<Vec<_>>()
        );
        Ok(())
    });
}

#[test]
fn net_serves_udp_services_and_trusted_sandboxes() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let counter = Arc::new(AtomicUsize::new(0));
        /// Counts datagrams.
        struct Udp(Arc<AtomicUsize>);
        impl DatagramApp for Udp {
            type Timer = ();
            fn line(
                &mut self,
                _: Result<Vec<u8>, LineError>,
                from: SocketAddr,
                sends: &mut Sends<'_, ()>,
            ) {
                let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                sends.send_to(from, format!("{n}\n").into_bytes());
            }
        }
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("svc", |h| {
                h.at(Ipv4Addr::new(10, 40, 0, 1))
                    .tcp_stack(7, |_| Echo::stack())
                    .udp_stack(9, Budget::unlimited(), move |info| {
                        Datagrammed::new(Udp(counter.clone()), info.local)
                    })
            })
            .route(
                "box",
                Prefix {
                    addr: Ipv4Addr::new(10, 50, 0, 7).into(),
                    len: 32,
                },
            )
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut conn = s
            .tcp
            .connect(&fcx, SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 7))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        let mut u = s.udp.bind(5000)?;
        u.send_to(
            b"x\n",
            SocketAddr::new(Ipv4Addr::new(10, 40, 0, 1).into(), 9),
        );
        assert_eq!(u.recv(&fcx).await?.0, b"1\n");
        // The trusted sandbox at its fixed address, reached from the agent.
        let boxed = machine(&fcx, attacher.attach("box")?, Ipv4Addr::new(10, 50, 0, 7));
        let mut l = boxed.tcp.listen(22)?;
        fcx.spawn(move |fcx| async move {
            let mut c = l.accept(&fcx).await?;
            c.write_all(&fcx, b"SSH-2.0-real\r\n").await?;
            Ok(())
        });
        let mut ssh = s
            .tcp
            .connect(
                &fcx,
                SocketAddr::new(Ipv4Addr::new(10, 50, 0, 7).into(), 22),
            )
            .await?;
        assert_eq!(read_some(&fcx, &mut ssh, 14).await, b"SSH-2.0-real\r\n");

        conn.write_all(&fcx, b"hi\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 3).await, b"hi\n");
        Ok(())
    });
}

#[test]
fn ephemeral_udp_service_reports_its_wire_endpoint() {
    struct Announce {
        to: SocketAddr,
        reported: Arc<Mutex<Option<SocketAddr>>>,
    }
    impl DatagramApp for Announce {
        type Timer = ();
        fn open(&mut self, sends: &mut Sends<'_, ()>) {
            *self.reported.lock().unwrap() = sends.local();
            sends.send_to(self.to, vec![1]);
        }
        fn line(&mut self, _: Result<Vec<u8>, LineError>, _: SocketAddr, _: &mut Sends<'_, ()>) {}
    }
    world(Duration::from_secs(60), |fcx| async move {
        let reported = Arc::new(Mutex::new(None));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("receiver", |h| {
                h.at(Ipv4Addr::new(10, 40, 0, 2)).program(
                    move |fcx: Cx, machine: fictionet::stdlib::world::net::Endpoints| {
                        let tx = tx.clone();
                        async move {
                            let mut socket = machine.udp.bind(0)?;
                            tx.send(socket.local_addr())?;
                            let (_, wire_source) = socket.recv(&fcx).await?;
                            tx.send(wire_source)?;
                            Ok(())
                        }
                    },
                )
            });
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let to = rx.recv().await.expect("the receiving socket opened");
        let shared = reported.clone();
        handle.add_host(
            Host::new("announcer")
                .at(Ipv4Addr::new(10, 40, 0, 1))
                .udp_stack(0, Budget::unlimited(), move |info| {
                    let reported = shared.clone();
                    Datagrammed::new(Announce { to, reported }, info.local)
                }),
        )?;
        let wire_source = rx.recv().await.expect("the datagram arrived");
        let observed = reported.lock().unwrap().expect("the service opened");
        assert_eq!(
            observed, wire_source,
            "service metadata must identify its actual socket"
        );
        Ok(())
    });
}

#[test]
fn two_ephemeral_udp_services_fit_on_one_machine() {
    world(Duration::from_secs(60), move |fcx| async move {
        let addr = Ipv4Addr::new(203, 0, 113, 9);
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("first", move |h| {
                h.at(addr).udp_stack(0, Budget::unlimited(), echo_datagrams)
            });
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let second = Host::new("second")
            .at(addr)
            .udp_stack(0, Budget::unlimited(), echo_datagrams);
        handle
            .add_host(second)
            .map_err(|e| fictionet::Error::msg(format!("second ephemeral UDP service: {e}")))?;
        Ok(())
    });
}

/// The longest line [`Wide`] reads.
const WIDE_LINE: usize = 10 << 10;

/// Says hello, then takes lines up to [`WIDE_LINE`]: a line buffer that
/// may grow to twice that, charged to the connection's budget with the
/// runner's read buffer.
struct Wide;

impl LineApp for Wide {
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Next = Infallible;
    type Error = Infallible;

    fn max_line(&self) -> usize {
        WIDE_LINE
    }

    fn open(&mut self, out: &mut LineOut<'_, Self>) -> Result<(), Infallible> {
        out.write(b"hello\n");
        Ok(())
    }

    fn line(
        &mut self,
        _: Result<Vec<u8>, LineError>,
        _: &mut LineOut<'_, Self>,
    ) -> Result<(), Infallible> {
        Ok(())
    }
}

/// Net counts each service's connections against its cap, and charges
/// every connection from a sandbox to that sandbox's budget. Before, Net
/// read neither.
#[test]
fn net_caps_connections_per_service_and_bytes_per_sandbox() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 3);
        let limits = fictionet::stdlib::world::net::Limits {
            sandbox_budget: 100 << 10,
            ..Default::default()
        };
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .limits(limits)
            .host("svc", |h| {
                h.at(addr)
                    .tcp_stack_with(7, StreamLimits::default(), 1, |_| Echo::stack())
                    .tcp_stack(8, |_| Lined::new(Wide))
            })
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let mut a = s.tcp.connect(&fcx, SocketAddr::new(addr.into(), 7)).await?;
        assert_eq!(read_some(&fcx, &mut a, 6).await, b"hello\n");
        let mut b = s.tcp.connect(&fcx, SocketAddr::new(addr.into(), 7)).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&fcx, Duration::from_secs(2), b.read(&fcx, &mut buf))
            .await
            .expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        // With the echo above, two wide connections fit the 100 KiB budget;
        // a third does not.
        let to = SocketAddr::new(addr.into(), 8);
        let mut c = s.tcp.connect(&fcx, to).await?;
        let mut d = s.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut c, 6).await, b"hello\n");
        assert_eq!(read_some(&fcx, &mut d, 6).await, b"hello\n");
        let mut e = s.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut e, 6).await, b"");
        Ok(())
    });
}

/// A port served with `tcp` takes the default cap: that many connections
/// are served at once, and the next one is reset.
#[test]
fn net_serves_the_default_cap_of_connections_on_a_tcp_port() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 3);
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("svc", |h| h.at(addr).tcp_stack(7, |_| Echo::stack()))
            .start(&fcx, attachments)?;
        let s = machine(&fcx, attacher.attach("agent")?, ME);
        let to = SocketAddr::new(addr.into(), 7);
        let mut open = Vec::new();
        for _ in 0..fictionet::stdlib::world::net::DEFAULT_MAX_CONNS {
            let mut conn = s.tcp.connect(&fcx, to).await?;
            assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
            open.push(conn);
        }
        let mut past = s.tcp.connect(&fcx, to).await?;
        let mut buf = [0u8; 16];
        let r = timeout(&fcx, Duration::from_secs(2), past.read(&fcx, &mut buf))
            .await
            .expect("an answer");
        assert!(matches!(r, Err(ConnError::Reset) | Ok(0)), "{r:?}");
        drop(open);
        Ok(())
    });
}

/// Net fails on a host it cannot serve as declared. Before, each of these
/// was dropped without a word.
#[test]
fn net_refuses_a_host_it_cannot_serve() {
    world(Duration::from_secs(60), |fcx| async move {
        let fail = |net: Net| {
            let (_attacher, attachments) = fictionet::attachments();
            net.ipv4_only()
                .start(&fcx, attachments)
                .err()
                .map(|e| e.to_string())
        };
        let twice = fail(
            Net::new(fictionet_extras::network::cdn_pools()).host("a", |h| {
                h.at(Ipv4Addr::new(10, 40, 0, 1))
                    .tcp_stack(7, |_| Echo::stack())
                    .tcp_stack(7, |_| Echo::stack())
            }),
        );
        assert!(
            twice
                .as_deref()
                .is_some_and(|e| e.contains("already served")),
            "{twice:?}"
        );
        let bad = fail(
            Net::new(fictionet_extras::network::cdn_pools()).host("b", |h| {
                h.at(Ipv4Addr::new(224, 0, 0, 1))
                    .tcp_stack(7, |_| Echo::stack())
            }),
        );
        assert!(
            bad.as_deref().is_some_and(|e| e.contains("224.0.0.1")),
            "{bad:?}"
        );
        let udp = fail(
            Net::new(fictionet_extras::network::cdn_pools()).host("c", |h| {
                h.at(Ipv4Addr::new(10, 40, 0, 2))
                    .udp_stack(9, Budget::unlimited(), echo_datagrams)
                    .udp_stack(9, Budget::unlimited(), echo_datagrams)
            }),
        );
        assert!(udp.is_some(), "{udp:?}");
        // TLS and plain on one port, in either order. Before, the port
        // served only TLS.
        let config = |_: &Cx| -> Arc<fictionet::stdlib::services::tls::ServerConfig> {
            unreachable!("no handshake happens")
        };
        let at = Ipv4Addr::new(10, 40, 0, 3);
        let tls_first = fail(
            Net::new(fictionet_extras::network::cdn_pools()).host("d", |h| {
                h.at(at)
                    .tls_accept(443, Sni::Any, config, Spy::default())
                    .tcp_stack(443, |_| Echo::stack())
            }),
        );
        assert!(
            tls_first
                .as_deref()
                .is_some_and(|e| e.contains("serves TLS")),
            "{tls_first:?}"
        );
        let plain_first = fail(
            Net::new(fictionet_extras::network::cdn_pools()).host("e", |h| {
                h.at(at).tcp_stack(443, |_| Echo::stack()).tls_accept(
                    443,
                    Sni::Any,
                    config,
                    Spy::default(),
                )
            }),
        );
        assert!(
            plain_first
                .as_deref()
                .is_some_and(|e| e.contains("serves without TLS")),
            "{plain_first:?}"
        );
        Ok(())
    });
}

/// A LAN joins Net: a host placed on it, a VM attached to it as a member,
/// DNS at the LAN's first address, the agent reaching the LAN through the
/// router, multicast from a host to a member, and LAN drops recorded.
#[test]
fn hosts_and_members_share_a_lan_on_the_net() {
    /// Sends `tick` to a multicast group every 20 ms.
    struct Feed(SocketAddr);
    impl DatagramApp for Feed {
        type Timer = ();
        fn open(&mut self, sends: &mut Sends<'_, ()>) {
            sends.set_timer((), Duration::from_millis(20));
        }
        fn line(&mut self, _: Result<Vec<u8>, LineError>, _: SocketAddr, _: &mut Sends<'_, ()>) {}
        fn timer(&mut self, _: (), sends: &mut Sends<'_, ()>) {
            sends.send_to(self.0, b"tick".to_vec());
            sends.set_timer((), Duration::from_millis(20));
        }
    }
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        let group = SocketAddr::new(Ipv4Addr::new(239, 1, 1, 1).into(), 30001);
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .lan(&corp)
            .host("dc01", |h| {
                h.on(&corp)
                    .at(dc)
                    .dns_name("dc01.corp.test")
                    .tcp_stack(389, |_| Echo::stack())
            })
            .host("feed", |h| {
                h.on(&corp).dns_name("feed.corp.test").udp_stack(
                    30000,
                    Budget::unlimited(),
                    move |info| Datagrammed::new(Feed(group), info.local),
                )
            })
            .member("ws01", &corp, ws.into())
            .start(&fcx, attachments)?;

        // The VM: its own stack at its LAN address, no DHCP.
        let vm = machine(&fcx, attacher.attach("ws01")?, ws);
        // DNS at the LAN's first address.
        let mut socket = vm.udp.bind(40001)?;
        let mut q = Message::query();
        q.metadata.id = 9;
        q.add_query(Query::query(
            Name::from_ascii("dc01.corp.test").unwrap(),
            RecordType::A,
        ));
        socket.send_to(
            &q.to_vec().unwrap(),
            SocketAddr::new(Ipv4Addr::new(192, 168, 56, 1).into(), 53),
        );
        let (bytes, _) = timeout(&fcx, Duration::from_secs(2), socket.recv(&fcx))
            .await
            .expect("a DNS answer")?;
        let answer = Message::from_vec(&bytes).unwrap();
        assert!(
            answer
                .answers
                .iter()
                .any(|a| matches!(&a.data, RData::A(a) if a.0 == dc))
        );
        // The VM reaches the host across the LAN.
        let mut conn = vm
            .tcp
            .connect(&fcx, SocketAddr::new(dc.into(), 389))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        // Multicast from a host on the LAN reaches the member that joined.
        vm.udp.join(group.ip())?;
        let mut feed = vm.udp.bind(group.port())?;
        assert_eq!(
            timeout(&fcx, Duration::from_secs(2), feed.recv(&fcx))
                .await
                .expect("a tick")?
                .0,
            b"tick"
        );

        // The agent, on the sandboxes' subnet, reaches the LAN through the
        // router.
        let agent = machine(&fcx, attacher.attach("agent")?, ME);
        let mut conn = agent
            .tcp
            .connect(&fcx, SocketAddr::new(dc.into(), 389))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        conn.write_all(&fcx, b"hi\n").await?;
        assert_eq!(read_some(&fcx, &mut conn, 3).await, b"hi\n");
        Ok(())
    });
}

#[test]
fn trusted_routes_attribute_requests_and_refusals() {
    fictionet_test_support::world::world(Duration::from_secs(10), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let address: Ipv4Addr = "192.168.56.50".parse()?;
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("office", |host| {
                host.at(PLC_ADDR).dns_name("office.internal")
            })
            .route("server", "192.168.56.0/24".parse()?)
            .start(&fcx, attachments)?;
        let server = machine(&fcx, attacher.attach("server")?, address);
        assert_eq!(
            lookup(&fcx, &server, "office.internal").await,
            Some(PLC_ADDR)
        );
        let guest = machine(&fcx, attacher.attach("agent")?, ME);
        assert_eq!(
            lookup(&fcx, &guest, "office.internal").await,
            Some(PLC_ADDR)
        );
        let mut listener = guest.tcp.listen(390)?;
        fcx.spawn(move |cx| async move {
            let mut connection = listener.accept(&cx).await?;
            connection.write_all(&cx, b"hello\n").await?;
            Ok(())
        });
        let mut connection = server.tcp.connect(&fcx, (ME, 390).into()).await?;
        assert_eq!(read_some(&fcx, &mut connection, 6).await, b"hello\n");
        let mut socket = server.udp.bind(40001)?;
        socket.send_to(b"query", "8.8.8.8:53".parse()?);
        Ok(())
    });
}

#[test]
fn net_refuses_lans_that_overlap() {
    world(Duration::from_secs(60), |fcx| async move {
        let fail = |net: Net| {
            let (_attacher, attachments) = fictionet::attachments();
            net.ipv4_only()
                .start(&fcx, attachments)
                .err()
                .map(|e| e.to_string())
        };
        let p = |s: &str| s.parse::<Prefix>().unwrap();
        assert!(
            fail(
                Net::new(fictionet_extras::network::cdn_pools())
                    .lan(&Lan::new("a", p("10.0.0.0/16")))
            )
            .is_some_and(|e| e.contains("sandboxes"))
        );
        assert!(
            fail(
                Net::new(fictionet_extras::network::cdn_pools())
                    .lan(&Lan::new("a", p("192.168.0.0/16")))
                    .lan(&Lan::new("b", p("192.168.56.0/24")))
            )
            .is_some_and(|e| e.contains("overlaps LAN a"))
        );
        assert!(
            fail(
                Net::new(fictionet_extras::network::cdn_pools())
                    .lan(&Lan::new("a", p("192.168.56.0/24")))
                    .member(
                        "vm",
                        &Lan::new("a", p("192.168.56.0/24")),
                        "192.168.56.1".parse().unwrap()
                    )
            )
            .is_some()
        );
        assert!(
            fail(
                Net::new(fictionet_extras::network::cdn_pools())
                    .lan(&Lan::new("a", p("192.168.56.0/24")))
                    .host("x", |h| h.at(Ipv4Addr::new(192, 168, 56, 5)))
            )
            .is_some_and(|e| e.contains("Host::on"))
        );
        Ok(())
    });
}

/// Keeps the budget each connection arrives with, and closes it.
#[derive(Default)]
struct Spy(Arc<Mutex<Vec<Option<Budget>>>>);

impl PortServer for Spy {
    fn serve(&self, _: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.0.lock().unwrap().push(arrival.budget);
        Box::pin(async {})
    }
}

/// What `spy` has kept, once it has kept `n`.
async fn spied(fcx: &Cx, spy: &Mutex<Vec<Option<Budget>>>, n: usize) -> Vec<Option<Budget>> {
    fcx.idle()
        .await
        .expect("the world stopped before the spy ran");
    let kept = spy.lock().unwrap().clone();
    assert!(kept.len() >= n, "the spy kept fewer than {n} budgets");
    kept
}

/// `ended_with_done` accepts only Done: any other error comes back
/// unchanged, and a region that ends with `Ok` is an error.
#[test]
fn early_region_error_is_failure() {
    world(Duration::from_secs(60), |fcx| async move {
        ended_with_done(
            fcx.region(|_| async { Err(fictionet::Error::from(Done)) })
                .await,
        )?;

        let cause = fictionet::Error::from(std::io::Error::other("early region failure"));
        let error = ended_with_done(fcx.region(|_| async { Err(cause.clone()) }).await)
            .expect_err("an unexpected region error must fail");
        assert_eq!(error.to_string(), "early region failure");
        assert!(std::ptr::addr_eq(&*error, &*cause));

        let error = ended_with_done(fcx.region(|_| async { Ok(()) }).await)
            .expect_err("a region without Done must fail");
        assert_eq!(error.to_string(), "the region should end with Done");
        Ok(())
    });
}

/// A sandbox has one budget for its IPv4 and IPv6 addresses, and a new
/// attachment at the same address gets a new one. Before, budgets were
/// kept by address: each family had its own, and an address kept its
/// budget after its sandbox detached.
#[test]
fn net_keeps_one_budget_per_attachment() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (addr, addr6) = (
            Ipv4Addr::new(10, 40, 0, 3),
            "2606:4700:100::3".parse::<Ipv6Addr>()?,
        );
        let me6: Ipv6Addr = "2001:db8::2".parse()?;
        let spy = Spy::default();
        let budgets = spy.0.clone();
        Net::new(fictionet_extras::network::cdn_pools())
            .host("svc", |h| {
                h.at(addr)
                    .at(addr6)
                    .tcp_stack(8, |_| Lined::new(Wide))
                    .port_server(9, spy)
            })
            .start(&fcx, attachments)?;

        // One sandbox on both families: a connection over IPv4 is charged
        // to the budget a connection over IPv6 gets.
        let first = budgets.clone();
        let first_attacher = &attacher;
        ended_with_done(
            fcx.region(|fcx| async move {
                let (v4, v6, _other) = ip::split_versions(&fcx, first_attacher.attach("a")?);
                let (a4, a6) = (machine(&fcx, v4, ME), machine(&fcx, v6, me6));
                let mut wide = a4
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr.into(), 8))
                    .await?;
                assert_eq!(read_some(&fcx, &mut wide, 6).await, b"hello\n");
                let _spied4 = a4
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr.into(), 9))
                    .await?;
                let _spied6 = a6
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr6.into(), 9))
                    .await?;
                let got = spied(&fcx, &first, 2).await;
                let (b4, b6) = (
                    got[0].clone().expect("a budget"),
                    got[1].clone().expect("a budget"),
                );
                assert!(b4.used() >= 2 * WIDE_LINE, "{b4:?}");
                assert_eq!(b6.used(), b4.used(), "IPv6 has its own budget");
                // Leaving the region detaches the sandbox.
                Err(fictionet::Error::from(Done))
            })
            .await,
        )?;
        let a = budgets.lock().unwrap()[0].clone().expect("a budget");

        // Another sandbox at the same address: its own budget.
        let b = machine(&fcx, attacher.attach("b")?, ME);
        let mut wide = b.tcp.connect(&fcx, SocketAddr::new(addr.into(), 8)).await?;
        assert_eq!(read_some(&fcx, &mut wide, 6).await, b"hello\n");
        let _spied = b.tcp.connect(&fcx, SocketAddr::new(addr.into(), 9)).await?;
        let got = spied(&fcx, &budgets, 3).await;
        let b_budget = got[2].clone().expect("a budget");
        assert!(b_budget.used() >= 2 * WIDE_LINE, "{b_budget:?}");
        fcx.idle().await?;
        assert_eq!(
            a.used(),
            0,
            "the sandbox that detached still has charges: {a:?}"
        );
        Ok(())
    });
}

/// A LAN member detaches as any sandbox does: its connections are reset
/// and `net.detached` is recorded, and it can attach again. Before, a
/// member was never detached.
#[test]
fn a_lan_member_detaches_like_any_sandbox() {
    fictionet_test_support::world::world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        {
            let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
            Net::new(fictionet_extras::network::cdn_pools())
                .ipv4_only()
                .lan(&corp)
                .host("dc01", |h| {
                    h.on(&corp).at(dc).tcp_stack(389, |_| Echo::stack())
                })
                .member("ws01", &corp, ws.into())
                .start(&fcx, attachments)?;
        }

        let to = SocketAddr::new(dc.into(), 389);
        let first_attacher = &attacher;
        ended_with_done(
            fcx.region(|fcx| async move {
                let vm = machine(&fcx, first_attacher.attach("ws01")?, ws);
                let mut conn = vm.tcp.connect(&fcx, to).await?;
                assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
                // Leaving the region takes the VM away without a word to
                // the server.
                Err(fictionet::Error::from(Done))
            })
            .await,
        )?;
        // The member attaches again, as a new sandbox.
        let vm = machine(&fcx, attacher.attach("ws01")?, ws);
        let mut conn = vm.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        Ok(())
    });
}

/// LANs cannot reserve addresses from the automatic pool.
#[test]
fn lan_cannot_overlap_the_automatic_address_pool() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        let error = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .lan(&Lan::new("lab", "104.18.0.0/24".parse()?))
            .start(&fcx, attachments)
            .expect_err("overlapping LAN is refused");
        assert!(error.to_string().contains("automatic address pool"));
        Ok(())
    });
}

#[test]
fn ipv6_lan_cannot_overlap_the_automatic_address_pool() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        let error = Net::new(fictionet_extras::network::cdn_pools())
            .lan(&Lan::new("lab", "2606:4700:100::/64".parse()?))
            .start(&fcx, attachments)
            .expect_err("overlapping LAN is refused");
        assert!(error.to_string().contains("automatic address pool"));
        Ok(())
    });
}

/// Hosts without `at` take addresses from the pools the world gives, and
/// LANs are checked against those pools, not any other range.
#[test]
fn hosts_and_lans_follow_the_supplied_pools() {
    let other = Pools {
        v4: Some("23.32.0.0/11".parse().unwrap()),
        v6: Some("2a02:26f0::/32".parse().unwrap()),
    };
    for (pools, first) in [
        (fictionet_extras::network::cdn_pools(), "104.18.0.1"),
        (other, "23.32.0.1"),
    ] {
        world(Duration::from_secs(60), move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            Net::new(pools)
                .ipv4_only()
                .host("www", |h| {
                    h.dns_name("www.test").tcp_stack(7, |_| Echo::stack())
                })
                .host("plc", |h| {
                    h.dns_name("plc.test").tcp_stack(7, |_| Echo::stack())
                })
                .start(&fcx, attachments)?;
            let m = machine(&fcx, attacher.attach("client")?, ME);
            let first: Ipv4Addr = first.parse()?;
            assert_eq!(lookup(&fcx, &m, "www.test").await, Some(first));
            assert_eq!(
                lookup(&fcx, &m, "plc.test").await,
                Some(Ipv4Addr::from(u32::from(first) + 1))
            );
            Ok(())
        });
    }
    world(Duration::from_secs(60), move |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        let error = Net::new(other)
            .lan(&Lan::new("lab", "23.32.4.0/24".parse()?))
            .start(&fcx, attachments)
            .expect_err("a LAN in the supplied pool is refused");
        assert!(error.to_string().contains("automatic address pool"));
        Ok(())
    });
    world(Duration::from_secs(60), move |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        Net::new(other)
            .lan(&Lan::new("lab", "104.18.0.0/24".parse()?))
            .lan(&Lan::new("lab6", "2606:4700:100::/64".parse()?))
            .start(&fcx, attachments)?;
        Ok(())
    });
}

/// With no pools, every host needs `at`.
#[test]
fn without_pools_a_host_needs_an_address() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        let error = Net::new(Pools::NONE)
            .host("www", |h| {
                h.dns_name("www.test").tcp_stack(7, |_| Echo::stack())
            })
            .start(&fcx, attachments)
            .expect_err("a host with no address is refused");
        assert!(error.to_string().contains("no address"), "{error}");
        Ok(())
    });
}

#[test]
fn udp_ephemeral_ports_skip_bound_ports_and_reuse_released_ports() {
    world(Duration::from_secs(5), |fcx| async move {
        let (_, endpoint, _, _) = two_machines(&fcx);
        let reserved = endpoint.bind(49152)?;
        let mut sockets = Vec::new();
        for port in 49153..=u16::MAX {
            let socket = endpoint.bind(0)?;
            assert_eq!(socket.local_addr(), SocketAddr::new(SERVER.into(), port));
            sockets.push(socket);
        }
        assert!(endpoint.bind(0).is_err());
        assert!(endpoint.bind(49152).is_err());
        drop(reserved);
        assert_eq!(endpoint.bind(0)?.local_addr().port(), 49152);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// The gateway's resolver and DNS programs on hosts

/// A query for `name` of type `kind` with RD set, with an OPT record when
/// `edns`.
fn dns_query(id: u16, name: &str, kind: RecordType, edns: bool) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    if edns {
        query.set_edns(Edns::new());
    }
    query
}

/// What `server` answers `query` over UDP, if it answers within two
/// seconds.
async fn ask(fcx: &Cx, m: &Machine, server: SocketAddr, query: &Message) -> Option<Message> {
    let mut socket = m.udp.bind(0).ok()?;
    socket.send_to(&query.to_vec().ok()?, server);
    let (bytes, _) = timeout(fcx, Duration::from_secs(2), socket.recv(fcx))
        .await?
        .ok()?;
    Message::from_vec(&bytes).ok()
}

/// The Extended DNS Error codes a reply carries.
fn edes(reply: &Message) -> Vec<EdeCode> {
    reply.edns.as_ref().map_or_else(Vec::new, |edns| {
        edns.options()
            .as_ref()
            .iter()
            .filter_map(|(_, option)| Ede::from_option(option))
            .map(|ede| ede.code)
            .collect()
    })
}

fn lower(name: &str) -> LowerName {
    LowerName::new(&Name::from_ascii(name).unwrap())
}

/// The gateway answers as a resolver with no internet: the names hosts
/// declare, with RA set; NXDOMAIN with an SOA for other names under a
/// top-level domain a declared name uses; and SERVFAIL with Extended DNS
/// Error 22 for every other name. Before, it answered as an authority,
/// with AA set, NXDOMAIN without an SOA for every unknown name, and a
/// 60-second TTL.
#[test]
fn the_gateway_answers_declared_names_as_a_resolver_with_no_internet() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("plc", |h| h.at(PLC_ADDR).dns_name("plc1.plant.test"))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let gateway = SocketAddr::new(GATEWAY.into(), 53);

        // A declared name: its address, from a resolver (RA), with AA as
        // Unbound sets it on local data, and Unbound's local-data TTL.
        let query = dns_query(1, "plc1.plant.test.", RecordType::A, false);
        let reply = ask(&fcx, &m, gateway, &query).await.expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.recursion_available);
        assert!(reply.metadata.authoritative);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].data, RData::A(PLC_ADDR.into()));
        assert_eq!(reply.answers[0].ttl, 3600);
        // A query without OPT gets a reply without one (RFC 6891 §7).
        assert!(reply.edns.is_none());

        // Another name under `test`: NXDOMAIN with the zone's SOA, which a
        // resolver needs to cache the negative answer (RFC 2308 §3).
        let query = dns_query(2, "nope.plant.test.", RecordType::A, false);
        let reply = ask(&fcx, &m, gateway, &query).await.expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(reply.metadata.recursion_available);
        let soa: Vec<_> = reply
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .collect();
        assert_eq!(soa.len(), 1, "{:?}", reply.authorities);
        assert_eq!(LowerName::new(&soa[0].name), lower("test."));

        // The name above a declared one exists, with no data (RFC 8020).
        let query = dns_query(3, "plant.test.", RecordType::A, false);
        let reply = ask(&fcx, &m, gateway, &query).await.expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());

        // A name under another top-level domain has no server to ask.
        let query = dns_query(4, "example.com.", RecordType::A, true);
        let reply = ask(&fcx, &m, gateway, &query).await.expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert!(reply.metadata.recursion_available);
        assert!(
            edes(&reply).contains(&EdeCode::NO_REACHABLE_AUTHORITY),
            "{:?}",
            edes(&reply)
        );
        Ok(())
    });
}

/// An upstream that answers every lookup with one A record, authoritative
/// for the name asked, and counts the lookups it was given.
struct Answers {
    asked: Arc<AtomicUsize>,
}

impl Upstream for Answers {
    fn lookup<'a>(
        &'a self,
        _fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let question = lookup.question.clone();
        let mut reply = Message::response(1, OpCode::Query);
        reply.metadata.authoritative = true;
        reply.add_answer(Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(Ipv4Addr::new(203, 0, 113, 80).into()),
        ));
        reply.add_query(question);
        Box::pin(std::future::ready(Looked::Response(reply)))
    }
}

/// `Only` puts to its upstream only the lookups the policy allows. A
/// server whose lookup was refused stays silent, as a server that never
/// replies.
#[test]
fn only_looks_up_what_its_policy_allows() {
    world(Duration::from_secs(60), |fcx| async move {
        let address = Ipv4Addr::new(203, 0, 113, 53);
        let asked = Arc::new(AtomicUsize::new(0));
        let allowed = lower("allowed.test.");
        let policy =
            move |lookup: &Lookup| allowed.zone_of(&LowerName::new(lookup.question.name()));
        let upstream = Only::new(
            policy,
            Answers {
                asked: asked.clone(),
            },
        );
        let zones = LookupAuthority::new("test.");
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("copy", |h| {
                h.at(address)
                    .program(Authoritative::new(zones, ServerConfig::generic()).upstream(upstream))
            })
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(address.into(), 53);

        let query = dns_query(1, "www.allowed.test.", RecordType::A, false);
        let reply = ask(&fcx, &m, server, &query).await.expect("an answer");
        assert_eq!(reply.metadata.id, 1);
        assert_eq!(
            reply.answers[0].data,
            RData::A(Ipv4Addr::new(203, 0, 113, 80).into())
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        let query = dns_query(2, "www.other.test.", RecordType::A, false);
        assert!(ask(&fcx, &m, server, &query).await.is_none());
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "the upstream was not asked"
        );
        Ok(())
    });
}

/// A root zone at `ns.` holding `www.example.` directly, with no
/// delegations.
fn small_root(server: Ipv4Addr) -> Zone {
    let rrset = |owner: &str, rdata: RData| {
        let owner = Name::from_ascii(owner).unwrap();
        let mut set = RecordSet::with_ttl(owner.clone(), rdata.record_type(), 3600);
        set.set_records(vec![Record::from_rdata(owner, 3600, rdata)]);
        set
    };
    let ns = Name::from_ascii("ns.").unwrap();
    let soa = SOA::new(
        ns.clone(),
        Name::from_ascii("hostmaster.ns.").unwrap(),
        1,
        3600,
        600,
        86400,
        300,
    );
    Zone::builder(Name::root(), soa, 3600)
        .rrset(rrset(".", RData::NS(NS(ns))))
        .rrset(rrset("ns.", RData::A(server.into())))
        .rrset(rrset(
            "www.example.",
            RData::A(Ipv4Addr::new(203, 0, 113, 80).into()),
        ))
        .build()
        .unwrap()
}

/// The declared names in front of iteration, as Unbound serves
/// `local-data` with no `local-zone`: a declared name answers, and the
/// names above it, its top-level domain's apex among them, are asked of
/// the servers, which know them.
#[test]
fn transparent_declared_names_leave_the_names_above_them_to_iteration() {
    world(Duration::from_secs(60), |fcx| async move {
        let root = Ipv4Addr::new(203, 0, 113, 53);
        let clock = WallClock {
            start: std::time::SystemTime::UNIX_EPOCH,
        };
        let server = Authoritative::new(
            Zones::new(vec![Arc::new(small_root(root))]),
            ServerConfig::generic(),
        );
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("root", |h| h.at(root).program(server))
            .host("api", |h| h.at(PLC_ADDR).dns_name("api.www.example"))
            .gateway(move |h, declared| {
                let config = Config {
                    anchors: None,
                    local: Vec::new(),
                    ..Config::new()
                }
                .hints(&[(Name::from_ascii("ns.").unwrap(), IpAddr::V4(root))])
                .local(LocalZone::new(Arc::new(declared.transparent())));
                h.program(Recursive::new(config, clock))
            })
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let gateway = SocketAddr::new(GATEWAY.into(), 53);
        let resolve = |id, name: &'static str, rtype| {
            let (fcx, m) = (fcx.clone(), &m);
            async move {
                let query = dns_query(id, name, rtype, false);
                ask(&fcx, m, gateway, &query).await.expect("an answer")
            }
        };

        let api = resolve(1, "api.www.example.", RecordType::A).await;
        assert_eq!(api.answers[0].data, RData::A(PLC_ADDR.into()));
        // The name above the declared one is the root server's.
        let www = resolve(2, "www.example.", RecordType::A).await;
        assert_eq!(www.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            www.answers
                .iter()
                .map(|r| r.data.clone())
                .collect::<Vec<_>>(),
            vec![RData::A(Ipv4Addr::new(203, 0, 113, 80).into())]
        );
        // The top-level domain's apex has no made-up NS: the root server
        // says `example.` has no NS RRset.
        let apex = resolve(3, "example.", RecordType::NS).await;
        assert_eq!(apex.metadata.response_code, ResponseCode::NoError);
        assert!(apex.answers.is_empty(), "{:?}", apex.answers);
        let RData::SOA(soa) = &apex.authorities[0].data else {
            panic!("an SOA");
        };
        assert_eq!(soa.mname, Name::from_ascii("ns.").unwrap());
        Ok(())
    });
}

/// Advancing a namespace reaches a running resolver: it empties its cache
/// and asks again.
#[test]
fn advancing_a_namespace_reaches_a_running_resolver() {
    world(Duration::from_secs(60), |fcx| async move {
        let root = Ipv4Addr::new(203, 0, 113, 53);
        let clock = WallClock {
            start: std::time::SystemTime::UNIX_EPOCH,
        };
        let namespace = Namespace::new(clock);
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        let www = lower("www.example.");
        let server = Authoritative::new(
            Zones::new(vec![Arc::new(small_root(root))]),
            ServerConfig::generic(),
        )
        .on_event(move |event| {
            if let Event::Query { question, .. } = event
                && LowerName::new(question.name()) == www
            {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        });
        // The resolver iterates from this root, which is unsigned.
        let config = Config {
            anchors: None,
            ..Config::new()
        }
        .hints(&[(Name::from_ascii("ns.")?, IpAddr::V4(root))]);
        let resolvers = namespace.clone();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("root", |h| h.at(root).program(server))
            .gateway(move |h, _| {
                h.program(Recursive::new(config.clone(), clock).namespace(&resolvers))
            })
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let gateway = SocketAddr::new(GATEWAY.into(), 53);
        let resolve = |id| {
            let (fcx, m) = (fcx.clone(), &m);
            async move {
                let query = dns_query(id, "www.example.", RecordType::A, false);
                let reply = ask(&fcx, m, gateway, &query).await.expect("an answer");
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert_eq!(
                    reply.answers[0].data,
                    RData::A(Ipv4Addr::new(203, 0, 113, 80).into())
                );
            }
        };
        resolve(1).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // From the cache.
        resolve(2).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // A new session: the cache is gone, so the root is asked again.
        namespace.advance(clock);
        resolve(3).await;
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        Ok(())
    });
}

/// A query through a resolver's handle, as DNS over TLS would put it, gets
/// the answer a query over UDP gets.
#[test]
fn a_resolver_handle_answers_as_udp_does() {
    world(Duration::from_secs(60), |fcx| async move {
        let handles: Arc<Mutex<Vec<ResolverHandle>>> = Arc::default();
        let kept = handles.clone();
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .host("plc", |h| h.at(PLC_ADDR).dns_name("plc1.plant.test"))
            .gateway(move |h, declared| {
                let clock = WallClock {
                    start: std::time::SystemTime::UNIX_EPOCH,
                };
                let config = Config {
                    hints: Vec::new(),
                    ..Config::new()
                };
                let resolver = Recursive::new(declared.over(config), clock);
                kept.lock().unwrap().push(resolver.handle());
                h.program(resolver)
            })
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let handle = handles.lock().unwrap()[0].clone();
        for (id, name) in [(1, "plc1.plant.test."), (2, "nope.plant.test.")] {
            let query = dns_query(id, name, RecordType::A, true);
            let udp = ask(&fcx, &m, SocketAddr::new(GATEWAY.into(), 53), &query)
                .await
                .expect("an answer over UDP");
            let client = Client {
                peer: SocketAddr::new(ME.into(), 40000),
                local: SocketAddr::new(GATEWAY.into(), 853),
                transport: Transport::Tcp,
                connection: None,
                sandbox: None,
            };
            let bytes = handle
                .query(&fcx, client, query.to_vec()?)
                .await
                .expect("an answer through the handle");
            let handled = Message::from_vec(&bytes)?;
            assert_eq!(handled.metadata, udp.metadata);
            assert_eq!(handled.queries, udp.queries);
            assert_eq!(handled.answers, udp.answers);
            assert_eq!(handled.authorities, udp.authorities);
        }
        // An address the resolver does not run at.
        let elsewhere = Client {
            peer: SocketAddr::new(ME.into(), 40000),
            local: SocketAddr::new(PLC_ADDR.into(), 853),
            transport: Transport::Tcp,
            connection: None,
            sandbox: None,
        };
        let query = dns_query(3, "plc1.plant.test.", RecordType::A, false);
        assert!(
            handle
                .query(&fcx, elsewhere, query.to_vec()?)
                .await
                .is_none()
        );
        Ok(())
    });
}
