use super::*;
use fictionet::stdlib::world::net::Lan;
use fictionet_test_support::ended_with_done;

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
            Net::new()
                .add_host(first)
                .resolve(move |name| match name {
                    "bad.test" => Some(bad.clone()),
                    "good.test" => Some(good.clone()),
                    _ => None,
                })
                .start(&fcx, attachments)?;
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
            assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
            assert_eq!(*server.installed.lock().unwrap(), expected);
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
fn failed_host_binding_leaves_no_route_service_or_registration() {
    for failure in [
        "bind",
        "port-zero",
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
                .udp(9, Arc::new(()), move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Echo
                });
            let config = |_: &Cx| -> Arc<fictionet::stdlib::services::tls::ServerConfig> {
                panic!("no handshake for a rejected host")
            };
            let bad = match failure {
                "bind" => bad
                    .udp(0, Arc::new(()), || Echo)
                    .udp(49152, Arc::new(()), || Echo),
                "port-zero" => bad.tcp(0, Arc::new(()), || Echo),
                "udp-duplicate" => bad.udp(9, Arc::new(()), || Echo),
                "tcp-duplicate" => bad
                    .tcp(81, Arc::new(()), || Echo)
                    .tcp(81, Arc::new(()), || Echo),
                "tls-plain" => bad.tls_accept(80, Sni::Any, config, Spy::default()),
                "sni-duplicate" => bad
                    .tls_accept(443, Sni::Any, config, Spy::default())
                    .tls_accept(443, Sni::Any, config, Spy::default()),
                _ => unreachable!(),
            };
            let (attacher, attachments) = fictionet::attachments();
            Net::new()
                .resolve(move |name| match name {
                    "bad.test" => Some(bad.clone()),
                    "good.test" => Some(
                        Host::new("good")
                            .ipv4_only()
                            .at(addr)
                            .tcp(80, Arc::new(()), || Echo)
                            .udp(9, Arc::new(()), || Echo)
                            .udp(49152, Arc::new(()), || Echo),
                    ),
                    _ => None,
                })
                .start(&fcx, attachments)?;
            let m = machine(&fcx, attacher.attach("client")?, ME);
            assert_eq!(lookup(&fcx, &m, "bad.test").await, None);
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert!(server.installed.lock().unwrap().is_empty());
            assert!(matches!(
                m.tcp.connect(&fcx, SocketAddr::new(addr.into(), 80)).await,
                Err(ConnError::Unreachable(_))
            ));
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
            let host =
                Host::new("bad")
                    .port_server(80, server.clone())
                    .udp(9, Arc::new(()), move || {
                        count.fetch_add(1, Ordering::SeqCst);
                        Echo
                    });
            let net = if lan {
                let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
                Net::new()
                    .lan(&corp)
                    .add_host(host.on(&corp).at(Ipv4Addr::new(192, 168, 56, 255)))
            } else {
                Net::new().add_host(host.tls_accept(
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
                .udp(0, Arc::new(()), || Echo);
            let mut net = Net::new().add_host(first);
            if existing_v4 {
                net = net.add_host(
                    Host::new("first4")
                        .dns_name("first4.test")
                        .at(v4)
                        .ipv4_only()
                        .port_server(80, server.clone())
                        .tcp(7, Arc::new(()), || Echo),
                );
            }
            let bad = Host::new("bad")
                .at(v4)
                .at(v6)
                .port_server(80, server.clone())
                .tcp(81, Arc::new(()), || Echo)
                .udp(9, Arc::new(()), || Echo)
                .udp(49152, Arc::new(()), || Echo);
            let good = Host::new("good")
                .at(v4)
                .at(v6)
                .port_server(80, server.clone())
                .tcp(81, Arc::new(()), || Echo)
                .udp(9, Arc::new(()), || Echo);
            let (attacher, attachments) = fictionet::attachments();
            net.resolve(move |name| match name {
                "bad.test" => Some(bad.clone()),
                "good.test" => Some(good.clone()),
                _ => None,
            })
            .start(&fcx, attachments)?;
            let before = server.installed.lock().unwrap().clone();
            let m = machine(&fcx, attacher.attach("client")?, ME);
            let mut existing = if existing_v4 {
                Some(m.tcp.connect(&fcx, SocketAddr::new(v4.into(), 7)).await?)
            } else {
                None
            };
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
        Net::new()
            .add_host(first)
            .resolve(move |_| Some(bad.clone()))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
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
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
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
        Net::new()
            .ipv4_only()
            .host("plc", |h| {
                h.at(PLC_ADDR)
                    .dns_name("plc1.plant.test")
                    .tcp(modbus::PORT, plant.clone(), || Plc)
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

        let alarm = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.level == Level::Alarm
            })
            .await?;
        assert_eq!(alarm[0].kind, "write_register");
        let sandbox_name = |e: &Event| e.conn.sandbox.as_ref().map(|s| s.name.to_string());
        assert_eq!(sandbox_name(&alarm[0]).as_deref(), Some("operator"));
        assert_eq!(
            alarm[0].conn.local,
            Some(SocketAddr::new(PLC_ADDR.into(), 502))
        );
        kept.wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
            e.is("http", "request")
        })
        .await?;
        let kinds: BTreeSet<String> = kept
            .all()
            .iter()
            .map(|e| format!("{}.{}", e.source, e.kind))
            .collect();
        for want in [
            "net.attached",
            "net.bound",
            "dns.query",
            "modbus.read",
            "modbus.write_register",
            "http.request",
            "net.blocked",
        ] {
            assert!(kinds.contains(want), "no {want} in {kinds:?}");
        }
        let blocked = kept.of("net", "blocked");
        assert_eq!(blocked[0].u64("dst_port"), Some(102));

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
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let counter = Arc::new(AtomicUsize::new(0));
        /// Counts datagrams.
        struct Udp;
        service_fixture! {
            Udp => (Lines, AtomicUsize, Infallible);
            decoder(self) {
                Lines::new(64, Ending::LfOrCrlf)
            }
            on_item(self, _: Result<Vec<u8>, LineError>; n, driver) -> Flow {
                driver.emit("udp", "datagram", |event| event);
                driver.reply().extend_from_slice(
                    format!("{}\n", n.fetch_add(1, Ordering::SeqCst) + 1).as_bytes(),
                );
                Ok(Flow::Continue)
            }
        }
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("svc", |h| {
                h.at(Ipv4Addr::new(10, 40, 0, 1))
                    .tcp(7, Arc::new(()), || Echo)
                    .udp(9, counter.clone(), || Udp)
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
        // A datagram's events name its sandbox, as a connection's do.
        let datagram = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("udp", "datagram")
            })
            .await?;
        assert_eq!(
            datagram[0]
                .conn
                .sandbox
                .as_ref()
                .map(|s| s.name.to_string())
                .as_deref(),
            Some("agent")
        );
        assert_eq!(
            datagram[0].conn.transport,
            fictionet::events::Transport::Udp
        );

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

        // The service's own events carry the connection, numbered by Net.
        assert!(
            kept.all().iter().all(|e| e.source != "echo"),
            "no line was sent yet"
        );
        conn.write_all(&fcx, b"hi\n").await?;
        let lines = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| e.is("echo", "line"))
            .await?;
        assert_eq!(lines[0].conn.id, Some(1));
        assert_eq!(lines[0].conn.sandbox.as_ref().map(|s| s.id), Some(1));
        Ok(())
    });
}

/// Says hello, then takes lines up to 40 KiB: a decoder that holds up to
/// that much, charged to the connection's budget.
struct Wide;

service_fixture! {
    Wide => (Lines, (), Infallible);
    decoder(self) {
        Lines::new(40 << 10, Ending::LfOrCrlf)
    }
    on_open(self; _, driver) -> Flow {
        driver.reply().extend_from_slice(b"hello\n");
        Ok(Flow::Continue)
    }
    on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
        Ok(Flow::Continue)
    }
}

/// Net counts each service's connections against its cap, and charges
/// every connection from a sandbox to that sandbox's budget. Before, Net
/// read neither.
#[test]
fn net_caps_connections_per_service_and_bytes_per_sandbox() {
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let addr = Ipv4Addr::new(10, 40, 0, 3);
        let limits = fictionet::stdlib::world::net::Limits {
            sandbox_budget: 100 << 10,
            ..Default::default()
        };
        let capped = ServeOptions::default()
            .max_conns(1)
            .connection_events(false);
        let wide = ServeOptions::default();
        Net::new()
            .ipv4_only()
            .limits(limits)
            .host("svc", |h| {
                h.at(addr)
                    .tcp_with(7, Arc::new(()), || Echo, capped)
                    .tcp_with(8, Arc::new(()), || Wide, wide)
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
        let blocked = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("net", "blocked")
            })
            .await?;
        assert_eq!(blocked[0].str("why"), Some("TooManyConnections"));

        // Two 40 KiB decoders fit the 100 KiB budget; a third does not.
        let to = SocketAddr::new(addr.into(), 8);
        let mut c = s.tcp.connect(&fcx, to).await?;
        let mut d = s.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut c, 6).await, b"hello\n");
        assert_eq!(read_some(&fcx, &mut d, 6).await, b"hello\n");
        let mut e = s.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut e, 6).await, b"");
        let closed = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("conn", "close")
            })
            .await?;
        assert_eq!(closed[0].str("end"), Some("budget"));
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
        let twice = fail(Net::new().host("a", |h| {
            h.at(Ipv4Addr::new(10, 40, 0, 1))
                .tcp(7, Arc::new(()), || Echo)
                .tcp(7, Arc::new(()), || Echo)
        }));
        assert!(
            twice
                .as_deref()
                .is_some_and(|e| e.contains("already served")),
            "{twice:?}"
        );
        let bad = fail(Net::new().host("b", |h| {
            h.at(Ipv4Addr::new(224, 0, 0, 1))
                .tcp(7, Arc::new(()), || Echo)
        }));
        assert!(
            bad.as_deref().is_some_and(|e| e.contains("224.0.0.1")),
            "{bad:?}"
        );
        let udp = fail(Net::new().host("c", |h| {
            h.at(Ipv4Addr::new(10, 40, 0, 2))
                .udp(9, Arc::new(()), || Echo)
                .udp(9, Arc::new(()), || Echo)
        }));
        assert!(udp.is_some(), "{udp:?}");
        // TLS and plain on one port, in either order. Before, the port
        // served only TLS.
        let config = |_: &Cx| -> Arc<fictionet::stdlib::services::tls::ServerConfig> {
            unreachable!("no handshake happens")
        };
        let at = Ipv4Addr::new(10, 40, 0, 3);
        let tls_first = fail(Net::new().host("d", |h| {
            h.at(at)
                .tls_accept(443, Sni::Any, config, Spy::default())
                .tcp(443, Arc::new(()), || Echo)
        }));
        assert!(
            tls_first
                .as_deref()
                .is_some_and(|e| e.contains("serves TLS")),
            "{tls_first:?}"
        );
        let plain_first = fail(Net::new().host("e", |h| {
            h.at(at).tcp(443, Arc::new(()), || Echo).tls_accept(
                443,
                Sni::Any,
                config,
                Spy::default(),
            )
        }));
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
    struct Feed;
    service_fixture! {
        Feed => (Lines, SocketAddr, Infallible);
        decoder(self) {
            Lines::new(64, Ending::LfOrCrlf)
        }
        on_open(self; _, driver) -> Flow {
            driver.set_timer((), Duration::from_millis(20));
            Ok(Flow::Continue)
        }
        on_item(self, _: Result<Vec<u8>, LineError>; _, _) -> Flow {
            Ok(Flow::Continue)
        }
        on_timer(self, _: (); group, driver) -> Flow {
            driver.send_to(*group, b"tick".to_vec());
            driver.set_timer((), Duration::from_millis(20));
            Ok(Flow::Continue)
        }
    }
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        let group = SocketAddr::new(Ipv4Addr::new(239, 1, 1, 1).into(), 30001);
        Net::new()
            .ipv4_only()
            .lan(&corp)
            .host("dc01", |h| {
                h.on(&corp)
                    .at(dc)
                    .dns_name("dc01.corp.test")
                    .tcp(389, Arc::new(()), || Echo)
            })
            .host("feed", |h| {
                h.on(&corp)
                    .dns_name("feed.corp.test")
                    .udp(30000, Arc::new(group), || Feed)
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
        // An address on the LAN with no member: the LAN drops it, and the
        // events say so.
        let mut u = agent.udp.bind(5000)?;
        u.send_to(
            b"anyone?",
            SocketAddr::new(Ipv4Addr::new(192, 168, 56, 99).into(), 7),
        );
        let drops = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("lan", "drop") && e.str("lan") == Some("corp")
            })
            .await?;
        assert_eq!(drops[0].str("why"), Some("no member at that address"));
        assert_eq!(
            drops[0].conn.sandbox.as_ref().map(|s| &*s.name),
            Some("agent")
        );
        assert!(
            kept.of("net", "blocked")
                .iter()
                .all(|e| e.str("why") != Some("Lan"))
        );
        socket.send_to(
            b"anyone?",
            SocketAddr::new(Ipv4Addr::new(192, 168, 56, 99).into(), 7),
        );
        let drops = kept
            .wait(&fcx, 0, 2, Duration::from_secs(2), |e| {
                e.is("lan", "drop") && e.str("lan") == Some("corp")
            })
            .await?;
        assert_eq!(
            drops[1].conn.sandbox.as_ref().map(|s| &*s.name),
            Some("ws01")
        );
        assert!(drops[1].get("count").is_none());
        assert_eq!(drops[1].str("why"), Some("no member at that address"));
        // The VM is named in events like any sandbox.
        let joined = kept.of("net", "attached");
        assert!(
            joined
                .iter()
                .any(|e| e.conn.sandbox.as_ref().is_some_and(|s| &*s.name == "ws01"))
        );
        let vm_lines: Vec<Event> = kept
            .all()
            .into_iter()
            .filter(|e| {
                e.conn.sandbox.as_ref().is_some_and(|s| &*s.name == "ws01") && e.is("dns", "query")
            })
            .collect();
        assert!(!vm_lines.is_empty());
        Ok(())
    });
}

#[test]
fn trusted_routes_attribute_requests_and_refusals() {
    crate::common::world::observed_world(Duration::from_secs(10), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let address: Ipv4Addr = "192.168.56.50".parse()?;
        Net::new()
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
        let queries = kept.of("dns", "query");
        assert!(queries.iter().any(|event| {
            event.str("name") == Some("office.internal")
                && event.conn.sandbox.as_ref().is_some_and(|sandbox| {
                    sandbox.name.as_ref() == "server" && sandbox.addr == Some(address)
                })
        }));
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
        assert!(
            kept.of("net", "blocked")
                .iter()
                .all(|event| { event.str("dst") != Some(ME.to_string().as_str()) })
        );
        let mut socket = server.udp.bind(40001)?;
        socket.send_to(b"query", "8.8.8.8:53".parse()?);
        let refused = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |event| {
                event.is("net", "blocked") && event.str("dst") == Some("8.8.8.8")
            })
            .await?;
        assert_eq!(refused[0].str("why"), Some("NoRoute"));
        assert_eq!(
            refused[0]
                .conn
                .sandbox
                .as_ref()
                .map(|sandbox| &*sandbox.name),
            Some("server")
        );
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
            fail(Net::new().lan(&Lan::new("a", p("10.0.0.0/16"))))
                .is_some_and(|e| e.contains("sandboxes"))
        );
        assert!(
            fail(
                Net::new()
                    .lan(&Lan::new("a", p("192.168.0.0/16")))
                    .lan(&Lan::new("b", p("192.168.56.0/24")))
            )
            .is_some_and(|e| e.contains("overlaps LAN a"))
        );
        assert!(
            fail(Net::new().lan(&Lan::new("a", p("192.168.56.0/24"))).member(
                "vm",
                &Lan::new("a", p("192.168.56.0/24")),
                "192.168.56.1".parse().unwrap()
            ))
            .is_some()
        );
        assert!(
            fail(
                Net::new()
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
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (addr, addr6) = (
            Ipv4Addr::new(10, 40, 0, 3),
            "2606:4700:100::3".parse::<Ipv6Addr>()?,
        );
        let me6: Ipv6Addr = "2001:db8::2".parse()?;
        let spy = Spy::default();
        let budgets = spy.0.clone();
        Net::new()
            .host("svc", |h| {
                h.at(addr)
                    .at(addr6)
                    .tcp(8, Arc::new(()), || Wide)
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
                assert!(b4.used() >= 40 << 10, "{b4:?}");
                assert_eq!(b6.used(), b4.used(), "IPv6 has its own budget");
                // Leaving the region detaches the sandbox.
                Err(fictionet::Error::from(Done))
            })
            .await,
        )?;
        kept.wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
            e.is("net", "detached")
        })
        .await?;
        let a = budgets.lock().unwrap()[0].clone().expect("a budget");

        // Another sandbox at the same address: its own budget.
        let b = machine(&fcx, attacher.attach("b")?, ME);
        let mut wide = b.tcp.connect(&fcx, SocketAddr::new(addr.into(), 8)).await?;
        assert_eq!(read_some(&fcx, &mut wide, 6).await, b"hello\n");
        let _spied = b.tcp.connect(&fcx, SocketAddr::new(addr.into(), 9)).await?;
        let got = spied(&fcx, &budgets, 3).await;
        let b_budget = got[2].clone().expect("a budget");
        assert!(b_budget.used() >= 40 << 10, "{b_budget:?}");
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
    crate::common::world::observed_world(Duration::from_secs(60), |fcx, kept| async move {
        let (attacher, attachments) = fictionet::attachments();
        let dc: Ipv4Addr = "192.168.56.10".parse()?;
        let ws: Ipv4Addr = "192.168.56.31".parse()?;
        {
            let corp = Lan::new("corp", "192.168.56.0/24".parse()?);
            Net::new()
                .ipv4_only()
                .lan(&corp)
                .host("dc01", |h| {
                    h.on(&corp).at(dc).tcp(389, Arc::new(()), || Echo)
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
        let detached = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("net", "detached")
            })
            .await?;
        let first = detached[0].conn.sandbox.clone().expect("a sandbox");
        assert_eq!((&*first.name, first.addr), ("ws01", Some(ws)));
        // The server's side of the connection was reset.
        let closed = kept
            .wait(&fcx, 0, 1, Duration::from_secs(2), |e| {
                e.is("conn", "close")
            })
            .await?;
        assert_eq!(
            closed[0].conn.sandbox.as_ref().map(|s| s.id),
            Some(first.id)
        );

        // The member attaches again, as a new sandbox.
        let vm = machine(&fcx, attacher.attach("ws01")?, ws);
        let mut conn = vm.tcp.connect(&fcx, to).await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        let attached = kept.of("net", "attached");
        assert_eq!(attached.len(), 2, "{attached:?}");
        assert_ne!(
            attached[1].conn.sandbox.as_ref().map(|s| s.id),
            Some(first.id)
        );
        Ok(())
    });
}

/// LANs cannot reserve addresses from the automatic pool.
#[test]
fn lan_cannot_overlap_the_automatic_address_pool() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_, attachments) = fictionet::attachments();
        let error = Net::new()
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
        let error = Net::new()
            .lan(&Lan::new("lab", "2606:4700:100::/64".parse()?))
            .start(&fcx, attachments)
            .expect_err("overlapping LAN is refused");
        assert!(error.to_string().contains("automatic address pool"));
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
