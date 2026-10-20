//! Raw probes through the office, including a real server played at IP level.
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::task::Poll;

use fictionet::events::Level;
use fictionet::prelude::*;
use fictionet::stdlib::network::ports::{Event, Ports};
use fictionet::stdlib::network::{ip, tcp, udp};
use fictionet::time::ms;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RunOptions, Seed};
use fictionet_observe::{Limits, Memory};
use scan_world::ports::MAX_ROWS;
use scan_world::{
    Machine, MachineKind, PortMap, PortRow, PortState, Protocol, SCANNER, SERVER, SERVER_ADDR,
    office, start,
};

const SCANNER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 9, 2);

fn syn(host: Ipv4Addr, port: u16) -> Packet {
    tcp_packet(SCANNER_ADDR, host, (4000, port), 100, 0, 2)
}

fn tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
) -> Packet {
    let mut t = [0; 20];
    t[..2].copy_from_slice(&ports.0.to_be_bytes());
    t[2..4].copy_from_slice(&ports.1.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    let sum = ip::transport_checksum(src.into(), dst.into(), 6, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    ip::packet(src.into(), dst.into(), 6, &t)
}

fn datagram(host: Ipv4Addr, port: u16) -> Packet {
    let mut t = [0; 8];
    udp::encode(
        (SCANNER_ADDR, 4000).into(),
        (host, port).into(),
        b"",
        &mut t,
    )
    .unwrap();
    ip::packet(SCANNER_ADDR.into(), host.into(), 17, &t)
}

#[test]
fn echo_discovery_updates_snapshots_and_facts() {
    let memory = Arc::new(Memory::default());
    let history = memory.clone();
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(42)).observer(memory),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let ports = start(&fcx, office(), attachments)?;
            let mut scanner = attacher.attach(SCANNER)?;
            for (i, (last, state, state_name)) in [
                (10, PortState::Open, "open"),
                (11, PortState::Open, "open"),
                (12, PortState::Open, "open"),
                (13, PortState::Open, "open"),
                (14, PortState::Unreachable, "unreachable"),
            ]
            .into_iter()
            .enumerate()
            {
                let host = Ipv4Addr::new(10, 0, 0, last);
                let mut echo = [8, 0, 0, 0, 0x51, 0x52, 0, 1];
                let sum = ip::checksum(&echo);
                echo[2..4].copy_from_slice(&sum.to_be_bytes());
                let prior = ports.snapshot().revision;
                scanner.send(ip::packet(SCANNER_ADDR.into(), host.into(), 1, &echo));
                let reply = scanner.recv(&fcx).await?;
                let header = ip::Header::parse(&reply.0).unwrap();
                assert_eq!(header.protocol, 1);
                let payload = header.payload(&reply.0);
                assert_eq!(payload[0], if last == 14 { 3 } else { 0 });
                if last == 14 {
                    assert_eq!(payload[1], 1);
                }
                let map = ports.snapshot();
                assert_eq!(map.revision, prior + 2);
                assert_eq!(map.rows.len(), i + 1);
                let row = &map.rows[i];
                assert_eq!(
                    (row.host, row.protocol, row.port, row.state, row.probes),
                    (host, Protocol::Icmp, 0, state, 1)
                );
                assert_eq!(row.revision, map.revision);
                let facts = history.checked_of("scan", "port").unwrap();
                assert_eq!(facts.len(), (i + 1) * 2);
                for (event, expected, previous) in [
                    (&facts[i * 2], "unanswered", None),
                    (&facts[i * 2 + 1], state_name, Some("unanswered")),
                ] {
                    assert_eq!(event.str("host"), Some(host.to_string().as_str()));
                    assert_eq!(event.str("protocol"), Some("icmp"));
                    assert_eq!(event.u64("port"), Some(0));
                    assert_eq!(event.str("state"), Some(expected));
                    assert_eq!(event.str("previous"), previous);
                }
            }
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

/// The injection end lets the server send an unsolicited packet too.
fn server(fcx: &Cx, sandbox: End) -> (tcp::Endpoint, tcp::Listener, End) {
    let (stack, stack_link) = fictionet::pair();
    let (inject, inject_link) = fictionet::pair();
    fcx.spawn(move |fcx| async move {
        let mut links = Ports::new(vec![sandbox, stack_link, inject_link]);
        loop {
            match links.next(&fcx, None, |_| Poll::Pending).await? {
                Event::Packet(0, packet) => links.send(1, packet),
                Event::Packet(1 | 2, packet) => links.send(0, packet),
                Event::Closed(_) => break,
                _ => unreachable!(),
            }
        }
        Ok(())
    });
    let (t, _u, _icmp, _other) = ip::split_protocols(fcx, stack);
    let tcp = tcp::endpoint(fcx, t, SERVER_ADDR.into());
    let listener = tcp.listen(80).unwrap();
    (tcp, listener, inject)
}

#[test]
fn scan_snapshot_deltas_and_facts_follow_the_packets() {
    let memory = Arc::new(Memory::default());
    let history = memory.clone();
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(42)).observer(memory),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let ports = start(&fcx, office(), attachments)?;
            let (_server, _listener, mut inject) = server(&fcx, attacher.attach(SERVER)?);
            let mut scanner = attacher.attach(SCANNER)?;
            let mut intermediate = 0;
            let packets = [
                syn(Ipv4Addr::new(10, 0, 0, 10), 22),
                syn(Ipv4Addr::new(10, 0, 0, 10), 23),
                syn(Ipv4Addr::new(10, 0, 0, 14), 22),
                syn(SERVER_ADDR, 80),
                syn(SERVER_ADDR, 25),
                datagram(Ipv4Addr::new(10, 0, 0, 11), 53),
                datagram(SERVER_ADDR, 161),
                syn(Ipv4Addr::new(10, 0, 9, 1), 53),
                syn(Ipv4Addr::new(198, 18, 0, 1), 80),
            ];
            for (i, packet) in packets.into_iter().enumerate() {
                scanner.send(packet);
                fcx.sleep(ms(10)).await?;
                if i == 3 {
                    intermediate = ports.snapshot().revision;
                }
            }
            assert_eq!(intermediate, 8);
            scanner.send(syn(Ipv4Addr::new(10, 0, 0, 10), 23));
            fcx.sleep(ms(10)).await?;
            let expected = PortMap {
                revision: 14,
                at_ms: 90,
                max_rows: MAX_ROWS,
                untracked: 0,
                untracked_banners: 0,
                banners: vec![],
                machines: [
                    ("www", 10),
                    ("mail", 11),
                    ("files", 12),
                    ("printer", 13),
                    ("server", 50),
                ]
                .map(|(name, host)| Machine {
                    name: name.into(),
                    addr: Ipv4Addr::new(10, 0, 0, host),
                    kind: if host == 50 {
                        MachineKind::Real
                    } else {
                        MachineKind::Simulated
                    },
                })
                .into(),
                rows: [
                    (10, 22, Protocol::Tcp, PortState::Open, 0, 0, 1, 2),
                    (10, 23, Protocol::Tcp, PortState::Closed, 10, 90, 2, 14),
                    (11, 53, Protocol::Udp, PortState::Closed, 50, 50, 1, 12),
                    (14, 22, Protocol::Tcp, PortState::Unreachable, 20, 20, 1, 6),
                    (50, 25, Protocol::Tcp, PortState::Closed, 40, 40, 1, 10),
                    (50, 80, Protocol::Tcp, PortState::Open, 30, 30, 1, 8),
                    (50, 161, Protocol::Udp, PortState::Unanswered, 60, 60, 1, 13),
                ]
                .map(
                    |(
                        host,
                        port,
                        protocol,
                        state,
                        first_probe_ms,
                        last_probe_ms,
                        probes,
                        revision,
                    )| PortRow {
                        host: Ipv4Addr::new(10, 0, 0, host),
                        port,
                        protocol,
                        state,
                        first_probe_ms,
                        last_probe_ms,
                        probes,
                        revision,
                    },
                )
                .into(),
            };
            assert_eq!(ports.snapshot(), expected);
            let facts = history.checked_of("scan", "port").unwrap();
            let expected_facts = [
                ("10.0.0.10", 22, "tcp", "unanswered", None),
                ("10.0.0.10", 22, "tcp", "open", Some("unanswered")),
                ("10.0.0.10", 23, "tcp", "unanswered", None),
                ("10.0.0.10", 23, "tcp", "closed", Some("unanswered")),
                ("10.0.0.14", 22, "tcp", "unanswered", None),
                ("10.0.0.14", 22, "tcp", "unreachable", Some("unanswered")),
                ("10.0.0.50", 80, "tcp", "unanswered", None),
                ("10.0.0.50", 80, "tcp", "open", Some("unanswered")),
                ("10.0.0.50", 25, "tcp", "unanswered", None),
                ("10.0.0.50", 25, "tcp", "closed", Some("unanswered")),
                ("10.0.0.11", 53, "udp", "unanswered", None),
                ("10.0.0.11", 53, "udp", "closed", Some("unanswered")),
                ("10.0.0.50", 161, "udp", "unanswered", None),
            ];
            assert_eq!(facts.len(), expected_facts.len());
            for (i, (event, (host, port, protocol, state, previous))) in
                facts.iter().zip(expected_facts).enumerate()
            {
                assert_eq!(
                    (
                        event.str("host").unwrap(),
                        event.u64("port").unwrap(),
                        event.str("protocol").unwrap(),
                        event.str("state").unwrap(),
                        event.str("previous")
                    ),
                    (host, port, protocol, state, previous)
                );
                assert_eq!(event.get("previous").unwrap().is_null(), previous.is_none());
                assert_eq!(event.level, Level::Info);
                assert_eq!(event.summary, format!("{host}:{port}/{protocol} {state}"));
                assert_eq!(
                    event
                        .fields
                        .iter()
                        .map(|(name, _)| name)
                        .collect::<Vec<_>>(),
                    [
                        "host",
                        "protocol",
                        "state",
                        "previous",
                        "port",
                        "first_probe_ms",
                        "last_probe_ms",
                        "probes",
                        "revision"
                    ]
                );
                assert_eq!(
                    event.repeat_fields(),
                    Some(
                        &[
                            "port",
                            "first_probe_ms",
                            "last_probe_ms",
                            "probes",
                            "revision"
                        ][..]
                    )
                );
                assert_eq!(event.u64("revision"), Some(i as u64 + 1));
                let first = (i / 2) as u64 * 10;
                assert_eq!(event.u64("first_probe_ms"), Some(first));
                assert_eq!(event.u64("last_probe_ms"), Some(first));
                assert_eq!(event.u64("probes"), Some(1));
            }
            inject.send(tcp_packet(
                SERVER_ADDR,
                SCANNER_ADDR,
                (80, 4000),
                0,
                0,
                0x14,
            ));
            fcx.sleep(ms(10)).await?;
            assert_eq!(ports.snapshot(), expected);
            assert_eq!(history.checked_of("scan", "port").unwrap(), facts);
            assert!(history.checked_of("scan", "full").unwrap().is_empty());
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

/// Reads the first data a connection sends after `request`, then closes it.
async fn first_data(fcx: &Cx, tcp: &tcp::Endpoint, host: Ipv4Addr, port: u16, request: &[u8]) {
    let mut conn = tcp.connect(fcx, (host, port).into()).await.unwrap();
    if !request.is_empty() {
        conn.write_all(fcx, request).await.unwrap();
    }
    let mut bytes = [0; 512];
    assert_ne!(conn.read(fcx, &mut bytes).await.unwrap(), 0);
    conn.shutdown(fcx).await.unwrap();
}

#[test]
fn banners_from_real_connections_are_kept_once_with_facts() {
    let memory = Arc::new(Memory::default());
    let history = memory.clone();
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(42)).observer(memory),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let ports = start(&fcx, office(), attachments)?;
            let (server, mut web, _inject) = server(&fcx, attacher.attach(SERVER)?);
            fcx.spawn(move |fcx| async move {
                while let Ok(mut conn) = web.accept(&fcx).await {
                    let mut request = [0; 512];
                    let _ = conn.read(&fcx, &mut request).await;
                    conn.write_all(
                        &fcx,
                        b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await?;
                    conn.shutdown(&fcx).await?;
                }
                Ok(())
            });
            let mut ssh = server.listen(22).unwrap();
            fcx.spawn(move |fcx| async move {
                while let Ok(mut conn) = ssh.accept(&fcx).await {
                    conn.write_all(&fcx, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n\xff")
                        .await?;
                    conn.shutdown(&fcx).await?;
                }
                Ok(())
            });
            let scanner = tcp::endpoint(&fcx, attacher.attach(SCANNER)?, SCANNER_ADDR.into());
            let www = Ipv4Addr::new(10, 0, 0, 10);
            let mail = Ipv4Addr::new(10, 0, 0, 11);
            first_data(&fcx, &scanner, www, 22, b"").await;
            first_data(&fcx, &scanner, mail, 25, b"").await;
            first_data(&fcx, &scanner, SERVER_ADDR, 22, b"").await;
            let request = b"GET / HTTP/1.0\r\n\r\n";
            first_data(&fcx, &scanner, SERVER_ADDR, 80, request).await;
            let before = ports.snapshot();
            // Later connections leave every kept banner as it was.
            first_data(&fcx, &scanner, www, 22, b"").await;
            first_data(&fcx, &scanner, SERVER_ADDR, 80, request).await;
            fcx.sleep(ms(10)).await?;
            let map = ports.snapshot();
            assert_eq!(map.banners, before.banners);
            assert_eq!(
                map.banners
                    .iter()
                    .map(|b| (b.host, b.port, b.text.as_str(), b.server.as_deref()))
                    .collect::<Vec<_>>(),
                [
                    (www, 22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", None),
                    (mail, 25, "220 mail.corp.test ESMTP Postfix (Debian/GNU)", None),
                    (SERVER_ADDR, 22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", None),
                    (SERVER_ADDR, 80, "HTTP/1.1 200 OK", Some("nginx/1.24.0 (Ubuntu)")),
                ]
            );
            assert_eq!(map.untracked_banners, 0);
            for banner in &map.banners {
                let row = map
                    .rows
                    .iter()
                    .find(|r| (r.host, r.port, r.protocol) == (banner.host, banner.port, Protocol::Tcp))
                    .unwrap();
                assert_eq!(row.state, PortState::Open);
            }
            let facts = history.checked_of("scan", "banner").unwrap();
            assert_eq!(facts.len(), 4);
            for (event, banner) in facts.iter().zip(&map.banners) {
                assert_eq!(event.str("host"), Some(banner.host.to_string().as_str()));
                assert_eq!(event.u64("port"), Some(u64::from(banner.port)));
                assert_eq!(event.str("text"), Some(banner.text.as_str()));
                assert_eq!(event.str("server"), banner.server.as_deref());
                assert_eq!(event.u64("at_ms"), Some(banner.at_ms));
                assert_eq!(event.u64("revision"), Some(banner.revision));
                assert_eq!(event.level, Level::Info);
            }
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn port_facts_do_not_evict_other_events() {
    // Room for 64 ordinary events and 1,000 repeatable ones.
    let memory = Arc::new(Memory::with_noise_limits(
        Limits::new(64, 1 << 20),
        Limits::new(1000, 1 << 20),
    ));
    let history = memory.clone();
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(42)).observer(memory),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let ports = start(&fcx, office(), attachments)?;
            let mut scanner = attacher.attach(SCANNER)?;
            fcx.emit("story", "moment", |e| e.level(Level::Notice));
            for port in 1..=200 {
                scanner.send(syn(Ipv4Addr::new(10, 0, 0, 10), port));
                fcx.sleep(ms(1)).await?;
            }
            fcx.sleep(ms(50)).await?;
            assert_eq!(ports.snapshot().rows.len(), 200);
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    assert_eq!(history.checked_of("story", "moment").unwrap().len(), 1);
    let facts = history.checked_of("scan", "port").unwrap();
    assert_eq!(facts.len(), 400);
    assert!(facts.iter().all(|fact| fact.repeat_fields().is_some()));
}
