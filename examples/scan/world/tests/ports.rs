//! Raw probes through the office, including a real server played at IP level.
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::task::Poll;

use fictionet::events::Level;
use fictionet::stdlib::network::ports::{Event, Ports as Links};
use fictionet::stdlib::network::{ip, tcp, udp};
use fictionet::time::ms;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RunOptions, Seed};
use fictionet_observe::Memory;
use scan_world::ports::MAX_ROWS;
use scan_world::{
    Machine, MachineKind, PortChanges, PortMap, PortRow, PortState, Protocol, SCANNER, SERVER,
    SERVER_ADDR, office, start,
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
fn echo_discovery_updates_snapshots_deltas_and_facts() {
    let memory = Arc::new(Memory::default());
    let history = memory.clone();
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(42)).observer(memory),
        move |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let ports = start(&fcx, office(), attachments)?;
            let mut scanner = attacher.attach(SCANNER)?;
            for (i, (last, state)) in [
                (10, PortState::Open),
                (11, PortState::Open),
                (12, PortState::Open),
                (13, PortState::Open),
                (14, PortState::Unreachable),
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
                let delta = ports.changes_since(prior);
                assert_eq!(map.revision, prior + 2);
                assert_eq!(map.rows.len(), i + 1);
                assert_eq!(delta.rows, [map.rows[i].clone()]);
                let row = &delta.rows[0];
                assert_eq!(
                    (row.host, row.protocol, row.port, row.state, row.probes),
                    (host, Protocol::Icmp, 0, state, 1)
                );
                assert_eq!(row.revision, map.revision);
                let facts = history.checked_of("scan", "port").unwrap();
                assert_eq!(facts.len(), (i + 1) * 2);
                for (event, expected, previous) in [
                    (&facts[i * 2], "unanswered", None),
                    (&facts[i * 2 + 1], state.as_str(), Some("unanswered")),
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
        let mut links = Links::new(vec![sandbox, stack_link, inject_link]);
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
            assert_eq!(
                ports.changes_since(intermediate),
                PortChanges {
                    from_revision: 8,
                    revision: 14,
                    at_ms: 90,
                    untracked: 0,
                    rows: [1, 2, 4, 6].map(|i| expected.rows[i].clone()).into(),
                }
            );
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
                        "port",
                        "protocol",
                        "state",
                        "previous",
                        "first_probe_ms",
                        "last_probe_ms",
                        "probes",
                        "revision"
                    ]
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
