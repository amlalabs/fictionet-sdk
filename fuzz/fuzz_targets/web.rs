//! `web::Sites` as one sandbox reaches it, packet by packet: the filter
//! that binds the sandbox's address, DHCP, DNS over UDP and TCP, routing,
//! "host unreachable", and the TCP stacks of the gateway and the sites'
//! machines, with events on.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use arbitrary::Arbitrary;
use fictionet::stdlib::dhcp;
use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RecordType};
use fictionet::{Interface, Packet};
use fictionet_fuzz::web::{DEFAULT_ADDR, NAMES, SITE_ADDR, serve};
use fictionet_fuzz::{Segment, fix_checksums, poll_once, settle, tcp_packet, udp_packet, world};
use libfuzzer_sys::fuzz_target;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

#[derive(Arbitrary, Debug)]
enum Step {
    /// Any packet.
    Raw { fix: bool, bytes: Vec<u8> },
    /// A UDP datagram to the gateway's DNS server, any bytes.
    DnsBytes(Vec<u8>),
    /// A well-formed query for one of the world's names.
    DnsQuery { name: u8, qtype: u16, id: u16, edns: bool },
    /// A DHCP message from 0.0.0.0, any bytes after a valid start.
    Dhcp { kind: u8, xid: u32, requested: Option<u8>, ciaddr: Option<u8>, server: Option<u8>, extra: Vec<u8> },
    /// A TCP segment to the gateway or a site.
    Tcp { to: u8, sport: u8, dport: u8, seq: u32, ack: u32, flags: u8, data: Vec<u8> },
    /// Let the world run.
    Pump(u8),
}

fn dst(to: u8) -> Ipv4Addr {
    [GATEWAY, SITE_ADDR, DEFAULT_ADDR, Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(10, 0, 0, 3)][to as usize % 5]
}

fuzz_target!(|steps: Vec<Step>| {
    world(move |cx| async move {
        let attacher = serve(&cx);
        let mut end = attacher.attach("agent").unwrap();
        let me = IpAddr::V4(ME);
        for step in steps {
            let packet = match step {
                Step::Raw { fix, mut bytes } => {
                    if fix {
                        fix_checksums(&mut bytes);
                    }
                    bytes
                }
                Step::DnsBytes(b) => udp_packet(me, 5353, GATEWAY.into(), 53, &b),
                Step::DnsQuery { name, qtype, id, edns } => {
                    let mut m = Message::query();
                    m.metadata.id = id;
                    let n = Name::from_ascii(format!("{}.", NAMES[name as usize % NAMES.len()])).unwrap();
                    m.add_query(Query::query(n, RecordType::from(qtype)));
                    if edns {
                        m.edns = Some(Default::default());
                    }
                    udp_packet(me, 5353, GATEWAY.into(), 53, &m.to_vec().unwrap())
                }
                Step::Dhcp { kind, xid, requested, ciaddr, server, extra } => {
                    let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, xid);
                    m.push(dhcp::opt::MESSAGE_TYPE, [kind % 9]);
                    if let Some(r) = requested {
                        m.push(dhcp::opt::REQUESTED_IP, [10, 0, 0, r]);
                    }
                    if let Some(c) = ciaddr {
                        m.ciaddr = Ipv4Addr::new(10, 0, 0, c);
                    }
                    if let Some(s) = server {
                        m.push(dhcp::opt::SERVER_ID, [10, 0, 0, s]);
                    }
                    // The extra bytes go before the END option, where the
                    // parser still reads them as options.
                    let mut b = m.to_bytes();
                    let end = b.iter().rposition(|&x| x == dhcp::opt::END).unwrap();
                    b.truncate(end);
                    b.extend_from_slice(&extra);
                    b.push(dhcp::opt::END);
                    let src = if ciaddr.is_some() { m.ciaddr } else { Ipv4Addr::UNSPECIFIED };
                    udp_packet(src.into(), 68, Ipv4Addr::BROADCAST.into(), 67, &b)
                }
                Step::Tcp { to, sport, dport, seq, ack, flags, data } => {
                    let dport = [53, 80, 443, 22][dport as usize % 4];
                    let seg = Segment {
                        sport: 40000 + (sport % 8) as u16,
                        dport,
                        seq,
                        ack,
                        flags,
                        window: 65535,
                        options: &[],
                        data: &data,
                        bad_checksum: false,
                    };
                    tcp_packet(me, dst(to).into(), &seg)
                }
                Step::Pump(n) => {
                    settle(&cx, 1 + n as usize % 16).await;
                    while let Some(Ok(_)) = poll_once(fictionet::InterfaceExt::recv(&mut end, &cx)).await {}
                    continue;
                }
            };
            end.send(Packet(packet));
        }
        settle(&cx, 16).await;
        drop(end);
        settle(&cx, 8).await;
    });
});
