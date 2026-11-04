//! The link's other end in the QEMU test: the honeypot's gateway and
//! router, and the internet clients behind it, speaking whole Ethernet
//! frames over QEMU's socket network.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream};

use fictionet::stdlib::network::ethernet::frame::{self, Frame, Mac};
use fictionet::stdlib::network::ip;
use fictionet::stdlib::protocols::arp;
use fictionet::stdlib::protocols::mld::{self, RecordType};
use fictionet::stdlib::protocols::ndp::{
    self, Envelope, Message, NdOption, NeighborAdvertisement, NeighborSolicitation,
    RouterAdvertisement,
};

use super::frames::{ADDRESS, ADDRESS6, GATEWAY, GATEWAY_MAC};
use crate::Result;

/// The honeypot's card, as QEMU's command line sets it.
pub const HONEYPOT_MAC: Mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

/// An internet client over IPv6, behind the router.
const CLIENT6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);

/// The router's link-local address, made from its MAC as a Linux router
/// makes it.
fn router() -> Ipv6Addr {
    frame::link_local(GATEWAY_MAC)
}

/// The QEMU socket: frames, each after its length as four big-endian
/// bytes.
pub struct Peer {
    stream: TcpStream,
}

impl Peer {
    pub fn new(stream: TcpStream) -> Peer {
        Peer { stream }
    }

    pub fn send(&mut self, frame: &[u8]) -> Result {
        self.stream.write_all(&(frame.len() as u32).to_be_bytes())?;
        self.stream.write_all(frame)?;
        Ok(())
    }

    /// The next frame from the honeypot.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut size = [0; 4];
        self.stream.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        if !(frame::HEADER..=2036).contains(&size) {
            return Err("invalid honeypot frame length".into());
        }
        let mut bytes = vec![0; size];
        self.stream.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// The first frame `want` takes, answering the honeypot's ARP and
    /// neighbor discovery as the gateway does in between. `want` returns
    /// `None` to pass a frame by, and an error for a frame that should not
    /// have come.
    pub fn next<T>(&mut self, mut want: impl FnMut(&[u8]) -> Result<Option<T>>) -> Result<T> {
        loop {
            let bytes = self.recv()?;
            if self.answer(&bytes)? {
                continue;
            }
            if let Some(found) = want(&bytes)? {
                return Ok(found);
            }
        }
    }

    /// Answers a frame the honeypot sends to keep the link up, as its
    /// gateway and router do: ARP requests for the gateway, and neighbor
    /// solicitations for the router. Its group reports, router
    /// solicitations and duplicate address checks need no answer. Returns
    /// whether `bytes` was one of those.
    fn answer(&mut self, bytes: &[u8]) -> Result<bool> {
        let Some(f) = Frame::parse(bytes) else {
            return Err("invalid Ethernet frame from the honeypot".into());
        };
        if f.src != HONEYPOT_MAC {
            return Err("frame from another MAC".into());
        }
        match link(&f)? {
            Some(Link::Arp(p))
                if p.operation == arp::Operation::Request && p.target_ip == GATEWAY =>
            {
                self.send(&arp_reply())?;
                Ok(true)
            }
            Some(Link::Nd(_, Message::NeighborSolicitation(ns))) if ns.target == router() => {
                let asker = ns.options.iter().find_map(|option| match option {
                    NdOption::SourceLinkLayer(mac) => Some(*mac),
                    _ => None,
                });
                self.send(&router_advertises_itself(asker))?;
                Ok(true)
            }
            Some(Link::Mld(_) | Link::Nd(_, Message::RouterSolicitation(_))) => Ok(true),
            Some(Link::Nd(envelope, Message::NeighborSolicitation(_)))
                if envelope.source.is_unspecified() =>
            {
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// A link-layer message from the honeypot.
enum Link {
    Arp(arp::Packet),
    Nd(Envelope, Message),
    Mld(mld::Report),
}

/// The ARP, neighbor discovery or MLD message `f` carries, checked as a
/// receiver checks it, or `None` for anything else.
fn link(f: &Frame<'_>) -> Result<Option<Link>> {
    match f.ethertype {
        frame::ARP => Ok(Some(Link::Arp(
            arp::Packet::receive(f.payload).map_err(|e| format!("ARP: {e}"))?,
        ))),
        frame::IPV6 => {
            let packet = frame::ip_packet(f.ethertype, f.payload).ok_or("invalid IPv6 packet")?;
            let header = ip::Header::parse_whole(packet).ok_or("invalid IPv6 header")?;
            let msg = header.payload(packet);
            if header.protocol != 58 || msg.is_empty() {
                return Ok(None);
            }
            if msg[0] == mld::REPORT_V2 {
                let report = mld::Report::from_packet(packet).map_err(|e| format!("MLD: {e}"))?;
                return Ok(Some(Link::Mld(report)));
            }
            if !(133..=137).contains(&msg[0]) {
                return Ok(None);
            }
            let envelope = Envelope::of(packet).ok_or("neighbor discovery envelope")?;
            let message =
                Message::receive(&envelope, msg).map_err(|e| format!("neighbor discovery: {e}"))?;
            Ok(Some(Link::Nd(envelope, message)))
        }
        _ => Ok(None),
    }
}

/// The gateway's ARP reply to the honeypot.
fn arp_reply() -> Vec<u8> {
    let reply = arp::Packet {
        operation: arp::Operation::Reply,
        sender_mac: GATEWAY_MAC,
        sender_ip: GATEWAY,
        target_mac: HONEYPOT_MAC,
        target_ip: ADDRESS,
    };
    frame::frame(HONEYPOT_MAC, GATEWAY_MAC, frame::ARP, &reply.encode())
}

/// The router's solicited advertisement of its own address, to the
/// honeypot's link-local address, with the router flag set so the
/// honeypot keeps it as its default router.
fn router_advertises_itself(asker: Option<Mac>) -> Vec<u8> {
    let na = Message::NeighborAdvertisement(NeighborAdvertisement {
        router: true,
        solicited: true,
        overrides: true,
        target: router(),
        options: vec![NdOption::TargetLinkLayer(GATEWAY_MAC)],
    });
    let packet = na
        .packet(router(), frame::link_local(HONEYPOT_MAC))
        .expect("a valid advertisement");
    let dst = asker.unwrap_or(HONEYPOT_MAC);
    frame::frame(dst, GATEWAY_MAC, frame::IPV6, &packet)
}

/// What the honeypot sends when it starts, before anything answers it:
/// an MLDv2 report from the unspecified address that joins the
/// solicited-node groups of both its IPv6 addresses (RFC 4862 section
/// 5.4.2), one duplicate address detection solicitation for each address
/// (RFC 4862 section 5.4.2), ARP for its gateway at once and again after
/// a second, and, once its link-local address passed the check, a router
/// solicitation from it (RFC 4861 section 6.3.7). Then the gateway
/// answers the ARP, and the router advertises itself.
pub fn start_link(peer: &mut Peer) -> Result {
    let link_local = frame::link_local(HONEYPOT_MAC);
    let request = arp::Packet {
        operation: arp::Operation::Request,
        sender_mac: HONEYPOT_MAC,
        sender_ip: ADDRESS,
        target_mac: [0; 6],
        target_ip: GATEWAY,
    };
    let expected_arp = frame::frame(
        frame::BROADCAST,
        HONEYPOT_MAC,
        frame::ARP,
        &request.encode(),
    );
    let groups: HashSet<Ipv6Addr> = [
        ndp::solicited_node(link_local),
        ndp::solicited_node(ADDRESS6),
    ]
    .into_iter()
    .collect();
    let mut arps = 0;
    let mut joined = false;
    let mut checked = HashSet::new();
    let mut solicited_router = false;
    while arps < 2 || !solicited_router {
        let bytes = peer.recv()?;
        let f = Frame::parse(&bytes).ok_or("invalid Ethernet frame from the honeypot")?;
        match link(&f)? {
            Some(Link::Arp(_)) => {
                if bytes != expected_arp {
                    return Err("honeypot did not request its configured gateway".into());
                }
                arps += 1;
            }
            Some(Link::Mld(report)) => {
                let ip = ip::Header::parse_whole(frame::ip_packet(f.ethertype, f.payload).unwrap())
                    .ok_or("invalid MLD packet")?;
                let reported: HashSet<Ipv6Addr> = report
                    .records
                    .iter()
                    .filter(|r| r.kind == RecordType::ChangeToExclude && r.sources.is_empty())
                    .map(|r| r.group)
                    .collect();
                if reported != groups
                    || f.dst != frame::multicast_mac(mld::ALL_MLDV2_ROUTERS)
                    || ![IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6(link_local)]
                        .contains(&ip.src)
                {
                    return Err("honeypot did not join its solicited-node groups".into());
                }
                joined |= ip.src == IpAddr::V6(Ipv6Addr::UNSPECIFIED);
            }
            Some(Link::Nd(envelope, Message::NeighborSolicitation(ns)))
                if envelope.source.is_unspecified() =>
            {
                let group = ndp::solicited_node(ns.target);
                if !joined
                    || !ns.options.is_empty()
                    || envelope.destination != group
                    || f.dst != frame::multicast_mac(group)
                    || ![link_local, ADDRESS6].contains(&ns.target)
                {
                    return Err("invalid duplicate address detection".into());
                }
                checked.insert(ns.target);
            }
            Some(Link::Nd(envelope, Message::RouterSolicitation(rs))) => {
                if checked.len() != 2
                    || envelope.source != link_local
                    || envelope.destination != ndp::ALL_ROUTERS
                    || rs.options != [NdOption::SourceLinkLayer(HONEYPOT_MAC)]
                {
                    return Err("router solicitation before the address checks".into());
                }
                solicited_router = true;
            }
            _ => return Err("unexpected frame while the honeypot started".into()),
        }
    }
    println!(
        "Honeypot joined its groups, checked both IPv6 addresses for duplicates, and solicited a router"
    );
    peer.send(&arp_reply())?;
    println!("Honeypot requested and retried ARP for its configured gateway");
    let ra = Message::RouterAdvertisement(RouterAdvertisement {
        cur_hop_limit: 64,
        managed: false,
        other: false,
        router_lifetime: 1800,
        reachable_time: 0,
        retrans_timer: 0,
        options: vec![NdOption::SourceLinkLayer(GATEWAY_MAC)],
    });
    let packet = ra.packet(router(), ndp::ALL_NODES)?;
    peer.send(&frame::frame(
        frame::multicast_mac(ndp::ALL_NODES),
        GATEWAY_MAC,
        frame::IPV6,
        &packet,
    ))?;
    Ok(())
}

/// The neighbor advertisement in `bytes`, if it is one for `target`.
fn advertisement(
    bytes: &[u8],
    target: Ipv6Addr,
) -> Result<Option<(Mac, Envelope, NeighborAdvertisement)>> {
    let f = Frame::parse(bytes).ok_or("invalid Ethernet frame")?;
    match link(&f)? {
        Some(Link::Nd(envelope, Message::NeighborAdvertisement(na))) if na.target == target => {
            Ok(Some((f.dst, envelope, na)))
        }
        _ => Err("expected a neighbor advertisement".into()),
    }
}

/// The router resolves the honeypot's IPv6 address, and another node
/// checks whether the address is free: the first gets a solicited answer
/// at its MAC, the second an answer to all nodes (RFC 4861 section 7.2.4).
pub fn neighbor_discovery(peer: &mut Peer) -> Result {
    let group = ndp::solicited_node(ADDRESS6);
    let solicit = |source: Ipv6Addr, options: Vec<NdOption>| -> Result<Vec<u8>> {
        let ns = Message::NeighborSolicitation(NeighborSolicitation {
            target: ADDRESS6,
            options,
        });
        let packet = ns.packet(source, group)?;
        Ok(frame::frame(
            frame::multicast_mac(group),
            GATEWAY_MAC,
            frame::IPV6,
            &packet,
        ))
    };
    peer.send(&solicit(
        router(),
        vec![NdOption::SourceLinkLayer(GATEWAY_MAC)],
    )?)?;
    let (dst, envelope, na) = peer.next(|bytes| advertisement(bytes, ADDRESS6))?;
    if dst != GATEWAY_MAC
        || envelope.source != ADDRESS6
        || envelope.destination != router()
        || !na.solicited
        || !na.overrides
        || na.router
        || na.options != [NdOption::TargetLinkLayer(HONEYPOT_MAC)]
    {
        return Err("invalid answer to the router's neighbor solicitation".into());
    }
    println!("Honeypot answered the router's neighbor solicitation for its IPv6 address");
    peer.send(&solicit(Ipv6Addr::UNSPECIFIED, vec![])?)?;
    let (dst, envelope, na) = peer.next(|bytes| advertisement(bytes, ADDRESS6))?;
    if dst != frame::multicast_mac(ndp::ALL_NODES)
        || envelope.destination != ndp::ALL_NODES
        || na.solicited
        || !na.overrides
        || na.options != [NdOption::TargetLinkLayer(HONEYPOT_MAC)]
    {
        return Err("invalid defense of the IPv6 address".into());
    }
    println!("Honeypot defended its IPv6 address against duplicate address detection");
    Ok(())
}

/// A TCP segment from the IPv6 client to the honeypot's `port`, framed by
/// the router.
fn segment6(port: u16, seq: u32, ack: u32, flags: u8, options: &[u8]) -> Vec<u8> {
    let mut segment = Vec::from(0x4321u16.to_be_bytes());
    segment.extend(port.to_be_bytes());
    segment.extend(seq.to_be_bytes());
    segment.extend(ack.to_be_bytes());
    segment.extend([((20 + options.len()) / 4) as u8 * 16, flags]);
    segment.extend([0xff, 0xff, 0, 0, 0, 0]);
    segment.extend(options);
    let checksum = ip::transport_checksum(CLIENT6.into(), ADDRESS6.into(), 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    let packet = ip::packet(CLIENT6.into(), ADDRESS6.into(), 6, &segment);
    frame::frame(HONEYPOT_MAC, GATEWAY_MAC, frame::IPV6, &packet.0)
}

/// The TCP segment in `bytes`, checked to come from the honeypot's IPv6
/// address and port 22 to the client, through the router.
fn from_ssh6(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let f = Frame::parse(bytes).ok_or("invalid Ethernet frame")?;
    let packet = frame::ip_packet(f.ethertype, f.payload).ok_or("expected an IP packet")?;
    let header = ip::Header::parse_whole(packet).ok_or("invalid IP packet")?;
    let segment = header.payload(packet);
    if f.dst != GATEWAY_MAC
        || f.ethertype != frame::IPV6
        || header.src != IpAddr::V6(ADDRESS6)
        || header.dst != IpAddr::V6(CLIENT6)
        || header.protocol != 6
        || segment.len() < 20
        || segment[..4] != [0, 22, 0x43, 0x21]
        || ip::transport_checksum(header.src, header.dst, 6, segment) != 0
    {
        return Err("invalid IPv6 TCP segment from the honeypot".into());
    }
    Ok(Some(segment.to_vec()))
}

/// A client connects to SSH at the honeypot's IPv6 address, which answers
/// through the router it learned from the advertisement, and reads the
/// banner.
pub fn ssh6(peer: &mut Peer) -> Result {
    peer.send(&segment6(22, 1000, 0, 0x02, &[2, 4, 0x05, 0xa0]))?;
    let syn_ack = peer.next(from_ssh6)?;
    if syn_ack[13] != 0x12 || syn_ack[8..12] != 1001u32.to_be_bytes() {
        return Err("honeypot did not answer the IPv6 SYN with a SYN-ACK".into());
    }
    let iss = u32::from_be_bytes(syn_ack[4..8].try_into()?);
    peer.send(&segment6(22, 1001, iss.wrapping_add(1), 0x10, &[]))?;
    let data = peer.next(from_ssh6)?;
    let payload = &data[usize::from(data[12] >> 4) * 4..];
    if !payload.starts_with(b"SSH-2.0-OpenSSH_") || !payload.ends_with(b"\r\n") {
        return Err("honeypot did not send the SSH banner over IPv6".into());
    }
    let acked = iss.wrapping_add(1).wrapping_add(payload.len() as u32);
    peer.send(&segment6(22, 1001, acked, 0x10, &[]))?;
    peer.send(&segment6(22, 1001, acked, 0x04, &[]))?;
    println!("Honeypot served the SSH banner at its IPv6 address through the advertised router");
    Ok(())
}
