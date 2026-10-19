//! Ethernet frames: reading and writing them, and the link-local answers
//! the link gives itself (ARP and IPv6 neighbor advertisements).
//!
//! Everything here is pure: it takes bytes and returns bytes. The VM is
//! run by the agent, so every frame is read as hostile input: no length
//! is trusted before it is checked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fictionet::stdlib::network::ip::{self, Fields, Header};
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::udp;

/// A MAC address.
pub type Mac = [u8; 6];

/// The broadcast MAC.
pub const BROADCAST: Mac = [0xff; 6];

/// The link's own MAC, on the VM's side: the gateway's, as the VM sees
/// it. It is locally administered (`02:...`), and the same every run, so a
/// VM that keeps running while the link restarts keeps a valid ARP entry.
pub const GATEWAY_MAC: Mac = [0x02, 0x66, 0x6e, 0x00, 0x00, 0x01];

/// The EtherType of IPv4.
pub const IPV4: u16 = 0x0800;
/// The EtherType of ARP.
pub const ARP: u16 = 0x0806;
/// The EtherType of IPv6.
pub const IPV6: u16 = 0x86dd;

/// The length of an Ethernet header.
pub const HEADER: usize = 14;

pub(super) const UDP: u8 = 17;
pub(super) const ICMPV6: u8 = 58;

/// An Ethernet frame, read.
pub struct Frame<'a> {
    /// The destination MAC.
    pub dst: Mac,
    /// The source MAC.
    pub src: Mac,
    /// The type of the payload, such as [`IPV4`].
    pub ethertype: u16,
    /// Everything after the header, padding included.
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Reads a frame. `None` if it is shorter than a header.
    pub fn parse(b: &'a [u8]) -> Option<Frame<'a>> {
        if b.len() < HEADER {
            return None;
        }
        Some(Frame {
            dst: b[0..6].try_into().unwrap(),
            src: b[6..12].try_into().unwrap(),
            ethertype: u16::from_be_bytes([b[12], b[13]]),
            payload: &b[HEADER..],
        })
    }
}

/// Whether a MAC is a group (broadcast or multicast) address.
pub fn is_group(mac: &Mac) -> bool {
    mac[0] & 1 == 1
}

/// An Ethernet header.
pub fn header(dst: Mac, src: Mac, ethertype: u16) -> [u8; HEADER] {
    let mut h = [0u8; HEADER];
    h[0..6].copy_from_slice(&dst);
    h[6..12].copy_from_slice(&src);
    h[12..14].copy_from_slice(&ethertype.to_be_bytes());
    h
}

/// A whole frame: a header, then `payload`, padded to Ethernet's minimum
/// of 60 bytes.
pub fn frame(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity((HEADER + payload.len()).max(60));
    f.extend_from_slice(&header(dst, src, ethertype));
    f.extend_from_slice(payload);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

/// The Ethernet destination and type for an IP packet on its way to the
/// VM: broadcast for 255.255.255.255, the multicast MAC for a multicast
/// address, and otherwise `vm`. Unicast is dropped until the VM's MAC is
/// known. `None` if the packet is neither IPv4 nor IPv6.
///
/// A known subnet's directed broadcast also uses the broadcast MAC.
/// Prefixes /31 and /32 have no directed broadcast. With Family::FromWorld,
/// the link does not know the subnet and treats directed broadcasts as unicast.
pub(super) fn destination(
    packet: &[u8],
    vm: Option<Mac>,
    subnet: Option<(Ipv4Addr, u8)>,
) -> Option<(Mac, u16)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let d: [u8; 4] = packet[16..20].try_into().unwrap();
            let mac = if d == [255; 4]
                || subnet.is_some_and(|(addr, prefix)| {
                    Prefix {
                        addr: addr.into(),
                        len: prefix,
                    }
                    .broadcast()
                        == Some(Ipv4Addr::from(d))
                }) {
                BROADCAST
            } else if Ipv4Addr::from(d).is_multicast() {
                [0x01, 0x00, 0x5e, d[1] & 0x7f, d[2], d[3]]
            } else {
                vm?
            };
            Some((mac, IPV4))
        }
        6 if packet.len() >= 40 => {
            let d = &packet[24..40];
            let mac = if d[0] == 0xff {
                [0x33, 0x33, d[12], d[13], d[14], d[15]]
            } else {
                vm?
            };
            Some((mac, IPV6))
        }
        _ => None,
    }
}

/// The IP packet in an IPv4 or IPv6 frame's payload, without the padding
/// Ethernet may add after it. `None` if the header is broken or says the
/// packet is longer than the payload.
pub(super) fn ip_packet(ethertype: u16, payload: &[u8]) -> Option<&[u8]> {
    let version = match ethertype {
        IPV4 => 4,
        IPV6 => 6,
        _ => return None,
    };
    if payload.first()? >> 4 != version {
        return None;
    }
    let h = Header::parse(payload)?;
    Some(&payload[..h.payload.end])
}

// Packet building, on the stdlib's IP layer

/// An IPv4 packet around `payload`, with TTL 64, identification 0, no
/// flags and a correct header checksum.
pub(super) fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    ip::packet_with(
        src.into(),
        dst.into(),
        proto,
        Fields {
            dont_fragment: false,
            ..Fields::default()
        },
        payload,
    )
    .0
}

/// A UDP datagram in an IPv4 packet, with a correct checksum.
pub(super) fn udp4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    ipv4(
        src,
        dst,
        UDP,
        &udp(src.into(), sport, dst.into(), dport, data),
    )
}

/// A UDP datagram from `src` to `dst`, with a correct checksum.
fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, data: &[u8]) -> Vec<u8> {
    let len = udp::encoded_len(src, dst, data.len()).expect("a DHCP reply fits one IP packet");
    let mut u = vec![0; len];
    udp::encode(
        SocketAddr::new(src, sport),
        SocketAddr::new(dst, dport),
        data,
        &mut u,
    )
    .expect("a checked UDP length fits");
    u
}

/// An IPv6 packet around `payload`.
pub(super) fn ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    ip::packet_with(
        src.into(),
        dst.into(),
        next,
        Fields {
            ttl: hop_limit,
            ..Fields::default()
        },
        payload,
    )
    .0
}

/// A UDP datagram in an IPv6 packet, with a correct checksum.
pub(super) fn udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, data: &[u8]) -> Vec<u8> {
    ipv6(
        src,
        dst,
        UDP,
        64,
        &udp(src.into(), sport, dst.into(), dport, data),
    )
}

/// An ICMPv6 message in an IPv6 packet with hop limit 255, as neighbor
/// discovery requires. `body` is the whole message with its checksum
/// field (bytes 2 and 3) zero; this fills it in.
pub(super) fn icmp6(src: Ipv6Addr, dst: Ipv6Addr, mut body: Vec<u8>) -> Vec<u8> {
    let sum = ip::transport_checksum(src.into(), dst.into(), ICMPV6, &body);
    body[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv6(src, dst, ICMPV6, 255, &body)
}

/// The link-local address made from a MAC (modified EUI-64).
pub(super) fn link_local(mac: Mac) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8] = mac[0] ^ 0x02;
    a[9] = mac[1];
    a[10] = mac[2];
    a[11] = 0xff;
    a[12] = 0xfe;
    a[13] = mac[3];
    a[14] = mac[4];
    a[15] = mac[5];
    Ipv6Addr::from(a)
}

// ARP and neighbor discovery

/// The answer to an ARP request from the VM: a reply frame that gives
/// [`GATEWAY_MAC`] for the asked address. The link answers for every
/// address, as a proxy ARP router does, so every packet the VM sends
/// reaches the link, and the world decides what is there. It does not
/// answer:
///
/// - probes (sender address 0.0.0.0) and gratuitous ARP (sender address
///   equal to the target): an answer would tell the VM its own address is
///   taken;
/// - questions about `own`, the address the link handed the VM, for the same
///   reason;
/// - anything that is not an Ethernet/IPv4 request.
pub(super) fn arp_reply(arp: &[u8], vm: Mac, own: Option<Ipv4Addr>) -> Option<Vec<u8>> {
    if arp.len() < 28 || arp[0..8] != [0, 1, 0x08, 0x00, 6, 4, 0, 1] {
        return None;
    }
    let sha = &arp[8..14];
    let spa = &arp[14..18];
    let tpa = &arp[24..28];
    if spa == [0; 4] || spa == tpa || own.is_some_and(|a| a.octets() == tpa) {
        return None;
    }
    let mut reply = Vec::with_capacity(28);
    reply.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
    reply.extend_from_slice(&GATEWAY_MAC);
    reply.extend_from_slice(tpa);
    reply.extend_from_slice(sha);
    reply.extend_from_slice(spa);
    Some(frame(vm, GATEWAY_MAC, ARP, &reply))
}

/// ICMPv6 types of neighbor discovery.
pub(super) const ROUTER_SOLICITATION: u8 = 133;
pub(super) const ROUTER_ADVERTISEMENT: u8 = 134;
pub(super) const NEIGHBOR_SOLICITATION: u8 = 135;
pub(super) const NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub(super) const REDIRECT: u8 = 137;

/// What the link needs to know about the transport of one IP packet from
/// the VM. [`Header::check`] reads the extension headers and fragments,
/// with the parser the world's own stack uses; this adds the UDP port and
/// the ICMPv6 type.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Upper<'a> {
    /// A whole UDP datagram: its destination port and payload.
    Udp { port: u16, payload: &'a [u8] },
    /// The first fragment of a UDP datagram: its destination port. The rest
    /// of the datagram is in later fragments, which the link does not keep.
    UdpFragment { port: u16 },
    /// An ICMPv6 message: its type, and the message from its first byte.
    /// With `fragment`, this is the first fragment of a longer message.
    Icmp6 {
        kind: u8,
        msg: &'a [u8],
        fragment: bool,
    },
    /// Any other transport, or a fragment other than the first, which
    /// holds no transport header.
    Other,
    /// The world must process an IPv6 Parameter Problem.
    Problem,
}

/// A packet whose transport the link cannot read: an IPv6 extension header
/// that runs past its end, a UDP or ICMPv6 header cut short, or a UDP length
/// that does not fit the packet. IPv6 Parameter Problems are passed separately.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Unreadable;

/// Reads the transport of an IP packet, which [`ip_packet`] has checked.
/// Checks complete UDP lengths, but leaves checksums to the recipient.
pub(super) fn upper(packet: &[u8]) -> Result<Upper<'_>, Unreadable> {
    let h = match Header::check(packet) {
        Ok(h) => h,
        Err(ip::Reject::Problem { .. }) => return Ok(Upper::Problem),
        Err(ip::Reject::Discard) => return Err(Unreadable),
    };
    // An atomic fragment is a whole packet, but neighbor discovery may not
    // carry a fragment header at all (RFC 6980), so it counts as a fragment
    // here. A fragment after the first holds no transport header.
    let fragment = match h.fragment {
        Some(f) if f.offset != 0 => return Ok(Upper::Other),
        f => f.is_some(),
    };
    let (proto, bytes) = (h.protocol, h.payload(packet));
    match proto {
        UDP => {
            if fragment {
                if bytes.len() < 8 {
                    return Err(Unreadable);
                }
                let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                return Ok(Upper::UdpFragment { port });
            }
            let datagram = udp::Datagram::parse(bytes).ok_or(Unreadable)?;
            Ok(Upper::Udp {
                port: datagram.destination_port(),
                payload: datagram.payload(),
            })
        }
        ICMPV6 if packet[0] >> 4 == 6 => {
            if bytes.len() < 4 {
                return Err(Unreadable);
            }
            Ok(Upper::Icmp6 {
                kind: bytes[0],
                msg: bytes,
                fragment,
            })
        }
        _ => Ok(Upper::Other),
    }
}

/// The ICMPv6 types of neighbor discovery and redirects, which only make
/// sense on one link.
pub(super) fn is_neighbor_discovery(kind: u8) -> bool {
    (ROUTER_SOLICITATION..=REDIRECT).contains(&kind)
}

/// Checks solicitation fields and option boundaries. Checksums belong to
/// the recipient because a VM backend may leave them to an offload.
pub(super) fn solicitation_valid(packet: &[u8], msg: &[u8], fixed: usize) -> bool {
    if packet[7] != 255 || msg.len() < fixed || msg[1] != 0 {
        return false;
    }
    let mut options = &msg[fixed..];
    while !options.is_empty() {
        if options.len() < 2
            || options[1] == 0
            || (source_v6(packet).is_unspecified() && options[0] == 1)
        {
            return false;
        }
        let Some(rest) = options.get(usize::from(options[1]) * 8..) else {
            return false;
        };
        options = rest;
    }
    true
}

/// Whether a packet that calls for Parameter Problem hides neighbor discovery.
pub(super) fn problem_hides_neighbor_discovery(packet: &[u8]) -> bool {
    Header::parse(packet).is_some_and(|h| {
        h.protocol == ICMPV6
            && h.payload(packet)
                .first()
                .is_some_and(|kind| is_neighbor_discovery(*kind))
    })
}

/// The answer to a neighbor solicitation from the VM: a neighbor
/// advertisement that gives [`GATEWAY_MAC`] for the target, for the same
/// reason [`arp_reply`] answers every address. It does not answer
/// duplicate address detection (source `::`), a target that is the source,
/// `own` or multicast, or a solicitation with invalid fields or options.
pub(super) fn neighbor_advert(
    packet: &[u8],
    msg: &[u8],
    vm: Mac,
    own: Option<Ipv6Addr>,
) -> Option<Vec<u8>> {
    if !solicitation_valid(packet, msg, 24) {
        return None;
    }
    let src = source_v6(packet);
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&msg[8..24]).unwrap());
    if src.is_unspecified() || src == target || target.is_multicast() || Some(target) == own {
        return None;
    }
    let mut body = Vec::with_capacity(32);
    // Router, solicited and override: the VM may use the link as a router
    // for any address, so the router flag is always set.
    body.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT, 0, 0, 0, 0xe0, 0, 0, 0]);
    body.extend_from_slice(&target.octets());
    // Target link-layer address option.
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&GATEWAY_MAC);
    let ip = icmp6(target, src, body);
    Some(frame(vm, GATEWAY_MAC, IPV6, &ip))
}

/// The UDP destination port and payload of an IPv4 or IPv6 packet that
/// holds a whole UDP datagram. `None` otherwise.
#[cfg(test)]
pub(super) fn udp_to(packet: &[u8]) -> Option<(u16, &[u8])> {
    match upper(packet) {
        Ok(Upper::Udp { port, payload }) => Some((port, payload)),
        _ => None,
    }
}

/// The source address of an IPv4 or IPv6 packet. The packet must be at
/// least a header long, as [`ip_packet`] checks.
pub(super) fn source_v4(packet: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])
}

pub(super) fn source_v6(packet: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::addresses::{router_advert, tests::lease6};
    use super::*;

    fn answer_solicitation(packet: &[u8], vm: Mac, own: Option<Ipv6Addr>) -> Option<Vec<u8>> {
        let Ok(Upper::Icmp6 {
            kind: NEIGHBOR_SOLICITATION,
            msg,
            fragment: false,
        }) = upper(packet)
        else {
            return None;
        };
        super::neighbor_advert(packet, msg, vm, own)
    }

    pub(crate) const VM: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    pub(crate) fn v6_checksum_ok(packet: &[u8]) -> bool {
        let src = source_v6(packet);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
        ip::transport_checksum(src.into(), dst.into(), packet[6], &packet[40..]) == 0
    }

    pub(crate) fn arp_request(spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut a = vec![0, 1, 0x08, 0x00, 6, 4, 0, 1];
        a.extend_from_slice(&VM);
        a.extend_from_slice(&spa);
        a.extend_from_slice(&[0; 6]);
        a.extend_from_slice(&tpa);
        a
    }

    #[test]
    fn frames_parse_and_build() {
        let f = frame(VM, GATEWAY_MAC, IPV4, &[1, 2, 3]);
        assert_eq!(f.len(), 60, "padded to the minimum");
        let p = Frame::parse(&f).unwrap();
        assert_eq!((p.dst, p.src, p.ethertype), (VM, GATEWAY_MAC, IPV4));
        assert_eq!(&p.payload[..3], &[1, 2, 3]);
        assert!(Frame::parse(&f[..13]).is_none());
        assert!(is_group(&BROADCAST) && is_group(&[0x33, 0x33, 0, 0, 0, 1]) && !is_group(&VM));
    }

    #[test]
    fn padding_is_trimmed_and_lying_lengths_are_refused() {
        let p = udp4(
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            2,
            b"hi",
        );
        let mut padded = p.clone();
        padded.resize(46, 0);
        assert_eq!(ip_packet(IPV4, &padded), Some(&p[..]));
        assert_eq!(
            ip_packet(IPV4, &p[..p.len() - 1]),
            None,
            "total length past the end"
        );
        let mut bad = p.clone();
        bad[0] = 0x44;
        assert_eq!(ip_packet(IPV4, &bad), None, "header length under 20");
        let p6 = udp6(link_local(VM), 1, link_local(GATEWAY_MAC), 2, b"hi");
        let mut padded = p6.clone();
        padded.extend_from_slice(&[0; 4]);
        assert_eq!(ip_packet(IPV6, &padded), Some(&p6[..]));
        assert_eq!(ip_packet(IPV6, &p6[..p6.len() - 1]), None);
        assert_eq!(ip_packet(IPV6, &p), None, "an IPv4 packet in an IPv6 frame");
        assert_eq!(ip_packet(ARP, &p), None);
    }

    #[test]
    fn built_packets_have_correct_checksums() {
        let p = udp4(
            Ipv4Addr::new(10, 0, 0, 1),
            67,
            Ipv4Addr::BROADCAST,
            68,
            b"odd",
        );
        assert_eq!(ip::checksum(&p[..20]), 0, "IPv4 header");
        let (src, dst) = (
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::BROADCAST.into(),
        );
        assert_eq!(
            ip::transport_checksum(src, dst, UDP, &p[20..]),
            0,
            "UDP over IPv4"
        );
        let p = udp6(link_local(GATEWAY_MAC), 547, link_local(VM), 546, b"odd");
        assert!(v6_checksum_ok(&p));
        assert_eq!(udp_to(&p), Some((546, &b"odd"[..])));
    }

    #[test]
    fn destinations() {
        let to = |dst: Ipv4Addr| {
            destination(
                &ipv4(Ipv4Addr::new(10, 0, 0, 1), dst, UDP, &[]),
                Some(VM),
                None,
            )
        };
        assert_eq!(to(Ipv4Addr::new(10, 0, 0, 2)), Some((VM, IPV4)));
        assert_eq!(to(Ipv4Addr::BROADCAST), Some((BROADCAST, IPV4)));
        assert_eq!(
            to(Ipv4Addr::new(239, 129, 2, 3)),
            Some(([1, 0, 0x5e, 1, 2, 3], IPV4))
        );
        let p = ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            UDP,
            &[],
        );
        assert_eq!(
            destination(&p, None, None),
            None,
            "the VM's MAC is not known yet"
        );
        let p = ipv6(
            link_local(GATEWAY_MAC),
            "ff02::1:ff12:3456".parse().unwrap(),
            UDP,
            1,
            &[],
        );
        assert_eq!(
            destination(&p, Some(VM), None),
            Some(([0x33, 0x33, 0xff, 0x12, 0x34, 0x56], IPV6))
        );
        let p = ipv6(
            link_local(GATEWAY_MAC),
            "fd00::2".parse().unwrap(),
            UDP,
            1,
            &[],
        );
        assert_eq!(destination(&p, Some(VM), None), Some((VM, IPV6)));
        assert_eq!(destination(&p, None, None), None);
        assert_eq!(destination(&[0x50; 40], Some(VM), None), None);
        assert_eq!(destination(&[0x45; 19], Some(VM), None), None);
        assert_eq!(destination(&[], Some(VM), None), None);
    }

    #[test]
    fn arp_answers_every_address_but_probes_gratuitous_and_its_own() {
        let reply = arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 1]), VM, None).unwrap();
        let f = Frame::parse(&reply).unwrap();
        assert_eq!((f.dst, f.src, f.ethertype), (VM, GATEWAY_MAC, ARP));
        let a = f.payload;
        assert_eq!(&a[6..8], &[0, 2], "a reply");
        assert_eq!(&a[8..14], &GATEWAY_MAC, "the gateway's MAC");
        assert_eq!(&a[14..18], &[10, 0, 0, 1], "for the asked address");
        assert_eq!(&a[18..24], &VM);
        assert_eq!(&a[24..28], &[10, 0, 0, 2]);
        // Any address: the world decides what is there.
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 77]), VM, None).is_some());
        // A probe, a gratuitous ARP, and a question about the VM's own address.
        assert!(arp_reply(&arp_request([0; 4], [10, 0, 0, 2]), VM, None).is_none());
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 2]), VM, None).is_none());
        let own = Some(Ipv4Addr::new(10, 0, 0, 2));
        assert!(arp_reply(&arp_request([10, 0, 0, 9], [10, 0, 0, 2]), VM, own).is_none());
        // A reply, a short request, another hardware type.
        let mut r = arp_request([10, 0, 0, 2], [10, 0, 0, 1]);
        r[7] = 2;
        assert!(arp_reply(&r, VM, None).is_none());
        assert!(arp_reply(&arp_request([10, 0, 0, 2], [10, 0, 0, 1])[..27], VM, None).is_none());
        let mut r = arp_request([10, 0, 0, 2], [10, 0, 0, 1]);
        r[1] = 6;
        assert!(arp_reply(&r, VM, None).is_none());
    }

    pub(crate) fn router_solicit(src: Ipv6Addr) -> Vec<u8> {
        icmp6(
            src,
            "ff02::2".parse().unwrap(),
            vec![ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0],
        )
    }

    pub(crate) fn fragment6(packet: &[u8], offset: u16, more: bool, body: &[u8]) -> Vec<u8> {
        let mut fragment = vec![packet[6], 0];
        fragment.extend_from_slice(&(offset | u16::from(more)).to_be_bytes());
        fragment.extend_from_slice(&42u32.to_be_bytes());
        fragment.extend_from_slice(body);
        ipv6(
            source_v6(packet),
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
            44,
            packet[7],
            &fragment,
        )
    }

    pub(crate) fn fragments6(packet: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
        (
            fragment6(packet, 0, true, &packet[40..40 + cut]),
            fragment6(packet, cut as u16, false, &packet[40 + cut..]),
        )
    }

    pub(crate) fn solicitation(src: Ipv6Addr, target: Ipv6Addr, hop: u8) -> Vec<u8> {
        let mut body = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        body.extend_from_slice(&[1, 1]);
        body.extend_from_slice(&VM);
        let mut p = icmp6(src, "ff02::1:ff00:1".parse().unwrap(), body);
        p[7] = hop;
        p
    }

    #[test]
    fn neighbor_solicitations_are_answered_except_dad() {
        let vm_ll = link_local(VM);
        let target: Ipv6Addr = "fd00::1".parse().unwrap();
        let reply = answer_solicitation(&solicitation(vm_ll, target, 255), VM, None).unwrap();
        let f = Frame::parse(&reply).unwrap();
        assert_eq!((f.dst, f.src, f.ethertype), (VM, GATEWAY_MAC, IPV6));
        let p = f.payload;
        assert!(v6_checksum_ok(p));
        assert_eq!(p[7], 255, "hop limit");
        assert_eq!(source_v6(p), target);
        assert_eq!(&p[24..40], &vm_ll.octets());
        assert_eq!(p[40], NEIGHBOR_ADVERTISEMENT);
        assert_eq!(p[44], 0xe0, "router, solicited, override");
        assert_eq!(&p[48..64], &target.octets());
        assert_eq!(&p[64..72], &[2, 1, 0x02, 0x66, 0x6e, 0, 0, 1]);

        let dad = solicitation(Ipv6Addr::UNSPECIFIED, "fd00::2".parse().unwrap(), 255);
        assert!(
            answer_solicitation(&dad, VM, None).is_none(),
            "duplicate address detection"
        );
        assert!(
            answer_solicitation(&solicitation(vm_ll, target, 64), VM, None).is_none(),
            "hop limit not 255"
        );
        assert!(
            answer_solicitation(
                &solicitation(vm_ll, "ff02::1".parse().unwrap(), 255),
                VM,
                None
            )
            .is_none()
        );
        assert!(
            answer_solicitation(&solicitation(vm_ll, target, 255), VM, Some(target)).is_none(),
            "its own address"
        );
        let short = solicitation(vm_ll, target, 255);
        assert!(answer_solicitation(&short[..60], VM, None).is_none());
    }

    /// `n` destination options headers before `inner`, with hop limit 255.
    pub(crate) fn behind_options(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        n: usize,
        proto: u8,
        inner: &[u8],
    ) -> Vec<u8> {
        let mut ext = Vec::new();
        for i in 0..n {
            ext.extend_from_slice(&[if i + 1 == n { proto } else { 60 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        ext.extend_from_slice(inner);
        ipv6(src, dst, if n == 0 { proto } else { 60 }, 255, &ext)
    }

    fn icmp6_kind(p: &[u8]) -> Option<u8> {
        match upper(p) {
            Ok(Upper::Icmp6 { kind, .. }) => Some(kind),
            _ => None,
        }
    }

    #[test]
    fn extension_headers_are_skipped() {
        let src = link_local(VM);
        let ra = router_advert(&lease6(), 1500);
        // The same message behind a hop-by-hop header.
        let mut ext = vec![ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&ra[40..]);
        let p = ipv6(src, "ff02::1".parse().unwrap(), 0, 255, &ext);
        assert_eq!(icmp6_kind(&p), Some(ROUTER_ADVERTISEMENT));
        for n in [8, 16] {
            assert_eq!(
                icmp6_kind(&behind_options(
                    src,
                    "ff02::1".parse().unwrap(),
                    n,
                    ICMPV6,
                    &ra[40..]
                )),
                Some(ROUTER_ADVERTISEMENT)
            );
        }
        // Behind an authentication header.
        let mut ah = vec![ICMPV6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ah.extend_from_slice(&ra[40..]);
        assert_eq!(
            icmp6_kind(&ipv6(src, "ff02::1".parse().unwrap(), 51, 255, &ah)),
            Some(ROUTER_ADVERTISEMENT)
        );
        // A first fragment holds the type, and says it is a fragment; a later
        // one does not hold it.
        let (p, later) = fragments6(&ra, 8);
        assert!(matches!(
            upper(&p),
            Ok(Upper::Icmp6 {
                kind: ROUTER_ADVERTISEMENT,
                fragment: true,
                ..
            })
        ));
        assert_eq!(upper(&later), Ok(Upper::Other));
        // A header that runs past the end cannot be read, unlike a packet
        // that is simply not ICMPv6 or UDP.
        assert_eq!(upper(&ipv6(src, src, 0, 1, &[UDP, 9])), Err(Unreadable));
        assert_eq!(upper(&ipv6(src, src, 6, 1, &[0; 20])), Ok(Upper::Other));
        // UDP behind a destination options header.
        let mut dst = vec![UDP, 0, 1, 4, 0, 0, 0, 0];
        dst.extend_from_slice(&udp6(src, 546, src, 547, b"x")[40..]);
        assert_eq!(udp_to(&ipv6(src, src, 60, 1, &dst)), Some((547, &b"x"[..])));
    }

    #[test]
    fn complete_udp_uses_the_shared_boundary_without_checking_checksums() {
        for p in [
            udp4(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67, b"odd"),
            udp6(link_local(VM), 546, link_local(GATEWAY_MAC), 547, b"odd"),
        ] {
            let h = Header::parse_whole(&p).unwrap();
            let mut bytes = h.payload(&p).to_vec();
            bytes.extend_from_slice(b"outside UDP");
            // TAP classifies complete datagrams even with a bad checksum.
            bytes[6..8].copy_from_slice(&[0x12, 0x34]);
            let datagram = udp::Datagram::parse(&bytes).unwrap();
            assert!(!datagram.checksum_ok(h.src, h.dst));
            let expected = Ok(Upper::Udp {
                port: datagram.destination_port(),
                payload: datagram.payload(),
            });
            let packet = ip::packet(h.src, h.dst, UDP, &bytes);
            assert_eq!(upper(&packet.0), expected);
            for len in [0u16, 7, 100] {
                bytes[4..6].copy_from_slice(&len.to_be_bytes());
                assert!(udp::Datagram::parse(&bytes).is_none());
                assert_eq!(
                    upper(&ip::packet(h.src, h.dst, UDP, &bytes).0),
                    Err(Unreadable)
                );
            }
        }
    }

    #[test]
    fn udp_lengths_and_fragments() {
        let p = udp4(
            Ipv4Addr::UNSPECIFIED,
            68,
            Ipv4Addr::BROADCAST,
            67,
            b"discover",
        );
        assert_eq!(
            upper(&p),
            Ok(Upper::Udp {
                port: 67,
                payload: b"discover"
            })
        );
        // The first fragment gives the port, and only the port.
        let mut first = p.clone();
        first[6] = 0x20;
        first[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(upper(&first), Ok(Upper::UdpFragment { port: 67 }));
        let mut later = p.clone();
        later[7] = 1;
        assert_eq!(upper(&later), Ok(Upper::Other));
        // A first fragment that stops inside the UDP header.
        let cut = ipv4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::BROADCAST,
            UDP,
            &p[20..24],
        );
        let mut cut_first = cut.clone();
        cut_first[6] = 0x20;
        assert_eq!(upper(&cut_first), Err(Unreadable));
        // IPv6: a first fragment of a DHCPv6 request.
        let u = udp6(
            link_local(VM),
            546,
            "ff02::1:2".parse().unwrap(),
            547,
            &[1; 40],
        );
        let (p6, _) = fragments6(&u, 48);
        assert_eq!(upper(&p6), Ok(Upper::UdpFragment { port: 547 }));
    }

    #[test]
    fn link_local_from_mac() {
        assert_eq!(
            link_local(VM),
            "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            link_local(GATEWAY_MAC),
            "fe80::66:6eff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
    }
}
