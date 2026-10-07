//! ICMP: answering pings.
//!
//! Use this module when a machine in the world should answer `ping`. It has
//! plain functions that read and build packets. They start no task and take
//! no context. Nothing answers pings unless the world does it, so a machine
//! with no ICMP loop looks silent to `ping`.
//!
//! Answering pings takes a short loop on the ICMP interface that
//! [`ip::split_protocols`](crate::stdlib::ip::split_protocols) returns. It
//! receives each ICMP packet, builds the reply with [`echo_reply`], and
//! sends it back:
//!
//! ```
//! # use fictionet::prelude::*;
//! # use fictionet::{Cx, Interface, stdlib::icmp};
//! # async fn answer(cx: Cx, mut icmp: impl Interface, addr: std::net::IpAddr) {
//! while let Ok(packet) = icmp.recv(&cx).await {
//!     if let Some(reply) = icmp::echo_reply(&packet, addr) {
//!         icmp.send(reply);
//!     }
//! }
//! # }
//! ```
//!
//! To answer pings slowly, or only some of the time, change one line of
//! that loop: sleep with [`Cx::sleep`](crate::Cx::sleep) before sending, or
//! skip the send when [`Cx::random_f64`](crate::Cx::random_f64) is above
//! some threshold.

use std::net::IpAddr;

use crate::Packet;
use crate::stdlib::wire::{self, V4, V6};

/// The reply to `packet`, if it is an echo request (a ping) sent to `addr`.
///
/// Returns `None` for any other packet. Works for IPv4 and IPv6.
///
/// The reply comes from `addr`, goes to the request's source, and carries
/// the request's identifier, sequence number and data, with a TTL or hop
/// limit of 64 and correct checksums. A request with a wrong ICMP checksum
/// gets no reply, as from a kernel. So does a fragment: put fragments back
/// together first, as [`split_protocols`](crate::stdlib::ip::split_protocols)
/// does. IPv4 options and IPv6 extension headers of the request are not
/// copied into the reply. A request with IPv6 extension headers that a host
/// must not accept, such as an unknown option whose type says to discard
/// the packet, gets no reply; `split_protocols` drops those before they get
/// here, and answers the ones RFC 8200 asks it to.
pub fn echo_reply(packet: &Packet, addr: IpAddr) -> Option<Packet> {
    let bytes = &packet.0;
    match addr {
        IpAddr::V4(addr) => {
            let ip = V4::parse(bytes, false)?;
            if ip.is_fragment() || ip.proto() != wire::PROTO_ICMP || ip.dst() != addr {
                return None;
            }
            let icmp = ip.payload();
            // Type 8 is an echo request, 0 the reply.
            if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 || wire::checksum(0, icmp) != 0 {
                return None;
            }
            let mut reply = wire::v4_header(wire::PROTO_ICMP, addr, ip.src(), 64, ip.id(), bytes[1], &[], icmp.len());
            let at = reply.len();
            reply.extend_from_slice(icmp);
            reply[at] = 0;
            set_icmp_checksum(&mut reply[at..], 0);
            Some(Packet(reply))
        }
        IpAddr::V6(addr) => {
            let ip = V6::parse(bytes, false)?;
            let chain = wire::ext6_chain(bytes).ok()?;
            if chain.frag.is_some() || chain.proto != wire::PROTO_ICMPV6 || ip.dst() != addr {
                return None;
            }
            let icmp = &bytes[chain.upper..chain.end];
            let len = icmp.len() as u32;
            // Type 128 is an echo request, 129 the reply.
            if icmp.len() < 8 || icmp[0] != 128 || icmp[1] != 0 {
                return None;
            }
            let src = ip.src();
            if wire::checksum(wire::pseudo_v6(&src, &addr, wire::PROTO_ICMPV6, len), icmp) != 0 {
                return None;
            }
            let mut reply = Vec::with_capacity(40 + icmp.len());
            // Version, traffic class and flow label as in the request.
            reply.extend_from_slice(&bytes[..4]);
            reply.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            reply.push(wire::PROTO_ICMPV6);
            reply.push(64);
            reply.extend_from_slice(&addr.octets());
            reply.extend_from_slice(&src.octets());
            reply.extend_from_slice(icmp);
            reply[40] = 129;
            set_icmp_checksum(&mut reply[40..], wire::pseudo_v6(&addr, &src, wire::PROTO_ICMPV6, len));
            Some(Packet(reply))
        }
    }
}

/// Sets the checksum of an ICMP message (bytes 2 and 3), starting from the
/// pseudo-header sum `pseudo` (0 for ICMPv4, which has none).
fn set_icmp_checksum(icmp: &mut [u8], pseudo: u32) {
    icmp[2] = 0;
    icmp[3] = 0;
    let c = wire::checksum(pseudo, icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
}

/// The ICMP "host unreachable" answer (type 3, code 1) to the IPv4 packet
/// `packet`, sent from `from`, as a router with no route to the packet's
/// destination sends it. A client then fails at once with "No route to
/// host", instead of waiting for a timeout.
///
/// `None` where RFC 1122 forbids an answer: for ICMP errors (only ICMP
/// queries are answered), for fragments after the first, and for packets
/// from or to an address that is not one host. The answer quotes as much
/// of the packet as fits in 576 bytes (RFC 1812).
pub fn host_unreachable(packet: &[u8], from: std::net::Ipv4Addr) -> Option<Packet> {
    error_v4(packet, from, 3, 1)
}

/// The ICMP "time exceeded in transit" answer (type 11, code 0) to the IPv4
/// or IPv6 packet `packet`, sent from `from`, as a router sends it when a
/// packet's TTL or hop limit runs out. For IPv6 it is ICMPv6 type 3, code 0.
/// This is what `traceroute` reads.
///
/// `None` where the RFCs forbid an answer, as for [`host_unreachable`] and
/// [`address_unreachable`], or when `from` is not of the packet's family.
pub fn time_exceeded(packet: &[u8], from: IpAddr) -> Option<Packet> {
    match (wire::version(packet)?, from) {
        (4, IpAddr::V4(from)) => error_v4(packet, from, 11, 0),
        (6, IpAddr::V6(from)) => error_v6(packet, from, 3, 0),
        _ => None,
    }
}

/// An ICMP error of `kind` and `code` about `packet`, from `from`.
fn error_v4(packet: &[u8], from: std::net::Ipv4Addr, kind: u8, code: u8) -> Option<Packet> {
    let v4 = V4::parse(packet, false)?;
    if v4.frag_offset() != 0 {
        return None;
    }
    let (src, dst) = (v4.src(), v4.dst());
    if src.is_unspecified() || src.is_broadcast() || src.is_multicast() || src.is_loopback() {
        return None;
    }
    if dst.is_broadcast() || dst.is_multicast() {
        return None;
    }
    if v4.proto() == wire::PROTO_ICMP {
        // Only queries (echo, timestamp, information, mask) get an answer.
        let kind = *v4.payload().first()?;
        if !matches!(kind, 0 | 8 | 13..=18) {
            return None;
        }
    }
    let quote = &packet[..v4.total.min(576 - 28)];
    let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quote);
    let sum = wire::checksum(0, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(crate::stdlib::udp::ip_packet(from.into(), src.into(), wire::PROTO_ICMP, 0, &icmp))
}

/// The ICMPv6 "destination unreachable, address unreachable" answer (type
/// 1, code 3) to the IPv6 packet `packet`, sent from `from`. Linux reports
/// it to the program as "No route to host", as it does ICMP "host
/// unreachable".
///
/// `None` where RFC 4443 forbids an answer: for ICMPv6 errors and
/// redirects, fragments after the first, and packets from or to an address
/// that is not one host. Also `None` for neighbor discovery messages. The
/// answer quotes as much of the packet as fits in the minimum MTU, 1280
/// bytes.
pub fn address_unreachable(packet: &[u8], from: std::net::Ipv6Addr) -> Option<Packet> {
    error_v6(packet, from, 1, 3)
}

/// An ICMPv6 error of `kind` and `code` about `packet`, from `from`.
fn error_v6(packet: &[u8], from: std::net::Ipv6Addr, kind: u8, code: u8) -> Option<Packet> {
    let v6 = V6::parse(packet, false)?;
    if let Some((at, _)) = v6.frag
        && u16::from_be_bytes([packet[at + 2], packet[at + 3]]) & 0xfff8 != 0
    {
        return None;
    }
    let (src, dst) = (v6.src(), v6.dst());
    if src.is_unspecified() || src.is_multicast() || src.is_loopback() || dst.is_multicast() {
        return None;
    }
    // Error messages (types below 128) and redirects (137) never get an
    // error. Neither do the other neighbor discovery messages (133 to 136),
    // which belong to one link and are never routed.
    if v6.proto == wire::PROTO_ICMPV6 && v6.payload().first().is_none_or(|t| *t < 128 || (133..=137).contains(t)) {
        return None;
    }
    let quote = &packet[..v6.end.min(1280 - 48)];
    let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(quote);
    let sum = crate::stdlib::udp::transport_checksum(from.into(), src.into(), wire::PROTO_ICMPV6, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(crate::stdlib::udp::ip_packet(from.into(), src.into(), wire::PROTO_ICMPV6, 0, &icmp))
}
