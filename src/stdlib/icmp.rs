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
