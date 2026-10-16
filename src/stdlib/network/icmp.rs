//! ICMP: answering pings.
//!
//! Use this module when a machine in the world should answer `ping`. It has
//! plain functions that read and build packets. They start no task and take
//! no context. Nothing answers pings unless the world does it, so a machine
//! with no ICMP loop looks silent to `ping`.
//!
//! Answering pings takes a short loop on the ICMP interface that
//! [`ip::split_protocols`] returns. It
//! receives each ICMP packet, builds the reply with [`echo_reply`], and
//! sends it back:
//!
//! ```
//! # use fictionet::prelude::*;
//! # use fictionet::{Cx, Interface, stdlib::icmp};
//! # async fn answer(fcx: Cx, mut icmp: impl Interface, addr: std::net::IpAddr) {
//! while let Ok(packet) = icmp.recv(&fcx).await {
//!     if let Some(reply) = icmp::echo_reply(&packet, addr) {
//!         icmp.send(reply);
//!     }
//! }
//! # }
//! ```
//!
//! To answer pings slowly, or only some of the time, change one line of
//! that loop: sleep with [`Cx::sleep`](fictionet::Cx::sleep) before sending, or
//! skip the send when [`Cx::random_f64`](fictionet::Cx::random_f64) is above
//! some threshold.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::Packet;
use fictionet::stdlib::ip::{self, Fields, Header, protocol};

/// The reply to `packet`, if it is an echo request (a ping) sent to `addr`.
///
/// Returns `None` for any other packet. Works for IPv4 and IPv6.
///
/// The reply comes from `addr`, goes to the request's source, and carries
/// the request's identifier, sequence number and data, with a TTL or hop
/// limit of 64 and correct checksums. A request with a wrong ICMP checksum
/// gets no reply, as from a kernel. So does a fragment: put fragments back
/// together first, as [`split_protocols`](fictionet::stdlib::ip::split_protocols)
/// does. IPv4 options and IPv6 extension headers of the request are not
/// copied into the reply. A request with IPv6 extension headers that a host
/// must not accept, such as an unknown option whose type says to discard
/// the packet, gets no reply; `split_protocols` drops those before they get
/// here, and answers the ones RFC 8200 asks it to.
pub fn echo_reply(packet: &Packet, addr: IpAddr) -> Option<Packet> {
    let bytes = &packet.0;
    let ip = Header::parse_whole(bytes)?;
    if ip.dst != addr {
        return None;
    }
    let icmp = ip.payload(bytes);
    // Type 8 is an echo request over IPv4, 0 its reply; 128 and 129 over
    // IPv6. The checksum covers a pseudo-header only over IPv6.
    let (proto, request, reply, sum) = match addr {
        IpAddr::V4(_) => (protocol::ICMP, 8, 0, ip::checksum(icmp)),
        IpAddr::V6(_) => (
            protocol::ICMPV6,
            128,
            129,
            ip::transport_checksum(ip.src, addr, protocol::ICMPV6, icmp),
        ),
    };
    if ip.protocol != proto || icmp.len() < 8 || icmp[0] != request || icmp[1] != 0 || sum != 0 {
        return None;
    }
    let mut message = icmp.to_vec();
    message[0] = reply;
    set_checksum(&mut message, addr, ip.src);
    // The IPv4 identification and type of service, and the IPv6 traffic
    // class and flow label, as in the request.
    let fields = Fields {
        id: u16::from_be_bytes([bytes[4], bytes[5]]),
        tos: bytes[1],
        dont_fragment: false,
        ..Fields::default()
    };
    let mut out = ip::packet_with(addr, ip.src, proto, fields, &message);
    if addr.is_ipv6() {
        out.0[..4].copy_from_slice(&bytes[..4]);
    }
    Some(out)
}

/// Sets the checksum of an ICMP or ICMPv6 message (bytes 2 and 3) from
/// `src` to `dst`.
fn set_checksum(icmp: &mut [u8], src: IpAddr, dst: IpAddr) {
    icmp[2..4].copy_from_slice(&[0, 0]);
    let sum = match src {
        IpAddr::V4(_) => ip::checksum(icmp),
        IpAddr::V6(_) => ip::transport_checksum(src, dst, protocol::ICMPV6, icmp),
    };
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
}

/// The ICMP "host unreachable" answer (type 3, code 1) to the IPv4 packet
/// `packet`, sent from `from`, as a router with no route to the packet's
/// destination sends it. A client then fails at once with "No route to
/// host", instead of waiting for a timeout.
///
/// `None` where [`error`] sends no answer.
pub fn host_unreachable(packet: &[u8], from: Ipv4Addr) -> Option<Packet> {
    error(packet, from.into(), 3, 1, 0)
}

/// The ICMP "time exceeded in transit" answer (type 11, code 0) to the IPv4
/// or IPv6 packet `packet`, sent from `from`, as a router sends it when a
/// packet's TTL or hop limit runs out. For IPv6 it is ICMPv6 type 3, code 0.
/// This is what `traceroute` reads.
///
/// `None` where [`error`] sends no answer, or when `from` is not of the
/// packet's family.
pub fn time_exceeded(packet: &[u8], from: IpAddr) -> Option<Packet> {
    let kind = if from.is_ipv4() { 11 } else { 3 };
    error(packet, from, kind, 0, 0)
}

/// The ICMPv6 "destination unreachable, address unreachable" answer (type
/// 1, code 3) to the IPv6 packet `packet`, sent from `from`. Linux reports
/// it to the program as "No route to host", as it does ICMP "host
/// unreachable".
///
/// `None` where [`error`] sends no answer.
pub fn address_unreachable(packet: &[u8], from: Ipv6Addr) -> Option<Packet> {
    error(packet, from.into(), 1, 3, 0)
}

/// The ICMP or ICMPv6 error message of `kind` and `code` about `packet`, a
/// whole IP packet, sent from `from` back to the packet's source. `word` is
/// the message's second 32-bit word: the pointer of a parameter problem,
/// the MTU of "packet too big", and 0 for most others. The message quotes
/// as much of the packet as fits in 576 bytes over IPv4 (RFC 1812) and in
/// the minimum MTU, 1,280 bytes, over IPv6 (RFC 4443).
///
/// `None` where the RFCs forbid an answer (RFC 1122 section 3.2.2, RFC 4443
/// section 2.4):
///
/// - for a packet from an address that is not one host (unspecified,
///   loopback, multicast, or the IPv4 broadcast address) or to a multicast
///   or broadcast address;
/// - for an ICMP error: over IPv4 only queries (echo, timestamp,
///   information, mask) are answered; over IPv6, errors (types below 128)
///   and redirects (137) are not, nor the other neighbor discovery
///   messages (133 to 136), which belong to one link;
/// - over IPv4, for a fragment after the first. Over IPv6 such a fragment
///   is answered, as by Linux, since it holds no ICMPv6 type to read;
/// - when `from` is not of the packet's family, or the packet cannot be
///   read.
pub fn error(packet: &[u8], from: IpAddr, kind: u8, code: u8, word: u32) -> Option<Packet> {
    let ip = Header::parse(packet)?;
    let later = ip.fragment.is_some_and(|f| f.offset != 0);
    let first = ip.payload(packet).first().copied();
    let (proto, limit) = match (ip.src, ip.dst, from) {
        (IpAddr::V4(src), IpAddr::V4(dst), IpAddr::V4(_)) => {
            if later
                || src.is_unspecified()
                || src.is_broadcast()
                || src.is_multicast()
                || src.is_loopback()
            {
                return None;
            }
            if dst.is_broadcast() || dst.is_multicast() {
                return None;
            }
            if ip.protocol == protocol::ICMP && !first.is_some_and(|k| matches!(k, 0 | 8 | 13..=18))
            {
                return None;
            }
            (protocol::ICMP, 576 - 28)
        }
        (IpAddr::V6(src), IpAddr::V6(dst), IpAddr::V6(_)) => {
            if src.is_unspecified() || src.is_multicast() || src.is_loopback() || dst.is_multicast()
            {
                return None;
            }
            if ip.protocol == protocol::ICMPV6
                && !later
                && first.is_none_or(|t| t < 128 || (133..=137).contains(&t))
            {
                return None;
            }
            (protocol::ICMPV6, 1280 - 48)
        }
        _ => return None,
    };
    let quote = &packet[..ip.payload.end.min(limit)];
    let mut icmp = Vec::with_capacity(8 + quote.len());
    icmp.extend_from_slice(&[kind, code, 0, 0]);
    icmp.extend_from_slice(&word.to_be_bytes());
    icmp.extend_from_slice(quote);
    set_checksum(&mut icmp, from, ip.src);
    Some(ip::packet(from, ip.src, proto, &icmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    const DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 1, 0, 1);
    const ROUTER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    /// A fragment of an IPv6 packet from `SRC` to `DST` at `offset`, whose
    /// first fragment carries ICMPv6 of type `kind`.
    fn fragment6(offset: u16, kind: u8) -> Vec<u8> {
        let frag = [
            protocol::ICMPV6,
            0,
            (offset >> 8) as u8,
            offset as u8 | 1,
            0,
            0,
            0,
            9,
        ];
        let body = if offset == 0 {
            vec![kind, 0, 0, 0, 0, 0, 0, 0]
        } else {
            vec![kind; 8]
        };
        let fields = Fields {
            ttl: 1,
            ..Fields::default()
        };
        ip::packet_with(
            SRC.into(),
            DST.into(),
            protocol::FRAGMENT,
            fields,
            &[&frag[..], &body].concat(),
        )
        .0
    }

    /// Time exceeded and address unreachable now come from the one ICMP
    /// error builder, so they answer a non-first IPv6 fragment as Linux
    /// does: it holds no ICMPv6 type, so it may not be an error. Before,
    /// they refused it, while parameter problem answered it.
    #[test]
    fn a_later_ipv6_fragment_is_answered() {
        let later = fragment6(8, 1);
        let answer = time_exceeded(&later, ROUTER.into()).expect("an answer").0;
        let h = Header::parse(&answer).unwrap();
        assert_eq!(
            (h.src, h.dst, h.protocol),
            (ROUTER.into(), SRC.into(), protocol::ICMPV6)
        );
        let icmp = h.payload(&answer);
        assert_eq!((icmp[0], icmp[1]), (3, 0));
        assert_eq!(&icmp[8..], &later[..]);
        assert_eq!(
            ip::transport_checksum(ROUTER.into(), SRC.into(), protocol::ICMPV6, icmp),
            0
        );
        assert!(address_unreachable(&later, ROUTER).is_some());
        // A first fragment shows its type: an error gets no error, a ping
        // does.
        assert!(time_exceeded(&fragment6(0, 1), ROUTER.into()).is_none());
        assert!(time_exceeded(&fragment6(0, 128), ROUTER.into()).is_some());
    }

    #[test]
    fn errors_go_only_to_one_host() {
        let to = |src: &str, dst: &str| {
            ip::packet(
                src.parse().unwrap(),
                dst.parse().unwrap(),
                protocol::UDP,
                &[0; 8],
            )
            .0
        };
        let from = "10.0.0.1".parse().unwrap();
        assert!(error(&to("10.0.0.2", "10.0.0.9"), from, 3, 3, 0).is_some());
        for (src, dst) in [
            ("0.0.0.0", "10.0.0.9"),
            ("127.0.0.1", "10.0.0.9"),
            ("224.0.0.1", "10.0.0.9"),
            ("10.0.0.2", "255.255.255.255"),
        ] {
            assert!(
                error(&to(src, dst), from, 3, 3, 0).is_none(),
                "{src} to {dst}"
            );
        }
        // Not from an address of the other family.
        assert!(error(&to("10.0.0.2", "10.0.0.9"), ROUTER.into(), 3, 3, 0).is_none());
        // An IPv4 ICMP error gets none; a ping does.
        let icmp = |kind: u8| {
            ip::packet(
                "10.0.0.2".parse().unwrap(),
                "10.0.0.9".parse().unwrap(),
                protocol::ICMP,
                &[kind, 0, 0, 0, 0, 0, 0, 0],
            )
            .0
        };
        assert!(host_unreachable(&icmp(3), "10.0.0.1".parse().unwrap()).is_none());
        assert!(host_unreachable(&icmp(8), "10.0.0.1".parse().unwrap()).is_some());
    }
}
