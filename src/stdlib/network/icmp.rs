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
//! # use fictionet::{Cx, Interface, stdlib::network::icmp};
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
use std::sync::Arc;

use fictionet::Packet;
use fictionet::stdlib::network::ip::{self, Fields, Header, protocol};

/// Constructs IPv4 header fields from reply source, reply destination,
/// request TOS, and whether the reply is an error rather than an echo.
pub type Ipv4Fields = Arc<dyn Fn(Ipv4Addr, Ipv4Addr, u8, bool) -> Fields + Send + Sync>;

/// Host choices shared by echo replies and transport errors.
#[derive(Clone, Default)]
pub struct Options {
    /// Accept IPv4 echo requests with a nonzero code and echo that code.
    pub echo_nonzero_code: bool,
    /// Header policy for IPv4 replies. IPv6 retains the default behavior.
    pub ipv4_fields: Option<Ipv4Fields>,
}

impl Options {
    fn fields(&self, from: IpAddr, to: IpAddr, tos: u8, error: bool, default: Fields) -> Fields {
        match (&self.ipv4_fields, from, to) {
            (Some(make), IpAddr::V4(from), IpAddr::V4(to)) => make(from, to, tos, error),
            _ => default,
        }
    }
}

/// The reply to `packet`, if it is an echo request (a ping) sent to `addr`.
///
/// Returns `None` for any other packet. Works for IPv4 and IPv6.
///
/// The reply comes from `addr`, goes to the request's source, and carries
/// the request's identifier, sequence number and data, with a TTL or hop
/// limit of 64 and correct checksums. A request with a wrong ICMP checksum
/// gets no reply, as from a kernel, and so does one from a source that is
/// not one host: the unspecified address, loopback, a multicast address or
/// the IPv4 broadcast address. So does a fragment: put fragments back
/// together first, as [`split_protocols`](fictionet::stdlib::network::ip::split_protocols)
/// does. IPv4 options and IPv6 extension headers of the request are not
/// copied into the reply. A request with IPv6 extension headers that a host
/// must not accept, such as an unknown option whose type says to discard
/// the packet, gets no reply; `split_protocols` drops those before they get
/// here, and answers the ones RFC 8200 asks it to.
pub fn echo_reply(packet: &Packet, addr: IpAddr) -> Option<Packet> {
    Options::default().echo_reply(packet, addr)
}

impl Options {
    /// Builds an echo reply using this host's receive and header choices.
    pub fn echo_reply(&self, packet: &Packet, addr: IpAddr) -> Option<Packet> {
        let bytes = &packet.0;
        let ip = Header::parse_whole(bytes)?;
        if ip.dst != addr || !is_one_host(ip.src) {
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
        if ip.protocol != proto
            || icmp.len() < 8
            || icmp[0] != request
            || (icmp[1] != 0 && !(addr.is_ipv4() && self.echo_nonzero_code))
            || sum != 0
        {
            return None;
        }
        let mut message = icmp.to_vec();
        message[0] = reply;
        set_checksum(&mut message, addr, ip.src);
        // Default IPv4 fields echo the request; a host policy may replace them.
        let fields = self.fields(
            addr,
            ip.src,
            bytes[1],
            false,
            Fields {
                id: u16::from_be_bytes([bytes[4], bytes[5]]),
                tos: bytes[1],
                dont_fragment: false,
                ..Fields::default()
            },
        );
        let mut out = ip::packet_with(addr, ip.src, proto, fields, &message);
        if addr.is_ipv6() {
            out.0[..4].copy_from_slice(&bytes[..4]);
        }
        Some(out)
    }
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
    Options::default().error(packet, from, kind, code, word)
}

impl Options {
    /// Builds an ICMP error with this host's header choices and [`error`]'s exclusions.
    pub fn error(
        &self,
        packet: &[u8],
        from: IpAddr,
        kind: u8,
        code: u8,
        word: u32,
    ) -> Option<Packet> {
        let ip = Header::parse(packet)?;
        let later = ip.fragment.is_some_and(|f| f.offset != 0);
        let first = ip.payload(packet).first().copied();
        let (proto, limit) = match (ip.src, ip.dst, from) {
            (IpAddr::V4(_), IpAddr::V4(dst), IpAddr::V4(_)) => {
                if later || !is_one_host(ip.src) {
                    return None;
                }
                if dst.is_broadcast() || dst.is_multicast() {
                    return None;
                }
                if ip.protocol == protocol::ICMP
                    && !first.is_some_and(|k| matches!(k, 0 | 8 | 13..=18))
                {
                    return None;
                }
                (protocol::ICMP, 576 - 28)
            }
            (IpAddr::V6(_), IpAddr::V6(dst), IpAddr::V6(_)) => {
                if !is_one_host(ip.src) || dst.is_multicast() {
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
        let fields = self.fields(from, ip.src, packet[1], true, Fields::default());
        Some(ip::packet_with(from, ip.src, proto, fields, &icmp))
    }
}

/// Whether `src` can be the source of one host: not the unspecified
/// address, a multicast address, loopback (which never comes from the
/// network) or the IPv4 broadcast address (RFC 1122, section 3.2.1.3; RFC
/// 4291, section 2.5.2).
fn is_one_host(src: IpAddr) -> bool {
    match src {
        IpAddr::V4(a) => {
            !(a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback())
        }
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast() || a.is_loopback()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_choices_preserve_validation_and_leave_ipv6_unchanged() {
        let me = "10.0.0.1".parse().unwrap();
        let mut request = ping("10.0.0.2", "10.0.0.1");
        request.0[21] = 9;
        set_checksum(&mut request.0[20..], "10.0.0.2".parse().unwrap(), me);
        let options = Options {
            echo_nonzero_code: true,
            ipv4_fields: Some(Arc::new(|_, _, _, _| Fields {
                id: 4321,
                tos: 192,
                dont_fragment: false,
                ttl: 42,
            })),
        };
        assert!(echo_reply(&request, me).is_none());
        let reply = options.echo_reply(&request, me).unwrap();
        assert_eq!(&reply.0[20..22], &[0, 9]);
        assert_eq!(reply.0[8], 42);
        assert_eq!(reply.0[1], 192);
        assert_eq!(u16::from_be_bytes([reply.0[4], reply.0[5]]), 4321);
        assert_eq!(ip::checksum(&reply.0[..20]), 0);
        assert_eq!(ip::checksum(&reply.0[20..]), 0);
        request.0[22] ^= 1;
        assert!(options.echo_reply(&request, me).is_none());
        let request = ping(&SRC.to_string(), &DST.to_string());
        assert_eq!(
            options.echo_reply(&request, DST.into()),
            echo_reply(&request, DST.into())
        );
    }

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

    /// A ping from `src` to `dst` with correct ICMP checksums.
    fn ping(src: &str, dst: &str) -> Packet {
        let (src, dst): (IpAddr, IpAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let (proto, kind) = if src.is_ipv4() {
            (protocol::ICMP, 8)
        } else {
            (protocol::ICMPV6, 128)
        };
        let mut message = vec![kind, 0, 0, 0, 0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g'];
        set_checksum(&mut message, src, dst);
        ip::packet(src, dst, proto, &message)
    }

    /// A host discards a packet whose IPv4 header checksum is wrong
    /// (RFC 1122, section 3.2.1.2), as a kernel does, so a ping with a
    /// broken header gets no reply.
    #[test]
    fn a_ping_with_a_bad_header_checksum_gets_no_reply() {
        let me: IpAddr = "10.0.0.1".parse().unwrap();
        let good = ping("10.0.0.2", "10.0.0.1");
        assert!(echo_reply(&good, me).is_some());
        let mut bad = good.clone();
        bad.0[11] ^= 0x01;
        assert_ne!(
            ip::checksum(&bad.0[..20]),
            0,
            "the header checksum is wrong"
        );
        assert!(echo_reply(&bad, me).is_none());
    }

    /// A ping from an address that is not one host gets no reply, as an
    /// ICMP error gets none ([`error`]): the unspecified address, a
    /// broadcast or multicast address, or loopback from the network
    /// (RFC 1122, section 3.2.1.3).
    #[test]
    fn pings_from_an_address_that_is_not_one_host_get_no_reply() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(echo_reply(&ping("10.0.0.2", "10.0.0.1"), v4).is_some());
        for src in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1"] {
            assert!(
                echo_reply(&ping(src, "10.0.0.1"), v4).is_none(),
                "a ping from {src}"
            );
        }
        let v6: IpAddr = DST.into();
        assert!(echo_reply(&ping(&SRC.to_string(), &DST.to_string()), v6).is_some());
        for src in ["::", "ff02::1", "::1"] {
            assert!(
                echo_reply(&ping(src, &DST.to_string()), v6).is_none(),
                "a ping from {src}"
            );
        }
    }
}
