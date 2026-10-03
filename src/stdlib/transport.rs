//! Which transport an IP packet carries, read the way the stdlib reads it.
//!
//! `fictionet attach --type tap` uses this to pick out link-local control
//! messages and DHCP before a VM's packet reaches the world. It walks and
//! checks IPv6 extension headers with the same code as
//! [`ip::split_protocols`](crate::stdlib::ip::split_protocols)
//! (`wire::ext6_chain`), so a packet attach does not see as ICMPv6 or UDP
//! is one the world's stack does not see as ICMPv6 or UDP either. In
//! particular, a packet whose extension headers the world refuses cannot
//! be read here, and the mobility, HIP and shim6 headers are upper-layer
//! protocols, as they are to the world.
//!
//! Hidden from the docs: it is public only so that the binary can use it,
//! and may change at any time.

use super::wire::{self, V4};

/// What one packet shows of its transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport<'a> {
    /// A packet that is not a fragment: its protocol, and the bytes from
    /// the transport header to the end of the packet.
    Whole {
        /// The IP protocol number, such as 17 for UDP.
        proto: u8,
        /// The transport header and what follows it.
        bytes: &'a [u8],
    },
    /// The first fragment of a packet: its protocol, and the transport
    /// bytes this fragment holds, which stop short of the datagram's end.
    First {
        /// The IP protocol number.
        proto: u8,
        /// The start of the transport header and what follows it.
        bytes: &'a [u8],
    },
    /// A fragment other than the first. Its transport header, if any, is
    /// in the first fragment.
    Later,
    /// A whole packet in one fragment: offset 0, no more fragments, but
    /// with an IPv6 fragment header (an atomic fragment, RFC 6946).
    Atomic {
        /// The IP protocol number.
        proto: u8,
        /// The transport header and what follows it.
        bytes: &'a [u8],
    },
}

/// Reads which transport `packet` carries. `None` if it cannot be read:
/// it is not IPv4 or IPv6, its lengths do not fit, or the world refuses its
/// IPv6 extension headers, for example because one runs past the end, an
/// option says to discard the packet, or a second fragment header follows
/// the first.
pub fn transport(packet: &[u8]) -> Option<Transport<'_>> {
    match wire::version(packet)? {
        4 => {
            let ip = V4::parse(packet, false)?;
            Some(if ip.frag_offset() != 0 {
                Transport::Later
            } else if ip.more_fragments() {
                Transport::First { proto: ip.proto(), bytes: ip.payload() }
            } else {
                Transport::Whole { proto: ip.proto(), bytes: ip.payload() }
            })
        }
        6 => {
            let chain = wire::ext6_chain(packet).ok()?;
            let (proto, bytes) = (chain.proto, &packet[chain.upper..chain.end]);
            let Some((at, _)) = chain.frag else {
                return Some(Transport::Whole { proto, bytes });
            };
            let off_m = u16::from_be_bytes([packet[at + 2], packet[at + 3]]);
            Some(if off_m & 0xfff8 != 0 {
                Transport::Later
            } else if off_m & 1 != 0 {
                Transport::First { proto, bytes }
            } else {
                Transport::Atomic { proto, bytes }
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.push(next);
        p.push(255);
        p.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(&[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(payload);
        p
    }

    fn v4(flags_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 1]);
        p.extend_from_slice(&flags_offset.to_be_bytes());
        p.extend_from_slice(&[64, 17, 0, 0, 10, 0, 0, 2, 255, 255, 255, 255]);
        p.extend_from_slice(payload);
        p
    }

    const RA: [u8; 8] = [134, 0, 0, 0, 64, 0, 0, 0];

    #[test]
    fn every_extension_header_the_stack_reads_is_walked() {
        // Eight destination options headers, then a router advertisement.
        let mut chain = Vec::new();
        for i in 0..8 {
            chain.extend_from_slice(&[if i == 7 { 58 } else { 60 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        chain.extend_from_slice(&RA);
        assert_eq!(transport(&v6(60, &chain)), Some(Transport::Whole { proto: 58, bytes: &RA }));
        // An authentication header (length in 4-byte units, plus 2).
        let mut ah = vec![58, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ah.extend_from_slice(&RA);
        assert_eq!(transport(&v6(51, &ah)), Some(Transport::Whole { proto: 58, bytes: &RA }));
        assert_eq!(transport(&v6(51, &[58])), None);
        // Headers the world refuses cannot be read.
        let discard = [&[58u8, 0, 0x40, 0, 0, 0, 0, 0][..], &RA].concat();
        assert_eq!(transport(&v6(60, &discard)), None);
        let routed = [&[58u8, 0, 4, 1, 0, 0, 0, 0][..], &RA].concat();
        assert_eq!(transport(&v6(43, &routed)), None);
    }

    #[test]
    fn a_chain_that_runs_past_the_end_cannot_be_read() {
        assert_eq!(transport(&v6(60, &[58, 1, 0, 0, 0, 0, 0, 0])), None);
        assert_eq!(transport(&v6(44, &[58, 0, 0, 1])), None);
        // A header that says no next header is not the same as one cut off.
        assert_eq!(transport(&v6(60, &[59, 0, 0, 0, 0, 0, 0, 0])), Some(Transport::Whole { proto: 59, bytes: &[] }));
    }

    #[test]
    fn fragments() {
        let first = [&[58u8, 0, 0, 1, 0, 0, 0, 7][..], &RA].concat();
        assert_eq!(transport(&v6(44, &first)), Some(Transport::First { proto: 58, bytes: &RA }));
        let atomic = [&[58u8, 0, 0, 0, 0, 0, 0, 7][..], &RA].concat();
        assert_eq!(transport(&v6(44, &atomic)), Some(Transport::Atomic { proto: 58, bytes: &RA }));
        let later = [&[58u8, 0, 0, 8, 0, 0, 0, 7][..], &RA].concat();
        assert_eq!(transport(&v6(44, &later)), Some(Transport::Later));
        // An offset-0 fragment header, then one with an offset.
        let twice = [&[44u8, 0, 0, 1, 0, 0, 0, 7][..], &[58, 0, 0, 8, 0, 0, 0, 7], &RA].concat();
        assert_eq!(transport(&v6(44, &twice)), None);

        let udp = [0u8, 68, 0, 67, 0, 16, 0, 0];
        assert_eq!(transport(&v4(0, &udp)), Some(Transport::Whole { proto: 17, bytes: &udp }));
        assert_eq!(transport(&v4(0x2000, &udp)), Some(Transport::First { proto: 17, bytes: &udp }));
        assert_eq!(transport(&v4(0x0001, &udp)), Some(Transport::Later));
        assert_eq!(transport(&v4(0, &udp)[..20]), None, "total length past the end");
        assert_eq!(transport(&[0x50; 40]), None);
    }
}
