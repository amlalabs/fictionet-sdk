//! ARP: reading and writing Address Resolution Protocol packets for IPv4
//! over Ethernet, with no I/O.
//!
//! An IPv4 host on an Ethernet segment needs the MAC address of the next
//! hop before it can send it a packet. It broadcasts an ARP request that
//! names the IPv4 address it wants, and the host that owns the address
//! answers with a reply that carries its MAC. Both packets also carry the
//! sender's own pair of addresses, so every host that hears one can learn
//! where the sender is. This module follows
//! [RFC 826](https://www.rfc-editor.org/rfc/rfc826), for hardware type
//! Ethernet and protocol type IPv4 only: those are the only kinds of ARP an
//! Ethernet link carrying IPv4 sees.
//!
//! [`Packet`] is one request or reply. [`Packet::parse`] reads exactly one
//! packet through [`Wire`]. [`Packet::receive`] reads the payload of an
//! Ethernet frame, which Ethernet pads to at least 46 bytes, and so ignores
//! bytes after the packet. Both refuse any hardware type, protocol type or
//! address length but Ethernet's and IPv4's, and any operation but a
//! request or a reply. Writing never fails.
//!
//! Who answers what is up to the caller. [`Packet::is_probe`] and
//! [`Packet::is_announcement`] name the two requests a host sends about
//! its own address (RFC 5227), which other hosts should not answer as if the
//! address were theirs.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::protocols::arp::{Operation, Packet};
//!
//! // Who has 10.0.0.1? Tell 10.0.0.2.
//! let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
//! let request = Packet {
//!     operation: Operation::Request,
//!     sender_mac: mac,
//!     sender_ip: Ipv4Addr::new(10, 0, 0, 2),
//!     target_mac: [0; 6],
//!     target_ip: Ipv4Addr::new(10, 0, 0, 1),
//! };
//! // The router that owns 10.0.0.1 answers.
//! let router = [0x02, 0, 0, 0, 0, 1];
//! let reply = request.reply(router);
//! assert_eq!(reply.operation, Operation::Reply);
//! assert_eq!((reply.sender_mac, reply.sender_ip), (router, request.target_ip));
//! assert_eq!((reply.target_mac, reply.target_ip), (mac, request.sender_ip));
//! let bytes = reply.to_bytes().unwrap();
//! assert_eq!(&bytes[..8], &[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
//! assert_eq!(Packet::parse(&bytes).unwrap(), reply);
//! ```

use std::net::Ipv4Addr;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ethernet::frame::Mac;

/// The hardware type of Ethernet (RFC 826; IANA ARP parameters).
pub const HARDWARE_ETHERNET: u16 = 1;
/// The protocol type of IPv4: its EtherType (RFC 826).
pub const PROTOCOL_IPV4: u16 = 0x0800;
/// The length of an ARP packet for IPv4 over Ethernet: 8 bytes of fixed
/// fields, then two 6-byte MACs and two 4-byte IPv4 addresses.
pub const LEN: usize = 28;

/// What an ARP packet asks or says (RFC 826, the `ar$op` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// A request (1): who has the target IPv4 address?
    Request,
    /// A reply (2): the sender has the sender IPv4 address.
    Reply,
}

impl Operation {
    /// The operation's code on the wire.
    pub fn code(self) -> u16 {
        match self {
            Operation::Request => 1,
            Operation::Reply => 2,
        }
    }
}

/// One ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Packet {
    /// Whether this is a request or a reply.
    pub operation: Operation,
    /// The sender's MAC.
    pub sender_mac: Mac,
    /// The sender's IPv4 address, or 0.0.0.0 in a probe.
    pub sender_ip: Ipv4Addr,
    /// The target's MAC. A request does not know it yet and usually
    /// carries zeros.
    pub target_mac: Mac,
    /// The target's IPv4 address: the address a request asks about.
    pub target_ip: Ipv4Addr,
}

/// Why bytes are not an ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the packet does.
    Truncated,
    /// Bytes follow the packet. Only [`Packet::parse`] refuses them.
    Trailing {
        /// Number of bytes after the packet.
        remaining: usize,
    },
    /// The hardware type, protocol type and address lengths are not
    /// Ethernet's and IPv4's (1, 0x0800, 6 and 4).
    NotEthernetIpv4,
    /// The operation is neither a request (1) nor a reply (2).
    Operation(u16),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("ARP packet cut short"),
            Error::Trailing { remaining } => {
                write!(f, "{remaining} bytes after the ARP packet")
            }
            Error::NotEthernetIpv4 => f.write_str("ARP packet is not for IPv4 over Ethernet"),
            Error::Operation(op) => write!(f, "ARP operation {op} is not a request or a reply"),
        }
    }
}

impl std::error::Error for Error {}

/// The first 6 bytes of every ARP packet for IPv4 over Ethernet: the
/// hardware type, the protocol type, and the two address lengths.
const PREFIX: [u8; 6] = [0, 1, 0x08, 0x00, 6, 4];

impl Packet {
    /// Reads the packet at the start of `b`, the payload of an Ethernet
    /// frame, and ignores the padding after it.
    pub fn receive(b: &[u8]) -> Result<Packet, Error> {
        let b = b.get(..LEN).ok_or(Error::Truncated)?;
        if b[..6] != PREFIX {
            return Err(Error::NotEthernetIpv4);
        }
        let operation = match u16::from_be_bytes([b[6], b[7]]) {
            1 => Operation::Request,
            2 => Operation::Reply,
            op => return Err(Error::Operation(op)),
        };
        let mac = |at: usize| -> Mac { b[at..at + 6].try_into().unwrap() };
        let ip = |at: usize| Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3]);
        Ok(Packet {
            operation,
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }

    /// The packet's 28 bytes.
    pub fn encode(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        b[..6].copy_from_slice(&PREFIX);
        b[6..8].copy_from_slice(&self.operation.code().to_be_bytes());
        b[8..14].copy_from_slice(&self.sender_mac);
        b[14..18].copy_from_slice(&self.sender_ip.octets());
        b[18..24].copy_from_slice(&self.target_mac);
        b[24..28].copy_from_slice(&self.target_ip.octets());
        b
    }

    /// The reply to this request from the host at `mac` that owns the
    /// target address: RFC 826 swaps the sender and target fields, puts
    /// the owner's MAC in as the sender's, and sets the operation to reply.
    pub fn reply(&self, mac: Mac) -> Packet {
        Packet {
            operation: Operation::Reply,
            sender_mac: mac,
            sender_ip: self.target_ip,
            target_mac: self.sender_mac,
            target_ip: self.sender_ip,
        }
    }

    /// Whether this is an ARP probe: a request with sender address 0.0.0.0,
    /// which a host sends to check that no other host uses the target
    /// address before it takes it (RFC 5227, section 2.1.1).
    pub fn is_probe(&self) -> bool {
        self.operation == Operation::Request && self.sender_ip.is_unspecified()
    }

    /// Whether this is an ARP announcement, also called gratuitous ARP: a
    /// packet whose sender and target addresses are the same, which a host
    /// sends to say it has taken that address (RFC 5227, section 2.3).
    pub fn is_announcement(&self) -> bool {
        !self.sender_ip.is_unspecified() && self.sender_ip == self.target_ip
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = std::convert::Infallible;

    /// Reads exactly one packet; bytes after it are an error.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        let packet = Packet::receive(b)?;
        match b.len() - LEN {
            0 => Ok(packet),
            remaining => Err(Error::Trailing { remaining }),
        }
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), std::convert::Infallible> {
        out.extend_from_slice(&self.encode());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const ROUTER: Mac = [0x74, 0x83, 0xc2, 0x9a, 0x47, 0xd1];

    /// A request laid out as in RFC 826, field by field.
    fn request_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u16.to_be_bytes()); // ar$hrd: Ethernet
        b.extend_from_slice(&0x0800u16.to_be_bytes()); // ar$pro: IPv4
        b.push(6); // ar$hln
        b.push(4); // ar$pln
        b.extend_from_slice(&1u16.to_be_bytes()); // ar$op: request
        b.extend_from_slice(&MAC); // ar$sha
        b.extend_from_slice(&[10, 0, 0, 2]); // ar$spa
        b.extend_from_slice(&[0; 6]); // ar$tha
        b.extend_from_slice(&[10, 0, 0, 1]); // ar$tpa
        b
    }

    fn request() -> Packet {
        Packet {
            operation: Operation::Request,
            sender_mac: MAC,
            sender_ip: Ipv4Addr::new(10, 0, 0, 2),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::new(10, 0, 0, 1),
        }
    }

    #[test]
    fn reads_and_writes_a_request_from_its_layout() {
        let bytes = request_bytes();
        assert_eq!(bytes.len(), LEN);
        assert_eq!(Packet::parse(&bytes), Ok(request()));
        assert_eq!(request().encode().to_vec(), bytes);
        assert_eq!(request().to_bytes().unwrap(), bytes);
    }

    #[test]
    fn replies_round_trip() {
        let reply = request().reply(ROUTER);
        let bytes = reply.encode();
        assert_eq!(&bytes[6..8], &[0, 2]);
        assert_eq!(&bytes[8..14], &ROUTER);
        assert_eq!(&bytes[14..18], &[10, 0, 0, 1]);
        assert_eq!(&bytes[18..24], &MAC);
        assert_eq!(&bytes[24..28], &[10, 0, 0, 2]);
        assert_eq!(Packet::parse(&bytes), Ok(reply));
    }

    #[test]
    fn padding_is_ignored_on_receipt_and_refused_by_parse() {
        let mut padded = request_bytes();
        padded.resize(46, 0);
        assert_eq!(Packet::receive(&padded), Ok(request()));
        assert_eq!(
            Packet::parse(&padded),
            Err(Error::Trailing { remaining: 18 })
        );
    }

    #[test]
    fn every_short_input_is_truncated() {
        let bytes = request_bytes();
        for len in 0..LEN {
            assert_eq!(Packet::receive(&bytes[..len]), Err(Error::Truncated));
            assert_eq!(Packet::parse(&bytes[..len]), Err(Error::Truncated));
        }
    }

    #[test]
    fn other_hardware_protocols_and_operations_are_refused() {
        for (at, value) in [(1, 6), (2, 0x86), (3, 0xdd), (4, 8), (5, 16)] {
            let mut b = request_bytes();
            b[at] = value;
            assert_eq!(Packet::parse(&b), Err(Error::NotEthernetIpv4), "{at}");
        }
        for op in [0u16, 3, 4, 0x0100, u16::MAX] {
            let mut b = request_bytes();
            b[6..8].copy_from_slice(&op.to_be_bytes());
            assert_eq!(Packet::parse(&b), Err(Error::Operation(op)));
        }
    }

    #[test]
    fn every_byte_value_at_every_position_reads_or_fails_cleanly() {
        let bytes = request_bytes();
        for at in 0..LEN {
            for value in [0, 1, 2, 0x7f, 0x80, 0xff] {
                let mut b = bytes.clone();
                b[at] = value;
                if let Ok(p) = Packet::parse(&b) {
                    assert_eq!(p.encode().to_vec(), b);
                }
            }
        }
    }

    #[test]
    fn probes_and_announcements() {
        let probe = Packet {
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
            ..request()
        };
        assert!(probe.is_probe() && !probe.is_announcement());
        let announcement = Packet {
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
            ..request()
        };
        assert!(announcement.is_announcement() && !announcement.is_probe());
        assert!(!request().is_probe() && !request().is_announcement());
    }
}
