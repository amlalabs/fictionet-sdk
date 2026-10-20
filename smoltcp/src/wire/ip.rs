use core::convert::From;

use super::{Error, Result};

use crate::wire::{Ipv4Address, Ipv4AddressExt, Ipv4Packet, Ipv4Repr};

use crate::wire::{Ipv6Address, Ipv6AddressExt, Ipv6Packet, Ipv6Repr};

/// Internet protocol version.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub(crate) enum Version {
    Ipv4,

    Ipv6,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// Empty packets and unknown versions return `Err(Error)`.
    pub(crate) const fn of_packet(data: &[u8]) -> Result<Version> {
        let Some(&first) = data.first() else {
            return Err(Error);
        };
        match first >> 4 {
            4 => Ok(Version::Ipv4),

            6 => Ok(Version::Ipv6),
            _ => Err(Error),
        }
    }
}

enum_with_unknown! {
    /// IP datagram encapsulated protocol.
    pub(crate) enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        IpSecEsp  = 0x32,
        IpSecAh   = 0x33,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

/// An internetworking address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An IPv4 address.
    Ipv4(Ipv4Address),
    /// An IPv6 address.
    Ipv6(Ipv6Address),
}

impl Address {
    /// Return the protocol version.
    pub(crate) const fn version(&self) -> Version {
        match self {
            Address::Ipv4(_) => Version::Ipv4,
            Address::Ipv6(_) => Version::Ipv6,
        }
    }

    /// Query whether the address is a valid unicast address.
    pub(crate) fn is_unicast(&self) -> bool {
        match self {
            Address::Ipv4(addr) => addr.x_is_unicast(),
            Address::Ipv6(addr) => addr.x_is_unicast(),
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub(crate) fn is_unspecified(&self) -> bool {
        match self {
            Address::Ipv4(addr) => addr.is_unspecified(),
            Address::Ipv6(addr) => addr.is_unspecified(),
        }
    }
}

impl From<::core::net::IpAddr> for Address {
    fn from(x: ::core::net::IpAddr) -> Address {
        match x {
            ::core::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
            ::core::net::IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
        }
    }
}

impl From<Address> for ::core::net::IpAddr {
    fn from(x: Address) -> ::core::net::IpAddr {
        match x {
            Address::Ipv4(ipv4) => ::core::net::IpAddr::V4(ipv4),
            Address::Ipv6(ipv6) => ::core::net::IpAddr::V6(ipv6),
        }
    }
}

impl From<Ipv4Address> for Address {
    fn from(ipv4: Ipv4Address) -> Address {
        Address::Ipv4(ipv4)
    }
}

impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

/// An internet endpoint address.
///
/// `Endpoint` always fully specifies both the address and the port.
///
/// See also ['ListenEndpoint'], which allows not specifying the address
/// in order to listen on a given port on any address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Endpoint {
    pub(crate) addr: Address,
    pub(crate) port: u16,
}

impl Endpoint {
    /// Create an endpoint address from given address and port.
    pub(crate) const fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }
}

impl From<::core::net::SocketAddr> for Endpoint {
    fn from(x: ::core::net::SocketAddr) -> Endpoint {
        Endpoint {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

impl From<Endpoint> for ::core::net::SocketAddr {
    fn from(x: Endpoint) -> ::core::net::SocketAddr {
        ::core::net::SocketAddr::new(x.addr.into(), x.port)
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint {
            addr: addr.into(),
            port,
        }
    }
}

/// An internet endpoint address for listening.
///
/// In contrast with [`Endpoint`], `ListenEndpoint` allows not specifying the address,
/// in order to listen on a given port at all our addresses.
///
/// An endpoint can be constructed from a port, in which case the address is unspecified.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ListenEndpoint {
    pub(crate) addr: Option<Address>,
    pub(crate) port: u16,
}

impl From<::core::net::SocketAddr> for ListenEndpoint {
    fn from(x: ::core::net::SocketAddr) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(x.ip().into()),
            port: x.port(),
        }
    }
}

impl From<u16> for ListenEndpoint {
    fn from(port: u16) -> ListenEndpoint {
        ListenEndpoint { addr: None, port }
    }
}

impl From<Endpoint> for ListenEndpoint {
    fn from(endpoint: Endpoint) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(endpoint.addr),
            port: endpoint.port,
        }
    }
}

impl<T: Into<Address>> From<(T, u16)> for ListenEndpoint {
    fn from((addr, port): (T, u16)) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(addr.into()),
            port,
        }
    }
}

/// An IP packet representation.
///
/// This enum abstracts the various versions of IP packets. It either contains an IPv4
/// or IPv6 concrete high-level representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Repr {
    Ipv4(Ipv4Repr),

    Ipv6(Ipv6Repr),
}

impl From<Ipv4Repr> for Repr {
    fn from(repr: Ipv4Repr) -> Repr {
        Repr::Ipv4(repr)
    }
}

impl From<Ipv6Repr> for Repr {
    fn from(repr: Ipv6Repr) -> Repr {
        Repr::Ipv6(repr)
    }
}

impl Repr {
    /// Create a new IpRepr, choosing the right IP version for the src/dst addrs.
    ///
    /// # Panics
    ///
    /// Panics if `src_addr` and `dst_addr` are different IP version.
    pub(crate) fn new(
        src_addr: Address,
        dst_addr: Address,
        next_header: Protocol,
        payload_len: usize,
        hop_limit: u8,
    ) -> Self {
        match (src_addr, dst_addr) {
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => Self::Ipv4(Ipv4Repr {
                src_addr,
                dst_addr,
                next_header,
                payload_len,
                hop_limit,
            }),

            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => Self::Ipv6(Ipv6Repr {
                src_addr,
                dst_addr,
                next_header,
                payload_len,
                hop_limit,
            }),
            _ => panic!("IP version mismatch: src={src_addr:?} dst={dst_addr:?}"),
        }
    }

    /// Return the source address.
    pub(crate) const fn src_addr(&self) -> Address {
        match *self {
            Repr::Ipv4(repr) => Address::Ipv4(repr.src_addr),
            Repr::Ipv6(repr) => Address::Ipv6(repr.src_addr),
        }
    }

    /// Return the destination address.
    pub(crate) const fn dst_addr(&self) -> Address {
        match *self {
            Repr::Ipv4(repr) => Address::Ipv4(repr.dst_addr),
            Repr::Ipv6(repr) => Address::Ipv6(repr.dst_addr),
        }
    }

    /// Return the payload length.
    pub(crate) const fn payload_len(&self) -> usize {
        match *self {
            Repr::Ipv4(repr) => repr.payload_len,
            Repr::Ipv6(repr) => repr.payload_len,
        }
    }

    /// Set the payload length.
    pub(crate) fn set_payload_len(&mut self, length: usize) {
        match self {
            Repr::Ipv4(Ipv4Repr { payload_len, .. }) => *payload_len = length,
            Repr::Ipv6(Ipv6Repr { payload_len, .. }) => *payload_len = length,
        }
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub(crate) const fn header_len(&self) -> usize {
        match *self {
            Repr::Ipv4(repr) => repr.buffer_len(),
            Repr::Ipv6(repr) => repr.buffer_len(),
        }
    }

    /// Emit this high-level representation into a buffer.
    pub(crate) fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, buffer: T) {
        match *self {
            Repr::Ipv4(repr) => repr.emit(&mut Ipv4Packet::new_unchecked(buffer)),
            Repr::Ipv6(repr) => repr.emit(&mut Ipv6Packet::new_unchecked(buffer)),
        }
    }

    /// Return the total length of a packet that will be emitted from this
    /// high-level representation.
    ///
    /// This is the same as `repr.buffer_len() + repr.payload_len()`.
    pub(crate) const fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }
}

pub(crate) mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    const fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub(crate) fn data(data: &[u8]) -> u16 {
        // We calculate the sum in native-endian before converting to big-endian at the end
        // see RFC 1071 section 2.(B) for details
        let mut accum: u32 = 0;

        // Sum two words per iteration to reduce loop overhead.
        let (chunks, mut rem) = data.as_chunks::<4>();
        for chunk in chunks {
            let val_0 = u16::from_ne_bytes(chunk[..2].try_into().unwrap());
            let val_1 = u16::from_ne_bytes(chunk[2..4].try_into().unwrap());
            accum += val_0 as u32;
            accum += val_1 as u32;
        }

        // Handle 2 bytes of tail, if present.
        if rem.len() >= 2 {
            let val = u16::from_ne_bytes(rem[..2].try_into().unwrap());
            accum += val as u32;
            rem = &rem[2..];
        }

        // Add the last remaining odd byte, if any.
        if let Some(&value) = rem.first() {
            accum += u16::from_ne_bytes([value, 0]) as u32;
        }

        let collapsed = propagate_carries(accum);
        u16::to_be(collapsed)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub(crate) fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    pub(crate) fn pseudo_header_v4(
        src_addr: &Ipv4Address,
        dst_addr: &Ipv4Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(&src_addr.octets()),
            data(&dst_addr.octets()),
            data(&proto_len[..]),
        ])
    }

    pub(crate) fn pseudo_header_v6(
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(&src_addr.octets()),
            data(&dst_addr.octets()),
            data(&proto_len[..]),
        ])
    }

    pub(crate) fn pseudo_header(
        src_addr: &Address,
        dst_addr: &Address,
        next_header: Protocol,
        length: u32,
    ) -> u16 {
        match (src_addr, dst_addr) {
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => {
                pseudo_header_v4(src_addr, dst_addr, next_header, length)
            }

            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => {
                pseudo_header_v6(src_addr, dst_addr, next_header, length)
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {

    use super::*;

    #[test]
    fn test_empty_packet_version() {
        assert_eq!(Version::of_packet(&[]), Err(Error));
    }
}
