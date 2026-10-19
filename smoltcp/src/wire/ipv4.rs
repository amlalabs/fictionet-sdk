use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};
use crate::wire::ip::checksum;

use super::IpProtocol as Protocol;

/// Minimum IHL length 5x32 bit words or 20 bytes
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
const MINIMUM_IHL_BYTES: u8 = 20;

pub use core::net::Ipv4Addr as Address;

pub(crate) trait AddressExt {
    /// Query whether the address is an unicast address.
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_is_unicast(&self) -> bool;
}

impl AddressExt for Address {
    /// Query whether the address is an unicast address.
    fn x_is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    pub(super) const VER_IHL: usize = 0;
    pub(super) const DSCP_ECN: usize = 1;
    pub(super) const LENGTH: Field = 2..4;
    pub(super) const IDENT: Field = 4..6;
    pub(super) const FLG_OFF: Field = 6..8;
    pub(super) const TTL: usize = 8;
    pub(super) const PROTOCOL: usize = 9;
    pub(super) const CHECKSUM: Field = 10..12;
    pub(super) const SRC_ADDR: Field = 12..16;
    pub(super) const DST_ADDR: Field = 16..20;
}

pub(crate) const HEADER_LEN: usize = field::DST_ADDR.end;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub(crate) fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the header length is greater
    /// than total length.
    /// Returns `Err(Error)` if the header length is less than minimum allowed IHL
    ///
    /// The result of this check is invalidated by calling [set_header_len]
    /// and [set_total_len].
    ///
    /// [set_header_len]: #method.set_header_len
    /// [set_total_len]: #method.set_total_len
    #[allow(clippy::if_same_then_else)]
    pub(crate) fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end {
            Err(Error)
        } else if len < self.header_len() as usize {
            Err(Error)
        } else if self.header_len() as u16 > self.total_len() {
            Err(Error)
        } else if len < self.total_len() as usize {
            Err(Error)
        } else if self.header_len() < MINIMUM_IHL_BYTES {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the version field.
    #[inline]
    pub(crate) fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub(crate) fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the total length field.
    #[inline]
    pub(crate) fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub(crate) fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub(crate) fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub(crate) fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the next_header (protocol) field.
    #[inline]
    pub(crate) fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::PROTOCOL])
    }

    /// Return the source address field.
    #[inline]
    pub(crate) fn src_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_octets(data[field::SRC_ADDR].try_into().unwrap())
    }

    /// Return the destination address field.
    #[inline]
    pub(crate) fn dst_addr(&self) -> Address {
        let data = self.buffer.as_ref();
        Address::from_octets(data[field::DST_ADDR].try_into().unwrap())
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(&data[..self.header_len() as usize]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub(crate) fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub(crate) fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub(crate) fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub(crate) fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub(crate) fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub(crate) fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub(crate) fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub(crate) fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub(crate) fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the next header (protocol) field.
    #[inline]
    pub(crate) fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub(crate) fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub(crate) fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(&value.octets())
    }

    /// Set the destination address field.
    #[inline]
    pub(crate) fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(&value.octets())
    }

    /// Compute and fill in the header checksum.
    pub(crate) fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// A high-level representation of an Internet Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Repr {
    pub(crate) src_addr: Address,
    pub(crate) dst_addr: Address,
    pub(crate) next_header: Protocol,
    pub(crate) payload_len: usize,
    pub(crate) hop_limit: u8,
}

impl Repr {
    /// Parse an Internet Protocol version 4 packet and return a high-level representation.
    pub(crate) fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr> {
        packet.check_len()?;
        // Version 4 is expected.
        if packet.version() != 4 {
            return Err(Error);
        }
        // Valid checksum is expected.
        if !packet.verify_checksum() {
            return Err(Error);
        }

        // We do not support fragmentation.
        if packet.more_frags() || packet.frag_offset() != 0 {
            return Err(Error);
        }

        let payload_len = packet.total_len() as usize - packet.header_len() as usize;

        // All DSCP values are acceptable, since they are of no concern to receiving endpoint.
        // All ECN values are acceptable, since ECN requires opt-in from both endpoints.
        // All TTL values are acceptable, since we do not perform routing.
        Ok(Repr {
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len,
            hop_limit: packet.hop_limit(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub(crate) const fn buffer_len(&self) -> usize {
        // We never emit any options.
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    pub(crate) fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(4);
        packet.set_header_len(field::DST_ADDR.end as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);

        let total_len = packet.header_len() as u16 + self.payload_len as u16;

        packet.set_total_len(total_len);
        packet.set_ident(0);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);

        packet.fill_checksum();
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    static PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 10] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let packet = Packet::new_unchecked(&PACKET_BYTES[..]);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.total_len(), 30);
        assert!(packet.more_frags());
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.next_header(), Protocol::Icmp);
        assert_eq!(packet.src_addr(), Address::new(0x11, 0x12, 0x13, 0x14));
        assert_eq!(packet.dst_addr(), Address::new(0x21, 0x22, 0x23, 0x24));
        assert!(packet.verify_checksum());
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_hop_limit(0x1a);
        packet.set_next_header(Protocol::Icmp);
        packet.set_src_addr(Address::new(0x11, 0x12, 0x13, 0x14));
        packet.set_dst_addr(Address::new(0x21, 0x22, 0x23, 0x24));
        packet.fill_checksum();
        bytes[HEADER_LEN..].copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&bytes[..], &PACKET_BYTES[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(
            Packet::new_unchecked(&bytes).payload().len(),
            PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_total_len(128);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(), Error);
    }

    static REPR_PACKET_BYTES: [u8; 24] = [
        0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0xd2, 0x79, 0x11, 0x12, 0x13,
        0x14, 0x21, 0x22, 0x23, 0x24, 0xaa, 0x00, 0x00, 0xff,
    ];

    static REPR_PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    const fn packet_repr() -> Repr {
        Repr {
            src_addr: Address::new(0x11, 0x12, 0x13, 0x14),
            dst_addr: Address::new(0x21, 0x22, 0x23, 0x24),
            next_header: Protocol::Icmp,
            payload_len: 4,
            hop_limit: 64,
        }
    }

    #[test]
    fn test_parse() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_parse_bad_version() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(6);
        packet.fill_checksum();
        let packet = Packet::new_unchecked(&bytes[..]);
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = vec![0; 40];
        bytes[0] = 0x09;
        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_parse_small_ihl() {
        let mut bytes = vec![0; 24];
        bytes.copy_from_slice(&REPR_PACKET_BYTES[..]);
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(16);

        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet);
        bytes[HEADER_LEN..].copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&bytes[..], &REPR_PACKET_BYTES[..]);
    }

    #[test]
    fn test_unspecified() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::UNSPECIFIED.is_broadcast());
        assert!(!Address::UNSPECIFIED.is_multicast());
        assert!(!Address::UNSPECIFIED.is_link_local());
        assert!(!Address::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Address::BROADCAST.is_unspecified());
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_link_local());
        assert!(!Address::BROADCAST.is_loopback());
    }
}
