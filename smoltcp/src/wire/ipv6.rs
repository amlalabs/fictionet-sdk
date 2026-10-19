#![deny(missing_docs)]

use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};

use super::IpProtocol as Protocol;

pub use core::net::Ipv6Addr as Address;

pub(crate) trait AddressExt {
    /// Query whether the IPv6 address is an [unicast address].
    ///
    /// [unicast address]: https://tools.ietf.org/html/rfc4291#section-2.5
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_is_unicast(&self) -> bool;
}

impl AddressExt for Address {
    fn x_is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }
}

/// A read/write wrapper around an Internet Protocol version 6 packet buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;
    pub(super) const VER_TC_FLOW: Field = 0..4;
    pub(super) const LENGTH: Field = 4..6;
    pub(super) const NXT_HDR: usize = 6;
    pub(super) const HOP_LIMIT: usize = 7;
    pub(super) const SRC_ADDR: Field = 8..24;
    pub(super) const DST_ADDR: Field = 24..40;
}

/// Length of an IPv6 header.
pub(crate) const HEADER_LEN: usize = field::DST_ADDR.end;

impl<T: AsRef<[u8]>> Packet<T> {
    /// Create a raw octet buffer with an IPv6 packet structure.
    #[inline]
    pub(crate) const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub(crate) fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_payload_len].
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[inline]
    pub(crate) fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end || len < self.total_len() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the header length.
    #[inline]
    pub(crate) const fn header_len(&self) -> usize {
        field::DST_ADDR.end
    }

    /// Return the version field.
    #[inline]
    pub(crate) fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_TC_FLOW.start] >> 4
    }

    /// Return the payload length field.
    #[inline]
    pub(crate) fn payload_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the payload length added to the known header length.
    #[inline]
    pub(crate) fn total_len(&self) -> usize {
        self.header_len() + self.payload_len() as usize
    }

    /// Return the next header field.
    #[inline]
    pub(crate) fn next_header(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::NXT_HDR])
    }

    /// Return the hop limit field.
    #[inline]
    pub(crate) fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HOP_LIMIT]
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
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub(crate) fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        let range = self.header_len()..self.total_len();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub(crate) fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[0] = (data[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the traffic class field.
    #[inline]
    pub(crate) fn set_traffic_class(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[0] = (data[0] & 0xf0) | ((value & 0xf0) >> 4);
        data[1] = (data[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the flow label field.
    #[inline]
    pub(crate) fn set_flow_label(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        let raw = (((data[1] & 0xf0) as u32) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut data[1..4], raw);
    }

    /// Set the payload length field.
    #[inline]
    pub(crate) fn set_payload_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value);
    }

    /// Set the next header field.
    #[inline]
    pub(crate) fn set_next_header(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value.into();
    }

    /// Set the hop limit field.
    #[inline]
    pub(crate) fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HOP_LIMIT] = value;
    }

    /// Set the source address field.
    #[inline]
    pub(crate) fn set_src_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(&value.octets());
    }

    /// Set the destination address field.
    #[inline]
    pub(crate) fn set_dst_addr(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(&value.octets());
    }
}

/// A high-level representation of an Internet Protocol version 6 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Repr {
    /// IPv6 address of the source node.
    pub(crate) src_addr: Address,
    /// IPv6 address of the destination node.
    pub(crate) dst_addr: Address,
    /// Protocol contained in the next header.
    pub(crate) next_header: Protocol,
    /// Length of the payload including the extension headers.
    pub(crate) payload_len: usize,
    /// The 8-bit hop limit field.
    pub(crate) hop_limit: u8,
}

impl Repr {
    /// Parse an Internet Protocol version 6 packet and return a high-level representation.
    pub(crate) fn parse<T: AsRef<[u8]> + ?Sized>(packet: &Packet<&T>) -> Result<Repr> {
        packet.check_len()?;
        if packet.version() != 6 {
            return Err(Error);
        }
        Ok(Repr {
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len: packet.payload_len() as usize,
            hop_limit: packet.hop_limit(),
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub(crate) const fn buffer_len(&self) -> usize {
        field::DST_ADDR.end
    }

    /// Emit a high-level representation into an Internet Protocol version 6 packet.
    pub(crate) fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);

        let payload_len = self.payload_len as u16;

        packet.set_payload_len(payload_len);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.dst_addr);
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    const LINK_LOCAL_ALL_NODES: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    const LINK_LOCAL_ALL_ROUTERS: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

    static REPR_PACKET_BYTES: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00,
        0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];
    static REPR_PAYLOAD_BYTES: [u8; 12] = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];

    const fn packet_repr() -> Repr {
        Repr {
            src_addr: Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: LINK_LOCAL_ALL_NODES,
            next_header: Protocol::Udp,
            payload_len: 12,
            hop_limit: 64,
        }
    }

    #[test]
    fn test_packet_deconstruction() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.version(), 6);
        assert_eq!(&packet.buffer[..4], &[0x60, 0, 0, 0]);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(packet.payload_len() as usize, REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(packet.dst_addr(), LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let mut bytes = [0xff; 52];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        // Check that setters preserve adjacent fields.
        packet.set_version(6);
        assert_eq!(packet.version(), 6);
        packet.set_traffic_class(0x99);
        assert_eq!(packet.version(), 6);
        assert_eq!(&packet.buffer[..4], &[0x69, 0x9f, 0xff, 0xff]);
        packet.set_flow_label(0x54321);
        assert_eq!(&packet.buffer[..4], &[0x69, 0x95, 0x43, 0x21]);
        packet.set_payload_len(0xc);
        packet.set_next_header(Protocol::Udp);
        packet.set_hop_limit(0xfe);
        packet.set_src_addr(LINK_LOCAL_ALL_ROUTERS);
        packet.set_dst_addr(LINK_LOCAL_ALL_NODES);
        packet.buffer[HEADER_LEN..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        let mut expected_bytes = [
            0x69, 0x95, 0x43, 0x21, 0x00, 0x0c, 0x11, 0xfe, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let start = expected_bytes.len() - REPR_PAYLOAD_BYTES.len();
        expected_bytes[start..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(&bytes[..], &expected_bytes[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(
            Packet::new_unchecked(&bytes).payload().len(),
            REPR_PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_payload_len(0x80);

        assert_eq!(Packet::new_checked(&bytes).unwrap_err(), Error);
    }

    #[test]
    fn test_repr_parse_valid() {
        let packet = Packet::new_unchecked(&REPR_PACKET_BYTES[..]);
        let repr = Repr::parse(&packet).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_repr_parse_bad_version() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(4);
        packet.set_payload_len(0);
        let packet = Packet::new_unchecked(&bytes[..]);
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_repr_parse_smaller_than_header() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(39);
        let packet = Packet::new_unchecked(&bytes[..]);
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_repr_parse_smaller_than_payload() {
        let mut bytes = [0; 40];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_version(6);
        packet.set_payload_len(1);
        let packet = Packet::new_unchecked(&bytes[..]);
        assert_eq!(Repr::parse(&packet), Err(Error));
    }

    #[test]
    fn test_basic_repr_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xff; repr.buffer_len() + REPR_PAYLOAD_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        repr.emit(&mut packet);
        bytes[HEADER_LEN..].copy_from_slice(&REPR_PAYLOAD_BYTES);
        assert_eq!(&bytes[..], &REPR_PACKET_BYTES[..]);
    }
}
