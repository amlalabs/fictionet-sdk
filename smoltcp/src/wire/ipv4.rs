use byteorder::{ByteOrder, NetworkEndian};

use super::{Error, Result};
use crate::wire::ip::checksum;

use super::IpProtocol as Protocol;

/// Minimum IHL length 5x32 bit words or 20 bytes
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
const MINIMUM_IHL_BYTES: u8 = 20;

pub use core::net::Ipv4Addr as Address;

/// One IPv4 header option, preserving unknown and malformed wire contents.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ipv4Option {
    /// Terminates the list; remaining header bytes are padding.
    EndOfList,
    /// Single byte padding.
    NoOperation,
    /// Addresses recorded along the path. The pointer is one based.
    RecordRoute { pointer: u8, routes: Vec<Address> },
    /// A loose source route. The pointer is one based.
    LooseSourceRoute { pointer: u8, routes: Vec<Address> },
    /// A strict source route. The pointer is one based.
    StrictSourceRoute { pointer: u8, routes: Vec<Address> },
    /// Internet timestamps and their overflow count.
    Timestamp {
        pointer: u8,
        overflow: u8,
        timestamps: Ipv4Timestamp,
    },
    /// The original security option.
    Security {
        security: u16,
        compartments: u16,
        handling_restrictions: u16,
        transmission_control_code: [u8; 3],
    },
    /// The obsolete stream identifier.
    StreamId(u16),
    /// Router Alert value.
    RouterAlert(u16),
    /// Unrecognized full type octet and bytes after type and length.
    Unknown { kind: u8, data: Vec<u8> },
    /// Invalid option, with every byte after its type, including length.
    Malformed { kind: u8, data: Vec<u8> },
}

/// Timestamp data selected by the option's low flag nibble.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ipv4Timestamp {
    /// Flag zero: timestamps only.
    Timestamps(Vec<u32>),
    /// Flag one: addresses and timestamps.
    Addresses(Vec<(Address, u32)>),
    /// Flag three: timestamps for prespecified addresses.
    Prespecified(Vec<(Address, u32)>),
    /// An unrecognized flag nibble and its uninterpreted data.
    Unknown { flags: u8, data: Vec<u8> },
}

/// Why an IPv4 option list cannot be encoded or its header cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4OptionsError {
    /// Invalid IPv4 header lengths or version.
    Header,
    /// Options exceed the forty bytes permitted by the header length field.
    TooLong,
    /// An option cannot be read back as the value supplied.
    Unreadable,
}

impl core::fmt::Display for Ipv4OptionsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Header => "invalid IPv4 header",
            Self::TooLong => "IPv4 options exceed forty bytes",
            Self::Unreadable => "IPv4 option cannot be read back as written",
        })
    }
}
impl core::error::Error for Ipv4OptionsError {}

/// A lossless option walker. An invalid length consumes the remaining area.
/// A framed but malformed option consumes only its own bytes.
pub struct Ipv4Options<'a> {
    rest: &'a [u8],
}
impl<'a> Ipv4Options<'a> {
    /// Walk an IPv4 header's option area, stopping at End of List.
    pub fn new(area: &'a [u8]) -> Self {
        Self { rest: area }
    }
}
impl Iterator for Ipv4Options<'_> {
    type Item = Ipv4Option;
    fn next(&mut self) -> Option<Self::Item> {
        use Ipv4Option::*;
        let (&kind, suffix) = self.rest.split_first()?;
        if kind == 0 {
            self.rest = &[];
            return Some(EndOfList);
        }
        if kind == 1 {
            self.rest = suffix;
            return Some(NoOperation);
        }
        let len = suffix.first().copied().unwrap_or(0) as usize;
        if len < 2 || len > self.rest.len() {
            self.rest = &[];
            return Some(Malformed {
                kind,
                data: suffix.to_vec(),
            });
        }
        let bytes = &self.rest[..len];
        self.rest = &self.rest[len..];
        let data = &bytes[2..];
        let malformed = || Malformed {
            kind,
            data: bytes[1..].to_vec(),
        };
        Some(match kind {
            7 | 131 | 137 if len >= 3 && (len - 3).is_multiple_of(4) && data[0] >= 4 => {
                let pointer = data[0];
                let routes = data[1..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Address::from_octets(*b))
                    .collect();
                match kind {
                    7 => RecordRoute { pointer, routes },
                    131 => LooseSourceRoute { pointer, routes },
                    _ => StrictSourceRoute { pointer, routes },
                }
            }
            68 if len >= 4 && data[0] >= 5 => {
                let flags = data[1] & 15;
                let body = &data[2..];
                let timestamps = match flags {
                    0 if body.len().is_multiple_of(4) => Ipv4Timestamp::Timestamps(
                        body.as_chunks::<4>()
                            .0
                            .iter()
                            .map(|b| NetworkEndian::read_u32(b))
                            .collect(),
                    ),
                    1 | 3 if body.len().is_multiple_of(8) => {
                        let entries = body
                            .as_chunks::<8>()
                            .0
                            .iter()
                            .map(|b| {
                                (
                                    Address::from_octets(b[..4].try_into().unwrap()),
                                    NetworkEndian::read_u32(&b[4..]),
                                )
                            })
                            .collect();
                        if flags == 1 {
                            Ipv4Timestamp::Addresses(entries)
                        } else {
                            Ipv4Timestamp::Prespecified(entries)
                        }
                    }
                    0 | 1 | 3 => return Some(malformed()),
                    _ => Ipv4Timestamp::Unknown {
                        flags,
                        data: body.to_vec(),
                    },
                };
                Timestamp {
                    pointer: data[0],
                    overflow: data[1] >> 4,
                    timestamps,
                }
            }
            130 if len == 11 => Security {
                security: NetworkEndian::read_u16(data),
                compartments: NetworkEndian::read_u16(&data[2..]),
                handling_restrictions: NetworkEndian::read_u16(&data[4..]),
                transmission_control_code: data[6..9].try_into().unwrap(),
            },
            136 if len == 4 => StreamId(NetworkEndian::read_u16(data)),
            148 if len == 4 => RouterAlert(NetworkEndian::read_u16(data)),
            7 | 131 | 137 | 68 | 130 | 136 | 148 => malformed(),
            _ => Unknown {
                kind,
                data: data.to_vec(),
            },
        })
    }
}

/// Encode the exact option bytes without header padding. Malformed values,
/// values with incompatible kinds, and options after End of List are refused.
pub fn encode_ipv4_options(
    options: &[Ipv4Option],
) -> core::result::Result<Vec<u8>, Ipv4OptionsError> {
    use Ipv4Option::*;
    let mut bytes = Vec::new();
    for (index, option) in options.iter().enumerate() {
        if bytes.len() >= 40 {
            return Err(Ipv4OptionsError::TooLong);
        }
        let start = bytes.len();
        match option {
            EndOfList => {
                if index + 1 != options.len() {
                    return Err(Ipv4OptionsError::Unreadable);
                }
                bytes.push(0);
            }
            NoOperation => bytes.push(1),
            RecordRoute { pointer, routes }
            | LooseSourceRoute { pointer, routes }
            | StrictSourceRoute { pointer, routes } => {
                if routes.len() > 9 {
                    return Err(Ipv4OptionsError::TooLong);
                }
                let kind = match option {
                    RecordRoute { .. } => 7,
                    LooseSourceRoute { .. } => 131,
                    _ => 137,
                };
                bytes.extend([kind, (3 + routes.len() * 4) as u8, *pointer]);
                for address in routes {
                    bytes.extend(address.octets());
                }
            }
            Timestamp {
                pointer,
                overflow,
                timestamps,
            } => {
                if *overflow > 15 {
                    return Err(Ipv4OptionsError::Unreadable);
                }
                bytes.extend([68, 0, *pointer, overflow << 4]);
                match timestamps {
                    Ipv4Timestamp::Timestamps(entries) => {
                        if entries.len() > 9 {
                            return Err(Ipv4OptionsError::TooLong);
                        }
                        for value in entries {
                            bytes.extend(value.to_be_bytes());
                        }
                    }
                    Ipv4Timestamp::Addresses(entries) | Ipv4Timestamp::Prespecified(entries) => {
                        if entries.len() > 4 {
                            return Err(Ipv4OptionsError::TooLong);
                        }
                        bytes[start + 3] |= if matches!(timestamps, Ipv4Timestamp::Addresses(_)) {
                            1
                        } else {
                            3
                        };
                        for (address, value) in entries {
                            bytes.extend(address.octets());
                            bytes.extend(value.to_be_bytes());
                        }
                    }
                    Ipv4Timestamp::Unknown { flags, data } => {
                        if *flags > 15 {
                            return Err(Ipv4OptionsError::Unreadable);
                        }
                        if data.len() > 36 {
                            return Err(Ipv4OptionsError::TooLong);
                        }
                        bytes[start + 3] |= flags;
                        bytes.extend(data);
                    }
                }
                bytes[start + 1] = (bytes.len() - start) as u8;
            }
            Security {
                security,
                compartments,
                handling_restrictions,
                transmission_control_code,
            } => {
                bytes.extend([130, 11]);
                bytes.extend(security.to_be_bytes());
                bytes.extend(compartments.to_be_bytes());
                bytes.extend(handling_restrictions.to_be_bytes());
                bytes.extend(transmission_control_code);
            }
            StreamId(value) | RouterAlert(value) => {
                bytes.extend([
                    if matches!(option, StreamId(_)) {
                        136
                    } else {
                        148
                    },
                    4,
                ]);
                bytes.extend(value.to_be_bytes());
            }
            Unknown { kind, data } => {
                if data.len() > 38 {
                    return Err(Ipv4OptionsError::TooLong);
                }
                bytes.extend([*kind, (data.len() + 2) as u8]);
                bytes.extend(data);
            }
            Malformed { .. } => return Err(Ipv4OptionsError::Unreadable),
        }
        if bytes.len() > 40 {
            return Err(Ipv4OptionsError::TooLong);
        }
        if !Ipv4Options::new(&bytes[start..]).eq(core::iter::once(option.clone())) {
            return Err(Ipv4OptionsError::Unreadable);
        }
    }
    Ok(bytes)
}

/// Bounded storage imposed by IPv4's header length field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OptionBytes {
    bytes: [u8; 40],
    len: u8,
}
impl OptionBytes {
    pub(crate) const EMPTY: Self = Self {
        bytes: [0; 40],
        len: 0,
    };
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let mut out = Self::EMPTY;
        out.bytes[..bytes.len()].copy_from_slice(bytes);
        out.len = (bytes.len().div_ceil(4) * 4) as u8;
        out
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

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
    /// Read the option area after validating the complete IPv4 header.
    pub fn options_iter(&self) -> core::result::Result<Ipv4Options<'a>, Ipv4OptionsError> {
        self.check_len().map_err(|_| Ipv4OptionsError::Header)?;
        if self.version() != 4 {
            return Err(Ipv4OptionsError::Header);
        }
        Ok(Ipv4Options::new(
            &self.buffer.as_ref()[HEADER_LEN..self.header_len() as usize],
        ))
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
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
pub struct Repr {
    pub(crate) identification: u16,
    pub(crate) src_addr: Address,
    pub(crate) dst_addr: Address,
    pub(crate) next_header: Protocol,
    pub(crate) payload_len: usize,
    pub(crate) hop_limit: u8,
    pub(crate) options: OptionBytes,
    pub(crate) wire_dst: Option<Address>,
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
            identification: NetworkEndian::read_u16(&packet.buffer.as_ref()[field::IDENT]),
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            next_header: packet.next_header(),
            payload_len,
            hop_limit: packet.hop_limit(),
            options: OptionBytes::new(
                &packet.buffer.as_ref()[HEADER_LEN..packet.header_len() as usize],
            ),
            wire_dst: None,
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    pub(crate) const fn buffer_len(&self) -> usize {
        HEADER_LEN + self.options.len as usize
    }

    /// Emit a high-level representation into an Internet Protocol version 4 packet.
    pub(crate) fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, packet: &mut Packet<T>) {
        packet.set_version(4);
        packet.set_header_len(self.buffer_len() as u8);
        packet.set_dscp(0);
        packet.set_ecn(0);

        let total_len = packet.header_len() as u16 + self.payload_len as u16;

        packet.set_total_len(total_len);
        packet.set_ident(self.identification);
        packet.clear_flags();
        packet.set_more_frags(false);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0);
        packet.set_hop_limit(self.hop_limit);
        packet.set_next_header(self.next_header);
        packet.set_src_addr(self.src_addr);
        packet.set_dst_addr(self.wire_dst.unwrap_or(self.dst_addr));
        packet.buffer.as_mut()[HEADER_LEN..self.buffer_len()]
            .copy_from_slice(self.options.as_slice());

        packet.fill_checksum();
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[test]
    fn options_decode_known_unknown_and_malformed_without_losing_bytes() {
        let bytes = [
            1, 7, 7, 4, 192, 0, 2, 1, 68, 8, 5, 0x20, 0, 0, 0, 42, 222, 3, 9, 7, 3, 0, 1, 254, 8, 4,
        ];
        assert_eq!(
            Ipv4Options::new(&bytes).collect::<Vec<_>>(),
            vec![
                Ipv4Option::NoOperation,
                Ipv4Option::RecordRoute {
                    pointer: 4,
                    routes: vec![Address::new(192, 0, 2, 1)]
                },
                Ipv4Option::Timestamp {
                    pointer: 5,
                    overflow: 2,
                    timestamps: Ipv4Timestamp::Timestamps(vec![42])
                },
                Ipv4Option::Unknown {
                    kind: 222,
                    data: vec![9]
                },
                Ipv4Option::Malformed {
                    kind: 7,
                    data: vec![3, 0]
                },
                Ipv4Option::NoOperation,
                Ipv4Option::Malformed {
                    kind: 254,
                    data: vec![8, 4]
                },
            ]
        );
        assert_eq!(
            Ipv4Options::new(&[0, 254, 255]).collect::<Vec<_>>(),
            vec![Ipv4Option::EndOfList]
        );
        for bytes in [&[7][..], &[7, 0][..], &[7, 1, 9][..]] {
            assert_eq!(
                Ipv4Options::new(bytes).collect::<Vec<_>>(),
                vec![Ipv4Option::Malformed {
                    kind: 7,
                    data: bytes[1..].to_vec()
                }]
            );
        }
    }

    #[test]
    fn option_values_roundtrip_exactly_before_header_padding() {
        use Ipv4Option::*;
        let address = Address::new(192, 0, 2, 1);
        let values = vec![
            EndOfList,
            NoOperation,
            RecordRoute {
                pointer: 4,
                routes: vec![address],
            },
            LooseSourceRoute {
                pointer: 8,
                routes: vec![address],
            },
            StrictSourceRoute {
                pointer: 255,
                routes: vec![],
            },
            Timestamp {
                pointer: 5,
                overflow: 15,
                timestamps: Ipv4Timestamp::Timestamps(vec![0, u32::MAX]),
            },
            Timestamp {
                pointer: 13,
                overflow: 0,
                timestamps: Ipv4Timestamp::Addresses(vec![(address, 42)]),
            },
            Timestamp {
                pointer: 255,
                overflow: 1,
                timestamps: Ipv4Timestamp::Prespecified(vec![(address, 1)]),
            },
            Timestamp {
                pointer: 6,
                overflow: 0,
                timestamps: Ipv4Timestamp::Unknown {
                    flags: 2,
                    data: vec![9],
                },
            },
            Security {
                security: 0xf135,
                compartments: 1,
                handling_restrictions: 2,
                transmission_control_code: [3, 4, 5],
            },
            StreamId(42),
            RouterAlert(0),
            Unknown {
                kind: 222,
                data: vec![1, 2],
            },
        ];
        for value in values {
            let encoded = encode_ipv4_options(core::slice::from_ref(&value)).unwrap();
            assert_eq!(Ipv4Options::new(&encoded).collect::<Vec<_>>(), vec![value]);
        }
        let values = [
            NoOperation,
            Unknown {
                kind: 30,
                data: vec![1],
            },
            EndOfList,
        ];
        let encoded = encode_ipv4_options(&values).unwrap();
        assert_eq!(encoded.len(), 5);
        assert_eq!(Ipv4Options::new(&encoded).collect::<Vec<_>>(), values);
    }

    #[test]
    fn every_framed_option_is_preserved_or_explicitly_malformed() {
        for kind in 2..=255 {
            for len in 2..=40 {
                for value in [0, 1, 3, 4, 5, 15, 255] {
                    let mut bytes = vec![value; len];
                    bytes[0] = kind;
                    bytes[1] = len as u8;
                    let mut options = Ipv4Options::new(&bytes);
                    let option = options.next().unwrap();
                    assert_eq!(options.next(), None);
                    if let Ipv4Option::Malformed { kind: actual, data } = &option {
                        assert_eq!(*actual, kind);
                        assert_eq!(data, &bytes[1..]);
                        assert_eq!(
                            encode_ipv4_options(&[option]),
                            Err(Ipv4OptionsError::Unreadable)
                        );
                    } else {
                        assert_eq!(encode_ipv4_options(&[option]).unwrap(), bytes);
                    }
                }
            }
        }
    }

    #[test]
    fn option_walker_checks_header_lengths_before_reading_options() {
        for len in 0..=64 {
            for ihl in 0..=15 {
                for total in [0, 20, 60, 65] {
                    let mut bytes = vec![0; len];
                    if let Some(first) = bytes.first_mut() {
                        *first = 0x40 | ihl;
                    }
                    if len >= 4 {
                        bytes[3] = total;
                    }
                    let packet = Packet::new_unchecked(&bytes);
                    let valid = ihl >= 5
                        && usize::from(ihl) * 4 <= usize::from(total)
                        && usize::from(total) <= len;
                    assert_eq!(packet.options_iter().is_ok(), valid);
                }
            }
        }
        let mut bytes = [0; 20];
        bytes[0] = 0x65;
        bytes[3] = 20;
        assert!(matches!(
            Packet::new_unchecked(&bytes).options_iter(),
            Err(Ipv4OptionsError::Header)
        ));
    }

    #[test]
    fn option_encoding_rejects_incompatible_values_and_oversized_headers() {
        use Ipv4Option::*;
        for values in [
            vec![EndOfList, NoOperation],
            vec![Malformed {
                kind: 7,
                data: vec![2],
            }],
            vec![Unknown {
                kind: 1,
                data: vec![],
            }],
            vec![Unknown {
                kind: 7,
                data: vec![4],
            }],
            vec![RecordRoute {
                pointer: 3,
                routes: vec![],
            }],
            vec![Timestamp {
                pointer: 5,
                overflow: 16,
                timestamps: Ipv4Timestamp::Timestamps(vec![]),
            }],
            vec![Timestamp {
                pointer: 5,
                overflow: 0,
                timestamps: Ipv4Timestamp::Unknown {
                    flags: 0,
                    data: vec![],
                },
            }],
        ] {
            assert_eq!(
                encode_ipv4_options(&values),
                Err(Ipv4OptionsError::Unreadable)
            );
        }
        assert_eq!(
            encode_ipv4_options(&vec![NoOperation; 41]),
            Err(Ipv4OptionsError::TooLong)
        );
        assert_eq!(
            encode_ipv4_options(&vec![NoOperation; 40]).unwrap().len(),
            40
        );
        assert_eq!(
            encode_ipv4_options(&[Unknown {
                kind: 222,
                data: vec![0; 39]
            }]),
            Err(Ipv4OptionsError::TooLong)
        );
    }

    #[test]
    fn option_header_lengths_padding_and_checksums_include_the_full_header() {
        let options = [Ipv4Option::RecordRoute {
            pointer: 4,
            routes: vec![Address::new(192, 0, 2, 1)],
        }];
        let mut repr = packet_repr();
        repr.options = OptionBytes::new(&encode_ipv4_options(&options).unwrap());
        let mut bytes = vec![0xa5; repr.buffer_len() + repr.payload_len];
        repr.emit(&mut Packet::new_unchecked(&mut bytes));
        let packet = Packet::new_checked(&bytes).unwrap();
        assert_eq!(packet.header_len(), 28);
        assert_eq!(packet.total_len(), 32);
        assert!(packet.verify_checksum());
        assert_eq!(bytes[27], 0);
        assert_eq!(Repr::parse(&packet).unwrap(), repr);
        assert_eq!(
            packet.options_iter().unwrap().collect::<Vec<_>>(),
            vec![options[0].clone(), Ipv4Option::EndOfList]
        );
    }

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
            identification: 0,
            src_addr: Address::new(0x11, 0x12, 0x13, 0x14),
            dst_addr: Address::new(0x21, 0x22, 0x23, 0x24),
            next_header: Protocol::Icmp,
            payload_len: 4,
            hop_limit: 64,
            options: OptionBytes::EMPTY,
            wire_dst: None,
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
