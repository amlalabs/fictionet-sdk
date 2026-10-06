//! Geneve: reading and writing tunnel headers and their options, with no
//! I/O.
//!
//! Geneve (Generic Network Virtualization Encapsulation) carries one
//! network's packets inside UDP datagrams of another, usually on port
//! 6081. Cloud networks use it to keep each tenant's traffic apart: every
//! packet carries a 24-bit Virtual Network Identifier (VNI) that says
//! which virtual network it belongs to. Behind an 8-byte header come up to
//! 252 bytes of options, each a class, a type and some data, and then the
//! inner packet, often a whole Ethernet frame. This module follows RFC
//! 8926.
//!
//! Nothing here reads a socket. A world that plays a tunnel endpoint hands
//! each datagram it reads from a [`udp`](fictionet::stdlib::udp) socket to
//! [`Packet::parse`], looks at the [`Header`], and does what it likes with
//! the inner payload. To send, it builds a [`Packet`] and writes the bytes
//! [`Wire::to_bytes`] returns. For pieces of one datagram, use
//! [`Stream<Collect<Packet>>`](fictionet::stdlib::codec::Stream)
//! and a collection limit of [`MAX_DATAGRAM`]. Call `end` at the datagram boundary.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A header whose version is not 0, whose options run past the
//! header's option length, or whose C bit does not match its options is
//! refused. The reserved bits are ignored when read and written as zero,
//! as the RFC asks. Writers check the same rules, so bytes they return
//! always read back.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::geneve::{protocol, GeneveOption, Header, Packet};
//!
//! let packet = Packet {
//!     header: Header {
//!         control: false,
//!         protocol: protocol::TRANSPARENT_ETHERNET_BRIDGING,
//!         vni: 0x00abcd,
//!         options: vec![GeneveOption { class: 0x0105, kind: 1, critical: true, data: vec![0, 0, 0, 7] }],
//!     },
//!     payload: b"inner frame".to_vec(),
//! };
//! let bytes = packet.to_bytes().unwrap();
//! // Version 0 and 2 words of options; the C bit, since one option is
//! // critical; protocol 0x6558; VNI 0x00abcd; then the option.
//! assert_eq!(&bytes[..8], &[0x02, 0x40, 0x65, 0x58, 0x00, 0xab, 0xcd, 0x00]);
//! assert_eq!(&bytes[8..16], &[0x01, 0x05, 0x81, 0x01, 0, 0, 0, 7]);
//! assert_eq!(&bytes[16..], b"inner frame");
//!
//! let back = Packet::parse(&bytes).unwrap();
//! assert_eq!(back, packet);
//! assert_eq!(back.header.option(0x0105, 1).unwrap().data, [0, 0, 0, 7]);
//! ```

use fictionet::stdlib::codec::Wire;

/// The UDP port Geneve endpoints listen on.
pub const PORT: u16 = 6081;
/// The only version RFC 8926 defines.
pub const VERSION: u8 = 0;
/// The length of the fixed header, before the options.
pub const BASE_HEADER_LEN: usize = 8;
/// The most option bytes a header may carry: the 6-bit option length
/// field counts 4-byte words.
pub const MAX_OPTIONS_LEN: usize = 63 * 4;
/// The longest header: the fixed part and the most options.
pub const MAX_HEADER_LEN: usize = BASE_HEADER_LEN + MAX_OPTIONS_LEN;
/// The length of an option's own header, before its data.
pub const OPTION_HEADER_LEN: usize = 4;
/// The most data one option may carry: the 5-bit length field counts
/// 4-byte words.
pub const MAX_OPTION_DATA: usize = 31 * 4;
/// The highest option type, not counting the critical bit.
pub const MAX_OPTION_KIND: u8 = 0x7f;
/// The highest VNI: it is 24 bits long.
pub const MAX_VNI: u32 = 0x00ff_ffff;
/// The longest datagram this module reads or writes, header and payload
/// together: the most a UDP length field allows, less the UDP header.
pub const MAX_DATAGRAM: usize = 65535 - 8;
/// The longest payload a packet may carry when it has no options.
pub const MAX_PAYLOAD: usize = MAX_DATAGRAM - BASE_HEADER_LEN;

/// Protocol types: the EtherType of the inner packet.
pub mod protocol {
    /// The payload is a whole Ethernet frame.
    pub const TRANSPARENT_ETHERNET_BRIDGING: u16 = 0x6558;
    /// The payload is an IPv4 packet.
    pub const IPV4: u16 = 0x0800;
    /// The payload is an IPv6 packet.
    pub const IPV6: u16 = 0x86dd;
}

/// One option: a TLV after the fixed header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GeneveOption {
    /// The option class: who defined the option. Classes 0x0000 to 0x00ff
    /// are for the IETF, and 0xff00 to 0xffff are for experiments.
    pub class: u16,
    /// The option type within its class, from 0 to [`MAX_OPTION_KIND`].
    /// The type field's top bit is kept apart, in `critical`.
    pub kind: u8,
    /// The critical bit. An endpoint that does not know a critical option
    /// must drop the packet.
    pub critical: bool,
    /// The option's data: a multiple of 4 bytes, at most
    /// [`MAX_OPTION_DATA`].
    pub data: Vec<u8>,
}

impl GeneveOption {
    /// How many bytes the option takes in a header: its own header and its
    /// data.
    pub fn len(&self) -> usize {
        OPTION_HEADER_LEN.saturating_add(self.data.len())
    }

    /// Whether the option takes no bytes. It never does, since its header
    /// is 4 bytes, so this is always false.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Checks that the option can be written: its type fits in 7 bits and
    /// its data is a multiple of 4 bytes, at most [`MAX_OPTION_DATA`].
    pub fn check(&self) -> Result<(), GeneveError> {
        if self.kind > MAX_OPTION_KIND {
            return Err(GeneveError::OptionType(self.kind));
        }
        if self.data.len() > MAX_OPTION_DATA || !self.data.len().is_multiple_of(4) {
            return Err(GeneveError::OptionData(self.data.len()));
        }
        Ok(())
    }
}

/// A Geneve header: the fixed fields and the options. The version is
/// always 0, and the option length and the C bit are worked out from the
/// options, so none of them is kept.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Header {
    /// The O bit: the packet is a control message for the endpoints, not
    /// data to forward.
    pub control: bool,
    /// The EtherType of the payload, such as
    /// [`protocol::TRANSPARENT_ETHERNET_BRIDGING`].
    pub protocol: u16,
    /// The Virtual Network Identifier, from 0 to [`MAX_VNI`].
    pub vni: u32,
    /// The options, in the order they appear.
    pub options: Vec<GeneveOption>,
}

/// Why bytes are not a Geneve packet, or why a packet cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GeneveError {
    /// The bytes end before the header and its options do.
    Truncated,
    /// Bytes follow a standalone header.
    Trailing {
        /// Number of bytes after the Geneve header.
        remaining: usize,
    },
    /// The version was not 0. A receiver drops such packets.
    Version(u8),
    /// The option whose header starts at this offset says it is longer
    /// than the header's option length leaves room for.
    OptionOverrun(usize),
    /// The C bit, whose value is given, does not match the options: it
    /// must be set exactly when at least one option is critical.
    CriticalBit(bool),
    /// The datagram is longer than [`MAX_DATAGRAM`].
    TooLong,
    /// A VNI above [`MAX_VNI`] cannot be written.
    Vni(u32),
    /// An option type above [`MAX_OPTION_KIND`] cannot be written.
    OptionType(u8),
    /// Option data of this many bytes cannot be written: it must be a
    /// multiple of 4, at most [`MAX_OPTION_DATA`].
    OptionData(usize),
    /// Options of this many bytes in all cannot be written: they must fit
    /// in [`MAX_OPTIONS_LEN`].
    OptionsLength(usize),
}

impl std::fmt::Display for GeneveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeneveError::Trailing { remaining } => {
                write!(f, "{remaining} bytes after the Geneve header")
            }
            GeneveError::Truncated => f.write_str("bytes end inside the Geneve header"),
            GeneveError::Version(v) => write!(f, "Geneve version {v}, not 0"),
            GeneveError::OptionOverrun(at) => {
                write!(f, "option at offset {at} runs past the option length")
            }
            GeneveError::CriticalBit(true) => f.write_str("C bit set, but no option is critical"),
            GeneveError::CriticalBit(false) => f.write_str("a critical option, but the C bit is clear"),
            GeneveError::TooLong => write!(f, "datagram longer than {MAX_DATAGRAM} bytes"),
            GeneveError::Vni(v) => write!(f, "VNI {v} does not fit in 24 bits"),
            GeneveError::OptionType(t) => write!(f, "option type {t} does not fit in 7 bits"),
            GeneveError::OptionData(n) => {
                write!(f, "option data of {n} bytes, not a multiple of 4 up to {MAX_OPTION_DATA}")
            }
            GeneveError::OptionsLength(n) => {
                write!(f, "options of {n} bytes, more than {MAX_OPTIONS_LEN}")
            }
        }
    }
}

impl std::error::Error for GeneveError {}

impl Header {
    /// Reads the header at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the header and how many bytes
    /// of `b` it took. An error is returned as soon as the bytes so far
    /// show it, so a longer `b` with the same start gives the same error.
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Header, usize)>, GeneveError> {
        let Some(&first) = b.first() else {
            return Ok(None);
        };
        let version = first >> 6;
        if version != VERSION {
            return Err(GeneveError::Version(version));
        }
        let Some(&flags) = b.get(1) else {
            return Ok(None);
        };
        let control = flags & 0x80 != 0;
        let c_bit = flags & 0x40 != 0;
        let end = BASE_HEADER_LEN + usize::from(first & 0x3f) * 4;
        // Walk the option headers first: an overrun or a wrong C bit shows
        // before the option data comes.
        let mut at = BASE_HEADER_LEN;
        let mut any_critical = false;
        while at < end {
            let Some(h) = b.get(at..at + OPTION_HEADER_LEN) else {
                return Ok(None);
            };
            let next = at + OPTION_HEADER_LEN + usize::from(h[3] & 0x1f) * 4;
            if next > end {
                return Err(GeneveError::OptionOverrun(at));
            }
            if h[2] & 0x80 != 0 {
                // A critical option under a clear C bit shows here, before
                // the options after it come.
                if !c_bit {
                    return Err(GeneveError::CriticalBit(false));
                }
                any_critical = true;
            }
            at = next;
        }
        if any_critical != c_bit {
            return Err(GeneveError::CriticalBit(c_bit));
        }
        let Some(fixed) = b.get(..BASE_HEADER_LEN) else {
            return Ok(None);
        };
        let Some(raw) = b.get(BASE_HEADER_LEN..end) else {
            return Ok(None);
        };
        let mut options = Vec::new();
        let mut rest = raw;
        while let [c0, c1, t, len, tail @ ..] = rest {
            let n = usize::from(len & 0x1f) * 4;
            let Some((data, after)) = tail.split_at_checked(n) else {
                // The walk above already checked every length.
                return Err(GeneveError::OptionOverrun(end - rest.len()));
            };
            options.push(GeneveOption {
                class: u16::from_be_bytes([*c0, *c1]),
                kind: t & MAX_OPTION_KIND,
                critical: t & 0x80 != 0,
                data: data.to_vec(),
            });
            rest = after;
        }
        let header = Header {
            control,
            protocol: u16::from_be_bytes([fixed[2], fixed[3]]),
            vni: u32::from_be_bytes([0, fixed[4], fixed[5], fixed[6]]),
            options,
        };
        Ok(Some((header, end)))
    }

    /// Reads the header at the start of `b` and returns it with the bytes
    /// after it: the inner payload. A `b` too short for the header is
    /// [`GeneveError::Truncated`], and one longer than [`MAX_DATAGRAM`]
    /// is [`GeneveError::TooLong`].
    pub fn split(b: &[u8]) -> Result<(Header, &[u8]), GeneveError> {
        match Header::parse_prefix(b)? {
            None => Err(GeneveError::Truncated),
            Some(_) if b.len() > MAX_DATAGRAM => Err(GeneveError::TooLong),
            Some((header, used)) => Ok((header, b.get(used..).unwrap_or(&[]))),
        }
    }

    /// Whether any option has the critical bit set. The header's C bit is
    /// written from this.
    pub fn critical(&self) -> bool {
        self.options.iter().any(|o| o.critical)
    }

    /// The first option with this class and type, if there is one.
    pub fn option(&self, class: u16, kind: u8) -> Option<&GeneveOption> {
        self.options.iter().find(|o| o.class == class && o.kind == kind)
    }

    /// The bytes all the options take.
    pub fn options_len(&self) -> usize {
        self.options.iter().fold(0usize, |n, o| n.saturating_add(o.len()))
    }

    /// The bytes the whole header takes.
    pub fn len(&self) -> usize {
        BASE_HEADER_LEN.saturating_add(self.options_len())
    }

    /// Whether the header takes no bytes. It never does, so this is
    /// always false.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Checks that the header can be written: the VNI fits in 24 bits,
    /// each option passes [`GeneveOption::check`], and the options fit in
    /// [`MAX_OPTIONS_LEN`].
    pub fn check(&self) -> Result<(), GeneveError> {
        if self.vni > MAX_VNI {
            return Err(GeneveError::Vni(self.vni));
        }
        for o in &self.options {
            o.check()?;
        }
        let n = self.options_len();
        if n > MAX_OPTIONS_LEN {
            return Err(GeneveError::OptionsLength(n));
        }
        Ok(())
    }
}

/// One Geneve datagram: the header and the inner packet it carries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Packet {
    /// The header and its options.
    pub header: Header,
    /// The inner packet, whose kind the header's protocol type names.
    pub payload: Vec<u8>,
}

impl Packet {
    /// A packet that answers this one with `payload`, on the same virtual
    /// network, with the same protocol type, the same O bit and no
    /// options. Some peers want options echoed back: AWS Gateway Load
    /// Balancer, for one, drops returned traffic that lacks its flow
    /// cookie. To keep every option, build the reply from a copy of the
    /// header, `Packet { header: self.header.clone(), payload }`, which
    /// writes whenever this packet does.
    pub fn reply(&self, payload: Vec<u8>) -> Packet {
        let header =
            Header { control: self.header.control, protocol: self.header.protocol, vni: self.header.vni, options: Vec::new() };
        Packet { header, payload }
    }
}

impl Wire for Packet {
    type ParseError = GeneveError;
    type WriteError = GeneveError;

    /// Reads a whole datagram and copies the payload after the header.
    /// Refuses an invalid header or a datagram above [`MAX_DATAGRAM`].
    fn parse(b: &[u8]) -> Result<Self, GeneveError> {
        let (header, payload) = Header::split(b)?;
        Ok(Packet { header, payload: payload.to_vec() })
    }

    /// Appends a datagram after [`Header::check`]. Refuses a datagram above
    /// [`MAX_DATAGRAM`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), GeneveError> {
        self.header.check()?;
        let total = self.header.len().saturating_add(self.payload.len());
        if total > MAX_DATAGRAM {
            return Err(GeneveError::TooLong);
        }
        out.reserve(total);
        self.header.write(out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Wire for Header {
    type ParseError = GeneveError;
    type WriteError = GeneveError;

    /// Reads a standalone header. Refuses truncation, invalid options,
    /// an unsupported version, and bytes after the header.
    fn parse(b: &[u8]) -> Result<Self, GeneveError> {
        let (header, used) = Self::parse_prefix(b)?.ok_or(GeneveError::Truncated)?;
        if used != b.len() {
            return Err(GeneveError::Trailing { remaining: b.len() - used });
        }
        Ok(header)
    }

    /// Appends the header after [`Header::check`]. Refuses a VNI, option
    /// type, option length, or total option size that cannot fit its field.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), GeneveError> {
        self.check()?;
        // check() bounds the options to 252 bytes, so this is at most 63.
        let words = (self.options_len() / 4) as u8;
        out.reserve(self.len());
        out.push((VERSION << 6) | words);
        out.push(if self.control { 0x80 } else { 0 } | if self.critical() { 0x40 } else { 0 });
        out.extend_from_slice(&self.protocol.to_be_bytes());
        out.extend_from_slice(&self.vni.to_be_bytes()[1..]);
        out.push(0);
        for o in &self.options {
            out.extend_from_slice(&o.class.to_be_bytes());
            out.push(o.kind | if o.critical { 0x80 } else { 0 });
            // check() bounds the data to 124 bytes, so this is at most 31.
            out.push((o.data.len() / 4) as u8);
            out.extend_from_slice(&o.data);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Collect, CollectError, Fail, Lcg, contract,
        test_support::{decode_all, mutate},
    };

    fn collect(b: &[u8]) -> Result<Packet, GeneveError> {
        let make = || Collect::<Packet>::new(MAX_DATAGRAM);
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_DATAGRAM + 1));
        contract::check_wire::<Packet>(b);
        let parsed = Packet::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_DATAGRAM {
            assert_eq!(failure, parsed.clone().err().map(|e| Fail::Protocol(CollectError::Parse(e))));
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert_eq!(failure, Some(Fail::Protocol(CollectError::TooLong { limit: MAX_DATAGRAM })));
        }
        parsed
    }

    fn opt(class: u16, kind: u8, critical: bool, data: &[u8]) -> GeneveOption {
        GeneveOption { class, kind, critical, data: data.to_vec() }
    }

    fn header(options: Vec<GeneveOption>) -> Header {
        Header { control: false, protocol: protocol::TRANSPARENT_ETHERNET_BRIDGING, vni: 0x123456, options }
    }

    // The layouts of RFC 8926, sections 3.4 and 3.5.

    #[test]
    fn header_without_options() {
        // Ver 0, Opt Len 0, no flags, Transparent Ethernet Bridging,
        // VNI 0x123456, reserved byte 0, then the inner frame.
        let b = [0x00, 0x00, 0x65, 0x58, 0x12, 0x34, 0x56, 0x00, 0xde, 0xad];
        let p = Packet::parse(&b).unwrap();
        assert_eq!(p.header, header(vec![]));
        assert_eq!(p.payload, [0xde, 0xad]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(p.header.len(), BASE_HEADER_LEN);
    }

    #[test]
    fn header_with_options() {
        // Two options: class 0x0102 type 3 with 4 bytes, and class 0xffff
        // type 0x7f, critical, with none. Opt Len is (8 + 4) / 4 = 3.
        let b = [
            0x03, 0xc0, 0x08, 0x00, 0x00, 0x00, 0x2a, 0x00, // fixed header
            0x01, 0x02, 0x03, 0x01, 1, 2, 3, 4, // first option
            0xff, 0xff, 0xff, 0x00, // second option
            0x45, // payload
        ];
        let p = Packet::parse(&b).unwrap();
        assert!(p.header.control);
        assert_eq!(p.header.protocol, protocol::IPV4);
        assert_eq!(p.header.vni, 42);
        assert_eq!(p.header.options, vec![opt(0x0102, 3, false, &[1, 2, 3, 4]), opt(0xffff, 0x7f, true, &[])]);
        assert!(p.header.critical());
        assert_eq!(p.header.option(0xffff, 0x7f), Some(&p.header.options[1]));
        assert_eq!(p.header.option(0xffff, 0x7e), None);
        assert_eq!(p.payload, [0x45]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(p.header.len(), 20);
    }

    #[test]
    fn reserved_bits_are_ignored_and_written_as_zero() {
        // Reserved bits in the flags byte, the last header byte and the
        // option's R bits.
        let b = [0x01, 0x3f, 0x86, 0xdd, 0, 0, 1, 0xff, 0x00, 0x01, 0x05, 0xe0];
        let p = Packet::parse(&b).unwrap();
        assert_eq!(p.header.options, vec![opt(1, 5, false, &[])]);
        assert_eq!(p.header.vni, 1);
        assert_eq!(p.to_bytes().unwrap(), [0x01, 0x00, 0x86, 0xdd, 0, 0, 1, 0, 0x00, 0x01, 0x05, 0x00]);
    }

    #[test]
    fn largest_header() {
        // Options of 4 + 124 and 4 + 120 bytes fill the 252 exactly, and
        // the payload fills the rest of the datagram.
        let h = header(vec![opt(1, 1, false, &[7; 124]), opt(2, 2, true, &[8; 120])]);
        assert_eq!(h.options_len(), MAX_OPTIONS_LEN);
        let p = Packet { header: h, payload: vec![9; MAX_DATAGRAM - MAX_HEADER_LEN] };
        let b = p.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_DATAGRAM);
        assert_eq!(b[0], 63);
        assert_eq!(Packet::parse(&b).unwrap(), p);
        assert_eq!(collect(&b).unwrap(), p);
    }

    #[test]
    fn split_hands_back_the_payload() {
        let b = [0, 0, 0x65, 0x58, 0, 0, 5, 0, 1, 2, 3];
        let (h, payload) = Header::split(&b).unwrap();
        assert_eq!(h.vni, 5);
        assert_eq!(payload, [1, 2, 3]);
        // A header with nothing after it.
        let (_, payload) = Header::split(&b[..8]).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn reply_keeps_network_and_protocol() {
        let mut p = Packet { header: header(vec![opt(1, 1, true, &[])]), payload: vec![1] };
        p.header.control = true;
        let r = p.reply(vec![2, 3]);
        assert_eq!(r.header.vni, p.header.vni);
        assert_eq!(r.header.protocol, p.header.protocol);
        assert!(r.header.control);
        assert!(r.header.options.is_empty());
        assert_eq!(Packet::parse(&r.to_bytes().unwrap()).unwrap(), r);
    }

    // Error paths when reading.

    #[test]
    fn bad_version() {
        for v in 1..4u8 {
            let b = [v << 6, 0, 0x65, 0x58, 0, 0, 0, 0];
            assert_eq!(Packet::parse(&b), Err(GeneveError::Version(v)));
            // Known from the first byte.
            assert_eq!(Header::parse_prefix(&b[..1]), Err(GeneveError::Version(v)));
        }
    }

    #[test]
    fn option_overrun() {
        // Opt Len 1 word, but the option says it has 1 word of data.
        let b = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0x01, 0, 0, 0, 0];
        assert_eq!(Packet::parse(&b), Err(GeneveError::OptionOverrun(8)));
        // Known from the option's header, before its data.
        assert_eq!(Header::parse_prefix(&b[..12]), Err(GeneveError::OptionOverrun(8)));
        // The second option overruns.
        let b = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0x1f];
        assert_eq!(Packet::parse(&b), Err(GeneveError::OptionOverrun(12)));
    }

    #[test]
    fn critical_bit_must_match() {
        // A critical option with the C bit clear.
        let b = [0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, 0x81, 0];
        assert_eq!(Packet::parse(&b), Err(GeneveError::CriticalBit(false)));
        // The C bit with no critical option.
        let b = [0x01, 0x40, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0];
        assert_eq!(Packet::parse(&b), Err(GeneveError::CriticalBit(true)));
        // The C bit with no options at all, known from the second byte.
        let b = [0x00, 0x40, 0, 0, 0, 0, 0, 0];
        assert_eq!(Packet::parse(&b), Err(GeneveError::CriticalBit(true)));
        assert_eq!(Header::parse_prefix(&b[..2]), Err(GeneveError::CriticalBit(true)));
        assert!(GeneveError::CriticalBit(true).to_string().contains("C bit"));
    }

    #[test]
    fn critical_option_without_c_bit_shows_at_its_header() {
        // Opt Len 2 words and the C bit clear. The first option header is
        // critical, so the error shows before the second option comes.
        let b = [0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, 0x81, 0, 0, 1, 0x01, 0];
        assert_eq!(Header::parse_prefix(&b[..12]), Err(GeneveError::CriticalBit(false)));
        assert_eq!(Packet::parse(&b), Err(GeneveError::CriticalBit(false)));
        // Even when a later option overruns, the earlier error stands.
        let b = [0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, 0x81, 0, 0, 1, 0x01, 1];
        assert_eq!(Packet::parse(&b), Err(GeneveError::CriticalBit(false)));
        assert_eq!(collect(&b), Err(GeneveError::CriticalBit(false)));
    }

    /// Every prefix of `b` reads as incomplete or as the error the whole
    /// gives.
    fn check_prefixes(b: &[u8]) {
        let whole = Header::parse_prefix(b);
        for n in 0..=b.len() {
            match Header::parse_prefix(&b[..n]) {
                Ok(None) => {}
                Ok(Some(_)) => assert!(whole.as_ref().is_ok_and(|w| w.is_some()), "prefix {n}"),
                Err(e) => assert_eq!(whole, Err(e), "prefix {n}"),
            }
        }
    }

    #[test]
    fn prefixes_agree_with_the_whole() {
        let mut rng = Lcg::new(0xc0de);
        for _ in 0..3_000 {
            let mut b = random_packet(&mut rng).to_bytes().unwrap();
            if !b.is_empty() {
                let at = rng.index(b.len().min(40));
                b[at] ^= 1 << rng.index(8);
                b[0] &= 0x3f;
            }
            check_prefixes(&b);
        }
    }

    #[test]
    fn too_long() {
        let mut b = vec![0, 0, 0x65, 0x58, 0, 0, 0, 0];
        b.resize(MAX_DATAGRAM + 1, 0);
        assert_eq!(Packet::parse(&b), Err(GeneveError::TooLong));
        assert_eq!(collect(&b), Err(GeneveError::TooLong));
        b.pop();
        assert!(Packet::parse(&b).is_ok());
    }

    #[test]
    fn every_truncated_prefix() {
        let p = Packet {
            header: header(vec![opt(0x0102, 3, false, &[1, 2, 3, 4]), opt(0x0103, 4, true, &[5; 8])]),
            payload: vec![0xaa; 3],
        };
        let b = p.to_bytes().unwrap();
        let header_len = p.header.len();
        for n in 0..header_len {
            assert_eq!(Header::parse_prefix(&b[..n]), Ok(None), "prefix {n}");
            assert_eq!(Packet::parse(&b[..n]), Err(GeneveError::Truncated), "prefix {n}");
            assert_eq!(Header::split(&b[..n]), Err(GeneveError::Truncated));
            assert_eq!(collect(&b[..n]), Err(GeneveError::Truncated));
        }
        // From the end of the header on, the rest is payload.
        for n in header_len..=b.len() {
            let q = Packet::parse(&b[..n]).unwrap();
            assert_eq!(q.header, p.header);
            assert_eq!(q.payload, &b[header_len..n]);
            assert_eq!(collect(&b[..n]), Ok(q));
        }
    }

    #[test]
    fn header_prefix_and_stream_boundary() {
        let p = Packet { header: header(vec![opt(9, 9, false, &[1; 4])]), payload: vec![3; 100] };
        let b = p.to_bytes().unwrap();
        assert_eq!(Header::parse_prefix(&b[..p.header.len() - 1]), Ok(None));
        assert_eq!(Header::parse_prefix(&b[..p.header.len()]), Ok(Some((p.header.clone(), p.header.len()))));
        assert_eq!(collect(&b), Ok(p));
        assert_eq!(collect(&[]), Err(GeneveError::Truncated));
    }

    // Error paths when writing.

    #[test]
    fn writer_refuses_what_readers_would() {
        let mut h = header(vec![]);
        h.vni = MAX_VNI + 1;
        assert_eq!(h.to_bytes(), Err(GeneveError::Vni(MAX_VNI + 1)));
        h.vni = MAX_VNI;
        assert!(h.to_bytes().is_ok());

        let h = header(vec![opt(1, 0x80, false, &[])]);
        assert_eq!(h.to_bytes(), Err(GeneveError::OptionType(0x80)));

        let h = header(vec![opt(1, 1, false, &[1, 2, 3])]);
        assert_eq!(h.to_bytes(), Err(GeneveError::OptionData(3)));
        let h = header(vec![opt(1, 1, false, &[0; 128])]);
        assert_eq!(h.to_bytes(), Err(GeneveError::OptionData(128)));

        // Two full options are 256 bytes, over the 252 a header holds.
        let h = header(vec![opt(1, 1, false, &[0; 124]), opt(1, 2, false, &[0; 124])]);
        assert_eq!(h.to_bytes(), Err(GeneveError::OptionsLength(256)));
        assert_eq!(Packet { header: h, payload: vec![] }.to_bytes(), Err(GeneveError::OptionsLength(256)));

        let p = Packet { header: header(vec![opt(1, 1, false, &[0; 4])]), payload: vec![0; MAX_PAYLOAD - 7] };
        assert_eq!(p.to_bytes(), Err(GeneveError::TooLong));

        // On an error, write leaves the buffer alone.
        let mut out = vec![1, 2];
        let h = header(vec![opt(1, 1, false, &[1])]);
        assert_eq!(h.write(&mut out), Err(GeneveError::OptionData(1)));
        assert_eq!(out, [1, 2]);
    }

    #[test]
    fn most_options_a_header_holds() {
        // 63 empty options fill the 252 bytes; a 64th is one word over.
        let mut h = header((0..63).map(|i| opt(i, 1, i % 2 == 0, &[])).collect());
        let b = h.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_HEADER_LEN);
        assert_eq!(Header::parse_prefix(&b), Ok(Some((h.clone(), MAX_HEADER_LEN))));
        h.options.push(opt(63, 1, false, &[]));
        let mut out = vec![1, 2];
        assert_eq!(h.write(&mut out), Err(GeneveError::OptionsLength(256)));
        assert_eq!(out, [1, 2]);
    }

    #[test]
    fn reply_can_keep_the_options() {
        // An AWS Gateway Load Balancer packet with its flow cookie (class
        // 0x0108, type 3), answered with every option kept.
        let p = Packet { header: header(vec![opt(0x0108, 3, false, &[1, 2, 3, 4])]), payload: vec![1] };
        let r = Packet { header: p.header.clone(), payload: vec![2] };
        assert_eq!(Packet::parse(&r.to_bytes().unwrap()).unwrap().header.option(0x0108, 3), p.header.option(0x0108, 3));
    }

    #[test]
    fn fuzz_writer_on_any_values() {
        // Headers built from any field values, valid or not: the writer
        // either writes bytes that read back the same, or refuses and
        // leaves the buffer alone.
        let mut rng = Lcg::new(0xabcd);
        for _ in 0..5_000 {
            let mut options = Vec::new();
            for _ in 0..rng.index(70) {
                let n = if rng.index(4) == 0 { rng.index(140) } else { rng.index(8) * 4 };
                let data = rng.bytes(n);
                options.push(GeneveOption {
                    class: rng.next() as u16,
                    kind: rng.next() as u8,
                    critical: !rng.coin(),
                    data,
                });
            }
            let vni = if rng.index(4) == 0 { rng.next() as u32 } else { (rng.next() as u32) & MAX_VNI };
            let n = rng.index(64);
            let p = Packet {
                header: Header { control: !rng.coin(), protocol: rng.next() as u16, vni, options },
                payload: rng.bytes(n),
            };
            let mut out = vec![0xee];
            match p.write(&mut out) {
                Ok(()) => assert_eq!(Packet::parse(&out[1..]), Ok(p)),
                Err(e) => {
                    assert_eq!(out, [0xee]);
                    assert_eq!(p.header.check().err().unwrap_or(GeneveError::TooLong), e);
                }
            }
        }
    }

    #[test]
    fn packet_write_appends() {
        let p = Packet { header: header(vec![opt(3, 4, true, &[1; 8])]), payload: vec![5; 3] };
        let mut out = vec![0xee];
        p.write(&mut out).unwrap();
        assert_eq!(out[0], 0xee);
        assert_eq!(&out[1..], &p.to_bytes().unwrap()[..]);
        assert_eq!(Packet::parse(&out[1..]), Ok(p));
        // On an error, the buffer is left alone.
        let big = Packet { header: header(vec![]), payload: vec![0; MAX_PAYLOAD + 1] };
        let mut out = vec![1, 2];
        assert_eq!(big.write(&mut out), Err(GeneveError::TooLong));
        assert_eq!(out, [1, 2]);
        let bad = Packet { header: header(vec![opt(1, 1, false, &[1])]), payload: vec![] };
        assert_eq!(bad.write(&mut out), Err(GeneveError::OptionData(1)));
        assert_eq!(out, [1, 2]);
    }

    #[test]
    fn default_packet_writes_and_reads_back() {
        let p = Packet::default();
        let b = p.to_bytes().unwrap();
        assert_eq!(b, [0; BASE_HEADER_LEN]);
        assert_eq!(Packet::parse(&b), Ok(p));
    }

    #[test]
    fn huge_push_is_bounded() {
        let mut b = vec![0, 0, 0x65, 0x58, 0, 0, 0, 0];
        b.resize(3 * MAX_DATAGRAM, 0);
        assert_eq!(collect(&b), Err(GeneveError::TooLong));
    }

    #[test]
    fn errors_display() {
        let all = [
            GeneveError::Truncated,
            GeneveError::Trailing { remaining: 1 },
            GeneveError::Version(1),
            GeneveError::OptionOverrun(8),
            GeneveError::CriticalBit(true),
            GeneveError::CriticalBit(false),
            GeneveError::TooLong,
            GeneveError::Vni(1 << 24),
            GeneveError::OptionType(0x80),
            GeneveError::OptionData(3),
            GeneveError::OptionsLength(256),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
    }

    /// A random packet the writer accepts.
    fn random_packet(rng: &mut Lcg) -> Packet {
        let mut options = Vec::new();
        let mut room = MAX_OPTIONS_LEN;
        for _ in 0..rng.index(6) {
            let words = rng.index(32).min((room - OPTION_HEADER_LEN) / 4);
            let mut data = rng.bytes(words * 4);
            data.truncate(data.len() / 4 * 4);
            room -= OPTION_HEADER_LEN + data.len();
            let class = rng.next() as u16;
            let kind = rng.index(128) as u8;
            let critical = rng.index(4) == 0;
            options.push(GeneveOption { class, kind, critical, data });
            if room < OPTION_HEADER_LEN {
                break;
            }
        }
        let n = rng.index(64);
        Packet {
            header: Header {
                control: !rng.coin(),
                protocol: rng.next() as u16,
                vni: (rng.next() as u32) & MAX_VNI,
                options,
            },
            payload: rng.bytes(n),
        }
    }

    fn check_bytes(data: &[u8]) {
        let parsed = Packet::parse(data);
        if let Ok(p) = &parsed {
            // A packet read can be written, and reads back the same.
            let out = p.to_bytes().unwrap();
            assert!(out.len() <= data.len());
            assert_eq!(Packet::parse(&out).as_ref(), Ok(p));
            assert_eq!(Header::split(data).unwrap().1, &p.payload[..]);
        }
        assert_eq!(collect(data), parsed);
    }

    #[test]
    fn fuzz_round_trips() {
        let mut rng = Lcg::new(0x6081);
        for _ in 0..5_000 {
            let p = random_packet(&mut rng);
            let b = p.to_bytes().unwrap();
            assert_eq!(b.len(), p.header.len() + p.payload.len());
            assert_eq!(Packet::parse(&b), Ok(p.clone()));
            assert_eq!(collect(&b), Ok(p));
        }
    }

    #[test]
    fn fuzz_parsers() {
        let mut rng = Lcg::new(0x5eed);
        let mut seeds: Vec<Vec<u8>> = Vec::new();
        for _ in 0..20 {
            seeds.push(random_packet(&mut rng).to_bytes().unwrap());
        }
        for i in 0..20_000 {
            let mut data = if i % 4 == 0 {
                let n = rng.index(80);
                rng.bytes(n)
            } else {
                seeds[rng.index(seeds.len())].clone()
            };
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut data);
            }
            // Keep the version 0 most of the time, so mutations reach the
            // options.
            if i % 8 != 0
                && let Some(b) = data.first_mut() {
                    *b &= 0x3f;
                }
            check_bytes(&data);
        }
    }
}
