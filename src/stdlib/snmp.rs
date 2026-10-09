//! SNMP v1 and v2c: reading and writing messages, with no I/O.
//!
//! `Message` implements `Wire` and supports `codec::Frames<Message>` stream
//! decoding for SNMP v1 and v2c. There is no SNMPv3, manager or agent session,
//! MIB store, `Service`, or live transport.
//!
//! SNMP is how network equipment is watched and managed. A device runs an
//! agent that holds a tree of named values (the MIB): uptime, interface
//! counters, a printer's toner level. A manager asks for values by name
//! with Get, GetNext and GetBulk, changes them with Set, and the agent
//! sends traps when something happens. Each name is an object identifier
//! such as `1.3.6.1.2.1.1.1.0` (sysDescr.0). Messages are BER-encoded
//! ASN.1 and usually travel in UDP datagrams, requests to port 161 and
//! traps to port 162. This module follows RFC 1157 (version 1), RFC 3416
//! (the version 2 PDUs), RFC 1905 and RFC 3417 (the version 2 value
//! types) and the parts of RFC 3584 that say how the two versions meet.
//! A message in any other version, such as SNMPv3, is reported as
//! [`Error::Unsupported`].
//!
//! Nothing here reads a socket. A world that plays an agent hands each
//! datagram it receives to [`Message::parse`], answers the [`Pdu`] inside
//! from its own MIB, and sends the bytes of [`Message::response`] back.
//! Which objects exist, what they hold, and which communities may read or
//! write them is up to world code. Over TCP (RFC 3430), [`Stream<codec::Frames<Message>>`](fictionet::stdlib::codec::Stream)
//! splits the stream into messages first. Body errors are items; invalid
//! BER envelopes end the stream.
//!
//! Every reader checks lengths, tags and ranges, because the agent can
//! send any bytes it likes. Lengths are bounded by [`MAX_MESSAGE`],
//! nesting by [`MAX_DEPTH`] and object identifiers by [`MAX_OID_ARCS`].
//! Writers refuse a message longer than [`MAX_MESSAGE`].
//! [`Element`] reads and writes BER that is not SNMP, under the same
//! limits.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::snmp::{Message, Oid, Pdu, Value, VarBind};
//!
//! // A version 2c GetRequest for sysDescr.0, community "public".
//! let datagram = [
//!     0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c, 0x02, 0x04,
//!     0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b,
//!     0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
//! ];
//! let request = Message::parse(&datagram).unwrap();
//! assert_eq!(request.community, b"public");
//!
//! let sys_descr: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
//! let Pdu::Get(get) = &request.pdu else { panic!("not a GetRequest") };
//! let answers = get
//!     .bindings
//!     .iter()
//!     .map(|b| match b.name == sys_descr {
//!         true => VarBind::new(b.name.clone(), Value::OctetString(b"pump controller".to_vec())),
//!         false => VarBind::new(b.name.clone(), Value::NoSuchObject),
//!     })
//!     .collect();
//! let reply = request.response(answers).unwrap().to_bytes().unwrap();
//! assert_eq!(&reply[..4], [0x30, 0x38, 0x02, 0x01]);
//! let back = Message::parse(&reply).unwrap();
//! assert_eq!(back.pdu.request_id(), Some(0x12345678));
//! assert_eq!(back.pdu.bindings()[0].value, Value::OctetString(b"pump controller".to_vec()));
//! ```

use fictionet::stdlib::asn1;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use std::fmt;
use std::str::FromStr;

use fictionet::stdlib::codec::Wire;

/// The UDP port agents listen on for requests.
pub const PORT: u16 = 161;
/// The UDP port managers listen on for traps and informs.
pub const TRAP_PORT: u16 = 162;
/// The longest message, in bytes, this module reads or writes, headers
/// included. It also bounds the content of each [`Element`] and each
/// value. Over UDP the usable size is smaller: 65,507 bytes over IPv4 and
/// 65,527 over IPv6. The size to send is the caller's to choose; see
/// [`Message::encoded_len`].
pub const MAX_MESSAGE: usize = 65_535;
/// The deepest nesting of constructed elements [`Element`] reads or
/// writes. An SNMP message nests 4 deep: the message, the PDU, the
/// binding list and each binding.
pub const MAX_DEPTH: usize = 16;
/// The most arcs an object identifier may have (RFC 2578, section 3.5).
pub const MAX_OID_ARCS: usize = 128;

/// The object identifier sysUpTime.0, the first binding of every version 2
/// trap and inform.
pub const SYS_UP_TIME_0: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
/// The object identifier snmpTrapOID.0, the second binding of every
/// version 2 trap and inform. Its value names the trap.
pub const SNMP_TRAP_OID_0: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// BER tags this module reads and writes.
pub mod tag {
    /// INTEGER tag.
    pub const INTEGER: u8 = 0x02;
    /// OCTET STRING tag.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL tag.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER tag.
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    /// SEQUENCE tag.
    pub const SEQUENCE: u8 = 0x30;
    /// IpAddress tag.
    pub const IP_ADDRESS: u8 = 0x40;
    /// Counter32 tag.
    pub const COUNTER32: u8 = 0x41;
    /// Gauge32 tag.
    pub const GAUGE32: u8 = 0x42;
    /// TimeTicks tag.
    pub const TIME_TICKS: u8 = 0x43;
    /// Opaque tag.
    pub const OPAQUE: u8 = 0x44;
    /// Counter64 tag.
    pub const COUNTER64: u8 = 0x46;
    /// noSuchObject tag.
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    /// noSuchInstance tag.
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    /// endOfMibView tag.
    pub const END_OF_MIB_VIEW: u8 = 0x82;
    /// GetRequest-PDU tag.
    pub const GET_REQUEST: u8 = 0xa0;
    /// GetNextRequest-PDU tag.
    pub const GET_NEXT_REQUEST: u8 = 0xa1;
    /// Response-PDU tag.
    pub const RESPONSE: u8 = 0xa2;
    /// SetRequest-PDU tag.
    pub const SET_REQUEST: u8 = 0xa3;
    /// Trap-PDU (SNMP v1) tag.
    pub const TRAP_V1: u8 = 0xa4;
    /// GetBulkRequest-PDU tag.
    pub const GET_BULK_REQUEST: u8 = 0xa5;
    /// InformRequest-PDU tag.
    pub const INFORM_REQUEST: u8 = 0xa6;
    /// SNMPv2-Trap-PDU tag.
    pub const TRAP_V2: u8 = 0xa7;
    /// Report-PDU tag.
    pub const REPORT: u8 = 0xa8;
    /// Set in a tag whose content is more elements.
    pub const CONSTRUCTED: u8 = 0x20;
    /// The low bits of a tag that say its number follows in more bytes.
    /// This module does not read such tags; SNMP never uses them.
    pub const HIGH_NUMBER: u8 = 0x1f;
}

/// Why bytes are not an SNMP message, or not BER this module reads, or
/// why arcs or text are not an object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes end before an element does.
    Truncated,
    /// Bytes follow the message, or follow the last field of a sequence.
    TrailingBytes,
    /// An element has a tag that does not belong where it is.
    UnexpectedTag(u8),
    /// A length is indefinite, or uses the reserved first byte 0xff.
    Length,
    /// A length, or a whole message, is longer than [`MAX_MESSAGE`].
    TooLong(usize),
    /// Constructed elements nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// An integer is empty or out of range for its type.
    Integer,
    /// An object identifier's encoding is not valid.
    Oid,
    /// The content of a value of the given tag is the wrong size.
    Value(u8),
    /// The version field names a version other than 1 or 2c. SNMPv3
    /// messages carry 3.
    Unsupported(i32),
    /// Fewer than 2 arcs in an object identifier.
    TooFewArcs,
    /// More than [`MAX_OID_ARCS`] arcs in an object identifier.
    TooManyArcs,
    /// The first arc is above 2, or the second is 40 or more under a
    /// first arc of 0 or 1.
    FirstArcs,
    /// Text that is not a number from 0 to 4294967295 between the dots.
    OidText,
}

fictionet::error_display!(Error, f, {
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
    Error::Truncated => f.write_str("the bytes end inside an element"),
    Error::TrailingBytes => f.write_str("bytes follow the last element"),
    Error::UnexpectedTag(t) => write!(f, "unexpected tag 0x{t:02x}"),
    Error::Length => f.write_str("indefinite or reserved length"),
    Error::TooLong(n) => write!(f, "length {n}, over the limit of {MAX_MESSAGE}"),
    Error::TooDeep => write!(f, "elements nest deeper than {MAX_DEPTH}"),
    Error::Integer => f.write_str("integer empty or out of range"),
    Error::Oid => f.write_str("malformed object identifier"),
    Error::Value(t) => write!(f, "wrong size for a value of tag 0x{t:02x}"),
    Error::Unsupported(v) => write!(f, "SNMP version field {v}, not 0 (v1) or 1 (v2c)"),
    Error::TooFewArcs => f.write_str("an object identifier needs at least 2 arcs"),
    Error::TooManyArcs => write!(f, "more than {MAX_OID_ARCS} arcs"),
    Error::FirstArcs => f.write_str("first two arcs out of range"),
    Error::OidText => f.write_str("not dotted decimal numbers"),
});

// ---------------------------------------------------------------------------
// BER framing.

/// The header of a BER element: its tag and where its content lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The tag byte.
    pub tag: u8,
    /// How many bytes the tag and length take.
    pub header_len: usize,
    /// How many bytes of content follow the header.
    pub content_len: usize,
}

impl Header {
    /// Reads the header at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one. Tags in the multi-byte form, indefinite
    /// lengths and lengths over [`MAX_MESSAGE`] are errors. A long-form
    /// length may use more bytes than it needs (RFC 3417, section 8).
    pub fn parse(b: &[u8]) -> Result<Option<Header>, Error> {
        let Some(&tag) = b.first() else {
            return Ok(None);
        };
        if tag & tag::HIGH_NUMBER == tag::HIGH_NUMBER {
            return Err(Error::UnexpectedTag(tag));
        }
        let Some(&first) = b.get(1) else {
            return Ok(None);
        };
        let (content_len, header_len) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            // 0x80 is the indefinite form, and X.690 (8.1.3.5) reserves 0xff.
            let n = usize::from(first & 0x7f);
            if n == 0 || n == 0x7f {
                return Err(Error::Length);
            }
            let Some(bytes) = b.get(2..2 + n) else {
                return Ok(None);
            };
            let len = bytes.iter().fold(0usize, |acc, &x| {
                acc.saturating_mul(256).saturating_add(usize::from(x))
            });
            (len, 2 + n)
        };
        if content_len > MAX_MESSAGE {
            return Err(Error::TooLong(content_len));
        }
        Ok(Some(Header {
            tag,
            header_len,
            content_len,
        }))
    }

    /// The length of the whole element: header and content. A header
    /// built by hand with lengths whose sum overflows gives `usize::MAX`.
    pub fn total_len(&self) -> usize {
        self.header_len.saturating_add(self.content_len)
    }
}

/// Reads elements one after another from a slice, which must hold them
/// whole.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b }
    }

    /// The next element's tag and content.
    fn next(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let h = Header::parse(self.b)?.ok_or(Error::Truncated)?;
        let content = self
            .b
            .get(h.header_len..h.total_len())
            .ok_or(Error::Truncated)?;
        self.b = &self.b[h.total_len()..];
        Ok((h.tag, content))
    }

    /// The next element's content, which must have tag `t`.
    fn expect(&mut self, t: u8) -> Result<&'a [u8], Error> {
        match self.next()? {
            (found, content) if found == t => Ok(content),
            (found, _) => Err(Error::UnexpectedTag(found)),
        }
    }

    fn int(&mut self) -> Result<i32, Error> {
        let n = read_int(self.expect(tag::INTEGER)?)?;
        i32::try_from(n).map_err(|_| Error::Integer)
    }

    fn end(&self) -> Result<(), Error> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

/// How many bytes an element takes whose content is `len` bytes long,
/// or `usize::MAX` if that does not fit in a `usize`.
fn tlv_len(len: usize) -> usize {
    let len_len = if len < 0x80 {
        1
    } else {
        1 + (usize::BITS - len.leading_zeros()).div_ceil(8) as usize
    };
    len.saturating_add(1 + len_len)
}

fn write_tlv(out: &mut Vec<u8>, t: u8, content: &[u8]) {
    out.push(t);
    asn1::encode_length(content.len(), out);
    out.extend_from_slice(content);
}

/// An integer's content as a number. Redundant leading sign bytes are
/// allowed, so a value written by another encoder is still read.
fn read_int(c: &[u8]) -> Result<i128, Error> {
    if c.is_empty() {
        return Err(Error::Integer);
    }
    let bytes = asn1::minimal_twos(c);
    if bytes.len() > 9 {
        return Err(Error::Integer);
    }
    asn1::Integer::from_bytes(bytes)
        .ok()
        .and_then(|n| n.to_i128())
        .ok_or(Error::Integer)
}

/// The minimal two's complement content of an integer.
#[cfg(test)]
fn int_content(v: i128) -> Vec<u8> {
    asn1::minimal_twos(&v.to_be_bytes()).to_vec()
}

fn write_int(out: &mut Vec<u8>, t: u8, v: i128) {
    write_tlv(out, t, asn1::minimal_twos(&v.to_be_bytes()));
}

/// The length of a whole message at the start of `b`, for splitting a
/// stream. It returns `Ok(None)` if the header has not all come, and an
/// error if `b` does not start a message or the message would be longer
/// than [`MAX_MESSAGE`]. It does not look inside the message.
pub fn message_len(b: &[u8]) -> Result<Option<usize>, Error> {
    if let Some(&t) = b.first()
        && t != tag::SEQUENCE
    {
        return Err(Error::UnexpectedTag(t));
    }
    let Some(h) = Header::parse(b)? else {
        return Ok(None);
    };
    if h.total_len() > MAX_MESSAGE {
        return Err(Error::TooLong(h.total_len()));
    }
    Ok(Some(h.total_len()))
}

/// One BER element of any kind, with its content read as far as BER
/// goes. It is for reading things inside SNMP that are BER themselves,
/// such as the content of an [`Value::Opaque`], and for looking at
/// messages this module does not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Element {
    /// An element whose tag has the constructed bit clear.
    Primitive {
        /// The tag byte.
        tag: u8,
        /// The content bytes.
        content: Vec<u8>,
    },
    /// An element whose tag has the constructed bit set, and the elements
    /// it holds.
    Constructed {
        /// The tag byte.
        tag: u8,
        /// The elements inside, in order.
        children: Vec<Element>,
    },
}

impl Element {
    /// The tag byte.
    pub fn tag(&self) -> u8 {
        match self {
            Element::Primitive { tag, .. } | Element::Constructed { tag, .. } => *tag,
        }
    }

    fn parse_at(b: &[u8], depth: usize) -> Result<(Element, usize), Error> {
        let h = Header::parse(b)?.ok_or(Error::Truncated)?;
        let content = b.get(h.header_len..h.total_len()).ok_or(Error::Truncated)?;
        if h.tag & tag::CONSTRUCTED == 0 {
            return Ok((
                Element::Primitive {
                    tag: h.tag,
                    content: content.to_vec(),
                },
                h.total_len(),
            ));
        }
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut children = Vec::new();
        let mut rest = content;
        while !rest.is_empty() {
            let (child, used) = Element::parse_at(rest, depth + 1)?;
            children.push(child);
            rest = &rest[used..];
        }
        Ok((
            Element::Constructed {
                tag: h.tag,
                children,
            },
            h.total_len(),
        ))
    }

    fn write_at(&self, out: &mut Vec<u8>, depth: usize) -> Result<(), Error> {
        let (t, constructed) = match self {
            Element::Primitive { tag, .. } => (*tag, false),
            Element::Constructed { tag, .. } => (*tag, true),
        };
        if t & tag::HIGH_NUMBER == tag::HIGH_NUMBER || (t & tag::CONSTRUCTED != 0) != constructed {
            return Err(Error::UnexpectedTag(t));
        }
        let content = match self {
            Element::Primitive { content, .. } => {
                if content.len() > MAX_MESSAGE {
                    return Err(Error::TooLong(content.len()));
                }
                content.clone()
            }
            Element::Constructed { children, .. } => {
                if depth > MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                let mut content = Vec::new();
                for c in children {
                    c.write_at(&mut content, depth + 1)?;
                    if content.len() > MAX_MESSAGE {
                        return Err(Error::TooLong(content.len()));
                    }
                }
                content
            }
        };
        if content.len() > MAX_MESSAGE {
            return Err(Error::TooLong(content.len()));
        }
        write_tlv(out, t, &content);
        Ok(())
    }
}

impl Wire for Element {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one BER element. Refuses trailing bytes, invalid tags
    /// or lengths, content over [`MAX_MESSAGE`], and nesting over [`MAX_DEPTH`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (element, used) = Self::parse_at(bytes, 1)?;
        if used != bytes.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(element)
    }

    /// Appends one element. Refuses mismatched tags, oversized content,
    /// and excessive nesting without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bytes = Vec::new();
        self.write_at(&mut bytes, 1)
            .map_err(|_| Error::Unwritable)?;
        out.try_reserve(bytes.len())
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Object identifiers.

/// An object identifier: the name of a MIB object, as a list of numbers
/// (arcs). It always has 2 to [`MAX_OID_ARCS`] arcs, the first 0, 1 or 2,
/// and the second below 40 when the first is 0 or 1, so it can always be
/// written. Ordering is the lexicographic order GetNext walks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(Vec<u32>);

impl Oid {
    /// The object identifier with these arcs, if it is one.
    pub fn from_arcs(arcs: &[u32]) -> Result<Oid, Error> {
        if arcs.len() < 2 {
            return Err(Error::TooFewArcs);
        }
        if arcs.len() > MAX_OID_ARCS {
            return Err(Error::TooManyArcs);
        }
        let ok = match arcs[0] {
            0 | 1 => arcs[1] < 40,
            2 => true,
            _ => false,
        };
        if !ok {
            return Err(Error::FirstArcs);
        }
        Ok(Oid(arcs.to_vec()))
    }

    /// The arcs, first to last.
    pub fn arcs(&self) -> &[u32] {
        &self.0
    }

    /// Whether `prefix`'s arcs start this one's. Every identifier starts
    /// with itself.
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.starts_with(&prefix.0)
    }

    /// This identifier with `arc` added at the end, or `None` if it has
    /// [`MAX_OID_ARCS`] already.
    pub fn child(&self, arc: u32) -> Option<Oid> {
        if self.0.len() >= MAX_OID_ARCS {
            return None;
        }
        let mut arcs = self.0.clone();
        arcs.push(arc);
        Some(Oid(arcs))
    }

    fn content_len(&self) -> usize {
        let first = u64::from(self.0[0]) * 40 + u64::from(self.0[1]);
        std::iter::once(first)
            .chain(self.0[2..].iter().map(|&a| u64::from(a)))
            .map(|v| ((64 - v.leading_zeros()).max(1) as usize).div_ceil(7))
            .sum()
    }
}

impl Wire for Oid {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads BER object identifier content without its tag or length.
    /// Refuses empty, nonminimal, unfinished, oversized, or excess arcs.
    /// Every arc fits 32 bits. The first sub-identifier combines two arcs
    /// and may reach 2^32 - 1 + 80 under a first arc of 2.
    fn parse(content: &[u8]) -> Result<Oid, Error> {
        if content.is_empty() {
            return Err(Error::Oid);
        }
        let mut arcs = Vec::new();
        let mut v: u64 = 0;
        let mut fresh = true;
        for &b in content {
            if fresh && b == 0x80 {
                return Err(Error::Oid);
            }
            let limit = if arcs.is_empty() {
                u64::from(u32::MAX) + 80
            } else {
                u64::from(u32::MAX)
            };
            v = (v << 7) | u64::from(b & 0x7f);
            if v > limit {
                return Err(Error::Oid);
            }
            fresh = b & 0x80 == 0;
            if fresh {
                if arcs.is_empty() {
                    let first = (v / 40).min(2);
                    arcs.push(first as u32);
                    // At most u32::MAX by the limit above.
                    arcs.push((v - 40 * first) as u32);
                } else {
                    arcs.push(v as u32);
                }
                if arcs.len() > MAX_OID_ARCS {
                    return Err(Error::Oid);
                }
                v = 0;
            }
        }
        if !fresh {
            return Err(Error::Oid);
        }
        Ok(Oid(arcs))
    }

    /// Appends BER object identifier content. Construction checks every
    /// arc; this refuses allocation failure without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.try_reserve_exact(self.content_len())
            .map_err(|_| Error::Unwritable)?;
        // The invariant on the first two arcs keeps this below 2^33, which
        // five groups of 7 bits hold.
        let first = u64::from(self.0[0]) * 40 + u64::from(self.0[1]);
        for v in std::iter::once(first).chain(self.0[2..].iter().map(|&a| u64::from(a))) {
            let mut groups = [0u8; 5];
            let mut n = 0;
            let mut x = v;
            loop {
                groups[n] = (x & 0x7f) as u8;
                n += 1;
                x >>= 7;
                if x == 0 {
                    break;
                }
            }
            for i in (0..n).rev() {
                out.push(groups[i] | if i > 0 { 0x80 } else { 0 });
            }
        }
        Ok(())
    }
}

impl fmt::Display for Oid {
    /// Dotted decimal, such as `1.3.6.1.2.1.1.1.0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, a) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{a}")?;
        }
        Ok(())
    }
}

impl FromStr for Oid {
    type Err = Error;

    /// Reads dotted decimal, with or without a leading dot.
    fn from_str(s: &str) -> Result<Oid, Error> {
        let s = s.strip_prefix('.').unwrap_or(s);
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::OidText);
            }
            if arcs.len() >= MAX_OID_ARCS {
                return Err(Error::TooManyArcs);
            }
            arcs.push(part.parse::<u32>().map_err(|_| Error::OidText)?);
        }
        Oid::from_arcs(&arcs)
    }
}

// ---------------------------------------------------------------------------
// Values and bindings.

/// The protocol versions this module reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// SNMPv1 (RFC 1157), version field 0.
    V1,
    /// Community-based SNMPv2 (RFC 1901), version field 1.
    V2c,
}

impl Version {
    /// The version field's value.
    pub fn code(self) -> i32 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
        }
    }

    /// The version for a version field, or [`Error::Unsupported`].
    pub fn from_code(c: i32) -> Result<Version, Error> {
        match c {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2c),
            c => Err(Error::Unsupported(c)),
        }
    }
}

/// The value in a variable binding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// INTEGER, or Integer32: a signed 32-bit number.
    Integer(i32),
    /// OCTET STRING: bytes, often text.
    OctetString(Vec<u8>),
    /// NULL: the value a request puts in each binding.
    Null,
    /// OBJECT IDENTIFIER.
    ObjectIdentifier(Oid),
    /// IpAddress: an IPv4 address.
    IpAddress([u8; 4]),
    /// Counter32: a count that wraps at 2^32.
    Counter32(u32),
    /// Gauge32, also called Unsigned32: a level that goes up and down.
    Gauge32(u32),
    /// TimeTicks: hundredths of a second since some moment.
    TimeTicks(u32),
    /// Opaque: other BER, wrapped as bytes.
    Opaque(Vec<u8>),
    /// Counter64: a count that wraps at 2^64. Version 2 only.
    Counter64(u64),
    /// The agent has no such object. Version 2 only.
    NoSuchObject,
    /// The object exists but has no such instance. Version 2 only.
    NoSuchInstance,
    /// A GetNext or GetBulk walked past the last object. Version 2 only.
    EndOfMibView,
}

impl Value {
    /// The value's BER tag.
    pub fn tag(&self) -> u8 {
        match self {
            Value::Integer(_) => tag::INTEGER,
            Value::OctetString(_) => tag::OCTET_STRING,
            Value::Null => tag::NULL,
            Value::ObjectIdentifier(_) => tag::OBJECT_IDENTIFIER,
            Value::IpAddress(_) => tag::IP_ADDRESS,
            Value::Counter32(_) => tag::COUNTER32,
            Value::Gauge32(_) => tag::GAUGE32,
            Value::TimeTicks(_) => tag::TIME_TICKS,
            Value::Opaque(_) => tag::OPAQUE,
            Value::Counter64(_) => tag::COUNTER64,
            Value::NoSuchObject => tag::NO_SUCH_OBJECT,
            Value::NoSuchInstance => tag::NO_SUCH_INSTANCE,
            Value::EndOfMibView => tag::END_OF_MIB_VIEW,
        }
    }

    /// Whether a message of `version` may carry this value. Version 1 has
    /// no Counter64 and no exception values.
    pub fn allowed_in(&self, version: Version) -> bool {
        version == Version::V2c
            || !matches!(
                self,
                Value::Counter64(_)
                    | Value::NoSuchObject
                    | Value::NoSuchInstance
                    | Value::EndOfMibView
            )
    }

    /// Reads a value from an element's tag and content. Content longer
    /// than [`MAX_MESSAGE`] is [`Error::TooLong`], so it is never copied.
    pub fn from_ber(t: u8, c: &[u8]) -> Result<Value, Error> {
        if c.len() > MAX_MESSAGE {
            return Err(Error::TooLong(c.len()));
        }
        let unsigned = |max: i128| -> Result<i128, Error> {
            let v = read_int(c)?;
            if (0..=max).contains(&v) {
                Ok(v)
            } else {
                Err(Error::Integer)
            }
        };
        let empty = |v: Value| {
            if c.is_empty() {
                Ok(v)
            } else {
                Err(Error::Value(t))
            }
        };
        Ok(match t {
            tag::INTEGER => {
                Value::Integer(i32::try_from(read_int(c)?).map_err(|_| Error::Integer)?)
            }
            tag::OCTET_STRING => Value::OctetString(c.to_vec()),
            tag::NULL => empty(Value::Null)?,
            tag::OBJECT_IDENTIFIER => Value::ObjectIdentifier(Oid::parse(c)?),
            tag::IP_ADDRESS => Value::IpAddress(c.try_into().map_err(|_| Error::Value(t))?),
            tag::COUNTER32 => Value::Counter32(unsigned(u32::MAX.into())? as u32),
            tag::GAUGE32 => Value::Gauge32(unsigned(u32::MAX.into())? as u32),
            tag::TIME_TICKS => Value::TimeTicks(unsigned(u32::MAX.into())? as u32),
            tag::OPAQUE => Value::Opaque(c.to_vec()),
            tag::COUNTER64 => Value::Counter64(unsigned(u64::MAX.into())? as u64),
            tag::NO_SUCH_OBJECT => empty(Value::NoSuchObject)?,
            tag::NO_SUCH_INSTANCE => empty(Value::NoSuchInstance)?,
            tag::END_OF_MIB_VIEW => empty(Value::EndOfMibView)?,
            t => return Err(Error::UnexpectedTag(t)),
        })
    }

    /// How many bytes the value's content takes.
    fn content_len(&self) -> usize {
        match self {
            Value::Integer(v) => asn1::minimal_twos(&i128::from(*v).to_be_bytes()).len(),
            Value::OctetString(b) | Value::Opaque(b) => b.len(),
            Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => 0,
            Value::ObjectIdentifier(o) => o.content_len(),
            Value::IpAddress(_) => 4,
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => {
                asn1::minimal_twos(&i128::from(*v).to_be_bytes()).len()
            }
            Value::Counter64(v) => asn1::minimal_twos(&i128::from(*v).to_be_bytes()).len(),
        }
    }

    /// Writes the value's whole element.
    fn write_fields(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let t = self.tag();
        match self {
            Value::Integer(v) => write_int(out, t, (*v).into()),
            Value::OctetString(b) | Value::Opaque(b) => write_tlv(out, t, b),
            Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => {
                write_tlv(out, t, &[])
            }
            Value::ObjectIdentifier(o) => {
                out.push(t);
                asn1::encode_length(o.content_len(), out);
                o.write(out)?;
            }
            Value::IpAddress(a) => write_tlv(out, t, a),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => {
                write_int(out, t, (*v).into())
            }
            Value::Counter64(v) => write_int(out, t, (*v).into()),
        }
        Ok(())
    }
}

/// A variable binding: an object's name and its value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VarBind {
    /// The object's name.
    pub name: Oid,
    /// Its value, or [`Value::Null`] in a request that only names it.
    pub value: Value,
}

impl VarBind {
    /// A binding of `name` to `value`.
    pub fn new(name: Oid, value: Value) -> VarBind {
        VarBind { name, value }
    }

    /// A binding of `name` to [`Value::Null`], as a Get, GetNext or
    /// GetBulk request carries.
    pub fn null(name: Oid) -> VarBind {
        VarBind {
            name,
            value: Value::Null,
        }
    }

    /// How many bytes the binding's content takes: its name's element
    /// and its value's.
    fn content_len(&self) -> usize {
        tlv_len(self.name.content_len()).saturating_add(tlv_len(self.value.content_len()))
    }

    /// Writes the binding's whole element, straight into `out`.
    fn write_fields(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(tag::SEQUENCE);
        asn1::encode_length(self.content_len(), out);
        out.push(tag::OBJECT_IDENTIFIER);
        asn1::encode_length(self.name.content_len(), out);
        self.name.write(out)?;
        self.value.write_fields(out)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PDUs.

/// The error-status field of a response. Two statuses are equal when their
/// numbers are, so `Other(5)` equals `GenErr`; [`ErrorStatus::from_code`]
/// gives the named variant for a number that has one.
#[derive(Clone, Copy, Debug)]
pub enum ErrorStatus {
    /// The operation succeeded.
    NoError,
    /// The response exceeds the allowed message size.
    TooBig,
    /// An object or instance is unavailable in SNMPv1.
    NoSuchName,
    /// A Set value is invalid in SNMPv1.
    BadValue,
    /// An object cannot be changed in SNMPv1.
    ReadOnly,
    /// An error not covered by a more specific status.
    GenErr,
    /// Access to the requested object is denied.
    NoAccess,
    /// The value has the wrong ASN.1 type.
    WrongType,
    /// The value has a disallowed length.
    WrongLength,
    /// The value uses an invalid encoding.
    WrongEncoding,
    /// The value lies outside the object's allowed values.
    WrongValue,
    /// The requested object instance cannot be created.
    NoCreation,
    /// The value conflicts with the object's current state.
    InconsistentValue,
    /// The agent lacks a resource needed for the operation.
    ResourceUnavailable,
    /// The agent could not commit the Set operation.
    CommitFailed,
    /// The agent could not undo a failed Set operation.
    UndoFailed,
    /// The request is not authorized.
    AuthorizationError,
    /// The object does not permit writes.
    NotWritable,
    /// The instance name is invalid for the requested creation.
    InconsistentName,
    /// Any other number. One that has a name acts as that name.
    Other(i32),
}

impl PartialEq for ErrorStatus {
    fn eq(&self, other: &ErrorStatus) -> bool {
        self.code() == other.code()
    }
}

impl Eq for ErrorStatus {}

impl std::hash::Hash for ErrorStatus {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code().hash(state);
    }
}

const STATUSES: [ErrorStatus; 19] = [
    ErrorStatus::NoError,
    ErrorStatus::TooBig,
    ErrorStatus::NoSuchName,
    ErrorStatus::BadValue,
    ErrorStatus::ReadOnly,
    ErrorStatus::GenErr,
    ErrorStatus::NoAccess,
    ErrorStatus::WrongType,
    ErrorStatus::WrongLength,
    ErrorStatus::WrongEncoding,
    ErrorStatus::WrongValue,
    ErrorStatus::NoCreation,
    ErrorStatus::InconsistentValue,
    ErrorStatus::ResourceUnavailable,
    ErrorStatus::CommitFailed,
    ErrorStatus::UndoFailed,
    ErrorStatus::AuthorizationError,
    ErrorStatus::NotWritable,
    ErrorStatus::InconsistentName,
];

impl ErrorStatus {
    /// The field's number.
    pub fn code(self) -> i32 {
        use ErrorStatus::*;
        match self {
            NoError => 0,
            TooBig => 1,
            NoSuchName => 2,
            BadValue => 3,
            ReadOnly => 4,
            GenErr => 5,
            NoAccess => 6,
            WrongType => 7,
            WrongLength => 8,
            WrongEncoding => 9,
            WrongValue => 10,
            NoCreation => 11,
            InconsistentValue => 12,
            ResourceUnavailable => 13,
            CommitFailed => 14,
            UndoFailed => 15,
            AuthorizationError => 16,
            NotWritable => 17,
            InconsistentName => 18,
            Other(c) => c,
        }
    }

    /// The status for a number.
    pub fn from_code(c: i32) -> ErrorStatus {
        usize::try_from(c)
            .ok()
            .and_then(|i| STATUSES.get(i).copied())
            .unwrap_or(ErrorStatus::Other(c))
    }

    /// The status a version 1 response carries in place of this one, as
    /// RFC 3584, section 4.4, maps them. Version 1 statuses map to
    /// themselves, and unknown numbers to genErr.
    pub fn to_v1(self) -> ErrorStatus {
        use ErrorStatus::*;
        let named = ErrorStatus::from_code(self.code());
        match named {
            NoError | TooBig | NoSuchName | BadValue | ReadOnly | GenErr => named,
            WrongValue | WrongEncoding | WrongType | WrongLength | InconsistentValue => BadValue,
            NoAccess | NotWritable | NoCreation | InconsistentName | AuthorizationError => {
                NoSuchName
            }
            ResourceUnavailable | CommitFailed | UndoFailed | Other(_) => GenErr,
        }
    }
}

/// The generic-trap field of a version 1 trap. Two are equal when their
/// numbers are, so `Other(3)` equals `LinkUp`.
#[derive(Clone, Copy, Debug)]
pub enum GenericTrap {
    /// The agent restarted and may have changed its configuration.
    ColdStart,
    /// The agent restarted without changing its configuration.
    WarmStart,
    /// An interface went down.
    LinkDown,
    /// An interface came up.
    LinkUp,
    /// A request failed authentication.
    AuthenticationFailure,
    /// An EGP neighbor became unreachable.
    EgpNeighborLoss,
    /// The trap is named by the enterprise and specific-trap fields.
    EnterpriseSpecific,
    /// Any other number. One that has a name acts as that name.
    Other(i32),
}

impl PartialEq for GenericTrap {
    fn eq(&self, other: &GenericTrap) -> bool {
        self.code() == other.code()
    }
}

impl Eq for GenericTrap {}

impl std::hash::Hash for GenericTrap {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code().hash(state);
    }
}

impl GenericTrap {
    /// The field's number.
    pub fn code(self) -> i32 {
        match self {
            GenericTrap::ColdStart => 0,
            GenericTrap::WarmStart => 1,
            GenericTrap::LinkDown => 2,
            GenericTrap::LinkUp => 3,
            GenericTrap::AuthenticationFailure => 4,
            GenericTrap::EgpNeighborLoss => 5,
            GenericTrap::EnterpriseSpecific => 6,
            GenericTrap::Other(c) => c,
        }
    }

    /// The generic trap for a number.
    pub fn from_code(c: i32) -> GenericTrap {
        match c {
            0 => GenericTrap::ColdStart,
            1 => GenericTrap::WarmStart,
            2 => GenericTrap::LinkDown,
            3 => GenericTrap::LinkUp,
            4 => GenericTrap::AuthenticationFailure,
            5 => GenericTrap::EgpNeighborLoss,
            6 => GenericTrap::EnterpriseSpecific,
            c => GenericTrap::Other(c),
        }
    }
}

/// The body shared by every PDU but GetBulk and the version 1 trap.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BasicPdu {
    /// Chosen by the sender of a request and copied into the response.
    pub request_id: i32,
    /// [`ErrorStatus::NoError`] in everything but a failed response.
    pub error_status: ErrorStatus,
    /// Which binding, counting from 1, caused the error; 0 if none did.
    pub error_index: i32,
    /// The bindings.
    pub bindings: Vec<VarBind>,
}

impl BasicPdu {
    /// A body with no error and these bindings.
    pub fn new(request_id: i32, bindings: Vec<VarBind>) -> BasicPdu {
        BasicPdu {
            request_id,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            bindings,
        }
    }
}

/// The body of a GetBulkRequest (RFC 3416, section 4.2.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BulkPdu {
    /// Chosen by the manager and copied into the response.
    pub request_id: i32,
    /// How many bindings, from the first, get one GetNext each. Values
    /// below 0 count as 0.
    pub non_repeaters: i32,
    /// How many GetNext steps each other binding gets. Values below 0
    /// count as 0.
    pub max_repetitions: i32,
    /// The bindings: non-repeaters first, then repeaters.
    pub bindings: Vec<VarBind>,
}

impl BulkPdu {
    /// The request split as RFC 3416 says to answer it: the non-repeater
    /// bindings, the repeater bindings, and how many times to step each
    /// repeater. The response holds one binding per non-repeater, then up
    /// to that many rounds of one binding per repeater; how many rounds
    /// fit in a message is the agent's call.
    pub fn split(&self) -> (&[VarBind], &[VarBind], usize) {
        let n = usize::try_from(self.non_repeaters.max(0))
            .unwrap_or(0)
            .min(self.bindings.len());
        let m = usize::try_from(self.max_repetitions.max(0)).unwrap_or(0);
        let (non, rep) = self.bindings.split_at(n);
        (non, rep, m)
    }
}

/// The body of a version 1 trap (RFC 1157, section 4.1.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TrapV1Pdu {
    /// The type of object that sent the trap, usually its sysObjectID.
    pub enterprise: Oid,
    /// The IPv4 address of the agent that sent it.
    pub agent_addr: [u8; 4],
    /// Which generic trap this is.
    pub generic_trap: GenericTrap,
    /// The enterprise's own trap number, when generic is
    /// [`GenericTrap::EnterpriseSpecific`].
    pub specific_trap: i32,
    /// The sender's sysUpTime when the trap happened.
    pub time_stamp: u32,
    /// Bindings with more about the trap.
    pub bindings: Vec<VarBind>,
}

/// A protocol data unit: what a message asks or says.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Pdu {
    /// GetRequest: the values of the named objects.
    Get(BasicPdu),
    /// GetNextRequest: for each name, the first object after it.
    GetNext(BasicPdu),
    /// Response (GetResponse in version 1): the answer to a request.
    Response(BasicPdu),
    /// SetRequest: set the named objects to the given values.
    Set(BasicPdu),
    /// Version 1 Trap.
    TrapV1(TrapV1Pdu),
    /// GetBulkRequest: many GetNext steps at once. Version 2 only.
    GetBulk(BulkPdu),
    /// InformRequest: a trap the receiver answers. Version 2 only.
    Inform(BasicPdu),
    /// SNMPv2-Trap. Version 2 only.
    TrapV2(BasicPdu),
    /// Report. Defined by RFC 3416 for use by SNMPv3; read and written
    /// here so nothing is lost.
    Report(BasicPdu),
}

impl Pdu {
    /// The PDU's BER tag.
    pub fn tag(&self) -> u8 {
        match self {
            Pdu::Get(_) => tag::GET_REQUEST,
            Pdu::GetNext(_) => tag::GET_NEXT_REQUEST,
            Pdu::Response(_) => tag::RESPONSE,
            Pdu::Set(_) => tag::SET_REQUEST,
            Pdu::TrapV1(_) => tag::TRAP_V1,
            Pdu::GetBulk(_) => tag::GET_BULK_REQUEST,
            Pdu::Inform(_) => tag::INFORM_REQUEST,
            Pdu::TrapV2(_) => tag::TRAP_V2,
            Pdu::Report(_) => tag::REPORT,
        }
    }

    /// The request ID, which every PDU but the version 1 trap has.
    pub fn request_id(&self) -> Option<i32> {
        match self {
            Pdu::TrapV1(_) => None,
            Pdu::GetBulk(b) => Some(b.request_id),
            Pdu::Get(p) | Pdu::GetNext(p) | Pdu::Response(p) | Pdu::Set(p) => Some(p.request_id),
            Pdu::Inform(p) | Pdu::TrapV2(p) | Pdu::Report(p) => Some(p.request_id),
        }
    }

    /// The variable bindings.
    pub fn bindings(&self) -> &[VarBind] {
        match self {
            Pdu::TrapV1(t) => &t.bindings,
            Pdu::GetBulk(b) => &b.bindings,
            Pdu::Get(p) | Pdu::GetNext(p) | Pdu::Response(p) | Pdu::Set(p) => &p.bindings,
            Pdu::Inform(p) | Pdu::TrapV2(p) | Pdu::Report(p) => &p.bindings,
        }
    }

    /// The variable bindings, to change in place.
    pub fn bindings_mut(&mut self) -> &mut Vec<VarBind> {
        match self {
            Pdu::TrapV1(t) => &mut t.bindings,
            Pdu::GetBulk(b) => &mut b.bindings,
            Pdu::Get(p) | Pdu::GetNext(p) | Pdu::Response(p) | Pdu::Set(p) => &mut p.bindings,
            Pdu::Inform(p) | Pdu::TrapV2(p) | Pdu::Report(p) => &mut p.bindings,
        }
    }

    /// The body with request ID, error-status and error-index fields,
    /// which every PDU but GetBulk and the version 1 trap has. A manager
    /// reads a Response's error through it.
    pub fn basic(&self) -> Option<&BasicPdu> {
        match self {
            Pdu::TrapV1(_) | Pdu::GetBulk(_) => None,
            Pdu::Get(p) | Pdu::GetNext(p) | Pdu::Response(p) | Pdu::Set(p) => Some(p),
            Pdu::Inform(p) | Pdu::TrapV2(p) | Pdu::Report(p) => Some(p),
        }
    }

    /// Whether a message of `version` may carry this kind of PDU. Version
    /// 1 has no GetBulk, Inform, version 2 trap or Report, and version 2c
    /// no version 1 trap. RFC 3584 says to drop a message that breaks
    /// this; [`Message::parse`] reads it anyway and leaves the choice to
    /// the caller.
    pub fn allowed_in(&self, version: Version) -> bool {
        match self {
            Pdu::Get(_) | Pdu::GetNext(_) | Pdu::Response(_) | Pdu::Set(_) => true,
            Pdu::TrapV1(_) => version == Version::V1,
            Pdu::GetBulk(_) | Pdu::Inform(_) | Pdu::TrapV2(_) | Pdu::Report(_) => {
                version == Version::V2c
            }
        }
    }

    /// Whether this PDU asks for a Response: Get, GetNext, Set, GetBulk
    /// and Inform.
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            Pdu::Get(_) | Pdu::GetNext(_) | Pdu::Set(_) | Pdu::GetBulk(_) | Pdu::Inform(_)
        )
    }

    fn parse(t: u8, c: &[u8]) -> Result<Pdu, Error> {
        let mut r = Reader::new(c);
        if t == tag::TRAP_V1 {
            let enterprise = Oid::parse(r.expect(tag::OBJECT_IDENTIFIER)?)?;
            let agent_addr = r
                .expect(tag::IP_ADDRESS)?
                .try_into()
                .map_err(|_| Error::Value(tag::IP_ADDRESS))?;
            let generic_trap = GenericTrap::from_code(r.int()?);
            let specific_trap = r.int()?;
            let Value::TimeTicks(time_stamp) =
                Value::from_ber(tag::TIME_TICKS, r.expect(tag::TIME_TICKS)?)?
            else {
                return Err(Error::Value(tag::TIME_TICKS));
            };
            let bindings = parse_bindings(r.expect(tag::SEQUENCE)?)?;
            r.end()?;
            return Ok(Pdu::TrapV1(TrapV1Pdu {
                enterprise,
                agent_addr,
                generic_trap,
                specific_trap,
                time_stamp,
                bindings,
            }));
        }
        if !matches!(t, tag::GET_REQUEST..=tag::REPORT) {
            return Err(Error::UnexpectedTag(t));
        }
        let (request_id, a, b) = (r.int()?, r.int()?, r.int()?);
        let bindings = parse_bindings(r.expect(tag::SEQUENCE)?)?;
        r.end()?;
        if t == tag::GET_BULK_REQUEST {
            return Ok(Pdu::GetBulk(BulkPdu {
                request_id,
                non_repeaters: a,
                max_repetitions: b,
                bindings,
            }));
        }
        let p = BasicPdu {
            request_id,
            error_status: ErrorStatus::from_code(a),
            error_index: b,
            bindings,
        };
        Ok(match t {
            tag::GET_REQUEST => Pdu::Get(p),
            tag::GET_NEXT_REQUEST => Pdu::GetNext(p),
            tag::RESPONSE => Pdu::Response(p),
            tag::SET_REQUEST => Pdu::Set(p),
            tag::INFORM_REQUEST => Pdu::Inform(p),
            tag::TRAP_V2 => Pdu::TrapV2(p),
            _ => Pdu::Report(p),
        })
    }

    fn head_len(&self) -> usize {
        match self {
            Pdu::TrapV1(t) => {
                tlv_len(t.enterprise.content_len())
                    + tlv_len(4)
                    + [
                        i128::from(t.generic_trap.code()),
                        i128::from(t.specific_trap),
                        i128::from(t.time_stamp),
                    ]
                    .iter()
                    .map(|&v| tlv_len(asn1::minimal_twos(&v.to_be_bytes()).len()))
                    .sum::<usize>()
            }
            Pdu::GetBulk(b) => [b.request_id, b.non_repeaters, b.max_repetitions]
                .iter()
                .map(|&v| tlv_len(asn1::minimal_twos(&i128::from(v).to_be_bytes()).len()))
                .sum(),
            _ => self.basic().map_or(0, |p| {
                [p.request_id, p.error_status.code(), p.error_index]
                    .iter()
                    .map(|&v| tlv_len(asn1::minimal_twos(&i128::from(v).to_be_bytes()).len()))
                    .sum()
            }),
        }
    }

    /// The PDU's content before its bindings.
    fn head(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            Pdu::TrapV1(t) => {
                write_tlv(&mut out, tag::OBJECT_IDENTIFIER, &t.enterprise.to_bytes()?);
                write_tlv(&mut out, tag::IP_ADDRESS, &t.agent_addr);
                write_int(&mut out, tag::INTEGER, t.generic_trap.code().into());
                write_int(&mut out, tag::INTEGER, t.specific_trap.into());
                write_int(&mut out, tag::TIME_TICKS, t.time_stamp.into());
            }
            Pdu::GetBulk(b) => {
                for v in [b.request_id, b.non_repeaters, b.max_repetitions] {
                    write_int(&mut out, tag::INTEGER, v.into());
                }
            }
            Pdu::Get(p)
            | Pdu::GetNext(p)
            | Pdu::Response(p)
            | Pdu::Set(p)
            | Pdu::Inform(p)
            | Pdu::TrapV2(p)
            | Pdu::Report(p) => {
                for v in [p.request_id, p.error_status.code(), p.error_index] {
                    write_int(&mut out, tag::INTEGER, v.into());
                }
            }
        }
        Ok(out)
    }
}

fn parse_bindings(c: &[u8]) -> Result<Vec<VarBind>, Error> {
    let mut list = Reader::new(c);
    let mut out = Vec::new();
    while !list.b.is_empty() {
        let mut r = Reader::new(list.expect(tag::SEQUENCE)?);
        let name = Oid::parse(r.expect(tag::OBJECT_IDENTIFIER)?)?;
        let (t, content) = r.next()?;
        let value = Value::from_ber(t, content)?;
        r.end()?;
        out.push(VarBind { name, value });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Messages.

/// One SNMP v1 or v2c message: what one UDP datagram carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// The protocol version.
    pub version: Version,
    /// The community string, which works as a password. RFC 1157 sets no
    /// limit on its length; only the message's size bounds it.
    pub community: Vec<u8>,
    /// What the message asks or says.
    pub pdu: Pdu,
}

impl Message {
    /// How many bytes [`Wire::write`] would write, or `usize::MAX`
    /// if that does not fit in a `usize`. It allocates nothing in
    /// proportion to the bindings' size. An agent answering GetBulk uses
    /// it to drop rounds of bindings until the response fits the size it
    /// sends.
    pub fn encoded_len(&self) -> usize {
        let list = self.pdu.bindings().iter().fold(0usize, |acc, b| {
            acc.saturating_add(tlv_len(b.content_len()))
        });
        let pdu = self.pdu.head_len().saturating_add(tlv_len(list));
        // The version field is always 3 bytes: tag, length and 0 or 1.
        let content = tlv_len(self.community.len())
            .saturating_add(tlv_len(pdu))
            .saturating_add(3);
        tlv_len(content)
    }

    /// Whether the PDU and every value it carries are allowed in the
    /// message's version (see [`Pdu::allowed_in`] and
    /// [`Value::allowed_in`]).
    pub fn follows_version(&self) -> bool {
        self.pdu.allowed_in(self.version)
            && self
                .pdu
                .bindings()
                .iter()
                .all(|b| b.value.allowed_in(self.version))
    }

    /// The Response that answers this request with `bindings`, with the
    /// same version, community and request ID, and no error. It is `None`
    /// if this message is not a request that gets a response in its
    /// version (see [`Pdu::is_confirmed`]), or if it breaks its version
    /// ([`Message::follows_version`]). RFC 3584 (section 4.2.2.1) says
    /// to drop a version 1 request that carries a Counter64 unanswered,
    /// since an answer would copy it.
    ///
    /// Version 1 cannot carry Counter64 or the exception values. If one
    /// is among `bindings` in a version 1 answer, the answer becomes a
    /// noSuchName error at the first such binding. RFC 3584 (section
    /// 4.2.2) answers a Get that way, and a GetNext that ends in
    /// endOfMibView. For a version 1 GetNext it says to skip Counter64
    /// objects and return the next object that is not one; that walk is
    /// the world's to make, before it calls this. Whether all the answers
    /// fit in one message is left to the caller (see
    /// [`Message::encoded_len`]), who may answer tooBig with
    /// [`Message::error_response`].
    pub fn response(&self, bindings: Vec<VarBind>) -> Option<Message> {
        if !self.pdu.is_confirmed() || !self.follows_version() {
            return None;
        }
        if self.version == Version::V1
            && let Some(i) = bindings
                .iter()
                .position(|b| !b.value.allowed_in(Version::V1))
        {
            let index = i32::try_from(i + 1).unwrap_or(i32::MAX);
            return self.error_response(ErrorStatus::NoSuchName, index);
        }
        let request_id = self.pdu.request_id()?;
        Some(Message {
            version: self.version,
            community: self.community.clone(),
            pdu: Pdu::Response(BasicPdu::new(request_id, bindings)),
        })
    }

    /// The Response that refuses this request with `status` at binding
    /// `index` (counting from 1, or 0 for none). It carries the request's
    /// own bindings. A tooBig response always has error-index 0; in
    /// version 2c it carries no bindings (RFC 3416, section 4.2.1), and
    /// in version 1 the request's bindings, since RFC 1157 (section
    /// 4.1.2) answers with a GetResponse "of identical form". In version
    /// 1 the status is mapped with [`ErrorStatus::to_v1`]. It is `None`
    /// when [`Message::response`] would be.
    pub fn error_response(&self, status: ErrorStatus, index: i32) -> Option<Message> {
        if !self.pdu.is_confirmed() || !self.follows_version() {
            return None;
        }
        let status = if self.version == Version::V1 {
            status.to_v1()
        } else {
            ErrorStatus::from_code(status.code())
        };
        let too_big = status == ErrorStatus::TooBig;
        let index = if too_big { 0 } else { index };
        let bindings = if too_big && self.version == Version::V2c {
            Vec::new()
        } else {
            self.pdu.bindings().to_vec()
        };
        let request_id = self.pdu.request_id()?;
        Some(Message {
            version: self.version,
            community: self.community.clone(),
            pdu: Pdu::Response(BasicPdu {
                request_id,
                error_status: status,
                error_index: index,
                bindings,
            }),
        })
    }

    /// A version 2c trap: sysUpTime.0 set to `uptime` and snmpTrapOID.0
    /// set to `trap`, then `bindings`. With `inform` set it is an
    /// InformRequest, which the receiver answers.
    pub fn trap_v2(
        community: &[u8],
        request_id: i32,
        uptime: u32,
        trap: Oid,
        bindings: Vec<VarBind>,
        inform: bool,
    ) -> Message {
        let mut all = Vec::with_capacity(bindings.len() + 2);
        all.push(VarBind::new(
            Oid(SYS_UP_TIME_0.to_vec()),
            Value::TimeTicks(uptime),
        ));
        all.push(VarBind::new(
            Oid(SNMP_TRAP_OID_0.to_vec()),
            Value::ObjectIdentifier(trap),
        ));
        all.extend(bindings);
        let body = BasicPdu::new(request_id, all);
        Message {
            version: Version::V2c,
            community: community.to_vec(),
            pdu: if inform {
                Pdu::Inform(body)
            } else {
                Pdu::TrapV2(body)
            },
        }
    }

    /// The message with its bindings replaced, for building one message
    /// from another.
    pub fn with_bindings(mut self, bindings: Vec<VarBind>) -> Message {
        *self.pdu.bindings_mut() = bindings;
        self
    }
}

// ---------------------------------------------------------------------------
// Streams.

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one v1 or v2c message. Refuses incomplete fields,
    /// trailing bytes, invalid BER, oversized messages, and other versions.
    /// A PDU or value disallowed by its version is kept; see
    /// [`Message::follows_version`].
    fn parse(b: &[u8]) -> Result<Message, Error> {
        let len = message_len(b)?.ok_or(Error::Truncated)?;
        let whole = b.get(..len).ok_or(Error::Truncated)?;
        if b.len() > len {
            return Err(Error::TrailingBytes);
        }
        let mut outer = Reader::new(whole);
        let mut r = Reader::new(outer.expect(tag::SEQUENCE)?);
        let version = Version::from_code(r.int()?)?;
        let community = r.expect(tag::OCTET_STRING)?;
        let (t, content) = r.next()?;
        let pdu = Pdu::parse(t, content)?;
        r.end()?;
        Ok(Message {
            version,
            community: community.to_vec(),
            pdu,
        })
    }

    /// Appends the whole message. Refuses values over [`MAX_MESSAGE`] and
    /// allocation failure without changing `out`. Bindings and community
    /// bytes are never cut. Use [`Message::error_response`] for tooBig.
    fn write(&self, dest: &mut Vec<u8>) -> Result<(), Error> {
        let total = self.encoded_len();
        if total > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        let bindings = self.pdu.bindings();
        let list = bindings
            .iter()
            .map(|b| tlv_len(b.content_len()))
            .sum::<usize>();
        let head = self.pdu.head().map_err(|_| Error::Unwritable)?;
        let pdu = head.len() + tlv_len(list);
        let content = 3 + tlv_len(self.community.len()) + tlv_len(pdu);
        let mut out = Vec::with_capacity(total);
        out.push(tag::SEQUENCE);
        asn1::encode_length(content, &mut out);
        write_int(&mut out, tag::INTEGER, self.version.code().into());
        write_tlv(&mut out, tag::OCTET_STRING, &self.community);
        out.push(self.pdu.tag());
        asn1::encode_length(pdu, &mut out);
        out.extend_from_slice(&head);
        out.push(tag::SEQUENCE);
        asn1::encode_length(list, &mut out);
        for b in bindings {
            b.write_fields(&mut out).map_err(|_| Error::Unwritable)?;
        }
        dest.try_reserve_exact(total)
            .map_err(|_| Error::Unwritable)?;
        dest.extend_from_slice(&out);
        Ok(())
    }
}

// One tag, one length-form byte, and up to 126 redundant length bytes.
// RFC 3417 permits nonminimal definite lengths; 0xff is reserved.
const MAX_BER_HEADER: usize = 128;

fictionet::prefixed! {
    /// Reads SNMP messages from BER TLV envelopes over TCP (RFC 3430).
    ///
    /// This decoder owns no input. Malformed message bodies are `Err` items;
    /// a bad outer tag, invalid length, or oversized envelope ends framing.
    /// The whole message limit includes the BER header. Capacity is at least
    /// 128 bytes to read the longest permitted definite-length header, even
    /// when the configured limit is smaller. The header suffices to refuse
    /// an oversized message before its body arrives. Partial messages return
    /// [`fictionet::stdlib::codec::Step::Need`], including at EOF, so [`fictionet::stdlib::codec::Stream`] reports
    /// truncation. Redundant long-form BER lengths are accepted. Message bodies
    /// must use SNMP v1 or v2c.
    Message => (Result<Message, Error>, Error, usize);
    name = "SNMP/TCP";
    default { MAX_MESSAGE }
    normalize(limit) { limit.min(MAX_MESSAGE) }
    capacity(limit) { let limit = *limit;
        limit.max(MAX_BER_HEADER) }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        let Some(length) = message_len(input)? else {
            return Ok(None);
        };
        if length > limit {
            return Err(Error::TooLong(length));
        }
        Ok(input
            .get(..length)
            .map(|bytes| (Message::parse(bytes), length)))
    }
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{Element, ErrorStatus, Message, Oid};
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    /// Checks message and response round trips and lengths.
    pub fn check_message(data: &[u8]) {
        if let Ok(m) = Message::parse(data) {
            let b = m.to_bytes().unwrap();
            assert!(b.len() <= data.len());
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            // Answers to it follow its version and are no longer than it,
            // so they are written whole and read back the same.
            for r in [
                m.response(m.pdu.bindings().to_vec()),
                m.error_response(ErrorStatus::GenErr, 1),
            ]
            .into_iter()
            .flatten()
            {
                assert!(m.follows_version() && r.follows_version());
                let b = r.to_bytes().unwrap();
                assert!(b.len() <= data.len());
                assert_eq!(Message::parse(&b), Ok(r));
            }
        }
    }

    /// Checks BER elements and binary and text object identifiers.
    pub fn check_scalars(data: &[u8]) {
        if let Ok(e) = Element::parse(data) {
            let b = e.to_bytes().unwrap();
            assert_eq!(Element::parse(&b), Ok(e));
        }
        if let Ok(s) = std::str::from_utf8(data)
            && let Ok(o) = s.parse::<Oid>()
        {
            assert_eq!(o.to_string().parse::<Oid>(), Ok(o));
        }
        if let Ok(o) = Oid::parse(data) {
            assert_eq!(Oid::parse(&o.to_bytes().unwrap()), Ok(o));
        }
        contract::check_wire::<Element>(data);
        contract::check_wire::<Oid>(data);
    }
}

#[cfg(test)]
mod tests {
    fn fixture_message(version: Version, community: Vec<u8>, pdu: Pdu) -> Message {
        Message {
            version,
            community,
            pdu,
        }
    }
    fn fixture_element_primitive(tag: u8, content: Vec<u8>) -> Element {
        Element::Primitive { tag, content }
    }

    use super::harness::{check_message, check_scalars};
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn oid(s: &str) -> Oid {
        s.parse().unwrap()
    }

    /// The version 2c GetRequest for sysDescr.0 from the module example.
    const GET_SYS_DESCR: [u8; 43] = [
        0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c,
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
        0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];

    /// A version 1 coldStart trap from 10.0.0.1, enterprise
    /// 1.3.6.1.4.1.9, at tick 4242, community "public".
    const TRAP_COLD_START: [u8; 41] = [
        0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa4, 0x1a,
        0x06, 0x06, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x40, 0x04, 10, 0, 0, 1, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x43, 0x02, 0x10, 0x92, 0x30, 0x00,
    ];

    fn every_value() -> Vec<Value> {
        vec![
            Value::Integer(0),
            Value::Integer(-1),
            Value::Integer(i32::MIN),
            Value::Integer(i32::MAX),
            Value::OctetString(b"eth0".to_vec()),
            Value::OctetString(vec![]),
            Value::Null,
            Value::ObjectIdentifier(oid("1.3.6.1.4.1.8072.3.2.10")),
            Value::IpAddress([192, 0, 2, 1]),
            Value::Counter32(u32::MAX),
            Value::Gauge32(1_000_000_000),
            Value::TimeTicks(123_456),
            Value::Opaque(vec![0x9f, 0x78, 0x04, 0x3f, 0x80, 0, 0]),
            Value::Counter64(u64::MAX),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ]
    }

    fn samples() -> Vec<Message> {
        let binds: Vec<VarBind> = every_value()
            .into_iter()
            .enumerate()
            .map(|(i, v)| VarBind::new(oid("1.3.6.1.2.1.1").child(i as u32).unwrap(), v))
            .collect();
        let basic = BasicPdu {
            request_id: -5,
            error_status: ErrorStatus::WrongType,
            error_index: 3,
            bindings: binds.clone(),
        };
        let v1binds: Vec<VarBind> = binds
            .iter()
            .filter(|b| b.value.allowed_in(Version::V1))
            .cloned()
            .collect();
        vec![
            Message::parse(&GET_SYS_DESCR).unwrap(),
            fixture_message(
                Version::V1,
                b"private".to_vec(),
                Pdu::Get(BasicPdu::new(1, vec![])),
            ),
            fixture_message(Version::V2c, vec![], Pdu::GetNext(basic.clone())),
            fixture_message(Version::V2c, b"c".to_vec(), Pdu::Response(basic.clone())),
            fixture_message(
                Version::V1,
                b"c".to_vec(),
                Pdu::Set(BasicPdu::new(i32::MAX, v1binds.clone())),
            ),
            fixture_message(
                Version::V1,
                b"public".to_vec(),
                Pdu::TrapV1(TrapV1Pdu {
                    enterprise: oid("1.3.6.1.4.1.9"),
                    agent_addr: [10, 0, 0, 1],
                    generic_trap: GenericTrap::LinkDown,
                    specific_trap: 0,
                    time_stamp: 4242,
                    bindings: v1binds,
                }),
            ),
            fixture_message(
                Version::V2c,
                b"public".to_vec(),
                Pdu::GetBulk(BulkPdu {
                    request_id: 9,
                    non_repeaters: 1,
                    max_repetitions: 10,
                    bindings: binds.clone(),
                }),
            ),
            fixture_message(Version::V2c, b"x".to_vec(), Pdu::Inform(basic.clone())),
            Message::trap_v2(
                b"public",
                77,
                100,
                oid("1.3.6.1.6.3.1.1.5.1"),
                vec![],
                false,
            ),
            fixture_message(Version::V2c, b"x".to_vec(), Pdu::Report(basic)),
        ]
    }

    // X.690, section 8.3 (integers) and 8.19 (object identifiers).

    #[test]
    fn integer_encodings() {
        let cases: [(i128, &[u8]); 8] = [
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x00, 0x80]),
            (256, &[0x01, 0x00]),
            (-128, &[0x80]),
            (-129, &[0xff, 0x7f]),
            (u32::MAX as i128, &[0x00, 0xff, 0xff, 0xff, 0xff]),
            (
                u64::MAX as i128,
                &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (v, bytes) in cases {
            assert_eq!(int_content(v), bytes, "{v}");
            assert_eq!(read_int(bytes), Ok(v));
        }
        // Redundant sign bytes are read; empty and overlong are not.
        assert_eq!(read_int(&[0x00, 0x00, 0x05]), Ok(5));
        assert_eq!(read_int(&[0xff, 0xff, 0x80]), Ok(-128));
        assert_eq!(read_int(&[]), Err(Error::Integer));
        assert_eq!(read_int(&[1; 10]), Err(Error::Integer));
    }

    #[test]
    fn oid_encodings() {
        // X.690's own example: {2 100 3} is 0x813403.
        let o = Oid::from_arcs(&[2, 100, 3]).unwrap();
        assert_eq!(o.to_bytes().unwrap(), [0x81, 0x34, 0x03]);
        assert_eq!(Oid::parse(&[0x81, 0x34, 0x03]), Ok(o));
        let internet = oid("1.3.6.1");
        assert_eq!(internet.to_bytes().unwrap(), [0x2b, 0x06, 0x01]);
        assert_eq!(Oid::parse(&[0x00]).unwrap().arcs(), [0, 0]);
        let big = Oid::from_arcs(&[2, u32::MAX - 80, u32::MAX]).unwrap();
        assert_eq!(Oid::parse(&big.to_bytes().unwrap()), Ok(big));
        // Bad encodings.
        assert_eq!(Oid::parse(&[]), Err(Error::Oid));
        assert_eq!(Oid::parse(&[0x2b, 0x80, 0x01]), Err(Error::Oid));
        assert_eq!(Oid::parse(&[0x2b, 0x86]), Err(Error::Oid));
        assert_eq!(
            Oid::parse(&[0x2b, 0x90, 0x80, 0x80, 0x80, 0x00]),
            Err(Error::Oid)
        );
        assert_eq!(Oid::parse(&[0x2b; MAX_OID_ARCS]), Err(Error::Oid));
        assert!(Oid::parse(&[0x2b; MAX_OID_ARCS - 1]).is_ok());
    }

    #[test]
    fn oid_text() {
        let o = oid("1.3.6.1.2.1.1.1.0");
        assert_eq!(o.to_string(), "1.3.6.1.2.1.1.1.0");
        assert_eq!(".1.3.6".parse::<Oid>(), Ok(oid("1.3.6")));
        assert_eq!("1".parse::<Oid>(), Err(Error::TooFewArcs));
        assert_eq!("".parse::<Oid>(), Err(Error::OidText));
        assert_eq!("1..3".parse::<Oid>(), Err(Error::OidText));
        assert_eq!("1.3.".parse::<Oid>(), Err(Error::OidText));
        assert_eq!("1.+3".parse::<Oid>(), Err(Error::OidText));
        assert_eq!("1.3.4294967296".parse::<Oid>(), Err(Error::OidText));
        assert_eq!("3.1".parse::<Oid>(), Err(Error::FirstArcs));
        assert_eq!("1.40".parse::<Oid>(), Err(Error::FirstArcs));
        assert!("2.4294967295".parse::<Oid>().is_ok());
        let long = vec!["1"; MAX_OID_ARCS + 1].join(".");
        assert_eq!(long.parse::<Oid>(), Err(Error::TooManyArcs));
        let max = vec!["1"; MAX_OID_ARCS].join(".");
        let max = max.parse::<Oid>().unwrap();
        assert_eq!(max.child(1), None);
        assert!(o.starts_with(&oid("1.3.6.1.2.1")));
        assert!(!oid("1.3.6").starts_with(&o));
        // GetNext order is lexicographic.
        assert!(oid("1.3.6.1.2.1.1") < oid("1.3.6.1.2.1.1.1"));
        assert!(oid("1.3.6.1.2.1.1.9") < oid("1.3.6.1.2.1.2"));
    }

    #[test]
    fn get_request_example() {
        let m = Message::parse(&GET_SYS_DESCR).unwrap();
        assert_eq!(m.version, Version::V2c);
        assert_eq!(m.community, b"public");
        let Pdu::Get(p) = &m.pdu else { panic!() };
        assert_eq!(p.request_id, 0x12345678);
        assert_eq!(p.bindings, [VarBind::null(oid("1.3.6.1.2.1.1.1.0"))]);
        assert_eq!(m.to_bytes().unwrap(), GET_SYS_DESCR);
        assert!(m.follows_version());
    }

    #[test]
    fn module_example_reply() {
        let request = Message::parse(&GET_SYS_DESCR).unwrap();
        let answers = vec![VarBind::new(
            oid("1.3.6.1.2.1.1.1.0"),
            Value::OctetString(b"pump controller".to_vec()),
        )];
        let reply = request.response(answers).unwrap().to_bytes().unwrap();
        let mut want = vec![0x30, 0x38, 0x02, 0x01, 0x01, 0x04, 0x06];
        want.extend_from_slice(b"public");
        want.extend_from_slice(&[
            0xa2, 0x2b, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        ]);
        want.extend_from_slice(&[
            0x30, 0x1d, 0x30, 0x1b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        ]);
        want.extend_from_slice(&[0x04, 0x0f]);
        want.extend_from_slice(b"pump controller");
        assert_eq!(reply, want);
    }

    #[test]
    fn value_encodings() {
        let enc = |v: &Value| {
            let mut out = Vec::new();
            v.write_fields(&mut out).unwrap();
            out
        };
        assert_eq!(
            enc(&Value::Counter32(u32::MAX)),
            [0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            enc(&Value::IpAddress([10, 1, 2, 3])),
            [0x40, 0x04, 10, 1, 2, 3]
        );
        assert_eq!(enc(&Value::NoSuchObject), [0x80, 0x00]);
        assert_eq!(enc(&Value::NoSuchInstance), [0x81, 0x00]);
        assert_eq!(enc(&Value::EndOfMibView), [0x82, 0x00]);
        assert_eq!(enc(&Value::Integer(-1)), [0x02, 0x01, 0xff]);
        assert_eq!(enc(&Value::TimeTicks(0)), [0x43, 0x01, 0x00]);
        for v in every_value() {
            let b = enc(&v);
            let h = Header::parse(&b).unwrap().unwrap();
            assert_eq!(Value::from_ber(h.tag, &b[h.header_len..]), Ok(v));
        }
        // Wrong sizes and ranges.
        fictionet::assert_cases! {
            Value::from_ber;
            (tag::NULL, &[0]) => Err(Error::Value(tag::NULL)),
            (tag::END_OF_MIB_VIEW, &[0]) => Err(Error::Value(tag::END_OF_MIB_VIEW)),
            (tag::IP_ADDRESS, &[1, 2, 3]) => Err(Error::Value(tag::IP_ADDRESS)),
            (tag::COUNTER32, &[0xff]) => Err(Error::Integer),
            (tag::GAUGE32, &[1, 0, 0, 0, 0]) => Err(Error::Integer),
            (tag::INTEGER, &[0, 0x80, 0, 0, 0]) => Err(Error::Integer),
            (tag::COUNTER64, &[1, 0, 0, 0, 0, 0, 0, 0, 0]) => Err(Error::Integer),
            (0x45, &[]) => Err(Error::UnexpectedTag(0x45)),
            (0x24, &[]) => Err(Error::UnexpectedTag(0x24)),
        }
    }

    #[test]
    fn trap_v1_example() {
        let bytes = TRAP_COLD_START;
        let m = Message::parse(&bytes).unwrap();
        let Pdu::TrapV1(t) = &m.pdu else { panic!() };
        assert_eq!(t.enterprise, oid("1.3.6.1.4.1.9"));
        assert_eq!(t.agent_addr, [10, 0, 0, 1]);
        assert_eq!(t.generic_trap, GenericTrap::ColdStart);
        assert_eq!(t.time_stamp, 4242);
        assert_eq!(m.pdu.request_id(), None);
        assert_eq!(m.to_bytes().unwrap(), bytes);
        assert!(m.follows_version());
        assert_eq!(m.response(vec![]), None);
        for c in -2..10 {
            assert_eq!(GenericTrap::from_code(c).code(), c);
        }
    }

    #[test]
    fn get_bulk_example() {
        // RFC 3416, section 4.2.3: non-repeaters 1, max-repetitions 2, sysUpTime then two ifTable columns.
        let req = BulkPdu {
            request_id: 1,
            non_repeaters: 1,
            max_repetitions: 2,
            bindings: vec![
                VarBind::null(oid("1.3.6.1.2.1.1.3")),
                VarBind::null(oid("1.3.6.1.2.1.4.22.1.2")),
                VarBind::null(oid("1.3.6.1.2.1.4.22.1.4")),
            ],
        };
        let (non, rep, m) = req.split();
        assert_eq!((non.len(), rep.len(), m), (1, 2, 2));
        let msg = fixture_message(Version::V2c, b"public".to_vec(), Pdu::GetBulk(req.clone()));
        assert_eq!(Message::parse(&msg.to_bytes().unwrap()), Ok(msg.clone()));
        assert!(msg.follows_version());
        assert_eq!(msg.to_bytes().unwrap()[13], tag::GET_BULK_REQUEST);
        // Out-of-range fields count as 0 or all.
        let odd = BulkPdu {
            non_repeaters: 9,
            max_repetitions: -4,
            ..req.clone()
        };
        assert_eq!(odd.split().0.len(), 3);
        assert_eq!(odd.split().2, 0);
        let neg = BulkPdu {
            non_repeaters: -1,
            ..req
        };
        assert_eq!(neg.split().0.len(), 0);
        // GetBulk in version 1 is read but breaks the version, and gets no response.
        let v1 = Message {
            version: Version::V1,
            ..msg
        };
        assert!(!v1.follows_version());
        assert_eq!(Message::parse(&v1.to_bytes().unwrap()), Ok(v1.clone()));
        assert_eq!(v1.response(vec![]), None);
    }

    #[test]
    fn trap_v2_and_inform() {
        let m = Message::trap_v2(
            b"public",
            5,
            900,
            oid("1.3.6.1.6.3.1.1.5.3"),
            vec![VarBind::new(
                oid("1.3.6.1.2.1.2.2.1.1.2"),
                Value::Integer(2),
            )],
            false,
        );
        let b = m.pdu.bindings();
        assert_eq!(
            b[0],
            VarBind::new(
                Oid::from_arcs(SYS_UP_TIME_0).unwrap(),
                Value::TimeTicks(900)
            )
        );
        assert_eq!(b[1].name.arcs(), SNMP_TRAP_OID_0);
        assert_eq!(b.len(), 3);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m.clone()));
        assert_eq!(m.response(vec![]), None);
        let inform = Message::trap_v2(b"public", 6, 900, oid("1.3.6.1.6.3.1.1.5.3"), vec![], true);
        let ack = inform.response(inform.pdu.bindings().to_vec()).unwrap();
        let Pdu::Response(p) = &ack.pdu else { panic!() };
        assert_eq!(p.request_id, 6);
        assert_eq!(p.bindings, inform.pdu.bindings());
    }

    #[test]
    fn responses() {
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let err = get.error_response(ErrorStatus::NoAccess, 1).unwrap();
        let Pdu::Response(p) = &err.pdu else { panic!() };
        assert_eq!(
            (p.error_status, p.error_index, p.request_id),
            (ErrorStatus::NoAccess, 1, 0x12345678)
        );
        assert_eq!(p.bindings, get.pdu.bindings());
        let big = get.error_response(ErrorStatus::TooBig, 0).unwrap();
        assert!(big.pdu.bindings().is_empty());
        // Version 1 maps version 2 statuses and refuses version 2 values.
        let v1 = Message {
            version: Version::V1,
            ..get.clone()
        };
        let Pdu::Response(p) = v1.error_response(ErrorStatus::NotWritable, 1).unwrap().pdu else {
            panic!()
        };
        assert_eq!(p.error_status, ErrorStatus::NoSuchName);
        let answers = vec![VarBind::new(oid("1.3.6.1.2.1.1.1.0"), Value::NoSuchObject)];
        let Pdu::Response(p) = v1.response(answers.clone()).unwrap().pdu else {
            panic!()
        };
        assert_eq!(
            (p.error_status, p.error_index),
            (ErrorStatus::NoSuchName, 1)
        );
        assert_eq!(p.bindings, get.pdu.bindings());
        let ok = get.response(answers.clone()).unwrap();
        assert!(ok.follows_version());
        assert_eq!(ok.pdu.bindings(), answers);
        // A response is not answered.
        assert_eq!(ok.response(vec![]), None);
        assert_eq!(ok.error_response(ErrorStatus::GenErr, 0), None);
        assert_eq!(ok.clone().with_bindings(vec![]).pdu.bindings().len(), 0);
    }

    #[test]
    fn error_statuses() {
        for c in -3..25 {
            assert_eq!(ErrorStatus::from_code(c).code(), c);
        }
        assert_eq!(ErrorStatus::from_code(18), ErrorStatus::InconsistentName);
        assert_eq!(ErrorStatus::WrongLength.to_v1(), ErrorStatus::BadValue);
        assert_eq!(ErrorStatus::CommitFailed.to_v1(), ErrorStatus::GenErr);
        assert_eq!(
            ErrorStatus::AuthorizationError.to_v1(),
            ErrorStatus::NoSuchName
        );
        assert_eq!(ErrorStatus::ReadOnly.to_v1(), ErrorStatus::ReadOnly);
        assert_eq!(ErrorStatus::Other(99).to_v1(), ErrorStatus::GenErr);
        for c in 0..19 {
            assert!(ErrorStatus::from_code(c).to_v1().code() <= 5);
        }
    }

    #[test]
    fn round_trips() {
        for m in samples() {
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b), Ok(m.clone()), "{m:?}");
            let e = Element::parse(&b).unwrap();
            assert_eq!(e.to_bytes().unwrap(), b);
        }
    }

    #[test]
    fn truncated_prefixes() {
        for m in samples() {
            let b = m.to_bytes().unwrap();
            for n in 0..b.len() {
                assert_eq!(
                    Message::parse(&b[..n]),
                    Err(Error::Truncated),
                    "{n} of {}",
                    b.len()
                );
                assert_eq!(Element::parse(&b[..n]), Err(Error::Truncated));
                let len = message_len(&b[..n]).unwrap();
                assert!(len.is_none() || len == Some(b.len()));
                let mut d = Stream::new(Frames::<Message>::new());
                assert_eq!(d.push(&b[..n]), n);
                assert_eq!(d.next(), None);
            }
        }
    }

    #[test]
    fn error_paths() {
        let p = Message::parse;
        // Trailing bytes after the message, and inside it.
        let mut extra = GET_SYS_DESCR.to_vec();
        extra.push(0);
        assert_eq!(p(&extra), Err(Error::TrailingBytes));
        let mut inner = GET_SYS_DESCR.to_vec();
        inner[1] += 2;
        inner.extend_from_slice(&[0x05, 0x00]);
        assert_eq!(p(&inner), Err(Error::TrailingBytes));
        // Not a sequence, and wrong tags inside.
        assert_eq!(p(&[0x04, 0x00]), Err(Error::UnexpectedTag(0x04)));
        assert_eq!(
            p(&[0x30, 0x03, 0x04, 0x01, 0x00]),
            Err(Error::UnexpectedTag(0x04))
        );
        let mut pdu = GET_SYS_DESCR;
        pdu[13] = 0xa9;
        assert_eq!(p(&pdu), Err(Error::UnexpectedTag(0xa9)));
        assert_eq!(p(&[0x3f, 0x00]), Err(Error::UnexpectedTag(0x3f)));
        assert_eq!(Header::parse(&[0x1f]), Err(Error::UnexpectedTag(0x1f)));
        // Lengths.
        fictionet::assert_cases! {
            p;
            (&[0x30, 0x80, 0x00, 0x00]) => Err(Error::Length),
            (&[0x30, 0xff, 0, 0]) => Err(Error::Length),
            (&[0x30, 0x85, 0, 0, 0, 0, 1]) => Err(Error::Truncated),
            (&[0x30, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0]) => Err(Error::TooLong(usize::MAX)),
            (&[0x30, 0x83, 0x01, 0x00, 0x00]) => Err(Error::TooLong(0x10000)),
            (&[0x30, 0x82, 0xff, 0xff]) => Err(Error::TooLong(MAX_MESSAGE + 4)),
        }
        assert_eq!(
            Header::parse(&[0x04, 0x84, 0, 0, 0xff, 0xff]),
            Ok(Some(Header {
                tag: 4,
                header_len: 6,
                content_len: 0xffff
            }))
        );
        // Long-form lengths that are not minimal are still read.
        let mut long = vec![0x30, 0x81, 0x29];
        long.extend_from_slice(&GET_SYS_DESCR[2..]);
        assert_eq!(p(&long), Message::parse(&GET_SYS_DESCR));
        // Versions: SNMPv3 is refused, and an out-of-range version is a bad integer.
        let mut v3 = GET_SYS_DESCR;
        v3[4] = 3;
        assert_eq!(p(&v3), Err(Error::Unsupported(3)));
        assert_eq!(
            p(&[0x30, 0x07, 0x02, 0x05, 0x01, 0, 0, 0, 0]),
            Err(Error::Integer)
        );
        assert_eq!(Version::from_code(2), Err(Error::Unsupported(2)));
        // Bad values inside a binding.
        let mut null = GET_SYS_DESCR;
        null[41] = 0x81;
        assert!(p(&null).is_ok());
        null[41] = 0x44;
        assert!(p(&null).is_ok());
        null[41] = 0x40;
        assert_eq!(p(&null), Err(Error::Value(0x40)));
        let mut name = GET_SYS_DESCR;
        name[31] = 0x04;
        assert_eq!(p(&name), Err(Error::UnexpectedTag(0x04)));
        let mut sub = GET_SYS_DESCR;
        sub[40] = 0x80;
        assert_eq!(p(&sub), Err(Error::Oid));
        // A trap with a bad agent address and a negative time stamp.
        let mut bad = TRAP_COLD_START;
        bad[24] = 3;
        assert!(p(&bad).is_err());
        let mut neg = TRAP_COLD_START;
        neg[37] = 0x80;
        assert_eq!(p(&neg), Err(Error::Integer));
        let mut addr = TRAP_COLD_START;
        addr[23] = 0x04;
        assert_eq!(p(&addr), Err(Error::UnexpectedTag(0x04)));
        // Every error has a message.
        let all = [
            Error::Truncated,
            Error::TrailingBytes,
            Error::UnexpectedTag(1),
            Error::Length,
            Error::TooLong(1),
            Error::TooDeep,
            Error::Integer,
            Error::Oid,
            Error::Value(1),
            Error::Unsupported(3),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
        for e in [
            Error::TooFewArcs,
            Error::TooManyArcs,
            Error::FirstArcs,
            Error::OidText,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn elements_and_depth() {
        let mut deep = Vec::new();
        for _ in 0..=MAX_DEPTH {
            deep = [vec![0x30, deep.len() as u8], deep].concat();
        }
        assert_eq!(Element::parse(&deep), Err(Error::TooDeep));
        assert!(Element::parse(&deep[2..]).is_ok());
        // Writers refuse what the reader would.
        let mut e = fixture_element_primitive(0x04, vec![]);
        for _ in 0..=MAX_DEPTH {
            e = Element::Constructed {
                tag: 0x30,
                children: vec![e],
            };
        }
        assert_eq!(e.to_bytes(), Err(Error::Unwritable));
        let Element::Constructed { children, .. } = e else {
            panic!()
        };
        let ok = children[0].to_bytes().unwrap();
        assert_eq!(Element::parse(&ok), Ok(children[0].clone()));
        assert_eq!(
            fixture_element_primitive(0x30, vec![]).to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Element::Constructed {
                tag: 0x04,
                children: vec![]
            }
            .to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            fixture_element_primitive(0x1f, vec![]).to_bytes(),
            Err(Error::Unwritable)
        );
        let huge = fixture_element_primitive(0x04, vec![0; MAX_MESSAGE + 1]);
        assert_eq!(huge.to_bytes(), Err(Error::Unwritable));
        let wide = Element::Constructed {
            tag: 0x30,
            children: vec![fixture_element_primitive(0x04, vec![0; 40_000]); 2],
        };
        assert!(matches!(wide.to_bytes(), Err(Error::Unwritable)));
        let fits = fixture_element_primitive(0x04, vec![7; MAX_MESSAGE]);
        let b = fits.to_bytes().unwrap();
        assert_eq!(Element::parse(&b), Ok(fits));
    }

    #[test]
    fn too_big_responses() {
        // RFC 3416, section 4.2.1: error-index zero and no bindings.
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let Pdu::Response(p) = get.error_response(ErrorStatus::TooBig, 3).unwrap().pdu else {
            panic!()
        };
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::TooBig, 0));
        assert!(p.bindings.is_empty());
        // RFC 1157, section 4.1.2: a GetResponse "of identical form" to the
        // request, error-index zero, so it carries the request's bindings.
        let v1 = Message {
            version: Version::V1,
            ..get.clone()
        };
        let Pdu::Response(p) = v1.error_response(ErrorStatus::TooBig, 3).unwrap().pdu else {
            panic!()
        };
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::TooBig, 0));
        assert_eq!(p.bindings, get.pdu.bindings());
    }

    #[test]
    fn depth_limit_is_inclusive() {
        // MAX_DEPTH levels of nesting are read and written; one more is not.
        let mut deep = Vec::new();
        for _ in 0..MAX_DEPTH {
            deep = [vec![0x30, deep.len() as u8], deep].concat();
        }
        let e = Element::parse(&deep).unwrap();
        assert_eq!(e.to_bytes(), Ok(deep.clone()));
        let deeper = [vec![0x30, deep.len() as u8], deep].concat();
        assert_eq!(Element::parse(&deeper), Err(Error::TooDeep));
        // An SNMP message nests 4 deep: message, PDU, binding list, binding.
        let mut levels = 0;
        let mut e = Element::parse(&GET_SYS_DESCR).unwrap();
        while let Element::Constructed { children, .. } = e {
            levels += 1;
            e = children.into_iter().last().unwrap();
        }
        assert_eq!(levels, 4);
    }

    #[test]
    fn other_codes_with_names_round_trip() {
        // Other(n) for a number that has a name is that name, on the wire and in Rust.
        assert_eq!(ErrorStatus::Other(5), ErrorStatus::GenErr);
        assert_eq!(GenericTrap::Other(3), GenericTrap::LinkUp);
        assert_ne!(ErrorStatus::Other(99), ErrorStatus::GenErr);
        // Hash agrees with Eq.
        use std::hash::BuildHasher;
        let rs = std::hash::RandomState::new();
        assert_eq!(
            rs.hash_one(ErrorStatus::Other(5)),
            rs.hash_one(ErrorStatus::GenErr)
        );
        assert_eq!(
            rs.hash_one(GenericTrap::Other(6)),
            rs.hash_one(GenericTrap::EnterpriseSpecific)
        );
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let mut m = get.error_response(ErrorStatus::Other(5), 1).unwrap();
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m.clone()));
        let Pdu::Response(p) = &mut m.pdu else {
            panic!()
        };
        p.error_status = ErrorStatus::Other(12);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m.clone()));
        let trap = Message::parse(&TRAP_COLD_START).unwrap();
        let mut t = trap.clone();
        let Pdu::TrapV1(body) = &mut t.pdu else {
            panic!()
        };
        body.generic_trap = GenericTrap::Other(0);
        assert_eq!(t, trap);
        assert_eq!(Message::parse(&t.to_bytes().unwrap()), Ok(t.clone()));
        // The version 1 mapping and the tooBig rules see the number, not the variant.
        assert_eq!(ErrorStatus::Other(1).to_v1(), ErrorStatus::TooBig);
        assert_eq!(ErrorStatus::Other(17).to_v1(), ErrorStatus::NoSuchName);
        let big = get.error_response(ErrorStatus::Other(1), 3).unwrap();
        let p = big.pdu.basic().unwrap();
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::TooBig, 0));
        assert!(p.bindings.is_empty());
    }

    #[test]
    fn header_total_len_does_not_overflow() {
        let h = Header {
            tag: 4,
            header_len: 6,
            content_len: usize::MAX,
        };
        assert_eq!(h.total_len(), usize::MAX);
    }

    #[test]
    fn accessors() {
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let err = get.error_response(ErrorStatus::NoAccess, 1).unwrap();
        let p = err.pdu.basic().unwrap();
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::NoAccess, 1));
        let trap = Message::parse(&TRAP_COLD_START).unwrap();
        assert_eq!(trap.pdu.basic(), None);
        let mut m = get.clone();
        m.pdu
            .bindings_mut()
            .push(VarBind::null(oid("1.3.6.1.2.1.1.5.0")));
        assert_eq!(m.pdu.bindings().len(), 2);
        let e = Element::parse(&GET_SYS_DESCR).unwrap();
        assert_eq!(e.tag(), tag::SEQUENCE);
        let mut d = Stream::new(Frames::<Message>::new());
        assert_eq!(d.push(&GET_SYS_DESCR[..10]), 10);
        assert!(d.next().is_none());
        assert_eq!(d.push(&GET_SYS_DESCR[10..]), 33);
        assert_eq!(d.next(), Some(Ok(Ok(get))));
    }

    #[test]
    fn stream_takes_many_small_messages_in_linear_time() {
        assert_linear(
            "stream_takes_many_small_messages_in_linear_time",
            rounds(500000),
            |size| {
                let count = size;
                let bytes = [0x30, 0].repeat(count);
                let mut stream = Stream::new(Frames::<Message>::new());
                let mut got = 0;
                pump(&mut stream, &bytes, |item| {
                    assert_eq!(item, Err(Error::Truncated));
                    got += 1;
                })
                .unwrap();
                assert_eq!(got, count);
                assert_eq!(stream.buffered(), 0);
                let message = Message::parse(&GET_SYS_DESCR).unwrap();
                assert_eq!(stream.push(&GET_SYS_DESCR), 43);
                assert_eq!(stream.push(&GET_SYS_DESCR[..5]), 5);
                assert_eq!(stream.next(), Some(Ok(Ok(message.clone()))));
                assert_eq!(stream.push(&GET_SYS_DESCR[5..]), 38);
                assert_eq!(stream.next(), Some(Ok(Ok(message))));
                assert_eq!(stream.next(), None);
            },
        );
    }

    #[test]
    fn writer_refuses_rather_than_drops_bindings() {
        // A Set of two 40,000-byte values does not fit, and is refused
        // whole rather than sent as a Set of the first alone.
        let binds: Vec<VarBind> = (0..2)
            .map(|i| {
                VarBind::new(
                    oid("1.3.6.1.2.1.1.5").child(i).unwrap(),
                    Value::OctetString(vec![b'x'; 40_000]),
                )
            })
            .collect();
        let set = fixture_message(
            Version::V2c,
            b"private".to_vec(),
            Pdu::Set(BasicPdu::new(1, binds)),
        );
        let len = set.encoded_len();
        assert!(len > MAX_MESSAGE);
        assert_eq!(set.to_bytes(), Err(Error::Unwritable));
        // So is a Response, which the agent answers with tooBig instead.
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let reply = get.response(set.pdu.bindings().to_vec()).unwrap();
        assert!(matches!(reply.to_bytes(), Err(Error::Unwritable)));
        let big = get.error_response(ErrorStatus::TooBig, 0).unwrap();
        assert_eq!(Message::parse(&big.to_bytes().unwrap()), Ok(big));
        // A value far too large for any message is measured, not copied.
        let huge = get
            .response(vec![VarBind::new(
                oid("1.3.6"),
                Value::Opaque(vec![0; rounds(1 << 26)]),
            )])
            .unwrap();
        assert_eq!(huge.to_bytes(), Err(Error::Unwritable));
        // Right at the limit: with this request, a binding of 1.3.6 to n
        // bytes makes a message of n + 47 bytes.
        for extra in 0..40 {
            let n = MAX_MESSAGE - 40 - extra;
            let m = get
                .response(vec![VarBind::new(
                    oid("1.3.6"),
                    Value::OctetString(vec![1; n]),
                )])
                .unwrap();
            match m.to_bytes() {
                Ok(b) => {
                    assert!(extra >= 7);
                    assert_eq!(b.len(), n + 47);
                    assert_eq!(m.encoded_len(), b.len());
                    assert_eq!(Message::parse(&b), Ok(m));
                }
                Err(e) => {
                    // Past the limit some lengths take a byte more.
                    assert!(extra < 7);
                    assert!(m.encoded_len() > MAX_MESSAGE);
                    assert_eq!(e, Error::Unwritable);
                }
            }
        }
    }

    #[test]
    fn long_communities_are_kept() {
        // RFC 3584, snmpCommunityName: only the message size bounds a community.
        let mut c = vec![
            0x30, 0x82, 0x01, 0x40, 0x02, 0x01, 0x01, 0x04, 0x82, 0x01, 0x2c,
        ];
        c.extend_from_slice(&[b'a'; 300]);
        c.extend_from_slice(&[
            0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ]);
        assert_eq!(c.len(), 4 + 0x140);
        let m = Message::parse(&c).unwrap();
        assert_eq!(m.community, [b'a'; 300]);
        assert_eq!(m.to_bytes().unwrap(), c);
        // Written whole, never cut, and refused only when the message is too long.
        let m = fixture_message(
            Version::V2c,
            vec![b'b'; 60_000],
            Pdu::Get(BasicPdu::new(1, vec![])),
        );
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m));
        let m = fixture_message(
            Version::V2c,
            vec![b'b'; MAX_MESSAGE],
            Pdu::Get(BasicPdu::new(1, vec![])),
        );
        assert!(matches!(m.to_bytes(), Err(Error::Unwritable)));
    }

    #[test]
    fn v1_request_with_counter64_gets_no_response() {
        // RFC 3584, section 4.2.2.1: such a request is ill-formed and
        // dropped, since an answer would copy the Counter64.
        let mut v = GET_SYS_DESCR.to_vec();
        v[4] = 0;
        v.splice(41..43, [tag::COUNTER64, 0x01, 0x01]);
        v[1] += 1;
        v[14] += 1;
        v[28] += 1;
        v[30] += 1;
        let m = Message::parse(&v).unwrap();
        assert_eq!(m.pdu.bindings()[0].value, Value::Counter64(1));
        assert!(!m.follows_version());
        assert_eq!(m.error_response(ErrorStatus::GenErr, 1), None);
        assert_eq!(m.response(m.pdu.bindings().to_vec()), None);
        // The same request in version 2c is answered.
        let v2 = Message {
            version: Version::V2c,
            ..m
        };
        assert!(
            v2.error_response(ErrorStatus::GenErr, 1)
                .unwrap()
                .follows_version()
        );
    }

    #[test]
    fn value_content_is_bounded() {
        let over = vec![0; MAX_MESSAGE + 1];
        for t in [
            tag::OCTET_STRING,
            tag::OPAQUE,
            tag::INTEGER,
            tag::OBJECT_IDENTIFIER,
        ] {
            assert_eq!(
                Value::from_ber(t, &over),
                Err(Error::TooLong(MAX_MESSAGE + 1))
            );
        }
        let most = vec![0; MAX_MESSAGE];
        assert_eq!(
            Value::from_ber(tag::OCTET_STRING, &most),
            Ok(Value::OctetString(most.clone()))
        );
        assert_eq!(Value::from_ber(tag::OPAQUE, &most), Ok(Value::Opaque(most)));
    }

    #[test]
    fn oid_second_arc_reaches_u32_max_under_2() {
        // RFC 2578, section 3.5 bounds each arc, not the combined first
        // sub-identifier: 2.4294967295 is 4294967375, 0x90 80 80 80 4f.
        let o = Oid::from_arcs(&[2, u32::MAX]).unwrap();
        assert_eq!(o.to_bytes().unwrap(), [0x90, 0x80, 0x80, 0x80, 0x4f]);
        assert_eq!(Oid::parse(&[0x90, 0x80, 0x80, 0x80, 0x4f]), Ok(o.clone()));
        assert_eq!("2.4294967295".parse::<Oid>(), Ok(o));
        // One more is past the last arc.
        assert_eq!(Oid::parse(&[0x90, 0x80, 0x80, 0x80, 0x50]), Err(Error::Oid));
        assert_eq!(
            Oid::parse(&[0x80 | 0x7f, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Err(Error::Oid)
        );
        let m = Message::trap_v2(
            b"p",
            1,
            0,
            Oid::from_arcs(&[2, u32::MAX, u32::MAX]).unwrap(),
            vec![],
            false,
        );
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m));
    }

    #[test]
    fn long_form_lengths_with_extra_bytes() {
        // RFC 3417, section 8 allows more length bytes than needed.
        let mut long = vec![0x30, 0x85, 0, 0, 0, 0, 0x29];
        long.extend_from_slice(&GET_SYS_DESCR[2..]);
        assert_eq!(Message::parse(&long), Message::parse(&GET_SYS_DESCR));
        let mut longest = vec![0x30, 0xfe];
        longest.extend_from_slice(&[0; 125]);
        longest.push(0x29);
        longest.extend_from_slice(&GET_SYS_DESCR[2..]);
        assert_eq!(Message::parse(&longest), Message::parse(&GET_SYS_DESCR));
        let mut d = Stream::new(Frames::<Message>::new());
        assert_eq!(d.push(&longest), longest.len());
        assert_eq!(d.next(), Some(Ok(Message::parse(&longest))));
    }

    #[test]
    fn stream_holds_at_most_capacity() {
        let n = rounds(10_000);
        let bytes = GET_SYS_DESCR.repeat(n);
        let mut stream = Stream::new(Frames::<Message>::new());
        assert_eq!(stream.push(&bytes), MAX_MESSAGE);
        assert_eq!(stream.push(&bytes), 0);
        contract::check_decode_with_alloc_limit(Frames::<Message>::new, &bytes, 2 * MAX_MESSAGE);
        let (items, failure) = decode_all(Frames::<Message>::new, &bytes);
        assert_eq!(items.len(), n);
        assert!(items.iter().all(Result::is_ok));
        assert_eq!(failure, None);
    }

    #[test]
    fn tlv_len_matches_writer() {
        for n in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536, 1 << 24] {
            let mut out = Vec::new();
            asn1::encode_length(n, &mut out);
            assert_eq!(tlv_len(n), 1 + out.len() + n, "{n}");
        }
    }

    #[test]
    fn stream_splits_a_stream() {
        let messages = samples();
        let bytes: Vec<u8> = messages
            .iter()
            .flat_map(|m| m.to_bytes().unwrap())
            .collect();
        contract::check_decode_with_alloc_limit(Frames::<Message>::new, &bytes, 2 * MAX_MESSAGE);
        assert_eq!(
            decode_all(Frames::<Message>::new, &bytes),
            (messages.into_iter().map(Ok).collect(), None)
        );
        for (bytes, error) in [
            (&[0x31, 0][..], Error::UnexpectedTag(0x31)),
            (&[0x30, 0x83, 1, 0, 0][..], Error::TooLong(0x10000)),
        ] {
            let mut stream = Stream::new(Frames::<Message>::new());
            assert_eq!(stream.push(bytes), bytes.len());
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(error))));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
        }
    }

    fn check(data: &[u8]) {
        check_message(data);
        check_scalars(data);
        contract::check_decode_with_alloc_limit(Frames::<Message>::new, data, 2 * MAX_MESSAGE);
        contract::check_wire::<Message>(data);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed);
        let seeds: Vec<Vec<u8>> = samples().iter().map(|m| m.to_bytes().unwrap()).collect();
        for i in 0..6000 {
            let data: Vec<u8> = if i % 3 == 0 {
                rng.bytes(95)
            } else {
                // Valid messages, one to three of them as a stream, with a
                // few bytes changed, to reach deeper.
                let count = if i % 3 == 1 { 1 } else { 1 + rng.index(3) };
                let mut d = Vec::new();
                for _ in 0..count {
                    d.extend_from_slice(&seeds[rng.index(seeds.len())]);
                }
                for _ in 0..rng.index(4) {
                    mutate(&mut rng, &mut d);
                }
                if rng.next().is_multiple_of(4) {
                    d.truncate(rng.index(d.len() + 1));
                }
                d
            };
            check(&data);
        }
        for t in ["1.3.6.1", ".0.39", "2.99999.1", "1.3.x", "1..2"] {
            check(t.as_bytes());
        }
    }
}
