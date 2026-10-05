//! SNMP v1 and v2c: reading and writing messages, with no I/O.
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
//! write them is up to world code. Over TCP (RFC 3430), a [`Decoder`]
//! splits the stream into messages first.
//!
//! Every reader checks lengths, tags and ranges, because the agent can
//! send any bytes it likes. Lengths are bounded by [`MAX_MESSAGE`],
//! nesting by [`MAX_DEPTH`] and object identifiers by [`MAX_OID_ARCS`].
//! [`Element`] reads and writes BER that is not SNMP, under the same
//! limits.
//!
//! ```
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
//! let reply = request.response(answers).unwrap().to_bytes();
//! assert_eq!(&reply[..4], [0x30, 0x38, 0x02, 0x01]);
//! let back = Message::parse(&reply).unwrap();
//! assert_eq!(back.pdu.request_id(), Some(0x12345678));
//! assert_eq!(back.pdu.bindings()[0].value, Value::OctetString(b"pump controller".to_vec()));
//! ```

use std::fmt;
use std::str::FromStr;

/// The UDP port agents listen on for requests.
pub const PORT: u16 = 161;
/// The UDP port managers listen on for traps and informs.
pub const TRAP_PORT: u16 = 162;
/// The longest message, in bytes, this module reads or writes, headers
/// included. One UDP datagram cannot carry more. It also bounds the
/// content of each [`Element`].
pub const MAX_MESSAGE: usize = 65_535;
/// The deepest nesting of constructed elements [`Element`] reads or
/// writes. An SNMP message nests 4 deep: the message, the PDU, the
/// binding list and each binding.
pub const MAX_DEPTH: usize = 16;
/// The most arcs an object identifier may have (RFC 2578, section 3.5).
pub const MAX_OID_ARCS: usize = 128;
/// The longest community string read or written. Longer ones are refused
/// when read and cut to this length when written.
pub const MAX_COMMUNITY: usize = 255;

/// The object identifier sysUpTime.0, the first binding of every version 2
/// trap and inform.
pub const SYS_UP_TIME_0: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
/// The object identifier snmpTrapOID.0, the second binding of every
/// version 2 trap and inform. Its value names the trap.
pub const SNMP_TRAP_OID_0: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// BER tags this module reads and writes.
pub mod tag {
    #![allow(missing_docs)]
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42;
    pub const TIME_TICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const COUNTER64: u8 = 0x46;
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    pub const END_OF_MIB_VIEW: u8 = 0x82;
    pub const GET_REQUEST: u8 = 0xa0;
    pub const GET_NEXT_REQUEST: u8 = 0xa1;
    pub const RESPONSE: u8 = 0xa2;
    pub const SET_REQUEST: u8 = 0xa3;
    pub const TRAP_V1: u8 = 0xa4;
    pub const GET_BULK_REQUEST: u8 = 0xa5;
    pub const INFORM_REQUEST: u8 = 0xa6;
    pub const TRAP_V2: u8 = 0xa7;
    pub const REPORT: u8 = 0xa8;
    /// Set in a tag whose content is more elements.
    pub const CONSTRUCTED: u8 = 0x20;
    /// The low bits of a tag that say its number follows in more bytes.
    /// This module does not read such tags; SNMP never uses them.
    pub const HIGH_NUMBER: u8 = 0x1f;
}

/// Why bytes are not an SNMP message, or not BER this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before an element does.
    Truncated,
    /// Bytes follow the message, or follow the last field of a sequence.
    TrailingBytes,
    /// An element has a tag that does not belong where it is.
    UnexpectedTag(u8),
    /// A length is indefinite or takes more than 4 bytes.
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
    /// The community string is longer than [`MAX_COMMUNITY`].
    Community(usize),
    /// The version field names a version other than 1 or 2c. SNMPv3
    /// messages carry 3.
    Unsupported(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => f.write_str("the bytes end inside an element"),
            Error::TrailingBytes => f.write_str("bytes follow the last element"),
            Error::UnexpectedTag(t) => write!(f, "unexpected tag 0x{t:02x}"),
            Error::Length => f.write_str("indefinite or overlong length"),
            Error::TooLong(n) => write!(f, "length {n}, over the limit of {MAX_MESSAGE}"),
            Error::TooDeep => write!(f, "elements nest deeper than {MAX_DEPTH}"),
            Error::Integer => f.write_str("integer empty or out of range"),
            Error::Oid => f.write_str("malformed object identifier"),
            Error::Value(t) => write!(f, "wrong size for a value of tag 0x{t:02x}"),
            Error::Community(n) => write!(f, "community of {n} bytes, over the limit of {MAX_COMMUNITY}"),
            Error::Unsupported(v) => write!(f, "SNMP version field {v}, not 0 (v1) or 1 (v2c)"),
        }
    }
}

impl std::error::Error for Error {}

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
    /// lengths and lengths over [`MAX_MESSAGE`] are errors.
    pub fn parse(b: &[u8]) -> Result<Option<Header>, Error> {
        let Some(&tag) = b.first() else { return Ok(None) };
        if tag & tag::HIGH_NUMBER == tag::HIGH_NUMBER {
            return Err(Error::UnexpectedTag(tag));
        }
        let Some(&first) = b.get(1) else { return Ok(None) };
        let (content_len, header_len) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return Err(Error::Length);
            }
            let Some(bytes) = b.get(2..2 + n) else { return Ok(None) };
            let len = bytes.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
            (len, 2 + n)
        };
        if content_len > MAX_MESSAGE {
            return Err(Error::TooLong(content_len));
        }
        Ok(Some(Header { tag, header_len, content_len }))
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
        let content = self.b.get(h.header_len..h.total_len()).ok_or(Error::Truncated)?;
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
        if self.b.is_empty() { Ok(()) } else { Err(Error::TrailingBytes) }
    }
}

/// The bytes of a length field, minimal.
fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// How many bytes an element takes whose content is `len` bytes long.
fn tlv_len(len: usize) -> usize {
    let len_len = if len < 0x80 { 1 } else { 1 + (usize::BITS - len.leading_zeros()).div_ceil(8) as usize };
    1 + len_len + len
}

fn write_tlv(out: &mut Vec<u8>, t: u8, content: &[u8]) {
    out.push(t);
    write_len(out, content.len());
    out.extend_from_slice(content);
}

/// An integer's content as a number. Redundant leading sign bytes are
/// allowed, so a value written by another encoder is still read.
fn read_int(c: &[u8]) -> Result<i128, Error> {
    let mut c = c;
    while c.len() > 1 && ((c[0] == 0 && c[1] & 0x80 == 0) || (c[0] == 0xff && c[1] & 0x80 != 0)) {
        c = &c[1..];
    }
    if c.is_empty() || c.len() > 9 {
        return Err(Error::Integer);
    }
    let mut v: i128 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in c {
        v = (v << 8) | i128::from(b);
    }
    Ok(v)
}

/// The minimal two's complement content of an integer.
fn int_content(v: i128) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut i = 0;
    while i < 15 && ((bytes[i] == 0 && bytes[i + 1] & 0x80 == 0) || (bytes[i] == 0xff && bytes[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    bytes[i..].to_vec()
}

fn write_int(out: &mut Vec<u8>, t: u8, v: i128) {
    write_tlv(out, t, &int_content(v));
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
    let Some(h) = Header::parse(b)? else { return Ok(None) };
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

    /// Reads the element at the start of `b`, and how many bytes it took.
    /// Nesting deeper than [`MAX_DEPTH`] is [`Error::TooDeep`].
    pub fn parse(b: &[u8]) -> Result<(Element, usize), Error> {
        Element::parse_at(b, 1)
    }

    fn parse_at(b: &[u8], depth: usize) -> Result<(Element, usize), Error> {
        let h = Header::parse(b)?.ok_or(Error::Truncated)?;
        let content = b.get(h.header_len..h.total_len()).ok_or(Error::Truncated)?;
        if h.tag & tag::CONSTRUCTED == 0 {
            return Ok((Element::Primitive { tag: h.tag, content: content.to_vec() }, h.total_len()));
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
        Ok((Element::Constructed { tag: h.tag, children }, h.total_len()))
    }

    /// The element's bytes. It fails, writing nothing, where
    /// [`Element::parse`] would refuse the result: a tag in the
    /// multi-byte form or whose constructed bit does not match the
    /// variant, content longer than [`MAX_MESSAGE`], or nesting deeper
    /// than [`MAX_DEPTH`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.write_at(&mut out, 1)?;
        Ok(out)
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

// ---------------------------------------------------------------------------
// Object identifiers.

/// An object identifier: the name of a MIB object, as a list of numbers
/// (arcs). It always has 2 to [`MAX_OID_ARCS`] arcs, the first 0, 1 or 2,
/// and the second below 40 when the first is 0 or 1, so it can always be
/// written. Ordering is the lexicographic order GetNext walks.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(Vec<u32>);

/// Why arcs or text are not an object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OidError {
    /// Fewer than 2 arcs.
    TooShort,
    /// More than [`MAX_OID_ARCS`] arcs.
    TooLong,
    /// The first arc is above 2, or the second is 40 or more under a
    /// first arc of 0 or 1, or too large to encode under 2.
    FirstArcs,
    /// Text that is not a number from 0 to 4294967295 between the dots.
    Syntax,
}

impl fmt::Display for OidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidError::TooShort => f.write_str("an object identifier needs at least 2 arcs"),
            OidError::TooLong => write!(f, "more than {MAX_OID_ARCS} arcs"),
            OidError::FirstArcs => f.write_str("first two arcs out of range"),
            OidError::Syntax => f.write_str("not dotted decimal numbers"),
        }
    }
}

impl std::error::Error for OidError {}

impl Oid {
    /// The object identifier with these arcs, if it is one.
    pub fn from_arcs(arcs: &[u32]) -> Result<Oid, OidError> {
        if arcs.len() < 2 {
            return Err(OidError::TooShort);
        }
        if arcs.len() > MAX_OID_ARCS {
            return Err(OidError::TooLong);
        }
        let ok = match arcs[0] {
            0 | 1 => arcs[1] < 40,
            2 => arcs[1] <= u32::MAX - 80,
            _ => false,
        };
        if !ok {
            return Err(OidError::FirstArcs);
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

    /// Reads an object identifier from the content of a BER element of tag
    /// [`tag::OBJECT_IDENTIFIER`]. Sub-identifiers must be minimal and fit
    /// in 32 bits.
    pub fn from_ber(content: &[u8]) -> Result<Oid, Error> {
        if content.is_empty() {
            return Err(Error::Oid);
        }
        let mut arcs = Vec::new();
        let mut v: u32 = 0;
        let mut fresh = true;
        for &b in content {
            if fresh && b == 0x80 {
                return Err(Error::Oid);
            }
            v = v.checked_mul(128).ok_or(Error::Oid)? | u32::from(b & 0x7f);
            fresh = b & 0x80 == 0;
            if fresh {
                if arcs.is_empty() {
                    let first = (v / 40).min(2);
                    arcs.push(first);
                    arcs.push(v - 40 * first);
                } else {
                    arcs.push(v);
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

    /// The content bytes of this identifier's BER element.
    pub fn to_ber(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // The invariant on the first two arcs keeps this in range.
        let first = self.0[0] * 40 + self.0[1];
        for v in std::iter::once(first).chain(self.0[2..].iter().copied()) {
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
        out
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
    type Err = OidError;

    /// Reads dotted decimal, with or without a leading dot.
    fn from_str(s: &str) -> Result<Oid, OidError> {
        let s = s.strip_prefix('.').unwrap_or(s);
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(OidError::Syntax);
            }
            if arcs.len() >= MAX_OID_ARCS {
                return Err(OidError::TooLong);
            }
            arcs.push(part.parse::<u32>().map_err(|_| OidError::Syntax)?);
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
            || !matches!(self, Value::Counter64(_) | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView)
    }

    /// Whether this is one of the three version 2 exception values.
    pub fn is_exception(&self) -> bool {
        matches!(self, Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView)
    }

    /// Reads a value from an element's tag and content.
    pub fn from_ber(t: u8, c: &[u8]) -> Result<Value, Error> {
        let unsigned = |max: i128| -> Result<i128, Error> {
            let v = read_int(c)?;
            if (0..=max).contains(&v) { Ok(v) } else { Err(Error::Integer) }
        };
        let empty = |v: Value| if c.is_empty() { Ok(v) } else { Err(Error::Value(t)) };
        Ok(match t {
            tag::INTEGER => Value::Integer(i32::try_from(read_int(c)?).map_err(|_| Error::Integer)?),
            tag::OCTET_STRING => Value::OctetString(c.to_vec()),
            tag::NULL => empty(Value::Null)?,
            tag::OBJECT_IDENTIFIER => Value::ObjectIdentifier(Oid::from_ber(c)?),
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

    /// Writes the value's whole element.
    fn write(&self, out: &mut Vec<u8>) {
        let t = self.tag();
        match self {
            Value::Integer(v) => write_int(out, t, (*v).into()),
            Value::OctetString(b) | Value::Opaque(b) => write_tlv(out, t, b),
            Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => write_tlv(out, t, &[]),
            Value::ObjectIdentifier(o) => write_tlv(out, t, &o.to_ber()),
            Value::IpAddress(a) => write_tlv(out, t, a),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => write_int(out, t, (*v).into()),
            Value::Counter64(v) => write_int(out, t, (*v).into()),
        }
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
        VarBind { name, value: Value::Null }
    }

    fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        write_tlv(&mut content, tag::OBJECT_IDENTIFIER, &self.name.to_ber());
        self.value.write(&mut content);
        let mut out = Vec::with_capacity(content.len() + 6);
        write_tlv(&mut out, tag::SEQUENCE, &content);
        out
    }
}

// ---------------------------------------------------------------------------
// PDUs.

/// The error-status field of a response. Two statuses are equal when their
/// numbers are, so `Other(5)` equals `GenErr`; [`ErrorStatus::from_code`]
/// gives the named variant for a number that has one.
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)] // each variant is the RFC 3416 name
pub enum ErrorStatus {
    NoError,
    TooBig,
    NoSuchName,
    BadValue,
    ReadOnly,
    GenErr,
    NoAccess,
    WrongType,
    WrongLength,
    WrongEncoding,
    WrongValue,
    NoCreation,
    InconsistentValue,
    ResourceUnavailable,
    CommitFailed,
    UndoFailed,
    AuthorizationError,
    NotWritable,
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
        usize::try_from(c).ok().and_then(|i| STATUSES.get(i).copied()).unwrap_or(ErrorStatus::Other(c))
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
            NoAccess | NotWritable | NoCreation | InconsistentName | AuthorizationError => NoSuchName,
            ResourceUnavailable | CommitFailed | UndoFailed | Other(_) => GenErr,
        }
    }
}

/// The generic-trap field of a version 1 trap. Two are equal when their
/// numbers are, so `Other(3)` equals `LinkUp`.
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)] // each variant is the RFC 1157 name
pub enum GenericTrap {
    ColdStart,
    WarmStart,
    LinkDown,
    LinkUp,
    AuthenticationFailure,
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
        BasicPdu { request_id, error_status: ErrorStatus::NoError, error_index: 0, bindings }
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
        let n = usize::try_from(self.non_repeaters.max(0)).unwrap_or(0).min(self.bindings.len());
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
            Pdu::GetBulk(_) | Pdu::Inform(_) | Pdu::TrapV2(_) | Pdu::Report(_) => version == Version::V2c,
        }
    }

    /// Whether this PDU asks for a Response: Get, GetNext, Set, GetBulk
    /// and Inform.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Pdu::Get(_) | Pdu::GetNext(_) | Pdu::Set(_) | Pdu::GetBulk(_) | Pdu::Inform(_))
    }

    fn parse(t: u8, c: &[u8]) -> Result<Pdu, Error> {
        let mut r = Reader::new(c);
        if t == tag::TRAP_V1 {
            let enterprise = Oid::from_ber(r.expect(tag::OBJECT_IDENTIFIER)?)?;
            let agent_addr = r.expect(tag::IP_ADDRESS)?.try_into().map_err(|_| Error::Value(tag::IP_ADDRESS))?;
            let generic_trap = GenericTrap::from_code(r.int()?);
            let specific_trap = r.int()?;
            let Value::TimeTicks(time_stamp) = Value::from_ber(tag::TIME_TICKS, r.expect(tag::TIME_TICKS)?)? else {
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
            return Ok(Pdu::GetBulk(BulkPdu { request_id, non_repeaters: a, max_repetitions: b, bindings }));
        }
        let p = BasicPdu { request_id, error_status: ErrorStatus::from_code(a), error_index: b, bindings };
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

    /// The PDU's content before its bindings.
    fn head(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Pdu::TrapV1(t) => {
                write_tlv(&mut out, tag::OBJECT_IDENTIFIER, &t.enterprise.to_ber());
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
        out
    }
}

fn parse_bindings(c: &[u8]) -> Result<Vec<VarBind>, Error> {
    let mut list = Reader::new(c);
    let mut out = Vec::new();
    while !list.b.is_empty() {
        let mut r = Reader::new(list.expect(tag::SEQUENCE)?);
        let name = Oid::from_ber(r.expect(tag::OBJECT_IDENTIFIER)?)?;
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
    /// The community string, which works as a password. At most
    /// [`MAX_COMMUNITY`] bytes are written.
    pub community: Vec<u8>,
    /// What the message asks or says.
    pub pdu: Pdu,
}

impl Message {
    /// Reads the message that `b` holds, all of it and nothing more. A
    /// message in a version other than 1 or 2c, such as SNMPv3, gives
    /// [`Error::Unsupported`]. A PDU or value the version does not allow
    /// is still read; see [`Message::follows_version`].
    pub fn parse(b: &[u8]) -> Result<Message, Error> {
        let len = message_len(b)?.ok_or(Error::Truncated)?;
        let whole = b.get(..len).ok_or(Error::Truncated)?;
        if b.len() > len {
            return Err(Error::TrailingBytes);
        }
        let mut outer = Reader::new(whole);
        let mut r = Reader::new(outer.expect(tag::SEQUENCE)?);
        let version = Version::from_code(r.int()?)?;
        let community = r.expect(tag::OCTET_STRING)?;
        if community.len() > MAX_COMMUNITY {
            return Err(Error::Community(community.len()));
        }
        let (t, content) = r.next()?;
        let pdu = Pdu::parse(t, content)?;
        r.end()?;
        Ok(Message { version, community: community.to_vec(), pdu })
    }

    /// The message's bytes. The community is cut to [`MAX_COMMUNITY`]
    /// bytes, and bindings are dropped from the end until the message
    /// fits in [`MAX_MESSAGE`] bytes. A message read by
    /// [`Message::parse`] always fits whole.
    pub fn to_bytes(&self) -> Vec<u8> {
        let community = &self.community[..self.community.len().min(MAX_COMMUNITY)];
        let head = self.pdu.head();
        let bindings: Vec<Vec<u8>> = self.pdu.bindings().iter().map(VarBind::encode).collect();
        // Total size with the first k bindings, for k from all down to 0.
        let fixed = 3 + tlv_len(community.len());
        let total = |list: usize| tlv_len(fixed + tlv_len(head.len() + tlv_len(list)));
        let mut list: usize = bindings.iter().map(Vec::len).sum();
        let mut k = bindings.len();
        while k > 0 && total(list) > MAX_MESSAGE {
            k -= 1;
            list -= bindings[k].len();
        }
        let mut pdu = head;
        pdu.push(tag::SEQUENCE);
        write_len(&mut pdu, list);
        for b in &bindings[..k] {
            pdu.extend_from_slice(b);
        }
        let mut content = Vec::with_capacity(fixed + tlv_len(pdu.len()));
        write_int(&mut content, tag::INTEGER, self.version.code().into());
        write_tlv(&mut content, tag::OCTET_STRING, community);
        write_tlv(&mut content, self.pdu.tag(), &pdu);
        let mut out = Vec::with_capacity(tlv_len(content.len()));
        write_tlv(&mut out, tag::SEQUENCE, &content);
        out
    }

    /// Whether the PDU and every value it carries are allowed in the
    /// message's version (see [`Pdu::allowed_in`] and
    /// [`Value::allowed_in`]).
    pub fn follows_version(&self) -> bool {
        self.pdu.allowed_in(self.version) && self.pdu.bindings().iter().all(|b| b.value.allowed_in(self.version))
    }

    /// The Response that answers this request with `bindings`, with the
    /// same version, community and request ID, and no error. It is `None`
    /// if this message is not a request that gets a response in its
    /// version (see [`Pdu::is_confirmed`] and [`Pdu::allowed_in`]).
    ///
    /// Version 1 cannot carry Counter64 or the exception values. If one
    /// is among `bindings` in a version 1 answer, the answer becomes a
    /// noSuchName error at the first such binding. RFC 3584 (section
    /// 4.2.2) answers a Get that way, and a GetNext that ends in
    /// endOfMibView. For a version 1 GetNext it says to skip Counter64
    /// objects and return the next object that is not one; that walk is
    /// the world's to make, before it calls this. Whether all the answers fit in one
    /// message is left to the caller, who may answer tooBig with
    /// [`Message::error_response`].
    pub fn response(&self, bindings: Vec<VarBind>) -> Option<Message> {
        if !self.pdu.is_confirmed() || !self.pdu.allowed_in(self.version) {
            return None;
        }
        if self.version == Version::V1
            && let Some(i) = bindings.iter().position(|b| !b.value.allowed_in(Version::V1))
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
        if !self.pdu.is_confirmed() || !self.pdu.allowed_in(self.version) {
            return None;
        }
        let status = if self.version == Version::V1 { status.to_v1() } else { ErrorStatus::from_code(status.code()) };
        let too_big = status == ErrorStatus::TooBig;
        let index = if too_big { 0 } else { index };
        let bindings = if too_big && self.version == Version::V2c { Vec::new() } else { self.pdu.bindings().to_vec() };
        let request_id = self.pdu.request_id()?;
        Some(Message {
            version: self.version,
            community: self.community.clone(),
            pdu: Pdu::Response(BasicPdu { request_id, error_status: status, error_index: index, bindings }),
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
        all.push(VarBind::new(Oid(SYS_UP_TIME_0.to_vec()), Value::TimeTicks(uptime)));
        all.push(VarBind::new(Oid(SNMP_TRAP_OID_0.to_vec()), Value::ObjectIdentifier(trap)));
        all.extend(bindings);
        let body = BasicPdu::new(request_id, all);
        Message {
            version: Version::V2c,
            community: community.to_vec(),
            pdu: if inform { Pdu::Inform(body) } else { Pdu::TrapV2(body) },
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

/// Splits an SNMP-over-TCP byte stream (RFC 3430) into messages. Feed it
/// the bytes a connection reads, in order, and take messages out until it
/// has none. Each comes out as bytes, for [`Message::parse`]; a message
/// that does not parse leaves the stream intact.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start in `buf`. Messages are
    /// taken by moving this, not by shifting `buf`, so taking many small
    /// messages from one large feed stays linear.
    start: usize,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After an error the stream
    /// cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        // Drop the bytes already taken once they are at least half the
        // buffer, so each byte is moved a bounded number of times.
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole message's bytes, if one has come. It returns `None`
    /// when it needs more bytes. Bytes that cannot start a message, or a
    /// length over [`MAX_MESSAGE`], break the stream; it then keeps
    /// returning the same error. Taking a message out is linear in its
    /// size, however much is buffered behind it. The bytes waiting
    /// ([`Decoder::buffered`]) are never more than one message's beyond
    /// what one `feed` added, and the memory held is at most about twice
    /// that.
    pub fn next_message(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let rest = &self.buf[self.start..];
        match message_len(rest) {
            Ok(Some(len)) if rest.len() >= len => {
                let message = rest[..len].to_vec();
                self.start += len;
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                Some(Ok(message))
            }
            Ok(_) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(s: &str) -> Oid {
        s.parse().unwrap()
    }

    /// The version 2c GetRequest for sysDescr.0 from the module example.
    const GET_SYS_DESCR: [u8; 43] = [
        0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x1c, 0x02, 0x04, 0x12,
        0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
        0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];

    /// A version 1 coldStart trap from 10.0.0.1, enterprise
    /// 1.3.6.1.4.1.9, at tick 4242, community "public".
    const TRAP_COLD_START: [u8; 41] = [
        0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa4, 0x1a, 0x06, 0x06, 0x2b,
        0x06, 0x01, 0x04, 0x01, 0x09, 0x40, 0x04, 10, 0, 0, 1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x43, 0x02, 0x10,
        0x92, 0x30, 0x00,
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
        let basic =
            BasicPdu { request_id: -5, error_status: ErrorStatus::WrongType, error_index: 3, bindings: binds.clone() };
        let v1binds: Vec<VarBind> = binds.iter().filter(|b| b.value.allowed_in(Version::V1)).cloned().collect();
        vec![
            Message::parse(&GET_SYS_DESCR).unwrap(),
            Message { version: Version::V1, community: b"private".to_vec(), pdu: Pdu::Get(BasicPdu::new(1, vec![])) },
            Message { version: Version::V2c, community: vec![], pdu: Pdu::GetNext(basic.clone()) },
            Message { version: Version::V2c, community: b"c".to_vec(), pdu: Pdu::Response(basic.clone()) },
            Message {
                version: Version::V1,
                community: b"c".to_vec(),
                pdu: Pdu::Set(BasicPdu::new(i32::MAX, v1binds.clone())),
            },
            Message {
                version: Version::V1,
                community: b"public".to_vec(),
                pdu: Pdu::TrapV1(TrapV1Pdu {
                    enterprise: oid("1.3.6.1.4.1.9"),
                    agent_addr: [10, 0, 0, 1],
                    generic_trap: GenericTrap::LinkDown,
                    specific_trap: 0,
                    time_stamp: 4242,
                    bindings: v1binds,
                }),
            },
            Message {
                version: Version::V2c,
                community: b"public".to_vec(),
                pdu: Pdu::GetBulk(BulkPdu {
                    request_id: 9,
                    non_repeaters: 1,
                    max_repetitions: 10,
                    bindings: binds.clone(),
                }),
            },
            Message { version: Version::V2c, community: b"x".to_vec(), pdu: Pdu::Inform(basic.clone()) },
            Message::trap_v2(b"public", 77, 100, oid("1.3.6.1.6.3.1.1.5.1"), vec![], false),
            Message { version: Version::V2c, community: b"x".to_vec(), pdu: Pdu::Report(basic) },
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
            (u64::MAX as i128, &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
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
        assert_eq!(o.to_ber(), [0x81, 0x34, 0x03]);
        assert_eq!(Oid::from_ber(&[0x81, 0x34, 0x03]), Ok(o));
        let internet = oid("1.3.6.1");
        assert_eq!(internet.to_ber(), [0x2b, 0x06, 0x01]);
        assert_eq!(Oid::from_ber(&[0x00]).unwrap().arcs(), [0, 0]);
        let big = Oid::from_arcs(&[2, u32::MAX - 80, u32::MAX]).unwrap();
        assert_eq!(Oid::from_ber(&big.to_ber()), Ok(big));
        // Bad encodings.
        assert_eq!(Oid::from_ber(&[]), Err(Error::Oid));
        assert_eq!(Oid::from_ber(&[0x2b, 0x80, 0x01]), Err(Error::Oid));
        assert_eq!(Oid::from_ber(&[0x2b, 0x86]), Err(Error::Oid));
        assert_eq!(Oid::from_ber(&[0x2b, 0x90, 0x80, 0x80, 0x80, 0x00]), Err(Error::Oid));
        assert_eq!(Oid::from_ber(&[0x2b; MAX_OID_ARCS]), Err(Error::Oid));
        assert!(Oid::from_ber(&[0x2b; MAX_OID_ARCS - 1]).is_ok());
    }

    #[test]
    fn oid_text() {
        let o = oid("1.3.6.1.2.1.1.1.0");
        assert_eq!(o.to_string(), "1.3.6.1.2.1.1.1.0");
        assert_eq!(".1.3.6".parse::<Oid>(), Ok(oid("1.3.6")));
        assert_eq!("1".parse::<Oid>(), Err(OidError::TooShort));
        assert_eq!("".parse::<Oid>(), Err(OidError::Syntax));
        assert_eq!("1..3".parse::<Oid>(), Err(OidError::Syntax));
        assert_eq!("1.3.".parse::<Oid>(), Err(OidError::Syntax));
        assert_eq!("1.+3".parse::<Oid>(), Err(OidError::Syntax));
        assert_eq!("1.3.4294967296".parse::<Oid>(), Err(OidError::Syntax));
        assert_eq!("3.1".parse::<Oid>(), Err(OidError::FirstArcs));
        assert_eq!("1.40".parse::<Oid>(), Err(OidError::FirstArcs));
        assert_eq!("2.4294967216".parse::<Oid>(), Err(OidError::FirstArcs));
        let long = vec!["1"; MAX_OID_ARCS + 1].join(".");
        assert_eq!(long.parse::<Oid>(), Err(OidError::TooLong));
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
        assert_eq!(m.to_bytes(), GET_SYS_DESCR);
        assert!(m.follows_version());
    }

    #[test]
    fn module_example_reply() {
        let request = Message::parse(&GET_SYS_DESCR).unwrap();
        let answers = vec![VarBind::new(oid("1.3.6.1.2.1.1.1.0"), Value::OctetString(b"pump controller".to_vec()))];
        let reply = request.response(answers).unwrap().to_bytes();
        let mut want = vec![0x30, 0x38, 0x02, 0x01, 0x01, 0x04, 0x06];
        want.extend_from_slice(b"public");
        want.extend_from_slice(&[0xa2, 0x2b, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
        want.extend_from_slice(&[0x30, 0x1d, 0x30, 0x1b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
        want.extend_from_slice(&[0x04, 0x0f]);
        want.extend_from_slice(b"pump controller");
        assert_eq!(reply, want);
    }

    #[test]
    fn value_encodings() {
        let enc = |v: &Value| {
            let mut out = Vec::new();
            v.write(&mut out);
            out
        };
        assert_eq!(enc(&Value::Counter32(u32::MAX)), [0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(enc(&Value::IpAddress([10, 1, 2, 3])), [0x40, 0x04, 10, 1, 2, 3]);
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
        assert_eq!(Value::from_ber(tag::NULL, &[0]), Err(Error::Value(tag::NULL)));
        assert_eq!(Value::from_ber(tag::END_OF_MIB_VIEW, &[0]), Err(Error::Value(tag::END_OF_MIB_VIEW)));
        assert_eq!(Value::from_ber(tag::IP_ADDRESS, &[1, 2, 3]), Err(Error::Value(tag::IP_ADDRESS)));
        assert_eq!(Value::from_ber(tag::COUNTER32, &[0xff]), Err(Error::Integer));
        assert_eq!(Value::from_ber(tag::GAUGE32, &[1, 0, 0, 0, 0]), Err(Error::Integer));
        assert_eq!(Value::from_ber(tag::INTEGER, &[0, 0x80, 0, 0, 0]), Err(Error::Integer));
        assert_eq!(Value::from_ber(tag::COUNTER64, &[1, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Integer));
        assert_eq!(Value::from_ber(0x45, &[]), Err(Error::UnexpectedTag(0x45)));
        assert_eq!(Value::from_ber(0x24, &[]), Err(Error::UnexpectedTag(0x24)));
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
        assert_eq!(m.to_bytes(), bytes);
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
        let msg = Message { version: Version::V2c, community: b"public".to_vec(), pdu: Pdu::GetBulk(req.clone()) };
        assert_eq!(Message::parse(&msg.to_bytes()), Ok(msg.clone()));
        assert!(msg.follows_version());
        assert_eq!(msg.to_bytes()[13], tag::GET_BULK_REQUEST);
        // Out-of-range fields count as 0 or all.
        let odd = BulkPdu { non_repeaters: 9, max_repetitions: -4, ..req.clone() };
        assert_eq!(odd.split().0.len(), 3);
        assert_eq!(odd.split().2, 0);
        let neg = BulkPdu { non_repeaters: -1, ..req };
        assert_eq!(neg.split().0.len(), 0);
        // GetBulk in version 1 is read but breaks the version, and gets no response.
        let v1 = Message { version: Version::V1, ..msg };
        assert!(!v1.follows_version());
        assert_eq!(Message::parse(&v1.to_bytes()), Ok(v1.clone()));
        assert_eq!(v1.response(vec![]), None);
    }

    #[test]
    fn trap_v2_and_inform() {
        let m = Message::trap_v2(
            b"public",
            5,
            900,
            oid("1.3.6.1.6.3.1.1.5.3"),
            vec![VarBind::new(oid("1.3.6.1.2.1.2.2.1.1.2"), Value::Integer(2))],
            false,
        );
        let b = m.pdu.bindings();
        assert_eq!(b[0], VarBind::new(Oid::from_arcs(SYS_UP_TIME_0).unwrap(), Value::TimeTicks(900)));
        assert_eq!(b[1].name.arcs(), SNMP_TRAP_OID_0);
        assert_eq!(b.len(), 3);
        assert_eq!(Message::parse(&m.to_bytes()), Ok(m.clone()));
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
        assert_eq!((p.error_status, p.error_index, p.request_id), (ErrorStatus::NoAccess, 1, 0x12345678));
        assert_eq!(p.bindings, get.pdu.bindings());
        let big = get.error_response(ErrorStatus::TooBig, 0).unwrap();
        assert!(big.pdu.bindings().is_empty());
        // Version 1 maps version 2 statuses and refuses version 2 values.
        let v1 = Message { version: Version::V1, ..get.clone() };
        let Pdu::Response(p) = v1.error_response(ErrorStatus::NotWritable, 1).unwrap().pdu else { panic!() };
        assert_eq!(p.error_status, ErrorStatus::NoSuchName);
        let answers = vec![VarBind::new(oid("1.3.6.1.2.1.1.1.0"), Value::NoSuchObject)];
        let Pdu::Response(p) = v1.response(answers.clone()).unwrap().pdu else { panic!() };
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::NoSuchName, 1));
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
        assert_eq!(ErrorStatus::AuthorizationError.to_v1(), ErrorStatus::NoSuchName);
        assert_eq!(ErrorStatus::ReadOnly.to_v1(), ErrorStatus::ReadOnly);
        assert_eq!(ErrorStatus::Other(99).to_v1(), ErrorStatus::GenErr);
        for c in 0..19 {
            assert!(ErrorStatus::from_code(c).to_v1().code() <= 5);
        }
    }

    #[test]
    fn round_trips() {
        for m in samples() {
            let b = m.to_bytes();
            assert_eq!(Message::parse(&b), Ok(m.clone()), "{m:?}");
            let (e, used) = Element::parse(&b).unwrap();
            assert_eq!(used, b.len());
            assert_eq!(e.to_bytes().unwrap(), b);
        }
    }

    #[test]
    fn truncated_prefixes() {
        for m in samples() {
            let b = m.to_bytes();
            for n in 0..b.len() {
                assert_eq!(Message::parse(&b[..n]), Err(Error::Truncated), "{n} of {}", b.len());
                assert_eq!(Element::parse(&b[..n]), Err(Error::Truncated));
                let len = message_len(&b[..n]).unwrap();
                assert!(len.is_none() || len == Some(b.len()));
                let mut d = Decoder::new();
                d.feed(&b[..n]);
                assert_eq!(d.next_message(), None);
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
        assert_eq!(p(&[0x30, 0x03, 0x04, 0x01, 0x00]), Err(Error::UnexpectedTag(0x04)));
        let mut pdu = GET_SYS_DESCR;
        pdu[13] = 0xa9;
        assert_eq!(p(&pdu), Err(Error::UnexpectedTag(0xa9)));
        assert_eq!(p(&[0x3f, 0x00]), Err(Error::UnexpectedTag(0x3f)));
        assert_eq!(Header::parse(&[0x1f]), Err(Error::UnexpectedTag(0x1f)));
        // Lengths.
        assert_eq!(p(&[0x30, 0x80, 0x00, 0x00]), Err(Error::Length));
        assert_eq!(p(&[0x30, 0x85, 0, 0, 0, 0, 1]), Err(Error::Length));
        assert_eq!(p(&[0x30, 0x83, 0x01, 0x00, 0x00]), Err(Error::TooLong(0x10000)));
        assert_eq!(p(&[0x30, 0x82, 0xff, 0xff]), Err(Error::TooLong(MAX_MESSAGE + 4)));
        assert_eq!(
            Header::parse(&[0x04, 0x84, 0, 0, 0xff, 0xff]),
            Ok(Some(Header { tag: 4, header_len: 6, content_len: 0xffff }))
        );
        // Long-form lengths that are not minimal are still read.
        let mut long = vec![0x30, 0x81, 0x29];
        long.extend_from_slice(&GET_SYS_DESCR[2..]);
        assert_eq!(p(&long), Message::parse(&GET_SYS_DESCR));
        // Versions: SNMPv3 is refused, and an out-of-range version is a bad integer.
        let mut v3 = GET_SYS_DESCR;
        v3[4] = 3;
        assert_eq!(p(&v3), Err(Error::Unsupported(3)));
        assert_eq!(p(&[0x30, 0x07, 0x02, 0x05, 0x01, 0, 0, 0, 0]), Err(Error::Integer));
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
        // A community too long.
        let m = Message { version: Version::V2c, community: vec![b'a'; 300], pdu: Pdu::Get(BasicPdu::new(1, vec![])) };
        let b = m.to_bytes();
        assert_eq!(Message::parse(&b).unwrap().community.len(), MAX_COMMUNITY);
        let mut c = vec![0x30, 0x82, 0x01, 0x40, 0x02, 0x01, 0x01, 0x04, 0x82, 0x01, 0x2c];
        c.extend_from_slice(&[b'a'; 300]);
        c.extend_from_slice(&[0xa0, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00]);
        assert_eq!(c.len(), 4 + 0x140);
        assert_eq!(p(&c), Err(Error::Community(300)));
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
            Error::Community(1),
            Error::Unsupported(3),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
        for e in [OidError::TooShort, OidError::TooLong, OidError::FirstArcs, OidError::Syntax] {
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
        let mut e = Element::Primitive { tag: 0x04, content: vec![] };
        for _ in 0..=MAX_DEPTH {
            e = Element::Constructed { tag: 0x30, children: vec![e] };
        }
        assert_eq!(e.to_bytes(), Err(Error::TooDeep));
        let Element::Constructed { children, .. } = e else { panic!() };
        let ok = children[0].to_bytes().unwrap();
        assert_eq!(Element::parse(&ok), Ok((children[0].clone(), ok.len())));
        assert_eq!(Element::Primitive { tag: 0x30, content: vec![] }.to_bytes(), Err(Error::UnexpectedTag(0x30)));
        assert_eq!(Element::Constructed { tag: 0x04, children: vec![] }.to_bytes(), Err(Error::UnexpectedTag(0x04)));
        assert_eq!(Element::Primitive { tag: 0x1f, content: vec![] }.to_bytes(), Err(Error::UnexpectedTag(0x1f)));
        let huge = Element::Primitive { tag: 0x04, content: vec![0; MAX_MESSAGE + 1] };
        assert_eq!(huge.to_bytes(), Err(Error::TooLong(MAX_MESSAGE + 1)));
        let wide = Element::Constructed {
            tag: 0x30,
            children: vec![Element::Primitive { tag: 0x04, content: vec![0; 40_000] }; 2],
        };
        assert!(matches!(wide.to_bytes(), Err(Error::TooLong(_))));
        let fits = Element::Primitive { tag: 0x04, content: vec![7; MAX_MESSAGE] };
        let b = fits.to_bytes().unwrap();
        assert_eq!(Element::parse(&b), Ok((fits, b.len())));
    }

    #[test]
    fn too_big_responses() {
        // RFC 3416, section 4.2.1: error-index zero and no bindings.
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let Pdu::Response(p) = get.error_response(ErrorStatus::TooBig, 3).unwrap().pdu else { panic!() };
        assert_eq!((p.error_status, p.error_index), (ErrorStatus::TooBig, 0));
        assert!(p.bindings.is_empty());
        // RFC 1157, section 4.1.2: a GetResponse "of identical form" to the
        // request, error-index zero, so it carries the request's bindings.
        let v1 = Message { version: Version::V1, ..get.clone() };
        let Pdu::Response(p) = v1.error_response(ErrorStatus::TooBig, 3).unwrap().pdu else { panic!() };
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
        let (e, used) = Element::parse(&deep).unwrap();
        assert_eq!(used, deep.len());
        assert_eq!(e.to_bytes(), Ok(deep.clone()));
        let deeper = [vec![0x30, deep.len() as u8], deep].concat();
        assert_eq!(Element::parse(&deeper), Err(Error::TooDeep));
        // An SNMP message nests 4 deep: message, PDU, binding list, binding.
        let mut levels = 0;
        let (mut e, _) = Element::parse(&GET_SYS_DESCR).unwrap();
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
        assert_eq!(rs.hash_one(ErrorStatus::Other(5)), rs.hash_one(ErrorStatus::GenErr));
        assert_eq!(rs.hash_one(GenericTrap::Other(6)), rs.hash_one(GenericTrap::EnterpriseSpecific));
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let mut m = get.error_response(ErrorStatus::Other(5), 1).unwrap();
        assert_eq!(Message::parse(&m.to_bytes()), Ok(m.clone()));
        let Pdu::Response(p) = &mut m.pdu else { panic!() };
        p.error_status = ErrorStatus::Other(12);
        assert_eq!(Message::parse(&m.to_bytes()), Ok(m.clone()));
        let trap = Message::parse(&TRAP_COLD_START).unwrap();
        let mut t = trap.clone();
        let Pdu::TrapV1(body) = &mut t.pdu else { panic!() };
        body.generic_trap = GenericTrap::Other(0);
        assert_eq!(t, trap);
        assert_eq!(Message::parse(&t.to_bytes()), Ok(t.clone()));
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
        let h = Header { tag: 4, header_len: 6, content_len: usize::MAX };
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
        m.pdu.bindings_mut().push(VarBind::null(oid("1.3.6.1.2.1.1.5.0")));
        assert_eq!(m.pdu.bindings().len(), 2);
        let (e, _) = Element::parse(&GET_SYS_DESCR).unwrap();
        assert_eq!(e.tag(), tag::SEQUENCE);
        let mut d = Decoder::new();
        d.feed(&GET_SYS_DESCR[..10]);
        let mut copy = d.clone();
        copy.feed(&GET_SYS_DESCR[10..]);
        assert_eq!(copy.next_message(), Some(Ok(GET_SYS_DESCR.to_vec())));
        assert_eq!(d.buffered(), 10);
    }

    #[test]
    fn decoder_takes_many_small_messages_in_linear_time() {
        // One feed of 2,000,000 two-byte messages. Draining each from the
        // front of the buffer moves 4 TB in all; this must take moments.
        let n = 2_000_000;
        let stream: Vec<u8> = [0x30, 0x00].repeat(n);
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut count = 0;
        while let Some(m) = d.next_message() {
            assert_eq!(m.unwrap(), [0x30, 0x00]);
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
        // Feeding after a partial take keeps the order.
        d.feed(&GET_SYS_DESCR);
        d.feed(&GET_SYS_DESCR[..5]);
        assert_eq!(d.next_message(), Some(Ok(GET_SYS_DESCR.to_vec())));
        d.feed(&GET_SYS_DESCR[5..]);
        assert_eq!(d.next_message(), Some(Ok(GET_SYS_DESCR.to_vec())));
        assert_eq!(d.next_message(), None);
    }

    #[test]
    fn writer_drops_bindings_to_fit() {
        let binds = (0..10)
            .map(|i| VarBind::new(oid("1.3.6.1.2.1.1.5").child(i).unwrap(), Value::OctetString(vec![b'x'; 10_000])))
            .collect();
        let get = Message::parse(&GET_SYS_DESCR).unwrap();
        let reply = get.response(binds).unwrap();
        let b = reply.to_bytes();
        assert!(b.len() <= MAX_MESSAGE);
        let back = Message::parse(&b).unwrap();
        assert_eq!(back.pdu.bindings().len(), 6);
        assert_eq!(back.pdu.bindings(), &reply.pdu.bindings()[..6]);
        let one = get.response(vec![VarBind::new(oid("1.3.6"), Value::Opaque(vec![0; MAX_MESSAGE]))]).unwrap();
        assert!(Message::parse(&one.to_bytes()).unwrap().pdu.bindings().is_empty());
        // Right at the limit: with this request, a binding of 1.3.6 to n
        // bytes makes a message of n + 47 bytes.
        for extra in 0..40 {
            let n = MAX_MESSAGE - 40 - extra;
            let m = get.response(vec![VarBind::new(oid("1.3.6"), Value::OctetString(vec![1; n]))]).unwrap();
            let b = m.to_bytes();
            let back = Message::parse(&b).unwrap();
            if extra >= 7 {
                assert_eq!(b.len(), n + 47);
                assert_eq!(back, m);
            } else {
                assert!(back.pdu.bindings().is_empty());
            }
        }
    }

    #[test]
    fn tlv_len_matches_writer() {
        for n in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536, 1 << 24] {
            let mut out = Vec::new();
            write_len(&mut out, n);
            assert_eq!(tlv_len(n), 1 + out.len() + n, "{n}");
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let msgs: Vec<Vec<u8>> = samples().iter().map(Message::to_bytes).collect();
        let stream = msgs.concat();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(m) = d.next_message() {
                got.push(m.unwrap());
            }
        }
        assert_eq!(got, msgs);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        d.feed(&[0x31, 0x00]);
        assert_eq!(d.next_message(), Some(Err(Error::UnexpectedTag(0x31))));
        d.feed(&msgs[0]);
        assert_eq!(d.next_message(), Some(Err(Error::UnexpectedTag(0x31))));
        assert_eq!(d.buffered(), 0);
        let mut d = Decoder::new();
        d.feed(&[0x30, 0x83, 0x01, 0x00, 0x00]);
        assert_eq!(d.next_message(), Some(Err(Error::TooLong(0x10000))));
    }

    /// A small deterministic generator, so the fuzz loop is the same on
    /// every run.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
    }

    fn check(data: &[u8]) {
        if let Ok(m) = Message::parse(data) {
            let b = m.to_bytes();
            assert!(b.len() <= data.len());
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            for r in
                [m.response(m.pdu.bindings().to_vec()), m.error_response(ErrorStatus::GenErr, 1)].into_iter().flatten()
            {
                let back = Message::parse(&r.to_bytes()).unwrap();
                assert!(r.pdu.bindings().starts_with(back.pdu.bindings()));
            }
        }
        if let Ok((e, used)) = Element::parse(data) {
            assert!(used <= data.len());
            let b = e.to_bytes().unwrap();
            assert_eq!(Element::parse(&b), Ok((e, b.len())));
        }
        if let Ok(s) = std::str::from_utf8(data)
            && let Ok(o) = s.parse::<Oid>()
        {
            assert_eq!(o.to_string().parse::<Oid>(), Ok(o));
        }
        if let Ok(o) = Oid::from_ber(data) {
            assert_eq!(Oid::from_ber(&o.to_ber()), Ok(o));
        }
        // The stream, split two ways: all at once, and a byte at a time.
        // Both give the same messages, then the same error or the same
        // bytes held.
        fn take(d: &mut Decoder, out: &mut Vec<Vec<u8>>) -> Option<Error> {
            while let Some(r) = d.next_message() {
                match r {
                    Ok(m) => out.push(m),
                    Err(e) => return Some(e),
                }
            }
            None
        }
        let mut whole = Decoder::new();
        whole.feed(data);
        let mut messages = Vec::new();
        let whole_err = take(&mut whole, &mut messages);
        let mut bytewise = Decoder::new();
        let mut again = Vec::new();
        let mut bytewise_err = None;
        for b in data {
            bytewise.feed(std::slice::from_ref(b));
            if let Some(e) = take(&mut bytewise, &mut again) {
                bytewise_err.get_or_insert(e);
            }
        }
        assert_eq!(messages, again);
        assert_eq!(whole_err, bytewise_err);
        assert_eq!(whole.buffered(), bytewise.buffered());
        // Without an error every byte is in a message or still held;
        // after one, nothing is held.
        match whole_err {
            None => assert_eq!(messages.iter().map(Vec::len).sum::<usize>() + whole.buffered(), data.len()),
            Some(_) => assert_eq!(whole.buffered(), 0),
        }
        for m in &messages {
            let _ = Message::parse(m);
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x5eed);
        let seeds: Vec<Vec<u8>> = samples().iter().map(Message::to_bytes).collect();
        for i in 0..6000 {
            let data: Vec<u8> = if i % 3 == 0 {
                let n = (rng.next() % 96) as usize;
                (0..n).map(|_| rng.next() as u8).collect()
            } else {
                // Valid messages, one to three of them as a stream, with a
                // few bytes changed, to reach deeper.
                let count = if i % 3 == 1 { 1 } else { 1 + rng.next() % 3 };
                let mut d = Vec::new();
                for _ in 0..count {
                    d.extend_from_slice(&seeds[(rng.next() as usize) % seeds.len()]);
                }
                for _ in 0..rng.next() % 4 {
                    let at = (rng.next() as usize) % d.len();
                    d[at] = rng.next() as u8;
                }
                if rng.next().is_multiple_of(4) {
                    d.truncate((rng.next() as usize) % (d.len() + 1));
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
