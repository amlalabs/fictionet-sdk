//! FAST (FIX Adapted for STreaming) 1.1 compresses template-based messages.
//! It is used for FIX market data, often over UDP multicast.
//!
//! The source is the public [FIX Protocol Ltd. specification, 2006-12-20][spec]:
//! sections 6–7 define templates and dictionaries, sections 10.2–10.7 define
//! wire encodings, and appendices 1–2 define the template XML grammar.
//! No exchange templates or session control protocol are included.
//!
//! [`Messages`] reads the message stream of section 10. [`BlockMessages`] reads
//! the block form, `block ::= BlockSize message+`, and refuses a message that
//! crosses a block boundary. [`Blocks`] yields raw block payloads.
//! [`Encoder`] writes messages using the same templates. Resets are explicit
//! and must occur at matching message boundaries at both endpoints (§6.3.1).
//! Packet feeds usually reset dictionaries per packet. For those feeds, worlds
//! call `stream.decoder().reset()` between datagrams when using [`Messages`],
//! or `stream.decoder().messages().reset()` with [`BlockMessages`].
//! Primitive units implement [`Wire`]. A message requires template and session
//! state, so its writer is [`Encoder::write`]. Reportable encoding errors,
//! including nonminimal encodings, are refused. Block sizes may be overlong (§10).
//!
//! ```
//! use fictionet::stdlib::{codec::{Stream, Wire}, fast::*};
//! let templates = Templates::from_xml(br#"
//! <templates xmlns="http://www.fixprotocol.org/ns/fast/td/1.1">
//!   <template name="Sample" id="1">
//!     <uInt32 name="number"><increment value="1"/></uInt32>
//!   </template>
//! </templates>"#)?;
//! let message = Message { template_id: 1, fields: vec![Value::UInt32(1)] };
//! let mut encoder = Encoder::new(templates.clone());
//! let mut bytes = Vec::new();
//! encoder.write(&message, &mut bytes)?;
//! let mut stream = Stream::new(Messages::new(templates));
//! assert_eq!(stream.push(&bytes), bytes.len());
//! assert_eq!(stream.next().transpose()?.unwrap(), message);
//! assert_eq!(UInt32(128).to_bytes()?, [1, 0x80]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [spec]: https://www.fixtrading.org/wp-content/uploads/download-manager-files/FAST-Specification-1-x-1.pdf

use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::xml;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Maximum encoded bytes in a message or an encoder's temporary output.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;
/// Maximum bytes in one ASCII string, UTF-8 string, or byte vector.
pub const MAX_STRING_BYTES: usize = 64 << 10;
/// Maximum XML document bytes, including comments and foreign extensions.
pub const MAX_TEMPLATE_BYTES: usize = 1 << 20;
/// Maximum templates in a template set.
pub const MAX_TEMPLATES: usize = 256;
/// Maximum instructions and component fields in a template set.
pub const MAX_FIELDS: usize = 4096;
/// Maximum XML elements, including operators and foreign extensions.
pub const MAX_XML_NODES: usize = 16384;
/// Maximum nesting of XML elements, groups, sequences, or template calls.
pub const MAX_DEPTH: usize = 32;
/// Maximum bytes in a name, namespace, dictionary name, or auxiliary ID.
pub const MAX_NAME_BYTES: usize = 256;
/// Maximum entries across all dictionary scopes.
pub const MAX_DICTIONARY_ENTRIES: usize = 4096;
/// Maximum precomputed field-to-dictionary bindings across application types.
pub const MAX_DICTIONARY_BINDINGS: usize = 16384;
/// Maximum bytes of dictionary values, excluding fixed entry metadata.
pub const MAX_DICTIONARY_BYTES: usize = 1 << 20;
/// Maximum elements in one sequence.
pub const MAX_SEQUENCE_LENGTH: usize = 4096;
/// Maximum field values and sequence rows expanded in one message.
pub const MAX_VALUES: usize = 16384;
/// Maximum aggregate bytes of decoded string and byte vector values.
pub const MAX_VALUE_BYTES: usize = 1 << 20;
/// Maximum bytes in a presence map, or seven times as many logical bits.
pub const MAX_PMAP_BYTES: usize = 1024;
/// Maximum bytes in an integer, including 65-bit deltas and nullable uInt64.
pub const MAX_INTEGER_BYTES: usize = 10;
/// FAST 1.1 template definition namespace (§3.1).
pub const TEMPLATE_NAMESPACE: &str = "http://www.fixprotocol.org/ns/fast/td/1.1";

/// A syntax, state, range, or resource limit failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends before a complete unit.
    Truncated,
    /// Bytes follow an exact wire unit.
    Trailing,
    /// An integer, string, or map is not minimally encoded (§10).
    Overlong,
    /// A numeric value exceeds its field range (§6.2).
    Range,
    /// ASCII or UTF-8 bytes are invalid (§10.6).
    Text,
    /// A named resource limit was exceeded.
    Limit(&'static str),
    /// XML is malformed or does not satisfy the FAST template grammar.
    Template,
    /// An operator is invalid for its type or initial value (§6.3).
    Operator,
    /// A template name or wire ID is unknown (§6.4).
    UnknownTemplate,
    /// A mandatory omitted field has no previous or initial value (§6.3).
    Undefined,
    /// An empty dictionary entry cannot supply this field (§6.3).
    Empty,
    /// Dictionary entry and field types differ (§6.3.1).
    DictionaryType,
    /// A presence map contains unused set bits (§10.5).
    Presence,
    /// A value has the wrong type, shape, presence, or constant value.
    Value,
    /// A string delta removes more bytes than its base contains (§6.3.7).
    Subtraction,
    /// A block has zero payload bytes (§10, D12).
    BlockSize,
    /// A message does not end within its block (§10).
    BlockBoundary,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FAST: {self:?}")
    }
}
impl core::error::Error for Error {}

fn limit(n: usize, max: usize, name: &'static str) -> Result<(), Error> {
    if n > max {
        Err(Error::Limit(name))
    } else {
        Ok(())
    }
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Range)
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    limit(
        add(out.len(), bytes.len())?,
        MAX_MESSAGE_BYTES,
        "MAX_MESSAGE_BYTES",
    )?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// A decimal preserving its exponent and mantissa (§§6.2.2, 10.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decimal {
    /// Base ten exponent, from -63 through 63.
    pub exponent: i32,
    /// Signed 64-bit mantissa. Wire values are not normalized.
    pub mantissa: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    I32,
    U32,
    I64,
    U64,
    Decimal,
    Ascii,
    Unicode,
    Bytes,
}
impl Kind {
    fn integer(self) -> bool {
        matches!(self, Self::I32 | Self::U32 | Self::I64 | Self::U64)
    }
    fn signed(self) -> bool {
        matches!(self, Self::I32 | Self::I64)
    }
    fn range(self) -> (i128, i128) {
        match self {
            Self::I32 => (i32::MIN.into(), i32::MAX.into()),
            Self::U32 => (0, u32::MAX.into()),
            Self::I64 => (i64::MIN.into(), i64::MAX.into()),
            Self::U64 => (0, u64::MAX.into()),
            _ => (0, 0),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Atom {
    Null,
    Num(i128),
    Decimal(Decimal),
    Bytes(Vec<u8>),
}
impl Atom {
    fn bytes(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            _ => 0,
        }
    }
}

// A probe remembers only an input position. It never owns input. Retrying a
// partial ASCII entity resumes scanning; integer retries inspect at most 10 bytes.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    probe: &'a mut usize,
}
impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        limit(add(self.pos, 1)?, MAX_MESSAGE_BYTES, "MAX_MESSAGE_BYTES")?;
        let b = self.input.get(self.pos).copied().ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn integer(&mut self, signed: bool, nullable: bool) -> Result<Option<i128>, Error> {
        let first = self.byte()?;
        let mut b = first;
        let mut n = if signed && first & 0x40 != 0 {
            -1i128
        } else {
            0
        };
        for count in 0..MAX_INTEGER_BYTES {
            if count > 0 {
                b = self.byte()?;
                if count == 1
                    && ((first == 0 && (!signed || b & 0x40 == 0))
                        || (signed && first == 0x7f && b & 0x40 != 0))
                {
                    return Err(Error::Overlong);
                }
            }
            n = n
                .checked_mul(128)
                .and_then(|n| n.checked_add(i128::from(b & 0x7f)))
                .ok_or(Error::Range)?;
            if b & 0x80 != 0 {
                return Ok(if nullable && n == 0 {
                    None
                } else {
                    Some(if nullable && n > 0 { n - 1 } else { n })
                });
            }
        }
        Err(Error::Range)
    }
    fn bytes(&mut self, ascii: bool, nullable: bool, scan: bool) -> Result<Atom, Error> {
        let (start, end) = if ascii {
            let start = self.pos;
            let mut end = (*self.probe).max(start);
            loop {
                limit(
                    end.saturating_sub(start),
                    MAX_STRING_BYTES + 2,
                    "MAX_STRING_BYTES",
                )?;
                limit(add(end, 1)?, MAX_MESSAGE_BYTES, "MAX_MESSAGE_BYTES")?;
                let Some(b) = self.input.get(end) else {
                    *self.probe = end;
                    return Err(Error::Truncated);
                };
                end += 1;
                if b & 0x80 != 0 {
                    break;
                }
            }
            self.pos = end;
            *self.probe = 0;
            let mut data_start = start;
            if self.input.get(data_start).is_some_and(|b| b & 0x7f == 0) {
                data_start += 1;
                if nullable && data_start == end {
                    return Ok(Atom::Null);
                }
                if nullable {
                    if self.input.get(data_start).is_none_or(|b| b & 0x7f != 0) {
                        return Err(Error::Overlong);
                    }
                    data_start += 1;
                }
                if data_start < end && self.input.get(data_start).is_none_or(|b| b & 0x7f != 0) {
                    return Err(Error::Overlong);
                }
            }
            (data_start, end)
        } else {
            let Some(n) = self.integer(false, nullable)? else {
                return Ok(Atom::Null);
            };
            let n = usize::try_from(n).map_err(|_| Error::Range)?;
            limit(n, MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
            let start = self.pos;
            let end = add(start, n)?;
            limit(end, MAX_MESSAGE_BYTES, "MAX_MESSAGE_BYTES")?;
            if end > self.input.len() {
                return Err(Error::Truncated);
            }
            self.pos = end;
            (start, end)
        };
        limit(end - start, MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
        if scan {
            return Ok(Atom::Bytes(Vec::new()));
        }
        let bytes = self.input.get(start..end).ok_or(Error::Truncated)?;
        Ok(Atom::Bytes(if ascii {
            bytes.iter().map(|b| b & 0x7f).collect()
        } else {
            bytes.to_vec()
        }))
    }
    fn raw(&mut self, kind: Kind, optional: bool, scan: bool) -> Result<Atom, Error> {
        let value = if kind.integer() {
            match self.integer(kind.signed(), optional)? {
                Some(n) => Atom::Num(n),
                None => Atom::Null,
            }
        } else if kind == Kind::Decimal {
            match self.integer(true, optional)? {
                None => Atom::Null,
                Some(exponent) => Atom::Decimal(Decimal {
                    exponent: i32::try_from(exponent).map_err(|_| Error::Range)?,
                    mantissa: i64::try_from(self.integer(true, false)?.ok_or(Error::Value)?)
                        .map_err(|_| Error::Range)?,
                }),
            }
        } else {
            self.bytes(kind == Kind::Ascii, optional, scan)?
        };
        validate_atom(kind, optional, &value)?;
        Ok(value)
    }
}
fn validate_atom(kind: Kind, optional: bool, value: &Atom) -> Result<(), Error> {
    match value {
        Atom::Null if optional => Ok(()),
        Atom::Num(n) if kind.integer() => {
            let (min, max) = kind.range();
            if *n < min || *n > max {
                Err(Error::Range)
            } else {
                Ok(())
            }
        }
        Atom::Decimal(d) if kind == Kind::Decimal => {
            if !(-63..=63).contains(&d.exponent) {
                Err(Error::Range)
            } else {
                Ok(())
            }
        }
        Atom::Bytes(b) if matches!(kind, Kind::Ascii | Kind::Unicode | Kind::Bytes) => {
            limit(b.len(), MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
            if (kind == Kind::Ascii && !b.is_ascii())
                || (kind == Kind::Unicode && std::str::from_utf8(b).is_err())
            {
                Err(Error::Text)
            } else {
                Ok(())
            }
        }
        _ => Err(Error::Value),
    }
}
fn put_integer(mut n: i128, signed: bool, nullable: bool, out: &mut Vec<u8>) -> Result<(), Error> {
    if nullable && n >= 0 {
        n = n.checked_add(1).ok_or(Error::Range)?;
    }
    let mut bytes = [0u8; MAX_INTEGER_BYTES];
    let mut pos = MAX_INTEGER_BYTES;
    loop {
        pos = pos.checked_sub(1).ok_or(Error::Range)?;
        let b = (n & 0x7f) as u8;
        *bytes.get_mut(pos).ok_or(Error::Range)? = b;
        n >>= 7;
        if if signed {
            (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0)
        } else {
            n == 0
        } {
            break;
        }
    }
    if let Some(last) = bytes.last_mut() {
        *last |= 0x80;
    }
    append(out, bytes.get(pos..).ok_or(Error::Range)?)
}
fn put_bytes(bytes: &[u8], ascii: bool, optional: bool, out: &mut Vec<u8>) -> Result<(), Error> {
    limit(bytes.len(), MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
    if !ascii {
        put_integer(bytes.len() as i128, false, optional, out)?;
        return append(out, bytes);
    }
    if !bytes.is_ascii() {
        return Err(Error::Text);
    }
    if bytes.is_empty() || bytes.first() == Some(&0) {
        append(out, if optional { &[0, 0] } else { &[0] })?;
    }
    append(out, bytes)?;
    *out.last_mut().ok_or(Error::Value)? |= 0x80;
    Ok(())
}
fn put_raw(kind: Kind, optional: bool, value: &Atom, out: &mut Vec<u8>) -> Result<(), Error> {
    validate_atom(kind, optional, value)?;
    match value {
        Atom::Null => append(out, &[0x80]),
        Atom::Num(n) => put_integer(*n, kind.signed(), optional, out),
        Atom::Decimal(d) => {
            put_integer(d.exponent.into(), true, optional, out)?;
            put_integer(d.mantissa.into(), true, false, out)
        }
        Atom::Bytes(b) => put_bytes(b, kind == Kind::Ascii, optional, out),
    }
}

/// A nullable wire unit (§10.4). `None` writes the one-byte NULL encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nullable<T>(
    /// The present unit, or `None` for NULL.
    pub Option<T>,
);
macro_rules! unit {
    ($name:ident, $ty:ty, $kind:ident, $doc:literal, $to:expr, $from:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(#[doc = "The decoded value."] pub $ty);
        impl Wire for $name {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads one exact non-nullable unit (§10.6). Refuses truncation,
            /// trailing bytes, overlong forms, invalid text, and named limits.
            fn parse(input: &[u8]) -> Result<Self, Error> {
                let a = parse_atom(input, Kind::$kind, false)?;
                ($from)(a).map(Self)
            }
            /// Appends one unit (§10.6). Refuses invalid text, out-of-range
            /// values, and named limits. Failure leaves `out` unchanged.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                unit_limit(&self.0)?;
                write_atom(Kind::$kind, false, &($to)(&self.0), out)
            }
        }
        impl Wire for Nullable<$name> {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads one exact nullable unit (§§10.4, 10.6). Refuses truncation,
            /// trailing bytes, overlong forms, invalid text, and named limits.
            fn parse(input: &[u8]) -> Result<Self, Error> {
                let a = parse_atom(input, Kind::$kind, true)?;
                Ok(Self(if a == Atom::Null {
                    None
                } else {
                    Some($name(($from)(a)?))
                }))
            }
            /// Appends a nullable unit. Refuses invalid text, out-of-range
            /// values, and named limits. Failure leaves `out` unchanged.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                if let Some(v) = &self.0 {
                    unit_limit(&v.0)?;
                }
                write_atom(
                    Kind::$kind,
                    true,
                    &self.0.as_ref().map_or(Atom::Null, |v| ($to)(&v.0)),
                    out,
                )
            }
        }
    };
}
trait UnitSize {
    fn unit_size(&self) -> usize;
}
impl UnitSize for String {
    fn unit_size(&self) -> usize {
        self.len()
    }
}
impl UnitSize for Vec<u8> {
    fn unit_size(&self) -> usize {
        self.len()
    }
}
macro_rules! number_size { ($($t:ty),*) => { $(impl UnitSize for $t { fn unit_size(&self) -> usize { 0 } })* }; }
number_size!(i32, u32, i64, u64);
fn unit_limit(v: &impl UnitSize) -> Result<(), Error> {
    limit(v.unit_size(), MAX_STRING_BYTES, "MAX_STRING_BYTES")
}
fn number<T: TryFrom<i128>>(a: Atom) -> Result<T, Error> {
    if let Atom::Num(n) = a {
        T::try_from(n).map_err(|_| Error::Range)
    } else {
        Err(Error::Value)
    }
}
fn text_value(a: Atom) -> Result<String, Error> {
    if let Atom::Bytes(b) = a {
        String::from_utf8(b).map_err(|_| Error::Text)
    } else {
        Err(Error::Value)
    }
}
unit!(
    Int32,
    i32,
    I32,
    "A signed 32-bit stop-bit integer (§10.6.1).",
    |n: &i32| Atom::Num((*n).into()),
    number::<i32>
);
unit!(
    UInt32,
    u32,
    U32,
    "An unsigned 32-bit stop-bit integer (§10.6.1).",
    |n: &u32| Atom::Num((*n).into()),
    number::<u32>
);
unit!(
    Int64,
    i64,
    I64,
    "A signed 64-bit stop-bit integer (§10.6.1).",
    |n: &i64| Atom::Num((*n).into()),
    number::<i64>
);
unit!(
    UInt64,
    u64,
    U64,
    "An unsigned 64-bit stop-bit integer (§10.6.1).",
    |n: &u64| Atom::Num((*n).into()),
    number::<u64>
);
unit!(
    Ascii,
    String,
    Ascii,
    "An ASCII stop-bit string, including embedded NUL characters (§10.6.3).",
    |s: &String| Atom::Bytes(s.as_bytes().to_vec()),
    text_value
);
unit!(
    Unicode,
    String,
    Unicode,
    "A length-prefixed UTF-8 string (§10.6.4).",
    |s: &String| Atom::Bytes(s.as_bytes().to_vec()),
    text_value
);
unit!(
    ByteVector,
    Vec<u8>,
    Bytes,
    "A length-prefixed byte vector (§10.6.5).",
    |b: &Vec<u8>| Atom::Bytes(b.clone()),
    |a| if let Atom::Bytes(b) = a {
        Ok(b)
    } else {
        Err(Error::Value)
    }
);
fn parse_atom(input: &[u8], kind: Kind, optional: bool) -> Result<Atom, Error> {
    let mut probe = 0;
    let mut r = Reader {
        input,
        pos: 0,
        probe: &mut probe,
    };
    let a = r.raw(kind, optional, false)?;
    if r.pos != input.len() {
        return Err(Error::Trailing);
    }
    Ok(a)
}
fn write_atom(kind: Kind, optional: bool, a: &Atom, out: &mut Vec<u8>) -> Result<(), Error> {
    let mut bytes = Vec::new();
    put_raw(kind, optional, a, &mut bytes)?;
    out.extend_from_slice(&bytes);
    Ok(())
}
impl Wire for Decimal {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads an exact scaled number (§10.6.2). Refuses overlong integers,
    /// exponents outside -63..=63, overflow, truncation, and trailing bytes.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        match parse_atom(input, Kind::Decimal, false)? {
            Atom::Decimal(d) => Ok(d),
            _ => Err(Error::Value),
        }
    }
    /// Appends a scaled number. Refuses exponents outside -63..=63 and
    /// leaves `out` unchanged on failure.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_atom(Kind::Decimal, false, &Atom::Decimal(*self), out)
    }
}
impl Wire for Nullable<Decimal> {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads an exact nullable scaled number. Refuses invalid exponents,
    /// overflow, overlong integers, truncation, and trailing bytes (§10.6.2).
    fn parse(input: &[u8]) -> Result<Self, Error> {
        match parse_atom(input, Kind::Decimal, true)? {
            Atom::Decimal(d) => Ok(Self(Some(d))),
            Atom::Null => Ok(Self(None)),
            _ => Err(Error::Value),
        }
    }
    /// Appends a nullable scaled number. Refuses invalid exponents and
    /// leaves `out` unchanged on failure.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_atom(
            Kind::Decimal,
            true,
            &self.0.map_or(Atom::Null, Atom::Decimal),
            out,
        )
    }
}

/// A presence map with its infinite zero suffix omitted (§10.5).
/// Use [`PresenceMap::new`] to discard trailing false bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceMap {
    bits: Vec<bool>,
}
impl PresenceMap {
    /// Builds a map of at most `7 * MAX_PMAP_BYTES` bits.
    pub fn new(mut bits: Vec<bool>) -> Result<Self, Error> {
        limit(bits.len(), 7 * MAX_PMAP_BYTES, "MAX_PMAP_BYTES")?;
        while bits.last() == Some(&false) {
            bits.pop();
        }
        Ok(Self { bits })
    }
    /// Returns the bit at `index`. Omitted suffix bits are false.
    pub fn bit(&self, index: usize) -> bool {
        self.bits.get(index).copied().unwrap_or(false)
    }
    /// Returns the significant bits, through the last true bit.
    pub fn bits(&self) -> &[bool] {
        &self.bits
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct Map {
    start: usize,
    bytes: usize,
    bit: usize,
}
impl Map {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let start = r.pos;
        let mut end = (*r.probe).max(start);
        loop {
            limit(add(end - start, 1)?, MAX_PMAP_BYTES, "MAX_PMAP_BYTES")?;
            let Some(b) = r.input.get(end).copied() else {
                *r.probe = end;
                return Err(Error::Truncated);
            };
            end += 1;
            if b & 0x80 != 0 {
                if end - start > 1 && b == 0x80 {
                    return Err(Error::Overlong);
                }
                r.pos = end;
                *r.probe = 0;
                return Ok(Self {
                    start,
                    bytes: end - start,
                    bit: 0,
                });
            }
        }
    }
    fn next(&mut self, input: &[u8]) -> Result<bool, Error> {
        limit(add(self.bit, 1)?, 7 * MAX_PMAP_BYTES, "MAX_PMAP_BYTES")?;
        let result = if self.bit / 7 < self.bytes {
            input
                .get(add(self.start, self.bit / 7)?)
                .is_some_and(|b| b & (0x40 >> (self.bit % 7)) != 0)
        } else {
            false
        };
        self.bit += 1;
        Ok(result)
    }
    fn finish(self, input: &[u8]) -> Result<(), Error> {
        for bit in self.bit..self.bytes * 7 {
            if input
                .get(add(self.start, bit / 7)?)
                .is_some_and(|b| b & (0x40 >> (bit % 7)) != 0)
            {
                return Err(Error::Presence);
            }
        }
        Ok(())
    }
}
impl Wire for PresenceMap {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one exact map (§10.5). Refuses overlong maps, truncation,
    /// trailing bytes, and maps exceeding [`MAX_PMAP_BYTES`].
    fn parse(input: &[u8]) -> Result<Self, Error> {
        let mut probe = 0;
        let mut r = Reader {
            input,
            pos: 0,
            probe: &mut probe,
        };
        let mut map = Map::read(&mut r)?;
        if r.pos != input.len() {
            return Err(Error::Trailing);
        }
        let mut bits = Vec::new();
        for _ in 0..map.bytes * 7 {
            bits.push(map.next(input)?);
        }
        Self::new(bits)
    }
    /// Appends a minimal map. Refuses maps above [`MAX_PMAP_BYTES`].
    /// Failure leaves `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        limit(self.bits.len(), 7 * MAX_PMAP_BYTES, "MAX_PMAP_BYTES")?;
        let mut bytes = Vec::new();
        for chunk in self.bits.chunks(7) {
            let mut byte = 0;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    byte |= 0x40 >> i;
                }
            }
            bytes.push(byte);
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        *bytes.last_mut().ok_or(Error::Value)? |= 0x80;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A namespace and local name (§7). Namespaces are identifiers, not URLs to fetch.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name {
    /// Namespace URI, or the empty string.
    pub namespace: String,
    /// Local name.
    pub local: String,
}
/// A dictionary selected for an explicit reset (§6.3.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dictionary {
    /// Shared across all templates. Also resets the copied template identifier.
    Global,
    /// Entries local to a template's qualified name.
    Template(Name),
    /// Entries local to an application type. `None` selects the initial `any` type.
    Type(Option<Name>),
    /// A user defined dictionary, shared by its exact name.
    Named(String),
}
/// One template's identity and wire identifier (§§6, 7.1, 10.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// Qualified template name.
    pub name: Name,
    /// XML auxiliary identifier, retained even when it is not numeric.
    pub auxiliary_id: Option<String>,
    /// Wire identifier. Numeric XML IDs supply the initial binding.
    pub id: Option<u32>,
    body: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    None,
    Constant,
    Default,
    Copy,
    Increment,
    Delta,
    Tail,
}
impl Op {
    fn bit(self, optional: bool) -> bool {
        matches!(
            self,
            Self::Default | Self::Copy | Self::Increment | Self::Tail
        ) || (self == Self::Constant && optional)
    }
    fn dictionary(self) -> bool {
        matches!(
            self,
            Self::Copy | Self::Increment | Self::Delta | Self::Tail
        )
    }
}
#[derive(Clone, Debug)]
struct Field {
    kind: Kind,
    optional: bool,
    op: Op,
    initial: Option<Atom>,
    key: Name,
    component: u8,
    dictionary: String,
    owner: usize,
    slots: Vec<usize>,
}
#[derive(Clone, Debug)]
enum Node {
    Scalar(usize),
    Decimal(usize, usize),
    Group { body: usize, optional: bool },
    Sequence { length: usize, body: usize },
    Static(Name),
    Dynamic,
}
#[derive(Clone, Debug, Default)]
struct Body {
    nodes: Vec<Node>,
    type_ref: Option<usize>,
    pmap: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    scope: Dictionary,
    name: Name,
    component: u8,
}
#[derive(Clone, Debug, Default)]
struct Definitions {
    templates: Vec<Template>,
    bodies: Vec<Body>,
    fields: Vec<Field>,
    types: Vec<Option<Name>>,
    keys: Vec<Key>,
    held: usize,
    count: usize,
}
/// An immutable, bounded set of FAST 1.1 templates supplied as XML data.
///
/// Parsing follows §§3.1, 6–9 and the template definition schemas in
/// appendices 1–2. Foreign extensions are ignored. DTDs are refused.
/// Static references must resolve. Static cycles and excessive nesting return
/// [`Error::Limit`] with `MAX_DEPTH`. ASCII digit `id` attributes that fit in
/// `u32` bind wire IDs; other IDs can be bound with [`Templates::bind`].
#[derive(Clone, Debug)]
pub struct Templates {
    definitions: Arc<Definitions>,
}
impl Templates {
    /// Parses one `template` or a `templates` collection in the FAST 1.1
    /// namespace. Refuses malformed XML, invalid grammar or operators,
    /// duplicate names or IDs, unresolved static references, cycles, and
    /// all `MAX_TEMPLATE_*`, `MAX_XML_NODES`, `MAX_FIELDS`, `MAX_DEPTH`,
    /// `MAX_NAME_BYTES`, and `MAX_DICTIONARY_ENTRIES` limits.
    pub fn from_xml(input: &[u8]) -> Result<Self, Error> {
        limit(input.len(), MAX_TEMPLATE_BYTES, "MAX_TEMPLATE_BYTES")?;
        let tree = xml_tree(input)?;
        let root = tree.first().ok_or(Error::Template)?;
        let mut d = Definitions {
            types: vec![None],
            ..Definitions::default()
        };
        let context = Context::default().at(&root.start)?;
        let roots = match root.start.name.local.as_str() {
            "template" => vec![0],
            "templates" => {
                attributes(&root.start, &["ns", "templateNs", "dictionary"])?;
                root.children.clone()
            }
            _ => return Err(Error::Template),
        };
        limit(roots.len(), MAX_TEMPLATES, "MAX_TEMPLATES")?;
        for index in &roots {
            let x = tree.get(*index).ok_or(Error::Template)?;
            if x.start.name.local != "template" {
                return Err(Error::Template);
            }
            attributes(&x.start, &["name", "id", "ns", "templateNs", "dictionary"])?;
            let c = context.at(&x.start)?;
            let name = qualified(&x.start, &c.template_ns, true)?;
            let auxiliary_id = x.start.attribute(None, "id").map(str::to_owned);
            let id = auxiliary_id
                .as_deref()
                .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|id| id.parse::<u32>().ok());
            if d.templates
                .iter()
                .any(|t| t.name == name || (id.is_some() && t.id == id))
            {
                return Err(Error::Template);
            }
            d.templates.push(Template {
                name,
                auxiliary_id,
                id,
                body: 0,
            });
        }
        for (owner, index) in roots.into_iter().enumerate() {
            let x = tree.get(index).ok_or(Error::Template)?;
            let body = compile_body(&tree, &x.children, &context.at(&x.start)?, owner, 1, &mut d)?;
            d.templates.get_mut(owner).ok_or(Error::Template)?.body = body;
        }
        let mut memo = vec![None; d.bodies.len()];
        for index in 0..d.bodies.len() {
            let (pmap, _) = body_bits(&d, index, 0, &mut memo)?;
            d.bodies.get_mut(index).ok_or(Error::Template)?.pmap = pmap;
        }
        let mut keys = BTreeMap::new();
        let mut bindings = 0usize;
        for field in &mut d.fields {
            if !field.op.dictionary() {
                continue;
            }
            let scopes = match field.dictionary.as_str() {
                "global" => vec![Dictionary::Global],
                "template" => vec![Dictionary::Template(
                    d.templates
                        .get(field.owner)
                        .ok_or(Error::Template)?
                        .name
                        .clone(),
                )],
                "type" => d.types.iter().cloned().map(Dictionary::Type).collect(),
                name => vec![Dictionary::Named(name.to_owned())],
            };
            for scope in scopes {
                let key = Key {
                    scope,
                    name: field.key.clone(),
                    component: field.component,
                };
                let slot = if let Some(slot) = keys.get(&key) {
                    *slot
                } else {
                    limit(
                        add(d.keys.len(), 1)?,
                        MAX_DICTIONARY_ENTRIES,
                        "MAX_DICTIONARY_ENTRIES",
                    )?;
                    let slot = d.keys.len();
                    d.keys.push(key.clone());
                    keys.insert(key, slot);
                    slot
                };
                bindings = add(bindings, 1)?;
                limit(bindings, MAX_DICTIONARY_BINDINGS, "MAX_DICTIONARY_BINDINGS")?;
                field.slots.push(slot);
            }
        }
        // Conservative accounting includes container storage and duplicated names.
        d.held = definition_bytes(&d);
        Ok(Self {
            definitions: Arc::new(d),
        })
    }
    /// Lists template identities in document order.
    pub fn templates(&self) -> &[Template] {
        &self.definitions.templates
    }
    /// Binds a wire ID to an existing template. Refuses an unknown name or
    /// an ID already bound to another template. Existing sessions keep their
    /// immutable template set. Failure leaves this set unchanged.
    pub fn bind(&mut self, name: &Name, id: u32) -> Result<(), Error> {
        let index = self
            .definitions
            .templates
            .iter()
            .position(|t| &t.name == name)
            .ok_or(Error::UnknownTemplate)?;
        if self
            .definitions
            .templates
            .iter()
            .enumerate()
            .any(|(i, t)| i != index && t.id == Some(id))
        {
            return Err(Error::Template);
        }
        Arc::make_mut(&mut self.definitions)
            .templates
            .get_mut(index)
            .ok_or(Error::Template)?
            .id = Some(id);
        Ok(())
    }
}
fn definition_bytes(d: &Definitions) -> usize {
    let names = |n: &Name| n.namespace.len() + n.local.len();
    d.templates
        .iter()
        .map(|t| {
            std::mem::size_of::<Template>()
                + names(&t.name)
                + t.auxiliary_id.as_ref().map_or(0, String::len)
        })
        .sum::<usize>()
        + d.bodies
            .iter()
            .map(|b| {
                std::mem::size_of::<Body>()
                    + b.nodes.capacity() * std::mem::size_of::<Node>()
                    + b.nodes
                        .iter()
                        .map(|n| if let Node::Static(n) = n { names(n) } else { 0 })
                        .sum::<usize>()
            })
            .sum::<usize>()
        + d.fields
            .iter()
            .map(|f| {
                std::mem::size_of::<Field>()
                    + names(&f.key)
                    + f.dictionary.len()
                    + f.slots.capacity() * std::mem::size_of::<usize>()
                    + f.initial.as_ref().map_or(0, Atom::bytes)
            })
            .sum::<usize>()
        + d.keys
            .iter()
            .map(|k| {
                std::mem::size_of::<Key>()
                    + names(&k.name)
                    + match &k.scope {
                        Dictionary::Template(n) | Dictionary::Type(Some(n)) => names(n),
                        Dictionary::Named(n) => n.len(),
                        _ => 0,
                    }
            })
            .sum::<usize>()
        + d.types
            .iter()
            .map(|n| std::mem::size_of::<Option<Name>>() + n.as_ref().map_or(0, names))
            .sum::<usize>()
}
struct XmlNode {
    start: xml::Start,
    children: Vec<usize>,
}
fn xml_tree(input: &[u8]) -> Result<Vec<XmlNode>, Error> {
    let mut parser = xml::Events::new();
    let mut pos = 0;
    let mut tree: Vec<XmlNode> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut foreign = 0usize;
    let mut depth = 0usize;
    let mut count = 0usize;
    loop {
        match parser
            .decode(input.get(pos..).ok_or(Error::Template)?, true)
            .map_err(|_| Error::Template)?
        {
            Step::Item(event, used) => {
                pos = add(pos, used)?;
                match event {
                    xml::Event::Start(start) => {
                        depth += 1;
                        count += 1;
                        limit(depth, MAX_DEPTH, "MAX_DEPTH")?;
                        limit(count, MAX_XML_NODES, "MAX_XML_NODES")?;
                        if foreign > 0
                            || start.name.namespace.as_deref() != Some(TEMPLATE_NAMESPACE)
                        {
                            if depth == 1 {
                                return Err(Error::Template);
                            }
                            foreign += 1;
                            continue;
                        }
                        let index = tree.len();
                        if let Some(parent) = stack.last() {
                            tree.get_mut(*parent)
                                .ok_or(Error::Template)?
                                .children
                                .push(index);
                        }
                        tree.push(XmlNode {
                            start,
                            children: Vec::new(),
                        });
                        stack.push(index);
                    }
                    xml::Event::End(_) => {
                        depth = depth.checked_sub(1).ok_or(Error::Template)?;
                        if foreign > 0 {
                            foreign -= 1;
                        } else {
                            stack.pop().ok_or(Error::Template)?;
                        }
                    }
                    xml::Event::Text(s) | xml::Event::CData(s) => {
                        if foreign == 0 && !s.chars().all(|c| matches!(c, ' ' | '\r' | '\n' | '\t'))
                        {
                            return Err(Error::Template);
                        }
                    }
                    xml::Event::Doctype { .. } => return Err(Error::Template),
                    _ => {}
                }
            }
            Step::Skip(used) => pos = add(pos, used)?,
            Step::Need | Step::End => break,
        }
    }
    if pos != input.len() || depth != 0 || tree.is_empty() {
        return Err(Error::Template);
    }
    Ok(tree)
}
fn attributes(start: &xml::Start, allowed: &[&str]) -> Result<(), Error> {
    for a in &start.attributes {
        if a.name
            .namespace
            .as_deref()
            .is_some_and(|ns| ns != TEMPLATE_NAMESPACE && !ns.is_empty())
        {
            continue;
        }
        if a.name.namespace.is_some() || !allowed.contains(&a.name.local.as_str()) {
            return Err(Error::Template);
        }
        if a.name.local != "value" {
            limit(a.value.len(), MAX_NAME_BYTES, "MAX_NAME_BYTES")?;
        }
        if matches!(a.name.local.as_str(), "name" | "key" | "id")
            && (a.value.is_empty()
                || a.value.trim() != a.value
                || a.value.contains(['\r', '\n', '\t'])
                || a.value.contains("  "))
        {
            return Err(Error::Template);
        }
    }
    Ok(())
}
#[derive(Clone)]
struct Context {
    ns: String,
    template_ns: String,
    dictionary: String,
}
impl Default for Context {
    fn default() -> Self {
        Self {
            ns: String::new(),
            template_ns: String::new(),
            dictionary: "global".into(),
        }
    }
}
impl Context {
    fn at(&self, s: &xml::Start) -> Result<Self, Error> {
        let get = |name, fallback: &str| -> Result<String, Error> {
            let value = s.attribute(None, name).unwrap_or(fallback);
            limit(value.len(), MAX_NAME_BYTES, "MAX_NAME_BYTES")?;
            Ok(value.to_owned())
        };
        Ok(Self {
            ns: get("ns", &self.ns)?,
            template_ns: get("templateNs", &self.template_ns)?,
            dictionary: get("dictionary", &self.dictionary)?,
        })
    }
}
fn qualified(s: &xml::Start, namespace: &str, required: bool) -> Result<Name, Error> {
    let name = s.attribute(None, "name").unwrap_or("");
    if required && name.is_empty() {
        return Err(Error::Template);
    }
    limit(name.len(), MAX_NAME_BYTES, "MAX_NAME_BYTES")?;
    Ok(Name {
        namespace: namespace.to_owned(),
        local: name.to_owned(),
    })
}
fn optional(s: &xml::Start) -> Result<bool, Error> {
    match s.attribute(None, "presence") {
        None | Some("mandatory") => Ok(false),
        Some("optional") => Ok(true),
        _ => Err(Error::Template),
    }
}
fn compile_body(
    tree: &[XmlNode],
    children: &[usize],
    context: &Context,
    owner: usize,
    depth: usize,
    d: &mut Definitions,
) -> Result<usize, Error> {
    limit(depth, MAX_DEPTH, "MAX_DEPTH")?;
    limit(add(d.bodies.len(), 1)?, MAX_FIELDS, "MAX_FIELDS")?;
    let index = d.bodies.len();
    d.bodies.push(Body::default());
    let mut body = Body::default();
    let mut names = std::collections::BTreeSet::new();
    for (position, child) in children.iter().enumerate() {
        let x = tree.get(*child).ok_or(Error::Template)?;
        let s = &x.start;
        if s.name.local == "typeRef" {
            if position != 0 || !x.children.is_empty() {
                return Err(Error::Template);
            }
            attributes(s, &["name", "ns"])?;
            let name = Some(qualified(s, &context.at(s)?.ns, true)?);
            let id = if let Some(i) = d.types.iter().position(|t| t == &name) {
                i
            } else {
                limit(add(d.types.len(), 1)?, MAX_FIELDS, "MAX_FIELDS")?;
                d.types.push(name);
                d.types.len() - 1
            };
            body.type_ref = Some(id);
            continue;
        }
        let c = context.at(s)?;
        if s.name.local != "templateRef" && !names.insert(qualified(s, &c.ns, true)?) {
            return Err(Error::Template);
        }
        let node = match s.name.local.as_str() {
            "group" | "sequence" => {
                attributes(s, &["name", "ns", "id", "presence", "dictionary"])?;
                let mut children = x.children.clone();
                let length = if s.name.local == "sequence" {
                    let length_pos = usize::from(
                        children
                            .first()
                            .and_then(|i| tree.get(*i))
                            .is_some_and(|n| n.start.name.local == "typeRef"),
                    );
                    let length = if children
                        .get(length_pos)
                        .and_then(|i| tree.get(*i))
                        .is_some_and(|n| n.start.name.local == "length")
                    {
                        let id = children.remove(length_pos);
                        compile_field(
                            tree,
                            id,
                            &c,
                            owner,
                            Kind::U32,
                            optional(s)?,
                            Some((qualified(s, &c.ns, true)?, 1)),
                            d,
                        )?
                    } else {
                        add_field(
                            Field {
                                kind: Kind::U32,
                                optional: optional(s)?,
                                op: Op::None,
                                initial: None,
                                key: qualified(s, &c.ns, true)?,
                                component: 1,
                                dictionary: c.dictionary.clone(),
                                owner,
                                slots: Vec::new(),
                            },
                            d,
                        )?
                    };
                    Some(length)
                } else {
                    None
                };
                let child_body = compile_body(tree, &children, &c, owner, depth + 1, d)?;
                match length {
                    Some(length) => Node::Sequence {
                        length,
                        body: child_body,
                    },
                    None => Node::Group {
                        body: child_body,
                        optional: optional(s)?,
                    },
                }
            }
            "templateRef" => {
                attributes(s, &["name", "templateNs"])?;
                if !x.children.is_empty() {
                    return Err(Error::Template);
                }
                if s.attribute(None, "name").is_some() {
                    Node::Static(qualified(s, &c.template_ns, true)?)
                } else if s.attribute(None, "templateNs").is_some() {
                    return Err(Error::Template);
                } else {
                    Node::Dynamic
                }
            }
            name => {
                let kind = match name {
                    "int32" => Kind::I32,
                    "uInt32" => Kind::U32,
                    "int64" => Kind::I64,
                    "uInt64" => Kind::U64,
                    "decimal" => Kind::Decimal,
                    "byteVector" => Kind::Bytes,
                    "string" => match s.attribute(None, "charset") {
                        None | Some("ascii") => Kind::Ascii,
                        Some("unicode") => Kind::Unicode,
                        _ => return Err(Error::Template),
                    },
                    _ => return Err(Error::Template),
                };
                if kind == Kind::Decimal
                    && x.children.iter().any(|i| {
                        tree.get(*i).is_some_and(|n| {
                            matches!(n.start.name.local.as_str(), "exponent" | "mantissa")
                        })
                    })
                {
                    attributes(s, &["name", "id", "ns", "presence"])?;
                    let name = qualified(s, &c.ns, true)?;
                    let mut parts = [None, None];
                    let mut previous = 0;
                    for child in &x.children {
                        let part = tree.get(*child).ok_or(Error::Template)?;
                        let at = match part.start.name.local.as_str() {
                            "exponent" => 0,
                            "mantissa" => 1,
                            _ => return Err(Error::Template),
                        };
                        if at < previous || parts.get(at).is_some_and(Option::is_some) {
                            return Err(Error::Template);
                        }
                        previous = at;
                        let value = compile_field(
                            tree,
                            *child,
                            &c,
                            owner,
                            if at == 0 { Kind::I32 } else { Kind::I64 },
                            at == 0 && optional(s)?,
                            Some((name.clone(), at as u8 + 2)),
                            d,
                        )?;
                        *parts.get_mut(at).ok_or(Error::Template)? = Some(value);
                    }
                    for (at, part) in parts.iter_mut().enumerate() {
                        if part.is_none() {
                            *part = Some(add_field(
                                Field {
                                    kind: if at == 0 { Kind::I32 } else { Kind::I64 },
                                    optional: at == 0 && optional(s)?,
                                    op: Op::None,
                                    initial: None,
                                    key: name.clone(),
                                    component: at as u8 + 2,
                                    dictionary: c.dictionary.clone(),
                                    owner,
                                    slots: Vec::new(),
                                },
                                d,
                            )?);
                        }
                    }
                    Node::Decimal(
                        parts.first().copied().flatten().ok_or(Error::Template)?,
                        parts.get(1).copied().flatten().ok_or(Error::Template)?,
                    )
                } else {
                    Node::Scalar(compile_field(
                        tree,
                        *child,
                        context,
                        owner,
                        kind,
                        optional(s)?,
                        None,
                        d,
                    )?)
                }
            }
        };
        if !matches!(node, Node::Scalar(_)) {
            d.count = add(d.count, 1)?;
            limit(d.count, MAX_FIELDS, "MAX_FIELDS")?;
        }
        body.nodes.push(node);
    }
    *d.bodies.get_mut(index).ok_or(Error::Template)? = body;
    Ok(index)
}
fn add_field(field: Field, d: &mut Definitions) -> Result<usize, Error> {
    d.count = add(d.count, 1)?;
    limit(d.count, MAX_FIELDS, "MAX_FIELDS")?;
    let index = d.fields.len();
    d.fields.push(field);
    Ok(index)
}
#[allow(clippy::too_many_arguments)]
fn compile_field(
    tree: &[XmlNode],
    index: usize,
    context: &Context,
    owner: usize,
    kind: Kind,
    optional: bool,
    generated: Option<(Name, u8)>,
    d: &mut Definitions,
) -> Result<usize, Error> {
    let x = tree.get(index).ok_or(Error::Template)?;
    let s = &x.start;
    let allowed: &[&str] = match s.name.local.as_str() {
        "exponent" | "mantissa" => &[],
        "length" => &["name", "id", "ns"],
        "string" => &["name", "id", "ns", "presence", "charset"],
        _ => &["name", "id", "ns", "presence"],
    };
    attributes(s, allowed)?;
    if matches!(s.name.local.as_str(), "exponent" | "mantissa") && x.children.is_empty() {
        return Err(Error::Template);
    }
    if s.name.local == "length"
        && s.attribute(None, "name").is_none()
        && (s.attribute(None, "ns").is_some() || s.attribute(None, "id").is_some())
    {
        return Err(Error::Template);
    }
    let c = context.at(s)?;
    let (mut key, mut component) = if let Some((name, part)) = generated {
        if s.attribute(None, "name").is_some() {
            (qualified(s, &c.ns, true)?, 0)
        } else {
            (name, part)
        }
    } else {
        (qualified(s, &c.ns, true)?, 0)
    };
    let mut op = Op::None;
    let mut initial = None;
    let mut dictionary = c.dictionary.clone();
    for (position, child) in x.children.iter().enumerate() {
        let child = tree.get(*child).ok_or(Error::Template)?;
        if child.start.name.local == "length" {
            if position != 0
                || !matches!(kind, Kind::Unicode | Kind::Bytes)
                || !child.children.is_empty()
            {
                return Err(Error::Template);
            }
            attributes(&child.start, &["name", "ns", "id"])?;
            qualified(&child.start, &c.at(&child.start)?.ns, true)?;
            continue;
        }
        if op != Op::None || !child.children.is_empty() {
            return Err(Error::Template);
        }
        op = match child.start.name.local.as_str() {
            "constant" => Op::Constant,
            "default" => Op::Default,
            "copy" => Op::Copy,
            "increment" => Op::Increment,
            "delta" => Op::Delta,
            "tail" => Op::Tail,
            _ => return Err(Error::Template),
        };
        attributes(
            &child.start,
            if op.dictionary() {
                &["dictionary", "key", "ns", "value"]
            } else {
                &["value"]
            },
        )?;
        if child.start.attribute(None, "ns").is_some()
            && child.start.attribute(None, "key").is_none()
        {
            return Err(Error::Template);
        }
        let oc = c.at(&child.start)?;
        dictionary = oc.dictionary;
        if let Some(k) = child.start.attribute(None, "key") {
            key = Name {
                namespace: oc.ns,
                local: k.to_owned(),
            };
            component = 0;
        }
        initial = child
            .start
            .attribute(None, "value")
            .map(|v| literal(kind, v))
            .transpose()?;
    }
    if (op == Op::Increment && !kind.integer())
        || (op == Op::Tail && !matches!(kind, Kind::Ascii | Kind::Unicode | Kind::Bytes))
        || ((op == Op::Constant || (op == Op::Default && !optional)) && initial.is_none())
    {
        return Err(Error::Operator);
    }
    add_field(
        Field {
            kind,
            optional,
            op,
            initial,
            key,
            component,
            dictionary,
            owner,
            slots: Vec::new(),
        },
        d,
    )
}
fn literal(kind: Kind, value: &str) -> Result<Atom, Error> {
    let trimmed = value.trim_matches([' ', '\r', '\n', '\t']);
    let atom = if kind.integer() {
        let digits = if kind.signed() {
            trimmed.strip_prefix('-').unwrap_or(trimmed)
        } else {
            trimmed
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Operator);
        }
        Atom::Num(trimmed.parse::<i128>().map_err(|_| Error::Operator)?)
    } else if kind == Kind::Decimal {
        let negative = trimmed.starts_with('-');
        let digits = trimmed.strip_prefix('-').unwrap_or(trimmed);
        let mut fraction = 0usize;
        let mut trailing = 0usize;
        let mut dot = false;
        let mut count = 0usize;
        for b in digits.bytes() {
            if b == b'.' && !dot {
                dot = true;
                continue;
            }
            if !b.is_ascii_digit() {
                return Err(Error::Operator);
            }
            count = add(count, 1)?;
            if dot {
                fraction = add(fraction, 1)?;
            }
            trailing = if b == b'0' { add(trailing, 1)? } else { 0 };
        }
        if count == 0 {
            return Err(Error::Operator);
        }
        let mut n = 0i128;
        for b in digits.bytes().filter(|b| *b != b'.').take(count - trailing) {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(i128::from(b - b'0')))
                .ok_or(Error::Range)?;
        }
        let exponent = if n == 0 {
            0
        } else {
            i32::try_from(trailing)
                .map_err(|_| Error::Range)?
                .checked_sub(i32::try_from(fraction).map_err(|_| Error::Range)?)
                .ok_or(Error::Range)?
        };
        Atom::Decimal(Decimal {
            exponent,
            mantissa: i64::try_from(if negative { -n } else { n }).map_err(|_| Error::Range)?,
        })
    } else if kind == Kind::Bytes {
        let mut bytes = Vec::new();
        let mut high = None;
        for c in value
            .chars()
            .filter(|c| !matches!(c, ' ' | '\r' | '\n' | '\t'))
        {
            let digit = c.to_digit(16).ok_or(Error::Operator)? as u8;
            if let Some(h) = high.take() {
                limit(add(bytes.len(), 1)?, MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
                bytes.push(h * 16 + digit);
            } else {
                high = Some(digit);
            }
        }
        if high.is_some() {
            return Err(Error::Operator);
        }
        Atom::Bytes(bytes)
    } else {
        limit(value.len(), MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
        Atom::Bytes(value.as_bytes().to_vec())
    };
    validate_atom(kind, false, &atom)?;
    Ok(atom)
}
fn template_by_name(d: &Definitions, name: &Name) -> Result<usize, Error> {
    d.templates
        .iter()
        .position(|t| &t.name == name)
        .ok_or(Error::UnknownTemplate)
}
fn template_by_id(d: &Definitions, id: u32) -> Result<usize, Error> {
    d.templates
        .iter()
        .position(|t| t.id == Some(id))
        .ok_or(Error::UnknownTemplate)
}
fn body_bits(
    d: &Definitions,
    body: usize,
    depth: usize,
    memo: &mut [Option<(bool, usize)>],
) -> Result<(bool, usize), Error> {
    limit(depth + 1, MAX_DEPTH, "MAX_DEPTH")?;
    if let Some(result) = memo.get(body).copied().flatten() {
        limit(depth + result.1, MAX_DEPTH, "MAX_DEPTH")?;
        return Ok(result);
    }
    let mut bits = false;
    let mut height = 1;
    for node in &d.bodies.get(body).ok_or(Error::Template)?.nodes {
        bits |= match node {
            Node::Scalar(f) | Node::Sequence { length: f, .. } => {
                let f = d.fields.get(*f).ok_or(Error::Template)?;
                f.op.bit(f.optional)
            }
            Node::Decimal(e, m) => [e, m]
                .into_iter()
                .any(|i| d.fields.get(*i).is_some_and(|f| f.op.bit(f.optional))),
            Node::Group { optional, .. } => *optional,
            Node::Static(name) => {
                let (child_bits, child_height) = body_bits(
                    d,
                    d.templates
                        .get(template_by_name(d, name)?)
                        .ok_or(Error::Template)?
                        .body,
                    depth + 1,
                    memo,
                )?;
                height = height.max(child_height + 1);
                child_bits
            }
            Node::Dynamic => false,
        };
        if let Node::Group { body, .. } | Node::Sequence { body, .. } = node {
            let (_, child_height) = body_bits(d, *body, depth + 1, memo)?;
            height = height.max(child_height + 1);
        }
    }
    *memo.get_mut(body).ok_or(Error::Template)? = Some((bits, height));
    Ok((bits, height))
}

/// One field value in template instruction order.
///
/// Groups and static template references each occupy one `Group` value.
/// A sequence contains one vector per row. Its length is derived from the
/// row count. Byte vector length aliases are metadata, not extra values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An absent optional field, group, or sequence.
    Null,
    /// A signed 32-bit integer.
    Int32(i32),
    /// An unsigned 32-bit integer.
    UInt32(u32),
    /// A signed 64-bit integer.
    Int64(i64),
    /// An unsigned 64-bit integer.
    UInt64(u64),
    /// An exact exponent and mantissa.
    Decimal(Decimal),
    /// An ASCII string, including NUL characters.
    Ascii(String),
    /// A UTF-8 string.
    Unicode(String),
    /// Uninterpreted bytes.
    Bytes(Vec<u8>),
    /// A group or static template reference's fields.
    Group(Vec<Value>),
    /// A sequence's rows. Empty and absent sequences are distinct.
    Sequence(Vec<Vec<Value>>),
    /// A dynamic template reference, with its own wire template ID.
    Dynamic(Box<Message>),
}
/// A message interpreted using its template (§§6, 10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The wire ID bound in [`Templates`].
    pub template_id: u32,
    /// Values in template instruction order. See [`Value`] for containers.
    pub fields: Vec<Value>,
}
fn to_value(kind: Kind, atom: Atom) -> Result<Value, Error> {
    if atom == Atom::Null {
        return Ok(Value::Null);
    }
    Ok(match kind {
        Kind::I32 => Value::Int32(number(atom)?),
        Kind::U32 => Value::UInt32(number(atom)?),
        Kind::I64 => Value::Int64(number(atom)?),
        Kind::U64 => Value::UInt64(number(atom)?),
        Kind::Ascii => Value::Ascii(text_value(atom)?),
        Kind::Unicode => Value::Unicode(text_value(atom)?),
        Kind::Bytes => {
            if let Atom::Bytes(b) = atom {
                Value::Bytes(b)
            } else {
                return Err(Error::Value);
            }
        }
        Kind::Decimal => {
            if let Atom::Decimal(d) = atom {
                Value::Decimal(d)
            } else {
                return Err(Error::Value);
            }
        }
    })
}
fn from_value(kind: Kind, value: &Value) -> Result<Atom, Error> {
    Ok(match (kind, value) {
        (_, Value::Null) => Atom::Null,
        (Kind::I32, Value::Int32(n)) => Atom::Num((*n).into()),
        (Kind::U32, Value::UInt32(n)) => Atom::Num((*n).into()),
        (Kind::I64, Value::Int64(n)) => Atom::Num((*n).into()),
        (Kind::U64, Value::UInt64(n)) => Atom::Num((*n).into()),
        (Kind::Decimal, Value::Decimal(d)) => Atom::Decimal(*d),
        (Kind::Ascii, Value::Ascii(s)) | (Kind::Unicode, Value::Unicode(s)) => {
            limit(s.len(), MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
            Atom::Bytes(s.as_bytes().to_vec())
        }
        (Kind::Bytes, Value::Bytes(b)) => {
            limit(b.len(), MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
            Atom::Bytes(b.clone())
        }
        _ => return Err(Error::Value),
    })
}
#[cfg(test)]
std::thread_local! {
    // Count dictionary entries copied or shadowed, independent of wall time.
    static DICTIONARY_WORK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[derive(Debug, Default)]
struct Entry {
    kind: Option<Kind>,
    value: Option<Atom>,
}
impl Clone for Entry {
    fn clone(&self) -> Self {
        #[cfg(test)]
        DICTIONARY_WORK.with(|work| work.set(work.get() + 1));
        Self {
            kind: self.kind,
            value: self.value.clone(),
        }
    }
}
impl Entry {
    fn allocated(&self) -> usize {
        match &self.value {
            Some(Atom::Bytes(bytes)) => bytes.capacity(),
            _ => 0,
        }
    }
}
#[derive(Debug)]
struct State {
    entries: Vec<Entry>,
    template_id: Option<u32>,
    bytes: usize,
    allocated: usize,
    // One moved old entry per touched slot, bounded by MAX_VALUES and
    // MAX_DICTIONARY_ENTRIES. Marks also serve the scanner's lazy shadows.
    undo: Vec<(usize, Entry)>,
    marked: Vec<bool>,
    transactional: bool,
}
impl Clone for State {
    fn clone(&self) -> Self {
        let entries = self.entries.clone();
        Self {
            allocated: entries.iter().map(Entry::allocated).sum(),
            entries,
            template_id: self.template_id,
            bytes: self.bytes,
            undo: self.undo.clone(),
            marked: self.marked.clone(),
            transactional: self.transactional,
        }
    }
}
impl State {
    fn new(d: &Definitions) -> Self {
        Self {
            entries: vec![Entry::default(); d.keys.len()],
            template_id: None,
            bytes: 0,
            allocated: 0,
            undo: Vec::new(),
            marked: vec![false; d.keys.len()],
            transactional: false,
        }
    }
    fn transaction<T>(
        &mut self,
        run: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let saved = (self.template_id, self.bytes, self.allocated);
        self.transactional = true;
        let result = run(self);
        for (slot, old) in self.undo.drain(..).rev() {
            if result.is_err()
                && let Some(entry) = self.entries.get_mut(slot)
            {
                *entry = old;
            }
            if let Some(marked) = self.marked.get_mut(slot) {
                *marked = false;
            }
        }
        if result.is_err() {
            (self.template_id, self.bytes, self.allocated) = saved;
        }
        self.transactional = false;
        result
    }
    fn slot(field: &Field, ty: usize) -> Result<usize, Error> {
        field
            .slots
            .get(if field.dictionary == "type" { ty } else { 0 })
            .copied()
            .ok_or(Error::Template)
    }
    fn previous(&self, field: &Field, ty: usize) -> Result<Option<Atom>, Error> {
        if !field.op.dictionary() {
            return Ok(None);
        }
        let e = self
            .entries
            .get(Self::slot(field, ty)?)
            .ok_or(Error::Template)?;
        if e.kind.is_some_and(|k| k != field.kind) {
            return Err(Error::DictionaryType);
        }
        Ok(e.value.clone())
    }
    fn set(&mut self, field: &Field, ty: usize, value: Atom) -> Result<(), Error> {
        let slot = Self::slot(field, ty)?;
        let e = self.entries.get_mut(slot).ok_or(Error::Template)?;
        let bytes = add(
            self.bytes
                .checked_sub(e.value.as_ref().map_or(0, Atom::bytes))
                .ok_or(Error::Template)?,
            value.bytes(),
        )?;
        limit(bytes, MAX_DICTIONARY_BYTES, "MAX_DICTIONARY_BYTES")?;
        let next = Entry {
            kind: Some(field.kind),
            value: Some(value),
        };
        let allocated = add(
            self.allocated
                .checked_sub(e.allocated())
                .ok_or(Error::Template)?,
            next.allocated(),
        )?;
        let marked = self.marked.get_mut(slot).ok_or(Error::Template)?;
        if self.transactional && !*marked {
            limit(add(self.undo.len(), 1)?, MAX_VALUES, "MAX_VALUES")?;
            self.undo.push((slot, std::mem::replace(e, next)));
            *marked = true;
        } else {
            *e = next;
        }
        self.bytes = bytes;
        self.allocated = allocated;
        Ok(())
    }
    fn reset(&mut self, d: &Definitions, scope: Option<&Dictionary>) {
        for (key, entry) in d.keys.iter().zip(&mut self.entries) {
            if scope.is_none_or(|scope| scope == &key.scope) {
                *entry = Entry::default();
            }
        }
        self.bytes = self
            .entries
            .iter()
            .map(|e| e.value.as_ref().map_or(0, Atom::bytes))
            .sum();
        self.allocated = self.entries.iter().map(Entry::allocated).sum();
        if scope.is_none_or(|s| s == &Dictionary::Global) {
            self.template_id = None;
        }
    }
    fn held(&self) -> usize {
        self.entries.capacity() * std::mem::size_of::<Entry>()
            + self.allocated
            + self.marked.capacity() * std::mem::size_of::<bool>()
            + self.undo.capacity() * std::mem::size_of::<(usize, Entry)>()
            + self
                .undo
                .iter()
                .map(|(_, entry)| entry.allocated())
                .sum::<usize>()
    }
}
fn shadow(a: &Atom, scan: bool) -> Atom {
    #[cfg(test)]
    DICTIONARY_WORK.with(|work| work.set(work.get() + 1));
    if scan && matches!(a, Atom::Bytes(_)) {
        Atom::Bytes(Vec::new())
    } else {
        a.clone()
    }
}
fn initial(field: &Field, scan: bool) -> Option<Atom> {
    field.initial.as_ref().map(|v| shadow(v, scan))
}
fn zero(kind: Kind) -> Atom {
    if kind.integer() {
        Atom::Num(0)
    } else if kind == Kind::Decimal {
        Atom::Decimal(Decimal {
            exponent: 0,
            mantissa: 0,
        })
    } else {
        Atom::Bytes(Vec::new())
    }
}
fn implied(field: &Field, previous: Option<&Atom>, scan: bool) -> Result<Atom, Error> {
    let value = match previous {
        None => initial(field, scan)
            .or(if field.optional {
                Some(Atom::Null)
            } else {
                None
            })
            .ok_or(Error::Undefined)?,
        Some(Atom::Null) if !field.optional => return Err(Error::Empty),
        Some(Atom::Num(n)) if field.op == Op::Increment => {
            let (min, max) = field.kind.range();
            Atom::Num(if *n == max {
                min
            } else {
                n.checked_add(1).ok_or(Error::Range)?
            })
        }
        Some(a) => shadow(a, scan),
    };
    Ok(value)
}
fn base(field: &Field, previous: Option<&Atom>, scan: bool) -> Result<Atom, Error> {
    match previous {
        Some(Atom::Null) if field.op == Op::Delta => Err(Error::Empty),
        Some(Atom::Null) | None => Ok(initial(field, scan).unwrap_or_else(|| zero(field.kind))),
        Some(a) => Ok(shadow(a, scan)),
    }
}
fn combine_bytes(
    base: Atom,
    part: Atom,
    subtraction: Option<i128>,
    scan: bool,
) -> Result<Atom, Error> {
    let (Atom::Bytes(base), Atom::Bytes(part)) = (base, part) else {
        return Err(Error::Value);
    };
    if scan {
        return Ok(Atom::Bytes(Vec::new()));
    }
    let (front, remove) = match subtraction {
        Some(n) => {
            i32::try_from(n).map_err(|_| Error::Subtraction)?;
            (
                n < 0,
                usize::try_from(if n < 0 { -n - 1 } else { n }).map_err(|_| Error::Subtraction)?,
            )
        }
        None => (false, part.len().min(base.len())),
    };
    let keep = base.len().checked_sub(remove).ok_or(Error::Subtraction)?;
    limit(add(keep, part.len())?, MAX_STRING_BYTES, "MAX_STRING_BYTES")?;
    let mut result = Vec::with_capacity(keep + part.len());
    if front {
        result.extend_from_slice(&part);
        result.extend_from_slice(base.get(remove..).ok_or(Error::Subtraction)?);
    } else {
        result.extend_from_slice(base.get(..keep).ok_or(Error::Subtraction)?);
        result.extend_from_slice(&part);
    }
    Ok(Atom::Bytes(result))
}
fn read_delta(
    r: &mut Reader<'_>,
    field: &Field,
    previous: Option<&Atom>,
    scan: bool,
) -> Result<Atom, Error> {
    let Some(delta) = r.integer(true, field.optional)? else {
        return Ok(Atom::Null);
    };
    let base = base(field, previous, scan)?;
    match base {
        Atom::Num(n) => Ok(Atom::Num(n.checked_add(delta).ok_or(Error::Range)?)),
        Atom::Decimal(d) => {
            let mantissa = r.integer(true, false)?.ok_or(Error::Value)?;
            Ok(Atom::Decimal(Decimal {
                exponent: i32::try_from(
                    i128::from(d.exponent)
                        .checked_add(delta)
                        .ok_or(Error::Range)?,
                )
                .map_err(|_| Error::Range)?,
                mantissa: i64::try_from(
                    i128::from(d.mantissa)
                        .checked_add(mantissa)
                        .ok_or(Error::Range)?,
                )
                .map_err(|_| Error::Range)?,
            }))
        }
        Atom::Bytes(b) => {
            i32::try_from(delta).map_err(|_| Error::Subtraction)?;
            let part = r.bytes(field.kind == Kind::Ascii, false, scan)?;
            combine_bytes(Atom::Bytes(b), part, Some(delta), scan)
        }
        Atom::Null => Err(Error::Empty),
    }
}
fn read_field(
    r: &mut Reader<'_>,
    map: &mut Map,
    field: &Field,
    ty: usize,
    state: &mut State,
    scan: bool,
) -> Result<Atom, Error> {
    let present = !field.op.bit(field.optional) || map.next(r.input)?;
    let previous = state.previous(field, ty)?;
    let value = match field.op {
        Op::None => r.raw(field.kind, field.optional, scan)?,
        Op::Constant => {
            if present {
                initial(field, scan).ok_or(Error::Operator)?
            } else {
                Atom::Null
            }
        }
        Op::Default => {
            if present {
                r.raw(field.kind, field.optional, scan)?
            } else {
                initial(field, scan).unwrap_or(Atom::Null)
            }
        }
        Op::Copy | Op::Increment => {
            if present {
                r.raw(field.kind, field.optional, scan)?
            } else {
                implied(field, previous.as_ref(), scan)?
            }
        }
        Op::Delta => read_delta(r, field, previous.as_ref(), scan)?,
        Op::Tail => {
            if present {
                let part = r.bytes(field.kind == Kind::Ascii, field.optional, scan)?;
                if part == Atom::Null {
                    Atom::Null
                } else {
                    combine_bytes(base(field, previous.as_ref(), scan)?, part, None, scan)?
                }
            } else {
                implied(field, previous.as_ref(), scan)?
            }
        }
    };
    validate_atom(field.kind, field.optional, &value)?;
    if field.op.dictionary() && !(field.op == Op::Delta && value == Atom::Null) {
        state.set(field, ty, value.clone())?;
    }
    Ok(value)
}
#[derive(Default)]
struct Budget {
    values: usize,
    bytes: usize,
}
impl Budget {
    fn value(&mut self) -> Result<(), Error> {
        self.values = add(self.values, 1)?;
        limit(self.values, MAX_VALUES, "MAX_VALUES")
    }
    fn atom(&mut self, a: &Atom) -> Result<(), Error> {
        self.bytes = add(self.bytes, a.bytes())?;
        limit(self.bytes, MAX_VALUE_BYTES, "MAX_VALUE_BYTES")
    }
}
fn read_id(
    r: &mut Reader<'_>,
    map: &mut Map,
    state: &mut State,
    d: &Definitions,
) -> Result<(u32, usize), Error> {
    let id = if map.next(r.input)? {
        u32::try_from(r.integer(false, false)?.ok_or(Error::Value)?).map_err(|_| Error::Range)?
    } else {
        state.template_id.ok_or(Error::Undefined)?
    };
    let template = template_by_id(d, id)?;
    state.template_id = Some(id);
    Ok((id, template))
}
#[allow(clippy::too_many_arguments)]
fn read_body(
    r: &mut Reader<'_>,
    map: &mut Map,
    d: &Definitions,
    body_id: usize,
    inherited_type: usize,
    state: &mut State,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<Value>, Error> {
    limit(depth, MAX_DEPTH, "MAX_DEPTH")?;
    let body = d.bodies.get(body_id).ok_or(Error::Template)?;
    let ty = body.type_ref.unwrap_or(inherited_type);
    let mut values = Vec::new();
    for node in &body.nodes {
        budget.value()?;
        let value = match node {
            Node::Scalar(f) => {
                let f = d.fields.get(*f).ok_or(Error::Template)?;
                let a = read_field(r, map, f, ty, state, false)?;
                budget.atom(&a)?;
                to_value(f.kind, a)?
            }
            Node::Decimal(e, m) => {
                let exponent = read_field(
                    r,
                    map,
                    d.fields.get(*e).ok_or(Error::Template)?,
                    ty,
                    state,
                    false,
                )?;
                match exponent {
                    Atom::Null => Value::Null,
                    Atom::Num(exponent) => {
                        let mantissa = read_field(
                            r,
                            map,
                            d.fields.get(*m).ok_or(Error::Template)?,
                            ty,
                            state,
                            false,
                        )?;
                        let d = Decimal {
                            exponent: i32::try_from(exponent).map_err(|_| Error::Range)?,
                            mantissa: number(mantissa)?,
                        };
                        validate_atom(Kind::Decimal, false, &Atom::Decimal(d))?;
                        Value::Decimal(d)
                    }
                    _ => return Err(Error::Value),
                }
            }
            Node::Group { body, optional } => {
                if *optional && !map.next(r.input)? {
                    Value::Null
                } else {
                    Value::Group(read_segment_body(
                        r,
                        d,
                        *body,
                        ty,
                        state,
                        budget,
                        depth + 1,
                    )?)
                }
            }
            Node::Sequence { length, body } => {
                match read_field(
                    r,
                    map,
                    d.fields.get(*length).ok_or(Error::Template)?,
                    d.bodies
                        .get(*body)
                        .ok_or(Error::Template)?
                        .type_ref
                        .unwrap_or(ty),
                    state,
                    false,
                )? {
                    Atom::Null => Value::Null,
                    Atom::Num(n) => {
                        let n = usize::try_from(n).map_err(|_| Error::Range)?;
                        limit(n, MAX_SEQUENCE_LENGTH, "MAX_SEQUENCE_LENGTH")?;
                        let mut rows = Vec::new();
                        for _ in 0..n {
                            budget.value()?;
                            rows.push(read_segment_body(
                                r,
                                d,
                                *body,
                                ty,
                                state,
                                budget,
                                depth + 1,
                            )?);
                        }
                        Value::Sequence(rows)
                    }
                    _ => return Err(Error::Value),
                }
            }
            Node::Static(name) => {
                let t = d
                    .templates
                    .get(template_by_name(d, name)?)
                    .ok_or(Error::Template)?;
                Value::Group(read_body(r, map, d, t.body, ty, state, budget, depth + 1)?)
            }
            Node::Dynamic => {
                let mut nested_map = Map::read(r)?;
                let (template_id, index) = read_id(r, &mut nested_map, state, d)?;
                let fields = read_body(
                    r,
                    &mut nested_map,
                    d,
                    d.templates.get(index).ok_or(Error::Template)?.body,
                    ty,
                    state,
                    budget,
                    depth + 1,
                )?;
                nested_map.finish(r.input)?;
                Value::Dynamic(Box::new(Message {
                    template_id,
                    fields,
                }))
            }
        };
        values.push(value);
    }
    Ok(values)
}
fn read_segment_body(
    r: &mut Reader<'_>,
    d: &Definitions,
    body: usize,
    ty: usize,
    state: &mut State,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<Value>, Error> {
    let mut map = if d.bodies.get(body).ok_or(Error::Template)?.pmap {
        Map::read(r)?
    } else {
        Map::default()
    };
    let fields = read_body(r, &mut map, d, body, ty, state, budget, depth)?;
    map.finish(r.input)?;
    Ok(fields)
}
fn read_message(
    input: &[u8],
    d: &Definitions,
    state: &mut State,
) -> Result<(Message, usize), Error> {
    let mut probe = 0;
    let mut r = Reader {
        input,
        pos: 0,
        probe: &mut probe,
    };
    let mut map = Map::read(&mut r)?;
    let (template_id, index) = read_id(&mut r, &mut map, state, d)?;
    let fields = read_body(
        &mut r,
        &mut map,
        d,
        d.templates.get(index).ok_or(Error::Template)?.body,
        0,
        state,
        &mut Budget::default(),
        1,
    )?;
    map.finish(input)?;
    Ok((
        Message {
            template_id,
            fields,
        },
        r.pos,
    ))
}

#[derive(Clone, Copy, Debug)]
enum Header {
    None,
    Map,
    Dynamic,
}
#[derive(Clone, Copy, Debug)]
struct ScanFrame {
    body: usize,
    at: usize,
    ty: usize,
    map: Map,
    share: bool,
    repeat: usize,
    header: Header,
}
#[derive(Debug)]
struct Scanner {
    frames: Vec<ScanFrame>,
    state: State,
    dirty: Vec<usize>,
    pos: usize,
    probe: usize,
    values: usize,
    active: bool,
}
impl Clone for Scanner {
    fn clone(&self) -> Self {
        // Vec::clone would discard spare capacity. Keep the fixed stack
        // reservation so a cloned decoder cannot allocate across Need.
        let mut frames = Vec::with_capacity(MAX_DEPTH);
        frames.extend_from_slice(&self.frames);
        let mut dirty = Vec::with_capacity(self.state.entries.len());
        dirty.extend_from_slice(&self.dirty);
        Self {
            frames,
            state: self.state.clone(),
            dirty,
            pos: self.pos,
            probe: self.probe,
            values: self.values,
            active: self.active,
        }
    }
}
impl Scanner {
    fn new(d: &Definitions) -> Self {
        Self {
            frames: Vec::with_capacity(MAX_DEPTH),
            state: State::new(d),
            dirty: Vec::with_capacity(d.keys.len()),
            pos: 0,
            probe: 0,
            values: 0,
            active: false,
        }
    }
    fn start(&mut self, committed: &State) {
        for slot in self.dirty.drain(..) {
            if let Some(marked) = self.state.marked.get_mut(slot) {
                *marked = false;
            }
        }
        self.state.template_id = committed.template_id;
        self.state.bytes = 0;
        self.pos = 0;
        self.probe = 0;
        self.values = 0;
        self.frames.clear();
        self.frames.push(ScanFrame {
            body: 0,
            at: 0,
            ty: 0,
            map: Map::default(),
            share: false,
            repeat: 1,
            header: Header::Dynamic,
        });
        self.active = true;
    }
    fn prepare(&mut self, field: &Field, ty: usize, committed: &State) -> Result<(), Error> {
        if !field.op.dictionary() {
            return Ok(());
        }
        let slot = State::slot(field, ty)?;
        let marked = self.state.marked.get_mut(slot).ok_or(Error::Template)?;
        if !*marked {
            limit(
                add(self.dirty.len(), 1)?,
                MAX_DICTIONARY_ENTRIES,
                "MAX_DICTIONARY_ENTRIES",
            )?;
            let old = committed.entries.get(slot).ok_or(Error::Template)?;
            *self.state.entries.get_mut(slot).ok_or(Error::Template)? = Entry {
                kind: old.kind,
                value: old.value.as_ref().map(|value| shadow(value, true)),
            };
            self.dirty.push(slot);
            *marked = true;
        }
        Ok(())
    }
    fn push(
        &mut self,
        d: &Definitions,
        body: usize,
        ty: usize,
        shared_map: Option<Map>,
        repeat: usize,
        dynamic: bool,
    ) -> Result<(), Error> {
        limit(add(self.frames.len(), 1)?, MAX_DEPTH, "MAX_DEPTH")?;
        let share = shared_map.is_some();
        let map = shared_map.unwrap_or_default();
        let header = if dynamic {
            Header::Dynamic
        } else if !share && d.bodies.get(body).ok_or(Error::Template)?.pmap {
            Header::Map
        } else {
            Header::None
        };
        let ty = if dynamic {
            ty
        } else {
            d.bodies
                .get(body)
                .ok_or(Error::Template)?
                .type_ref
                .unwrap_or(ty)
        };
        self.frames.push(ScanFrame {
            body,
            at: 0,
            ty,
            map,
            share,
            repeat,
            header,
        });
        Ok(())
    }
    fn value(&mut self) -> Result<(), Error> {
        self.values = add(self.values, 1)?;
        limit(self.values, MAX_VALUES, "MAX_VALUES")
    }
    fn run(&mut self, input: &[u8], d: &Definitions, committed: &State) -> Result<usize, Error> {
        loop {
            let Some(mut frame) = self.frames.last().copied() else {
                return Ok(self.pos);
            };
            if !matches!(frame.header, Header::None) {
                let mut r = Reader {
                    input,
                    pos: self.pos,
                    probe: &mut self.probe,
                };
                let mut map = Map::read(&mut r)?;
                if matches!(frame.header, Header::Dynamic) {
                    let (_, index) = read_id(&mut r, &mut map, &mut self.state, d)?;
                    frame.body = d.templates.get(index).ok_or(Error::Template)?.body;
                    frame.ty = d
                        .bodies
                        .get(frame.body)
                        .ok_or(Error::Template)?
                        .type_ref
                        .unwrap_or(frame.ty);
                }
                frame.map = map;
                frame.header = Header::None;
                self.pos = r.pos;
                *self.frames.last_mut().ok_or(Error::Template)? = frame;
            }
            let body = d.bodies.get(frame.body).ok_or(Error::Template)?;
            let Some(node) = body.nodes.get(frame.at) else {
                if !frame.share {
                    frame.map.finish(input)?;
                }
                if frame.repeat > 1 {
                    self.value()?;
                    frame.repeat -= 1;
                    frame.at = 0;
                    frame.map = Map::default();
                    frame.header = if body.pmap { Header::Map } else { Header::None };
                    *self.frames.last_mut().ok_or(Error::Template)? = frame;
                } else {
                    self.frames.pop();
                    if frame.share {
                        self.frames.last_mut().ok_or(Error::Template)?.map = frame.map;
                    }
                }
                continue;
            };
            match node {
                Node::Scalar(index) => self.prepare(
                    d.fields.get(*index).ok_or(Error::Template)?,
                    frame.ty,
                    committed,
                )?,
                Node::Decimal(e, m) => {
                    for index in [e, m] {
                        self.prepare(
                            d.fields.get(*index).ok_or(Error::Template)?,
                            frame.ty,
                            committed,
                        )?;
                    }
                }
                Node::Sequence { length, body } => self.prepare(
                    d.fields.get(*length).ok_or(Error::Template)?,
                    d.bodies
                        .get(*body)
                        .ok_or(Error::Template)?
                        .type_ref
                        .unwrap_or(frame.ty),
                    committed,
                )?,
                _ => {}
            }
            let mut r = Reader {
                input,
                pos: self.pos,
                probe: &mut self.probe,
            };
            let mut child = None;
            let mut rows = 0;
            match node {
                Node::Scalar(index) => {
                    read_field(
                        &mut r,
                        &mut frame.map,
                        d.fields.get(*index).ok_or(Error::Template)?,
                        frame.ty,
                        &mut self.state,
                        true,
                    )?;
                }
                Node::Decimal(e, m) => {
                    let e = d.fields.get(*e).ok_or(Error::Template)?;
                    let m = d.fields.get(*m).ok_or(Error::Template)?;
                    let slot = if e.op.dictionary() {
                        Some(State::slot(e, frame.ty)?)
                    } else {
                        None
                    };
                    let saved = slot.and_then(|i| self.state.entries.get(i).cloned());
                    let exponent =
                        read_field(&mut r, &mut frame.map, e, frame.ty, &mut self.state, true)?;
                    if let Atom::Num(exponent) = exponent {
                        if !(-63..=63).contains(&exponent) {
                            return Err(Error::Range);
                        }
                        if let Err(error) =
                            read_field(&mut r, &mut frame.map, m, frame.ty, &mut self.state, true)
                        {
                            if let (Some(slot), Some(saved)) = (slot, saved) {
                                *self.state.entries.get_mut(slot).ok_or(Error::Template)? = saved;
                            }
                            return Err(error);
                        }
                    }
                }
                Node::Group { body, optional } => {
                    if !optional || frame.map.next(input)? {
                        child = Some((*body, false, 1, false));
                    }
                }
                Node::Sequence { length, body } => {
                    let length = d.fields.get(*length).ok_or(Error::Template)?;
                    if let Atom::Num(n) = read_field(
                        &mut r,
                        &mut frame.map,
                        length,
                        d.bodies
                            .get(*body)
                            .ok_or(Error::Template)?
                            .type_ref
                            .unwrap_or(frame.ty),
                        &mut self.state,
                        true,
                    )? {
                        let n = usize::try_from(n).map_err(|_| Error::Range)?;
                        limit(n, MAX_SEQUENCE_LENGTH, "MAX_SEQUENCE_LENGTH")?;
                        if n > 0 {
                            child = Some((*body, false, n, false));
                            rows = 1;
                        }
                    }
                }
                Node::Static(name) => {
                    child = Some((
                        d.templates
                            .get(template_by_name(d, name)?)
                            .ok_or(Error::Template)?
                            .body,
                        true,
                        1,
                        false,
                    ));
                }
                Node::Dynamic => {
                    child = Some((0, false, 1, true));
                }
            }
            self.pos = r.pos;
            self.value()?;
            if rows > 0 {
                self.value()?;
            }
            frame.at += 1;
            *self.frames.last_mut().ok_or(Error::Template)? = frame;
            if let Some((body, share, repeat, dynamic)) = child {
                self.push(
                    d,
                    body,
                    frame.ty,
                    if share { Some(frame.map) } else { None },
                    repeat,
                    dynamic,
                )?;
            }
        }
    }
}

/// Reads one BlockSize header (§10): `Ok(None)` while it is incomplete,
/// else the header length and the payload size it declares. Refuses zero
/// (D12), a header longer than [`MAX_INTEGER_BYTES`], and a size above
/// [`MAX_MESSAGE_BYTES`].
fn block_header(input: &[u8]) -> Result<Option<(usize, usize)>, Error> {
    let mut size = 0usize;
    for at in 0..MAX_INTEGER_BYTES {
        let Some(&byte) = input.get(at) else {
            return Ok(None);
        };
        size = size
            .checked_mul(128)
            .and_then(|n| n.checked_add(usize::from(byte & 0x7f)))
            .ok_or(Error::Range)?;
        limit(size, MAX_MESSAGE_BYTES, "MAX_MESSAGE_BYTES")?;
        if byte & 0x80 != 0 {
            if size == 0 {
                return Err(Error::BlockSize);
            }
            return Ok(Some((add(at, 1)?, size)));
        }
    }
    Err(Error::Limit("MAX_INTEGER_BYTES"))
}

/// Reads the block form of a FAST stream (§10), yielding each block's raw
/// payload without reading its messages.
///
/// Block sizes exclude the header and may be overlong. The header is bounded
/// by [`MAX_INTEGER_BYTES`] and the payload by [`MAX_MESSAGE_BYTES`]. This
/// decoder keeps no input or state. To read the messages of a block stream,
/// use [`BlockMessages`], which also refuses a message that crosses a block
/// boundary. Joining payloads into one stream (for example with
/// `codec::Pipe` and `Carry::Bytes`) loses those boundaries.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, fast::Blocks};
/// let mut stream = Stream::new(Blocks);
/// assert_eq!(stream.push(&[0x82, 0xc0, 0x81]), 3);
/// assert_eq!(stream.next().transpose()?, Some(vec![0xc0, 0x81]));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Blocks;

impl Decode for Blocks {
    type Item = Vec<u8>;
    type Error = Error;
    const NAME: &'static str = "FAST 1.1 blocks";

    /// The largest accepted header and payload together.
    fn capacity(&self) -> usize {
        MAX_INTEGER_BYTES + MAX_MESSAGE_BYTES
    }

    /// Reads one block (§10). Refuses zero size (D12), a header longer than
    /// [`MAX_INTEGER_BYTES`], and a payload above [`MAX_MESSAGE_BYTES`].
    /// Partial headers and payloads return `Need`, including at EOF.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Vec<u8>>, Error> {
        let Some((start, size)) = block_header(input)? else {
            return Ok(Step::Need);
        };
        let end = add(start, size)?;
        Ok(match input.get(start..end) {
            Some(payload) => Step::Item(payload.to_vec(), end),
            None => Step::Need,
        })
    }
}

/// Reads the messages of a FAST block stream (§10):
/// `block ::= BlockSize message+`.
///
/// Each BlockSize header is skipped, and [`Messages`] reads messages from the
/// bytes of that block only. A message that would continue past the end of
/// its block is refused with [`Error::BlockBoundary`], as is a block whose
/// payload ends inside a message. Block sizes may be overlong. The decoder
/// holds no input, only the bytes left in the current block and the state
/// of its [`Messages`].
///
/// ```
/// use fictionet::stdlib::{codec::Stream, fast::{BlockMessages, Error, Messages, Templates}};
/// let templates = Templates::from_xml(br#"<template
///     xmlns="http://www.fixprotocol.org/ns/fast/td/1.1" name="Empty" id="1"/>"#)?;
/// let mut stream = Stream::new(BlockMessages::new(Messages::new(templates.clone())));
/// assert_eq!(stream.push(&[0x82, 0xc0, 0x81]), 3);
/// assert!(stream.next().transpose()?.is_some());
/// // A message split across two blocks is refused.
/// let mut stream = Stream::new(BlockMessages::new(Messages::new(templates)));
/// assert_eq!(stream.push(&[0x81, 0xc0, 0x81, 0x81]), 4);
/// assert!(stream.next().unwrap().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct BlockMessages {
    messages: Messages,
    remaining: usize,
}
impl BlockMessages {
    /// Reads blocks from the start of a stream, each message with `messages`.
    pub fn new(messages: Messages) -> Self {
        Self {
            messages,
            remaining: 0,
        }
    }
    /// The message decoder, for resets between messages.
    pub fn messages(&mut self) -> &mut Messages {
        &mut self.messages
    }
    /// Payload bytes of the current block not yet read as messages. Zero
    /// between blocks.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}
impl Decode for BlockMessages {
    type Item = Message;
    type Error = Error;
    const NAME: &'static str = "FAST 1.1 block messages";

    /// A message, which never exceeds its block's [`MAX_MESSAGE_BYTES`]
    /// payload, or a header of at most [`MAX_INTEGER_BYTES`].
    fn capacity(&self) -> usize {
        MAX_MESSAGE_BYTES.max(MAX_INTEGER_BYTES)
    }
    fn held(&self) -> usize {
        self.messages.held()
    }
    /// Skips a block header, or reads one message from the rest of the
    /// current block. Refuses what [`Blocks`] and [`Messages`] refuse, and a
    /// message that does not end within its block ([`Error::BlockBoundary`]).
    /// Partial headers and partial blocks return `Need`, including at EOF.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Message>, Error> {
        if self.remaining == 0 {
            return Ok(match block_header(input)? {
                Some((header, size)) => {
                    self.remaining = size;
                    Step::Skip(header)
                }
                None => Step::Need,
            });
        }
        let block = input
            .get(..input.len().min(self.remaining))
            .unwrap_or_default();
        match self.messages.decode(block, eof)? {
            Step::Item(message, n) => {
                self.remaining = self.remaining.checked_sub(n).ok_or(Error::Range)?;
                Ok(Step::Item(message, n))
            }
            Step::Skip(n) => {
                self.remaining = self.remaining.checked_sub(n).ok_or(Error::Range)?;
                Ok(Step::Skip(n))
            }
            Step::Need if block.len() == self.remaining => Err(Error::BlockBoundary),
            Step::Need => Ok(Step::Need),
            Step::End => Ok(Step::End),
        }
    }
}

/// A template-driven message decoder implementing [`Decode`].
///
/// Use [`codec::Stream`](fictionet::stdlib::codec::Stream) to own input.
/// The scanner retains positions, map cursors, and numeric dictionary shadows.
/// It does not retain input or decoded strings while returning `Need`.
/// Shadows are loaded only for touched slots and cleared using a dirty-slot list.
/// Each field is visited once during framing; partial strings resume scanning.
/// A complete message is then decoded once and its dictionary changes commit.
/// An undo journal moves the old entry on the first write to each slot. It
/// holds at most [`MAX_VALUES`] records and [`MAX_DICTIONARY_BYTES`] old data bytes.
/// Invalid input terminates the stream. Partial input returns `Need` at EOF.
#[derive(Clone, Debug)]
pub struct Messages {
    templates: Templates,
    state: State,
    scanner: Scanner,
}
impl Messages {
    /// Starts with every dictionary entry undefined (§6.3.1).
    pub fn new(templates: Templates) -> Self {
        Self {
            state: State::new(&templates.definitions),
            scanner: Scanner::new(&templates.definitions),
            templates,
        }
    }
    /// Resets all dictionaries and the copied template identifier.
    /// Call only at message boundaries. A reset also discards framing cursors.
    pub fn reset(&mut self) {
        self.state.reset(&self.templates.definitions, None);
        self.scanner.active = false;
    }
    /// Resets one dictionary (§6.3.1). Call only at message boundaries.
    /// Resetting `Global` also clears the copied template identifier.
    pub fn reset_dictionary(&mut self, scope: &Dictionary) {
        self.state.reset(&self.templates.definitions, Some(scope));
        self.scanner.active = false;
    }
    /// Reads exactly one message using this session. Refuses trailing bytes,
    /// truncation, malformed encodings, state errors, and all named limits.
    /// Failure leaves dictionaries and framing cursors unchanged.
    pub fn parse_exact(&mut self, input: &[u8]) -> Result<Message, Error> {
        limit(input.len(), MAX_MESSAGE_BYTES, "MAX_MESSAGE_BYTES")?;
        let message = self.state.transaction(|state| {
            let (message, used) = read_message(input, &self.templates.definitions, state)?;
            if used != input.len() {
                return Err(Error::Trailing);
            }
            Ok(message)
        })?;
        self.scanner.active = false;
        Ok(message)
    }
}
impl Decode for Messages {
    type Item = Message;
    type Error = Error;
    const NAME: &'static str = "FAST 1.1";
    fn capacity(&self) -> usize {
        MAX_MESSAGE_BYTES
    }
    fn held(&self) -> usize {
        self.templates.definitions.held
            + self.state.held()
            + self.scanner.state.held()
            + self.scanner.frames.capacity() * std::mem::size_of::<ScanFrame>()
            + self.scanner.dirty.capacity() * std::mem::size_of::<usize>()
    }
    /// Reads one message (§10). Refuses invalid templates, encodings, state,
    /// presence bits, ranges, text, and named limits. Incomplete input returns
    /// `Need`, including at EOF. Dictionary changes commit only with an item.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Message>, Error> {
        if input.is_empty() {
            return Ok(Step::Need);
        }
        if !self.scanner.active {
            self.scanner.start(&self.state);
        }
        match self
            .scanner
            .run(input, &self.templates.definitions, &self.state)
        {
            Ok(end) => {
                self.scanner.active = false;
                let message = self.parse_exact(input.get(..end).ok_or(Error::Truncated)?)?;
                Ok(Step::Item(message, end))
            }
            Err(Error::Truncated) if input.len() < MAX_MESSAGE_BYTES => Ok(Step::Need),
            Err(error) => {
                self.scanner.active = false;
                Err(if error == Error::Truncated {
                    Error::Limit("MAX_MESSAGE_BYTES")
                } else {
                    error
                })
            }
        }
    }
}

#[derive(Default)]
struct Output {
    bits: Vec<bool>,
    data: Vec<u8>,
}
impl Output {
    fn bit(&mut self, bit: bool) -> Result<(), Error> {
        limit(
            add(self.bits.len(), 1)?,
            7 * MAX_PMAP_BYTES,
            "MAX_PMAP_BYTES",
        )?;
        self.bits.push(bit);
        Ok(())
    }
    fn finish(self, pmap: bool) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        if pmap {
            PresenceMap::new(self.bits)?.write(&mut bytes)?;
        } else if !self.bits.is_empty() {
            return Err(Error::Presence);
        }
        append(&mut bytes, &self.data)?;
        Ok(bytes)
    }
}
fn write_delta(
    field: &Field,
    value: &Atom,
    previous: Option<&Atom>,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if value == &Atom::Null {
        return append(out, &[0x80]);
    }
    let base = base(field, previous, false)?;
    match (&base, value) {
        (Atom::Num(a), Atom::Num(b)) => put_integer(
            b.checked_sub(*a).ok_or(Error::Range)?,
            true,
            field.optional,
            out,
        ),
        (Atom::Decimal(a), Atom::Decimal(b)) => {
            put_integer(
                i128::from(b.exponent) - i128::from(a.exponent),
                true,
                field.optional,
                out,
            )?;
            put_integer(
                i128::from(b.mantissa) - i128::from(a.mantissa),
                true,
                false,
                out,
            )
        }
        (Atom::Bytes(a), Atom::Bytes(b)) => {
            let prefix = a.iter().zip(b).take_while(|(a, b)| a == b).count();
            let suffix = a
                .iter()
                .rev()
                .zip(b.iter().rev())
                .take_while(|(a, b)| a == b)
                .count();
            let (remove, part) = if suffix > prefix {
                (
                    -(a.len().saturating_sub(suffix) as i128) - 1,
                    b.get(..b.len() - suffix).ok_or(Error::Subtraction)?,
                )
            } else {
                (
                    (a.len() - prefix) as i128,
                    b.get(prefix..).ok_or(Error::Subtraction)?,
                )
            };
            put_integer(remove, true, field.optional, out)?;
            put_bytes(part, field.kind == Kind::Ascii, false, out)
        }
        _ => Err(Error::Value),
    }
}
fn write_field(
    out: &mut Output,
    field: &Field,
    ty: usize,
    value: &Atom,
    state: &mut State,
) -> Result<(), Error> {
    validate_atom(field.kind, field.optional, value)?;
    let previous = state.previous(field, ty)?;
    match field.op {
        Op::None => put_raw(field.kind, field.optional, value, &mut out.data)?,
        Op::Constant => {
            if field.optional {
                out.bit(value != &Atom::Null)?;
            }
            if value != &Atom::Null && field.initial.as_ref() != Some(value) {
                return Err(Error::Value);
            }
        }
        Op::Default => {
            let expected = field.initial.as_ref().unwrap_or(&Atom::Null);
            let present = value != expected;
            out.bit(present)?;
            if present {
                put_raw(field.kind, field.optional, value, &mut out.data)?;
            }
        }
        Op::Copy | Op::Increment | Op::Tail => {
            let present = implied(field, previous.as_ref(), false).as_ref() != Ok(value);
            out.bit(present)?;
            if present {
                if field.op == Op::Tail && value != &Atom::Null {
                    let base = base(field, previous.as_ref(), false)?;
                    let (Atom::Bytes(a), Atom::Bytes(b)) = (&base, value) else {
                        return Err(Error::Value);
                    };
                    if b.len() < a.len() {
                        return Err(Error::Value);
                    }
                    let prefix = if b.len() == a.len() {
                        a.iter().zip(b).take_while(|(a, b)| a == b).count()
                    } else {
                        0
                    };
                    put_bytes(
                        b.get(prefix..).ok_or(Error::Value)?,
                        field.kind == Kind::Ascii,
                        field.optional,
                        &mut out.data,
                    )?;
                } else {
                    put_raw(field.kind, field.optional, value, &mut out.data)?;
                }
            }
        }
        Op::Delta => write_delta(field, value, previous.as_ref(), &mut out.data)?,
    }
    if field.op.dictionary() && !(field.op == Op::Delta && value == &Atom::Null) {
        state.set(field, ty, value.clone())?;
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn write_body(
    out: &mut Output,
    values: &[Value],
    d: &Definitions,
    body_id: usize,
    inherited_type: usize,
    state: &mut State,
    budget: &mut Budget,
    depth: usize,
) -> Result<(), Error> {
    limit(depth, MAX_DEPTH, "MAX_DEPTH")?;
    let body = d.bodies.get(body_id).ok_or(Error::Template)?;
    if values.len() != body.nodes.len() {
        return Err(Error::Value);
    }
    let ty = body.type_ref.unwrap_or(inherited_type);
    for (node, value) in body.nodes.iter().zip(values) {
        budget.value()?;
        match node {
            Node::Scalar(f) => {
                let f = d.fields.get(*f).ok_or(Error::Template)?;
                let atom = from_value(f.kind, value)?;
                budget.atom(&atom)?;
                write_field(out, f, ty, &atom, state)?;
            }
            Node::Decimal(e, m) => {
                let (exponent, mantissa) = match value {
                    Value::Null => (Atom::Null, None),
                    Value::Decimal(v) => {
                        validate_atom(Kind::Decimal, false, &Atom::Decimal(*v))?;
                        (
                            Atom::Num(v.exponent.into()),
                            Some(Atom::Num(v.mantissa.into())),
                        )
                    }
                    _ => return Err(Error::Value),
                };
                write_field(
                    out,
                    d.fields.get(*e).ok_or(Error::Template)?,
                    ty,
                    &exponent,
                    state,
                )?;
                if let Some(mantissa) = mantissa {
                    write_field(
                        out,
                        d.fields.get(*m).ok_or(Error::Template)?,
                        ty,
                        &mantissa,
                        state,
                    )?;
                }
            }
            Node::Group { body, optional } => {
                if *optional {
                    out.bit(value != &Value::Null)?;
                }
                if value != &Value::Null || !optional {
                    let Value::Group(values) = value else {
                        return Err(Error::Value);
                    };
                    let bytes = write_segment_body(values, d, *body, ty, state, budget, depth + 1)?;
                    append(&mut out.data, &bytes)?;
                }
            }
            Node::Sequence { length, body } => {
                let (n, rows) = match value {
                    Value::Null => (Atom::Null, None),
                    Value::Sequence(rows) => {
                        limit(rows.len(), MAX_SEQUENCE_LENGTH, "MAX_SEQUENCE_LENGTH")?;
                        (Atom::Num(rows.len() as i128), Some(rows))
                    }
                    _ => return Err(Error::Value),
                };
                write_field(
                    out,
                    d.fields.get(*length).ok_or(Error::Template)?,
                    d.bodies
                        .get(*body)
                        .ok_or(Error::Template)?
                        .type_ref
                        .unwrap_or(ty),
                    &n,
                    state,
                )?;
                if let Some(rows) = rows {
                    for row in rows {
                        budget.value()?;
                        let bytes =
                            write_segment_body(row, d, *body, ty, state, budget, depth + 1)?;
                        append(&mut out.data, &bytes)?;
                    }
                }
            }
            Node::Static(name) => {
                let Value::Group(values) = value else {
                    return Err(Error::Value);
                };
                let t = d
                    .templates
                    .get(template_by_name(d, name)?)
                    .ok_or(Error::Template)?;
                write_body(out, values, d, t.body, ty, state, budget, depth + 1)?;
            }
            Node::Dynamic => {
                let Value::Dynamic(message) = value else {
                    return Err(Error::Value);
                };
                let bytes = write_message(message, d, ty, state, budget, depth + 1)?;
                append(&mut out.data, &bytes)?;
            }
        }
    }
    Ok(())
}
fn write_segment_body(
    values: &[Value],
    d: &Definitions,
    body: usize,
    ty: usize,
    state: &mut State,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Output::default();
    write_body(&mut out, values, d, body, ty, state, budget, depth)?;
    out.finish(d.bodies.get(body).ok_or(Error::Template)?.pmap)
}
fn write_message(
    message: &Message,
    d: &Definitions,
    ty: usize,
    state: &mut State,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<u8>, Error> {
    let t = d
        .templates
        .get(template_by_id(d, message.template_id)?)
        .ok_or(Error::Template)?;
    let mut out = Output::default();
    let present = state.template_id != Some(message.template_id);
    out.bit(present)?;
    if present {
        put_integer(message.template_id.into(), false, false, &mut out.data)?;
    }
    state.template_id = Some(message.template_id);
    write_body(
        &mut out,
        &message.fields,
        d,
        t.body,
        ty,
        state,
        budget,
        depth,
    )?;
    out.finish(true)
}
/// A stateful template-driven encoder (§§6, 10).
///
/// Writes are transactional for both output and dictionaries. Reset calls
/// must match the peer decoder. A tail operator cannot shorten its base;
/// such a value is refused (§6.3.8). Decimal component pairs are preserved.
#[derive(Clone, Debug)]
pub struct Encoder {
    templates: Templates,
    state: State,
}
impl Encoder {
    /// Starts an encoder with undefined dictionary entries.
    pub fn new(templates: Templates) -> Self {
        Self {
            state: State::new(&templates.definitions),
            templates,
        }
    }
    /// Resets all dictionaries and the copied template identifier (§6.3.1).
    pub fn reset(&mut self) {
        self.state.reset(&self.templates.definitions, None);
    }
    /// Resets one dictionary. Resetting `Global` also clears the copied
    /// template identifier (§§6.3.1, 10).
    pub fn reset_dictionary(&mut self, scope: &Dictionary) {
        self.state.reset(&self.templates.definitions, Some(scope));
    }
    /// Returns retained template and dictionary storage in bytes.
    pub fn held(&self) -> usize {
        self.templates.definitions.held + self.state.held()
    }
    /// Appends one FAST message. Refuses unknown IDs, wrong field shapes,
    /// absent mandatory fields, mismatched constants, invalid text, range
    /// errors, impossible tails, dictionary type conflicts, and named limits.
    /// On failure, both `out` and every dictionary remain unchanged.
    pub fn write(&mut self, message: &Message, out: &mut Vec<u8>) -> Result<(), Error> {
        let bytes = self.state.transaction(|state| {
            write_message(
                message,
                &self.templates.definitions,
                0,
                state,
                &mut Budget::default(),
                1,
            )
        })?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Stream,
        contract::{check_decode_with_alloc_limit, check_wire, check_wire_value},
        finish, pump,
        test_support::{chunks, decode_all},
    };

    fn templates(fields: &str) -> Templates {
        xml_templates(&format!(
            "<template name=\"Example\" id=\"1\">{fields}</template>"
        ))
    }
    fn xml_templates(body: &str) -> Templates {
        Templates::from_xml(
            format!("<templates xmlns=\"{TEMPLATE_NAMESPACE}\">{body}</templates>").as_bytes(),
        )
        .unwrap()
    }
    fn message(fields: Vec<Value>) -> Message {
        Message {
            template_id: 1,
            fields,
        }
    }
    fn exchange(t: Templates, values: &[Message]) -> Vec<u8> {
        let mut writer = Encoder::new(t.clone());
        let mut bytes = Vec::new();
        for value in values {
            writer.write(value, &mut bytes).unwrap();
        }
        assert_eq!(
            decode_all(|| Messages::new(t.clone()), &bytes),
            (values.to_vec(), None)
        );
        check_decode_with_alloc_limit(|| Messages::new(t.clone()), &bytes, 2 * MAX_MESSAGE_BYTES);
        bytes
    }
    fn exact<T: Wire<ParseError = Error, WriteError = Error> + std::fmt::Debug + PartialEq>(
        value: T,
        bytes: &[u8],
    ) {
        assert_eq!(value.to_bytes().unwrap(), bytes);
        assert_eq!(T::parse(bytes).unwrap(), value);
        check_wire::<T>(bytes);
        check_wire_value(&value);
    }
    #[test]
    fn appendix_3_1_integer_examples_and_extremes() {
        exact(Int32(942755), &[0x39, 0x45, 0xa3]);
        exact(Nullable(Some(Int32(942755))), &[0x39, 0x45, 0xa4]);
        exact(Nullable(Some(Int32(-942755))), &[0x46, 0x3a, 0xdd]);
        exact(Int32(-7942755), &[0x7c, 0x1b, 0x1b, 0x9d]);
        exact(Int32(8193), &[0, 0x40, 0x81]);
        // Appendix 3.1.1's -8193 hex column has a typo (73). Its binary
        // column and §10.6.1 require 7f.
        exact(Int32(-8193), &[0x7f, 0x3f, 0xff]);
        exact(UInt32(942755), &[0x39, 0x45, 0xa3]);
        exact(Nullable(Some(UInt32(942755))), &[0x39, 0x45, 0xa4]);
        exact(Nullable::<UInt32>(None), &[0x80]);
        exact(Nullable(Some(UInt32(0))), &[0x81]);
        exact(Nullable(Some(UInt32(u32::MAX))), &[0x10, 0, 0, 0, 0x80]);
        for n in [i64::MIN, i64::MAX, -8193, -65, -64, -1, 0, 63, 64, 8192] {
            check_wire_value(&Int64(n));
            check_wire_value(&Nullable(Some(Int64(n))));
        }
        for n in [0, 127, 128, u64::MAX] {
            check_wire_value(&UInt64(n));
            check_wire_value(&Nullable(Some(UInt64(n))));
        }
        for n in [i32::MIN, i32::MAX, 0] {
            check_wire_value(&Int32(n));
            check_wire_value(&Nullable(Some(Int32(n))));
        }
        check_wire_value(&Nullable::<Int64>(None));
        check_wire_value(&Nullable::<UInt64>(None));
        assert_eq!(UInt32::parse(&[0x10, 0, 0, 0, 0x80]), Err(Error::Range));
        assert_eq!(
            UInt64::parse(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]),
            Err(Error::Range)
        );
    }
    #[test]
    fn appendix_3_1_strings_vectors_and_decimals() {
        exact(Ascii("ABC".into()), &[0x41, 0x42, 0xc3]);
        exact(Nullable(Some(Ascii("ABC".into()))), &[0x41, 0x42, 0xc3]);
        exact(Ascii(String::new()), &[0x80]);
        exact(Nullable(Some(Ascii(String::new()))), &[0, 0x80]);
        exact(Nullable::<Ascii>(None), &[0x80]);
        exact(Ascii("\0".into()), &[0, 0x80]);
        exact(Nullable(Some(Ascii("\0".into()))), &[0, 0, 0x80]);
        exact(Ascii("\0A".into()), &[0, 0, 0xc1]);
        exact(Nullable(Some(Ascii("\0A".into()))), &[0, 0, 0, 0xc1]);
        exact(ByteVector(b"ABC".to_vec()), &[0x83, 0x41, 0x42, 0x43]);
        exact(
            Nullable(Some(ByteVector(b"ABC".to_vec()))),
            &[0x84, 0x41, 0x42, 0x43],
        );
        exact(Nullable::<ByteVector>(None), &[0x80]);
        exact(Nullable(Some(ByteVector(Vec::new()))), &[0x81]);
        exact(Unicode("é".into()), &[0x82, 0xc3, 0xa9]);
        exact(Nullable(Some(Unicode("é".into()))), &[0x83, 0xc3, 0xa9]);
        exact(Nullable::<Unicode>(None), &[0x80]);
        exact(
            Decimal {
                exponent: 2,
                mantissa: 942755,
            },
            &[0x82, 0x39, 0x45, 0xa3],
        );
        exact(
            Decimal {
                exponent: 1,
                mantissa: 9427550,
            },
            &[0x81, 0x04, 0x3f, 0x34, 0xde],
        );
        exact(
            Nullable(Some(Decimal {
                exponent: 2,
                mantissa: 942755,
            })),
            &[0x83, 0x39, 0x45, 0xa3],
        );
        exact(
            Decimal {
                exponent: -2,
                mantissa: 942755,
            },
            &[0xfe, 0x39, 0x45, 0xa3],
        );
        exact(
            Nullable(Some(Decimal {
                exponent: -2,
                mantissa: -942755,
            })),
            &[0xfe, 0x46, 0x3a, 0xdd],
        );
        exact(Nullable::<Decimal>(None), &[0x80]);
        for exponent in [-63, 0, 63] {
            for mantissa in [i64::MIN, 0, i64::MAX] {
                check_wire_value(&Decimal { exponent, mantissa });
            }
        }
        check_wire_value(&Decimal {
            exponent: 64,
            mantissa: 1,
        });
        check_wire_value(&Ascii("é".into()));
        assert_eq!(Unicode::parse(&[0x81, 0xff]), Err(Error::Text));
    }
    #[test]
    fn exact_wire_refuses_overlong_truncated_trailing_and_limits() {
        for bytes in [&[0, 0x80][..], &[0, 0x81], &[0x7f, 0xff]] {
            assert_eq!(Int64::parse(bytes), Err(Error::Overlong));
        }
        assert_eq!(UInt64::parse(&[0, 0x80]), Err(Error::Overlong));
        assert_eq!(Int64::parse(&[0x80, 0x80]), Err(Error::Trailing));
        assert_eq!(UInt64::parse(&[1; MAX_INTEGER_BYTES]), Err(Error::Range));
        for bytes in [&[0, 0xc1][..], &[0, 0, 0xc1]] {
            assert_eq!(Nullable::<Ascii>::parse(bytes), Err(Error::Overlong));
        }
        assert_eq!(Ascii::parse(&[0, 0xc1]), Err(Error::Overlong));
        assert_eq!(Int64::parse(&[]), Err(Error::Truncated));
        assert_eq!(ByteVector::parse(&[0x83, 1, 2]), Err(Error::Truncated));
        let long = vec![b'a'; MAX_STRING_BYTES + 1];
        check_wire_value(&ByteVector(long.clone()));
        check_wire_value(&Ascii(String::from_utf8(long.clone()).unwrap()));
        let mut stop = long;
        *stop.last_mut().unwrap() |= 0x80;
        assert!(matches!(
            Ascii::parse(&stop),
            Err(Error::Limit("MAX_STRING_BYTES"))
        ));
        let mut length = Vec::new();
        put_integer((MAX_STRING_BYTES + 1) as i128, false, false, &mut length).unwrap();
        assert_eq!(
            ByteVector::parse(&length),
            Err(Error::Limit("MAX_STRING_BYTES"))
        );
    }
    #[test]
    fn presence_maps_edges_and_unused_bits() {
        exact(PresenceMap::new(vec![]).unwrap(), &[0x80]);
        exact(PresenceMap::new(vec![true, false, true]).unwrap(), &[0xd0]);
        exact(PresenceMap::new(vec![false; 14]).unwrap(), &[0x80]);
        let mut bits = vec![false; 8];
        bits[7] = true;
        exact(PresenceMap::new(bits).unwrap(), &[0, 0xc0]);
        assert_eq!(PresenceMap::parse(&[0, 0x80]), Err(Error::Overlong));
        assert_eq!(PresenceMap::parse(&[0xc0, 0x80]), Err(Error::Trailing));
        assert_eq!(
            PresenceMap::parse(&vec![0; MAX_PMAP_BYTES]),
            Err(Error::Limit("MAX_PMAP_BYTES"))
        );
        assert_eq!(
            PresenceMap::new(vec![false; MAX_PMAP_BYTES * 7 + 1]),
            Err(Error::Limit("MAX_PMAP_BYTES"))
        );
        let t = templates("");
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&[0xe0, 0x81]),
            Err(Error::Presence)
        );
        check_decode_with_alloc_limit(
            || Messages::new(t.clone()),
            &[0xe0, 0x81],
            2 * MAX_MESSAGE_BYTES,
        );
        let fields = (0..9)
            .map(|i| format!("<uInt32 name=\"f{i}\"><default value=\"0\"/></uInt32>"))
            .collect::<String>();
        let bytes = exchange(templates(&fields), &[message(vec![Value::UInt32(1); 9])]);
        assert_eq!(bytes, [vec![0x7f, 0xf0, 0x81], vec![0x81; 9]].concat());
    }
    #[test]
    fn appendix_3_2_constant_default_copy_increment() {
        assert_eq!(
            exchange(
                templates("<uInt32 name=\"Flag\"><constant value=\"0\"/></uInt32>"),
                &[message(vec![Value::UInt32(0)])]
            ),
            [0xc0, 0x81]
        );
        assert_eq!(
            exchange(
                templates(
                    "<uInt32 name=\"Flag\" presence=\"optional\"><constant value=\"0\"/></uInt32>"
                ),
                &[message(vec![Value::UInt32(0)]), message(vec![Value::Null])]
            ),
            [0xe0, 0x81, 0x80]
        );
        assert_eq!(
            exchange(
                templates("<uInt32 name=\"Flag\"><default value=\"0\"/></uInt32>"),
                &[
                    message(vec![Value::UInt32(0)]),
                    message(vec![Value::UInt32(1)])
                ]
            ),
            [0xc0, 0x81, 0xa0, 0x81]
        );
        assert_eq!(
            exchange(
                templates("<uInt32 name=\"Flag\" presence=\"optional\"><default/></uInt32>"),
                &[message(vec![Value::Null])]
            ),
            [0xc0, 0x81]
        );
        assert_eq!(
            exchange(
                templates("<string name=\"Flag\"><copy/></string>"),
                &["CME", "CME", "ISE"].map(|s| message(vec![Value::Ascii(s.into())]))
            ),
            [0xe0, 0x81, 0x43, 0x4d, 0xc5, 0x80, 0xa0, 0x49, 0x53, 0xc5]
        );
        assert_eq!(
            exchange(
                templates("<uInt32 name=\"Flag\"><increment value=\"1\"/></uInt32>"),
                &[1, 2, 4, 5].map(|n| message(vec![Value::UInt32(n)]))
            ),
            [0xc0, 0x81, 0x80, 0xa0, 0x84, 0x80]
        );
        let t = templates("<uInt32 name=\"n\"><increment/></uInt32>");
        exchange(
            t,
            &[
                message(vec![Value::UInt32(u32::MAX)]),
                message(vec![Value::UInt32(0)]),
            ],
        );
        exchange(
            templates("<int64 name=\"n\"><increment/></int64>"),
            &[
                message(vec![Value::Int64(i64::MAX)]),
                message(vec![Value::Int64(i64::MIN)]),
            ],
        );
    }
    #[test]
    fn appendix_3_2_delta_examples() {
        assert_eq!(
            exchange(
                templates("<int32 name=\"Price\"><delta/></int32>"),
                &[942755, 942750, 942745, 942745].map(|n| message(vec![Value::Int32(n)]))
            ),
            [
                0xc0, 0x81, 0x39, 0x45, 0xa3, 0x80, 0xfb, 0x80, 0xfb, 0x80, 0x80
            ]
        );
        assert_eq!(
            exchange(
                templates("<decimal name=\"Price\"><delta/></decimal>"),
                &[942755, 942751, 942746].map(|mantissa| message(vec![Value::Decimal(Decimal {
                    exponent: -2,
                    mantissa
                })]))
            ),
            [
                0xc0, 0x81, 0xfe, 0x39, 0x45, 0xa3, 0x80, 0x80, 0xfc, 0x80, 0x80, 0xfb
            ]
        );
        assert_eq!(
            exchange(
                templates("<decimal name=\"Price\"><delta value=\"12000\"/></decimal>"),
                &[1210, 1215, 1220].map(|mantissa| message(vec![Value::Decimal(Decimal {
                    exponent: 1,
                    mantissa
                })]))
            ),
            [
                0xc0, 0x81, 0xfe, 0x09, 0xae, 0x80, 0x80, 0x85, 0x80, 0x80, 0x85
            ]
        );
        assert_eq!(
            exchange(
                templates("<string name=\"Security\"><delta/></string>"),
                &["GEH6", "GEM6", "ESM6", "RSESM6"].map(|s| message(vec![Value::Ascii(s.into())]))
            ),
            [
                0xc0, 0x81, 0x80, 0x47, 0x45, 0x48, 0xb6, 0x80, 0x82, 0x4d, 0xb6, 0x80, 0xfd, 0x45,
                0xd3, 0x80, 0xff, 0x52, 0xd3
            ]
        );
        exchange(
            templates("<uInt64 name=\"n\" presence=\"optional\"><delta/></uInt64>"),
            &[u64::MAX, 0, u64::MAX].map(|n| message(vec![Value::UInt64(n)])),
        );
        exchange(
            templates("<int64 name=\"n\"><delta/></int64>"),
            &[i64::MIN, i64::MAX, i64::MIN].map(|n| message(vec![Value::Int64(n)])),
        );
    }
    #[test]
    fn nullable_dictionary_states_and_tail() {
        assert_eq!(
            exchange(
                templates("<int32 name=\"n\" presence=\"optional\"><delta value=\"10\"/></int32>"),
                &[
                    message(vec![Value::Int32(12)]),
                    message(vec![Value::Null]),
                    message(vec![Value::Int32(13)])
                ]
            ),
            [0xc0, 0x81, 0x83, 0x80, 0x80, 0x80, 0x82]
        );
        assert_eq!(
            exchange(
                templates(
                    "<string name=\"s\" presence=\"optional\"><tail value=\"ABCD\"/></string>"
                ),
                &[
                    message(vec![Value::Ascii("ABxy".into())]),
                    message(vec![Value::Ascii("ABxy".into())]),
                    message(vec![Value::Null]),
                    message(vec![Value::Ascii("ABCD".into())])
                ]
            ),
            [0xe0, 0x81, b'x', 0xf9, 0x80, 0xa0, 0x80, 0xa0, 0, 0x80]
        );
        let t = templates("<uInt32 name=\"n\" presence=\"optional\"><copy/></uInt32>");
        exchange(
            t.clone(),
            &[
                message(vec![Value::Null]),
                message(vec![Value::UInt32(0)]),
                message(vec![Value::Null]),
                message(vec![Value::Null]),
            ],
        );
        let mut decoder = Messages::new(t);
        assert_eq!(
            decoder.parse_exact(&[0xe0, 0x81, 0x80]).unwrap(),
            message(vec![Value::Null])
        );
        assert_eq!(
            decoder.parse_exact(&[0x80]).unwrap(),
            message(vec![Value::Null])
        );
        let t = templates(
            "<uInt32 name=\"x\" presence=\"optional\"><copy key=\"k\"/></uInt32><uInt32 name=\"y\"><copy key=\"k\"/></uInt32>",
        );
        assert_eq!(
            Messages::new(t).parse_exact(&[0xe0, 0x81, 0x80]),
            Err(Error::Empty)
        );
        assert_eq!(
            Messages::new(templates("<uInt32 name=\"x\"><copy/></uInt32>"))
                .parse_exact(&[0xc0, 0x81]),
            Err(Error::Undefined)
        );
    }
    #[test]
    fn individual_decimals_omit_mantissa_bit_and_resume() {
        let t = templates(
            "<decimal name=\"d\" presence=\"optional\"><exponent><copy/></exponent><mantissa><copy/></mantissa></decimal><uInt32 name=\"after\"><default value=\"0\"/></uInt32>",
        );
        let values = [
            message(vec![
                Value::Decimal(Decimal {
                    exponent: -2,
                    mantissa: 942755,
                }),
                Value::UInt32(1),
            ]),
            message(vec![Value::Null, Value::UInt32(2)]),
            message(vec![
                Value::Decimal(Decimal {
                    exponent: -2,
                    mantissa: 942755,
                }),
                Value::UInt32(0),
            ]),
        ];
        // The mantissa remains non-nullable. Appendix 3.2.6's first mantissa
        // hex ends a4; §10.5.1 and the binary value require a3.
        assert_eq!(
            exchange(t, &values),
            [
                0xf8, 0x81, 0xfe, 0x39, 0x45, 0xa3, 0x81, 0xb0, 0x80, 0x82, 0xa0, 0xfe
            ]
        );
        exchange(
            templates(
                "<decimal name=\"d\"><exponent><constant value=\"-2\"/></exponent><mantissa><delta/></mantissa></decimal>",
            ),
            &[1, 4, 8].map(|mantissa| {
                message(vec![Value::Decimal(Decimal {
                    exponent: -2,
                    mantissa,
                })])
            }),
        );
    }
    #[test]
    fn unicode_and_binary_operators_allow_fragment_boundaries() {
        for op in ["delta", "tail"] {
            let fields = format!(
                "<string name=\"s\" charset=\"unicode\"><{op} value=\"é\"/></string><byteVector name=\"b\"><{op} value=\"00 FF\"/></byteVector>"
            );
            exchange(
                templates(&fields),
                &[
                    message(vec![Value::Unicode("ê".into()), Value::Bytes(vec![0, 128])]),
                    message(vec![
                        Value::Unicode("ế".into()),
                        Value::Bytes(vec![0, 128, 255]),
                    ]),
                ],
            );
        }
        let t = templates("<string name=\"s\" charset=\"unicode\"><delta value=\"é\"/></string>");
        assert_eq!(
            Messages::new(t)
                .parse_exact(&[0xc0, 0x81, 0x81, 0x81, 0xa9])
                .unwrap(),
            message(vec![Value::Unicode("é".into())])
        );
        let t = templates("<string name=\"s\"><delta/></string>");
        assert_eq!(
            Messages::new(t).parse_exact(&[0xc0, 0x81, 0x81, 0x80]),
            Err(Error::Subtraction)
        );
    }
    #[test]
    fn sequences_groups_static_and_dynamic_references() {
        let t = xml_templates(
            r#"
          <template name="Top" id="1">
            <group name="g" presence="optional"><uInt32 name="n"><copy/></uInt32></group>
            <sequence name="rows" presence="optional"><length name="count"><copy/></length><string name="s"><copy/></string></sequence>
            <templateRef name="Static"/><templateRef/>
          </template>
          <template name="Static"><int32 name="x"><default value="2"/></int32></template>
          <template name="Leaf" id="2"><uInt64 name="id"/></template>"#,
        );
        let first = message(vec![
            Value::Group(vec![Value::UInt32(3)]),
            Value::Sequence(vec![
                vec![Value::Ascii("A".into())],
                vec![Value::Ascii("A".into())],
            ]),
            Value::Group(vec![Value::Int32(2)]),
            Value::Dynamic(Box::new(Message {
                template_id: 2,
                fields: vec![Value::UInt64(7)],
            })),
        ]);
        let second = message(vec![
            Value::Null,
            Value::Sequence(vec![]),
            Value::Group(vec![Value::Int32(3)]),
            Value::Dynamic(Box::new(Message {
                template_id: 2,
                fields: vec![Value::UInt64(8)],
            })),
        ]);
        let bytes = exchange(t, &[first, second]);
        assert_eq!(
            bytes,
            [
                0xf0, 0x81, 0xc0, 0x83, 0x83, 0xc0, 0xc1, 0x80, 0xc0, 0x82, 0x87, 0xd8, 0x81, 0x81,
                0x83, 0xc0, 0x82, 0x88
            ]
        );
        let t = templates(
            "<sequence name=\"s\"><length><constant value=\"2\"/></length><uInt32 name=\"x\"/></sequence><group name=\"g\"><int32 name=\"y\"/></group>",
        );
        assert_eq!(
            exchange(
                t,
                &[message(vec![
                    Value::Sequence(vec![vec![Value::UInt32(1)], vec![Value::UInt32(2)]]),
                    Value::Group(vec![Value::Int32(3)])
                ])]
            ),
            [0xc0, 0x81, 0x81, 0x82, 0x83]
        );
    }
    #[test]
    fn shared_length_dictionary_updates_within_message() {
        let t = templates(
            "<uInt32 name=\"n\"/><sequence name=\"s\"><length name=\"n\"><copy value=\"2\"/></length><uInt32 name=\"x\"><copy key=\"n\"/></uInt32></sequence><sequence name=\"t\"><length name=\"n\"><copy/></length><uInt32 name=\"y\"/></sequence>",
        );
        let m = message(vec![
            Value::UInt32(9),
            Value::Sequence(vec![vec![Value::UInt32(1)], vec![Value::UInt32(3)]]),
            Value::Sequence(vec![
                vec![Value::UInt32(4)],
                vec![Value::UInt32(5)],
                vec![Value::UInt32(6)],
            ]),
        ]);
        exchange(t, &[m]);
    }
    #[test]
    fn dictionary_scopes_and_selective_resets() {
        for scope in ["global", "template", "type", "custom"] {
            let t = xml_templates(&format!(
                "<template name=\"A\" id=\"1\" dictionary=\"{scope}\"><typeRef name=\"Quote\"/><uInt32 name=\"x\"><copy value=\"1\"/></uInt32></template><template name=\"B\" id=\"2\" dictionary=\"{scope}\"><typeRef name=\"Quote\"/><uInt32 name=\"x\"><copy value=\"1\"/></uInt32></template>"
            ));
            let mut e = Encoder::new(t.clone());
            let mut f = Messages::new(t);
            let a = message(vec![Value::UInt32(9)]);
            let b = Message {
                template_id: 2,
                fields: vec![Value::UInt32(9)],
            };
            let mut bytes = Vec::new();
            e.write(&a, &mut bytes).unwrap();
            assert_eq!(f.parse_exact(&bytes).unwrap(), a);
            bytes.clear();
            e.write(&b, &mut bytes).unwrap();
            assert_eq!(f.parse_exact(&bytes).unwrap(), b);
            assert_eq!(
                bytes,
                if scope == "template" {
                    vec![0xe0, 0x82, 0x89]
                } else {
                    vec![0xc0, 0x82]
                }
            );
            let dictionary = match scope {
                "global" => Dictionary::Global,
                "template" => Dictionary::Template(Name {
                    namespace: String::new(),
                    local: "B".into(),
                }),
                "type" => Dictionary::Type(Some(Name {
                    namespace: String::new(),
                    local: "Quote".into(),
                })),
                _ => Dictionary::Named("custom".into()),
            };
            e.reset_dictionary(&dictionary);
            f.reset_dictionary(&dictionary);
            bytes.clear();
            e.write(&b, &mut bytes).unwrap();
            assert_eq!(f.parse_exact(&bytes).unwrap(), b);
            assert_eq!(
                bytes,
                if scope == "global" {
                    vec![0xe0, 0x82, 0x89]
                } else {
                    vec![0xa0, 0x89]
                }
            );
            e.reset();
            f.reset();
            bytes.clear();
            e.write(&a, &mut bytes).unwrap();
            assert_eq!(bytes, [0xe0, 0x81, 0x89]);
            assert_eq!(f.parse_exact(&bytes).unwrap(), a);
        }
    }
    #[test]
    fn type_inheritance_and_dictionary_type_conflicts() {
        let t = xml_templates(
            r#"<template name="A" id="1" dictionary="type"><typeRef name="A"/><uInt32 name="x"><copy value="1"/></uInt32><group name="g"><typeRef name="B"/><uInt32 name="x"><copy value="2"/></uInt32></group><templateRef/></template><template name="B" id="2" dictionary="type"><uInt32 name="x"><copy/></uInt32></template>"#,
        );
        exchange(
            t,
            &[message(vec![
                Value::UInt32(5),
                Value::Group(vec![Value::UInt32(6)]),
                Value::Dynamic(Box::new(Message {
                    template_id: 2,
                    fields: vec![Value::UInt32(5)],
                })),
            ])],
        );
        let t = templates(
            "<uInt32 name=\"x\"><copy key=\"k\"/></uInt32><string name=\"y\"><copy key=\"k\"/></string>",
        );
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&[0xf0, 0x81, 0x81, 0xc1]),
            Err(Error::DictionaryType)
        );
        let mut out = vec![9];
        assert_eq!(
            Encoder::new(t).write(
                &message(vec![Value::UInt32(1), Value::Ascii("A".into())]),
                &mut out
            ),
            Err(Error::DictionaryType)
        );
        assert_eq!(out, [9]);
    }
    #[test]
    fn section_10_blocks_allow_overlong_sizes_and_frame_messages() {
        // Section 10's BlockSize excludes its own bytes. The second block
        // uses the permitted overlong form of one (§10.6.1).
        let bytes = [0x83, 0xc0, 0x81, 0x80, 0, 0x81, 0x80];
        assert_eq!(
            decode_all(|| Blocks, &bytes),
            (vec![vec![0xc0, 0x81, 0x80], vec![0x80]], None)
        );
        check_decode_with_alloc_limit(
            || Blocks,
            &bytes,
            2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES),
        );
        let t = templates("<uInt32 name=\"n\"><increment value=\"1\"/></uInt32>");
        let make = || BlockMessages::new(Messages::new(t.clone()));
        assert_eq!(
            decode_all(make, &bytes),
            (
                (1..=3).map(|n| message(vec![Value::UInt32(n)])).collect(),
                None
            )
        );
        check_decode_with_alloc_limit(make, &bytes, 2 * MAX_MESSAGE_BYTES);
        for n in 0..=255u8 {
            check_decode_with_alloc_limit(
                || Blocks,
                &[n, 0x81, 0x80],
                2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES),
            );
        }
    }
    #[test]
    fn block_messages_refuse_messages_that_cross_block_boundaries() {
        use fictionet::stdlib::codec::Fail;
        let t = xml_templates(r#"<template name="A" id="1"/>"#);
        let empty = Message {
            template_id: 1,
            fields: Vec::new(),
        };
        let make = || BlockMessages::new(Messages::new(t.clone()));
        // Block 1 holds only the presence map, block 2 the template ID.
        let split = [0x81, 0xc0, 0x81, 0x81];
        assert_eq!(
            decode_all(make, &split),
            (Vec::new(), Some(Fail::Protocol(Error::BlockBoundary)))
        );
        // A whole message, then the start of one that ends in the next block.
        let tail = [0x83, 0xc0, 0x81, 0xc0, 0x81, 0x81];
        assert_eq!(
            decode_all(make, &tail),
            (
                vec![empty.clone()],
                Some(Fail::Protocol(Error::BlockBoundary))
            )
        );
        // A block that ends inside a message at end of input.
        assert_eq!(
            decode_all(make, &[0x81, 0xc0]),
            (Vec::new(), Some(Fail::Protocol(Error::BlockBoundary)))
        );
        // A partial block at end of input is truncated, not misframed.
        assert_eq!(
            decode_all(make, &[0x82, 0xc0]),
            (Vec::new(), Some(Fail::Truncated { unread: 1 }))
        );
        // Two messages in one block, one in the next.
        let ok = [0x84, 0xc0, 0x81, 0xc0, 0x81, 0x82, 0xc0, 0x81];
        assert_eq!(decode_all(make, &ok), (vec![empty; 3], None));
        let mut decoder = make();
        assert_eq!(decoder.decode(&ok, false), Ok(Step::Skip(1)));
        assert_eq!(decoder.remaining(), 4);
        for input in [
            &split[..],
            &tail,
            &ok,
            &[0x81, 0xc0],
            &[0x80],
            &[0, 0x81, 0x80],
        ] {
            check_decode_with_alloc_limit(make, input, 2 * MAX_MESSAGE_BYTES);
        }
    }
    #[test]
    fn blocks_refuse_zero_excessive_and_unterminated_sizes() {
        for bytes in [&[0x80][..], &[0, 0x80]] {
            assert_eq!(Blocks.decode(bytes, false), Err(Error::BlockSize));
            check_decode_with_alloc_limit(
                || Blocks,
                bytes,
                2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES),
            );
        }
        let mut over = Vec::new();
        UInt32((MAX_MESSAGE_BYTES + 1) as u32)
            .write(&mut over)
            .unwrap();
        assert_eq!(
            Blocks.decode(&over, false),
            Err(Error::Limit("MAX_MESSAGE_BYTES"))
        );
        assert_eq!(
            Blocks.decode(&[0; MAX_INTEGER_BYTES], false),
            Err(Error::Limit("MAX_INTEGER_BYTES"))
        );
        for bytes in [&over[..], &[0; MAX_INTEGER_BYTES], &[0], &[0x82, 0x80]] {
            check_decode_with_alloc_limit(
                || Blocks,
                bytes,
                2 * (MAX_MESSAGE_BYTES + MAX_INTEGER_BYTES),
            );
        }
        let mut maximum = vec![0; MAX_INTEGER_BYTES - 1];
        maximum.extend_from_slice(&[0x81, 0x80]);
        assert_eq!(
            Blocks.decode(&maximum, false),
            Ok(Step::Item(vec![0x80], maximum.len()))
        );
        let mut maximum = UInt32(MAX_MESSAGE_BYTES as u32).to_bytes().unwrap();
        let header = maximum.len();
        maximum.resize(header + MAX_MESSAGE_BYTES, 0x80);
        assert_eq!(
            Blocks.decode(&maximum[..maximum.len() - 1], false),
            Ok(Step::Need)
        );
        assert_eq!(
            Blocks.decode(&maximum, false),
            Ok(Step::Item(vec![0x80; MAX_MESSAGE_BYTES], maximum.len()))
        );
        let mut framed = vec![0x82];
        framed.extend_from_slice(&[0xc0, 0x81]);
        let mut stream = Stream::new(Blocks);
        let mut got = Vec::new();
        for part in chunks(&framed, &[1]) {
            pump(&mut stream, part, |block| got.push(block)).unwrap();
        }
        finish(&mut stream, |block| got.push(block)).unwrap();
        assert_eq!(got, [vec![0xc0, 0x81]]);
    }
    #[test]
    fn tiny_messages_do_not_visit_unrelated_dictionary_slots() {
        let fields = (0..MAX_DICTIONARY_ENTRIES)
            .map(|i| format!("<byteVector name=\"v{i}\"><copy/></byteVector>"))
            .collect::<String>();
        let t = xml_templates(&format!(
            "<template name=\"Full\" id=\"1\">{fields}</template><template name=\"Empty\" id=\"2\"/>"
        ));
        let mut encoder = Encoder::new(t.clone());
        let mut frames = Messages::new(t.clone());
        let mut exact = Messages::new(t);
        let large = message(
            (0..MAX_DICTIONARY_ENTRIES)
                .map(|i| Value::Bytes(if i < 16 { vec![7; 60_000] } else { Vec::new() }))
                .collect(),
        );
        let mut bytes = Vec::new();
        encoder.write(&large, &mut bytes).unwrap();
        assert_eq!(
            frames.decode(&bytes, false),
            Ok(Step::Item(large.clone(), bytes.len()))
        );
        assert_eq!(exact.parse_exact(&bytes), Ok(large));
        let tiny = Message {
            template_id: 2,
            fields: Vec::new(),
        };
        bytes.clear();
        encoder.write(&tiny, &mut bytes).unwrap();
        assert_eq!(
            frames.decode(&bytes, false),
            Ok(Step::Item(tiny.clone(), bytes.len()))
        );
        assert_eq!(exact.parse_exact(&bytes), Ok(tiny.clone()));
        for _ in 0..8 {
            for operation in 0..3 {
                DICTIONARY_WORK.with(|work| work.set(0));
                match operation {
                    0 => assert_eq!(
                        frames.decode(&[0x80], false),
                        Ok(Step::Item(tiny.clone(), 1))
                    ),
                    1 => assert_eq!(exact.parse_exact(&[0x80]), Ok(tiny.clone())),
                    _ => {
                        bytes.clear();
                        encoder.write(&tiny, &mut bytes).unwrap();
                        assert_eq!(bytes, [0x80]);
                    }
                }
                assert_eq!(
                    DICTIONARY_WORK.with(|work| work.get()),
                    0,
                    "operation {operation}"
                );
            }
        }
    }
    #[test]
    fn refused_messages_restore_prior_entries_and_template_id() {
        let t = xml_templates(
            "<template name=\"A\" id=\"1\"><sequence name=\"rows\"><length><constant value=\"3\"/></length><string name=\"s\"><copy/></string></sequence><string name=\"text\" charset=\"unicode\"/></template><template name=\"B\" id=\"2\"><string name=\"s\"><copy/></string><string name=\"text\" charset=\"unicode\"/></template>",
        );
        let valid = message(vec![
            Value::Sequence(vec![vec![Value::Ascii("old".into())]; 3]),
            Value::Unicode("OK".into()),
        ]);
        let mut encoder = Encoder::new(t.clone());
        let mut frames = Messages::new(t.clone());
        let mut exact = Messages::new(t);
        let mut first = Vec::new();
        encoder.write(&valid, &mut first).unwrap();
        assert_eq!(
            frames.decode(&first, false),
            Ok(Step::Item(valid.clone(), first.len()))
        );
        assert_eq!(exact.parse_exact(&first), Ok(valid.clone()));
        // Each row changes the same global entry. Invalid UTF-8 is found
        // after the scanner has finished and the parser has made all writes.
        let bad = [
            0x80, 0xc0, b'n', 0xb1, 0xc0, b'n', 0xb2, 0xc0, b'n', 0xb3, 0x81, 0xff,
        ];
        // Also change the copied template ID before failing.
        let other = [0xe0, 0x82, b'n', 0xb4, 0x81, 0xff];
        for refused in [&bad[..], &other[..]] {
            let saved = exact.state.clone();
            assert_eq!(exact.parse_exact(refused), Err(Error::Text));
            assert_eq!(frames.decode(refused, false), Err(Error::Text));
            for state in [&exact.state, &frames.state] {
                assert_eq!(state.template_id, saved.template_id);
                assert_eq!(state.bytes, saved.bytes);
                for (a, b) in state.entries.iter().zip(&saved.entries) {
                    assert_eq!(a.kind, b.kind);
                    assert_eq!(a.value, b.value);
                }
            }
            assert_eq!(
                exact.parse_exact(&[0x80, 0x80, 0x80, 0x80, 0x82, b'O', b'K']),
                Ok(valid.clone())
            );
            assert_eq!(
                frames.decode(&[0x80, 0x80, 0x80, 0x80, 0x82, b'O', b'K'], false),
                Ok(Step::Item(valid.clone(), 7))
            );
        }
        let mut bad_value = valid.clone();
        bad_value.fields[0] = Value::Sequence(vec![vec![Value::Ascii("new".into())]; 3]);
        bad_value.fields[1] = Value::UInt32(9);
        let mut out = vec![42];
        assert_eq!(encoder.write(&bad_value, &mut out), Err(Error::Value));
        assert_eq!(out, [42]);
        out.clear();
        encoder.write(&valid, &mut out).unwrap();
        assert_eq!(out, [0x80, 0x80, 0x80, 0x80, 0x82, b'O', b'K']);
    }
    #[test]
    fn template_wire_ids_use_only_ascii_digits() {
        for id in ["+1", "-1", "１", "4294967296", "feed"] {
            let t = xml_templates(&format!("<template name=\"A\" id=\"{id}\"/>"));
            assert_eq!(t.templates()[0].id, None, "{id}");
            assert_eq!(t.templates()[0].auxiliary_id.as_deref(), Some(id));
        }
        for id in ["", " 1", "1 "] {
            let xml = format!("<template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"A\" id=\"{id}\"/>");
            assert_eq!(
                Templates::from_xml(xml.as_bytes()).unwrap_err(),
                Error::Template
            );
        }
        let t = xml_templates("<template name=\"A\" id=\"0001\"/>");
        assert_eq!(t.templates()[0].id, Some(1));
    }
    #[test]
    fn transactional_writes_and_exact_parse() {
        let t = templates(
            "<uInt32 name=\"n\"><increment value=\"1\"/></uInt32><string name=\"c\"><constant value=\"OK\"/></string>",
        );
        let mut e = Encoder::new(t.clone());
        let mut d = Messages::new(t);
        let mut out = vec![42];
        assert_eq!(
            e.write(
                &message(vec![Value::UInt32(8), Value::Ascii("bad".into())]),
                &mut out
            ),
            Err(Error::Value)
        );
        assert_eq!(out, [42]);
        out.clear();
        let valid = message(vec![Value::UInt32(1), Value::Ascii("OK".into())]);
        e.write(&valid, &mut out).unwrap();
        assert_eq!(out, [0xc0, 0x81]);
        assert_eq!(d.parse_exact(&[0xc0, 0x81, 0x80]), Err(Error::Trailing));
        assert_eq!(d.parse_exact(&out).unwrap(), valid);
        assert_eq!(d.parse_exact(&[0xa0]), Err(Error::Truncated));
        assert_eq!(d.parse_exact(&[0x80]).unwrap().fields[0], Value::UInt32(2));
        let t = templates("<string name=\"s\"><tail value=\"long\"/></string>");
        assert_eq!(
            Encoder::new(t).write(&message(vec![Value::Ascii("x".into())]), &mut out),
            Err(Error::Value)
        );
    }
    #[test]
    fn xml_grammar_namespaces_initials_and_binding() {
        let t = Templates::from_xml(br#"<?xml version="1.0"?><f:templates xmlns:f="http://www.fixprotocol.org/ns/fast/td/1.1" xmlns:x="urn:extension" ns="urn:fields" templateNs="urn:templates" dictionary="book"><x:note><x:n/></x:note><f:template name="One" id="aux" x:label="ignored"><f:byteVector name="b"><f:length name="size"/><f:constant value="00 ff 1A"/></f:byteVector><f:string name="s" charset="unicode"><f:length name="size"/><f:default value="&lt;&#233;&gt;"/></f:string></f:template></f:templates>"#).unwrap();
        let mut bound = t.clone();
        bound
            .bind(
                &Name {
                    namespace: "urn:templates".into(),
                    local: "One".into(),
                },
                1,
            )
            .unwrap();
        assert_eq!(t.templates()[0].id, None);
        exchange(
            bound,
            &[message(vec![
                Value::Bytes(vec![0, 255, 26]),
                Value::Unicode("<é>".into()),
            ])],
        );
        for field in [
            "<uInt32 name=\"x\"><constant/></uInt32>",
            "<uInt32 name=\"x\"><default/></uInt32>",
            "<string name=\"x\"><increment/></string>",
            "<uInt32 name=\"x\"><tail/></uInt32>",
            "<uInt32 name=\"x\"><copy value=\"-1\"/></uInt32>",
            "<uInt32 name=\"x\"><copy value=\"+1\"/></uInt32>",
            "<decimal name=\"x\"><copy value=\"1e2\"/></decimal>",
            "<byteVector name=\"x\"><copy value=\"0\"/></byteVector>",
            "<uInt32 name=\"x\"><copy/><default value=\"1\"/></uInt32>",
            "<string name=\"x\"><length name=\"n\"/></string>",
            "<templateRef templateNs=\"x\"/>",
            "<uInt32 name=\"x\" bogus=\"y\"/>",
            "<decimal name=\"x\"><mantissa/><exponent/></decimal>",
        ] {
            let xml =
                format!("<template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"T\">{field}</template>");
            assert!(Templates::from_xml(xml.as_bytes()).is_err(), "{field}");
        }
        assert!(Templates::from_xml(b"<templates/>").is_err());
        assert!(
            Templates::from_xml(
                format!("<!DOCTYPE template><template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"T\"/>")
                    .as_bytes()
            )
            .is_err()
        );
        for body in [
            "<template name=\"T\"><templateRef name=\"T\"/></template>",
            "<template name=\"T\"><templateRef name=\"missing\"/></template>",
            "<template name=\"T\"/><template name=\"T\"/>",
            "<template name=\"T\" id=\"1\"/><template name=\"U\" id=\"1\"/>",
        ] {
            assert!(
                Templates::from_xml(
                    format!("<templates xmlns=\"{TEMPLATE_NAMESPACE}\">{body}</templates>")
                        .as_bytes()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn template_sequence_expansion_and_depth_limits() {
        assert_eq!(
            Templates::from_xml(&vec![b' '; MAX_TEMPLATE_BYTES + 1]).unwrap_err(),
            Error::Limit("MAX_TEMPLATE_BYTES")
        );
        let many = (0..=MAX_TEMPLATES)
            .map(|i| format!("<template name=\"T{i}\"/>"))
            .collect::<String>();
        assert_eq!(
            Templates::from_xml(
                format!("<templates xmlns=\"{TEMPLATE_NAMESPACE}\">{many}</templates>").as_bytes()
            )
            .unwrap_err(),
            Error::Limit("MAX_TEMPLATES")
        );
        let many = (0..=MAX_FIELDS)
            .map(|i| format!("<uInt32 name=\"f{i}\"/>"))
            .collect::<String>();
        assert!(matches!(
            Templates::from_xml(
                format!("<template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"T\">{many}</template>")
                    .as_bytes()
            ),
            Err(Error::Limit("MAX_FIELDS"))
        ));
        let deep = format!(
            "<template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"T\">{}{}</template>",
            "<group name=\"g\">".repeat(MAX_DEPTH),
            "</group>".repeat(MAX_DEPTH)
        );
        assert_eq!(
            Templates::from_xml(deep.as_bytes()).unwrap_err(),
            Error::Limit("MAX_DEPTH")
        );
        let t = templates("<sequence name=\"s\"><uInt32 name=\"x\"/></sequence>");
        let mut bytes = vec![0xc0, 0x81];
        put_integer((MAX_SEQUENCE_LENGTH + 1) as i128, false, false, &mut bytes).unwrap();
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&bytes),
            Err(Error::Limit("MAX_SEQUENCE_LENGTH"))
        );
        check_decode_with_alloc_limit(|| Messages::new(t.clone()), &bytes, 2 * MAX_MESSAGE_BYTES);
        let t = templates(
            "<sequence name=\"outer\"><length><constant value=\"4096\"/></length><sequence name=\"inner\"><length><constant value=\"4096\"/></length></sequence></sequence>",
        );
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&[0xc0, 0x81]),
            Err(Error::Limit("MAX_VALUES"))
        );
        check_decode_with_alloc_limit(
            || Messages::new(t.clone()),
            &[0xc0, 0x81],
            2 * MAX_MESSAGE_BYTES,
        );
        let t = templates("<templateRef/>");
        let bytes = [vec![0xc0, 0x81], vec![0x80; MAX_DEPTH]].concat();
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&bytes),
            Err(Error::Limit("MAX_DEPTH"))
        );
        check_decode_with_alloc_limit(|| Messages::new(t.clone()), &bytes, 2 * MAX_MESSAGE_BYTES);
    }
    #[test]
    fn fragmented_long_fields_keep_bounded_state_and_progress() {
        let t = templates("<string name=\"s\"/><byteVector name=\"b\"/>");
        let m = message(vec![
            Value::Ascii("A".repeat(MAX_STRING_BYTES)),
            Value::Bytes(vec![0xff; MAX_STRING_BYTES]),
        ]);
        let mut bytes = Vec::new();
        Encoder::new(t.clone()).write(&m, &mut bytes).unwrap();
        let mut stream = Stream::new(Messages::new(t));
        let held = stream.held();
        let mut result = Vec::new();
        for part in chunks(&bytes, &[1]) {
            pump(&mut stream, part, |m| result.push(m)).unwrap();
            if result.is_empty() {
                assert_eq!(stream.held(), held);
            }
        }
        finish(&mut stream, |m| result.push(m)).unwrap();
        assert_eq!(result, [m]);
    }
    #[test]
    fn malformed_bytes_obey_contracts() {
        let t = templates(
            "<int64 name=\"n\" presence=\"optional\"><delta/></int64><string name=\"s\" presence=\"optional\"><copy/></string><sequence name=\"rows\"><uInt32 name=\"x\"/></sequence>",
        );
        for n in 0..=255u8 {
            let bytes = [n, n.rotate_left(3), 0x81, n.wrapping_add(1), 0x80, n, 0xff];
            check_wire::<Int64>(&bytes);
            check_wire::<Nullable<UInt64>>(&bytes);
            check_wire::<Ascii>(&bytes);
            check_wire::<Nullable<Ascii>>(&bytes);
            check_wire::<Unicode>(&bytes);
            check_wire::<ByteVector>(&bytes);
            check_wire::<Decimal>(&bytes);
            check_wire::<PresenceMap>(&bytes);
            check_decode_with_alloc_limit(|| Messages::new(t.clone()), &bytes, 2 * MAX_MESSAGE_BYTES);
        }
    }
    #[test]
    fn aggregate_resource_limits_and_reset_recovery() {
        let bodies = (1..=17).map(|i| format!("<template name=\"T{i}\" id=\"{i}\"><byteVector name=\"v{i}\"><copy/></byteVector></template>")).collect::<String>();
        let t = xml_templates(&bodies);
        let mut e = Encoder::new(t.clone());
        let mut d = Messages::new(t);
        for id in 1..=16 {
            let m = Message {
                template_id: id,
                fields: vec![Value::Bytes(vec![7; MAX_STRING_BYTES])],
            };
            let mut bytes = Vec::new();
            e.write(&m, &mut bytes).unwrap();
            assert_eq!(d.parse_exact(&bytes).unwrap(), m);
        }
        let m = Message {
            template_id: 17,
            fields: vec![Value::Bytes(vec![8; MAX_STRING_BYTES])],
        };
        let mut bytes = vec![42];
        assert_eq!(
            e.write(&m, &mut bytes),
            Err(Error::Limit("MAX_DICTIONARY_BYTES"))
        );
        assert_eq!(bytes, [42]);
        let mut wire = vec![0xe0, 0x91];
        ByteVector(vec![8; MAX_STRING_BYTES])
            .write(&mut wire)
            .unwrap();
        assert_eq!(
            d.parse_exact(&wire),
            Err(Error::Limit("MAX_DICTIONARY_BYTES"))
        );
        assert_eq!(
            d.decode(&wire, false),
            Err(Error::Limit("MAX_DICTIONARY_BYTES"))
        );
        let previous = Message {
            template_id: 16,
            fields: vec![Value::Bytes(vec![7; MAX_STRING_BYTES])],
        };
        let mut after = Vec::new();
        e.write(&previous, &mut after).unwrap();
        assert_eq!(after, [0x80]);
        assert_eq!(d.decode(&after, false), Ok(Step::Item(previous, 1)));
        e.reset();
        d.reset();
        bytes.clear();
        e.write(&m, &mut bytes).unwrap();
        assert_eq!(d.parse_exact(&bytes).unwrap(), m);

        let t = templates(&format!(
            "<sequence name=\"s\"><length><constant value=\"4096\"/></length><string name=\"v\"><constant value=\"{}\"/></string></sequence>",
            "a".repeat(257)
        ));
        assert_eq!(
            Messages::new(t.clone()).parse_exact(&[0xc0, 0x81]),
            Err(Error::Limit("MAX_VALUE_BYTES"))
        );
        let m = message(vec![Value::Sequence(vec![
            vec![Value::Ascii(
                "a".repeat(257)
            )];
            MAX_SEQUENCE_LENGTH
        ])]);
        let mut bytes = vec![42];
        assert_eq!(
            Encoder::new(t).write(&m, &mut bytes),
            Err(Error::Limit("MAX_VALUE_BYTES"))
        );
        assert_eq!(bytes, [42]);

        let t = templates(
            &(0..17)
                .map(|i| format!("<byteVector name=\"v{i}\"/>"))
                .collect::<String>(),
        );
        let mut bytes = vec![0xc0, 0x81];
        for _ in 0..15 {
            ByteVector(vec![0; MAX_STRING_BYTES])
                .write(&mut bytes)
                .unwrap();
        }
        UInt32(MAX_STRING_BYTES as u32).write(&mut bytes).unwrap();
        assert_eq!(
            Messages::new(t.clone()).decode(&bytes, false),
            Err(Error::Limit("MAX_MESSAGE_BYTES"))
        );
        let m = message(vec![Value::Bytes(vec![0; MAX_STRING_BYTES]); 17]);
        let mut bytes = vec![42];
        assert_eq!(
            Encoder::new(t).write(&m, &mut bytes),
            Err(Error::Limit("MAX_MESSAGE_BYTES"))
        );
        assert_eq!(bytes, [42]);
    }
    #[test]
    fn xml_node_name_dictionary_and_binding_limits() {
        let children = "<x:n/>".repeat(MAX_XML_NODES);
        let xml = format!(
            "<templates xmlns=\"{TEMPLATE_NAMESPACE}\" xmlns:x=\"urn:x\">{children}</templates>"
        );
        assert_eq!(
            Templates::from_xml(xml.as_bytes()).unwrap_err(),
            Error::Limit("MAX_XML_NODES")
        );
        let xml = format!(
            "<template xmlns=\"{TEMPLATE_NAMESPACE}\" name=\"{}\"/>",
            "a".repeat(MAX_NAME_BYTES + 1)
        );
        assert_eq!(
            Templates::from_xml(xml.as_bytes()).unwrap_err(),
            Error::Limit("MAX_NAME_BYTES")
        );
        let fields = (0..300)
            .map(|i| format!("<uInt32 name=\"v{i}\"><copy/></uInt32>"))
            .collect::<String>();
        let templates = (0..17).map(|i| format!("<template name=\"T{i}\" dictionary=\"type\"><typeRef name=\"A{i}\"/>{}</template>",if i == 0 { fields.as_str() } else { "" })).collect::<String>();
        let xml = format!("<templates xmlns=\"{TEMPLATE_NAMESPACE}\">{templates}</templates>");
        assert_eq!(
            Templates::from_xml(xml.as_bytes()).unwrap_err(),
            Error::Limit("MAX_DICTIONARY_ENTRIES")
        );
        let templates = (0..130).map(|i| format!("<template name=\"T{i}\" dictionary=\"type\"><typeRef name=\"A{i}\"/><uInt32 name=\"x\"><copy key=\"shared\"/></uInt32></template>")).collect::<String>();
        let xml = format!("<templates xmlns=\"{TEMPLATE_NAMESPACE}\">{templates}</templates>");
        assert_eq!(
            Templates::from_xml(xml.as_bytes()).unwrap_err(),
            Error::Limit("MAX_DICTIONARY_BINDINGS")
        );
    }
    #[test]
    fn operator_type_and_nullable_matrix() {
        let cases = [
            ("int32", "1", Value::Int32(1), Value::Int32(2)),
            ("uInt32", "1", Value::UInt32(1), Value::UInt32(2)),
            ("int64", "1", Value::Int64(1), Value::Int64(2)),
            ("uInt64", "1", Value::UInt64(1), Value::UInt64(2)),
            (
                "decimal",
                "1",
                Value::Decimal(Decimal {
                    exponent: 0,
                    mantissa: 1,
                }),
                Value::Decimal(Decimal {
                    exponent: 0,
                    mantissa: 2,
                }),
            ),
            (
                "string",
                "AB",
                Value::Ascii("AB".into()),
                Value::Ascii("AC".into()),
            ),
            (
                "string charset=\"unicode\"",
                "é",
                Value::Unicode("é".into()),
                Value::Unicode("ê".into()),
            ),
            (
                "byteVector",
                "00ff",
                Value::Bytes(vec![0, 255]),
                Value::Bytes(vec![0, 128]),
            ),
        ];
        for (tag, initial, first, next) in cases {
            for op in ["constant", "default", "copy", "increment", "delta", "tail"] {
                let integer = matches!(
                    first,
                    Value::Int32(_) | Value::UInt32(_) | Value::Int64(_) | Value::UInt64(_)
                );
                let text = matches!(first, Value::Ascii(_) | Value::Unicode(_) | Value::Bytes(_));
                if (op == "increment" && !integer) || (op == "tail" && !text) {
                    continue;
                }
                for nullable in [false, true] {
                    let end = tag.split_whitespace().next().unwrap();
                    let field = format!(
                        "<{tag} name=\"v\" presence=\"{}\"><{op} value=\"{initial}\"/></{end}>",
                        if nullable { "optional" } else { "mandatory" }
                    );
                    let t = templates(&field);
                    let mut values =
                        vec![message(vec![first.clone()]), message(vec![first.clone()])];
                    if nullable {
                        values.push(message(vec![Value::Null]));
                        values.push(message(vec![first.clone()]));
                    }
                    if op != "constant" {
                        values.push(message(vec![next.clone()]));
                    }
                    exchange(t, &values);
                }
            }
        }
    }
    #[test]
    fn decimal_initials_normalize_before_fixed_width_conversion() {
        for (literal, value) in [
            (
                format!("1{}", "0".repeat(63)),
                Decimal {
                    exponent: 63,
                    mantissa: 1,
                },
            ),
            (
                format!("0.{}1", "0".repeat(62)),
                Decimal {
                    exponent: -63,
                    mantissa: 1,
                },
            ),
            (
                format!("1.{}", "0".repeat(100)),
                Decimal {
                    exponent: 0,
                    mantissa: 1,
                },
            ),
            (
                format!("-0.{}", "0".repeat(100)),
                Decimal {
                    exponent: 0,
                    mantissa: 0,
                },
            ),
            (
                "-9223372036854775808".into(),
                Decimal {
                    exponent: 0,
                    mantissa: i64::MIN,
                },
            ),
        ] {
            let t = templates(&format!(
                "<decimal name=\"d\"><constant value=\"{literal}\"/></decimal>"
            ));
            assert_eq!(
                exchange(t, &[message(vec![Value::Decimal(value)])]),
                [0xc0, 0x81]
            );
        }
    }
    #[test]
    fn cloned_decoders_preserve_framing_reservations() {
        let t = templates("<group name=\"g\"><string name=\"s\"/></group>");
        let original = Messages::new(t);
        check_decode_with_alloc_limit(
            || original.clone(),
            &[0xc0, 0x81, b'A', 0xc2],
            2 * MAX_MESSAGE_BYTES,
        );
        let mut partial = original.clone();
        assert_eq!(partial.decode(&[0xc0, 0x81, b'A'], false), Ok(Step::Need));
        let mut cloned = partial.clone();
        let held = cloned.held();
        assert_eq!(
            cloned.decode(&[0xc0, 0x81, b'A', b'B'], false),
            Ok(Step::Need)
        );
        assert_eq!(cloned.held(), held);
        assert_eq!(
            cloned.decode(&[0xc0, 0x81, b'A', b'B', 0xc3], false),
            Ok(Step::Item(
                message(vec![Value::Group(vec![Value::Ascii("ABC".into())])]),
                5
            ))
        );
    }
}
