//! ASN.1 BER and DER: reading and writing tags, lengths and values, with no
//! I/O.
//!
//! This is an encoding layer. `Frame` implements `Wire`, `Elements` decodes a
//! stream, and `Reader` and `Writer` handle individual values. It does not
//! compile ASN.1 schemas or implement the sessions, services, or cryptography
//! of protocols that use ASN.1.
//!
//! ASN.1 describes data structures, and its encoding rules turn them into
//! bytes. The Basic Encoding Rules (BER) allow several encodings of one
//! value. The Distinguished Encoding Rules (DER) allow exactly one. LDAP,
//! Kerberos and SNMP speak BER. X.509 certificates, OCSP and most other
//! signed structures use DER. Each value is a TLV: a tag that says what it
//! is, a length, and the contents. A constructed value's contents are more
//! TLVs. This module follows ITU-T X.690 (02/2021), the BER and DER
//! specification, and the character sets and time formats of ITU-T X.680.
//!
//! Nothing here reads a socket. A world that plays an LDAP server pushes the
//! bytes it reads from a connection to a [`Stream<Elements>`](fictionet::stdlib::codec::Stream),
//! gets one message's bytes at a time, and walks each one with a [`Reader`]. A world that
//! checks a certificate reads it with [`Rules::Der`], so any encoding DER
//! does not allow is refused. Replies are built with a [`Writer`], which
//! always writes DER. DER is also valid BER, so a reader under either rules
//! accepts what a writer writes. What the values mean (which sequence is a
//! bind request, which object identifier names which algorithm) is up to
//! world code.
//!
//! Every reader checks lengths, nesting and character sets, because the
//! agent can send any bytes it likes. Elements are at most [`MAX_INPUT`]
//! bytes, and constructed values nest at most [`MAX_DEPTH`] deep.
//!
//! ```
//! use fictionet::stdlib::asn1::{Error, Oid, Reader, Rules, Writer};
//!
//! // An AlgorithmIdentifier for sha256WithRSAEncryption, as X.509 writes it.
//! let oid: Oid = "1.2.840.113549.1.1.11".parse().unwrap();
//! let mut w = Writer::new();
//! w.sequence(|w| {
//!     w.oid(&oid);
//!     w.null();
//! });
//! let der = w.finish().unwrap();
//! assert_eq!(der, [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00]);
//!
//! let mut r = Reader::new(&der, Rules::Der);
//! let mut fields = r.read_sequence().unwrap();
//! assert_eq!(fields.read_oid().unwrap().to_string(), "1.2.840.113549.1.1.11");
//! fields.read_null().unwrap();
//! fields.finish().unwrap();
//! r.finish().unwrap();
//!
//! // The same value in BER with an indefinite length. BER reads it; DER
//! // refuses it.
//! let mut ber = vec![0x30, 0x80];
//! ber.extend_from_slice(&der[2..]);
//! ber.extend_from_slice(&[0x00, 0x00]);
//! let mut fields = Reader::new(&ber, Rules::Ber).read_sequence().unwrap();
//! assert_eq!(fields.read_oid().unwrap(), oid);
//! assert_eq!(Reader::new(&ber, Rules::Der).read_sequence().err(), Some(Error::Indefinite));
//! ```

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// Implements DER [`Wire`] parsing and checked writing for a protocol item.
///
/// Pass the local ASN.1 module path, item and error types, the refusal value,
/// and docs for each method. The item supplies `encode` and `decode` methods.
/// The module path keeps copied protocol modules independent of this crate.
#[macro_export]
macro_rules! der_wire {
    ($asn1:ident, impl Wire for $item:ty, $error:ty, $unwritable:expr,
     [$(#[$parse:meta])*], [$(#[$write:meta])*]) => {
        impl fictionet::stdlib::codec::Wire for $item {
            type ParseError = $error;
            type WriteError = $error;

            $(#[$parse])*
            fn parse(bytes: &[u8]) -> Result<Self, $error> {
                Self::decode(bytes)
            }

            $(#[$write])*
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                $asn1::write_checked(self, Self::encode, Self::decode, $unwritable, out)
            }
        }
    };
}

/// Encodes `value` and appends the bytes only if `decode` reads the same value.
///
/// Use this in [`Wire::write`] implementations with separate encode and decode
/// functions. Those functions must enforce the type's size and field limits.
/// The temporary encoding is kept only for this call.
///
/// Returns an encoding error unchanged. Returns `unwritable` if decoding fails
/// or changes the value. Leaves `out` unchanged on either error.
pub fn write_checked<T: PartialEq, E>(
    value: &T,
    encode: impl FnOnce(&T) -> Result<Vec<u8>, E>,
    decode: impl FnOnce(&[u8]) -> Result<T, E>,
    unwritable: E,
    out: &mut Vec<u8>,
) -> Result<(), E> {
    let bytes = encode(value)?;
    if decode(&bytes).as_ref().ok() != Some(value) {
        return Err(unwritable);
    }
    out.extend_from_slice(&bytes);
    Ok(())
}

/// The longest element, header and contents together, a reader accepts and
/// a writer writes. A [`Stream<Elements>`](fictionet::stdlib::codec::Stream) never holds much more than this.
pub const MAX_INPUT: usize = 1 << 20;
/// How deep constructed values may nest. Elements read straight from the
/// input are at depth 0, their children at depth 1, and so on. A
/// constructed element at this depth can be read but not opened. One with
/// an indefinite length cannot be read either, since finding its end means
/// looking inside it.
pub const MAX_DEPTH: usize = 32;
/// The most octets a long-form length may have after its first octet. BER
/// allows up to 126, but no element under [`MAX_INPUT`] needs more than 3.
pub const MAX_LENGTH_OCTETS: usize = 4;
/// The longest object identifier's contents, in bytes.
pub const MAX_OID_LEN: usize = 255;
/// The longest UTCTime or GeneralizedTime text.
pub const MAX_TIME_LEN: usize = 64;

/// Which encoding rules a reader holds input to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rules {
    /// The Basic Encoding Rules: indefinite lengths, long-form lengths with
    /// spare octets, strings split into segments, and any nonzero byte for
    /// TRUE are all allowed.
    Ber,
    /// The Distinguished Encoding Rules: one encoding per value. Lengths
    /// are definite and as short as they can be, strings are primitive,
    /// and sets are in order.
    Der,
}

/// Why bytes are not the ASN.1 a reader asked for, or why a writer could
/// not write a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ends inside an element, or an element runs past the end
    /// of the one holding it.
    Truncated,
    /// An element, or a value a writer was given, is longer than
    /// [`MAX_INPUT`].
    TooLong,
    /// Constructed values nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The identifier octets are malformed: a number below 31 in the long
    /// form, a long form with a leading zero group, a number too large for
    /// 32 bits, or a tag a writer may not use.
    Tag,
    /// The length octets are malformed: the reserved value 0xFF, or more
    /// than [`MAX_LENGTH_OCTETS`] octets.
    Length,
    /// Under DER, a length written in more octets than it needs.
    NonMinimalLength,
    /// An indefinite length where it is not allowed: under DER, or on a
    /// primitive element.
    Indefinite,
    /// An end-of-contents marker (tag 0) outside an indefinite length, or
    /// one that is malformed.
    Eoc,
    /// The next element has another tag. For [`Reader::read_text`],
    /// `expected` is UTF8String and stands for any string type.
    Unexpected {
        /// The tag that was asked for.
        expected: Tag,
        /// The tag that came.
        found: Tag,
    },
    /// The reader has no more elements.
    Empty,
    /// Bytes remain after the last element that was expected.
    Trailing,
    /// A primitive element was opened as if it held other elements.
    Primitive,
    /// A constructed element where only the primitive form is allowed: a
    /// boolean, integer, null or object identifier, or under DER, a string.
    Constructed,
    /// A boolean's contents are not one byte, or under DER, not 0x00 or
    /// 0xFF.
    Boolean,
    /// An integer's contents are empty or start with a redundant byte, or
    /// the integer does not fit the type asked for.
    Integer,
    /// A null has contents.
    Null,
    /// A bit string's unused-bit count is above 7 or set on an empty
    /// string, a segment other than the last has unused bits, or under DER
    /// the unused bits are not zero.
    BitString,
    /// An object identifier is empty, too long, or has a malformed or
    /// oversized arc.
    Oid,
    /// A string holds characters its type does not allow, or a type whose
    /// character set this module does not decode was asked for as text.
    Charset,
    /// A UTCTime or GeneralizedTime is not well formed, names a date or
    /// time that does not exist, or under DER, is not in the one form DER
    /// allows.
    Time,
    /// Under DER, a set's elements are out of order, or a writer's set has
    /// two elements with the same tag.
    SetOrder,
    /// [`Writer::implicit`] or [`Writer::explicit`] was given a closure
    /// that did not write exactly one element.
    Implicit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => f.write_str("input ends inside an element"),
            Error::TooLong => write!(f, "element longer than {MAX_INPUT} bytes"),
            Error::TooDeep => write!(f, "values nested deeper than {MAX_DEPTH}"),
            Error::Tag => f.write_str("malformed tag"),
            Error::Length => f.write_str("malformed length"),
            Error::NonMinimalLength => f.write_str("length not in its shortest form (DER)"),
            Error::Indefinite => f.write_str("indefinite length not allowed here"),
            Error::Eoc => f.write_str("misplaced or malformed end-of-contents"),
            Error::Unexpected { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            Error::Empty => f.write_str("no more elements"),
            Error::Trailing => f.write_str("bytes after the last element"),
            Error::Primitive => f.write_str("primitive element where a constructed one was expected"),
            Error::Constructed => f.write_str("constructed element where a primitive one was expected"),
            Error::Boolean => f.write_str("malformed boolean"),
            Error::Integer => f.write_str("malformed or out-of-range integer"),
            Error::Null => f.write_str("null with contents"),
            Error::BitString => f.write_str("malformed bit string"),
            Error::Oid => f.write_str("malformed object identifier"),
            Error::Charset => f.write_str("characters outside the string type's set"),
            Error::Time => f.write_str("malformed time"),
            Error::SetOrder => f.write_str("set elements out of order or repeated"),
            Error::Implicit => f.write_str("a tag needs exactly one element under it"),
        }
    }
}

impl std::error::Error for Error {}

/// A tag's class: who defined its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Defined by X.680 itself, such as INTEGER or SEQUENCE.
    Universal,
    /// Defined by one application's specification, such as LDAP's
    /// BindRequest.
    Application,
    /// Meaningful only inside the structure that holds it, such as `[0]`.
    ContextSpecific,
    /// Defined by a private agreement.
    Private,
}

impl Class {
    fn bits(self) -> u8 {
        (self as u8) << 6
    }

    fn from_bits(b: u8) -> Class {
        match b >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }
}

/// An element's tag: its class, whether its contents are more elements,
/// and its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tag {
    /// Who defined the number.
    pub class: Class,
    /// Whether the contents are more elements (constructed) or the value's
    /// own bytes (primitive).
    pub constructed: bool,
    /// The tag number.
    pub number: u32,
}
// Universal tag assignments from ITU-T X.680.
impl Tag {
    /// BOOLEAN (UNIVERSAL 1): a true or false value.
    pub const BOOLEAN: Tag = Tag::universal(1);
    /// INTEGER (UNIVERSAL 2): a signed whole number.
    pub const INTEGER: Tag = Tag::universal(2);
    /// BIT STRING (UNIVERSAL 3): an ordered sequence of bits.
    pub const BIT_STRING: Tag = Tag::universal(3);
    /// OCTET STRING (UNIVERSAL 4): an ordered sequence of bytes.
    pub const OCTET_STRING: Tag = Tag::universal(4);
    /// NULL (UNIVERSAL 5): a value with no contents.
    pub const NULL: Tag = Tag::universal(5);
    /// OBJECT IDENTIFIER (UNIVERSAL 6): a path of numeric arcs naming an object.
    pub const OID: Tag = Tag::universal(6);
    /// ENUMERATED (UNIVERSAL 10): a value from a named set of alternatives.
    pub const ENUMERATED: Tag = Tag::universal(10);
    /// UTF8String (UNIVERSAL 12): text encoded as UTF-8.
    pub const UTF8_STRING: Tag = Tag::universal(12);
    /// SEQUENCE or SEQUENCE OF (UNIVERSAL 16): an ordered collection of values.
    pub const SEQUENCE: Tag = Tag::universal(16).as_constructed();
    /// SET or SET OF (UNIVERSAL 17): an unordered collection of values.
    pub const SET: Tag = Tag::universal(17).as_constructed();
    /// NumericString (UNIVERSAL 18): digits and spaces.
    pub const NUMERIC_STRING: Tag = Tag::universal(18);
    /// PrintableString (UNIVERSAL 19): letters, digits, spaces, and selected punctuation.
    pub const PRINTABLE_STRING: Tag = Tag::universal(19);
    /// TeletexString (UNIVERSAL 20): text from the Teletex character repertoire.
    pub const TELETEX_STRING: Tag = Tag::universal(20);
    /// VideotexString (UNIVERSAL 21): text from the Videotex character repertoire.
    pub const VIDEOTEX_STRING: Tag = Tag::universal(21);
    /// IA5String (UNIVERSAL 22): text from the seven-bit IA5 character repertoire.
    pub const IA5_STRING: Tag = Tag::universal(22);
    /// UTCTime (UNIVERSAL 23): a date and time with a two-digit year.
    pub const UTC_TIME: Tag = Tag::universal(23);
    /// GeneralizedTime (UNIVERSAL 24): a date and time with a four-digit year.
    pub const GENERALIZED_TIME: Tag = Tag::universal(24);
    /// GraphicString (UNIVERSAL 25): graphic characters from registered character sets.
    pub const GRAPHIC_STRING: Tag = Tag::universal(25);
    /// VisibleString (UNIVERSAL 26): printing ASCII characters, including space.
    pub const VISIBLE_STRING: Tag = Tag::universal(26);
    /// GeneralString (UNIVERSAL 27): graphic and control characters from registered sets.
    pub const GENERAL_STRING: Tag = Tag::universal(27);
    /// UniversalString (UNIVERSAL 28): text from the ISO/IEC 10646 character repertoire.
    pub const UNIVERSAL_STRING: Tag = Tag::universal(28);
    /// BMPString (UNIVERSAL 30): text from the Unicode Basic Multilingual Plane.
    pub const BMP_STRING: Tag = Tag::universal(30);
}

impl Tag {
    /// A primitive universal tag.
    pub const fn universal(number: u32) -> Tag {
        Tag { class: Class::Universal, constructed: false, number }
    }

    /// A primitive application tag, `[APPLICATION number]`.
    pub const fn application(number: u32) -> Tag {
        Tag { class: Class::Application, constructed: false, number }
    }

    /// A primitive context-specific tag, `[number]`.
    pub const fn context(number: u32) -> Tag {
        Tag { class: Class::ContextSpecific, constructed: false, number }
    }

    /// A primitive private tag, `[PRIVATE number]`.
    pub const fn private(number: u32) -> Tag {
        Tag { class: Class::Private, constructed: false, number }
    }

    /// The same tag in constructed form.
    pub const fn as_constructed(self) -> Tag {
        Tag { class: self.class, constructed: true, number: self.number }
    }

    /// Whether two tags have the same class and number, in either form.
    pub fn same_type(self, other: Tag) -> bool {
        self.class == other.class && self.number == other.number
    }

    /// Reads the identifier octets at the start of `b`, and how many bytes
    /// they took.
    pub fn parse(b: &[u8]) -> Result<(Tag, usize), Error> {
        read_tag(b, 0)
    }

    /// Appends the identifier octets to `out`: one byte for numbers below
    /// 31, and otherwise 0x1F-style long form in as few bytes as it takes.
    pub fn encode(self, out: &mut Vec<u8>) {
        let first = self.class.bits() | if self.constructed { 0x20 } else { 0 };
        if self.number < 31 {
            out.push(first | self.number as u8);
        } else {
            out.push(first | 0x1f);
            push_base128(out, u128::from(self.number));
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.class {
            Class::Universal => "UNIVERSAL ",
            Class::Application => "APPLICATION ",
            Class::ContextSpecific => "",
            Class::Private => "PRIVATE ",
        };
        write!(f, "[{class}{}]", self.number)?;
        if self.constructed {
            f.write_str(" constructed")?;
        }
        Ok(())
    }
}

/// An element's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Length {
    /// The contents are this many bytes.
    Definite(usize),
    /// The contents run to an end-of-contents marker, two zero bytes. BER
    /// allows this on constructed elements only.
    Indefinite,
}

/// An element's identifier and length octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The tag.
    pub tag: Tag,
    /// The length of the contents.
    pub length: Length,
    /// How many bytes the identifier and length octets took.
    pub len: usize,
}

/// The capacity floor for ASN.1 message decoders. It leaves room for
/// any header [`Header::parse`] reads or refuses, even with a tiny limit.
pub const HEADER_ROOM: usize = 16;

impl Header {
    /// Reads the header at the start of `b` under `rules`. It returns
    /// [`Error::Truncated`] if `b` ends inside it.
    pub fn parse(b: &[u8], rules: Rules) -> Result<Header, Error> {
        read_header(b, 0, rules)
    }
}

/// Appends a definite length in its shortest form.
#[inline]
pub fn encode_length(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// The byte at `i` of an element that starts at `b[0]`. Past
/// [`MAX_INPUT`] the element is too long, whatever `b` holds.
fn at(b: &[u8], i: usize) -> Result<u8, Error> {
    if i >= MAX_INPUT {
        return Err(Error::TooLong);
    }
    b.get(i).copied().ok_or(Error::Truncated)
}

/// The tag at `b[start..]` and the index after it.
fn read_tag(b: &[u8], start: usize) -> Result<(Tag, usize), Error> {
    let first = at(b, start)?;
    let mut i = start + 1;
    let class = Class::from_bits(first);
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    if number == 31 {
        number = 0;
        let mut leading = true;
        loop {
            let c = at(b, i)?;
            i += 1;
            // The first subsequent octet may not be a zero group (8.1.2.4.2 c).
            if leading && c == 0x80 {
                return Err(Error::Tag);
            }
            leading = false;
            if number >> 25 != 0 {
                return Err(Error::Tag);
            }
            number = number << 7 | u32::from(c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
        }
        // Numbers below 31 must use the one-byte form (8.1.2.2).
        if number < 31 {
            return Err(Error::Tag);
        }
    }
    Ok((Tag { class, constructed, number }, i))
}

/// The header at `b[start..]`, with `len` counted from `start`.
fn read_header(b: &[u8], start: usize, rules: Rules) -> Result<Header, Error> {
    let (tag, mut i) = read_tag(b, start)?;
    let first = at(b, i)?;
    i += 1;
    let length = match first {
        0..=0x7f => Length::Definite(usize::from(first)),
        0x80 => {
            if rules == Rules::Der || !tag.constructed {
                return Err(Error::Indefinite);
            }
            Length::Indefinite
        }
        0xff => return Err(Error::Length),
        _ => {
            let n = usize::from(first & 0x7f);
            if n > MAX_LENGTH_OCTETS {
                return Err(Error::Length);
            }
            let mut v: u64 = 0;
            for k in 0..n {
                let c = at(b, i)?;
                i += 1;
                if rules == Rules::Der && k == 0 && c == 0 {
                    return Err(Error::NonMinimalLength);
                }
                v = v << 8 | u64::from(c);
            }
            if rules == Rules::Der && v < 0x80 {
                return Err(Error::NonMinimalLength);
            }
            if v > MAX_INPUT as u64 {
                return Err(Error::TooLong);
            }
            Length::Definite(v as usize)
        }
    };
    Ok(Header { tag, length, len: i - start })
}

fn is_eoc_tag(tag: Tag) -> bool {
    tag.class == Class::Universal && tag.number == 0
}

/// Finds the element at the start of `b`, at nesting depth `depth`. It
/// returns the header, where the contents end, and where the element ends.
/// An indefinite length is followed to its end-of-contents marker without
/// recursion: only headers are read, and a count of open elements is kept.
fn extent(b: &[u8], rules: Rules, depth: usize) -> Result<(Header, usize, usize), Error> {
    let h = read_header(b, 0, rules)?;
    if is_eoc_tag(h.tag) {
        return Err(Error::Eoc);
    }
    let n = match h.length {
        Length::Definite(n) => n,
        Length::Indefinite => {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            return match scan(b, rules, depth, Scan { pos: h.len, open: 1 })? {
                Ok((eoc, end)) => Ok((h, eoc, end)),
                Err(_) => Err(Error::Truncated),
            };
        }
    };
    let end = end_of(b, h.len, n)?;
    Ok((h, end, end))
}

/// How far a scan of an indefinite length has come: the start of the next
/// header to read, and how many elements are still open.
#[derive(Clone, Copy, Debug)]
struct Scan {
    pos: usize,
    open: usize,
}

/// Follows an indefinite length in `b`, from `at`, to its end-of-contents
/// marker. It returns where the marker starts and where the element ends,
/// or, if `b` ends first, where to go on from once more bytes come.
fn scan(b: &[u8], rules: Rules, depth: usize, at: Scan) -> Result<Result<(usize, usize), Scan>, Error> {
    let Scan { mut pos, mut open } = at;
    loop {
        let here = Scan { pos, open };
        let c = match read_header(b, pos, rules) {
            Ok(c) => c,
            Err(Error::Truncated) => return Ok(Err(here)),
            Err(e) => return Err(e),
        };
        let next = pos + c.len;
        if is_eoc_tag(c.tag) {
            // The marker is exactly two zero octets (X.690 8.1.5).
            if c.tag.constructed || c.len != 2 || c.length != Length::Definite(0) {
                return Err(Error::Eoc);
            }
            open -= 1;
            if open == 0 {
                return Ok(Ok((pos, next)));
            }
            pos = next;
            continue;
        }
        match c.length {
            Length::Definite(n) => match end_of(b, next, n) {
                Ok(end) => pos = end,
                Err(Error::Truncated) => return Ok(Err(here)),
                Err(e) => return Err(e),
            },
            Length::Indefinite => {
                if depth + open >= MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                open += 1;
                pos = next;
            }
        }
    }
}

/// Where `n` bytes of contents starting at `start` end, if `b` holds them.
fn end_of(b: &[u8], start: usize, n: usize) -> Result<usize, Error> {
    let end = start.checked_add(n).ok_or(Error::TooLong)?;
    if end > MAX_INPUT {
        return Err(Error::TooLong);
    }
    if end > b.len() {
        return Err(Error::Truncated);
    }
    Ok(end)
}

/// How long the element at the start of `b` is, header, contents and any
/// end-of-contents marker together. It returns `Ok(None)` if `b` holds only
/// part of it. Only headers are checked; the values inside are read later,
/// with a [`Reader`].
pub fn element_len(b: &[u8], rules: Rules) -> Result<Option<usize>, Error> {
    match extent(b, rules, 0) {
        Ok((_, _, total)) => Ok(Some(total)),
        Err(Error::Truncated) => Ok(None),
        Err(e) => Err(e),
    }
}

/// One encoded BER element, bounded by [`MAX_INPUT`].
///
/// Only framing is checked. Use [`Reader`] to interpret its contents.
/// [`Wire`] reads exactly one element and writes its bytes unchanged.
/// The borrowed [`Element`] and [`Reader`] keep their existing APIs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// The tag, length, contents, and any end-of-contents marker.
    pub Vec<u8>,
);

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one BER element. Refuses bad framing, trailing bytes,
    /// and input above [`MAX_INPUT`]. Does not interpret the contents.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        check_frame(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Appends the stored BER element unchanged. Refuses bad framing,
    /// trailing bytes, and input above [`MAX_INPUT`], leaving `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        check_frame(&self.0)?;
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

fn check_frame(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::TooLong);
    }
    match element_len(bytes, Rules::Ber)? {
        Some(n) if n == bytes.len() => Ok(()),
        Some(_) => Err(Error::Trailing),
        None => Err(Error::Truncated),
    }
}

/// Reads ASN.1 elements without holding input bytes.
///
/// Use with [`Stream<Elements>`](fictionet::stdlib::codec::Stream) for a buffer limited to [`MAX_INPUT`].
/// Partial elements return [`Step::Need`], including at EOF. The stream
/// reports truncation at EOF and framing errors once. An indefinite BER
/// length keeps a scan position relative to the unread start, so pushing
/// one byte at a time takes linear time. Only framing is checked.
///
/// ```
/// use fictionet::stdlib::{asn1::{Elements, Frame, Rules}, codec::{Stream, Wire, finish, pump}};
///
/// let bytes = Frame(vec![5, 0]).to_bytes()?;
/// let mut stream = Stream::new(Elements::new(Rules::Der));
/// let mut elements = Vec::new();
/// for byte in &bytes {
///     pump(&mut stream, core::slice::from_ref(byte), |item| elements.push(item))?;
/// }
/// finish(&mut stream, |item| elements.push(item))?;
/// assert_eq!(elements, [bytes]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Elements {
    rules: Rules,
    resume: Option<Scan>,
}

impl Elements {
    /// Creates an element decoder using `rules` and [`MAX_INPUT`].
    pub fn new(rules: Rules) -> Self {
        Self { rules, resume: None }
    }

    /// The encoding rules used to frame elements.
    pub fn rules(&self) -> Rules {
        self.rules
    }
}

impl Decode for Elements {
    type Item = Vec<u8>;
    type Error = Error;
    const NAME: &'static str = "ASN.1";

    fn capacity(&self) -> usize {
        MAX_INPUT
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Vec<u8>>, Error> {
        let at = match self.resume {
            Some(at) => Some(at),
            None => match read_header(input, 0, self.rules) {
                Ok(h) if h.length == Length::Indefinite && !is_eoc_tag(h.tag) => Some(Scan { pos: h.len, open: 1 }),
                _ => None,
            },
        };
        let total = match at {
            Some(at) => match scan(input, self.rules, 0, at)? {
                Ok((_, end)) => Some(end),
                Err(at) => {
                    self.resume = Some(at);
                    None
                }
            },
            None => element_len(input, self.rules)?,
        };
        let Some(total) = total else {
            return Ok(Step::Need);
        };
        let bytes = input.get(..total).ok_or(Error::Truncated)?;
        self.resume = None;
        Ok(Step::Item(bytes.to_vec(), total))
    }
}

/// One element: a tag, a length and contents, borrowed from the input.
/// Its methods read the contents as a value of some type. They do not
/// check the tag, so they read implicitly tagged values too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    tag: Tag,
    contents: &'a [u8],
    raw: &'a [u8],
    indefinite: bool,
    rules: Rules,
    depth: usize,
}

impl<'a> Element<'a> {
    /// The tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The contents, without the header or any end-of-contents marker.
    pub fn contents(&self) -> &'a [u8] {
        self.contents
    }

    /// The whole element as it was read: header, contents and any
    /// end-of-contents marker.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Whether the element had an indefinite length.
    pub fn is_indefinite(&self) -> bool {
        self.indefinite
    }

    /// The rules it was read under.
    pub fn rules(&self) -> Rules {
        self.rules
    }

    /// How deep it is: 0 for an element read straight from the input.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// A reader over a constructed element's children.
    pub fn reader(&self) -> Result<Reader<'a>, Error> {
        if !self.tag.constructed {
            return Err(Error::Primitive);
        }
        if self.depth >= MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        Ok(Reader { rest: self.contents, rules: self.rules, depth: self.depth + 1 })
    }

    /// A reader over a SET's children. Under DER it checks first that
    /// their tags are in ascending order, class first, then number, with
    /// none repeated (X.690 10.3). The order of a CHOICE inside a set
    /// depends on the schema, so a set holding one may need
    /// [`Element::reader`] instead.
    pub fn set_reader(&self) -> Result<Reader<'a>, Error> {
        let r = self.reader()?;
        if self.rules == Rules::Der {
            let mut prev: Option<Tag> = None;
            for e in r.clone() {
                let t = e?.tag;
                if prev.is_some_and(|p| (p.class, p.number) >= (t.class, t.number)) {
                    return Err(Error::SetOrder);
                }
                prev = Some(t);
            }
        }
        Ok(r)
    }

    /// A reader over a SET OF's children. Under DER it checks first that
    /// their encodings are in ascending order, compared as octet strings
    /// padded with zeros (X.690 11.6).
    pub fn set_of_reader(&self) -> Result<Reader<'a>, Error> {
        let r = self.reader()?;
        if self.rules == Rules::Der {
            let mut prev: Option<&[u8]> = None;
            for e in r.clone() {
                let raw = e?.raw;
                if prev.is_some_and(|p| padded_cmp(p, raw) == Ordering::Greater) {
                    return Err(Error::SetOrder);
                }
                prev = Some(raw);
            }
        }
        Ok(r)
    }

    fn primitive(&self) -> Result<&'a [u8], Error> {
        if self.tag.constructed { Err(Error::Constructed) } else { Ok(self.contents) }
    }

    /// The contents as a BOOLEAN. BER takes any nonzero byte as TRUE; DER
    /// takes only 0xFF.
    pub fn boolean(&self) -> Result<bool, Error> {
        match (self.primitive()?, self.rules) {
            ([0x00], _) => Ok(false),
            ([0xff], _) => Ok(true),
            ([_], Rules::Ber) => Ok(true),
            _ => Err(Error::Boolean),
        }
    }

    /// The contents as an INTEGER (or ENUMERATED) of any size.
    pub fn integer(&self) -> Result<Integer<'a>, Error> {
        Integer::from_bytes(self.primitive()?)
    }

    /// Checks the contents are a NULL: none at all.
    pub fn null(&self) -> Result<(), Error> {
        if self.primitive()?.is_empty() { Ok(()) } else { Err(Error::Null) }
    }

    /// The contents as an OBJECT IDENTIFIER.
    pub fn oid(&self) -> Result<Oid, Error> {
        Oid::from_contents(self.primitive()?)
    }

    /// The contents as an OCTET STRING. Under BER a constructed one is put
    /// back together from its segments; DER refuses that form.
    pub fn octet_string(&self) -> Result<Cow<'a, [u8]>, Error> {
        if !self.tag.constructed {
            return Ok(Cow::Borrowed(self.contents));
        }
        if self.rules == Rules::Der {
            return Err(Error::Constructed);
        }
        let mut out = Vec::new();
        self.append_segments(&mut out)?;
        Ok(Cow::Owned(out))
    }

    /// Appends the bytes of a constructed string's segments, each an OCTET
    /// STRING (X.690 8.7.3.2 and 8.23.6). Nesting is bounded by
    /// [`Element::reader`]'s depth check.
    fn append_segments(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        for child in self.reader()? {
            let child = child?;
            if !child.tag.same_type(Tag::OCTET_STRING) {
                return Err(Error::Unexpected { expected: Tag::OCTET_STRING, found: child.tag });
            }
            if child.tag.constructed {
                child.append_segments(out)?;
            } else {
                out.extend_from_slice(child.contents);
            }
        }
        Ok(())
    }

    /// The contents as a BIT STRING. Under BER a constructed one is put
    /// back together from its segments, and unused bits may hold anything;
    /// DER refuses both.
    pub fn bit_string(&self) -> Result<BitString<'a>, Error> {
        if !self.tag.constructed {
            let (unused, bytes) = bit_segment(self.contents, self.rules)?;
            return Ok(BitString { unused, bytes: Cow::Borrowed(bytes) });
        }
        if self.rules == Rules::Der {
            return Err(Error::Constructed);
        }
        let mut out = Vec::new();
        let mut unused = 0;
        self.append_bit_segments(&mut out, &mut unused)?;
        Ok(BitString { unused, bytes: Cow::Owned(out) })
    }

    fn append_bit_segments(&self, out: &mut Vec<u8>, unused: &mut u8) -> Result<(), Error> {
        for child in self.reader()? {
            let child = child?;
            if !child.tag.same_type(Tag::BIT_STRING) {
                return Err(Error::Unexpected { expected: Tag::BIT_STRING, found: child.tag });
            }
            // Only the last segment may leave bits unused (8.6.4). Any
            // segment after one that did is refused, even an empty
            // constructed one.
            if *unused != 0 {
                return Err(Error::BitString);
            }
            if child.tag.constructed {
                child.append_bit_segments(out, unused)?;
            } else {
                let (u, bytes) = bit_segment(child.contents, self.rules)?;
                out.extend_from_slice(bytes);
                *unused = u;
            }
        }
        Ok(())
    }

    /// The contents as a string of type `kind`, as bytes, with its
    /// character set checked. Under BER a constructed one is put back
    /// together from its segments.
    pub fn string_bytes(&self, kind: StringKind) -> Result<Cow<'a, [u8]>, Error> {
        let b = self.octet_string()?;
        kind.check(&b)?;
        Ok(b)
    }

    /// The contents as a string of type `kind`, decoded to text. Types
    /// whose character sets this module does not decode give
    /// [`Error::Charset`]; read those with [`Element::string_bytes`].
    pub fn text(&self, kind: StringKind) -> Result<String, Error> {
        kind.decode(&self.octet_string()?)
    }

    /// The contents as a UTCTime, checked and returned as text, such as
    /// `"910506234540Z"`.
    pub fn utc_time(&self) -> Result<String, Error> {
        let b = self.string_bytes(StringKind::Visible)?;
        check_utc_time(&b, self.rules)?;
        String::from_utf8(b.into_owned()).map_err(|_| Error::Charset)
    }

    /// The contents as a GeneralizedTime, checked and returned as text,
    /// such as `"19920521000000Z"`.
    pub fn generalized_time(&self) -> Result<String, Error> {
        let b = self.string_bytes(StringKind::Visible)?;
        check_generalized_time(&b, self.rules)?;
        String::from_utf8(b.into_owned()).map_err(|_| Error::Charset)
    }
}

/// One primitive BIT STRING's unused-bit count and data bytes.
fn bit_segment(contents: &[u8], rules: Rules) -> Result<(u8, &[u8]), Error> {
    let (&unused, bytes) = contents.split_first().ok_or(Error::BitString)?;
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(Error::BitString);
    }
    if rules == Rules::Der && bytes.last().is_some_and(|&b| b & !(0xffu8 << unused) != 0) {
        return Err(Error::BitString);
    }
    Ok((unused, bytes))
}

/// Compares two encodings as X.690 11.6 orders a SET OF: as octet strings,
/// the shorter padded with zeros.
fn padded_cmp(a: &[u8], b: &[u8]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// Reads elements one after another from a run of bytes: the input, or a
/// constructed element's contents. It is also an iterator over them,
/// which stops after the first error.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
    rules: Rules,
    depth: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `input`, holding it to `rules`. Its elements are at
    /// depth 0.
    pub fn new(input: &'a [u8], rules: Rules) -> Reader<'a> {
        Reader { rest: input, rules, depth: 0 }
    }

    /// The rules the reader holds input to.
    pub fn rules(&self) -> Rules {
        self.rules
    }

    /// The depth of the elements it reads.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The bytes not read yet.
    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// Whether every element has been read.
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Checks every element has been read, as the end of a sequence must.
    pub fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() { Ok(()) } else { Err(Error::Trailing) }
    }

    /// The next element, without reading past it.
    pub fn peek(&self) -> Result<Element<'a>, Error> {
        if self.rest.is_empty() {
            return Err(Error::Empty);
        }
        let (h, end, total) = extent(self.rest, self.rules, self.depth)?;
        Ok(Element {
            tag: h.tag,
            contents: &self.rest[h.len..end],
            raw: &self.rest[..total],
            indefinite: h.length == Length::Indefinite,
            rules: self.rules,
            depth: self.depth,
        })
    }

    /// The next element, whatever its tag.
    pub fn read(&mut self) -> Result<Element<'a>, Error> {
        let e = self.peek()?;
        self.rest = &self.rest[e.raw.len()..];
        Ok(e)
    }

    /// The next element, which must have `tag`'s class and number. The form
    /// is not compared, since BER may split a string into segments. On an
    /// error nothing is read.
    pub fn read_expected(&mut self, tag: Tag) -> Result<Element<'a>, Error> {
        let e = self.peek()?;
        if !e.tag.same_type(tag) {
            return Err(Error::Unexpected { expected: tag, found: e.tag });
        }
        self.rest = &self.rest[e.raw.len()..];
        Ok(e)
    }

    /// The next element if it has `tag`'s class and number, for an
    /// OPTIONAL or DEFAULT field. It returns `None`, and reads nothing,
    /// when the reader is empty or the next element has another tag.
    pub fn read_optional(&mut self, tag: Tag) -> Result<Option<Element<'a>>, Error> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let e = self.peek()?;
        if !e.tag.same_type(tag) {
            return Ok(None);
        }
        self.rest = &self.rest[e.raw.len()..];
        Ok(Some(e))
    }

    /// Reads an optional explicit context field and returns its contents reader.
    /// A matching outer element is consumed before its form is checked.
    #[inline]
    pub fn read_optional_explicit(&mut self, number: u32) -> Result<Option<Reader<'a>>, Error> {
        self.read_optional(Tag::context(number))?.map(|e| e.reader()).transpose()
    }

    /// Reads an optional explicit context field with `f` and checks its end.
    /// An absent field leaves the reader unchanged.
    #[inline]
    pub fn read_optional_explicit_with<T, E: From<Error>>(
        &mut self,
        number: u32,
        f: impl FnOnce(&mut Reader<'a>) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        if self.is_empty() || !self.peek()?.tag().same_type(Tag::context(number)) {
            return Ok(None);
        }
        self.read_explicit_with(number, f).map(Some)
    }

    /// Reads an explicit context field with `f`, then checks that it is exhausted.
    /// The callback's error type preserves the caller's field errors.
    #[inline]
    pub fn read_explicit_with<T, E: From<Error>>(
        &mut self,
        number: u32,
        f: impl FnOnce(&mut Reader<'a>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut inner = self.read_explicit(number)?;
        let value = f(&mut inner)?;
        inner.finish()?;
        Ok(value)
    }

    /// Reads a BOOLEAN.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        self.read_with(Tag::BOOLEAN, |e| e.boolean())
    }

    /// Reads an INTEGER of any size.
    pub fn read_integer(&mut self) -> Result<Integer<'a>, Error> {
        self.read_with(Tag::INTEGER, |e| e.integer())
    }

    /// Reads an INTEGER that fits an `i64`.
    pub fn read_i64(&mut self) -> Result<i64, Error> {
        self.read_with(Tag::INTEGER, |e| e.integer()?.to_i64().ok_or(Error::Integer))
    }

    /// Reads an INTEGER that fits a `u64`.
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        self.read_with(Tag::INTEGER, |e| e.integer()?.to_u64().ok_or(Error::Integer))
    }

    /// Reads an ENUMERATED.
    pub fn read_enumerated(&mut self) -> Result<Integer<'a>, Error> {
        self.read_with(Tag::ENUMERATED, |e| e.integer())
    }

    /// Reads a NULL.
    pub fn read_null(&mut self) -> Result<(), Error> {
        self.read_with(Tag::NULL, |e| e.null())
    }

    /// Reads a BIT STRING.
    pub fn read_bit_string(&mut self) -> Result<BitString<'a>, Error> {
        self.read_with(Tag::BIT_STRING, |e| e.bit_string())
    }

    /// Reads an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<Cow<'a, [u8]>, Error> {
        self.read_with(Tag::OCTET_STRING, |e| e.octet_string())
    }

    /// Reads an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> Result<Oid, Error> {
        self.read_with(Tag::OID, |e| e.oid())
    }

    /// Reads a string of any of the types in [`StringKind`], as text, with
    /// the type it had.
    pub fn read_text(&mut self) -> Result<(StringKind, String), Error> {
        let e = self.peek()?;
        let kind = StringKind::from_tag(e.tag).ok_or(Error::Unexpected { expected: Tag::UTF8_STRING, found: e.tag })?;
        let text = e.text(kind)?;
        self.rest = &self.rest[e.raw.len()..];
        Ok((kind, text))
    }

    /// Reads a string of type `kind`, as bytes with its character set
    /// checked. This reads the types [`Reader::read_text`] cannot decode.
    pub fn read_string_bytes(&mut self, kind: StringKind) -> Result<Cow<'a, [u8]>, Error> {
        self.read_with(kind.tag(), |e| e.string_bytes(kind))
    }

    /// Reads a UTCTime, as checked text.
    pub fn read_utc_time(&mut self) -> Result<String, Error> {
        self.read_with(Tag::UTC_TIME, |e| e.utc_time())
    }

    /// Reads a GeneralizedTime, as checked text.
    pub fn read_generalized_time(&mut self) -> Result<String, Error> {
        self.read_with(Tag::GENERALIZED_TIME, |e| e.generalized_time())
    }

    /// Reads a SEQUENCE (or SEQUENCE OF), and returns a reader over its
    /// children.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, Error> {
        self.read_with(Tag::SEQUENCE, |e| e.reader())
    }

    /// Reads a SET, and returns a reader over its children. See
    /// [`Element::set_reader`] for what DER checks.
    pub fn read_set(&mut self) -> Result<Reader<'a>, Error> {
        self.read_with(Tag::SET, |e| e.set_reader())
    }

    /// Reads a SET OF, and returns a reader over its children. See
    /// [`Element::set_of_reader`] for what DER checks.
    pub fn read_set_of(&mut self) -> Result<Reader<'a>, Error> {
        self.read_with(Tag::SET, |e| e.set_of_reader())
    }

    /// Reads an explicitly tagged `[number]`, and returns a reader over
    /// what it wraps.
    pub fn read_explicit(&mut self, number: u32) -> Result<Reader<'a>, Error> {
        self.read_with(Tag::context(number), |e| e.reader())
    }

    /// Reads the next element if it has `tag`'s class and number and `f`
    /// accepts it. On an error nothing is read.
    fn read_with<T>(&mut self, tag: Tag, f: impl FnOnce(&Element<'a>) -> Result<T, Error>) -> Result<T, Error> {
        let e = self.peek()?;
        if !e.tag.same_type(tag) {
            return Err(Error::Unexpected { expected: tag, found: e.tag });
        }
        let v = f(&e)?;
        self.rest = &self.rest[e.raw.len()..];
        Ok(v)
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Element<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match self.read() {
            Ok(e) => Some(Ok(e)),
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// An INTEGER or ENUMERATED of any size: its two's-complement bytes, most
/// significant first, in their shortest form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Integer<'a> {
    bytes: &'a [u8],
}

impl<'a> Integer<'a> {
    /// Checks `bytes` are an integer's contents: at least one byte, and no
    /// first byte that only repeats the sign (X.690 8.3.2).
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Integer<'a>, Error> {
        match bytes {
            [] => Err(Error::Integer),
            [0x00, b, ..] if b & 0x80 == 0 => Err(Error::Integer),
            [0xff, b, ..] if b & 0x80 != 0 => Err(Error::Integer),
            _ => Ok(Integer { bytes }),
        }
    }

    /// The two's-complement bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Whether the value is below zero.
    pub fn is_negative(&self) -> bool {
        self.bytes[0] & 0x80 != 0
    }

    /// For a value of zero or more, its magnitude's bytes without the sign
    /// byte, as an RSA modulus is used. Zero gives `[0]`.
    pub fn unsigned_bytes(&self) -> Option<&'a [u8]> {
        if self.is_negative() {
            return None;
        }
        match self.bytes {
            [0, rest @ ..] if !rest.is_empty() => Some(rest),
            b => Some(b),
        }
    }

    /// The value, if it fits.
    pub fn to_i128(&self) -> Option<i128> {
        if self.bytes.len() > 16 {
            return None;
        }
        let mut v: i128 = if self.is_negative() { -1 } else { 0 };
        for &b in self.bytes {
            v = v << 8 | i128::from(b);
        }
        Some(v)
    }

    /// The value, if it fits.
    pub fn to_u128(&self) -> Option<u128> {
        let m = self.unsigned_bytes()?;
        if m.len() > 16 {
            return None;
        }
        Some(m.iter().fold(0u128, |v, &b| v << 8 | u128::from(b)))
    }

    /// The value, if it fits.
    pub fn to_i64(&self) -> Option<i64> {
        self.to_i128().and_then(|v| i64::try_from(v).ok())
    }

    /// The value, if it fits.
    pub fn to_u64(&self) -> Option<u64> {
        self.to_u128().and_then(|v| u64::try_from(v).ok())
    }
}

/// A BIT STRING: bytes, and how many bits at the end of the last byte are
/// not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BitString<'a> {
    unused: u8,
    bytes: Cow<'a, [u8]>,
}

impl<'a> BitString<'a> {
    /// A bit string of `bytes`, less `unused` bits at the end. `unused` is
    /// at most 7, and 0 if `bytes` is empty. More than [`MAX_INPUT`] bytes
    /// is [`Error::TooLong`].
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>, unused: u8) -> Result<BitString<'a>, Error> {
        let bytes = bytes.into();
        if unused > 7 || (bytes.is_empty() && unused != 0) {
            return Err(Error::BitString);
        }
        if bytes.len() > MAX_INPUT {
            return Err(Error::TooLong);
        }
        Ok(BitString { unused, bytes })
    }

    /// The same bit string, owning its bytes, to keep past the input.
    pub fn into_owned(self) -> BitString<'static> {
        BitString { unused: self.unused, bytes: Cow::Owned(self.bytes.into_owned()) }
    }

    /// How many bits at the end of the last byte are unused.
    pub fn unused(&self) -> u8 {
        self.unused
    }

    /// The bytes, unused bits included as they were read.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many bits the string holds.
    pub fn len(&self) -> usize {
        self.bytes.len() * 8 - usize::from(self.unused)
    }

    /// Whether the string holds no bits.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bit `i`, counting from the most significant bit of the first byte,
    /// as X.690 numbers named bits. `None` past the end.
    pub fn bit(&self, i: usize) -> Option<bool> {
        if i >= self.len() {
            return None;
        }
        Some(self.bytes[i / 8] & (0x80 >> (i % 8)) != 0)
    }
}

/// An OBJECT IDENTIFIER, such as 2.5.4.3 (an X.509 common name). Each arc
/// fits a `u128`, so UUID-based identifiers under 2.25 fit too.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid {
    bytes: Vec<u8>,
}

impl Oid {
    /// Checks `b` is an object identifier's contents (X.690 8.19): not
    /// empty, at most [`MAX_OID_LEN`] bytes, each subidentifier in its
    /// shortest form and small enough for a `u128`.
    pub fn from_contents(b: &[u8]) -> Result<Oid, Error> {
        if b.is_empty() || b.len() > MAX_OID_LEN || b[b.len() - 1] & 0x80 != 0 {
            return Err(Error::Oid);
        }
        let mut start = true;
        let mut v: u128 = 0;
        for &c in b {
            if start && c == 0x80 {
                return Err(Error::Oid);
            }
            if v >> 121 != 0 {
                return Err(Error::Oid);
            }
            v = v << 7 | u128::from(c & 0x7f);
            start = c & 0x80 == 0;
            if start {
                v = 0;
            }
        }
        Ok(Oid { bytes: b.to_vec() })
    }

    /// The identifier with these arcs. There must be at least two, the
    /// first at most 2, and the second below 40 unless the first is 2.
    pub fn from_arcs(arcs: &[u128]) -> Result<Oid, Error> {
        let [first, second, rest @ ..] = arcs else {
            return Err(Error::Oid);
        };
        if *first > 2 || (*first < 2 && *second >= 40) {
            return Err(Error::Oid);
        }
        let head = (first * 40).checked_add(*second).ok_or(Error::Oid)?;
        let mut bytes = Vec::new();
        push_base128(&mut bytes, head);
        for &arc in rest {
            push_base128(&mut bytes, arc);
            if bytes.len() > MAX_OID_LEN {
                return Err(Error::Oid);
            }
        }
        if bytes.len() > MAX_OID_LEN {
            return Err(Error::Oid);
        }
        Ok(Oid { bytes })
    }

    /// The arcs.
    pub fn arcs(&self) -> Vec<u128> {
        let mut arcs = Vec::new();
        let mut v: u128 = 0;
        for &c in &self.bytes {
            v = v << 7 | u128::from(c & 0x7f);
            if c & 0x80 == 0 {
                if arcs.is_empty() {
                    let first = (v / 40).min(2);
                    arcs.push(first);
                    arcs.push(v - first * 40);
                } else {
                    arcs.push(v);
                }
                v = 0;
            }
        }
        arcs
    }

    /// The contents bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Oid {
    type Err = Error;

    /// Reads dotted decimal, such as `"1.2.840.113549"`.
    fn from_str(s: &str) -> Result<Oid, Error> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) || arcs.len() > MAX_OID_LEN {
                return Err(Error::Oid);
            }
            arcs.push(part.parse::<u128>().map_err(|_| Error::Oid)?);
        }
        Oid::from_arcs(&arcs)
    }
}

/// Appends `v` in base 128, high groups first, every byte but the last
/// with its top bit set: the form of long tag numbers and OID arcs.
fn push_base128(out: &mut Vec<u8>, mut v: u128) {
    let mut tmp = [0u8; 19];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for b in &mut tmp[i..last] {
        *b |= 0x80;
    }
    out.extend_from_slice(&tmp[i..]);
}

/// The character string types of X.680, and what each allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StringKind {
    /// UTF8String: any valid UTF-8.
    Utf8,
    /// NumericString: digits and space.
    Numeric,
    /// PrintableString: letters, digits, space and `'()+,-./:=?`.
    Printable,
    /// TeletexString (T61String). Its bytes are not checked or decoded.
    Teletex,
    /// VideotexString. Its bytes are not checked or decoded.
    Videotex,
    /// IA5String: ASCII, 0x00 to 0x7F.
    Ia5,
    /// GraphicString. Its bytes are not checked or decoded.
    Graphic,
    /// VisibleString (ISO646String): printing ASCII, 0x20 to 0x7E.
    Visible,
    /// GeneralString, as Kerberos uses it. Its bytes are not checked or
    /// decoded.
    General,
    /// UniversalString: UCS-4, four bytes per character, big-endian.
    Universal,
    /// BMPString: UCS-2, two bytes per character, big-endian, no
    /// surrogates.
    Bmp,
}

impl StringKind {
    /// The universal tag the type is written with.
    pub fn tag(self) -> Tag {
        match self {
            StringKind::Utf8 => Tag::UTF8_STRING,
            StringKind::Numeric => Tag::NUMERIC_STRING,
            StringKind::Printable => Tag::PRINTABLE_STRING,
            StringKind::Teletex => Tag::TELETEX_STRING,
            StringKind::Videotex => Tag::VIDEOTEX_STRING,
            StringKind::Ia5 => Tag::IA5_STRING,
            StringKind::Graphic => Tag::GRAPHIC_STRING,
            StringKind::Visible => Tag::VISIBLE_STRING,
            StringKind::General => Tag::GENERAL_STRING,
            StringKind::Universal => Tag::UNIVERSAL_STRING,
            StringKind::Bmp => Tag::BMP_STRING,
        }
    }

    /// The type a universal tag names, in either form.
    pub fn from_tag(tag: Tag) -> Option<StringKind> {
        if tag.class != Class::Universal {
            return None;
        }
        Some(match tag.number {
            12 => StringKind::Utf8,
            18 => StringKind::Numeric,
            19 => StringKind::Printable,
            20 => StringKind::Teletex,
            21 => StringKind::Videotex,
            22 => StringKind::Ia5,
            25 => StringKind::Graphic,
            26 => StringKind::Visible,
            27 => StringKind::General,
            28 => StringKind::Universal,
            30 => StringKind::Bmp,
            _ => return None,
        })
    }

    /// Whether this module decodes the type's characters to text.
    pub fn is_decoded(self) -> bool {
        !matches!(self, StringKind::Teletex | StringKind::Videotex | StringKind::Graphic | StringKind::General)
    }

    /// Checks `b` holds only characters the type allows.
    pub fn check(self, b: &[u8]) -> Result<(), Error> {
        let ok = match self {
            StringKind::Utf8 => std::str::from_utf8(b).is_ok(),
            StringKind::Numeric => b.iter().all(|&c| c.is_ascii_digit() || c == b' '),
            StringKind::Printable => b.iter().all(|&c| c.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&c)),
            StringKind::Ia5 => b.is_ascii(),
            StringKind::Visible => b.iter().all(|&c| (0x20..=0x7e).contains(&c)),
            StringKind::Universal => {
                b.len().is_multiple_of(4)
                    && b.as_chunks::<4>().0.iter().all(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).is_some())
                    && no_shifts(b.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            }
            StringKind::Bmp => {
                b.len().is_multiple_of(2)
                    && b.as_chunks::<2>().0.iter().all(|c| !(0xd800..=0xdfff).contains(&u16::from_be_bytes([c[0], c[1]])))
                    && no_shifts(b.as_chunks::<2>().0.iter().map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))))
            }
            StringKind::Teletex | StringKind::Videotex | StringKind::Graphic | StringKind::General => true,
        };
        if ok { Ok(()) } else { Err(Error::Charset) }
    }

    /// Decodes `b` to text, after checking it. More than [`MAX_INPUT`]
    /// bytes is [`Error::TooLong`].
    pub fn decode(self, b: &[u8]) -> Result<String, Error> {
        if !self.is_decoded() {
            return Err(Error::Charset);
        }
        if b.len() > MAX_INPUT {
            return Err(Error::TooLong);
        }
        self.check(b)?;
        Ok(match self {
            StringKind::Universal => {
                b.as_chunks::<4>().0.iter().filter_map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))).collect()
            }
            StringKind::Bmp => {
                b.as_chunks::<2>().0.iter().filter_map(|c| char::from_u32(u32::from(u16::from_be_bytes([c[0], c[1]])))).collect()
            }
            _ => String::from_utf8_lossy(b).into_owned(),
        })
    }

    /// Encodes `s` as contents octets, without a tag or length, if every
    /// character is allowed.
    /// An encoding of more than [`MAX_INPUT`] bytes is [`Error::TooLong`],
    /// so whatever [`StringKind::decode`] gives, this takes back.
    pub fn encode(self, s: &str) -> Result<Vec<u8>, Error> {
        if !self.is_decoded() {
            return Err(Error::Charset);
        }
        // Every character takes at most 4 bytes of UTF-8, and at least 2
        // bytes in a BMPString and 4 in a UniversalString, so a longer `s`
        // is too long in every type. Below that, counting is cheap.
        if s.len() > 4 * MAX_INPUT {
            return Err(Error::TooLong);
        }
        let len = match self {
            StringKind::Universal => 4 * s.chars().count(),
            StringKind::Bmp => 2 * s.chars().count(),
            _ => s.len(),
        };
        if len > MAX_INPUT {
            return Err(Error::TooLong);
        }
        let out = match self {
            StringKind::Universal => s.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect(),
            StringKind::Bmp => {
                let mut out = Vec::with_capacity(2 * s.len());
                for c in s.chars() {
                    let v = u16::try_from(u32::from(c)).map_err(|_| Error::Charset)?;
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out
            }
            _ => s.as_bytes().to_vec(),
        };
        self.check(&out)?;
        Ok(out)
    }
}

/// Whether UCS characters, as a BMPString or UniversalString holds them,
/// stay clear of the ISO/IEC 2022 shifts and escape sequences X.690 8.23.9
/// forbids: SHIFT OUT, SHIFT IN, SINGLE SHIFT TWO and THREE, and ESC
/// followed by an intermediate byte (announcers, designations and the
/// identifying sequences of ISO/IEC 10646), by `N` or `O` (single shifts),
/// or by `n`, `o`, `|`, `}` or `~` (locking shifts). An ESC at the end is
/// an unfinished sequence and is refused too. Other control functions of
/// ISO/IEC 6429, such as TAB, LF, CR and CSI sequences, are allowed.
fn no_shifts(chars: impl Iterator<Item = u32>) -> bool {
    let mut after_esc = false;
    for c in chars {
        if matches!(c, 0x0e | 0x0f | 0x8e | 0x8f)
            || (after_esc && matches!(c, 0x20..=0x2f | 0x4e | 0x4f | 0x6e | 0x6f | 0x7c..=0x7e))
        {
            return false;
        }
        after_esc = c == 0x1b;
    }
    !after_esc
}

/// A cursor over time text.
struct Text<'a> {
    b: &'a [u8],
    i: usize,
}

impl Text<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn digit(&self) -> bool {
        self.peek().is_some_and(|c| c.is_ascii_digit())
    }

    fn two(&mut self) -> Result<u32, Error> {
        match self.b.get(self.i..self.i + 2) {
            Some(&[a, b]) if a.is_ascii_digit() && b.is_ascii_digit() => {
                self.i += 2;
                Ok(u32::from(a - b'0') * 10 + u32::from(b - b'0'))
            }
            _ => Err(Error::Time),
        }
    }

    /// The time zone and the end of the text: `Z`, `+hhmm` or `-hhmm`.
    /// GeneralizedTime may also give hours alone, or no zone (local time).
    /// DER allows only `Z`.
    fn zone(&mut self, utc: bool, rules: Rules) -> Result<(), Error> {
        match self.peek() {
            Some(b'Z') => self.i += 1,
            Some(b'+' | b'-') if rules == Rules::Ber => {
                self.i += 1;
                let h = self.two()?;
                let m = if utc || self.digit() { self.two()? } else { 0 };
                if h > 23 || m > 59 {
                    return Err(Error::Time);
                }
            }
            None if !utc && rules == Rules::Ber => {}
            _ => return Err(Error::Time),
        }
        if self.i == self.b.len() { Ok(()) } else { Err(Error::Time) }
    }
}

/// Checks a calendar date and a time of day. Second 60, a positive leap
/// second, is allowed when `leap` is set.
fn check_date(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32, leap: bool) -> Result<(), Error> {
    let leap_year = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return Err(Error::Time),
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > if leap { 60 } else { 59 } {
        return Err(Error::Time);
    }
    Ok(())
}

/// Checks UTCTime text (X.680 47): `YYMMDDhhmm[ss]` and then `Z` or an
/// offset. DER needs the seconds and `Z` (X.690 11.8). Two-digit years 50
/// to 99 are taken as 19xx and the rest as 20xx, as RFC 5280 does, which
/// only matters for whether 00 is a leap year.
pub fn check_utc_time(b: &[u8], rules: Rules) -> Result<(), Error> {
    if b.len() > MAX_TIME_LEN {
        return Err(Error::Time);
    }
    let mut t = Text { b, i: 0 };
    let yy = t.two()?;
    let (month, day, hour, minute) = (t.two()?, t.two()?, t.two()?, t.two()?);
    let second = if t.digit() {
        t.two()?
    } else if rules == Rules::Der {
        return Err(Error::Time);
    } else {
        0
    };
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    check_date(year, month, day, hour, minute, second, false)?;
    t.zone(true, rules)
}

/// Checks GeneralizedTime text (X.680 46): `YYYYMMDDhh[mm[ss]]`, an
/// optional fraction after `.` or `,`, and `Z`, an offset or nothing. DER
/// needs the minutes, the seconds and `Z`, and a fraction, if any, after
/// `.` with no trailing zero (X.690 11.7). The seconds may be 60, a leap
/// second, as ISO 8601 allows.
pub fn check_generalized_time(b: &[u8], rules: Rules) -> Result<(), Error> {
    if b.len() > MAX_TIME_LEN {
        return Err(Error::Time);
    }
    let mut t = Text { b, i: 0 };
    let year = t.two()? * 100 + t.two()?;
    let (month, day, hour) = (t.two()?, t.two()?, t.two()?);
    let (mut minute, mut second, mut parts) = (0, 0, 1);
    if t.digit() {
        minute = t.two()?;
        parts = 2;
        if t.digit() {
            second = t.two()?;
            parts = 3;
        }
    }
    if rules == Rules::Der && parts < 3 {
        return Err(Error::Time);
    }
    if let Some(sep @ (b'.' | b',')) = t.peek() {
        if rules == Rules::Der && sep == b',' {
            return Err(Error::Time);
        }
        t.i += 1;
        let start = t.i;
        while t.digit() {
            t.i += 1;
        }
        if t.i == start || (rules == Rules::Der && b[t.i - 1] == b'0') {
            return Err(Error::Time);
        }
    }
    check_date(year, month, day, hour, minute, second, true)?;
    t.zone(false, rules)
}

/// How a constructed value's children are ordered when it closes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    AsWritten,
    Tags,
    Encodings,
}

/// Builds DER, which is also BER. Values are written in order; constructed
/// values take a closure that writes their children. A value that cannot
/// be written (a string with characters its type does not allow, too much
/// nesting, too many bytes) is not written, and [`Writer::finish`] returns
/// the first such error.
///
/// The closure a constructed value takes gets a writer of its own, so
/// whatever it does to that writer (even replacing it) cannot change what
/// was written before.
#[derive(Debug)]
pub struct Writer {
    out: Vec<u8>,
    /// How deep the next element written sits.
    depth: usize,
    error: Option<Error>,
    /// The most bytes `out` may hold: [`MAX_INPUT`] for a writer of its
    /// own, and what is left of its parent's room for a closure's writer.
    room: usize,
}

impl Default for Writer {
    fn default() -> Writer {
        Writer { out: Vec::new(), depth: 0, error: None, room: MAX_INPUT }
    }
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Writer {
        Writer::default()
    }

    /// The bytes written, or the first error.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(self.out),
        }
    }

    /// The first error so far, if any. After one, nothing more is written.
    pub fn error(&self) -> Option<Error> {
        self.error
    }

    /// How many bytes have been written.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    fn fail(&mut self, e: Error) {
        if self.error.is_none() {
            self.error = Some(e);
        }
    }

    /// Writes one element with a definite length.
    fn put(&mut self, tag: Tag, contents: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if contents.len() > MAX_INPUT {
            return self.fail(Error::TooLong);
        }
        let mut head = Vec::with_capacity(11);
        tag.encode(&mut head);
        encode_length(contents.len(), &mut head);
        if head.len() + contents.len() > self.left() {
            return self.fail(Error::TooLong);
        }
        self.out.extend_from_slice(&head);
        self.out.extend_from_slice(contents);
    }

    /// How many more bytes `out` may take.
    fn left(&self) -> usize {
        self.room.min(MAX_INPUT).saturating_sub(self.out.len())
    }

    /// Runs `f` on a writer of its own whose elements sit at `depth`, and
    /// returns what it wrote. If `f` put another writer in its place, one
    /// made for another depth, what that writer holds is read again at
    /// `depth`, so nothing nests deeper than a reader opens.
    fn run(&self, depth: usize, f: impl FnOnce(&mut Writer)) -> Result<Vec<u8>, Error> {
        let mut child = Writer { out: Vec::new(), depth, error: None, room: self.left() };
        f(&mut child);
        if let Some(e) = child.error {
            return Err(e);
        }
        if child.depth != depth {
            for e in (Reader { rest: &child.out, rules: Rules::Der, depth }) {
                check_der(&e?)?;
            }
        }
        Ok(child.out)
    }

    /// The contents of a constructed value whose children `f` writes, in
    /// `order`, or `None` after an error.
    fn nest(&mut self, order: Order, f: impl FnOnce(&mut Writer)) -> Option<Vec<u8>> {
        if self.error.is_some() {
            return None;
        }
        if self.depth >= MAX_DEPTH {
            self.fail(Error::TooDeep);
            return None;
        }
        let contents = match self.run(self.depth + 1, f) {
            Ok(c) => c,
            Err(e) => {
                self.fail(e);
                return None;
            }
        };
        let contents = match order {
            Order::AsWritten => contents,
            Order::Tags | Order::Encodings => match sorted(&contents, order) {
                Ok(c) => c,
                Err(e) => {
                    self.fail(e);
                    return None;
                }
            },
        };
        Some(contents)
    }

    fn nest_put(&mut self, tag: Tag, order: Order, f: impl FnOnce(&mut Writer)) {
        if let Some(contents) = self.nest(order, f) {
            self.put(tag.as_constructed(), &contents);
        }
    }

    /// Writes a BOOLEAN.
    pub fn boolean(&mut self, v: bool) {
        self.put(Tag::BOOLEAN, &[if v { 0xff } else { 0x00 }]);
    }

    /// Writes a NULL.
    pub fn null(&mut self) {
        self.put(Tag::NULL, &[]);
    }

    /// Writes an INTEGER.
    pub fn integer_i64(&mut self, v: i64) {
        self.integer_bytes(&v.to_be_bytes());
    }

    /// Writes an INTEGER.
    pub fn integer_u64(&mut self, v: u64) {
        self.integer_unsigned(&v.to_be_bytes());
    }

    /// Writes an INTEGER.
    pub fn integer_i128(&mut self, v: i128) {
        self.integer_bytes(&v.to_be_bytes());
    }

    /// Writes an INTEGER.
    pub fn integer_u128(&mut self, v: u128) {
        self.integer_unsigned(&v.to_be_bytes());
    }

    /// Writes an INTEGER from two's-complement bytes, most significant
    /// first, of any length. Redundant leading bytes are dropped, and no
    /// bytes at all is zero.
    pub fn integer_bytes(&mut self, b: &[u8]) {
        self.put(Tag::INTEGER, minimal_twos(b));
    }

    /// Writes a non-negative INTEGER from its magnitude's bytes, most
    /// significant first, as an RSA modulus is held.
    pub fn integer_unsigned(&mut self, magnitude: &[u8]) {
        let skip = magnitude.iter().take_while(|&&b| b == 0).count();
        let m = &magnitude[skip..];
        if self.error.is_some() {
            return;
        }
        if m.len() >= MAX_INPUT {
            return self.fail(Error::TooLong);
        }
        if m.first().is_none_or(|&b| b & 0x80 != 0) {
            let mut c = Vec::with_capacity(m.len() + 1);
            c.push(0);
            c.extend_from_slice(m);
            self.put(Tag::INTEGER, &c);
        } else {
            self.put(Tag::INTEGER, m);
        }
    }

    /// Writes an ENUMERATED.
    pub fn enumerated(&mut self, v: i64) {
        self.put(Tag::ENUMERATED, minimal_twos(&v.to_be_bytes()));
    }

    /// Writes a BIT STRING of `bytes`, less `unused` bits at the end. The
    /// unused bits are written as zeros, as DER requires.
    pub fn bit_string(&mut self, bytes: &[u8], unused: u8) {
        if unused > 7 || (bytes.is_empty() && unused != 0) {
            return self.fail(Error::BitString);
        }
        if bytes.len() >= MAX_INPUT {
            return self.fail(Error::TooLong);
        }
        let mut c = Vec::with_capacity(bytes.len() + 1);
        c.push(unused);
        c.extend_from_slice(bytes);
        if let Some(last) = c.last_mut().filter(|_| !bytes.is_empty()) {
            *last &= 0xffu8 << unused;
        }
        self.put(Tag::BIT_STRING, &c);
    }

    /// Writes a [`BitString`], as read or built with [`BitString::new`].
    pub fn bit_string_value(&mut self, b: &BitString<'_>) {
        self.bit_string(b.bytes(), b.unused());
    }

    /// Writes an OCTET STRING.
    pub fn octet_string(&mut self, bytes: &[u8]) {
        self.put(Tag::OCTET_STRING, bytes);
    }

    /// Writes an OBJECT IDENTIFIER.
    pub fn oid(&mut self, oid: &Oid) {
        self.put(Tag::OID, &oid.bytes);
    }

    /// Writes `s` as a string of type `kind`. A character the type does
    /// not allow, or a type this module does not encode, is an error.
    pub fn text(&mut self, kind: StringKind, s: &str) {
        match kind.encode(s) {
            Ok(b) => self.put(kind.tag(), &b),
            Err(e) => self.fail(e),
        }
    }

    /// Writes `b` as a string of type `kind`, after checking its
    /// characters. This writes the types [`Writer::text`] cannot.
    pub fn string_bytes(&mut self, kind: StringKind, b: &[u8]) {
        match kind.check(b) {
            Ok(()) => self.put(kind.tag(), b),
            Err(e) => self.fail(e),
        }
    }

    /// Writes a UTCTime, given as text in the form DER allows:
    /// `YYMMDDhhmmssZ`.
    pub fn utc_time(&mut self, text: &str) {
        match check_utc_time(text.as_bytes(), Rules::Der) {
            Ok(()) => self.put(Tag::UTC_TIME, text.as_bytes()),
            Err(e) => self.fail(e),
        }
    }

    /// Writes a GeneralizedTime, given as text in the form DER allows:
    /// `YYYYMMDDhhmmss[.f]Z`.
    pub fn generalized_time(&mut self, text: &str) {
        match check_generalized_time(text.as_bytes(), Rules::Der) {
            Ok(()) => self.put(Tag::GENERALIZED_TIME, text.as_bytes()),
            Err(e) => self.fail(e),
        }
    }

    /// Writes a primitive element with a non-universal tag and the given
    /// contents, in primitive form whatever `tag.constructed` says.
    /// Universal tags are refused with [`Error::Tag`]; their methods check
    /// the contents.
    pub fn primitive(&mut self, tag: Tag, contents: &[u8]) {
        if tag.class == Class::Universal {
            return self.fail(Error::Tag);
        }
        self.put(Tag { constructed: false, ..tag }, contents);
    }

    /// Writes a constructed element with a non-universal tag, whose
    /// children `f` writes. Universal tags are refused with
    /// [`Error::Tag`]; use [`Writer::sequence`] or [`Writer::set`].
    pub fn constructed(&mut self, tag: Tag, f: impl FnOnce(&mut Writer)) {
        if tag.class == Class::Universal {
            return self.fail(Error::Tag);
        }
        self.nest_put(tag, Order::AsWritten, f);
    }

    /// Writes an explicitly tagged `[number]` around the one element `f`
    /// writes (X.690 8.14.3). If `f` writes none or more than one, the
    /// error is [`Error::Implicit`].
    pub fn explicit(&mut self, number: u32, f: impl FnOnce(&mut Writer)) {
        let tag = Tag::context(number);
        if let Some(contents) = self.nest(Order::AsWritten, f) {
            let mut r = Reader::new(&contents, Rules::Der);
            match (r.read(), r.is_empty()) {
                (Ok(_), true) => self.put(tag.as_constructed(), &contents),
                _ => self.fail(Error::Implicit),
            }
        }
    }

    /// Writes a SEQUENCE (or SEQUENCE OF) whose children `f` writes, in
    /// order.
    pub fn sequence(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest_put(Tag::SEQUENCE, Order::AsWritten, f);
    }

    /// Writes a SET whose children `f` writes. They are put in tag order,
    /// as DER requires, and two with the same tag are an error.
    pub fn set(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest_put(Tag::SET, Order::Tags, f);
    }

    /// Writes a SET OF whose children `f` writes. They are put in the order
    /// of their encodings, as DER requires.
    pub fn set_of(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest_put(Tag::SET, Order::Encodings, f);
    }

    /// Writes one element already encoded in DER, such as the
    /// TBSCertificate a world keeps from a certificate to sign again. It is
    /// read under DER first, down to every child, and refused unless it is
    /// exactly one element. Universal types this module reads are checked
    /// with their readers; other values are copied as they are.
    pub fn encoded(&mut self, der: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let mut r = Reader { rest: der, rules: Rules::Der, depth: self.depth };
        let checked = r.read().and_then(|e| {
            r.finish()?;
            check_der(&e)
        });
        match checked {
            Ok(()) if der.len() > self.left() => self.fail(Error::TooLong),
            Ok(()) => self.out.extend_from_slice(der),
            Err(e) => self.fail(e),
        }
    }

    /// Writes the one element `f` writes with `tag`'s class and number in
    /// place of its own, keeping its form: an IMPLICIT tag. `tag` may not
    /// be universal.
    pub fn implicit(&mut self, tag: Tag, f: impl FnOnce(&mut Writer)) {
        if self.error.is_some() {
            return;
        }
        if tag.class == Class::Universal {
            return self.fail(Error::Tag);
        }
        let written = match self.run(self.depth, f) {
            Ok(w) => w,
            Err(e) => return self.fail(e),
        };
        let mut r = Reader::new(&written, Rules::Der);
        match (r.read(), r.is_empty()) {
            (Ok(e), true) => self.put(Tag { constructed: e.tag.constructed, ..tag }, e.contents),
            _ => self.fail(Error::Implicit),
        }
    }
}

/// Checks a DER element as the readers would: each universal type this
/// module reads, with its reader, and every constructed element's children.
/// Recursion is bounded by [`Element::reader`]'s depth check.
fn check_der(e: &Element<'_>) -> Result<(), Error> {
    let t = e.tag;
    if t.class == Class::Universal {
        match t.number {
            1 => e.boolean().map(drop)?,
            2 | 10 => e.integer().map(drop)?,
            3 => e.bit_string().map(drop)?,
            4 => e.octet_string().map(drop)?,
            5 => e.null()?,
            6 => e.oid().map(drop)?,
            23 => e.utc_time().map(drop)?,
            24 => e.generalized_time().map(drop)?,
            16 | 17 if !t.constructed => return Err(Error::Primitive),
            17 if e.set_reader().is_err() => e.set_of_reader().map(drop)?,
            n => {
                if let Some(kind) = StringKind::from_tag(Tag::universal(n)) {
                    e.string_bytes(kind).map(drop)?;
                }
            }
        }
    }
    if t.constructed {
        for child in e.reader()? {
            check_der(&child?)?;
        }
    }
    Ok(())
}

/// Two's-complement bytes without redundant leading bytes. No bytes at
/// all is zero.
#[inline]
pub fn minimal_twos(b: &[u8]) -> &[u8] {
    let mut b = b;
    while let [first, second, ..] = b {
        if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
            b = &b[1..];
        } else {
            break;
        }
    }
    if b.is_empty() { &[0] } else { b }
}

/// A set's children, as the writer wrote them, put in DER order.
fn sorted(contents: &[u8], order: Order) -> Result<Vec<u8>, Error> {
    let mut items = Reader::new(contents, Rules::Der).collect::<Result<Vec<_>, _>>()?;
    if order == Order::Encodings {
        items.sort_by(|a, b| padded_cmp(a.raw, b.raw));
    } else {
        items.sort_by_key(|e| (e.tag.class, e.tag.number));
        if items.windows(2).any(|w| w[0].tag.same_type(w[1].tag)) {
            return Err(Error::SetOrder);
        }
    }
    Ok(items.iter().flat_map(|e| e.raw.iter().copied()).collect())
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{Class, Element, Elements, Error, Frame, MAX_INPUT, Oid, Reader, Rules, StringKind, Tag, Writer,
        check_generalized_time, check_utc_time, element_len};
    use fictionet::stdlib::test_support::contract;

    /// ASN.1 string kinds.
    const ALL_KINDS: [StringKind; 11] = [
        StringKind::Utf8,
        StringKind::Numeric,
        StringKind::Printable,
        StringKind::Teletex,
        StringKind::Videotex,
        StringKind::Ia5,
        StringKind::Graphic,
        StringKind::Visible,
        StringKind::General,
        StringKind::Universal,
        StringKind::Bmp,
    ];

    fn children(e: Element<'_>) -> Option<Vec<Element<'_>>> {
        e.reader().ok()?.collect::<Result<Vec<_>, _>>().ok()
    }

    fn copy_all(kids: Vec<Element<'_>>, w: &mut Writer) -> Option<()> {
        kids.into_iter().try_for_each(|k| copy(k, w))
    }

    /// Copies values supported by the DER writer.
    pub fn copy(e: Element<'_>, w: &mut Writer) -> Option<()> {
        let t = e.tag();
        let mut ok = Some(());
        if t.class != Class::Universal {
            if t.constructed {
                let kids = children(e)?;
                w.constructed(t, |w| ok = copy_all(kids, w));
            } else {
                w.primitive(t, e.contents());
            }
            return ok;
        }
        match t.number {
            1 => w.boolean(e.boolean().ok()?),
            2 => w.integer_bytes(e.integer().ok()?.as_bytes()),
            3 => w.bit_string_value(&e.bit_string().ok()?),
            4 => w.octet_string(&e.octet_string().ok()?),
            5 => {
                e.null().ok()?;
                w.null();
            }
            6 => w.oid(&e.oid().ok()?),
            10 => w.enumerated(e.integer().ok()?.to_i64()?),
            16 => {
                let kids = children(e)?;
                w.sequence(|w| ok = copy_all(kids, w));
            }
            17 => {
                let kids = children(e)?;
                let mut tags: Vec<_> = kids.iter().map(|k| (k.tag().class, k.tag().number)).collect();
                tags.sort();
                let distinct = tags.windows(2).all(|p| p[0] != p[1]);
                if distinct && e.set_reader().is_ok() {
                    w.set(|w| ok = copy_all(kids, w));
                } else if e.set_of_reader().is_ok() {
                    w.set_of(|w| ok = copy_all(kids, w));
                } else {
                    return None;
                }
            }
            23 => {
                let s = e.utc_time().ok()?;
                check_utc_time(s.as_bytes(), Rules::Der).ok()?;
                w.utc_time(&s);
            }
            24 => {
                let s = e.generalized_time().ok()?;
                check_generalized_time(s.as_bytes(), Rules::Der).ok()?;
                w.generalized_time(&s);
            }
            n => {
                let kind = StringKind::from_tag(Tag::universal(n))?;
                w.string_bytes(kind, &e.string_bytes(kind).ok()?);
            }
        }
        ok
    }

    /// Checks value readers on an element and its children.
    pub fn walk(e: Element<'_>) {
        let _ = e.boolean();
        if let Ok(i) = e.integer() {
            let _ = (i.to_i64(), i.to_u64(), i.to_i128(), i.to_u128(), i.unsigned_bytes());
        }
        let _ = e.null();
        if let Ok(o) = e.oid() {
            let back = Oid::from_arcs(&o.arcs()).unwrap();
            assert_eq!(back, o);
            assert_eq!(o.to_string().parse::<Oid>(), Ok(o));
        }
        let _ = e.octet_string();
        if let Ok(b) = e.bit_string() {
            let _ = b.bit(b.len().saturating_sub(1));
            for i in 0..b.len().min(64) {
                assert!(b.bit(i).is_some());
            }
        }
        for kind in ALL_KINDS {
            let _ = e.string_bytes(kind);
            if let Ok(s) = e.text(kind) {
                assert_eq!(kind.encode(&s).ok().as_deref(), e.string_bytes(kind).ok().as_deref());
                let mut writer = Writer::new();
                writer.text(kind, &s);
                let bytes = writer.finish().expect("decoded text re-encodes");
                let mut reader = Reader::new(&bytes, Rules::Der);
                assert_eq!(
                    reader.read().unwrap().string_bytes(kind).ok().as_deref(),
                    e.string_bytes(kind).ok().as_deref()
                );
            }
        }
        let _ = (e.utc_time(), e.generalized_time(), e.set_reader().is_ok(), e.set_of_reader().is_ok());
        if let Ok(r) = e.reader() {
            for child in r {
                match child {
                    Ok(c) => walk(c),
                    Err(_) => break,
                }
            }
        }
    }

    /// Checks BER and DER framing and writer round trips.
    pub fn check(data: &[u8]) {
        for rules in [Rules::Ber, Rules::Der] {
            contract::check_decode_with_alloc_limit(|| Elements::new(rules), data, 2 * MAX_INPUT);
        }
        contract::check_wire::<Frame>(data);
        // DER is BER: what DER frames, BER frames the same.
        if let Ok(Some(n)) = element_len(data, Rules::Der) {
            assert_eq!(element_len(data, Rules::Ber), Ok(Some(n)));
        }
        for rules in [Rules::Ber, Rules::Der] {
            for e in Reader::new(data, rules) {
                let Ok(e) = e else { break };
                walk(e);
                // What `Writer::encoded` takes, it writes as is, and DER reads.
                let mut w = Writer::new();
                w.encoded(e.raw());
                if let Ok(out) = w.finish() {
                    assert_eq!(out, e.raw());
                    let mut r = Reader::new(&out, Rules::Der);
                    walk(r.read().unwrap());
                    assert!(r.is_empty());
                }
                let mut w = Writer::new();
                if copy(e, &mut w).is_none() {
                    continue;
                }
                let out = match w.finish() {
                    Ok(out) => out,
                    Err(err) => {
                        assert_eq!(err, Error::TooLong);
                        continue;
                    }
                };
                if rules == Rules::Der {
                    assert_eq!(out, e.raw(), "DER copy differs");
                }
                // What a writer writes reads under DER, and copies the same.
                let mut r = Reader::new(&out, Rules::Der);
                let back = r.read().unwrap();
                assert!(r.is_empty());
                let mut w2 = Writer::new();
                copy(back, &mut w2).unwrap();
                assert_eq!(w2.finish().unwrap(), out);
                // And `Writer::encoded` takes it back unchanged.
                let mut w3 = Writer::new();
                w3.encoded(&out);
                assert_eq!(w3.finish().unwrap(), out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::harness::{check, copy};
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream,
    };
    use fictionet::stdlib::test_support::{chunks, mutate};

    fn der(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.finish().unwrap()
    }

    fn one(b: &[u8], rules: Rules) -> Result<Element<'_>, Error> {
        let mut r = Reader::new(b, rules);
        let e = r.read()?;
        r.finish()?;
        Ok(e)
    }

    // Examples from ITU-T X.690 (02/2021), section 8 and annex A.

    fn tag_bytes(tag: Tag) -> Vec<u8> {
        let mut bytes = Vec::new();
        tag.encode(&mut bytes);
        bytes
    }

    #[test]
    fn review_write_checked_rejects_lossy_encoding() {
        let mut out = vec![42];
        let result = write_checked(&256u16, |v| Ok(vec![*v as u8]),
            |b| Ok(u16::from(b[0])), Error::Integer, &mut out);
        assert_eq!(result, Err(Error::Integer));
        assert_eq!(out, [42]);
    }

    #[test]
    fn boolean_example() {
        // 8.2.2: TRUE may be any nonzero byte in BER; DER uses 0xFF.
        assert_eq!(der(|w| w.boolean(true)), [0x01, 0x01, 0xff]);
        assert_eq!(der(|w| w.boolean(false)), [0x01, 0x01, 0x00]);
        assert_eq!(Reader::new(&[0x01, 0x01, 0x05], Rules::Ber).read_boolean(), Ok(true));
        assert_eq!(Reader::new(&[0x01, 0x01, 0x05], Rules::Der).read_boolean(), Err(Error::Boolean));
    }

    #[test]
    fn length_examples() {
        // 8.1.3.4 and 8.1.3.5: L = 38 in short form, L = 201 in long form.
        let mut out = Vec::new();
        encode_length(38, &mut out);
        assert_eq!(out, [0x26]);
        out.clear();
        encode_length(201, &mut out);
        assert_eq!(out, [0x81, 0xc9]);
        // BER may spend more octets on a length; DER may not.
        let long = [0x04, 0x81, 0x01, 0xaa];
        assert_eq!(Reader::new(&long, Rules::Ber).read_octet_string().unwrap().as_ref(), [0xaa]);
        assert_eq!(Reader::new(&long, Rules::Der).read_octet_string(), Err(Error::NonMinimalLength));
        let padded = [0x04, 0x82, 0x00, 0x81, 0xaa];
        assert_eq!(Header::parse(&padded, Rules::Ber).unwrap().length, Length::Definite(0x81));
        assert_eq!(Header::parse(&padded, Rules::Der), Err(Error::NonMinimalLength));
        // A 200-byte octet string takes a two-byte length.
        let w = der(|w| w.octet_string(&[7; 200]));
        assert_eq!(&w[..3], [0x04, 0x81, 200]);
        assert_eq!(w.len(), 203);
    }

    #[test]
    fn sequence_example() {
        // 8.9.3: SEQUENCE {name IA5String, ok BOOLEAN} {name "Smith", ok TRUE}.
        let bytes = [0x30, 0x0a, 0x16, 0x05, b'S', b'm', b'i', b't', b'h', 0x01, 0x01, 0xff];
        let built = der(|w| {
            w.sequence(|w| {
                w.text(StringKind::Ia5, "Smith");
                w.boolean(true);
            })
        });
        assert_eq!(built, bytes);
        let mut r = Reader::new(&bytes, Rules::Der);
        let mut s = r.read_sequence().unwrap();
        assert_eq!(s.read_text().unwrap(), (StringKind::Ia5, "Smith".to_string()));
        assert!(s.read_boolean().unwrap());
        s.finish().unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn bit_string_example() {
        // 8.6.4.2: '0A3B5F291CD'H, primitive and then constructed.
        let primitive = [0x03, 0x07, 0x04, 0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0];
        let b = Reader::new(&primitive, Rules::Der).read_bit_string().unwrap();
        assert_eq!((b.unused(), b.bytes()), (4, &[0x0a, 0x3b, 0x5f, 0x29, 0x1c, 0xd0][..]));
        assert_eq!(b.len(), 44);
        assert_eq!(b.bit(4), Some(true));
        assert_eq!(b.bit(0), Some(false));
        assert_eq!(b.bit(44), None);
        assert_eq!(der(|w| w.bit_string(b.bytes(), 4)), primitive);
        let constructed =
            [0x23, 0x80, 0x03, 0x03, 0x00, 0x0a, 0x3b, 0x03, 0x05, 0x04, 0x5f, 0x29, 0x1c, 0xd0, 0x00, 0x00];
        let c = Reader::new(&constructed, Rules::Ber).read_bit_string().unwrap();
        assert_eq!(c, b);
        assert_eq!(Reader::new(&constructed, Rules::Der).read_bit_string(), Err(Error::Indefinite));
        // The same, definite-length: DER still refuses the constructed form.
        let definite = [0x23, 0x0c, 0x03, 0x03, 0x00, 0x0a, 0x3b, 0x03, 0x05, 0x04, 0x5f, 0x29, 0x1c, 0xd0];
        assert_eq!(Reader::new(&definite, Rules::Ber).read_bit_string().unwrap(), b);
        assert_eq!(Reader::new(&definite, Rules::Der).read_bit_string(), Err(Error::Constructed));
    }

    #[test]
    fn octet_string_segments() {
        // 8.7.3.2: a constructed octet string, nested, with an indefinite
        // length inside a definite one.
        let b = [0x24, 0x0b, 0x04, 0x01, b'a', 0x24, 0x80, 0x04, 0x02, b'b', b'c', 0x00, 0x00];
        assert_eq!(Reader::new(&b, Rules::Ber).read_octet_string().unwrap().as_ref(), b"abc");
        // Segments must be octet strings.
        let bad = [0x24, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(
            Reader::new(&bad, Rules::Ber).read_octet_string(),
            Err(Error::Unexpected { expected: Tag::OCTET_STRING, found: Tag::INTEGER })
        );
        // A constructed UTF8String is made of octet string segments too.
        let s = [0x2c, 0x80, 0x04, 0x02, 0xc3, 0xa9, 0x04, 0x01, b'!', 0x00, 0x00];
        assert_eq!(Reader::new(&s, Rules::Ber).read_text().unwrap(), (StringKind::Utf8, "é!".to_string()));
    }

    #[test]
    fn oid_examples() {
        // 8.19.5: {2 999 3} is 88 37 03.
        let o = Oid::from_arcs(&[2, 999, 3]).unwrap();
        assert_eq!(o.as_bytes(), [0x88, 0x37, 0x03]);
        assert_eq!(der(|w| w.oid(&o)), [0x06, 0x03, 0x88, 0x37, 0x03]);
        assert_eq!(o.to_string(), "2.999.3");
        // id-at-commonName, 2.5.4.3.
        let cn: Oid = "2.5.4.3".parse().unwrap();
        assert_eq!(cn.as_bytes(), [0x55, 0x04, 0x03]);
        // A UUID arc under 2.25 needs all 128 bits.
        let big = Oid::from_arcs(&[2, 25, u128::MAX]).unwrap();
        assert_eq!(Oid::from_contents(big.as_bytes()).unwrap().arcs(), [2, 25, u128::MAX]);
        assert_eq!(big.to_string().parse::<Oid>(), Ok(big));
        // One bit more does not fit.
        let mut over = vec![0x69, 0x84];
        over.extend_from_slice(&[0xff; 18]);
        over.push(0x7f);
        assert_eq!(Oid::from_contents(&over), Err(Error::Oid));
        // 0.39 and 1.39 are the largest second arcs under 0 and 1.
        assert_eq!(Oid::from_arcs(&[1, 39]).unwrap().arcs(), [1, 39]);
        assert_eq!(Oid::from_arcs(&[0, 0]).unwrap().as_bytes(), [0]);
    }

    #[test]
    fn integer_examples() {
        let cases: &[(i128, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x00, 0x80]),
            (256, &[0x01, 0x00]),
            (-1, &[0xff]),
            (-128, &[0x80]),
            (-129, &[0xff, 0x7f]),
            (i128::MIN, &[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ];
        for &(v, contents) in cases {
            let b = der(|w| w.integer_i128(v));
            assert_eq!(&b[2..], contents, "{v}");
            let i = Reader::new(&b, Rules::Der).read_integer().unwrap();
            assert_eq!(i.to_i128(), Some(v));
            assert_eq!(i.is_negative(), v < 0);
        }
        // u64::MAX needs a leading zero byte.
        let b = der(|w| w.integer_u64(u64::MAX));
        assert_eq!(b, [0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(Reader::new(&b, Rules::Der).read_u64(), Ok(u64::MAX));
        assert_eq!(Reader::new(&b, Rules::Der).read_i64(), Err(Error::Integer));
        // An integer larger than any Rust type, such as an RSA modulus.
        let modulus = [0xc5u8; 256];
        let b = der(|w| w.integer_unsigned(&modulus));
        let i = Reader::new(&b, Rules::Der).read_integer().unwrap();
        assert_eq!(i.unsigned_bytes(), Some(&modulus[..]));
        assert_eq!(i.to_u128(), None);
        assert_eq!(der(|w| w.integer_unsigned(&[0, 0, 5])), [0x02, 0x01, 0x05]);
        assert_eq!(der(|w| w.integer_unsigned(&[])), [0x02, 0x01, 0x00]);
        assert_eq!(der(|w| w.integer_bytes(&[])), [0x02, 0x01, 0x00]);
        assert_eq!(der(|w| w.integer_bytes(&[0xff, 0xff, 0x80])), [0x02, 0x01, 0x80]);
        assert_eq!(der(|w| w.enumerated(2)), [0x0a, 0x01, 0x02]);
        let e = der(|w| w.enumerated(-300));
        assert_eq!(Reader::new(&e, Rules::Der).read_enumerated().unwrap().to_i64(), Some(-300));
    }

    #[test]
    fn integer_round_trips() {
        let mut rng = Lcg::new(1);
        for _ in 0..2000 {
            let mut bytes = [0; 8];
            rng.fill(&mut bytes);
            let x = u64::from_le_bytes(bytes);
            let shift = (x >> 58) as u32;
            let v = (x as i64) >> shift;
            let b = der(|w| w.integer_i64(v));
            assert_eq!(Reader::new(&b, Rules::Der).read_i64(), Ok(v));
            let u = x >> shift;
            let b = der(|w| w.integer_u64(u));
            assert_eq!(Reader::new(&b, Rules::Der).read_u64(), Ok(u));
            let wide = (i128::from(v) << 64) | i128::from(u);
            let b = der(|w| w.integer_i128(wide));
            assert_eq!(Reader::new(&b, Rules::Der).read_integer().unwrap().to_i128(), Some(wide));
            let uw = (u128::from(u) << 64) | u128::from(x);
            let b = der(|w| w.integer_u128(uw));
            assert_eq!(Reader::new(&b, Rules::Der).read_integer().unwrap().to_u128(), Some(uw));
        }
    }

    #[test]
    fn tags() {
        // 8.1.2.4: [APPLICATION 201], constructed, in the long form.
        let t = Tag::application(201).as_constructed();
        assert_eq!(tag_bytes(t), [0x7f, 0x81, 0x49]);
        assert_eq!(Tag::parse(&[0x7f, 0x81, 0x49]), Ok((t, 3)));
        assert_eq!(tag_bytes(Tag::context(30)), [0x9e]);
        assert_eq!(tag_bytes(Tag::context(31)), [0x9f, 0x1f]);
        assert_eq!(tag_bytes(Tag::private(u32::MAX)), [0xdf, 0x8f, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(Tag::parse(&tag_bytes(Tag::private(u32::MAX))), Ok((Tag::private(u32::MAX), 6)));
        // A long form for a number below 31, a leading zero group, and a
        // number past 32 bits.
        assert_eq!(Tag::parse(&[0x1f, 0x1e]), Err(Error::Tag));
        assert_eq!(Tag::parse(&[0x1f, 0x80, 0x7f]), Err(Error::Tag));
        assert_eq!(Tag::parse(&[0x1f, 0x90, 0x80, 0x80, 0x80, 0x00]), Err(Error::Tag));
        assert_eq!(Tag::parse(&[0x1f, 0x81]), Err(Error::Truncated));
        assert_eq!(Tag::SEQUENCE.to_string(), "[UNIVERSAL 16] constructed");
        // A long-tagged element reads and writes.
        let b = der(|w| w.primitive(Tag::context(1000), b"x"));
        assert_eq!(b, [0x9f, 0x87, 0x68, 0x01, b'x']);
        let e = Reader::new(&b, Rules::Der).read_expected(Tag::context(1000)).unwrap();
        assert_eq!(e.contents(), b"x");
    }

    #[test]
    fn explicit_implicit_and_optional() {
        // A TBSCertificate's start: [0] EXPLICIT version, serial, and an
        // absent [1] IMPLICIT field.
        let b = der(|w| {
            w.sequence(|w| {
                w.explicit(0, |w| w.integer_i64(2));
                w.integer_i64(0x1234);
                w.implicit(Tag::context(2), |w| w.octet_string(b"id"));
                w.implicit(Tag::context(3), |w| w.sequence(|w| w.null()));
            })
        });
        assert_eq!(
            b,
            [
                0x30, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x12, 0x34, 0x82, 0x02, b'i', b'd', 0xa3, 0x02,
                0x05, 0x00
            ]
        );
        let mut r = Reader::new(&b, Rules::Der);
        let mut s = r.read_sequence().unwrap();
        let mut v = s.read_explicit(0).unwrap();
        assert_eq!(v.read_i64(), Ok(2));
        v.finish().unwrap();
        assert_eq!(s.read_i64(), Ok(0x1234));
        assert_eq!(s.read_optional(Tag::context(1)).unwrap(), None);
        let id = s.read_optional(Tag::context(2)).unwrap().unwrap();
        assert_eq!(id.octet_string().unwrap().as_ref(), b"id");
        let mut inner = s.read_expected(Tag::context(3)).unwrap().reader().unwrap();
        inner.read_null().unwrap();
        assert_eq!(s.read_optional(Tag::context(4)), Ok(None));
        s.finish().unwrap();
        // The closure for an implicit tag must write one element.
        let mut w = Writer::new();
        w.implicit(Tag::context(0), |_| {});
        assert_eq!(w.finish(), Err(Error::Implicit));
        let mut w = Writer::new();
        w.implicit(Tag::context(0), |w| {
            w.null();
            w.null();
        });
        assert_eq!(w.finish(), Err(Error::Implicit));
    }

    #[test]
    fn sets() {
        // DER puts a SET in tag order and a SET OF in encoding order.
        let s = der(|w| {
            w.set(|w| {
                w.primitive(Tag::context(1), b"b");
                w.integer_i64(5);
                w.primitive(Tag::context(0), b"a");
            })
        });
        assert_eq!(s, [0x31, 0x09, 0x02, 0x01, 0x05, 0x80, 0x01, b'a', 0x81, 0x01, b'b']);
        let mut set = Reader::new(&s, Rules::Der).read_set().unwrap();
        assert_eq!(set.read_i64(), Ok(5));
        let so = der(|w| {
            w.set_of(|w| {
                w.integer_i64(300);
                w.integer_i64(2);
                w.integer_i64(1);
            })
        });
        assert_eq!(so, [0x31, 0x0a, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x02, 0x01, 0x2c]);
        let got: Vec<i64> = Reader::new(&so, Rules::Der)
            .read_set_of()
            .unwrap()
            .map(|e| e.unwrap().integer().unwrap().to_i64().unwrap())
            .collect();
        assert_eq!(got, [1, 2, 300]);
        // Out of order: DER refuses, BER does not care.
        let bad = [0x31, 0x06, 0x02, 0x01, 0x01, 0x01, 0x01, 0xff];
        assert_eq!(Reader::new(&bad, Rules::Der).read_set().err(), Some(Error::SetOrder));
        assert!(Reader::new(&bad, Rules::Ber).read_set().is_ok());
        let bad_of = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        assert_eq!(Reader::new(&bad_of, Rules::Der).read_set_of().err(), Some(Error::SetOrder));
        // A set with two elements of one tag cannot be written.
        let mut w = Writer::new();
        w.set(|w| {
            w.null();
            w.null();
        });
        assert_eq!(w.finish(), Err(Error::SetOrder));
    }

    #[test]
    fn strings() {
        let cases: &[(StringKind, &str, &[u8])] = &[
            (StringKind::Utf8, "héllo", "héllo".as_bytes()),
            (StringKind::Printable, "Test User 1", b"Test User 1"),
            (StringKind::Numeric, "12 34", b"12 34"),
            (StringKind::Ia5, "a@b.example", b"a@b.example"),
            (StringKind::Visible, "~x~", b"~x~"),
            (StringKind::Bmp, "Aé", &[0x00, 0x41, 0x00, 0xe9]),
            (StringKind::Universal, "A😀", &[0, 0, 0, 0x41, 0, 0x01, 0xf6, 0x00]),
        ];
        for &(kind, text, bytes) in cases {
            let b = der(|w| w.text(kind, text));
            assert_eq!(&b[2..], bytes);
            assert_eq!(b[0] as u32, kind.tag().number);
            assert_eq!(Reader::new(&b, Rules::Der).read_text(), Ok((kind, text.to_string())));
        }
        // Characters a type does not allow.
        for (kind, text) in [
            (StringKind::Printable, "a@b"),
            (StringKind::Numeric, "12a"),
            (StringKind::Ia5, "é"),
            (StringKind::Visible, "\n"),
            (StringKind::Bmp, "😀"),
        ] {
            let mut w = Writer::new();
            w.text(kind, text);
            assert_eq!(w.finish(), Err(Error::Charset), "{kind:?}");
        }
        assert_eq!(Reader::new(&[0x0c, 0x01, 0xff], Rules::Ber).read_text(), Err(Error::Charset));
        assert_eq!(Reader::new(&[0x1e, 0x02, 0xd8, 0x00], Rules::Ber).read_text(), Err(Error::Charset));
        assert_eq!(Reader::new(&[0x1e, 0x01, 0x41], Rules::Ber).read_text(), Err(Error::Charset));
        assert_eq!(Reader::new(&[0x1c, 0x04, 0, 0x11, 0, 0], Rules::Ber).read_text(), Err(Error::Charset));
        // Teletex is kept as bytes.
        let t = der(|w| w.string_bytes(StringKind::Teletex, &[0xc2, 0x61]));
        let e = Reader::new(&t, Rules::Der).read_expected(Tag::TELETEX_STRING).unwrap();
        assert_eq!(e.string_bytes(StringKind::Teletex).unwrap().as_ref(), [0xc2, 0x61]);
        assert_eq!(e.text(StringKind::Teletex), Err(Error::Charset));
        let mut w = Writer::new();
        w.text(StringKind::General, "x");
        assert_eq!(w.finish(), Err(Error::Charset));
        // Not a string at all.
        assert_eq!(
            Reader::new(&[0x05, 0x00], Rules::Der).read_text(),
            Err(Error::Unexpected { expected: Tag::UTF8_STRING, found: Tag::NULL })
        );
    }

    #[test]
    fn times() {
        // X.680 47.3 example: 6 May 1991, 16:45:40 at UTC-7, and the same
        // instant in the one form DER allows.
        assert_eq!(check_utc_time(b"910506164540-0700", Rules::Ber), Ok(()));
        assert_eq!(check_utc_time(b"910506164540-0700", Rules::Der), Err(Error::Time));
        assert_eq!(check_utc_time(b"910506234540Z", Rules::Der), Ok(()));
        assert_eq!(check_utc_time(b"9105062345Z", Rules::Ber), Ok(()));
        assert_eq!(check_utc_time(b"9105062345Z", Rules::Der), Err(Error::Time));
        let b = der(|w| w.utc_time("910506234540Z"));
        assert_eq!(&b[..2], [0x17, 0x0d]);
        assert_eq!(Reader::new(&b, Rules::Der).read_utc_time().unwrap(), "910506234540Z");
        // GeneralizedTime, X.680 46.3 and X.690 11.7.
        for ok in ["19920521000000Z", "19920622123421.5Z", "20001231235959.999Z"] {
            assert_eq!(check_generalized_time(ok.as_bytes(), Rules::Der), Ok(()), "{ok}");
            let b = der(|w| w.generalized_time(ok));
            assert_eq!(Reader::new(&b, Rules::Der).read_generalized_time().unwrap(), ok);
        }
        for ber_only in [
            "1992052100Z",
            "199205210000",
            "19920622123421,5Z",
            "19920622123421.50Z",
            "19851106210627.3-0500",
            "19851106210627.3+05",
        ] {
            assert_eq!(check_generalized_time(ber_only.as_bytes(), Rules::Ber), Ok(()), "{ber_only}");
            assert_eq!(check_generalized_time(ber_only.as_bytes(), Rules::Der), Err(Error::Time), "{ber_only}");
        }
        for bad in [
            "",
            "2000",
            "20000230000000Z",
            "19000229000000Z",
            "20001301000000Z",
            "20000101240000Z",
            "20000101006000Z",
            "20000101000061Z",
            "20000101000000.Z",
            "20000101000000Zx",
            "20000101000000+2400",
            "2000010100000a",
        ] {
            assert_eq!(check_generalized_time(bad.as_bytes(), Rules::Ber), Err(Error::Time), "{bad}");
        }
        // Leap years: 2000 was one, 1900 was not.
        assert_eq!(check_generalized_time(b"20000229000000Z", Rules::Der), Ok(()));
        assert_eq!(check_utc_time(b"000229000000Z", Rules::Der), Ok(()));
        assert_eq!(check_utc_time(b"990229000000Z", Rules::Der), Err(Error::Time));
        assert_eq!(check_utc_time(b"9105062345", Rules::Ber), Err(Error::Time));
        assert_eq!(check_utc_time(&[b'1'; 70], Rules::Ber), Err(Error::Time));
        let mut w = Writer::new();
        w.utc_time("9105062345Z");
        assert_eq!(w.finish(), Err(Error::Time));
        let mut w = Writer::new();
        w.generalized_time("19920521000000");
        assert_eq!(w.finish(), Err(Error::Time));
    }

    #[test]
    fn indefinite_lengths() {
        // Nested indefinite lengths, with a definite one inside.
        let b = [0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00];
        let mut r = Reader::new(&b, Rules::Ber);
        let outer = r.read().unwrap();
        assert!(outer.is_indefinite());
        assert_eq!(outer.raw().len(), 13);
        assert_eq!(outer.contents().len(), 9);
        let mut s = outer.reader().unwrap();
        let mut inner = s.read_sequence().unwrap();
        assert_eq!(inner.read_i64(), Ok(7));
        inner.finish().unwrap();
        s.read_null().unwrap();
        s.finish().unwrap();
        assert!(!r.read_boolean().unwrap());
        assert_eq!(element_len(&b, Rules::Ber), Ok(Some(13)));
        assert_eq!(element_len(&b, Rules::Der), Err(Error::Indefinite));
        // Copied, it comes out as DER.
        let mut w = Writer::new();
        copy(outer, &mut w).unwrap();
        assert_eq!(w.finish().unwrap(), [0x30, 0x07, 0x30, 0x03, 0x02, 0x01, 0x07, 0x05, 0x00]);
    }

    #[test]
    fn error_paths() {
        fn ber(b: &[u8]) -> Result<Element<'_>, Error> {
            one(b, Rules::Ber)
        }
        fn derr(b: &[u8]) -> Result<Element<'_>, Error> {
            one(b, Rules::Der)
        }
        assert_eq!(ber(&[0x30, 0x05, 0x01]), Err(Error::Truncated));
        assert_eq!(ber(&[0x04, 0x83, 0x20, 0x00, 0x00]), Err(Error::TooLong));
        assert_eq!(ber(&[0x04, 0xff]), Err(Error::Length));
        assert_eq!(ber(&[0x04, 0x85, 0, 0, 0, 0, 1, 0]), Err(Error::Length));
        assert_eq!(derr(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0]), Err(Error::NonMinimalLength));
        assert_eq!(derr(&[0x30, 0x80, 0x00, 0x00]), Err(Error::Indefinite));
        assert_eq!(ber(&[0x04, 0x80, 0x00, 0x00]), Err(Error::Indefinite));
        assert_eq!(ber(&[0x00, 0x00]), Err(Error::Eoc));
        assert_eq!(ber(&[0x30, 0x80, 0x00, 0x01, 0x00]), Err(Error::Eoc));
        assert_eq!(ber(&[0x30, 0x80, 0x20, 0x00]), Err(Error::Eoc));
        assert_eq!(ber(&[0x1f, 0x05, 0x00]), Err(Error::Tag));
        assert_eq!(ber(&[0x05, 0x00, 0x05]), Err(Error::Trailing));
        assert_eq!(Reader::new(&[], Rules::Ber).read(), Err(Error::Empty));
        assert_eq!(
            Reader::new(&[0x02, 0x01, 0x00], Rules::Ber).read_boolean(),
            Err(Error::Unexpected { expected: Tag::BOOLEAN, found: Tag::INTEGER })
        );
        assert_eq!(ber(&[0x04, 0x00]).unwrap().reader().err(), Some(Error::Primitive));
        assert_eq!(ber(&[0x21, 0x03, 0x01, 0x01, 0xff]).unwrap().boolean(), Err(Error::Constructed));
        assert_eq!(derr(&[0x24, 0x03, 0x04, 0x01, 0x00]).unwrap().octet_string(), Err(Error::Constructed));
        assert_eq!(ber(&[0x01, 0x02, 0x00, 0x00]).unwrap().boolean(), Err(Error::Boolean));
        assert_eq!(ber(&[0x01, 0x00]).unwrap().boolean(), Err(Error::Boolean));
        assert_eq!(ber(&[0x02, 0x00]).unwrap().integer(), Err(Error::Integer));
        assert_eq!(ber(&[0x02, 0x02, 0x00, 0x7f]).unwrap().integer(), Err(Error::Integer));
        assert_eq!(ber(&[0x02, 0x02, 0xff, 0x80]).unwrap().integer(), Err(Error::Integer));
        assert_eq!(ber(&[0x05, 0x01, 0x00]).unwrap().null(), Err(Error::Null));
        assert_eq!(ber(&[0x03, 0x00]).unwrap().bit_string(), Err(Error::BitString));
        assert_eq!(ber(&[0x03, 0x01, 0x01]).unwrap().bit_string(), Err(Error::BitString));
        assert_eq!(ber(&[0x03, 0x02, 0x08, 0x00]).unwrap().bit_string(), Err(Error::BitString));
        assert_eq!(derr(&[0x03, 0x02, 0x01, 0x01]).unwrap().bit_string(), Err(Error::BitString));
        assert!(ber(&[0x03, 0x02, 0x01, 0x01]).is_ok_and(|e| e.bit_string().is_ok()));
        // A segment other than the last with unused bits.
        let seg = [0x23, 0x08, 0x03, 0x02, 0x01, 0xfe, 0x03, 0x02, 0x00, 0xff];
        assert_eq!(ber(&seg).unwrap().bit_string(), Err(Error::BitString));
        assert_eq!(ber(&[0x06, 0x00]).unwrap().oid(), Err(Error::Oid));
        assert_eq!(ber(&[0x06, 0x01, 0x81]).unwrap().oid(), Err(Error::Oid));
        assert_eq!(ber(&[0x06, 0x02, 0x80, 0x01]).unwrap().oid(), Err(Error::Oid));
        assert_eq!(ber(&[0x06, 0x03, 0x2a, 0x80, 0x01]).unwrap().oid(), Err(Error::Oid));
        assert_eq!(Oid::from_contents(&[0x01; MAX_OID_LEN + 1]), Err(Error::Oid));
        assert_eq!(Oid::from_arcs(&[1]), Err(Error::Oid));
        assert_eq!(Oid::from_arcs(&[3, 1]), Err(Error::Oid));
        assert_eq!(Oid::from_arcs(&[1, 40]), Err(Error::Oid));
        assert_eq!(Oid::from_arcs(&[2, u128::MAX]), Err(Error::Oid));
        assert_eq!(Oid::from_arcs(&[1; 300]), Err(Error::Oid));
        for bad in ["", "1", "1.", ".1", "1..2", "1.+2", "1.2.x", "3.1", "1.2.340282366920938463463374607431768211456"]
        {
            assert_eq!(bad.parse::<Oid>(), Err(Error::Oid), "{bad:?}");
        }
        assert_eq!(ber(&[0x13, 0x01, b'@']).unwrap().text(StringKind::Printable), Err(Error::Charset));
        assert_eq!(ber(&[0x17, 0x01, b'1']).unwrap().utc_time(), Err(Error::Time));
        assert_eq!(BitString::new(&[][..], 1), Err(Error::BitString));
        assert_eq!(BitString::new(&[1][..], 8), Err(Error::BitString));
        // Writer refusals.
        let mut w = Writer::new();
        w.primitive(Tag::INTEGER, &[1]);
        assert_eq!(w.finish(), Err(Error::Tag));
        let mut w = Writer::new();
        w.constructed(Tag::universal(8), |_| {});
        assert_eq!(w.finish(), Err(Error::Tag));
        let mut w = Writer::new();
        w.implicit(Tag::universal(4), |w| w.null());
        assert_eq!(w.finish(), Err(Error::Tag));
        let mut w = Writer::new();
        w.bit_string(&[], 3);
        assert_eq!(w.finish(), Err(Error::BitString));
        let mut w = Writer::new();
        w.octet_string(&vec![0; MAX_INPUT]);
        assert_eq!(w.finish(), Err(Error::TooLong));
        // Nothing more is written after an error.
        let mut w = Writer::new();
        w.text(StringKind::Numeric, "x");
        w.null();
        assert!(w.is_empty());
        assert_eq!(w.error(), Some(Error::Charset));
        // Every error has a message.
        assert!(Error::Unexpected { expected: Tag::NULL, found: Tag::BOOLEAN }.to_string().contains("[UNIVERSAL 5]"));
    }

    #[test]
    fn depth_limits() {
        // MAX_DEPTH + 1 nested sequences, written by hand.
        let mut b = vec![0x05, 0x00];
        for _ in 0..=MAX_DEPTH {
            let mut outer = vec![0x30];
            encode_length(b.len(), &mut outer);
            outer.extend_from_slice(&b);
            b = outer;
        }
        let mut e = one(&b, Rules::Der).unwrap();
        let mut opened = 0;
        let err = loop {
            match e.reader() {
                Ok(mut r) => {
                    e = r.read().unwrap();
                    opened += 1;
                }
                Err(err) => break err,
            }
        };
        assert_eq!((err, opened), (Error::TooDeep, MAX_DEPTH));
        // The writer stops at the same depth.
        fn nest(w: &mut Writer, n: usize) {
            if n == 0 {
                w.null();
            } else {
                w.sequence(|w| nest(w, n - 1));
            }
        }
        let mut w = Writer::new();
        nest(&mut w, MAX_DEPTH);
        let ok = w.finish().unwrap();
        check(&ok);
        let mut w = Writer::new();
        nest(&mut w, MAX_DEPTH + 1);
        assert_eq!(w.finish(), Err(Error::TooDeep));
        // Indefinite lengths too deep are refused while framing.
        let mut deep = [0x30, 0x80].repeat(MAX_DEPTH + 1);
        deep.extend_from_slice(&[0x00, 0x00].repeat(MAX_DEPTH + 1));
        assert_eq!(element_len(&deep, Rules::Ber), Err(Error::TooDeep));
        let mut fits = [0x30, 0x80].repeat(MAX_DEPTH);
        fits.extend_from_slice(&[0x00, 0x00].repeat(MAX_DEPTH));
        assert_eq!(element_len(&fits, Rules::Ber), Ok(Some(fits.len())));
        check(&fits);
        // A definite-length sequence at the limit reads; an indefinite one
        // does not, since its end lies inside it.
        let mut at_limit = [0x30, 0x80].repeat(MAX_DEPTH);
        at_limit.extend_from_slice(&[0x30, 0x00]);
        at_limit.extend_from_slice(&[0x00, 0x00].repeat(MAX_DEPTH));
        assert_eq!(element_len(&at_limit, Rules::Ber), Ok(Some(at_limit.len())));
    }

    #[test]
    fn size_limits() {
        // An element just at the limit reads; one byte more does not.
        let n = MAX_INPUT - 5;
        let mut b = vec![0x04, 0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8];
        b.resize(MAX_INPUT, 0);
        assert_eq!(element_len(&b, Rules::Der), Ok(Some(MAX_INPUT)));
        let w = der(|w| w.octet_string(&b[5..]));
        assert_eq!(w, b);
        b[4] += 1;
        assert_eq!(element_len(&b, Rules::Der), Err(Error::TooLong));
        // An indefinite length that never ends is refused at the limit.
        let mut endless = vec![0x30, 0x80];
        while endless.len() < MAX_INPUT + 10 {
            endless.extend_from_slice(&[0x04, 0x01, 0x00]);
        }
        assert_eq!(element_len(&endless, Rules::Ber), Err(Error::TooLong));
        assert_eq!(element_len(&endless[..1000], Rules::Ber), Ok(None));
        let mut d = Stream::new(Elements::new(Rules::Ber));
        let mut result = None;
        for chunk in chunks(&endless, &[1 << 16]) {
            assert_eq!(d.push(chunk), chunk.len());
            assert!(d.buffered() <= MAX_INPUT);
            if let Some(r) = d.next() {
                result = Some(r);
                break;
            }
        }
        assert_eq!(result, Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(d.buffered(), MAX_INPUT);
        assert_eq!(d.next(), None);
    }

    fn samples() -> Vec<Vec<u8>> {
        let oid: Oid = "1.2.840.113549.1.1.11".parse().unwrap();
        vec![
            der(|w| {
                w.sequence(|w| {
                    w.oid(&oid);
                    w.null();
                })
            }),
            der(|w| {
                w.sequence(|w| {
                    w.explicit(0, |w| w.integer_i64(2));
                    w.integer_u128(u128::MAX);
                    w.set(|w| {
                        w.text(StringKind::Printable, "US");
                        w.boolean(false);
                    });
                    w.set_of(|w| {
                        w.octet_string(b"zz");
                        w.octet_string(b"a");
                    });
                    w.bit_string(&[0xa5, 0xf0], 4);
                    w.utc_time("250101000000Z");
                    w.generalized_time("20250101000000.25Z");
                    w.enumerated(3);
                    w.text(StringKind::Bmp, "hi");
                    w.text(StringKind::Universal, "hi");
                    w.implicit(Tag::application(70), |w| w.text(StringKind::Utf8, "x"));
                    w.constructed(Tag::private(5).as_constructed(), |w| w.null());
                })
            }),
            vec![0x30, 0x80, 0x24, 0x80, 0x04, 0x01, b'a', 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00],
            vec![0x23, 0x80, 0x03, 0x03, 0x00, 0x0a, 0x3b, 0x03, 0x05, 0x04, 0x5f, 0x29, 0x1c, 0xd0, 0x00, 0x00],
            vec![0x31, 0x80, 0x01, 0x01, 0x07, 0x02, 0x01, 0x00, 0x00, 0x00],
            vec![0x7f, 0x81, 0x49, 0x84, 0x00, 0x00, 0x00, 0x03, 0x17, 0x01, b'9'],
            vec![0x04, 0x81, 0x02, 0xab, 0xcd],
        ]
    }

    #[test]
    fn round_trips() {
        for s in samples() {
            check(&s);
        }
        // Sample 1 copies to exactly itself under DER.
        let s = &samples()[1];
        let e = one(s, Rules::Der).unwrap();
        let mut w = Writer::new();
        copy(e, &mut w).unwrap();
        assert_eq!(&w.finish().unwrap(), s);
    }

    #[test]
    fn every_truncated_prefix() {
        for s in samples() {
            let n = element_len(&s, Rules::Ber).unwrap().unwrap();
            assert_eq!(n, s.len());
            for k in 0..n {
                assert_eq!(element_len(&s[..k], Rules::Ber), Ok(None), "{k} of {s:02x?}");
                let want = if k == 0 { Error::Empty } else { Error::Truncated };
                assert_eq!(Reader::new(&s[..k], Rules::Ber).read(), Err(want));
            }
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = der(|w| w.sequence(|w| w.integer_i64(1)));
        let b = vec![0x30, 0x80, 0x02, 0x01, 0x02, 0x00, 0x00];
        let stream: Vec<u8> = a.iter().chain(&b).chain(&a).copied().collect();
        let mut d = Stream::new(Elements::new(Rules::Ber));
        let mut got = Vec::new();
        for byte in chunks(&stream, &[1]) {
            assert_eq!(d.push(byte), 1);
            while let Some(e) = d.next() {
                got.push(e.unwrap());
            }
        }
        assert_eq!(got, [a.clone(), b.clone(), a.clone()]);
        assert_eq!(d.buffered(), 0);
        // DER refuses the indefinite one, and the stream stays broken.
        let mut d = Stream::new(Elements::new(Rules::Der));
        assert_eq!(d.push(&stream), stream.len());
        assert_eq!(d.next(), Some(Ok(a.clone())));
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::Indefinite))));
        assert_eq!(d.push(&a), a.len());
        assert_eq!(d.next(), None);
        assert_eq!(d.failed(), Some(&Fail::Protocol(Error::Indefinite)));
    }

    #[test]
    fn end_of_contents_is_two_zero_octets() {
        // X.690 8.1.5: the marker is exactly 00 00. A long-form zero length
        // after a zero tag is not one, even in BER.
        let b = [0x30, 0x80, 0x05, 0x00, 0x00, 0x81, 0x00];
        assert_eq!(element_len(&b, Rules::Ber), Err(Error::Eoc));
        assert_eq!(one(&b, Rules::Ber), Err(Error::Eoc));
        let b = [0x30, 0x80, 0x05, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(element_len(&b, Rules::Ber), Err(Error::Eoc));
    }

    #[test]
    fn decoder_fed_a_byte_at_a_time_stays_linear() {
        // An indefinite element of many small children, fed one byte at a
        // time. Each call must go on from where the last one stopped, not
        // scan the element again from its start.
        let mut b = vec![0x30, 0x80];
        while b.len() < 1 << 18 {
            b.extend_from_slice(&[0x04, 0x00]);
        }
        b.extend_from_slice(&[0x00, 0x00]);
        let mut d = Stream::new(Elements::new(Rules::Ber));
        let mut got = Vec::new();
        for byte in chunks(&b, &[1]) {
            assert_eq!(d.push(byte), 1);
            while let Some(e) = d.next() {
                got.push(e.unwrap());
            }
        }
        assert_eq!(got, [b]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_elements_in_linear_time() {
        // One push of half a million NULLs. Taking each one out must not
        // copy the bytes still waiting behind it.
        let n = MAX_INPUT / 2;
        let stream = [0x05, 0x00].repeat(n);
        let mut d = Stream::new(Elements::new(Rules::Der));
        assert_eq!(d.push(&stream), stream.len());
        let mut count = 0;
        while let Some(e) = d.next() {
            assert_eq!(e.unwrap(), [0x05, 0x00]);
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        // Interleaved with pushes, partial elements still join up.
        let a = [0x30, 0x03, 0x02, 0x01, 0x01];
        let b = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let stream = [&a[..], &b[..]].concat().repeat(1000);
        let mut d = Stream::new(Elements::new(Rules::Ber));
        let mut got = Vec::new();
        for chunk in chunks(&stream, &[7]) {
            assert_eq!(d.push(chunk), chunk.len());
            while let Some(e) = d.next() {
                got.push(e.unwrap());
            }
        }
        assert_eq!(got.len(), 2000);
        assert!(got.chunks(2).all(|p| p[0] == a && p[1] == b));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn writing_encoded_elements() {
        // A signed structure's part, kept as DER and written into a new one.
        let alg = der(|w| {
            w.sequence(|w| {
                w.oid(&"1.2.840.113549.1.1.11".parse().unwrap());
                w.null();
            })
        });
        let cert = der(|w| {
            w.sequence(|w| {
                w.encoded(&alg);
                w.bit_string(&[0xaa], 0);
            })
        });
        let mut s = Reader::new(&cert, Rules::Der).read_sequence().unwrap();
        assert_eq!(s.read().unwrap().raw(), alg);
        let sig = s.read_bit_string().unwrap().into_owned();
        assert_eq!(sig.bytes(), [0xaa]);
        assert_eq!(der(|w| w.bit_string_value(&sig)), [0x03, 0x02, 0x00, 0xaa]);
        // Refused: BER, nothing, two elements, a bad value deep inside, a
        // SET out of order, a primitive SEQUENCE.
        let refused: &[(&[u8], Error)] = &[
            (&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00], Error::Indefinite),
            (&[], Error::Empty),
            (&[0x05, 0x00, 0x05, 0x00], Error::Trailing),
            (&[0x30, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01], Error::Boolean),
            (&[0x30, 0x04, 0x02, 0x02, 0x00, 0x01], Error::Integer),
            (&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01], Error::SetOrder),
            (&[0x10, 0x00], Error::Primitive),
            (&[0x24, 0x03, 0x04, 0x01, 0x00], Error::Constructed),
            (&[0x13, 0x01, b'@'], Error::Charset),
        ];
        for &(b, want) in refused {
            let mut w = Writer::new();
            w.encoded(b);
            assert_eq!(w.finish(), Err(want), "{b:02x?}");
        }
        // Non-universal values are copied as they are.
        assert_eq!(der(|w| w.encoded(&[0x80, 0x01, 0xff])), [0x80, 0x01, 0xff]);
        // Depth counts from where it is written.
        fn nest(w: &mut Writer, n: usize, inner: &[u8]) {
            if n == 0 { w.encoded(inner) } else { w.sequence(|w| nest(w, n - 1, inner)) }
        }
        let mut w = Writer::new();
        nest(&mut w, MAX_DEPTH, &[0x30, 0x00]);
        assert_eq!(w.finish(), Err(Error::TooDeep));
        let mut w = Writer::new();
        nest(&mut w, MAX_DEPTH, &[0x05, 0x00]);
        check(&w.finish().unwrap());
        // Strings this module does not decode read as bytes.
        let t = der(|w| w.string_bytes(StringKind::General, b"x"));
        assert_eq!(Reader::new(&t, Rules::Der).read_string_bytes(StringKind::General).unwrap().as_ref(), b"x");
        assert_eq!(
            Reader::new(&t, Rules::Der).read_string_bytes(StringKind::Ia5),
            Err(Error::Unexpected { expected: Tag::IA5_STRING, found: Tag::GENERAL_STRING })
        );
        let mut d = Stream::new(Elements::new(Rules::Der));
        assert_eq!(d.decoder().rules(), Rules::Der);
        assert_eq!(d.push(&t[..1]), 1);
        assert_eq!((d.next(), d.buffered()), (None, 1));
        assert_eq!(BitString::new(vec![0; MAX_INPUT + 1], 0), Err(Error::TooLong));
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x2545_f491_4f6c_dd1d);
        let seeds = samples();
        // Bytes that make up most headers, so random input gets past them.
        const COMMON: [u8; 16] =
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x13, 0x17, 0x18, 0x30, 0x31, 0x80, 0x81, 0xa0];
        for round in 0..6000 {
            let mut data = if round % 2 == 0 {
                seeds[rng.index(seeds.len())].clone()
            } else {
                let mut bytes = rng.bytes(47);
                for byte in &mut bytes {
                    if rng.coin() {
                        *byte = COMMON[rng.index(COMMON.len())];
                    }
                }
                bytes
            };
            for _ in 0..rng.index(4) {
                mutate(&mut rng, &mut data);
            }
            check(&data);
        }
    }

    #[test]
    fn bit_string_segment_after_unused_bits_is_refused() {
        // X.690 8.6.4: only the last segment may leave bits unused. An
        // empty constructed segment after a seven-bit one is still a later
        // segment.
        let b = [0x23, 0x06, 0x03, 0x02, 0x01, 0xfe, 0x23, 0x00];
        assert_eq!(one(&b, Rules::Ber).unwrap().bit_string(), Err(Error::BitString));
        // Nested one level down too.
        let b = [0x23, 0x08, 0x23, 0x04, 0x03, 0x02, 0x01, 0xfe, 0x23, 0x00];
        assert_eq!(one(&b, Rules::Ber).unwrap().bit_string(), Err(Error::BitString));
        // Empty segments before the last are fine.
        let b = [0x23, 0x06, 0x23, 0x00, 0x03, 0x02, 0x01, 0xfe];
        let v = one(&b, Rules::Ber).unwrap().bit_string().unwrap();
        assert_eq!((v.bytes(), v.unused()), (&[0xfe][..], 1));
    }

    #[test]
    fn generalized_time_takes_a_leap_second() {
        // ISO 8601, which X.680 46 follows, writes a positive leap second
        // as second 60.
        for t in ["20161231235960Z", "20161231235960.5Z"] {
            assert_eq!(check_generalized_time(t.as_bytes(), Rules::Der), Ok(()), "{t}");
            let mut w = Writer::new();
            w.generalized_time(t);
            let b = w.finish().unwrap();
            assert_eq!(Reader::new(&b, Rules::Der).read_generalized_time().unwrap(), t);
        }
        assert_eq!(check_generalized_time(b"20170101085960+0900", Rules::Ber), Ok(()));
        assert_eq!(check_generalized_time(b"20161231235961Z", Rules::Ber), Err(Error::Time));
        assert_eq!(check_utc_time(b"161231235960Z", Rules::Der), Err(Error::Time));
    }

    #[test]
    fn ucs_strings_refuse_iso_2022_shifts() {
        // X.690 8.23.9: SHIFT OUT and SHIFT IN, single shifts, and ISO/IEC
        // 2022 escape sequences may not appear in a BMPString or a
        // UniversalString. TAB, LF, CR and other controls may.
        for bad in [
            &[0x00, 0x0e][..],
            &[0x00, 0x0f],
            &[0x00, 0x8e],
            &[0x00, 0x8f],
            &[0x00, 0x1b, 0x00, 0x28, 0x00, 0x42],
            &[0x00, 0x1b, 0x00, 0x6e],
            &[0x00, 0x1b],
        ] {
            assert_eq!(StringKind::Bmp.check(bad), Err(Error::Charset), "{bad:02x?}");
            let mut b = vec![0x1e, bad.len() as u8];
            b.extend_from_slice(bad);
            assert_eq!(Reader::new(&b, Rules::Der).read_text(), Err(Error::Charset));
        }
        assert_eq!(StringKind::Universal.check(&[0, 0, 0, 0x0e]), Err(Error::Charset));
        assert_eq!(StringKind::Universal.check(&[0, 0, 0, 0x1b, 0, 0, 0, 0x24]), Err(Error::Charset));
        let mut w = Writer::new();
        w.text(StringKind::Bmp, "\u{000e}");
        assert_eq!(w.finish(), Err(Error::Charset));
        let mut w = Writer::new();
        w.text(StringKind::Universal, "a\u{001b}(B");
        assert_eq!(w.finish(), Err(Error::Charset));
        // Allowed controls, and ESC before a CSI sequence or another ESC.
        for ok in ["a\tb\r\n", "\u{1b}[1m", "\u{1b}\u{1b}[", "\u{85}"] {
            for kind in [StringKind::Bmp, StringKind::Universal] {
                let b = kind.encode(ok).unwrap();
                assert_eq!(kind.decode(&b).unwrap(), ok);
            }
        }
        assert_eq!(StringKind::Bmp.encode("\u{1b}\u{1b}("), Err(Error::Charset));
    }

    #[test]
    fn large_bmp_text_round_trips() {
        // 400,000 characters of U+0800 are 800,000 bytes as a BMPString
        // but 1,200,000 bytes of UTF-8. What a reader gives, a writer
        // takes back.
        let s = "\u{800}".repeat(400_000);
        let mut w = Writer::new();
        w.text(StringKind::Bmp, &s);
        let b = w.finish().unwrap();
        let (kind, back) = Reader::new(&b, Rules::Der).read_text().unwrap();
        assert_eq!((kind, back.len()), (StringKind::Bmp, s.len()));
        assert!(StringKind::Bmp.encode(&back).unwrap() == b[5..]);
        // A UniversalString is measured by its own bytes too: 300,000
        // ASCII characters are 1,200,000 bytes.
        assert_eq!(StringKind::Universal.encode(&"a".repeat(300_000)), Err(Error::TooLong));
        assert_eq!(StringKind::Universal.encode(&"a".repeat(200_000)).map(|b| b.len()), Ok(800_000));
        assert_eq!(StringKind::Utf8.encode(&"a".repeat(MAX_INPUT + 1)), Err(Error::TooLong));
    }

    #[test]
    fn string_decode_is_bounded() {
        let big = vec![b'a'; MAX_INPUT + 1];
        assert_eq!(StringKind::Utf8.decode(&big), Err(Error::TooLong));
        assert_eq!(StringKind::Utf8.decode(&big[..MAX_INPUT]).map(|s| s.len()), Ok(MAX_INPUT));
    }

    #[test]
    fn integer_unsigned_checks_size_first() {
        let mut w = Writer::new();
        w.integer_unsigned(&vec![0x80; MAX_INPUT]);
        assert_eq!(w.error(), Some(Error::TooLong));
        assert!(w.is_empty());
        let mut w = Writer::new();
        w.integer_unsigned(&[0x80]);
        assert_eq!(w.finish().unwrap(), [0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn explicit_needs_exactly_one_element() {
        // X.690 8.14.3: the contents are the complete base encoding.
        let mut w = Writer::new();
        w.explicit(0, |_| {});
        assert_eq!(w.finish(), Err(Error::Implicit));
        let mut w = Writer::new();
        w.explicit(0, |w| {
            w.null();
            w.null();
        });
        assert_eq!(w.finish(), Err(Error::Implicit));
        assert_eq!(der(|w| w.explicit(0, |w| w.null())), [0xa0, 0x02, 0x05, 0x00]);
    }

    #[test]
    fn closures_cannot_corrupt_the_writer() {
        // Replacing the writer a closure is given cannot touch what was
        // written before, or the nesting count.
        let mut w = Writer::new();
        w.null();
        w.implicit(Tag::context(0), |inner| *inner = Writer::new());
        assert_eq!(w.finish(), Err(Error::Implicit));

        let mut w = Writer::new();
        w.null();
        w.sequence(|inner| *inner = Writer::new());
        w.null();
        assert_eq!(w.finish().unwrap(), [0x05, 0x00, 0x30, 0x00, 0x05, 0x00]);

        // A replacement holding elements of its own: they are kept, inside
        // the sequence, and the earlier NULL stays where it was.
        let mut w = Writer::new();
        w.null();
        w.sequence(|inner| {
            let mut other = Writer::new();
            other.sequence(|w| w.integer_i64(5));
            *inner = other;
        });
        let b = w.finish().unwrap();
        assert_eq!(b, [0x05, 0x00, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05]);
        check(&b);

        // A replacement made at depth 0 cannot carry nesting past the
        // limit into a deeper place.
        fn deep(w: &mut Writer, n: usize) {
            if n > 0 {
                w.sequence(|w| deep(w, n - 1));
            }
        }
        let mut w = Writer::new();
        w.sequence(|inner| {
            let mut other = Writer::new();
            deep(&mut other, MAX_DEPTH);
            assert_eq!(other.error(), None);
            *inner = other;
        });
        assert_eq!(w.finish(), Err(Error::TooDeep));

        // Taking the writer out with `mem::take` works the same way.
        let mut w = Writer::new();
        w.set(|inner| {
            inner.integer_i64(1);
            let taken = std::mem::take(inner);
            assert_eq!(taken.len(), 3);
        });
        assert_eq!(w.finish().unwrap(), [0x31, 0x00]);

        // A closure's writer has only the room its parent has left.
        let mut w = Writer::new();
        w.octet_string(&vec![0; MAX_INPUT - 20]);
        w.sequence(|inner| {
            inner.octet_string(&[0; 30]);
            assert_eq!(inner.error(), Some(Error::TooLong));
        });
        assert_eq!(w.finish(), Err(Error::TooLong));
    }

    #[test]
    fn decoder_holds_a_bounded_number_of_bytes() {
        // One large push is taken only up to MAX_INPUT bytes.
        let stream = [0x05, 0x00].repeat(MAX_INPUT);
        let mut d = Stream::new(Elements::new(Rules::Der));
        assert_eq!(d.push(&stream), MAX_INPUT);
        assert_eq!(d.buffered(), MAX_INPUT);
        // Pushing again without taking anything out takes nothing.
        assert_eq!(d.push(&stream[MAX_INPUT..]), 0);
        assert_eq!(d.buffered(), MAX_INPUT);
        assert!(d.into_parts().0.allocated() <= 2 * MAX_INPUT);
        // A loop of pushing and taking out gets every element.
        let mut d = Stream::new(Elements::new(Rules::Der));
        let mut rest = &stream[..];
        let mut count = 0;
        while !rest.is_empty() {
            let n = d.push(rest);
            rest = &rest[n..];
            while let Some(e) = d.next() {
                assert_eq!(e.unwrap(), [0x05, 0x00]);
                count += 1;
            }
            assert!(d.buffered() <= MAX_INPUT);
        }
        assert_eq!(count, MAX_INPUT);
        assert!(d.into_parts().0.allocated() <= 2 * MAX_INPUT);
        // An element that never ends gives an error at the limit instead
        // of stalling the loop.
        let mut d = Stream::new(Elements::new(Rules::Ber));
        let mut endless = vec![0x30, 0x80];
        endless.resize(MAX_INPUT + 100, 0x05);
        assert_eq!(d.push(&[0x24, 0x80]), 2);
        let mut rest = &[0x04, 0x01, 0x00].repeat(MAX_INPUT)[..];
        let result = loop {
            let n = d.push(rest);
            rest = &rest[n..];
            if let Some(r) = d.next() {
                break r;
            }
            assert!(n > 0);
        };
        assert_eq!(result, Err(Fail::Protocol(Error::TooLong)));
        // After an error every byte is taken and dropped.
        let held = d.buffered();
        assert_eq!(d.push(&endless), endless.len());
        assert_eq!(d.buffered(), held);
        assert_eq!(d.next(), None);
        assert!(d.into_parts().0.allocated() <= 2 * MAX_INPUT);
    }

    #[test]
    fn codec_wire_is_exact_and_transactional() {
        use fictionet::stdlib::codec::Wire;
        use fictionet::stdlib::test_support::contract;
        for bytes in [&[5, 0][..], &[0x30, 0x80, 5, 0, 0, 0], &[4], &[5, 0, 5, 0]] {
            contract::check_wire::<Frame>(bytes);
            contract::check_wire_value(&Frame(bytes.to_vec()));
        }
        assert_eq!(<Frame as Wire>::parse(&[5, 0, 5, 0]), Err(Error::Trailing));
        let mut out = vec![42];
        assert_eq!(Frame(vec![4]).write(&mut out), Err(Error::Truncated));
        assert_eq!(out, [42]);
        let mut too_long = vec![4, 0x83, 0x10, 0, 0];
        too_long.resize(MAX_INPUT + 1, 0);
        assert_eq!(<Frame as Wire>::parse(&too_long), Err(Error::TooLong));
    }

    #[test]
    fn codec_indefinite_scan_survives_compaction() {
        use fictionet::stdlib::codec::Stream;
        use fictionet::stdlib::test_support::contract;
        let mut w = Writer::new();
        w.octet_string(&[1; 256]);
        let first = w.finish().unwrap();
        let mut bytes = first.clone();
        bytes.extend_from_slice(&[0x30, 0x80, 5, 0]);
        let mut stream = Stream::new(Elements::new(Rules::Ber));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(first)));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().resume.unwrap().pos, 4);
        // The consumed prefix is larger than the suffix, forcing compaction.
        assert_eq!(stream.push(&[0x30, 0x80, 5, 0]), 4);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().resume.unwrap().pos, 8);
        assert_eq!(stream.push(&[0, 0, 0, 0, 5, 0]), 6);
        assert_eq!(stream.next(), Some(Ok(vec![0x30, 0x80, 5, 0, 0x30, 0x80, 5, 0, 0, 0, 0, 0])));
        assert_eq!(stream.next(), Some(Ok(vec![5, 0])));
        assert_eq!(stream.decoder().rules(), Rules::Ber);
        assert_eq!(stream.decoder().held(), 0);
        bytes.extend_from_slice(&[0x30, 0x80, 5, 0, 0, 0, 0, 0, 5, 0]);
        contract::check_decode_with_alloc_limit(|| Elements::new(Rules::Ber), &bytes, 2 * MAX_INPUT);
        contract::check_decode_with_alloc_limit(|| Elements::new(Rules::Der), &bytes, 2 * MAX_INPUT);
    }
}
