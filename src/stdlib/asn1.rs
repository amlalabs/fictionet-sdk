//! ASN.1 BER and DER: reading and writing tags, lengths and values, with no
//! I/O.
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
//! Nothing here reads a socket. A world that plays an LDAP server feeds the
//! bytes it reads from a connection to a [`Decoder`], gets one message's
//! bytes at a time, and walks each one with a [`Reader`]. A world that
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

/// The longest element, header and contents together, a reader accepts and
/// a writer writes. A [`Decoder`] never holds much more than this.
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
    /// [`Writer::implicit`] was given a closure that did not write exactly
    /// one element.
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
            Error::Unexpected { expected, found } => write!(f, "expected {expected}, found {found}"),
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
            Error::Implicit => f.write_str("implicit tag needs exactly one element"),
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

#[allow(missing_docs)] // each constant is the universal type it names
impl Tag {
    pub const BOOLEAN: Tag = Tag::universal(1);
    pub const INTEGER: Tag = Tag::universal(2);
    pub const BIT_STRING: Tag = Tag::universal(3);
    pub const OCTET_STRING: Tag = Tag::universal(4);
    pub const NULL: Tag = Tag::universal(5);
    pub const OID: Tag = Tag::universal(6);
    pub const ENUMERATED: Tag = Tag::universal(10);
    pub const UTF8_STRING: Tag = Tag::universal(12);
    pub const SEQUENCE: Tag = Tag::universal(16).as_constructed();
    pub const SET: Tag = Tag::universal(17).as_constructed();
    pub const NUMERIC_STRING: Tag = Tag::universal(18);
    pub const PRINTABLE_STRING: Tag = Tag::universal(19);
    pub const TELETEX_STRING: Tag = Tag::universal(20);
    pub const VIDEOTEX_STRING: Tag = Tag::universal(21);
    pub const IA5_STRING: Tag = Tag::universal(22);
    pub const UTC_TIME: Tag = Tag::universal(23);
    pub const GENERALIZED_TIME: Tag = Tag::universal(24);
    pub const GRAPHIC_STRING: Tag = Tag::universal(25);
    pub const VISIBLE_STRING: Tag = Tag::universal(26);
    pub const GENERAL_STRING: Tag = Tag::universal(27);
    pub const UNIVERSAL_STRING: Tag = Tag::universal(28);
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

    /// The identifier octets.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
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

impl Header {
    /// Reads the header at the start of `b` under `rules`. It returns
    /// [`Error::Truncated`] if `b` ends inside it.
    pub fn parse(b: &[u8], rules: Rules) -> Result<Header, Error> {
        read_header(b, 0, rules)
    }
}

/// Appends a definite length in its shortest form. Lengths above
/// [`MAX_INPUT`] are never written, so this takes at most 4 bytes.
fn encode_length(n: usize, out: &mut Vec<u8>) {
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

/// Splits a byte stream of ASN.1 elements, such as an LDAP connection,
/// into one element at a time. Feed it the bytes a connection reads, in
/// order, and take elements out until it has none.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start in `buf`. Taken bytes are
    /// dropped only once they are at least half of `buf`, so taking many
    /// small elements does not copy the rest each time.
    start: usize,
    rules: Rules,
    failed: Option<Error>,
    /// How far the scan of an unfinished indefinite length has come, so
    /// each call goes on from there instead of starting over.
    resume: Option<Scan>,
}

impl Decoder {
    /// A decoder holding no bytes, reading under `rules`.
    pub fn new(rules: Rules) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, rules, failed: None, resume: None }
    }

    /// Adds bytes read from the connection. After an error the stream
    /// cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.compact();
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole element's bytes, if one has come. Read them with
    /// [`Reader::new`]. It returns `None` when it needs more bytes, and
    /// keeps returning the same error once the stream has broken. A decoder
    /// holds at most [`MAX_INPUT`] bytes beyond what has been taken out,
    /// plus what one `feed` added. Taken bytes are freed on a later `feed`,
    /// so its buffer is never much more than twice what it holds.
    pub fn next_element(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match self.frame() {
            Ok(Some(n)) => {
                self.resume = None;
                let end = self.start + n;
                let element = self.buf[self.start..end].to_vec();
                self.start = end;
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                Some(Ok(element))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.resume = None;
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// What [`element_len`] gives for the held bytes, with an unfinished
    /// indefinite length picked up where the last call left it.
    fn frame(&mut self) -> Result<Option<usize>, Error> {
        let buf = &self.buf[self.start..];
        let at = match self.resume {
            Some(at) => at,
            None => match read_header(buf, 0, self.rules) {
                // An indefinite length is scanned here, so the scan can be
                // picked up again. Everything else is as `element_len` does.
                Ok(h) if h.length == Length::Indefinite && !is_eoc_tag(h.tag) => Scan { pos: h.len, open: 1 },
                _ => return element_len(buf, self.rules),
            },
        };
        match scan(buf, self.rules, 0, at)? {
            Ok((_, end)) => Ok(Some(end)),
            Err(at) => {
                self.resume = Some(at);
                Ok(None)
            }
        }
    }

    /// How many bytes are held, waiting to be taken out.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The rules the decoder holds the stream to.
    pub fn rules(&self) -> Rules {
        self.rules
    }

    /// Drops the bytes already taken out, once they are at least half of
    /// the buffer. Each byte is moved a bounded number of times on average.
    fn compact(&mut self) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
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
            if child.tag.constructed {
                child.append_bit_segments(out, unused)?;
            } else {
                // Only the last segment may leave bits unused (8.6.4.2).
                if *unused != 0 {
                    return Err(Error::BitString);
                }
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
        let [first, second, rest @ ..] = arcs else { return Err(Error::Oid) };
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
                    && b.chunks_exact(4).all(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).is_some())
            }
            StringKind::Bmp => {
                b.len().is_multiple_of(2)
                    && b.chunks_exact(2).all(|c| !(0xd800..=0xdfff).contains(&u16::from_be_bytes([c[0], c[1]])))
            }
            StringKind::Teletex | StringKind::Videotex | StringKind::Graphic | StringKind::General => true,
        };
        if ok { Ok(()) } else { Err(Error::Charset) }
    }

    /// Decodes `b` to text, after checking it.
    pub fn decode(self, b: &[u8]) -> Result<String, Error> {
        if !self.is_decoded() {
            return Err(Error::Charset);
        }
        self.check(b)?;
        Ok(match self {
            StringKind::Universal => {
                b.chunks_exact(4).filter_map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))).collect()
            }
            StringKind::Bmp => {
                b.chunks_exact(2).filter_map(|c| char::from_u32(u32::from(u16::from_be_bytes([c[0], c[1]])))).collect()
            }
            _ => String::from_utf8_lossy(b).into_owned(),
        })
    }

    /// Encodes `s` as the type's bytes, if every character is allowed.
    pub fn encode(self, s: &str) -> Result<Vec<u8>, Error> {
        if !self.is_decoded() {
            return Err(Error::Charset);
        }
        if s.len() > MAX_INPUT {
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

/// Checks a calendar date and a time of day.
fn check_date(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Result<(), Error> {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(Error::Time),
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
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
    check_date(year, month, day, hour, minute, second)?;
    t.zone(true, rules)
}

/// Checks GeneralizedTime text (X.680 46): `YYYYMMDDhh[mm[ss]]`, an
/// optional fraction after `.` or `,`, and `Z`, an offset or nothing. DER
/// needs the minutes, the seconds and `Z`, and a fraction, if any, after
/// `.` with no trailing zero (X.690 11.7).
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
    check_date(year, month, day, hour, minute, second)?;
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
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
    depth: usize,
    error: Option<Error>,
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
        if head.len() + contents.len() > MAX_INPUT - self.out.len().min(MAX_INPUT) {
            return self.fail(Error::TooLong);
        }
        self.out.extend_from_slice(&head);
        self.out.extend_from_slice(contents);
    }

    fn nest(&mut self, tag: Tag, order: Order, f: impl FnOnce(&mut Writer)) {
        if self.error.is_some() {
            return;
        }
        if self.depth >= MAX_DEPTH {
            return self.fail(Error::TooDeep);
        }
        let start = self.out.len();
        self.depth += 1;
        f(self);
        self.depth -= 1;
        if self.error.is_some() {
            return;
        }
        let contents = self.out.split_off(start);
        let contents = match order {
            Order::AsWritten => contents,
            Order::Tags | Order::Encodings => match sorted(&contents, order) {
                Ok(c) => c,
                Err(e) => return self.fail(e),
            },
        };
        self.put(tag.as_constructed(), &contents);
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
        self.nest(tag, Order::AsWritten, f);
    }

    /// Writes an explicitly tagged `[number]` around what `f` writes.
    pub fn explicit(&mut self, number: u32, f: impl FnOnce(&mut Writer)) {
        self.nest(Tag::context(number), Order::AsWritten, f);
    }

    /// Writes a SEQUENCE (or SEQUENCE OF) whose children `f` writes, in
    /// order.
    pub fn sequence(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest(Tag::SEQUENCE, Order::AsWritten, f);
    }

    /// Writes a SET whose children `f` writes. They are put in tag order,
    /// as DER requires, and two with the same tag are an error.
    pub fn set(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest(Tag::SET, Order::Tags, f);
    }

    /// Writes a SET OF whose children `f` writes. They are put in the order
    /// of their encodings, as DER requires.
    pub fn set_of(&mut self, f: impl FnOnce(&mut Writer)) {
        self.nest(Tag::SET, Order::Encodings, f);
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
            Ok(()) if der.len() > MAX_INPUT - self.out.len().min(MAX_INPUT) => self.fail(Error::TooLong),
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
        let start = self.out.len();
        f(self);
        if self.error.is_some() {
            return;
        }
        let written = self.out.split_off(start);
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
fn minimal_twos(b: &[u8]) -> &[u8] {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `e` again with a [`Writer`], if every value in it is one the
    /// writer has a method for. Read under DER, the copy must be the same
    /// bytes.
    fn copy(e: Element<'_>, w: &mut Writer) -> Option<()> {
        let t = e.tag();
        let mut ok = Some(());
        if t.class != Class::Universal {
            if t.constructed {
                let kids = children(e)?;
                w.constructed(t, |w| ok = copy_all(kids, w));
                return ok;
            }
            w.primitive(t, e.contents());
            return Some(());
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
                let distinct = {
                    let mut tags: Vec<_> = kids.iter().map(|k| (k.tag.class, k.tag.number)).collect();
                    tags.sort();
                    tags.windows(2).all(|w| w[0] != w[1])
                };
                // Under DER, a set in tag order is one; under BER any set
                // with distinct tags is put in tag order.
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

    fn children(e: Element<'_>) -> Option<Vec<Element<'_>>> {
        e.reader().ok()?.collect::<Result<Vec<_>, _>>().ok()
    }

    fn copy_all(kids: Vec<Element<'_>>, w: &mut Writer) -> Option<()> {
        kids.into_iter().try_for_each(|k| copy(k, w))
    }

    /// Calls every value reader on `e` and its children, for panics.
    fn walk(e: Element<'_>) {
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
            for i in 0..b.len().min(64) {
                assert!(b.bit(i).is_some());
            }
        }
        for kind in ALL_KINDS {
            let _ = e.string_bytes(kind);
            if let Ok(s) = e.text(kind) {
                assert_eq!(kind.encode(&s).ok().as_deref(), e.string_bytes(kind).ok().as_deref());
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

    /// What the fuzz target checks, on one input.
    fn check(data: &[u8]) {
        for rules in [Rules::Ber, Rules::Der] {
            // The stream, split two ways: all at once, and a byte at a time.
            let mut whole = Decoder::new(rules);
            whole.feed(data);
            let mut all = Vec::new();
            let mut end = None;
            while let Some(r) = whole.next_element() {
                match r {
                    Ok(e) => all.push(e),
                    Err(e) => {
                        end = Some(e);
                        break;
                    }
                }
            }
            let mut bytewise = Decoder::new(rules);
            let mut again = Vec::new();
            let mut end_again = None;
            'outer: for b in data {
                bytewise.feed(std::slice::from_ref(b));
                while let Some(r) = bytewise.next_element() {
                    match r {
                        Ok(e) => again.push(e),
                        Err(e) => {
                            end_again = Some(e);
                            break 'outer;
                        }
                    }
                }
            }
            assert_eq!(all, again);
            assert_eq!(end, end_again);
        }
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
        let mut x: u64 = 1;
        for _ in 0..2000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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
        assert_eq!(t.to_bytes(), [0x7f, 0x81, 0x49]);
        assert_eq!(Tag::parse(&[0x7f, 0x81, 0x49]), Ok((t, 3)));
        assert_eq!(Tag::context(30).to_bytes(), [0x9e]);
        assert_eq!(Tag::context(31).to_bytes(), [0x9f, 0x1f]);
        assert_eq!(Tag::private(u32::MAX).to_bytes(), [0xdf, 0x8f, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(Tag::parse(&Tag::private(u32::MAX).to_bytes()), Ok((Tag::private(u32::MAX), 6)));
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
            "20000101000060Z",
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
        let mut d = Decoder::new(Rules::Ber);
        let mut result = None;
        for chunk in endless.chunks(1 << 16) {
            d.feed(chunk);
            assert!(d.buffered() <= MAX_INPUT + (1 << 16));
            if let Some(r) = d.next_element() {
                result = Some(r);
                break;
            }
        }
        assert_eq!(result, Some(Err(Error::TooLong)));
        assert_eq!(d.buffered(), 0);
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
        let mut d = Decoder::new(Rules::Ber);
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(e) = d.next_element() {
                got.push(e.unwrap());
            }
        }
        assert_eq!(got, [a.clone(), b.clone(), a.clone()]);
        assert_eq!(d.buffered(), 0);
        // DER refuses the indefinite one, and the stream stays broken.
        let mut d = Decoder::new(Rules::Der);
        d.feed(&stream);
        assert_eq!(d.next_element(), Some(Ok(a.clone())));
        assert_eq!(d.next_element(), Some(Err(Error::Indefinite)));
        d.feed(&a);
        assert_eq!(d.next_element(), Some(Err(Error::Indefinite)));
        assert_eq!(d.buffered(), 0);
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
        let mut d = Decoder::new(Rules::Ber);
        let mut got = Vec::new();
        for byte in &b {
            d.feed(std::slice::from_ref(byte));
            while let Some(e) = d.next_element() {
                got.push(e.unwrap());
            }
        }
        assert_eq!(got, [b]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_elements_in_linear_time() {
        // One feed of half a million NULLs. Taking each one out must not
        // copy the bytes still waiting behind it.
        let n = MAX_INPUT / 2;
        let stream = [0x05, 0x00].repeat(n);
        let mut d = Decoder::new(Rules::Der);
        d.feed(&stream);
        let mut count = 0;
        while let Some(e) = d.next_element() {
            assert_eq!(e.unwrap(), [0x05, 0x00]);
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        // Interleaved with feeds, partial elements still join up.
        let a = [0x30, 0x03, 0x02, 0x01, 0x01];
        let b = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let stream = [&a[..], &b[..]].concat().repeat(1000);
        let mut d = Decoder::new(Rules::Ber);
        let mut got = Vec::new();
        for chunk in stream.chunks(7) {
            d.feed(chunk);
            while let Some(e) = d.next_element() {
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
        let mut d = Decoder::new(Rules::Der);
        assert_eq!(d.rules(), Rules::Der);
        d.feed(&t[..1]);
        assert_eq!((d.next_element(), d.buffered()), (None, 1));
        assert_eq!(BitString::new(vec![0; MAX_INPUT + 1], 0), Err(Error::TooLong));
    }

    #[test]
    fn lcg_fuzz() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u32
        };
        let seeds = samples();
        // Bytes that make up most headers, so random input gets past them.
        const COMMON: [u8; 16] =
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x13, 0x17, 0x18, 0x30, 0x31, 0x80, 0x81, 0xa0];
        for round in 0..6000 {
            let mut data = if round % 2 == 0 {
                seeds[next() as usize % seeds.len()].clone()
            } else {
                let len = next() as usize % 48;
                (0..len)
                    .map(|_| if next() % 2 == 0 { COMMON[next() as usize % COMMON.len()] } else { next() as u8 })
                    .collect()
            };
            for _ in 0..next() % 4 {
                if data.is_empty() {
                    break;
                }
                let i = next() as usize % data.len();
                match next() % 4 {
                    0 => data[i] = next() as u8,
                    1 => data[i] ^= 1 << (next() % 8),
                    2 => data.truncate(i),
                    _ => data.insert(i, COMMON[next() as usize % COMMON.len()]),
                }
            }
            check(&data);
        }
    }
}
