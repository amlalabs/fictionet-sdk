//! QPACK, the header compression of HTTP/3: reading and writing field
//! sections and the encoder and decoder streams, with no I/O.
//!
//! HTTP/3 does not send header fields as text. Each request and response
//! carries an encoded field section: a short prefix, then one field line
//! per field. A field line can name an entry in a fixed table of 99 common
//! fields (the static table), an entry in a table the two sides build as
//! they go (the dynamic table), or spell the field out, often in Huffman
//! code. The side that encodes fields fills the dynamic table with
//! instructions on its encoder stream. The side that decodes them answers
//! on its decoder stream, so the encoder knows which entries it may use and
//! which it may evict. This module follows RFC 9204, and RFC 7541 for the
//! integer format and the Huffman code.
//!
//! Nothing here reads a socket. A world that plays an HTTP/3 server gives
//! a [`Decoder`] the bytes of the peer's encoder stream and each request's
//! field section, and writes what [`Decoder::take_decoder_stream`] returns
//! to its own decoder stream. To answer, it encodes the response's fields
//! with an [`Encoder`], writes [`Encoder::take_encoder_stream`] to its
//! encoder stream, and reads the peer's decoder stream into
//! [`Encoder::feed_decoder_stream`]. Which entries to insert is up to world
//! code. The encoder only refers to entries the peer has acknowledged, so
//! its field sections never block.
//!
//! Every reader checks lengths, indexes and sizes, because the agent can
//! send any bytes it likes. Integers stop at [`MAX_INTEGER`], strings at
//! [`MAX_STRING`], tables at [`MAX_TABLE_CAPACITY`] and field sections at
//! [`MAX_FIELD_SECTION_SIZE`]. An error from [`Decoder::feed_encoder_stream`]
//! is the connection error [`error_code::ENCODER_STREAM_ERROR`], one from
//! [`Encoder::feed_decoder_stream`] is
//! [`error_code::DECODER_STREAM_ERROR`], and one from decoding a field
//! section is [`error_code::DECOMPRESSION_FAILED`].
//!
//! ```
//! use fictionet::stdlib::qpack::{Decoder, Encoder, Field, Section};
//!
//! // RFC 9204 Appendix B.1: ":path: /index.html" as a literal with a
//! // reference to static entry 1, and no dynamic table.
//! let mut decoder = Decoder::new(4096, 16, 16 << 10);
//! let mut section = vec![0x00, 0x00, 0x51, 0x0b];
//! section.extend_from_slice(b"/index.html");
//! let Section::Fields(fields) = decoder.decode_section(0, &section).unwrap() else { panic!() };
//! assert_eq!(fields, [Field::new(":path", "/index.html")]);
//!
//! // An encoder inserts a field, the decoder reads the insert and
//! // acknowledges it, and the encoder then refers to the entry.
//! let mut encoder = Encoder::new(4096, 16 << 10);
//! encoder.set_capacity(4096).unwrap();
//! encoder.insert(b"x-trace", b"abc").unwrap();
//! decoder.feed_encoder_stream(&encoder.take_encoder_stream()).unwrap();
//! encoder.feed_decoder_stream(&decoder.take_decoder_stream()).unwrap();
//! let fields = vec![Field::new(":method", "GET"), Field::new("x-trace", "abc")];
//! let bytes = encoder.encode_section(4, &fields).unwrap();
//! // Prefix, then static entry 17 and dynamic entry 0: four bytes.
//! assert_eq!(bytes.len(), 4);
//! let Section::Fields(back) = decoder.decode_section(4, &bytes).unwrap() else { panic!() };
//! assert_eq!(back, fields);
//! ```

use std::collections::VecDeque;

/// The largest integer a reader accepts, 2^62 - 1, the largest QUIC stream
/// ID. Writers lower larger values to it.
pub const MAX_INTEGER: u64 = (1 << 62) - 1;
/// The longest string, before or after Huffman decoding. Writers cut
/// longer strings to this length.
pub const MAX_STRING: usize = 64 << 10;
/// The largest dynamic table capacity. A larger maximum given to
/// [`Decoder::new`] or [`Encoder::new`] is lowered to it, so a world
/// should not advertise more.
pub const MAX_TABLE_CAPACITY: u64 = 64 << 10;
/// What each entry adds to the table's size, besides its name and value.
pub const ENTRY_OVERHEAD: u64 = 32;
/// The largest field section size, counted as HTTP/3 counts it: each
/// field's name and value plus 32. A larger limit given to a decoder or
/// encoder is lowered to it.
pub const MAX_FIELD_SECTION_SIZE: u64 = 256 << 10;
/// The most bytes an encoded field section may have. Writers stay below it
/// for any section within [`MAX_FIELD_SECTION_SIZE`].
pub const MAX_SECTION_BYTES: usize = MAX_FIELD_SECTION_SIZE as usize + 64;
/// The most fields one field section may hold.
pub const MAX_FIELDS: usize = 4096;
/// The most streams a decoder lets wait for inserts. A larger number given
/// to [`Decoder::new`] is lowered to it.
pub const MAX_BLOCKED_STREAMS: usize = 256;
/// The most bytes of field sections a decoder holds for blocked streams.
pub const MAX_BLOCKED_BYTES: usize = 1 << 20;
/// The most field sections a decoder holds for blocked streams. One
/// stream may have several, such as a header and a trailer section.
pub const MAX_BLOCKED_SECTIONS: usize = 4 * MAX_BLOCKED_STREAMS;
/// The longest encoder stream instruction: a byte, two integers and two
/// strings. A decoder never holds more bytes of an unfinished one.
pub const MAX_INSTRUCTION: usize = 2 * (10 + MAX_STRING);
/// The most field sections an encoder tracks while it waits for their
/// acknowledgments. Past it, the encoder stops using the dynamic table.
pub const MAX_OUTSTANDING: usize = 1024;

/// The HTTP/3 error codes for QPACK failures (RFC 9204 section 6).
pub mod error_code {
    /// A field section could not be decoded.
    pub const DECOMPRESSION_FAILED: u64 = 0x200;
    /// An encoder stream instruction could not be read or applied.
    pub const ENCODER_STREAM_ERROR: u64 = 0x201;
    /// A decoder stream instruction could not be read or applied.
    pub const DECODER_STREAM_ERROR: u64 = 0x202;
}

/// The static table (RFC 9204 Appendix A): name and value by index.
pub const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// The static entry at `index`, if there is one.
pub fn static_entry(index: u64) -> Option<(&'static str, &'static str)> {
    usize::try_from(index).ok().and_then(|i| STATIC_TABLE.get(i)).copied()
}

/// The index of the static entry with this name and value.
pub fn static_find(name: &[u8], value: &[u8]) -> Option<u64> {
    STATIC_TABLE.iter().position(|(n, v)| n.as_bytes() == name && v.as_bytes() == value).map(|i| i as u64)
}

/// The index of the first static entry with this name.
pub fn static_find_name(name: &[u8]) -> Option<u64> {
    STATIC_TABLE.iter().position(|(n, _)| n.as_bytes() == name).map(|i| i as u64)
}

/// Why bytes could not be read, or an instruction could not be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A field section ended in the middle of its prefix or a field line.
    Truncated,
    /// An integer was above [`MAX_INTEGER`], or had too many bytes.
    IntegerOverflow,
    /// A string was longer than [`MAX_STRING`].
    StringTooLong,
    /// A Huffman-coded string had bad padding or held the end-of-string
    /// code.
    Huffman,
    /// A reference to a static entry that does not exist.
    StaticIndex(u64),
    /// A reference to a dynamic entry that does not exist, was evicted, or
    /// is at or past the section's Required Insert Count. The number is
    /// the index as sent.
    DynamicIndex(u64),
    /// The encoded Required Insert Count could not be valid, or was larger
    /// than the section's references need.
    InsertCount,
    /// The section's Base came out below zero.
    Base,
    /// A table capacity above the maximum.
    Capacity(u64),
    /// An entry larger than the table's capacity.
    EntryTooLarge,
    /// An Insert Count Increment of 0.
    ZeroIncrement,
    /// An Insert Count Increment past the number of entries inserted.
    Increment,
    /// A Section Acknowledgment for a stream with no section waiting.
    UnknownStream(u64),
    /// A section would block more streams than allowed, or would hold
    /// more than [`MAX_BLOCKED_SECTIONS`] or [`MAX_BLOCKED_BYTES`].
    TooManyBlocked,
    /// A field section larger than the limit on field section size.
    FieldSectionTooLarge,
    /// A field section with more than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// An encoder change would evict an entry that is not evictable: one a
    /// field section not yet acknowledged refers to, or one whose insert
    /// the decoder has not acknowledged.
    Referenced,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("field section cut short"),
            Error::IntegerOverflow => f.write_str("integer too large"),
            Error::StringTooLong => f.write_str("string too long"),
            Error::Huffman => f.write_str("bad Huffman code"),
            Error::StaticIndex(i) => write!(f, "no static entry {i}"),
            Error::DynamicIndex(i) => write!(f, "no dynamic entry at index {i}"),
            Error::InsertCount => f.write_str("bad Required Insert Count"),
            Error::Base => f.write_str("negative Base"),
            Error::Capacity(c) => write!(f, "table capacity {c} above the maximum"),
            Error::EntryTooLarge => f.write_str("entry larger than the table capacity"),
            Error::ZeroIncrement => f.write_str("Insert Count Increment of 0"),
            Error::Increment => f.write_str("Insert Count Increment past the inserts"),
            Error::UnknownStream(s) => write!(f, "no section waiting on stream {s}"),
            Error::TooManyBlocked => f.write_str("too many blocked streams"),
            Error::FieldSectionTooLarge => f.write_str("field section too large"),
            Error::TooManyFields => f.write_str("too many fields"),
            Error::Referenced => f.write_str("would evict an entry still in use"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------
// Integers and strings (RFC 7541 sections 5.1 and 5.2).

/// Why a reader stopped: it needs more bytes, or the bytes are bad.
enum Stop {
    More,
    Bad(Error),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Bad(e)
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Result<u8, Stop> {
        self.b.get(self.i).copied().ok_or(Stop::More)
    }

    fn byte(&mut self) -> Result<u8, Stop> {
        let b = self.peek()?;
        self.i += 1;
        Ok(b)
    }

    /// An integer with a `prefix`-bit prefix, 1 to 8 bits.
    fn int(&mut self, prefix: u8) -> Result<u64, Stop> {
        let mask = ((1u16 << prefix) - 1) as u8;
        let mut v = u64::from(self.byte()? & mask);
        if v < u64::from(mask) {
            return Ok(v);
        }
        let mut shift = 0u32;
        loop {
            if shift > 56 {
                return Err(Error::IntegerOverflow.into());
            }
            let b = self.byte()?;
            v = v.checked_add(u64::from(b & 0x7f) << shift).ok_or(Error::IntegerOverflow)?;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        if v > MAX_INTEGER {
            return Err(Error::IntegerOverflow.into());
        }
        Ok(v)
    }

    /// A string whose Huffman flag is the bit just above a `prefix`-bit
    /// length, still encoded.
    fn raw_string(&mut self, prefix: u8) -> Result<RawString<'a>, Stop> {
        let huffman = self.peek()? & (1 << prefix) != 0;
        let len = self.int(prefix)?;
        if len > MAX_STRING as u64 {
            return Err(Error::StringTooLong.into());
        }
        let len = len as usize;
        let end = self.i.checked_add(len).ok_or(Stop::More)?;
        let bytes = self.b.get(self.i..end).ok_or(Stop::More)?;
        self.i = end;
        Ok(RawString { huffman, bytes })
    }
}

/// A string as sent. Readers decode it only once the whole instruction or
/// field line is there, so bytes fed one at a time cost linear time.
struct RawString<'a> {
    huffman: bool,
    bytes: &'a [u8],
}

impl RawString<'_> {
    fn decode(&self) -> Result<Vec<u8>, Error> {
        if self.huffman { huffman_decode(self.bytes) } else { Ok(self.bytes.to_vec()) }
    }
}

/// Appends `v` as an integer with a `prefix`-bit prefix (1 to 8 bits),
/// the bits above it set to `flags`. Bits of `flags` inside the prefix are
/// ignored. Values above [`MAX_INTEGER`] are lowered to it.
pub fn encode_integer(out: &mut Vec<u8>, prefix: u8, flags: u8, v: u64) {
    let prefix = prefix.clamp(1, 8);
    let v = v.min(MAX_INTEGER);
    let max = (1u64 << prefix) - 1;
    let flags = flags & !(max as u8);
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = v - max;
    while rest >= 0x80 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Reads an integer with a `prefix`-bit prefix (1 to 8 bits) from the
/// start of `b`. It returns `Ok(None)` if `b` holds only part of one, and
/// otherwise the value and how many bytes it took.
pub fn decode_integer(b: &[u8], prefix: u8) -> Result<Option<(u64, usize)>, Error> {
    let mut c = Cursor { b, i: 0 };
    match c.int(prefix.clamp(1, 8)) {
        Ok(v) => Ok(Some((v, c.i))),
        Err(Stop::More) => Ok(None),
        Err(Stop::Bad(e)) => Err(e),
    }
}

/// Appends `s` as a string with a `prefix`-bit length, Huffman-coded if
/// that is shorter. Strings longer than [`MAX_STRING`] are cut.
fn put_string(out: &mut Vec<u8>, prefix: u8, flags: u8, s: &[u8]) {
    let s = &s[..s.len().min(MAX_STRING)];
    let h = huffman_len(s);
    if h < s.len() {
        encode_integer(out, prefix, flags | (1 << prefix), h as u64);
        huffman_encode_into(out, s);
    } else {
        encode_integer(out, prefix, flags, s.len() as u64);
        out.extend_from_slice(s);
    }
}

// ---------------------------------------------------------------------
// Huffman code (RFC 7541 Appendix B).

/// The length in bits of each symbol's Huffman code, 256 being the
/// end-of-string code. The code is canonical, so the lengths fix the codes.
#[rustfmt::skip]
const HUFFMAN_LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12,
    10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6,
    5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22,
    22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20,
    22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28,
    27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28,
    27, 27, 27, 27, 27, 26, 30,
];

/// The canonical code, worked out from the lengths at compile time.
struct Huffman {
    /// Each symbol's code, in its low bits.
    codes: [u32; 257],
    /// For each length: the first code of that length, how many codes
    /// have it, and where its symbols start in `symbols`.
    first: [u32; 31],
    count: [u32; 31],
    start: [u16; 31],
    /// The symbols, shortest code first.
    symbols: [u16; 257],
}

const HUFFMAN: Huffman = build_huffman();

const fn build_huffman() -> Huffman {
    let mut h = Huffman { codes: [0; 257], first: [0; 31], count: [0; 31], start: [0; 31], symbols: [0; 257] };
    let mut code = 0u32;
    let mut index = 0usize;
    let mut len = 1usize;
    while len <= 30 {
        h.first[len] = code;
        h.start[len] = index as u16;
        let mut s = 0usize;
        while s < 257 {
            if HUFFMAN_LENGTHS[s] as usize == len {
                h.codes[s] = code;
                h.symbols[index] = s as u16;
                h.count[len] += 1;
                index += 1;
                code += 1;
            }
            s += 1;
        }
        code <<= 1;
        len += 1;
    }
    h
}

/// How many bytes `s` takes Huffman-coded.
pub fn huffman_len(s: &[u8]) -> usize {
    let bits: usize = s.iter().map(|&b| usize::from(HUFFMAN_LENGTHS[usize::from(b)])).sum();
    bits.div_ceil(8)
}

/// `s` Huffman-coded, padded with 1 bits.
pub fn huffman_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(huffman_len(s));
    huffman_encode_into(&mut out, s);
    out
}

fn huffman_encode_into(out: &mut Vec<u8>, s: &[u8]) {
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in s {
        let len = u32::from(HUFFMAN_LENGTHS[usize::from(b)]);
        acc = (acc << len) | u64::from(HUFFMAN.codes[usize::from(b)]);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1 << pad) - 1)) as u8);
    }
}

/// Decodes a Huffman-coded string. Padding must be fewer than 8 bits, all
/// 1s, and the end-of-string code may not appear. The result is at most
/// [`MAX_STRING`] bytes.
pub fn huffman_decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let h = &HUFFMAN;
    let mut out = Vec::with_capacity((bytes.len().saturating_mul(8) / 5).min(MAX_STRING));
    let (mut code, mut len) = (0u32, 0usize);
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return Err(Error::Huffman);
            }
            if code >= h.first[len] && code - h.first[len] < h.count[len] {
                let sym = h.symbols[usize::from(h.start[len]) + (code - h.first[len]) as usize];
                if sym == 256 {
                    return Err(Error::Huffman);
                }
                if out.len() >= MAX_STRING {
                    return Err(Error::StringTooLong);
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }
    if len < 8 && code == (1 << len) - 1 { Ok(out) } else { Err(Error::Huffman) }
}

// ---------------------------------------------------------------------
// Fields and the dynamic table.

/// One header or trailer field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Field {
    /// The name, which HTTP/3 requires in lowercase.
    pub name: Vec<u8>,
    /// The value.
    pub value: Vec<u8>,
    /// Whether intermediaries must never put this field in a dynamic
    /// table, as for a password or cookie. Fields read from the static or
    /// dynamic table have it unset. An [`Encoder`] always writes such a
    /// field as a literal and never inserts it.
    pub never_index: bool,
}

impl Field {
    /// A field that may be indexed.
    pub fn new(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Field {
        Field { name: name.as_ref().to_vec(), value: value.as_ref().to_vec(), never_index: false }
    }

    /// The field's size: its name and value plus [`ENTRY_OVERHEAD`]. Both
    /// the dynamic table and the limit on field section size count this.
    pub fn size(&self) -> u64 {
        entry_size(&self.name, &self.value)
    }
}

fn entry_size(name: &[u8], value: &[u8]) -> u64 {
    name.len() as u64 + value.len() as u64 + ENTRY_OVERHEAD
}

/// The dynamic table: entries inserted in order, each with an absolute
/// index counting from 0, the oldest evicted first when room is needed.
/// Both sides of a connection keep one, and keep it the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicTable {
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: u64,
    capacity: u64,
    max_capacity: u64,
    inserted: u64,
}

impl DynamicTable {
    /// An empty table with capacity 0, which may grow to `max_capacity`
    /// (lowered to [`MAX_TABLE_CAPACITY`]).
    pub fn new(max_capacity: u64) -> DynamicTable {
        DynamicTable {
            entries: VecDeque::new(),
            size: 0,
            capacity: 0,
            max_capacity: max_capacity.min(MAX_TABLE_CAPACITY),
            inserted: 0,
        }
    }

    /// The most the capacity may be: the decoder's
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    /// The most the entries' sizes may add up to now.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// What the entries' sizes add up to.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// How many entries the table holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries have ever been inserted. The next one gets this
    /// absolute index.
    pub fn insert_count(&self) -> u64 {
        self.inserted
    }

    /// The most entries the table can hold: the maximum capacity over 32.
    /// Required Insert Counts are encoded with it.
    pub fn max_entries(&self) -> u64 {
        self.max_capacity / ENTRY_OVERHEAD
    }

    /// The absolute index of the oldest entry still held.
    pub fn first_index(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    /// The entry with absolute index `index`, if the table still holds it.
    pub fn get(&self, index: u64) -> Option<(&[u8], &[u8])> {
        let i = index.checked_sub(self.first_index())?;
        let (n, v) = self.entries.get(usize::try_from(i).ok()?)?;
        Some((n, v))
    }

    /// The entry an encoder stream instruction names by relative index: 0
    /// is the newest.
    pub fn get_relative(&self, relative: u64) -> Option<(&[u8], &[u8])> {
        self.get(self.inserted.checked_sub(relative.checked_add(1)?)?)
    }

    /// The absolute index of the newest entry with this name and value.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        let i = self.entries.iter().rposition(|(n, v)| n == name && v == value)?;
        Some(self.first_index() + i as u64)
    }

    /// The absolute index of the newest entry with this name.
    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        let i = self.entries.iter().rposition(|(n, _)| n == name)?;
        Some(self.first_index() + i as u64)
    }

    /// Sets the capacity, evicting the oldest entries until they fit. A
    /// capacity above the maximum is [`Error::Capacity`].
    pub fn set_capacity(&mut self, capacity: u64) -> Result<(), Error> {
        if capacity > self.max_capacity {
            return Err(Error::Capacity(capacity));
        }
        self.capacity = capacity;
        self.evict_to(capacity);
        Ok(())
    }

    /// Inserts an entry, evicting the oldest entries to make room, and
    /// returns its absolute index. An entry larger than the capacity is
    /// [`Error::EntryTooLarge`], and the table is left as it was.
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> Result<u64, Error> {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return Err(Error::EntryTooLarge);
        }
        let index = self.inserted;
        self.inserted = index.checked_add(1).ok_or(Error::IntegerOverflow)?;
        self.evict_to(self.capacity - size);
        self.size += size;
        self.entries.push_back((name, value));
        Ok(index)
    }

    fn evict_to(&mut self, room: u64) {
        while self.size > room {
            match self.entries.pop_front() {
                Some((n, v)) => self.size -= entry_size(&n, &v),
                None => break,
            }
        }
    }

    /// The absolute index of the oldest entry left after making room for
    /// `size` more within `capacity`, or `None` if it cannot fit at all.
    fn first_kept(&self, size: u64, capacity: u64) -> Option<u64> {
        if size > capacity {
            return None;
        }
        let mut used = self.size;
        let mut index = self.first_index();
        for (n, v) in &self.entries {
            if used + size <= capacity {
                break;
            }
            used -= entry_size(n, v);
            index += 1;
        }
        Some(index)
    }
}

// ---------------------------------------------------------------------
// Encoder and decoder stream instructions (RFC 9204 sections 4.3, 4.4).

/// An instruction on the encoder stream, which changes the dynamic table.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum EncoderInstruction {
    /// Set the table's capacity.
    SetCapacity(u64),
    /// Insert an entry with `value` and the name of static entry `index`,
    /// or of the dynamic entry at relative `index` (0 is the newest).
    InsertWithNameRef { static_table: bool, index: u64, value: Vec<u8> },
    /// Insert an entry with this name and value.
    InsertWithLiteralName { name: Vec<u8>, value: Vec<u8> },
    /// Insert a copy of the dynamic entry at this relative index.
    Duplicate(u64),
}

impl EncoderInstruction {
    /// Reads the instruction at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the instruction and how
    /// many bytes it took.
    pub fn parse(b: &[u8]) -> Result<Option<(EncoderInstruction, usize)>, Error> {
        let mut c = Cursor { b, i: 0 };
        let read = |c: &mut Cursor| -> Result<EncoderInstruction, Stop> {
            let first = c.peek()?;
            Ok(if first & 0x80 != 0 {
                let static_table = first & 0x40 != 0;
                let index = c.int(6)?;
                let value = c.raw_string(7)?.decode()?;
                EncoderInstruction::InsertWithNameRef { static_table, index, value }
            } else if first & 0x40 != 0 {
                let name = c.raw_string(5)?;
                let value = c.raw_string(7)?;
                EncoderInstruction::InsertWithLiteralName { name: name.decode()?, value: value.decode()? }
            } else if first & 0x20 != 0 {
                EncoderInstruction::SetCapacity(c.int(5)?)
            } else {
                EncoderInstruction::Duplicate(c.int(5)?)
            })
        };
        match read(&mut c) {
            Ok(ins) => Ok(Some((ins, c.i))),
            Err(Stop::More) => Ok(None),
            Err(Stop::Bad(e)) => Err(e),
        }
    }

    /// The instruction's bytes. Strings are Huffman-coded when that is
    /// shorter. Integers above [`MAX_INTEGER`] are lowered to it and
    /// strings longer than [`MAX_STRING`] are cut.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            EncoderInstruction::SetCapacity(c) => encode_integer(&mut out, 5, 0x20, *c),
            EncoderInstruction::InsertWithNameRef { static_table, index, value } => {
                encode_integer(&mut out, 6, if *static_table { 0xc0 } else { 0x80 }, *index);
                put_string(&mut out, 7, 0, value);
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                put_string(&mut out, 5, 0x40, name);
                put_string(&mut out, 7, 0, value);
            }
            EncoderInstruction::Duplicate(i) => encode_integer(&mut out, 5, 0, *i),
        }
        out
    }
}

/// An instruction on the decoder stream, which tells the encoder what the
/// decoder has seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// The decoder has decoded a field section on this stream that refers
    /// to the dynamic table.
    SectionAck(u64),
    /// This stream was reset or abandoned; its sections will not be
    /// acknowledged.
    StreamCancel(u64),
    /// The decoder has received this many more inserts.
    InsertCountIncrement(u64),
}

impl DecoderInstruction {
    /// Reads the instruction at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the instruction and how
    /// many bytes it took. An increment of 0 is read; an [`Encoder`]
    /// refuses it.
    pub fn parse(b: &[u8]) -> Result<Option<(DecoderInstruction, usize)>, Error> {
        let mut c = Cursor { b, i: 0 };
        let read = |c: &mut Cursor| -> Result<DecoderInstruction, Stop> {
            let first = c.peek()?;
            Ok(if first & 0x80 != 0 {
                DecoderInstruction::SectionAck(c.int(7)?)
            } else if first & 0x40 != 0 {
                DecoderInstruction::StreamCancel(c.int(6)?)
            } else {
                DecoderInstruction::InsertCountIncrement(c.int(6)?)
            })
        };
        match read(&mut c) {
            Ok(ins) => Ok(Some((ins, c.i))),
            Err(Stop::More) => Ok(None),
            Err(Stop::Bad(e)) => Err(e),
        }
    }

    /// The instruction's bytes. Integers above [`MAX_INTEGER`] are lowered
    /// to it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            DecoderInstruction::SectionAck(s) => encode_integer(&mut out, 7, 0x80, *s),
            DecoderInstruction::StreamCancel(s) => encode_integer(&mut out, 6, 0x40, *s),
            DecoderInstruction::InsertCountIncrement(n) => encode_integer(&mut out, 6, 0, *n),
        }
        out
    }
}

// ---------------------------------------------------------------------
// Field sections (RFC 9204 section 4.5).

/// The Required Insert Count as sent: 0 for none, and otherwise the count
/// modulo twice `max_entries`, plus 1. It is `None` if the count is not 0
/// and `max_entries` is, since no table can then hold an entry.
pub fn encode_insert_count(required: u64, max_entries: u64) -> Option<u64> {
    if required == 0 {
        return Some(0);
    }
    let full = max_entries.checked_mul(2).filter(|&f| f > 0)?;
    Some(required % full + 1)
}

/// The Required Insert Count from its encoded form, given the decoder's
/// maximum entries and how many inserts it has received (RFC 9204 section
/// 4.5.1.1).
pub fn decode_insert_count(encoded: u64, max_entries: u64, total_inserts: u64) -> Result<u64, Error> {
    if encoded == 0 {
        return Ok(0);
    }
    let full = max_entries.checked_mul(2).ok_or(Error::InsertCount)?;
    if encoded > full {
        return Err(Error::InsertCount);
    }
    let max_value = total_inserts.checked_add(max_entries).ok_or(Error::InsertCount)?;
    let max_wrapped = max_value / full * full;
    let mut required = max_wrapped.checked_add(encoded - 1).ok_or(Error::InsertCount)?;
    if required > max_value {
        if required <= full {
            return Err(Error::InsertCount);
        }
        required -= full;
    }
    if required == 0 {
        return Err(Error::InsertCount);
    }
    Ok(required)
}

/// The prefix of an encoded field section: which inserts the section needs
/// and the Base its dynamic references count from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionPrefix {
    /// One more than the largest absolute index the section refers to, or
    /// 0 if it refers to no dynamic entry.
    pub required_insert_count: u64,
    /// Relative indexes count down from it, post-base indexes up.
    pub base: u64,
}

impl SectionPrefix {
    /// Reads the prefix at the start of `b`, given the decoder's maximum
    /// entries and inserts received, and returns it and its length.
    pub fn parse(b: &[u8], max_entries: u64, total_inserts: u64) -> Result<(SectionPrefix, usize), Error> {
        let mut c = Cursor { b, i: 0 };
        let mut read = || -> Result<SectionPrefix, Stop> {
            let encoded = c.int(8)?;
            let required = decode_insert_count(encoded, max_entries, total_inserts)?;
            let negative = c.peek()? & 0x80 != 0;
            let delta = c.int(7)?;
            let base = if negative {
                delta.checked_add(1).and_then(|d| required.checked_sub(d)).ok_or(Error::Base)?
            } else {
                required.checked_add(delta).ok_or(Error::IntegerOverflow)?
            };
            Ok(SectionPrefix { required_insert_count: required, base })
        };
        match read() {
            Ok(p) => Ok((p, c.i)),
            Err(Stop::More) => Err(Error::Truncated),
            Err(Stop::Bad(e)) => Err(e),
        }
    }

    /// The prefix's bytes, for a decoder with `max_entries`. A nonzero
    /// count with `max_entries` 0, or a Base more than [`MAX_INTEGER`] from
    /// the count, is an error. The prefix reads back the same only if the
    /// decoder's insert count is within `max_entries` of the required one,
    /// as it is when the section's entries are in its table.
    pub fn to_bytes(&self, max_entries: u64) -> Result<Vec<u8>, Error> {
        let required = self.required_insert_count;
        let encoded = encode_insert_count(required, max_entries).ok_or(Error::InsertCount)?;
        let (sign, delta) =
            if self.base >= required { (0, self.base - required) } else { (0x80, required - self.base - 1) };
        if delta > MAX_INTEGER {
            return Err(Error::IntegerOverflow);
        }
        let mut out = Vec::new();
        encode_integer(&mut out, 8, 0, encoded);
        encode_integer(&mut out, 7, sign, delta);
        Ok(out)
    }
}

/// One field line of an encoded field section.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Representation {
    /// The whole field from static entry `index`, or from the dynamic
    /// entry at relative `index` (Base - 1 - `index` is its absolute
    /// index).
    Indexed { static_table: bool, index: u64 },
    /// The whole field from the dynamic entry whose absolute index is Base
    /// plus this number.
    IndexedPostBase(u64),
    /// The name from a static or relative dynamic entry, and `value`.
    LiteralNameRef { never_index: bool, static_table: bool, index: u64, value: Vec<u8> },
    /// The name from the dynamic entry with absolute index Base + `index`,
    /// and `value`.
    LiteralPostBaseNameRef { never_index: bool, index: u64, value: Vec<u8> },
    /// The name and value spelled out.
    LiteralName { never_index: bool, name: Vec<u8>, value: Vec<u8> },
}

impl Representation {
    /// Reads the field line at the start of `b`, and returns it and its
    /// length. A field line cut short is [`Error::Truncated`].
    pub fn parse(b: &[u8]) -> Result<(Representation, usize), Error> {
        let mut c = Cursor { b, i: 0 };
        let read = |c: &mut Cursor| -> Result<Representation, Stop> {
            let first = c.peek()?;
            Ok(if first & 0x80 != 0 {
                Representation::Indexed { static_table: first & 0x40 != 0, index: c.int(6)? }
            } else if first & 0x40 != 0 {
                let (never_index, static_table) = (first & 0x20 != 0, first & 0x10 != 0);
                let index = c.int(4)?;
                let value = c.raw_string(7)?.decode()?;
                Representation::LiteralNameRef { never_index, static_table, index, value }
            } else if first & 0x20 != 0 {
                let never_index = first & 0x10 != 0;
                let name = c.raw_string(3)?;
                let value = c.raw_string(7)?;
                Representation::LiteralName { never_index, name: name.decode()?, value: value.decode()? }
            } else if first & 0x10 != 0 {
                Representation::IndexedPostBase(c.int(4)?)
            } else {
                let never_index = first & 0x08 != 0;
                let index = c.int(3)?;
                let value = c.raw_string(7)?.decode()?;
                Representation::LiteralPostBaseNameRef { never_index, index, value }
            })
        };
        match read(&mut c) {
            Ok(r) => Ok((r, c.i)),
            Err(Stop::More) => Err(Error::Truncated),
            Err(Stop::Bad(e)) => Err(e),
        }
    }

    /// Appends the field line's bytes. Strings are Huffman-coded when that
    /// is shorter. Integers above [`MAX_INTEGER`] are lowered to it and
    /// strings longer than [`MAX_STRING`] are cut.
    pub fn write(&self, out: &mut Vec<u8>) {
        match self {
            Representation::Indexed { static_table, index } => {
                encode_integer(out, 6, if *static_table { 0xc0 } else { 0x80 }, *index)
            }
            Representation::IndexedPostBase(index) => encode_integer(out, 4, 0x10, *index),
            Representation::LiteralNameRef { never_index, static_table, index, value } => {
                let flags = 0x40 | if *never_index { 0x20 } else { 0 } | if *static_table { 0x10 } else { 0 };
                encode_integer(out, 4, flags, *index);
                put_string(out, 7, 0, value);
            }
            Representation::LiteralPostBaseNameRef { never_index, index, value } => {
                encode_integer(out, 3, if *never_index { 0x08 } else { 0 }, *index);
                put_string(out, 7, 0, value);
            }
            Representation::LiteralName { never_index, name, value } => {
                put_string(out, 3, if *never_index { 0x30 } else { 0x20 }, name);
                put_string(out, 7, 0, value);
            }
        }
    }

    /// The field line's bytes, as [`Representation::write`] makes them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
}

/// Decodes the field lines after a section's prefix.
fn decode_fields(table: &DynamicTable, prefix: SectionPrefix, b: &[u8], limit: u64) -> Result<Vec<Field>, Error> {
    let SectionPrefix { required_insert_count: required, base } = prefix;
    let mut fields = Vec::new();
    let mut size = 0u64;
    let mut largest: Option<u64> = None;
    let mut i = 0;
    // The entry at absolute index `abs`, which must be below the Required
    // Insert Count; `sent` is the index as the field line gave it.
    fn lookup<'t>(
        table: &'t DynamicTable,
        required: u64,
        largest: &mut Option<u64>,
        abs: Option<u64>,
        sent: u64,
    ) -> Result<(&'t [u8], &'t [u8]), Error> {
        let abs = abs.filter(|&a| a < required).ok_or(Error::DynamicIndex(sent))?;
        let entry = table.get(abs).ok_or(Error::DynamicIndex(sent))?;
        *largest = Some(largest.map_or(abs, |l| l.max(abs)));
        Ok(entry)
    }
    let mut dynamic = |abs: Option<u64>, sent: u64| lookup(table, required, &mut largest, abs, sent);
    let relative = |index: u64| index.checked_add(1).and_then(|d| base.checked_sub(d));
    let static_ = |index: u64| static_entry(index).ok_or(Error::StaticIndex(index));
    while i < b.len() {
        let (rep, used) = Representation::parse(&b[i..])?;
        i += used;
        let field = match rep {
            Representation::Indexed { static_table: true, index } => Field::new(static_(index)?.0, static_(index)?.1),
            Representation::Indexed { static_table: false, index } => {
                let (n, v) = dynamic(relative(index), index)?;
                Field::new(n, v)
            }
            Representation::IndexedPostBase(index) => {
                let (n, v) = dynamic(base.checked_add(index), index)?;
                Field::new(n, v)
            }
            Representation::LiteralNameRef { never_index, static_table, index, value } => {
                let name = if static_table {
                    static_(index)?.0.as_bytes().to_vec()
                } else {
                    dynamic(relative(index), index)?.0.to_vec()
                };
                Field { name, value, never_index }
            }
            Representation::LiteralPostBaseNameRef { never_index, index, value } => {
                let name = dynamic(base.checked_add(index), index)?.0.to_vec();
                Field { name, value, never_index }
            }
            Representation::LiteralName { never_index, name, value } => Field { name, value, never_index },
        };
        if fields.len() >= MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        size = size.saturating_add(field.size());
        if size > limit {
            return Err(Error::FieldSectionTooLarge);
        }
        fields.push(field);
    }
    // A section must not ask for more inserts than it uses.
    if required != largest.map_or(0, |l| l + 1) {
        return Err(Error::InsertCount);
    }
    Ok(fields)
}

/// What [`Decoder::decode_section`] made of a field section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Section {
    /// The section's fields, in order.
    Fields(Vec<Field>),
    /// The section needs inserts the decoder has not received. Its fields
    /// come out of [`Decoder::unblocked`] once they arrive.
    Blocked,
}

#[derive(Clone, Debug)]
struct BlockedSection {
    stream: u64,
    prefix: SectionPrefix,
    body: Vec<u8>,
}

/// The decoding side of QPACK: it keeps the dynamic table the peer's
/// encoder stream builds, decodes field sections, and writes the decoder
/// stream.
#[derive(Clone, Debug)]
pub struct Decoder {
    table: DynamicTable,
    max_blocked: usize,
    field_limit: u64,
    buf: Vec<u8>,
    start: usize,
    failed: Option<Error>,
    blocked: Vec<BlockedSection>,
    blocked_bytes: usize,
    ready: Vec<(u64, Result<Vec<Field>, Error>)>,
    out: Vec<u8>,
    /// The insert count the encoder knows of, from acknowledgments and
    /// increments already written.
    reported: u64,
}

impl Decoder {
    /// A decoder with the settings it advertises: its
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_QPACK_BLOCKED_STREAMS
    /// and SETTINGS_MAX_FIELD_SECTION_SIZE. Each is lowered to this
    /// module's limit.
    pub fn new(max_table_capacity: u64, max_blocked_streams: usize, max_field_section_size: u64) -> Decoder {
        Decoder {
            table: DynamicTable::new(max_table_capacity),
            max_blocked: max_blocked_streams.min(MAX_BLOCKED_STREAMS),
            field_limit: max_field_section_size.min(MAX_FIELD_SECTION_SIZE),
            buf: Vec::new(),
            start: 0,
            failed: None,
            blocked: Vec::new(),
            blocked_bytes: 0,
            ready: Vec::new(),
            out: Vec::new(),
            reported: 0,
        }
    }

    /// The dynamic table as the encoder stream has built it so far.
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Adds bytes read from the peer's encoder stream and applies each
    /// whole instruction. An error is a connection error; once there is
    /// one, every later call returns it and bytes are dropped. Sections
    /// the new inserts unblock are decoded at once and wait in
    /// [`Decoder::unblocked`].
    pub fn feed_encoder_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
        loop {
            let result = match EncoderInstruction::parse(&self.buf[self.start..]) {
                Ok(Some((ins, used))) => {
                    self.start += used;
                    self.apply(ins)
                }
                Ok(None) => return Ok(()),
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                return Err(e);
            }
        }
    }

    fn apply(&mut self, ins: EncoderInstruction) -> Result<(), Error> {
        let (name, value) = match ins {
            EncoderInstruction::SetCapacity(c) => return self.table.set_capacity(c),
            EncoderInstruction::InsertWithNameRef { static_table: true, index, value } => {
                let (n, _) = static_entry(index).ok_or(Error::StaticIndex(index))?;
                (n.as_bytes().to_vec(), value)
            }
            EncoderInstruction::InsertWithNameRef { static_table: false, index, value } => {
                let (n, _) = self.table.get_relative(index).ok_or(Error::DynamicIndex(index))?;
                (n.to_vec(), value)
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => (name, value),
            EncoderInstruction::Duplicate(index) => {
                let (n, v) = self.table.get_relative(index).ok_or(Error::DynamicIndex(index))?;
                (n.to_vec(), v.to_vec())
            }
        };
        self.table.insert(name, value)?;
        self.unblock();
        Ok(())
    }

    fn unblock(&mut self) {
        let count = self.table.insert_count();
        let mut i = 0;
        while i < self.blocked.len() {
            if self.blocked[i].prefix.required_insert_count <= count {
                let b = self.blocked.remove(i);
                self.blocked_bytes -= b.body.len();
                let result = decode_fields(&self.table, b.prefix, &b.body, self.field_limit);
                if result.is_ok() {
                    self.acknowledge(b.stream, b.prefix.required_insert_count);
                }
                self.ready.push((b.stream, result));
            } else {
                i += 1;
            }
        }
    }

    fn acknowledge(&mut self, stream: u64, required: u64) {
        if required > 0 {
            self.out.extend_from_slice(&DecoderInstruction::SectionAck(stream).to_bytes());
            self.reported = self.reported.max(required);
        }
    }

    /// Decodes the encoded field section that came on `stream`, a QUIC
    /// stream ID below 2^62. A section that needs inserts not yet received
    /// is held and gives [`Section::Blocked`]. If that would block more
    /// streams than the limit, or hold more than [`MAX_BLOCKED_SECTIONS`]
    /// or [`MAX_BLOCKED_BYTES`], it is [`Error::TooManyBlocked`]. Any error
    /// is the connection error [`error_code::DECOMPRESSION_FAILED`].
    pub fn decode_section(&mut self, stream: u64, bytes: &[u8]) -> Result<Section, Error> {
        if bytes.len() > MAX_SECTION_BYTES {
            return Err(Error::FieldSectionTooLarge);
        }
        let (prefix, used) = SectionPrefix::parse(bytes, self.table.max_entries(), self.table.insert_count())?;
        let body = &bytes[used..];
        if prefix.required_insert_count > self.table.insert_count() {
            let new_stream = !self.blocked.iter().any(|b| b.stream == stream);
            let too_many = new_stream && self.blocked_streams() >= self.max_blocked;
            let full = self.blocked.len() >= MAX_BLOCKED_SECTIONS;
            if too_many || full || self.blocked_bytes + body.len() > MAX_BLOCKED_BYTES {
                return Err(Error::TooManyBlocked);
            }
            self.blocked_bytes += body.len();
            self.blocked.push(BlockedSection { stream, prefix, body: body.to_vec() });
            return Ok(Section::Blocked);
        }
        let fields = decode_fields(&self.table, prefix, body, self.field_limit)?;
        self.acknowledge(stream, prefix.required_insert_count);
        Ok(Section::Fields(fields))
    }

    /// The sections that were blocked and have since been decoded, with
    /// their streams, oldest first. Each is taken out once.
    pub fn unblocked(&mut self) -> Vec<(u64, Result<Vec<Field>, Error>)> {
        std::mem::take(&mut self.ready)
    }

    /// How many streams have a section waiting for inserts. This is what
    /// SETTINGS_QPACK_BLOCKED_STREAMS limits.
    pub fn blocked_streams(&self) -> usize {
        let mut streams: Vec<u64> = self.blocked.iter().map(|b| b.stream).collect();
        streams.sort_unstable();
        streams.dedup();
        streams.len()
    }

    /// Drops what waits for `stream`, which was reset or abandoned, and
    /// tells the encoder so, unless the table can hold nothing.
    pub fn cancel_stream(&mut self, stream: u64) {
        let before = self.blocked.len();
        self.blocked.retain(|b| b.stream != stream);
        if self.blocked.len() != before {
            self.blocked_bytes = self.blocked.iter().map(|b| b.body.len()).sum();
        }
        self.ready.retain(|(s, _)| *s != stream);
        if self.table.max_capacity() > 0 {
            self.out.extend_from_slice(&DecoderInstruction::StreamCancel(stream).to_bytes());
        }
    }

    /// The bytes to write to the decoder stream: acknowledgments and
    /// cancellations so far, then an Insert Count Increment for inserts
    /// not yet reported. Each byte is returned once.
    pub fn take_decoder_stream(&mut self) -> Vec<u8> {
        let count = self.table.insert_count();
        if count > self.reported {
            self.out.extend_from_slice(&DecoderInstruction::InsertCountIncrement(count - self.reported).to_bytes());
            self.reported = count;
        }
        std::mem::take(&mut self.out)
    }
}

#[derive(Clone, Copy, Debug)]
struct Outstanding {
    stream: u64,
    required: u64,
    /// The smallest absolute index the section refers to.
    oldest: u64,
}

/// The encoding side of QPACK: it inserts entries on the encoder stream,
/// encodes field sections, and reads the peer's decoder stream to learn
/// which entries it may use and evict.
#[derive(Clone, Debug)]
pub struct Encoder {
    table: DynamicTable,
    field_limit: u64,
    known_received: u64,
    outstanding: VecDeque<Outstanding>,
    out: Vec<u8>,
    buf: Vec<u8>,
    start: usize,
    failed: Option<Error>,
}

impl Encoder {
    /// An encoder for a peer that advertised this
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    /// SETTINGS_MAX_FIELD_SECTION_SIZE. Each is lowered to this module's
    /// limit. The table starts with capacity 0.
    pub fn new(max_table_capacity: u64, max_field_section_size: u64) -> Encoder {
        Encoder {
            table: DynamicTable::new(max_table_capacity),
            field_limit: max_field_section_size.min(MAX_FIELD_SECTION_SIZE),
            known_received: 0,
            outstanding: VecDeque::new(),
            out: Vec::new(),
            buf: Vec::new(),
            start: 0,
            failed: None,
        }
    }

    /// The dynamic table as the encoder has built it.
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// How many inserts the decoder has said it received. Only entries
    /// below this absolute index are used in field sections.
    pub fn known_received_count(&self) -> u64 {
        self.known_received
    }

    /// The oldest absolute index that may not be evicted (RFC 9204 section
    /// 2.1.1): the oldest entry a section still waiting for its
    /// acknowledgment uses, or the oldest insert the decoder has not yet
    /// acknowledged, whichever is older.
    fn evict_limit(&self) -> u64 {
        self.outstanding.iter().map(|o| o.oldest).min().unwrap_or(u64::MAX).min(self.known_received)
    }

    /// Whether room for `size` more within `capacity` keeps every entry
    /// that is not evictable.
    fn room(&self, size: u64, capacity: u64) -> Result<(), Error> {
        let kept = self.table.first_kept(size, capacity).ok_or(Error::EntryTooLarge)?;
        if kept > self.evict_limit() { Err(Error::Referenced) } else { Ok(()) }
    }

    /// Sets the table's capacity and writes the instruction. A capacity
    /// above the maximum is [`Error::Capacity`]. One that would evict an
    /// entry in use, or one whose insert the decoder has not acknowledged,
    /// is [`Error::Referenced`].
    pub fn set_capacity(&mut self, capacity: u64) -> Result<(), Error> {
        if capacity > self.table.max_capacity() {
            return Err(Error::Capacity(capacity));
        }
        self.room(0, capacity)?;
        self.table.set_capacity(capacity)?;
        self.out.extend_from_slice(&EncoderInstruction::SetCapacity(capacity).to_bytes());
        Ok(())
    }

    /// Inserts an entry and writes the instruction, naming the static or
    /// dynamic entry with the same name when there is one. It returns the
    /// entry's absolute index. A name or value longer than [`MAX_STRING`]
    /// is [`Error::StringTooLong`], and an entry larger than the capacity
    /// [`Error::EntryTooLarge`]. One that would evict an entry in use, or
    /// one whose insert the decoder has not acknowledged, is
    /// [`Error::Referenced`]. On an error nothing changes.
    pub fn insert(&mut self, name: &[u8], value: &[u8]) -> Result<u64, Error> {
        if name.len() > MAX_STRING || value.len() > MAX_STRING {
            return Err(Error::StringTooLong);
        }
        self.room(entry_size(name, value), self.table.capacity())?;
        let ins = if let Some(index) = static_find_name(name) {
            EncoderInstruction::InsertWithNameRef { static_table: true, index, value: value.to_vec() }
        } else if let Some(abs) = self.table.find_name(name) {
            let index = self.table.insert_count() - 1 - abs;
            EncoderInstruction::InsertWithNameRef { static_table: false, index, value: value.to_vec() }
        } else {
            EncoderInstruction::InsertWithLiteralName { name: name.to_vec(), value: value.to_vec() }
        };
        let abs = self.table.insert(name.to_vec(), value.to_vec())?;
        self.out.extend_from_slice(&ins.to_bytes());
        Ok(abs)
    }

    /// Inserts a copy of the entry at absolute index `index` and writes the
    /// instruction, which keeps a used entry from being evicted. It
    /// returns the copy's absolute index. It fails as [`Encoder::insert`]
    /// does, and with [`Error::DynamicIndex`] if the table does not hold
    /// the entry.
    pub fn duplicate(&mut self, index: u64) -> Result<u64, Error> {
        let (n, v) = self.table.get(index).ok_or(Error::DynamicIndex(index))?;
        let (n, v) = (n.to_vec(), v.to_vec());
        self.room(entry_size(&n, &v), self.table.capacity())?;
        let relative = self.table.insert_count() - 1 - index;
        let abs = self.table.insert(n, v)?;
        self.out.extend_from_slice(&EncoderInstruction::Duplicate(relative).to_bytes());
        Ok(abs)
    }

    /// Encodes `fields` for `stream`, a QUIC stream ID below 2^62. Each
    /// field uses a static entry, or a dynamic entry the decoder has
    /// acknowledged, when one matches; otherwise it is written as a
    /// literal. A section past the peer's field section size limit is
    /// [`Error::FieldSectionTooLarge`], one with more than [`MAX_FIELDS`]
    /// fields [`Error::TooManyFields`], and a name or value longer than
    /// [`MAX_STRING`] [`Error::StringTooLong`].
    pub fn encode_section(&mut self, stream: u64, fields: &[Field]) -> Result<Vec<u8>, Error> {
        if fields.len() > MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        let mut size = 0u64;
        for f in fields {
            if f.name.len() > MAX_STRING || f.value.len() > MAX_STRING {
                return Err(Error::StringTooLong);
            }
            size = size.saturating_add(f.size());
        }
        if size > self.field_limit {
            return Err(Error::FieldSectionTooLarge);
        }
        // Choose each line: a static index, a dynamic absolute index, or
        // neither, for the whole field and for its name.
        enum Line {
            Static(u64),
            Dynamic(u64),
            StaticName(u64),
            DynamicName(u64),
            Literal,
        }
        let use_dynamic = self.outstanding.len() < MAX_OUTSTANDING;
        let acked = |abs: Option<u64>| abs.filter(|&a| use_dynamic && a < self.known_received);
        let lines: Vec<Line> = fields
            .iter()
            .map(|f| {
                if !f.never_index {
                    if let Some(i) = static_find(&f.name, &f.value) {
                        return Line::Static(i);
                    }
                    if let Some(a) = acked(self.table.find(&f.name, &f.value)) {
                        return Line::Dynamic(a);
                    }
                }
                if let Some(i) = static_find_name(&f.name) {
                    Line::StaticName(i)
                } else if let Some(a) = acked(self.table.find_name(&f.name)) {
                    Line::DynamicName(a)
                } else {
                    Line::Literal
                }
            })
            .collect();
        let used = lines.iter().filter_map(|l| match l {
            Line::Dynamic(a) | Line::DynamicName(a) => Some(*a),
            _ => None,
        });
        let (oldest, newest) = used.fold((None, None), |(lo, hi): (Option<u64>, Option<u64>), a| {
            (Some(lo.map_or(a, |l| l.min(a))), Some(hi.map_or(a, |h| h.max(a))))
        });
        let required = newest.map_or(0, |n| n + 1);
        let prefix = SectionPrefix { required_insert_count: required, base: required };
        let mut out = prefix.to_bytes(self.table.max_entries())?;
        for (line, f) in lines.iter().zip(fields) {
            let rep = match *line {
                Line::Static(index) => Representation::Indexed { static_table: true, index },
                Line::Dynamic(a) => Representation::Indexed { static_table: false, index: required - 1 - a },
                Line::StaticName(index) => Representation::LiteralNameRef {
                    never_index: f.never_index,
                    static_table: true,
                    index,
                    value: f.value.clone(),
                },
                Line::DynamicName(a) => Representation::LiteralNameRef {
                    never_index: f.never_index,
                    static_table: false,
                    index: required - 1 - a,
                    value: f.value.clone(),
                },
                Line::Literal => Representation::LiteralName {
                    never_index: f.never_index,
                    name: f.name.clone(),
                    value: f.value.clone(),
                },
            };
            rep.write(&mut out);
        }
        if let Some(oldest) = oldest {
            self.outstanding.push_back(Outstanding { stream, required, oldest });
        }
        Ok(out)
    }

    /// The bytes to write to the encoder stream. Each byte is returned
    /// once.
    pub fn take_encoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Adds bytes read from the peer's decoder stream and applies each
    /// whole instruction. An error is a connection error; once there is
    /// one, every later call returns it and bytes are dropped.
    pub fn feed_decoder_stream(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
        loop {
            let result = match DecoderInstruction::parse(&self.buf[self.start..]) {
                Ok(Some((ins, used))) => {
                    self.start += used;
                    self.apply(ins)
                }
                Ok(None) => return Ok(()),
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                return Err(e);
            }
        }
    }

    fn apply(&mut self, ins: DecoderInstruction) -> Result<(), Error> {
        match ins {
            DecoderInstruction::SectionAck(stream) => {
                let i = self.outstanding.iter().position(|o| o.stream == stream).ok_or(Error::UnknownStream(stream))?;
                if let Some(o) = self.outstanding.remove(i) {
                    self.known_received = self.known_received.max(o.required);
                }
            }
            DecoderInstruction::StreamCancel(stream) => self.outstanding.retain(|o| o.stream != stream),
            DecoderInstruction::InsertCountIncrement(0) => return Err(Error::ZeroIncrement),
            DecoderInstruction::InsertCountIncrement(n) => {
                let k = self.known_received.checked_add(n).ok_or(Error::Increment)?;
                if k > self.table.insert_count() {
                    return Err(Error::Increment);
                }
                self.known_received = k;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }

    fn fields(section: Section) -> Vec<Field> {
        match section {
            Section::Fields(f) => f,
            Section::Blocked => panic!("blocked"),
        }
    }

    /// A deterministic generator: a linear congruential one.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn bytes(&mut self, max: u64) -> Vec<u8> {
            let n = self.below(max + 1);
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    // RFC 7541 Appendix C.1: integers.

    #[test]
    fn integer_examples() {
        let mut out = Vec::new();
        encode_integer(&mut out, 5, 0, 10);
        assert_eq!(out, [0x0a]);
        out.clear();
        encode_integer(&mut out, 5, 0, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        out.clear();
        encode_integer(&mut out, 8, 0, 42);
        assert_eq!(out, [0x2a]);
        assert_eq!(decode_integer(&[0x1f, 0x9a, 0x0a], 5), Ok(Some((1337, 3))));
        assert_eq!(decode_integer(&[0xea], 5), Ok(Some((10, 1))));
        for n in 0..3 {
            assert_eq!(decode_integer(&[0x1f, 0x9a, 0x0a][..n], 5), Ok(None));
        }
    }

    #[test]
    fn integer_limits() {
        for prefix in 1..=8 {
            for v in [0, 1, 30, 31, 127, 128, 255, 256, 1 << 40, MAX_INTEGER - 1, MAX_INTEGER, u64::MAX] {
                let mut out = Vec::new();
                encode_integer(&mut out, prefix, 0, v);
                assert!(out.len() <= 10);
                assert_eq!(decode_integer(&out, prefix), Ok(Some((v.min(MAX_INTEGER), out.len()))));
            }
        }
        // One past the maximum.
        let mut over = vec![0xff];
        let mut rest = MAX_INTEGER + 1 - 255;
        while rest >= 0x80 {
            over.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        over.push(rest as u8);
        assert_eq!(decode_integer(&over, 8), Err(Error::IntegerOverflow));
        // Too many continuation bytes, even of zeros.
        let mut long = vec![0x1f];
        long.extend_from_slice(&[0x80; 10]);
        long.push(0);
        assert_eq!(decode_integer(&long, 5), Err(Error::IntegerOverflow));
        assert_eq!(decode_integer(&[0xff; 30], 8), Err(Error::IntegerOverflow));
    }

    // RFC 7541 Appendix C.4: Huffman-coded strings.

    #[test]
    fn huffman_examples() {
        for (text, code) in [
            ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
            ("no-cache", "a8eb 1064 9cbf"),
            ("custom-key", "25a8 49e9 5ba9 7d7f"),
            ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
            ("302", "6402"),
            ("private", "aec3 771a 4b"),
            ("Mon, 21 Oct 2013 20:13:21 GMT", "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff"),
            ("https://www.example.com", "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3"),
        ] {
            assert_eq!(huffman_encode(text.as_bytes()), hex(code), "{text}");
            assert_eq!(huffman_decode(&hex(code)).unwrap(), text.as_bytes());
            assert_eq!(huffman_len(text.as_bytes()), hex(code).len());
        }
    }

    #[test]
    fn huffman_every_byte_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
        for b in 0..=255u8 {
            assert_eq!(huffman_decode(&huffman_encode(&[b])).unwrap(), [b]);
        }
        assert_eq!(huffman_decode(&[]).unwrap(), b"");
    }

    #[test]
    fn huffman_errors() {
        // Eight 1 bits of padding.
        assert_eq!(huffman_decode(&[0xff]), Err(Error::Huffman));
        // The end-of-string code: thirty 1 bits.
        assert_eq!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]), Err(Error::Huffman));
        // 'a' (00011) padded with 0 bits.
        assert_eq!(huffman_decode(&[0x18]), Err(Error::Huffman));
        assert_eq!(huffman_decode(&[0x1f]).unwrap(), b"a");
        // Too long once decoded: '0' is 5 bits, so this gives 1.6 bytes per byte.
        let long = huffman_encode(&vec![b'0'; MAX_STRING + 1]);
        assert_eq!(huffman_decode(&long), Err(Error::StringTooLong));
        assert_eq!(huffman_decode(&huffman_encode(&vec![b'0'; MAX_STRING])).unwrap().len(), MAX_STRING);
    }

    #[test]
    fn static_table() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(static_entry(0), Some((":authority", "")));
        assert_eq!(static_entry(17), Some((":method", "GET")));
        assert_eq!(static_entry(25), Some((":status", "200")));
        assert_eq!(static_entry(98), Some(("x-frame-options", "sameorigin")));
        assert_eq!(static_entry(99), None);
        assert_eq!(static_entry(u64::MAX), None);
        assert_eq!(static_find(b":path", b"/"), Some(1));
        assert_eq!(static_find_name(b"content-type"), Some(44));
        assert_eq!(static_find(b"x-unknown", b""), None);
    }

    // RFC 9204 Appendix B.

    #[test]
    fn rfc_b1_literal_with_static_name() {
        let mut d = Decoder::new(0, 0, 1 << 16);
        let section = hex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
        assert_eq!(fields(d.decode_section(0, &section).unwrap()), [Field::new(":path", "/index.html")]);
        // No dynamic table use, so nothing to acknowledge.
        assert_eq!(d.take_decoder_stream(), b"");
    }

    #[test]
    fn rfc_b2_to_b5_dynamic_table() {
        let mut d = Decoder::new(220, 2, 1 << 16);
        // B.2: the section on stream 4 arrives before the inserts.
        let s4 = hex("0381 10 11");
        assert_eq!(d.decode_section(4, &s4), Ok(Section::Blocked));
        assert_eq!(d.blocked_streams(), 1);
        let enc = hex("3fbd01 c00f7777772e6578616d706c652e636f6d c10c2f73616d706c652f70617468");
        d.feed_encoder_stream(&enc).unwrap();
        assert_eq!(d.table().size(), 106);
        let unblocked = d.unblocked();
        assert_eq!(
            unblocked,
            [(4, Ok(vec![Field::new(":authority", "www.example.com"), Field::new(":path", "/sample/path")]))]
        );
        assert_eq!(d.take_decoder_stream(), [0x84]);
        // B.3: an insert with a literal name.
        d.feed_encoder_stream(&hex("4a637573746f6d2d6b65790c637573746f6d2d76616c7565")).unwrap();
        assert_eq!(d.table().size(), 160);
        assert_eq!(d.take_decoder_stream(), [0x01]);
        // B.4: the section on stream 8 needs a duplicate not yet sent, and
        // the stream is cancelled.
        let s8 = hex("0500 80 c1 81");
        assert_eq!(d.decode_section(8, &s8), Ok(Section::Blocked));
        d.cancel_stream(8);
        assert_eq!(d.take_decoder_stream(), [0x48]);
        d.feed_encoder_stream(&hex("02")).unwrap();
        assert_eq!(d.unblocked(), []);
        assert_eq!(d.table().size(), 217);
        assert_eq!(d.table().get(3), Some((&b":authority"[..], &b"www.example.com"[..])));
        // The same section, decoded now.
        assert_eq!(
            fields(d.decode_section(12, &s8).unwrap()),
            [
                Field::new(":authority", "www.example.com"),
                Field::new(":path", "/"),
                Field::new("custom-key", "custom-value")
            ]
        );
        // B.5: an insert naming dynamic entry 1 (relative), which evicts
        // entry 0.
        d.feed_encoder_stream(&hex("810d637573746f6d2d76616c756532")).unwrap();
        assert_eq!(d.table().size(), 215);
        assert_eq!(d.table().first_index(), 1);
        assert_eq!(d.table().get(4), Some((&b"custom-key"[..], &b"custom-value2"[..])));
        assert_eq!(d.take_decoder_stream(), [0x8c, 0x01]);
    }

    #[test]
    fn insert_count_encoding() {
        // RFC 9204 section 4.5.1.1, for every count a decoder can see.
        for max_entries in [1u64, 2, 6, 128] {
            for total in 0..300u64 {
                let low = (total + 1).saturating_sub(max_entries).max(1);
                for required in low..=total + max_entries {
                    let e = encode_insert_count(required, max_entries).unwrap();
                    assert_eq!(decode_insert_count(e, max_entries, total), Ok(required));
                }
            }
        }
        assert_eq!(encode_insert_count(0, 0), Some(0));
        assert_eq!(encode_insert_count(1, 0), None);
        assert_eq!(decode_insert_count(1, 0, 0), Err(Error::InsertCount));
        assert_eq!(decode_insert_count(13, 6, 0), Err(Error::InsertCount));
        // A count of 0 sent as nonzero, and ones that would need to wrap below 0.
        assert_eq!(decode_insert_count(1, 6, 0), Err(Error::InsertCount));
        assert_eq!(decode_insert_count(12, 6, 0), Err(Error::InsertCount));
        assert_eq!(decode_insert_count(8, 6, 0), Err(Error::InsertCount));
    }

    #[test]
    fn section_prefix() {
        for (required, base) in [(0, 0), (2, 0), (4, 4), (4, 9), (5, 1), (100, 0)] {
            let p = SectionPrefix { required_insert_count: required, base };
            let bytes = p.to_bytes(128).unwrap();
            assert_eq!(SectionPrefix::parse(&bytes, 128, required), Ok((p, bytes.len())));
            for n in 0..bytes.len() {
                assert_eq!(SectionPrefix::parse(&bytes[..n], 128, required), Err(Error::Truncated));
            }
        }
        // A negative Base.
        assert_eq!(SectionPrefix::parse(&[0x00, 0x80], 6, 0), Err(Error::Base));
        assert_eq!(SectionPrefix::parse(&[0x03, 0x82], 6, 2), Err(Error::Base));
        assert_eq!(SectionPrefix { required_insert_count: 1, base: 0 }.to_bytes(0), Err(Error::InsertCount));
        let far = SectionPrefix { required_insert_count: 0, base: u64::MAX };
        assert_eq!(far.to_bytes(6), Err(Error::IntegerOverflow));
    }

    #[test]
    fn representations_round_trip() {
        let reps = [
            Representation::Indexed { static_table: true, index: 98 },
            Representation::Indexed { static_table: false, index: 0 },
            Representation::Indexed { static_table: false, index: 1000 },
            Representation::IndexedPostBase(0),
            Representation::IndexedPostBase(70),
            Representation::LiteralNameRef { never_index: true, static_table: true, index: 15, value: b"x".to_vec() },
            Representation::LiteralNameRef {
                never_index: false,
                static_table: false,
                index: 3,
                value: b"some value".to_vec(),
            },
            Representation::LiteralPostBaseNameRef { never_index: true, index: 9, value: vec![0, 1, 2, 255] },
            Representation::LiteralPostBaseNameRef { never_index: false, index: 0, value: Vec::new() },
            Representation::LiteralName { never_index: false, name: b"custom-key".to_vec(), value: b"v".to_vec() },
            Representation::LiteralName { never_index: true, name: vec![0xff; 40], value: vec![b'a'; 300] },
        ];
        for r in &reps {
            let bytes = r.to_bytes();
            assert_eq!(Representation::parse(&bytes), Ok((r.clone(), bytes.len())), "{r:?}");
            for n in 0..bytes.len() {
                assert_eq!(Representation::parse(&bytes[..n]), Err(Error::Truncated), "{r:?} cut at {n}");
            }
        }
        // A string past the limit is cut by the writer, refused by the reader.
        let r = Representation::LiteralName { never_index: false, name: b"n".to_vec(), value: vec![0; MAX_STRING + 1] };
        let (back, _) = Representation::parse(&r.to_bytes()).unwrap();
        let Representation::LiteralName { value, .. } = back else { panic!() };
        assert_eq!(value.len(), MAX_STRING);
        let mut raw = vec![0x50, 0x7f];
        let mut rest = MAX_STRING as u64 + 1 - 127;
        while rest >= 0x80 {
            raw.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        raw.push(rest as u8);
        assert_eq!(Representation::parse(&raw), Err(Error::StringTooLong));
        // A bad Huffman string.
        assert_eq!(Representation::parse(&[0x50, 0x81, 0xff]), Err(Error::Huffman));
    }

    #[test]
    fn instructions_round_trip() {
        let enc = [
            EncoderInstruction::SetCapacity(0),
            EncoderInstruction::SetCapacity(220),
            EncoderInstruction::InsertWithNameRef { static_table: true, index: 0, value: b"www.example.com".to_vec() },
            EncoderInstruction::InsertWithNameRef { static_table: false, index: 200, value: Vec::new() },
            EncoderInstruction::InsertWithLiteralName { name: b"custom-key".to_vec(), value: b"custom-value".to_vec() },
            EncoderInstruction::InsertWithLiteralName { name: vec![1; 100], value: vec![2; 100] },
            EncoderInstruction::Duplicate(0),
            EncoderInstruction::Duplicate(MAX_INTEGER),
        ];
        for ins in &enc {
            let bytes = ins.to_bytes();
            assert_eq!(EncoderInstruction::parse(&bytes), Ok(Some((ins.clone(), bytes.len()))));
            for n in 0..bytes.len() {
                assert_eq!(EncoderInstruction::parse(&bytes[..n]), Ok(None), "{ins:?} cut at {n}");
            }
        }
        assert_eq!(EncoderInstruction::SetCapacity(220).to_bytes(), [0x3f, 0xbd, 0x01]);
        assert_eq!(EncoderInstruction::Duplicate(2).to_bytes(), [0x02]);
        let dec = [
            (DecoderInstruction::SectionAck(4), vec![0x84]),
            (DecoderInstruction::StreamCancel(8), vec![0x48]),
            (DecoderInstruction::InsertCountIncrement(1), vec![0x01]),
            (DecoderInstruction::SectionAck(1 << 40), DecoderInstruction::SectionAck(1 << 40).to_bytes()),
        ];
        for (ins, bytes) in &dec {
            assert_eq!(&ins.to_bytes(), bytes);
            assert_eq!(DecoderInstruction::parse(bytes), Ok(Some((*ins, bytes.len()))));
            for n in 0..bytes.len() {
                assert_eq!(DecoderInstruction::parse(&bytes[..n]), Ok(None));
            }
        }
        assert_eq!(DecoderInstruction::parse(&[0xff; 12]), Err(Error::IntegerOverflow));
    }

    #[test]
    fn dynamic_table_capacity_and_eviction() {
        let mut t = DynamicTable::new(100);
        assert_eq!(t.max_entries(), 3);
        assert_eq!(t.insert(b"a".to_vec(), b"b".to_vec()), Err(Error::EntryTooLarge));
        assert_eq!(t.set_capacity(101), Err(Error::Capacity(101)));
        t.set_capacity(100).unwrap();
        assert_eq!(t.insert(b"a".to_vec(), b"1".to_vec()), Ok(0)); // 34
        assert_eq!(t.insert(b"b".to_vec(), b"2".to_vec()), Ok(1)); // 68
        assert_eq!(t.insert(b"c".to_vec(), b"3".to_vec()), Ok(2)); // 102 > 100: evicts 0
        assert_eq!(t.first_index(), 1);
        assert_eq!(t.size(), 68);
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(2), Some((&b"c"[..], &b"3"[..])));
        assert_eq!(t.get_relative(0), t.get(2));
        assert_eq!(t.get_relative(1), t.get(1));
        assert_eq!(t.get_relative(2), None);
        assert_eq!(t.get_relative(u64::MAX), None);
        assert_eq!(t.find(b"b", b"2"), Some(1));
        assert_eq!(t.find_name(b"c"), Some(2));
        // An entry as large as the capacity empties the table.
        assert_eq!(t.insert(vec![b'x'; 60], vec![b'y'; 8]), Ok(3));
        assert_eq!((t.len(), t.size()), (1, 100));
        assert_eq!(t.insert(vec![b'x'; 60], vec![b'y'; 9]), Err(Error::EntryTooLarge));
        assert_eq!(t.insert_count(), 4);
        t.set_capacity(0).unwrap();
        assert!(t.is_empty());
        assert_eq!(DynamicTable::new(u64::MAX).max_capacity(), MAX_TABLE_CAPACITY);
    }

    #[test]
    fn decoder_errors() {
        let mut d = Decoder::new(220, 1, 200);
        // Encoder stream errors, each latched.
        let mut e = d.clone();
        assert_eq!(e.feed_encoder_stream(&[0x3f, 0xbe, 0x01]), Err(Error::Capacity(221)));
        assert_eq!(e.feed_encoder_stream(&[0x20]), Err(Error::Capacity(221)));
        let mut e = d.clone();
        assert_eq!(e.feed_encoder_stream(&[0xc0 | 0x3f, 99 - 63, 0]), Err(Error::StaticIndex(99)));
        let mut e = d.clone();
        assert_eq!(e.feed_encoder_stream(&[0x80, 0]), Err(Error::DynamicIndex(0)));
        let mut e = d.clone();
        assert_eq!(e.feed_encoder_stream(&[0x00]), Err(Error::DynamicIndex(0)));
        let mut e = d.clone();
        assert_eq!(e.feed_encoder_stream(&[0x41, b'a', 0x01, b'b']), Err(Error::EntryTooLarge));
        // Field section errors.
        assert_eq!(d.decode_section(0, &[]), Err(Error::Truncated));
        assert_eq!(d.decode_section(0, &[0x00]), Err(Error::Truncated));
        assert_eq!(d.decode_section(0, &[0x00, 0x00, 0x51]), Err(Error::Truncated));
        assert_eq!(d.decode_section(0, &[0x00, 0x00, 0xff, 0x24]), Err(Error::StaticIndex(99)));
        assert_eq!(d.decode_section(0, &[0x00, 0x00, 0x80]), Err(Error::DynamicIndex(0)));
        assert_eq!(d.decode_section(0, &[0x00, 0x00, 0x10]), Err(Error::DynamicIndex(0)));
        assert_eq!(d.decode_section(0, &[0x0e, 0x00]), Err(Error::InsertCount));
        assert_eq!(d.decode_section(0, &[0x00, 0x80]), Err(Error::Base));
        let mut big = vec![0x00, 0x00];
        for _ in 0..10 {
            big.push(0xc0 | 31); // static 31: 64 bytes counted
        }
        assert_eq!(d.decode_section(0, &big), Err(Error::FieldSectionTooLarge));
        assert_eq!(d.decode_section(0, &vec![0; MAX_SECTION_BYTES + 1]), Err(Error::FieldSectionTooLarge));
        // Blocked streams: one allowed.
        assert_eq!(d.decode_section(0, &[0x02, 0x00, 0x80]), Ok(Section::Blocked));
        assert_eq!(d.decode_section(4, &[0x02, 0x00, 0x80]), Err(Error::TooManyBlocked));
        // A section that asks for more inserts than it uses.
        d.feed_encoder_stream(&[0x3f, 0xbd, 0x01, 0x41, b'a', 0x01, b'b', 0x41, b'c', 0x01, b'd']).unwrap();
        assert_eq!(d.unblocked(), [(0, Ok(vec![Field::new("a", "b")]))]);
        assert_eq!(d.decode_section(8, &[0x03, 0x00, 0x81]), Err(Error::InsertCount));
        assert_eq!(d.decode_section(8, &[0x03, 0x00, 0xd1]), Err(Error::InsertCount));
        assert_eq!(fields(d.decode_section(8, &[0x03, 0x00, 0x80, 0x81]).unwrap()).len(), 2);
        // An index at or past the Required Insert Count, post-base.
        assert_eq!(d.decode_section(8, &[0x02, 0x80, 0x10, 0x11]), Err(Error::DynamicIndex(1)));
        assert_eq!(fields(d.decode_section(8, &[0x03, 0x81, 0x10, 0x11]).unwrap()).len(), 2);
        // Too many fields.
        let mut many = vec![0x00, 0x00];
        many.extend(std::iter::repeat_n(0xc0 | 17, MAX_FIELDS + 1));
        let mut wide = Decoder::new(0, 0, MAX_FIELD_SECTION_SIZE);
        assert_eq!(wide.decode_section(0, &many), Err(Error::TooManyFields));
    }

    #[test]
    fn encoder_errors() {
        let mut e = Encoder::new(100, 1 << 16);
        assert_eq!(e.set_capacity(101), Err(Error::Capacity(101)));
        assert_eq!(e.insert(b"a", b"b"), Err(Error::EntryTooLarge));
        assert_eq!(e.insert(&vec![0; MAX_STRING + 1], b""), Err(Error::StringTooLong));
        assert_eq!(e.duplicate(0), Err(Error::DynamicIndex(0)));
        e.set_capacity(100).unwrap();
        assert_eq!(e.insert(b"x-a", b"1"), Ok(0));
        assert_eq!(e.feed_decoder_stream(&[0x01]), Ok(()));
        let section = e.encode_section(4, &[Field::new("x-a", "1")]).unwrap();
        assert_eq!(section, [0x02, 0x00, 0x80]);
        // Entry 0 is in use until stream 4's section is acknowledged.
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Err(Error::Referenced));
        assert_eq!(e.set_capacity(0), Err(Error::Referenced));
        assert_eq!(e.feed_decoder_stream(&[0x84]), Ok(()));
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Ok(1));
        // Decoder stream errors, each latched.
        let mut f = e.clone();
        assert_eq!(f.feed_decoder_stream(&[0x84]), Err(Error::UnknownStream(4)));
        assert_eq!(f.feed_decoder_stream(&[0x48]), Err(Error::UnknownStream(4)));
        let mut f = e.clone();
        assert_eq!(f.feed_decoder_stream(&[0x00]), Err(Error::ZeroIncrement));
        let mut f = e.clone();
        assert_eq!(f.feed_decoder_stream(&[0x02]), Err(Error::Increment));
        let mut f = e.clone();
        assert_eq!(
            f.feed_decoder_stream(&[0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Err(Error::IntegerOverflow)
        );
        // Section errors.
        let mut small = Encoder::new(0, 100);
        assert_eq!(
            small.encode_section(0, &[Field::new(vec![b'n'; 40], vec![b'v'; 40])]),
            Err(Error::FieldSectionTooLarge)
        );
        assert_eq!(small.encode_section(0, &vec![Field::new("a", ""); MAX_FIELDS + 1]), Err(Error::TooManyFields));
        assert_eq!(small.encode_section(0, &[Field::new(vec![0; MAX_STRING + 1], "")]), Err(Error::StringTooLong));
    }

    #[test]
    fn never_index_fields_stay_literal() {
        let mut e = Encoder::new(4096, 1 << 16);
        let mut d = Decoder::new(4096, 0, 1 << 16);
        e.set_capacity(4096).unwrap();
        e.insert(b"x-secret", b"s").unwrap();
        d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
        e.feed_decoder_stream(&d.take_decoder_stream()).unwrap();
        let mut secret = Field::new("x-secret", "s");
        secret.never_index = true;
        let mut auth = Field::new("authorization", "");
        auth.never_index = true;
        let list = vec![secret, auth, Field::new("x-secret", "s")];
        let bytes = e.encode_section(0, &list).unwrap();
        assert_eq!(fields(d.decode_section(0, &bytes).unwrap()), list);
        let (rep, _) = Representation::parse(&bytes[2..]).unwrap();
        assert!(matches!(rep, Representation::LiteralNameRef { never_index: true, .. }));
    }

    #[test]
    fn truncated_sections() {
        let mut e = Encoder::new(4096, 1 << 16);
        let mut d = Decoder::new(4096, 0, 1 << 16);
        e.set_capacity(4096).unwrap();
        e.insert(b"x-one", b"first").unwrap();
        d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
        e.feed_decoder_stream(&d.take_decoder_stream()).unwrap();
        let list = vec![
            Field::new(":status", "200"),
            Field::new("x-one", "first"),
            Field::new("content-type", "text/x-weird"),
            Field::new("x-two", "a longer value that is Huffman-coded"),
        ];
        let bytes = e.encode_section(0, &list).unwrap();
        assert_eq!(fields(d.decode_section(0, &bytes).unwrap()), list);
        for n in 0..bytes.len() {
            match d.clone().decode_section(0, &bytes[..n]) {
                Err(Error::Truncated) | Err(Error::InsertCount) => {}
                Ok(Section::Fields(f)) => assert!(f.len() < list.len() && list.starts_with(&f), "cut at {n}"),
                other => panic!("cut at {n}: {other:?}"),
            }
        }
    }

    #[test]
    fn encoder_and_decoder_stay_in_step() {
        let names: [&[u8]; 6] = [b":path", b"x-id", b"cookie", b"x-long", b"accept", b"x-a"];
        let mut rng = Lcg(7);
        let mut dynamic_sections = 0;
        for round in 0..40 {
            let cap = [0u64, 64, 220, 500, 4096][round % 5];
            let mut e = Encoder::new(cap, 1 << 16);
            let mut d = Decoder::new(cap, 0, 1 << 16);
            if cap > 0 {
                e.set_capacity(cap - rng.below(cap / 2 + 1)).unwrap();
            }
            let mut pending_dec = Vec::new();
            for step in 0..200u64 {
                let field = |rng: &mut Lcg| {
                    let name = names[rng.below(names.len() as u64) as usize];
                    let value = format!("v{}", rng.below(8)).repeat(rng.below(6) as usize + 1);
                    let mut f = Field::new(name, value);
                    f.never_index = rng.below(10) == 0;
                    f
                };
                match rng.below(5) {
                    0 | 1 => {
                        let f = field(&mut rng);
                        let _ = e.insert(&f.name, &f.value);
                    }
                    2 => {
                        let first = e.table().first_index();
                        let n = e.table().insert_count() - first;
                        if n > 0 {
                            let _ = e.duplicate(first + rng.below(n));
                        }
                    }
                    _ => {
                        d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
                        let list: Vec<Field> = (0..rng.below(6)).map(|_| field(&mut rng)).collect();
                        let stream = step * 4;
                        let bytes = e.encode_section(stream, &list).unwrap();
                        dynamic_sections += usize::from(bytes[0] != 0);
                        assert_eq!(fields(d.decode_section(stream, &bytes).unwrap()), list);
                        if rng.below(4) == 0 {
                            d.cancel_stream(stream);
                        }
                    }
                }
                if rng.below(3) == 0 {
                    d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
                }
                pending_dec.extend(d.take_decoder_stream());
                if rng.below(3) == 0 {
                    // Deliver the decoder stream a byte at a time.
                    for b in pending_dec.drain(..) {
                        e.feed_decoder_stream(&[b]).unwrap();
                    }
                }
            }
            d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
            assert_eq!(d.table(), e.table());
        }
        assert!(dynamic_sections > 100, "{dynamic_sections}");
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x9204);
        for round in 0..4000 {
            let mut data = rng.bytes(64);
            // Bias some buffers toward valid-looking starts.
            if round % 3 == 0 && !data.is_empty() {
                data[0] &= 0x3f;
            }
            // The encoder stream, whole and a byte at a time.
            let mut whole = Decoder::new(220, 4, 1 << 12);
            let r1 = whole.feed_encoder_stream(&data);
            let mut bytewise = Decoder::new(220, 4, 1 << 12);
            let mut r2 = Ok(());
            for b in &data {
                r2 = bytewise.feed_encoder_stream(std::slice::from_ref(b));
                if r2.is_err() {
                    break;
                }
            }
            assert_eq!(r1, r2);
            assert_eq!(whole.table(), bytewise.table());
            // The same bytes as a field section, against that table.
            match whole.decode_section(0, &data) {
                Ok(Section::Fields(list)) => {
                    let mut e = Encoder::new(0, 1 << 12);
                    let bytes = e.encode_section(0, &list).unwrap();
                    assert_eq!(fields(Decoder::new(0, 0, 1 << 12).decode_section(0, &bytes).unwrap()), list);
                }
                Ok(Section::Blocked) | Err(_) => {}
            }
            // As single items.
            if let Ok((rep, used)) = Representation::parse(&data) {
                assert!(used <= data.len());
                let bytes = rep.to_bytes();
                assert_eq!(Representation::parse(&bytes), Ok((rep, bytes.len())));
            }
            if let Ok(Some((ins, _))) = EncoderInstruction::parse(&data) {
                let bytes = ins.to_bytes();
                assert_eq!(EncoderInstruction::parse(&bytes), Ok(Some((ins, bytes.len()))));
            }
            if let Ok(Some((ins, _))) = DecoderInstruction::parse(&data) {
                let bytes = ins.to_bytes();
                assert_eq!(DecoderInstruction::parse(&bytes), Ok(Some((ins, bytes.len()))));
            }
            if let Ok(s) = huffman_decode(&data) {
                assert_eq!(huffman_decode(&huffman_encode(&s)), Ok(s));
            }
            // The decoder stream, whole and a byte at a time.
            let mut e1 = Encoder::new(220, 1 << 12);
            let mut e2 = e1.clone();
            let r1 = e1.feed_decoder_stream(&data);
            let mut r2 = Ok(());
            for b in &data {
                r2 = e2.feed_decoder_stream(std::slice::from_ref(b));
                if r2.is_err() {
                    break;
                }
            }
            assert_eq!(r1, r2);
        }
    }

    #[test]
    fn lcg_fuzz_with_a_built_table() {
        // A table with entries, then random sections against it.
        let mut rng = Lcg(42);
        let mut base = Decoder::new(4096, 8, 1 << 14);
        let mut e = Encoder::new(4096, 1 << 14);
        e.set_capacity(4096).unwrap();
        for i in 0..40u32 {
            e.insert(format!("x-h{}", i % 7).as_bytes(), format!("{i}").as_bytes()).unwrap();
        }
        base.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
        for _ in 0..3000 {
            let mut data = vec![rng.below(80) as u8, rng.below(256) as u8];
            data.extend(rng.bytes(40));
            let mut d = base.clone();
            if let Ok(Section::Fields(list)) = d.decode_section(0, &data) {
                assert!(list.iter().map(Field::size).sum::<u64>() <= 1 << 14);
            }
            // Instructions on top of the table, whole and a byte at a time.
            let mut a = base.clone();
            let mut b = base.clone();
            let ra = a.feed_encoder_stream(&data);
            let mut rb = Ok(());
            for byte in &data {
                rb = b.feed_encoder_stream(std::slice::from_ref(byte));
                if rb.is_err() {
                    break;
                }
            }
            assert_eq!(ra, rb);
            assert_eq!(a.table(), b.table());
        }
    }

    #[test]
    fn encoder_keeps_unacknowledged_entries() {
        // RFC 9204 section 2.1.1: an entry is evictable only once the
        // decoder has acknowledged its insert.
        let mut e = Encoder::new(100, 1 << 16);
        e.set_capacity(100).unwrap();
        assert_eq!(e.insert(b"x-a", b"1"), Ok(0)); // 36
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Err(Error::Referenced));
        assert_eq!(e.duplicate(0), Ok(1)); // 72
        assert_eq!(e.duplicate(1), Err(Error::Referenced));
        assert_eq!(e.set_capacity(40), Err(Error::Referenced));
        let mut d = Decoder::new(100, 0, 1 << 16);
        d.feed_encoder_stream(&e.take_encoder_stream()).unwrap();
        assert_eq!(d.table(), e.table());
        // Once both inserts are acknowledged, they may go.
        e.feed_decoder_stream(&[0x02]).unwrap();
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Ok(2));
        assert_eq!(e.table().first_index(), 2);
        assert_eq!(e.set_capacity(0), Err(Error::Referenced));
        e.feed_decoder_stream(&[0x01]).unwrap();
        assert_eq!(e.set_capacity(0), Ok(()));
    }

    #[test]
    fn blocked_streams_are_counted_by_stream() {
        // RFC 9204 section 2.1.2 limits streams, not sections: a header
        // section and a trailer section blocked on one stream count once.
        let mut d = Decoder::new(220, 1, 1 << 16);
        assert_eq!(d.decode_section(0, &[0x02, 0x00, 0x80]), Ok(Section::Blocked));
        assert_eq!(d.decode_section(0, &[0x02, 0x00, 0x80]), Ok(Section::Blocked));
        assert_eq!(d.blocked_streams(), 1);
        assert_eq!(d.decode_section(4, &[0x02, 0x00, 0x80]), Err(Error::TooManyBlocked));
        d.feed_encoder_stream(&[0x3f, 0xbd, 0x01, 0x41, b'a', 0x01, b'b']).unwrap();
        let a = vec![Field::new("a", "b")];
        assert_eq!(d.unblocked(), [(0, Ok(a.clone())), (0, Ok(a))]);
        assert_eq!(d.blocked_streams(), 0);
        assert_eq!(d.take_decoder_stream(), [0x80, 0x80]);
    }

    #[test]
    fn long_instructions_fed_a_byte_at_a_time() {
        // A long Huffman-coded name must not be decoded again for every
        // byte of the value that follows it.
        let ins = EncoderInstruction::InsertWithLiteralName { name: vec![b'0'; 30_000], value: vec![b'1'; 30_000] };
        let bytes = ins.to_bytes();
        let mut d = Decoder::new(MAX_TABLE_CAPACITY, 0, 1 << 16);
        d.feed_encoder_stream(&EncoderInstruction::SetCapacity(MAX_TABLE_CAPACITY).to_bytes()).unwrap();
        let start = std::time::Instant::now();
        for b in &bytes {
            d.feed_encoder_stream(std::slice::from_ref(b)).unwrap();
        }
        assert_eq!(d.table().len(), 1);
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
    }

    #[test]
    fn blocked_sections_are_bounded_on_one_stream() {
        // Empty blocked sections cost no body bytes, so the byte limit
        // alone would let one stream hold any number of them.
        let mut d = Decoder::new(4096, 1, 1 << 16);
        for _ in 0..MAX_BLOCKED_SECTIONS {
            assert_eq!(d.decode_section(0, &[0x02, 0x00]), Ok(Section::Blocked));
        }
        assert_eq!(d.decode_section(0, &[0x02, 0x00]), Err(Error::TooManyBlocked));
        assert_eq!(d.blocked_streams(), 1);
    }

    #[test]
    fn integer_flags_never_spill_into_the_value() {
        let mut out = Vec::new();
        encode_integer(&mut out, 5, 0xff, 3);
        assert_eq!(out, [0xe3]);
        assert_eq!(decode_integer(&out, 5), Ok(Some((3, 1))));
    }
}
