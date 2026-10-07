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
//! integer format and the Huffman code. The shared coder lives in
//! [`huffman`].
//!
//! A server reads encoder instructions with
//! [`Stream<EncoderInstructions>`](fictionet::stdlib::codec::Stream) and applies each to
//! a [`Table`]. [`decode_section`] returns fields and an acknowledgment or a
//! [`BlockedSection`] to hold and retry. [`BlockedSections`] bounds that queue.
//! [`Encoder`] returns instruction and field-section values. Write those values
//! with [`Wire::write`] and apply peer acknowledgments between decoded items.
//! The encoder only references entries the peer has acknowledged.
//!
//! ```
//! use fictionet::stdlib::{codec::Wire, qpack::{self, Encoder, Field, Table, SectionResult}};
//!
//! // RFC 9204 Appendix B.1: a literal value with static name entry 1.
//! let mut bytes = vec![0x00, 0x00, 0x51, 0x0b];
//! bytes.extend_from_slice(b"/index.html");
//! let SectionResult::Fields { fields, ack } = qpack::decode_section(&Table::new(4096), 0, &bytes).unwrap()
//!     else { panic!("section is blocked") };
//! assert_eq!(fields, [Field::new(":path", "/index.html")]);
//! assert_eq!(ack, None);
//!
//! let mut encoder = Encoder::new(4096, 16 << 10);
//! let mut table = Table::new(4096);
//! table.apply(encoder.set_capacity(4096).unwrap()).unwrap();
//! let (_, instruction) = encoder.insert(b"x-trace", b"abc").unwrap();
//! table.apply(instruction).unwrap();
//! encoder.apply_instruction(table.take_increment().unwrap()).unwrap();
//! let fields = vec![Field::new(":method", "GET"), Field::new("x-trace", "abc")];
//! let section = encoder.section(4, &fields).unwrap();
//! let bytes = section.to_bytes().unwrap();
//! // Prefix, then static entry 17 and dynamic entry 0: four bytes.
//! assert_eq!(bytes.len(), 4);
//! let SectionResult::Fields { fields: back, ack } = qpack::decode_section(&table, 4, &bytes).unwrap()
//!     else { panic!("section is blocked") };
//! assert_eq!(back, fields);
//! encoder.apply_instruction(ack.unwrap()).unwrap();
//! ```

use std::collections::VecDeque;

use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::{huffman, prefix_int};

/// The largest integer a reader accepts, 2^62 - 1, the largest QUIC stream
/// ID. Larger values cannot be written.
pub const MAX_INTEGER: u64 = (1 << 62) - 1;
/// The longest string before or after Huffman decoding.
pub const MAX_STRING: usize = huffman::MAX_STRING;
/// The largest dynamic table capacity. A larger maximum given to
/// [`Table::new`] or [`Encoder::new`] still sets how Required Insert
/// Counts are encoded, as RFC 9204 requires, but the table never grows past
/// this. A decoder refuses a larger capacity, so a world should not
/// advertise more.
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
/// to [`BlockedSections::new`] is lowered to it.
pub const MAX_BLOCKED_STREAMS: usize = 256;
/// The most bytes of field sections a decoder holds: those waiting for
/// inserts in [`BlockedSections`].
pub const MAX_BLOCKED_BYTES: usize = 1 << 20;
/// The most field sections a decoder holds, counted as for
/// [`MAX_BLOCKED_BYTES`]. One stream may have several, such as a header and
/// a trailer section.
pub const MAX_BLOCKED_SECTIONS: usize = 4 * MAX_BLOCKED_STREAMS;
/// The longest encoder stream instruction: a byte, two integers and two
/// strings. A reader of either stream holds at most this many bytes of an
/// unfinished instruction, plus at most this many more while it reads.
pub const MAX_INSTRUCTION: usize = 2 * (10 + MAX_STRING);
/// Maximum encoded prefixed integer: one prefix byte and nine continuation bytes.
/// Every decoder-stream instruction consists of exactly one such integer.
pub const MAX_INTEGER_BYTES: usize = 10;
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
    /// A field section larger than the limit on field section size.
    FieldSectionTooLarge,
    /// A field section with more than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// An encoder change would evict an entry that is not evictable: one a
    /// field section not yet acknowledged refers to, or one whose insert
    /// the decoder has not acknowledged.
    Referenced,
    /// The value cannot be written without changing it.
    Unwritable,
    /// An exact parse ran out of input before a complete value, including
    /// empty input.
    Incomplete,
    /// Bytes follow the first complete value of an exact parse.
    Trailing,
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
            Error::FieldSectionTooLarge => f.write_str("field section too large"),
            Error::TooManyFields => f.write_str("too many fields"),
            Error::Referenced => f.write_str("would evict an entry still in use"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Incomplete => f.write_str("input ended before a complete QPACK value"),
            Error::Trailing => f.write_str("bytes follow the QPACK value"),
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

    /// An integer with a `prefix`-bit prefix, 1 to 8 bits.
    fn int(&mut self, prefix: u8) -> Result<u64, Stop> {
        let bytes = self.b.get(self.i..).ok_or(Stop::More)?;
        let bounded = &bytes[..bytes.len().min(MAX_INTEGER_BYTES)];
        let (value, used) = prefix_int::read(bounded, prefix).map_err(|error| match error {
            prefix_int::Error::Truncated if bytes.len() < MAX_INTEGER_BYTES => Stop::More,
            _ => Stop::Bad(Error::IntegerOverflow),
        })?;
        if value > MAX_INTEGER {
            return Err(Error::IntegerOverflow.into());
        }
        self.i = self.i.checked_add(used).ok_or(Error::IntegerOverflow)?;
        Ok(value)
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
/// field line is there, so bytes pushed one at a time cost linear time.
struct RawString<'a> {
    huffman: bool,
    bytes: &'a [u8],
}

impl RawString<'_> {
    fn decode(&self) -> Result<Vec<u8>, Error> {
        if self.huffman {
            huffman::decode(self.bytes).map_err(|error| match error {
                huffman::Error::TooLong => Error::StringTooLong,
                _ => Error::Huffman,
            })
        } else {
            Ok(self.bytes.to_vec())
        }
    }
}

fn put_integer(out: &mut Vec<u8>, prefix: u8, flags: u8, value: u64) -> Result<(), Error> {
    prefix_int::write(out, prefix, flags, value).map_err(|_| Error::Unwritable)
}

fn parse_stop(stop: Stop) -> Error {
    match stop {
        Stop::More => Error::Incomplete,
        Stop::Bad(error) => error,
    }
}

fn exact<T>(result: Result<(T, usize), Error>, len: usize) -> Result<T, Error> {
    let (value, used) = result?;
    if used != len {
        return Err(Error::Trailing);
    }
    Ok(value)
}

/// Appends `s` as a string with a `prefix`-bit length, Huffman-coded if
/// that is shorter. Callers check [`MAX_STRING`] first.
fn put_string(out: &mut Vec<u8>, prefix: u8, flags: u8, s: &[u8]) -> Result<(), Error> {
    let h = huffman::encoded_len(s).map_err(|_| Error::Unwritable)?;
    if h < s.len() {
        put_integer(out, prefix, flags | (1 << prefix), h as u64)?;
        huffman::encode(s, out).map_err(|_| Error::Unwritable)?;
    } else {
        put_integer(out, prefix, flags, s.len() as u64)?;
        out.extend_from_slice(s);
    }
    Ok(())
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
    (name.len() as u64).saturating_add(value.len() as u64).saturating_add(ENTRY_OVERHEAD)
}

/// The dynamic table: entries inserted in order, each with an absolute
/// index counting from 0, the oldest evicted first when room is needed.
/// Both sides of a connection keep one, and keep it the same.
///
/// Byte decoders do not borrow or modify it. The receiver applies one
/// instruction between items and lends the table to [`decode_section`].
/// Blocked sections and output bytes stay with the caller. The encoding
/// role uses [`Encoder`] to protect entries awaiting acknowledgment.
/// Section decoding borrows `&Table`: entries are read-only, while a
/// [`core::cell::Cell`] tracks reported inserts. This makes the table `!Sync`.
/// Send every returned Section Ack, even if its stream is reset and a Stream
/// Cancel is also sent. Decoding already counts the ack as reported; dropping
/// it would make later [`Table::take_increment`] values too small.
/// Send acknowledgments in return order before taking an increment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: u64,
    capacity: u64,
    max_capacity: u64,
    advertised: u64,
    inserted: u64,
    reported: core::cell::Cell<u64>,
}

impl Table {
    /// An empty table with capacity 0, for a decoder that advertised
    /// `max_capacity` as its SETTINGS_QPACK_MAX_TABLE_CAPACITY. The
    /// capacity may grow to `max_capacity` lowered to
    /// [`MAX_TABLE_CAPACITY`]; Required Insert Counts are encoded with
    /// `max_capacity` as advertised.
    pub fn new(max_capacity: u64) -> Table {
        Table {
            entries: VecDeque::new(),
            size: 0,
            capacity: 0,
            max_capacity: max_capacity.min(MAX_TABLE_CAPACITY),
            advertised: max_capacity,
            inserted: 0,
            reported: core::cell::Cell::new(0),
        }
    }

    /// The most the capacity may be: the decoder's
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY, lowered to [`MAX_TABLE_CAPACITY`].
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

    /// MaxEntries of RFC 9204 section 3.2.2: the advertised maximum
    /// capacity over 32, before it is lowered to [`MAX_TABLE_CAPACITY`].
    /// Required Insert Counts are encoded with it.
    pub fn max_entries(&self) -> u64 {
        self.advertised / ENTRY_OVERHEAD
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
    /// [`Error::EntryTooLarge`]. Strings above [`MAX_STRING`] and an exhausted
    /// insert-count range are refused. Errors leave the table unchanged.
    pub fn insert(&mut self, mut name: Vec<u8>, mut value: Vec<u8>) -> Result<u64, Error> {
        check_strings(&name, &value)?;
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return Err(Error::EntryTooLarge);
        }
        let index = self.inserted;
        self.inserted = index.checked_add(1).filter(|n| *n <= MAX_INTEGER).ok_or(Error::IntegerOverflow)?;
        self.evict_to(self.capacity - size);
        self.size += size;
        name.shrink_to_fit();
        value.shrink_to_fit();
        self.entries.push_back((name, value));
        Ok(index)
    }

    /// Applies one encoder instruction between decoded items.
    /// Errors leave the table unchanged. Application errors are session
    /// decisions; the instruction decoder only establishes its boundary.
    pub fn apply(&mut self, instruction: EncoderInstruction) -> Result<(), Error> {
        check_encoder_instruction(&instruction)?;
        let (name, value) = match instruction {
            EncoderInstruction::SetCapacity(n) => return self.set_capacity(n),
            EncoderInstruction::InsertWithLiteralName { name, value } => (name, value),
            EncoderInstruction::InsertWithNameRef { static_table: true, index, value } => {
                let (name, _) = static_entry(index).ok_or(Error::StaticIndex(index))?;
                (name.as_bytes().to_vec(), value)
            }
            EncoderInstruction::InsertWithNameRef { static_table: false, index, value } => {
                let (name, _) = self.get_relative(index).ok_or(Error::DynamicIndex(index))?;
                (name.to_vec(), value)
            }
            EncoderInstruction::Duplicate(index) => {
                let (name, value) = self.get_relative(index).ok_or(Error::DynamicIndex(index))?;
                (name.to_vec(), value.to_vec())
            }
        };
        self.insert(name, value)?;
        Ok(())
    }
    /// Takes an Insert Count Increment for received inserts not yet reported.
    /// Section acknowledgments returned by [`decode_section`] or
    /// [`BlockedSection::retry`] already report their Required Insert Counts.
    /// Send those values first, then this value, on the decoder stream.
    /// No bytes are queued; a second call without new inserts returns `None`.
    pub fn take_increment(&mut self) -> Option<DecoderInstruction> {
        let count = self.insert_count();
        let increment = count.saturating_sub(self.reported.get());
        self.reported.set(count);
        (increment != 0).then_some(DecoderInstruction::InsertCountIncrement(increment))
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
pub enum EncoderInstruction {
    /// Set the table's capacity.
    SetCapacity(u64),
    /// Insert an entry with `value` and the name of static entry `index`,
    /// or of the dynamic entry at relative `index` (0 is the newest).
    InsertWithNameRef {
        /// Whether the index refers to the static table.
        static_table: bool,
        /// The table index described by this variant.
        index: u64,
        /// The field value bytes.
        value: Vec<u8>,
    },
    /// Insert an entry with this name and value.
    InsertWithLiteralName {
        /// The field name bytes.
        name: Vec<u8>,
        /// The field value bytes.
        value: Vec<u8>,
    },
    /// Insert a copy of the dynamic entry at this relative index.
    Duplicate(u64),
}

impl EncoderInstruction {
    /// Reads the instruction at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the instruction and how
    /// many bytes it took.
    fn parse_prefix(b: &[u8]) -> Result<Option<(EncoderInstruction, usize)>, Error> {
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
    fn parse_prefix(b: &[u8]) -> Result<Option<(DecoderInstruction, usize)>, Error> {
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

    /// The wire prefix for a decoder with `max_entries`. A nonzero
    /// count with `max_entries` 0, or a Base more than [`MAX_INTEGER`] from
    /// the count, is an error. The prefix reads back the same only if the
    /// decoder's insert count is within `max_entries` of the required one,
    /// as it is when the section's entries are in its table.
    pub fn encoded(&self, max_entries: u64) -> Result<EncodedPrefix, Error> {
        let required = self.required_insert_count;
        let encoded = encode_insert_count(required, max_entries).ok_or(Error::Unwritable)?;
        if encoded > MAX_INTEGER {
            return Err(Error::Unwritable);
        }
        let negative = self.base < required;
        let delta_base = if negative { required - self.base - 1 } else { self.base - required };
        if delta_base > MAX_INTEGER {
            return Err(Error::Unwritable);
        }
        Ok(EncodedPrefix { encoded_insert_count: encoded, negative, delta_base })
    }
}

/// The two encoded integers at the start of a field section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedPrefix {
    /// Required Insert Count modulo the advertised table size.
    pub encoded_insert_count: u64,
    /// Whether Base is below Required Insert Count.
    pub negative: bool,
    /// The difference used to recover Base.
    pub delta_base: u64,
}

impl EncodedPrefix {
    fn parse_prefix(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let mut c = Cursor { b: bytes, i: 0 };
        let encoded_insert_count = c.int(8).map_err(parse_stop)?;
        let negative = c.peek().map_err(parse_stop)? & 0x80 != 0;
        let delta_base = c.int(7).map_err(parse_stop)?;
        Ok((Self { encoded_insert_count, negative, delta_base }, c.i))
    }
}

impl Wire for EncodedPrefix {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one prefix. Refuses overflowing integers, truncation, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(Self::parse_prefix(bytes), bytes.len())
    }

    /// Writes one prefix. Refuses integers above [`MAX_INTEGER`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.encoded_insert_count > MAX_INTEGER || self.delta_base > MAX_INTEGER {
            return Err(Error::Unwritable);
        }
        put_integer(out, 8, 0, self.encoded_insert_count)?;
        put_integer(
            out,
            7,
            if self.negative { 0x80 } else { 0 },
            self.delta_base,
        )?;
        Ok(())
    }
}

/// An encoded field section before references are resolved against a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSection {
    /// Insert-count and Base information.
    pub prefix: EncodedPrefix,
    /// Field lines in their transmitted order.
    pub representations: Vec<Representation>,
}

impl Wire for FieldSection {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete section. Refuses malformed lines, truncation, and section size or count limits.
    /// Table-dependent reference checks belong to [`decode_section`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SECTION_BYTES {
            return Err(Error::FieldSectionTooLarge);
        }
        let (prefix, mut used) = EncodedPrefix::parse_prefix(bytes)?;
        let mut representations = Vec::new();
        while used < bytes.len() {
            if representations.len() == MAX_FIELDS {
                return Err(Error::TooManyFields);
            }
            let (rep, n) = Representation::parse_prefix(&bytes[used..]).map_err(|e| match e {
                Error::Truncated => Error::Incomplete,
                other => other,
            })?;
            used += n;
            representations.push(rep);
        }
        Ok(Self { prefix, representations })
    }

    /// Writes a complete section. Refuses invalid lines and excessive encoded size or field count.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.representations.len() > MAX_FIELDS {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        self.prefix.write(&mut bytes)?;
        for rep in &self.representations {
            rep.write(&mut bytes)?;
            if bytes.len() > MAX_SECTION_BYTES {
                return Err(Error::Unwritable);
            }
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// One field line of an encoded field section.
/// A section resolves these references against its prefix and dynamic table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Representation {
    /// The whole field from static entry `index`, or from the dynamic
    /// entry at relative `index` (Base - 1 - `index` is its absolute
    /// index).
    Indexed {
        /// Whether the index refers to the static table.
        static_table: bool,
        /// The table index described by this variant.
        index: u64,
    },
    /// The whole field from the dynamic entry whose absolute index is Base
    /// plus this number.
    IndexedPostBase(u64),
    /// The name from a static or relative dynamic entry, and `value`.
    LiteralNameRef {
        /// Whether the field must remain a literal when forwarded.
        never_index: bool,
        /// Whether the index refers to the static table.
        static_table: bool,
        /// The table index described by this variant.
        index: u64,
        /// The field value bytes.
        value: Vec<u8>,
    },
    /// The name from the dynamic entry with absolute index Base + `index`,
    /// and `value`.
    LiteralPostBaseNameRef {
        /// Whether the field must remain a literal when forwarded.
        never_index: bool,
        /// The table index described by this variant.
        index: u64,
        /// The field value bytes.
        value: Vec<u8>,
    },
    /// The name and value spelled out.
    LiteralName {
        /// Whether the field must remain a literal when forwarded.
        never_index: bool,
        /// The field name bytes.
        name: Vec<u8>,
        /// The field value bytes.
        value: Vec<u8>,
    },
}

impl Representation {
    /// Reads the field line at the start of `b`, and returns it and its
    /// length. A field line cut short is [`Error::Truncated`].
    fn parse_prefix(b: &[u8]) -> Result<(Representation, usize), Error> {
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
}

/// Decodes the field lines after a section's prefix.
fn decode_fields(table: &Table, prefix: SectionPrefix, b: &[u8], limit: u64) -> Result<Vec<Field>, Error> {
    let SectionPrefix { required_insert_count: required, base } = prefix;
    let mut fields = Vec::new();
    let mut size = 0u64;
    let mut largest: Option<u64> = None;
    let mut i = 0;
    // The entry at absolute index `abs`, which must be below the Required
    // Insert Count; `sent` is the index as the field line gave it.
    fn lookup<'t>(
        table: &'t Table,
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
        let (rep, used) = Representation::parse_prefix(&b[i..])?;
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
    table: Table,
    field_limit: u64,
    known_received: u64,
    outstanding: VecDeque<Outstanding>,
}

impl Encoder {
    /// An encoder for a peer that advertised this
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    /// SETTINGS_MAX_FIELD_SECTION_SIZE. Each is lowered to this module's
    /// limit, except that Required Insert Counts are written with the table
    /// capacity as advertised. The table starts with capacity 0.
    pub fn new(max_table_capacity: u64, max_field_section_size: u64) -> Encoder {
        Encoder {
            table: Table::new(max_table_capacity),
            field_limit: max_field_section_size.min(MAX_FIELD_SECTION_SIZE),
            known_received: 0,
            outstanding: VecDeque::new(),
        }
    }

    /// The dynamic table as the encoder has built it.
    pub fn table(&self) -> &Table {
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

    /// Sets the table's capacity and returns the instruction. A capacity
    /// above the maximum is [`Error::Capacity`]. One that would evict an
    /// entry in use, or one whose insert the decoder has not acknowledged,
    /// is [`Error::Referenced`].
    /// On an error nothing changes.
    pub fn set_capacity(&mut self, capacity: u64) -> Result<EncoderInstruction, Error> {
        if capacity > self.table.max_capacity() {
            return Err(Error::Capacity(capacity));
        }
        self.room(0, capacity)?;
        self.table.set_capacity(capacity)?;
        Ok(EncoderInstruction::SetCapacity(capacity))
    }

    /// Inserts an entry and returns the instruction, naming the static or
    /// dynamic entry with the same name when there is one. It returns the
    /// entry's absolute index and the instruction. A name or value longer than [`MAX_STRING`]
    /// is [`Error::StringTooLong`], and an entry larger than the capacity
    /// [`Error::EntryTooLarge`]. One that would evict an entry in use, or
    /// one whose insert the decoder has not acknowledged, is
    /// [`Error::Referenced`].
    /// On an error nothing changes.
    pub fn insert(&mut self, name: &[u8], value: &[u8]) -> Result<(u64, EncoderInstruction), Error> {
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
        Ok((abs, ins))
    }

    /// Inserts a copy of the entry at absolute index `index` and returns the
    /// instruction, which keeps a used entry from being evicted. It
    /// returns the copy's absolute index and the instruction. It fails as [`Encoder::insert`]
    /// does, and with [`Error::DynamicIndex`] if the table does not hold
    /// the entry.
    pub fn duplicate(&mut self, index: u64) -> Result<(u64, EncoderInstruction), Error> {
        let (n, v) = self.table.get(index).ok_or(Error::DynamicIndex(index))?;
        let (n, v) = (n.to_vec(), v.to_vec());
        self.room(entry_size(&n, &v), self.table.capacity())?;
        let relative = self.table.insert_count() - 1 - index;
        let abs = self.table.insert(n, v)?;
        Ok((abs, EncoderInstruction::Duplicate(relative)))
    }

    /// Builds a field section from `fields` for `stream`, a QUIC stream ID below 2^62. Each
    /// field uses a static entry, or a dynamic entry the decoder has
    /// acknowledged, when one matches; otherwise it is written as a
    /// literal. A section past the peer's field section size limit is
    /// [`Error::FieldSectionTooLarge`], one with more than [`MAX_FIELDS`]
    /// fields [`Error::TooManyFields`], and a name or value longer than
    /// [`MAX_STRING`] [`Error::StringTooLong`]. A stream above [`MAX_INTEGER`]
    /// is refused with [`Error::Unwritable`].
    pub fn section(&mut self, stream: u64, fields: &[Field]) -> Result<FieldSection, Error> {
        if stream > MAX_INTEGER {
            return Err(Error::Unwritable);
        }
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
        let prefix = prefix.encoded(self.table.max_entries())?;
        let mut representations = Vec::with_capacity(fields.len());
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
            representations.push(rep);
        }
        if let Some(oldest) = oldest {
            self.outstanding.push_back(Outstanding { stream, required, oldest });
        }
        Ok(FieldSection { prefix, representations })
    }

    /// Applies one decoded peer instruction between items.
    ///
    /// Pair with [`DecoderInstructions`] and [`fictionet::stdlib::codec::Stream`]. This
    /// resolves Section Acknowledgments against this session's outstanding
    /// sections and updates its known received count. Errors do not change
    /// session state; the caller must enforce the QPACK connection policy.
    pub fn apply_instruction(&mut self, instruction: DecoderInstruction) -> Result<(), Error> {
        check_decoder_instruction(&instruction)?;
        self.apply(instruction)
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

// ---------------------------------------------------------------------
// Slice decoders and caller-owned session state.

/// Reads one encoder instruction per call without owning input.
///
/// Use with [`fictionet::stdlib::codec::Stream`]. Integer overflow and excessive string
/// lengths end framing. A complete instruction with invalid contents is an
/// error item. Apply successful items with [`Table::apply`] between calls.
/// Partial instructions return [`Step::Need`], including at EOF.
#[derive(Clone, Copy, Debug, Default)]
pub struct EncoderInstructions;

impl EncoderInstructions {
    /// Creates a decoder bounded by [`MAX_INSTRUCTION`].
    pub fn new() -> Self {
        Self
    }
}

// Find the boundary without decoding strings. Even a bad Huffman string
// has a trusted length, so its error consumes exactly one instruction.
fn encoder_instruction_len(input: &[u8]) -> Result<Option<usize>, Error> {
    let mut c = Cursor { b: input, i: 0 };
    let scan = |c: &mut Cursor<'_>| -> Result<(), Stop> {
        let first = c.peek()?;
        if first & 0x80 != 0 {
            c.int(6)?;
            c.raw_string(7)?;
        } else if first & 0x40 != 0 {
            c.raw_string(5)?;
            c.raw_string(7)?;
        } else {
            c.int(5)?;
        }
        Ok(())
    };
    match scan(&mut c) {
        Ok(()) => Ok(Some(c.i)),
        Err(Stop::More) => Ok(None),
        Err(Stop::Bad(e)) => Err(e),
    }
}

fn check_encoder_instruction(ins: &EncoderInstruction) -> Result<(), Error> {
    match ins {
        EncoderInstruction::SetCapacity(n) if *n > MAX_TABLE_CAPACITY => Err(Error::Capacity(*n)),
        EncoderInstruction::Duplicate(n) if *n > MAX_INTEGER => Err(Error::IntegerOverflow),
        EncoderInstruction::InsertWithNameRef { static_table, index, value } => {
            if *index > MAX_INTEGER {
                return Err(Error::IntegerOverflow);
            }
            if *static_table && static_entry(*index).is_none() {
                return Err(Error::StaticIndex(*index));
            }
            check_strings(&[], value)
        }
        EncoderInstruction::InsertWithLiteralName { name, value } => check_strings(name, value),
        _ => Ok(()),
    }
}

fn check_strings(name: &[u8], value: &[u8]) -> Result<(), Error> {
    if name.len() > MAX_STRING || value.len() > MAX_STRING { Err(Error::StringTooLong) } else { Ok(()) }
}

impl Decode for EncoderInstructions {
    type Item = Result<EncoderInstruction, Error>;
    type Error = Error;
    const NAME: &'static str = "QPACK encoder stream";

    fn capacity(&self) -> usize {
        MAX_INSTRUCTION
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        let Some(used) = encoder_instruction_len(input)? else { return Ok(Step::Need) };
        let bytes = input.get(..used).ok_or(Error::Truncated)?;
        let item = EncoderInstruction::parse_prefix(bytes).and_then(|parsed| {
            let (ins, _) = parsed.ok_or(Error::Truncated)?;
            check_encoder_instruction(&ins)?;
            Ok(ins)
        });
        Ok(Step::Item(item, used))
    }
}

/// Reads one decoder instruction per call without owning input.
///
/// Zero increments are error items. Integer overflow ends framing. Partial
/// integers return [`Step::Need`], so [`fictionet::stdlib::codec::Stream`] reports EOF
/// truncation. Stream acknowledgments need the caller's section metadata;
/// call [`Encoder::apply_instruction`] between items. This decoder has no
/// table or pending output queue.
#[derive(Clone, Copy, Debug, Default)]
pub struct DecoderInstructions;

impl DecoderInstructions {
    /// Creates a decoder bounded by [`MAX_INTEGER_BYTES`].
    pub fn new() -> Self {
        Self
    }
}

impl Decode for DecoderInstructions {
    type Item = Result<DecoderInstruction, Error>;
    type Error = Error;
    const NAME: &'static str = "QPACK decoder stream";

    fn capacity(&self) -> usize {
        MAX_INTEGER_BYTES
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        Ok(match DecoderInstruction::parse_prefix(input)? {
            Some((DecoderInstruction::InsertCountIncrement(0), used)) => Step::Item(Err(Error::ZeroIncrement), used),
            Some((ins, used)) => Step::Item(Ok(ins), used),
            None => Step::Need,
        })
    }
}

/// Strict encoding and exact parsing. SetCapacity is limited to
/// [`MAX_TABLE_CAPACITY`] in both directions, even if the peer advertises more.
impl Wire for EncoderInstruction {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one instruction. Refuses truncation, trailing bytes, integer overflow,
    /// invalid Huffman strings, oversized strings or capacity, and invalid static name indexes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = match EncoderInstructions.decode(bytes, true)? {
            Step::Item(item, used) => Ok((item, used)),
            _ => Err(Error::Incomplete),
        };
        exact(parsed, bytes.len())?
    }

    /// Writes one instruction, using Huffman strings when shorter. Refuses oversized strings,
    /// integer overflow, capacity above MAX_TABLE_CAPACITY, and invalid static name indexes.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        check_encoder_instruction(self).map_err(|_| Error::Unwritable)?;
        match self {
            EncoderInstruction::SetCapacity(c) => put_integer(out, 5, 0x20, *c)?,
            EncoderInstruction::InsertWithNameRef { static_table, index, value } => {
                put_integer(out, 6, if *static_table { 0xc0 } else { 0x80 }, *index)?;
                put_string(out, 7, 0, value)?;
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                put_string(out, 5, 0x40, name)?;
                put_string(out, 7, 0, value)?;
            }
            EncoderInstruction::Duplicate(i) => put_integer(out, 5, 0, *i)?,
        }
        Ok(())
    }
}

fn check_decoder_instruction(instruction: &DecoderInstruction) -> Result<(), Error> {
    let n = match instruction {
        DecoderInstruction::SectionAck(n) | DecoderInstruction::StreamCancel(n) => *n,
        DecoderInstruction::InsertCountIncrement(0) => return Err(Error::ZeroIncrement),
        DecoderInstruction::InsertCountIncrement(n) => *n,
    };
    if n > MAX_INTEGER {
        return Err(Error::IntegerOverflow);
    }
    Ok(())
}

impl Wire for DecoderInstruction {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one instruction. Refuses truncation, trailing bytes, overflow, and zero increments.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = match DecoderInstructions.decode(bytes, true)? {
            Step::Item(item, used) => Ok((item, used)),
            _ => Err(Error::Incomplete),
        };
        exact(parsed, bytes.len())?
    }

    /// Writes one instruction. Refuses integers above MAX_INTEGER and zero increments.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        check_decoder_instruction(self).map_err(|_| Error::Unwritable)?;
        match self {
            DecoderInstruction::SectionAck(s) => put_integer(out, 7, 0x80, *s)?,
            DecoderInstruction::StreamCancel(s) => put_integer(out, 6, 0x40, *s)?,
            DecoderInstruction::InsertCountIncrement(n) => put_integer(out, 6, 0, *n)?,
        }
        Ok(())
    }
}

impl Wire for Representation {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one field line. Refuses truncation, trailing bytes, overflow, invalid Huffman
    /// strings, and excessive string lengths. Table references are resolved by decode_section.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = Self::parse_prefix(bytes).map_err(|e| match e {
            Error::Truncated => Error::Incomplete,
            other => other,
        });
        exact(parsed, bytes.len())
    }

    /// Writes one field line, using Huffman strings when shorter. Refuses integers above
    /// MAX_INTEGER and strings longer than MAX_STRING.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (index, name, value): (u64, &[u8], &[u8]) = match self {
            Self::Indexed { index, .. } | Self::IndexedPostBase(index) => (*index, &[], &[]),
            Self::LiteralNameRef { index, value, .. } | Self::LiteralPostBaseNameRef { index, value, .. } => {
                (*index, &[], value)
            }
            Self::LiteralName { name, value, .. } => (0, name, value),
        };
        if index > MAX_INTEGER {
            return Err(Error::Unwritable);
        }
        check_strings(name, value).map_err(|_| Error::Unwritable)?;
        match self {
            Representation::Indexed {
                static_table,
                index,
            } => put_integer(out, 6, if *static_table { 0xc0 } else { 0x80 }, *index)?,
            Representation::IndexedPostBase(index) => put_integer(out, 4, 0x10, *index)?,
            Representation::LiteralNameRef { never_index, static_table, index, value } => {
                let flags = 0x40 | if *never_index { 0x20 } else { 0 } | if *static_table { 0x10 } else { 0 };
                put_integer(out, 4, flags, *index)?;
                put_string(out, 7, 0, value)?;
            }
            Representation::LiteralPostBaseNameRef { never_index, index, value } => {
                put_integer(out, 3, if *never_index { 0x08 } else { 0 }, *index)?;
                put_string(out, 7, 0, value)?;
            }
            Representation::LiteralName { never_index, name, value } => {
                put_string(out, 3, if *never_index { 0x30 } else { 0x20 }, name)?;
                put_string(out, 7, 0, value)?;
            }
        }
        Ok(())
    }
}

/// The value produced by [`decode_section`]. No result is queued internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionResult {
    /// A decoded section and the acknowledgment to send, if it used entries.
    Fields {
        /// Fields in their original order, under the section and field limits.
        fields: Vec<Field>,
        /// The instruction the caller must write to its decoder stream.
        ack: Option<DecoderInstruction>,
    },
    /// A bounded section the caller can hold and retry when inserts arrive.
    Blocked(BlockedSection),
}

/// A field section waiting for inserts, owned by the caller.
///
/// Retains its decoded prefix so insert-count wrapping cannot change its
/// meaning on retry. Each body is bounded by [`MAX_SECTION_BYTES`]. Use
/// [`BlockedSections`] to enforce connection-wide blocked limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedSection {
    stream: u64,
    prefix: SectionPrefix,
    body: Vec<u8>,
    field_limit: u64,
}

impl BlockedSection {
    /// The stream whose section is waiting.
    pub fn stream_id(&self) -> u64 {
        self.stream
    }
    /// The insert count needed before this section can be decoded.
    pub fn required_insert_count(&self) -> u64 {
        self.prefix.required_insert_count
    }
    /// The encoded field bytes retained, excluding the already read prefix.
    pub fn buffered(&self) -> usize {
        self.body.len()
    }
    /// Retries using the original prefix. If still blocked, returns this
    /// value unchanged. Successful decoding returns its acknowledgment.
    /// Every returned acknowledgment must be sent, even on stream reset;
    /// see [`Table`] for the reported-count and ordering requirements.
    pub fn retry(self, table: &Table) -> Result<SectionResult, Error> {
        if self.required_insert_count() > table.insert_count() {
            return Ok(SectionResult::Blocked(self));
        }
        section_fields(table, self.stream, self.prefix, &self.body, self.field_limit)
    }
}

fn section_fields(
    table: &Table,
    stream: u64,
    prefix: SectionPrefix,
    body: &[u8],
    limit: u64,
) -> Result<SectionResult, Error> {
    let fields = decode_fields(table, prefix, body, limit)?;
    let ack = (prefix.required_insert_count != 0).then_some(DecoderInstruction::SectionAck(stream));
    table.reported.set(table.reported.get().max(prefix.required_insert_count));
    Ok(SectionResult::Fields { fields, ack })
}

/// Decodes a field section using session-owned state and the default limits.
///
/// Returns fields and an acknowledgment, or a caller-owned blocked value.
/// A blocked value must be retried through [`BlockedSection::retry`] so its
/// original Required Insert Count is preserved across wrapping. Applications
/// stop that request stream until retry completes and preserve section order.
/// Use [`BlockedSections`] for bounded storage. Acknowledgments are values
/// to send on the decoder stream; there is no internal output queue.
/// Successful decoding updates only the decoder's reported count, through
/// interior mutability; entries stay unchanged. Send returned acknowledgments
/// in call order before taking [`Table::take_increment`] for the remaining inserts.
/// Every returned Section Ack must be sent, even when resetting that stream;
/// a Stream Cancel does not replace it.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, qpack::{self, EncoderInstruction, Table}};
/// let mut table = Table::new(128);
/// let mut input = Stream::new(qpack::EncoderInstructions::new());
/// let bytes = Wire::to_bytes(&EncoderInstruction::SetCapacity(128))?;
/// assert_eq!(input.push(&bytes), bytes.len());
/// if let Some(instruction) = input.next() {
///     table.apply(instruction??)?;
/// }
/// let result = qpack::decode_section(&table, 0, &[0, 0, 0xd1])?;
/// assert_eq!(result, qpack::SectionResult::Fields {
///     fields: vec![qpack::Field::new(":method", "GET")], ack: None,
/// });
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub fn decode_section(table: &Table, stream: u64, bytes: &[u8]) -> Result<SectionResult, Error> {
    decode_section_with_limit(table, stream, bytes, MAX_FIELD_SECTION_SIZE)
}

/// Decodes a section with a field-size limit capped by [`MAX_FIELD_SECTION_SIZE`].
/// Encoded bytes are bounded by [`MAX_SECTION_BYTES`] before any copy.
/// Strings and field counts keep [`MAX_STRING`] and [`MAX_FIELDS`] limits.
/// The acknowledgment requirements are the same as for [`decode_section`].
pub fn decode_section_with_limit(
    table: &Table,
    stream: u64,
    bytes: &[u8],
    field_limit: u64,
) -> Result<SectionResult, Error> {
    if stream > MAX_INTEGER {
        return Err(Error::IntegerOverflow);
    }
    if bytes.len() > MAX_SECTION_BYTES {
        return Err(Error::FieldSectionTooLarge);
    }
    let field_limit = field_limit.min(MAX_FIELD_SECTION_SIZE);
    let (prefix, used) = SectionPrefix::parse(bytes, table.max_entries(), table.insert_count())?;
    let body = bytes.get(used..).ok_or(Error::Truncated)?;
    if prefix.required_insert_count > table.insert_count() {
        return Ok(SectionResult::Blocked(BlockedSection { stream, prefix, body: body.to_vec(), field_limit }));
    }
    section_fields(table, stream, prefix, body, field_limit)
}

/// Explicit caller-owned storage for blocked field sections.
///
/// Enforces [`MAX_BLOCKED_BYTES`], [`MAX_BLOCKED_SECTIONS`], and the
/// negotiated stream limit capped by [`MAX_BLOCKED_STREAMS`]. This is never
/// filled by a byte decoder. The caller decides when to insert and drain.
#[derive(Clone, Debug)]
pub struct BlockedSections {
    sections: VecDeque<BlockedSection>,
    bytes: usize,
    max_streams: usize,
}

impl BlockedSections {
    /// Creates empty storage with the negotiated blocked-stream limit.
    pub fn new(max_streams: usize) -> Self {
        Self { sections: VecDeque::new(), bytes: 0, max_streams: max_streams.min(MAX_BLOCKED_STREAMS) }
    }
    /// Encoded body bytes retained across all sections.
    pub fn buffered(&self) -> usize {
        self.bytes
    }
    /// The number of waiting sections.
    pub fn len(&self) -> usize {
        self.sections.len()
    }
    /// Whether no sections are waiting.
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }
    /// Adds a section. On refusal, returns the original value to the caller.
    /// The caller must stop reading later sections on this stream or also
    /// retain them in stream order. No acknowledgment is generated here.
    pub fn push(&mut self, section: BlockedSection) -> Result<(), BlockedSection> {
        let mut streams = std::collections::BTreeSet::new();
        for s in &self.sections {
            streams.insert(s.stream);
        }
        let new_stream = !streams.contains(&section.stream);
        if (new_stream && streams.len() >= self.max_streams)
            || self.sections.len() >= MAX_BLOCKED_SECTIONS
            || section.buffered() > MAX_BLOCKED_BYTES.saturating_sub(self.bytes)
        {
            return Err(section);
        }
        self.bytes += section.buffered();
        self.sections.push_back(section);
        Ok(())
    }
    /// Takes one ready section's result. Other streams can pass a blocked
    /// stream, while sections on the same stream remain ordered.
    pub fn next_ready(&mut self, table: &Table) -> Option<(u64, Result<SectionResult, Error>)> {
        let mut waiting = std::collections::BTreeSet::new();
        let at = self.sections.iter().position(|s| {
            let first = waiting.insert(s.stream);
            first && s.required_insert_count() <= table.insert_count()
        })?;
        let section = self.sections.remove(at)?;
        self.bytes = self.bytes.saturating_sub(section.buffered());
        Some((section.stream, section.retry(table)))
    }
    /// Removes every section on a stream. Returns the cancellation value
    /// to write whenever the decoder advertised nonzero table capacity, even
    /// if reset arrived before a section was decoded. Does not queue output bytes.
    pub fn cancel(&mut self, table: &Table, stream: u64) -> Option<DecoderInstruction> {
        self.sections.retain(|s| s.stream != stream);
        self.bytes = self.sections.iter().map(BlockedSection::buffered).sum();
        (table.max_capacity() > 0).then_some(DecoderInstruction::StreamCancel(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Lcg, contract,
        test_support::{decode_all, mutate},
    };
    use fictionet::stdlib::prefix_int::Integer;

    fn apply(table: &mut Table, bytes: &[u8]) -> Result<(), Error> {
        let (items, error) = decode_all(EncoderInstructions::new, bytes);
        assert!(error.is_none(), "{error:?}");
        for item in items {
            table.apply(item?)?;
        }
        Ok(())
    }

    fn blocked(table: &Table, stream: u64, bytes: &[u8]) -> BlockedSection {
        let SectionResult::Blocked(section) = decode_section(table, stream, bytes).unwrap() else { panic!("ready") };
        section
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }

    fn fields(section: SectionResult) -> Vec<Field> {
        let SectionResult::Fields { fields, .. } = section else { panic!("blocked") };
        fields
    }

    // RFC 7541 Appendix C.1: integers.

    #[test]
    fn integer_examples() {
        assert_eq!(Integer::<5> { flags: 0, value: 10 }.to_bytes().unwrap(), [0x0a]);
        assert_eq!(Integer::<5> { flags: 0, value: 1337 }.to_bytes().unwrap(), [0x1f, 0x9a, 0x0a]);
        assert_eq!(Integer::<5>::parse(&[0x1f, 0x9a, 0x0a]), Ok(Integer { flags: 0, value: 1337 }));
        assert_eq!(Integer::<8> { flags: 0, value: 42 }.to_bytes().unwrap(), [0x2a]);
        assert_eq!(Integer::<5>::parse(&[0xea]), Ok(Integer { flags: 0xe0, value: 10 }));
        for n in 0..3 {
            assert_eq!(
                Integer::<5>::parse(&[0x1f, 0x9a, 0x0a][..n]),
                Err(prefix_int::Error::Truncated)
            );
        }
    }

    #[test]
    fn integer_limits() {
        fn check<const P: u8>() {
            for value in
                [0, 1, 30, 31, 127, 128, 255, 256, 1 << 40, MAX_INTEGER - 1, MAX_INTEGER, MAX_INTEGER + 1, u64::MAX]
            {
                let unit = Integer::<P> { flags: 0, value };
                contract::check_wire_value(&unit);
                let bytes = unit.to_bytes().unwrap();
                let mut c = Cursor { b: &bytes, i: 0 };
                if value > MAX_INTEGER {
                    assert!(matches!(c.int(P), Err(Stop::Bad(Error::IntegerOverflow))));
                    assert_eq!(
                        DecoderInstruction::SectionAck(value).to_bytes(),
                        Err(Error::Unwritable)
                    );
                } else {
                    assert!(bytes.len() <= MAX_INTEGER_BYTES);
                    assert_eq!(c.int(P).ok(), Some(value));
                }
            }
        }
        check::<1>();
        check::<2>();
        check::<3>();
        check::<4>();
        check::<5>();
        check::<6>();
        check::<7>();
        check::<8>();
        assert_eq!(
            Integer::<0> { flags: 0, value: 0 }.to_bytes(),
            Err(prefix_int::Error::Prefix)
        );
        assert_eq!(Integer::<9>::parse(&[0]), Err(prefix_int::Error::Prefix));
        assert_eq!(Integer::<8>::parse(&hex("ff 80feffffffffffff3f")), Ok(Integer { flags: 0, value: MAX_INTEGER }));
        // MAX_INTEGER + 1 with an eight-bit prefix.
        for bytes in [vec![0xff; 30], hex("ff 81feffffffffffff3f")] {
            let mut c = Cursor { b: &bytes, i: 0 };
            assert!(matches!(c.int(8), Err(Stop::Bad(Error::IntegerOverflow))));
        }
        let bytes = [
            0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0,
        ];
        let mut c = Cursor { b: &bytes, i: 0 };
        assert!(matches!(c.int(5), Err(Stop::Bad(Error::IntegerOverflow))));
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
        let mut table = Table::new(0);
        let section = hex("0000 510b 2f69 6e64 6578 2e68 746d 6c");
        assert_eq!(
            decode_section(&table, 0, &section),
            Ok(SectionResult::Fields { fields: vec![Field::new(":path", "/index.html")], ack: None })
        );
        assert_eq!(table.take_increment(), None);
    }

    #[test]
    fn rfc_b2_to_b5_dynamic_table() {
        let mut table = Table::new(220);
        let mut held = BlockedSections::new(2);
        let s4 = hex("0381 10 11");
        held.push(blocked(&table, 4, &s4)).unwrap();
        let enc = hex("3fbd01 c00f7777772e6578616d706c652e636f6d c10c2f73616d706c652f70617468");
        contract::check_decode_with_alloc_limit(EncoderInstructions::new, &enc, 2 * MAX_INSTRUCTION);
        apply(&mut table, &enc).unwrap();
        assert_eq!(table.size(), 106);
        assert_eq!(
            held.next_ready(&table),
            Some((
                4,
                Ok(SectionResult::Fields {
                    fields: vec![Field::new(":authority", "www.example.com"), Field::new(":path", "/sample/path")],
                    ack: Some(DecoderInstruction::SectionAck(4)),
                })
            ))
        );
        assert_eq!(table.take_increment(), None);
        apply(&mut table, &hex("4a637573746f6d2d6b65790c637573746f6d2d76616c7565")).unwrap();
        assert_eq!(table.size(), 160);
        assert_eq!(table.take_increment(), Some(DecoderInstruction::InsertCountIncrement(1)));
        let s8 = hex("0500 80 c1 81");
        held.push(blocked(&table, 8, &s8)).unwrap();
        assert_eq!(held.cancel(&table, 8), Some(DecoderInstruction::StreamCancel(8)));
        apply(&mut table, &[2]).unwrap();
        assert_eq!(held.next_ready(&table), None);
        assert_eq!(table.size(), 217);
        assert_eq!(table.get(3), Some((&b":authority"[..], &b"www.example.com"[..])));
        assert_eq!(
            decode_section(&table, 12, &s8),
            Ok(SectionResult::Fields {
                fields: vec![
                    Field::new(":authority", "www.example.com"),
                    Field::new(":path", "/"),
                    Field::new("custom-key", "custom-value")
                ],
                ack: Some(DecoderInstruction::SectionAck(12)),
            })
        );
        apply(&mut table, &hex("810d637573746f6d2d76616c756532")).unwrap();
        assert_eq!(table.size(), 215);
        assert_eq!(table.first_index(), 1);
        assert_eq!(table.get(4), Some((&b"custom-key"[..], &b"custom-value2"[..])));
        assert_eq!(table.take_increment(), Some(DecoderInstruction::InsertCountIncrement(1)));
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
            let bytes = p.encoded(128).unwrap().to_bytes().unwrap();
            assert_eq!(SectionPrefix::parse(&bytes, 128, required), Ok((p, bytes.len())));
            for n in 0..bytes.len() {
                assert_eq!(SectionPrefix::parse(&bytes[..n], 128, required), Err(Error::Truncated));
            }
        }
        // A negative Base.
        assert_eq!(SectionPrefix::parse(&[0x00, 0x80], 6, 0), Err(Error::Base));
        assert_eq!(SectionPrefix::parse(&[0x03, 0x82], 6, 2), Err(Error::Base));
        assert_eq!(SectionPrefix { required_insert_count: 1, base: 0 }.encoded(0), Err(Error::Unwritable));
        let far = SectionPrefix { required_insert_count: 0, base: u64::MAX };
        assert_eq!(far.encoded(6), Err(Error::Unwritable));
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
        for rep in &reps {
            contract::check_wire_value(rep);
            let bytes = rep.to_bytes().unwrap();
            for n in 0..bytes.len() {
                assert_eq!(Representation::parse(&bytes[..n]), Err(Error::Incomplete));
            }
        }
        let large =
            Representation::LiteralName { never_index: false, name: b"n".to_vec(), value: vec![0; MAX_STRING + 1] };
        assert_eq!(large.to_bytes(), Err(Error::Unwritable));
        let mut raw = vec![0x50];
        Integer::<7> { flags: 0, value: MAX_STRING as u64 + 1 }.write(&mut raw).unwrap();
        assert_eq!(Representation::parse(&raw), Err(Error::StringTooLong));
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
            contract::check_wire_value(ins);
            contract::check_decode_with_alloc_limit(
                EncoderInstructions::new,
                &ins.to_bytes().unwrap(),
                2 * MAX_INSTRUCTION,
            );
        }
        assert_eq!(EncoderInstruction::SetCapacity(220).to_bytes().unwrap(), [0x3f, 0xbd, 0x01]);
        assert_eq!(EncoderInstruction::Duplicate(2).to_bytes().unwrap(), [0x02]);
        for (ins, bytes) in [
            (DecoderInstruction::SectionAck(4), vec![0x84]),
            (DecoderInstruction::StreamCancel(8), vec![0x48]),
            (DecoderInstruction::InsertCountIncrement(1), vec![0x01]),
            (DecoderInstruction::SectionAck(1 << 40), DecoderInstruction::SectionAck(1 << 40).to_bytes().unwrap()),
        ] {
            assert_eq!(ins.to_bytes().unwrap(), bytes);
            contract::check_wire_value(&ins);
            contract::check_decode_with_alloc_limit(DecoderInstructions::new, &bytes, 2 * MAX_INTEGER_BYTES);
        }
        assert_eq!(DecoderInstruction::parse(&[0xff; 12]), Err(Error::IntegerOverflow));
    }

    #[test]
    fn dynamic_table_capacity_and_eviction() {
        let mut t = Table::new(100);
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
        assert_eq!(Table::new(u64::MAX).max_capacity(), MAX_TABLE_CAPACITY);
    }

    #[test]
    fn decoder_errors() {
        let mut table = Table::new(220);
        for (bytes, error) in [
            (vec![0x3f, 0xbe, 0x01], Error::Capacity(221)),
            (vec![0xff, 99 - 63, 0], Error::StaticIndex(99)),
            (vec![0x80, 0], Error::DynamicIndex(0)),
            (vec![0], Error::DynamicIndex(0)),
            (vec![0x41, b'a', 1, b'b'], Error::EntryTooLarge),
        ] {
            assert_eq!(apply(&mut table.clone(), &bytes), Err(error));
        }
        // Field section errors.
        assert_eq!(decode_section_with_limit(&table, 0, &[], 200), Err(Error::Truncated));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00], 200), Err(Error::Truncated));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00, 0x00, 0x51], 200), Err(Error::Truncated));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00, 0x00, 0xff, 0x24], 200), Err(Error::StaticIndex(99)));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00, 0x00, 0x80], 200), Err(Error::DynamicIndex(0)));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00, 0x00, 0x10], 200), Err(Error::DynamicIndex(0)));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x0e, 0x00], 200), Err(Error::InsertCount));
        assert_eq!(decode_section_with_limit(&table, 0, &[0x00, 0x80], 200), Err(Error::Base));
        let mut big = vec![0x00, 0x00];
        for _ in 0..10 {
            big.push(0xc0 | 31); // static 31: 64 bytes counted
        }
        assert_eq!(decode_section_with_limit(&table, 0, &big, 200), Err(Error::FieldSectionTooLarge));
        assert_eq!(
            decode_section_with_limit(&table, 0, &vec![0; MAX_SECTION_BYTES + 1], 200),
            Err(Error::FieldSectionTooLarge)
        );
        let mut held = BlockedSections::new(1);
        held.push(blocked(&table, 0, &[2, 0, 0x80])).unwrap();
        assert!(held.push(blocked(&table, 4, &[2, 0, 0x80])).is_err());
        apply(&mut table, &[0x3f, 0xbd, 0x01, 0x41, b'a', 1, b'b', 0x41, b'c', 1, b'd']).unwrap();
        let (id, result) = held.next_ready(&table).unwrap();
        assert_eq!((id, fields(result.unwrap())), (0, vec![Field::new("a", "b")]));
        assert_eq!(decode_section(&table, 8, &[0x03, 0x00, 0x81]), Err(Error::InsertCount));
        assert_eq!(decode_section(&table, 8, &[0x03, 0x00, 0xd1]), Err(Error::InsertCount));
        assert_eq!(fields(decode_section(&table, 8, &[0x03, 0x00, 0x80, 0x81]).unwrap()).len(), 2);
        // An index at or past the Required Insert Count, post-base.
        assert_eq!(decode_section(&table, 8, &[0x02, 0x80, 0x10, 0x11]), Err(Error::DynamicIndex(1)));
        assert_eq!(fields(decode_section(&table, 8, &[0x03, 0x81, 0x10, 0x11]).unwrap()).len(), 2);
        // Too many fields.
        let mut many = vec![0x00, 0x00];
        many.extend(std::iter::repeat_n(0xc0 | 17, MAX_FIELDS + 1));
        let wide = Table::new(0);
        assert_eq!(decode_section(&wide, 0, &many), Err(Error::TooManyFields));
    }

    #[test]
    fn encoder_errors() {
        let mut e = Encoder::new(100, 1 << 16);
        assert_eq!(e.set_capacity(101), Err(Error::Capacity(101)));
        assert_eq!(e.insert(b"a", b"b"), Err(Error::EntryTooLarge));
        assert_eq!(e.insert(&vec![0; MAX_STRING + 1], b""), Err(Error::StringTooLong));
        assert_eq!(e.duplicate(0), Err(Error::DynamicIndex(0)));
        e.set_capacity(100).unwrap();
        assert_eq!(e.insert(b"x-a", b"1").map(|v| v.0), Ok(0));
        assert_eq!(e.apply_instruction(DecoderInstruction::InsertCountIncrement(1)), Ok(()));
        assert_eq!(e.section(MAX_INTEGER + 1, &[Field::new("x-a", "1")]), Err(Error::Unwritable));
        assert!(e.outstanding.is_empty());
        assert_eq!(e.table().insert_count(), 1);
        let section = e.section(4, &[Field::new("x-a", "1")]).unwrap();
        assert_eq!(section.to_bytes().unwrap(), [0x02, 0x00, 0x80]);
        // Entry 0 is in use until stream 4's section is acknowledged.
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Err(Error::Referenced));
        assert_eq!(e.set_capacity(0), Err(Error::Referenced));
        assert_eq!(e.apply_instruction(DecoderInstruction::SectionAck(4)), Ok(()));
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()).map(|v| v.0), Ok(1));
        // Invalid acknowledgment values do not change session state.
        let mut f = e.clone();
        assert_eq!(f.apply_instruction(DecoderInstruction::SectionAck(4)), Err(Error::UnknownStream(4)));
        let mut f = e.clone();
        assert_eq!(f.apply_instruction(DecoderInstruction::InsertCountIncrement(0)), Err(Error::ZeroIncrement));
        let mut f = e.clone();
        assert_eq!(f.apply_instruction(DecoderInstruction::InsertCountIncrement(2)), Err(Error::Increment));
        // Section errors.
        let mut small = Encoder::new(0, 100);
        assert_eq!(
            small.section(0, &[Field::new(vec![b'n'; 40], vec![b'v'; 40])]),
            Err(Error::FieldSectionTooLarge)
        );
        assert_eq!(small.section(0, &vec![Field::new("a", ""); MAX_FIELDS + 1]), Err(Error::TooManyFields));
        assert_eq!(small.section(0, &[Field::new(vec![0; MAX_STRING + 1], "")]), Err(Error::StringTooLong));
    }

    #[test]
    fn encoder_releases_each_streams_sections_in_order() {
        let mut encoder = Encoder::new(4096, MAX_FIELD_SECTION_SIZE);
        encoder.set_capacity(4096).unwrap();
        encoder.insert(b"x-a", b"1").unwrap();
        encoder.insert(b"x-b", b"2").unwrap();
        encoder.apply_instruction(DecoderInstruction::InsertCountIncrement(2)).unwrap();
        for (stream, name, value) in [(0, "x-a", "1"), (4, "x-a", "1"), (4, "x-b", "2")] {
            let section = encoder.section(stream, &[Field::new(name, value)]).unwrap();
            contract::check_wire_value(&section);
        }
        assert_eq!(encoder.set_capacity(36), Err(Error::Referenced));
        let mut bytes = Vec::new();
        for stream in [0, 4, 4] {
            DecoderInstruction::SectionAck(stream).write(&mut bytes).unwrap();
        }
        let (instructions, failure) = decode_all(DecoderInstructions::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(instructions.len(), 3);
        for (i, instruction) in instructions.into_iter().enumerate() {
            encoder.apply_instruction(instruction.unwrap()).unwrap();
            let expected = if i == 0 { Err(Error::Referenced) } else { Ok(EncoderInstruction::SetCapacity(36)) };
            assert_eq!(encoder.set_capacity(36), expected);
        }
        assert_eq!(encoder.set_capacity(0), Ok(EncoderInstruction::SetCapacity(0)));
        assert_eq!(encoder.apply_instruction(DecoderInstruction::SectionAck(4)), Err(Error::UnknownStream(4)));
    }

    #[test]
    fn never_index_fields_stay_literal() {
        let mut e = Encoder::new(4096, 1 << 16);
        let mut table = Table::new(4096);
        table.apply(e.set_capacity(4096).unwrap()).unwrap();
        table.apply(e.insert(b"x-secret", b"s").unwrap().1).unwrap();
        e.apply_instruction(table.take_increment().unwrap()).unwrap();
        let mut secret = Field::new("x-secret", "s");
        secret.never_index = true;
        let mut auth = Field::new("authorization", "");
        auth.never_index = true;
        let list = vec![secret, auth, Field::new("x-secret", "s")];
        let bytes = e.section(0, &list).unwrap().to_bytes().unwrap();
        assert_eq!(fields(decode_section(&table, 0, &bytes).unwrap()), list);
        let section = FieldSection::parse(&bytes).unwrap();
        let rep = &section.representations[0];
        assert!(matches!(rep, Representation::LiteralNameRef { never_index: true, .. }));
    }

    #[test]
    fn truncated_sections() {
        let mut e = Encoder::new(4096, 1 << 16);
        let mut table = Table::new(4096);
        table.apply(e.set_capacity(4096).unwrap()).unwrap();
        table.apply(e.insert(b"x-one", b"first").unwrap().1).unwrap();
        e.apply_instruction(table.take_increment().unwrap()).unwrap();
        let list = vec![
            Field::new(":status", "200"),
            Field::new("x-one", "first"),
            Field::new("content-type", "text/x-weird"),
            Field::new("x-two", "a longer value that is Huffman-coded"),
        ];
        let bytes = e.section(0, &list).unwrap().to_bytes().unwrap();
        assert_eq!(fields(decode_section(&table, 0, &bytes).unwrap()), list);
        for n in 0..bytes.len() {
            match decode_section(&table, 0, &bytes[..n]) {
                Err(Error::Truncated) | Err(Error::InsertCount) => {}
                Ok(SectionResult::Fields { fields: f, .. }) => {
                    assert!(f.len() < list.len() && list.starts_with(&f), "cut at {n}")
                }
                other => panic!("cut at {n}: {other:?}"),
            }
        }
    }

    #[test]
    fn encoder_and_decoder_stay_in_step() {
        let names = [":path", "x-id", "cookie", "x-long", "accept", "x-a"];
        let mut rng = Lcg::new(7);
        let mut dynamic_sections = 0;
        for cap in [0, 64, 220, 500, 4096] {
            let mut encoder = Encoder::new(cap, 1 << 16);
            let mut table = Table::new(cap);
            let capacity = cap - rng.index((cap / 2 + 1) as usize) as u64;
            table.apply(encoder.set_capacity(capacity).unwrap()).unwrap();
            let mut instructions = Vec::new();
            let mut acknowledgments = Vec::new();
            for step in 0..1600 {
                let field = |rng: &mut Lcg| {
                    let name = names[rng.index(names.len())];
                    let value = format!("v{}", rng.index(8)).repeat(rng.index(6) + 1);
                    Field { name: name.as_bytes().to_vec(), value: value.into_bytes(), never_index: rng.index(10) == 0 }
                };
                let insert = field(&mut rng);
                if rng.coin() {
                    if let Ok((_, ins)) = encoder.insert(&insert.name, &insert.value) {
                        instructions.push(ins);
                    }
                } else if !encoder.table().is_empty() {
                    let index = encoder.table().first_index() + rng.index(encoder.table().len()) as u64;
                    if let Ok((_, ins)) = encoder.duplicate(index) {
                        instructions.push(ins);
                    }
                }
                if rng.coin() {
                    for ins in instructions.drain(..) {
                        table.apply(ins).unwrap();
                    }
                }
                let stream = step * 4;
                let list: Vec<_> = (0..rng.index(6)).map(|_| field(&mut rng)).collect();
                let section = encoder.section(stream, &list).unwrap();
                dynamic_sections += usize::from(section.prefix.encoded_insert_count != 0);
                let SectionResult::Fields { fields, ack } =
                    decode_section(&table, stream, &section.to_bytes().unwrap()).unwrap()
                else {
                    panic!("blocked")
                };
                assert_eq!(fields, list);
                acknowledgments.extend(ack);
                if rng.coin() {
                    acknowledgments.push(DecoderInstruction::StreamCancel(stream));
                }
                acknowledgments.extend(table.take_increment());
                if rng.coin() {
                    for ack in acknowledgments.drain(..) {
                        encoder.apply_instruction(ack).unwrap();
                    }
                }
            }
            for ins in instructions {
                table.apply(ins).unwrap();
            }
            assert_eq!(table.entries, encoder.table().entries);
            assert_eq!(table.capacity(), encoder.table().capacity());
            assert_eq!(table.size(), encoder.table().size());
            assert_eq!(table.insert_count(), encoder.table().insert_count());
        }
        assert!(dynamic_sections > 100, "{dynamic_sections}");
    }

    #[test]
    fn generated_wire_and_stream_contracts() {
        let mut rng = Lcg::new(0x9204);
        for round in 0..4000 {
            let mut data = if round % 2 == 0 { rng.bytes(64) } else { vec![0, 0, 0xd1, 0x50, 1, b'x'] };
            mutate(&mut rng, &mut data);
            contract::check_decode_with_alloc_limit(EncoderInstructions::new, &data, 2 * MAX_INSTRUCTION);
            contract::check_decode_with_alloc_limit(DecoderInstructions::new, &data, 2 * MAX_INTEGER_BYTES);
            contract::check_wire::<EncoderInstruction>(&data);
            contract::check_wire::<DecoderInstruction>(&data);
            contract::check_wire::<Representation>(&data);
            contract::check_wire::<huffman::HuffmanString>(&data);
            contract::check_wire::<FieldSection>(&data);
            let mut table = Table::new(220);
            let _ = apply(&mut table, &[]);
            let (items, _) = decode_all(EncoderInstructions::new, &data);
            for item in items {
                if item.and_then(|ins| table.apply(ins)).is_err() {
                    break;
                }
            }
            if let Ok(SectionResult::Fields { fields: list, .. }) = decode_section_with_limit(&table, 0, &data, 1 << 12)
            {
                let bytes = Encoder::new(0, 1 << 12).section(0, &list).unwrap().to_bytes().unwrap();
                assert_eq!(fields(decode_section(&Table::new(0), 0, &bytes).unwrap()), list);
            }
        }
    }

    #[test]
    fn generated_sections_with_a_built_table() {
        let mut rng = Lcg::new(42);
        let mut table = Table::new(4096);
        table.set_capacity(4096).unwrap();
        for i in 0..40 {
            table.insert(format!("x-h{}", i % 7).into_bytes(), i.to_string().into_bytes()).unwrap();
        }
        for _ in 0..3000 {
            let mut data = vec![rng.index(80) as u8, rng.next() as u8];
            data.extend(rng.bytes(40));
            if let Ok(SectionResult::Fields { fields, .. }) = decode_section_with_limit(&table, 0, &data, 1 << 14) {
                assert!(fields.iter().map(Field::size).sum::<u64>() <= 1 << 14);
            }
            contract::check_decode_with_alloc_limit(EncoderInstructions::new, &data, 2 * MAX_INSTRUCTION);
            let mut changed = table.clone();
            let (instructions, _) = decode_all(EncoderInstructions::new, &data);
            for instruction in instructions {
                if instruction.and_then(|instruction| changed.apply(instruction)).is_err() {
                    break;
                }
                assert!(changed.size() <= changed.capacity());
                assert!(changed.capacity() <= changed.max_capacity());
            }
        }
    }

    #[test]
    fn encoder_keeps_unacknowledged_entries() {
        // RFC 9204 section 2.1.1: an entry is evictable only once the
        // decoder has acknowledged its insert.
        let mut e = Encoder::new(100, 1 << 16);
        e.set_capacity(100).unwrap();
        assert_eq!(e.insert(b"x-a", b"1").map(|v| v.0), Ok(0)); // 36
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()), Err(Error::Referenced));
        assert_eq!(e.duplicate(0).map(|v| v.0), Ok(1)); // 72
        assert_eq!(e.duplicate(1), Err(Error::Referenced));
        assert_eq!(e.set_capacity(40), Err(Error::Referenced));
        // Once both inserts are acknowledged, they may go.
        e.apply_instruction(DecoderInstruction::InsertCountIncrement(2)).unwrap();
        assert_eq!(e.insert(b"x-b", vec![b'2'; 40].as_slice()).map(|v| v.0), Ok(2));
        assert_eq!(e.table().first_index(), 2);
        assert_eq!(e.set_capacity(0), Err(Error::Referenced));
        e.apply_instruction(DecoderInstruction::InsertCountIncrement(1)).unwrap();
        assert_eq!(e.set_capacity(0), Ok(EncoderInstruction::SetCapacity(0)));
    }

    #[test]
    fn blocked_streams_are_counted_by_stream() {
        let mut table = Table::new(220);
        let mut held = BlockedSections::new(1);
        for _ in 0..2 {
            held.push(blocked(&table, 0, &[2, 0, 0x80])).unwrap();
        }
        assert!(held.push(blocked(&table, 4, &[2, 0, 0x80])).is_err());
        apply(&mut table, &[0x3f, 0xbd, 1, 0x41, b'a', 1, b'b']).unwrap();
        for _ in 0..2 {
            assert_eq!(
                held.next_ready(&table),
                Some((
                    0,
                    Ok(SectionResult::Fields {
                        fields: vec![Field::new("a", "b")],
                        ack: Some(DecoderInstruction::SectionAck(0)),
                    })
                ))
            );
        }
        assert!(held.is_empty());
        assert_eq!(table.take_increment(), None);
    }

    #[test]
    fn long_instruction_allocation_contract() {
        let ins = EncoderInstruction::InsertWithLiteralName { name: vec![b'0'; 30_000], value: vec![b'1'; 30_000] };
        let bytes = ins.to_bytes().unwrap();
        let start = std::time::Instant::now();
        contract::check_decode_with_alloc_limit(EncoderInstructions::new, &bytes, 2 * MAX_INSTRUCTION);
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "instruction decoding exceeded two seconds");
        let mut table = Table::new(MAX_TABLE_CAPACITY);
        table.set_capacity(MAX_TABLE_CAPACITY).unwrap();
        apply(&mut table, &bytes).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn blocked_sections_are_bounded_on_one_stream() {
        let table = Table::new(4096);
        let mut held = BlockedSections::new(1);
        for _ in 0..MAX_BLOCKED_SECTIONS {
            held.push(blocked(&table, 0, &[2, 0])).unwrap();
        }
        assert!(held.push(blocked(&table, 0, &[2, 0])).is_err());
        assert_eq!(held.buffered(), 0);
        assert_eq!(held.len(), MAX_BLOCKED_SECTIONS);
    }

    #[test]
    fn integer_flags_never_spill_into_the_value() {
        assert_eq!(
            Integer::<5> {
                flags: 0xff,
                value: 3
            }
            .to_bytes(),
            Err(prefix_int::Error::Flags)
        );
        assert_eq!(
            Integer::<5> {
                flags: 0xe0,
                value: 3
            }
            .to_bytes()
            .unwrap(),
            [0xe3]
        );
    }

    #[test]
    fn sections_on_one_stream_are_acknowledged_in_order() {
        let mut table = Table::new(220);
        table.set_capacity(220).unwrap();
        let mut held = BlockedSections::new(1);
        held.push(blocked(&table, 0, &[3, 0, 0x80])).unwrap();
        held.push(blocked(&table, 0, &[2, 0, 0x80])).unwrap();
        apply(&mut table, &[0x41, b'a', 1, b'1']).unwrap();
        assert_eq!(held.next_ready(&table), None);
        assert_eq!(table.take_increment(), Some(DecoderInstruction::InsertCountIncrement(1)));
        apply(&mut table, &[0x41, b'b', 1, b'2']).unwrap();
        for field in [Field::new("b", "2"), Field::new("a", "1")] {
            assert_eq!(
                held.next_ready(&table),
                Some((
                    0,
                    Ok(SectionResult::Fields { fields: vec![field], ack: Some(DecoderInstruction::SectionAck(0)) })
                ))
            );
        }
        assert_eq!(table.take_increment(), None);
        // The owner waits until the blocked section is taken before reading later frames.
        assert_eq!(fields(decode_section(&table, 0, &[0, 0, 0xd1]).unwrap()), [Field::new(":method", "GET")]);
        held.push(blocked(&table, 4, &[4, 0, 0x80])).unwrap();
        apply(&mut table, &[0x41, b'c', 1, b'3']).unwrap();
        assert_eq!(fields(decode_section(&table, 8, &[0, 0, 0xd1]).unwrap()), [Field::new(":method", "GET")]);
        assert_eq!(fields(held.next_ready(&table).unwrap().1.unwrap()), [Field::new("c", "3")]);
        assert_eq!(fields(decode_section(&table, 4, &[0, 0, 0xd1]).unwrap()), [Field::new(":method", "GET")]);
    }

    #[test]
    fn released_sections_stay_within_the_held_limits() {
        let mut table = Table::new(MAX_TABLE_CAPACITY);
        table.set_capacity(MAX_TABLE_CAPACITY).unwrap();
        let mut held = BlockedSections::new(1);
        for _ in 0..MAX_BLOCKED_SECTIONS {
            held.push(blocked(&table, 0, &[2, 0, 0x80, 0x80, 0x80, 0x80])).unwrap();
        }
        table.insert(b"n".to_vec(), vec![b'v'; 60_000]).unwrap();
        assert!(held.push(blocked(&table, 0, &[3, 0, 0x80])).is_err());
        for _ in 0..MAX_BLOCKED_SECTIONS {
            let (stream, result) = held.next_ready(&table).unwrap();
            assert_eq!((stream, fields(result.unwrap()).len()), (0, 4));
        }
        assert_eq!(held.next_ready(&table), None);
    }

    #[test]
    fn advertised_capacity_sets_the_insert_count_modulus() {
        let advertised = 128 << 10;
        let mut encoder = Encoder::new(advertised, 1 << 16);
        let mut table = Table::new(advertised);
        assert_eq!(encoder.table().max_entries(), 4096);
        assert_eq!(encoder.table().max_capacity(), MAX_TABLE_CAPACITY);
        table.apply(encoder.set_capacity(MAX_TABLE_CAPACITY).unwrap()).unwrap();
        for i in 0..4096 {
            table.apply(encoder.insert(b"x", i.to_string().as_bytes()).unwrap().1).unwrap();
            encoder.apply_instruction(table.take_increment().unwrap()).unwrap();
        }
        let bytes = encoder.section(0, &[Field::new("x", "4095")]).unwrap().to_bytes().unwrap();
        let (prefix, _) = SectionPrefix::parse(&bytes, advertised / ENTRY_OVERHEAD, 4096).unwrap();
        assert_eq!(prefix.required_insert_count, 4096);
        assert_eq!(fields(decode_section(&table, 0, &bytes).unwrap()), [Field::new("x", "4095")]);
    }

    #[test]
    fn stream_readers_keep_bounded_buffers() {
        contract::check_decode_with_alloc_limit(EncoderInstructions::new, &vec![0x20; 4096], 2 * MAX_INSTRUCTION);
        contract::check_decode_with_alloc_limit(DecoderInstructions::new, &vec![0x40; 4096], 2 * MAX_INTEGER_BYTES);
        let ins = EncoderInstruction::InsertWithLiteralName { name: b"n".to_vec(), value: vec![b'v'; 100] };
        let mut bytes = EncoderInstruction::SetCapacity(4096).to_bytes().unwrap();
        ins.write(&mut bytes).unwrap();
        contract::check_decode_with_alloc_limit(EncoderInstructions::new, &bytes, 2 * MAX_INSTRUCTION);
        let mut table = Table::new(4096);
        apply(&mut table, &bytes).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn instruction_values_do_not_accumulate_in_sessions() {
        let mut encoder = Encoder::new(4096, 1 << 16);
        for _ in 0..4096 {
            assert_eq!(encoder.set_capacity(0), Ok(EncoderInstruction::SetCapacity(0)));
        }
        assert!(encoder.table().is_empty());
    }
}
