//! HPACK header compression for HTTP/2 (RFC 7541).
//!
//! Keep one [`Table`] and [`Encoder`] per direction. Pass complete header
//! blocks to [`Table::decode_block`]; HTTP/2 framing supplies their boundaries.
//! [`Table::set_settings_limit`] applies an acknowledged header table setting.
//! [`Representations`] and [`DynamicTable`] supply neutral parsing and storage
//! for capture reconstruction in [`dissect::http2`](crate::stdlib::dissect::http2).
//! Names and values stay as octets. Text conversion belongs to the caller.
//! A server using this module must advertise SETTINGS_HEADER_TABLE_SIZE
//! at most [`MAX_TABLE`].
//!
//! ```
//! use fictionet::Budget;
//! use fictionet::stdlib::protocols::{fields::Fields, hpack::{Table, Encoder, Field, MAX_DECODED}};
//! let mut encoder = Encoder::new(4096);
//! let fields = [Field::new(":method", "GET"), Field::new("x-color", "blue")];
//! let mut bytes = Vec::new();
//! encoder.encode_block(&fields, &mut bytes)?;
//! let mut block = Fields::new();
//! Table::new(4096).decode_block(&bytes, &mut block, &Budget::unlimited(), MAX_DECODED)?;
//! assert_eq!(block.get(b"x-color"), Some(&b"blue"[..]));
//! # Ok::<(), fictionet::stdlib::protocols::hpack::Error>(())
//! ```

use fictionet::Budget;
use fictionet::stdlib::codec::{Trailing, Truncated};

use fictionet::stdlib::{
    codec::Wire,
    protocols::{
        fields::{self, Fields},
        huffman, prefix_int,
    },
};
use std::collections::VecDeque;
use std::sync::Arc;

/// The most headers retained from a decoded block or accepted by the encoder.
pub const MAX_HEADERS: usize = 256;
/// The most retained name and value octets in one decoded or encoded block.
pub const MAX_DECODED: usize = 64 << 10;
/// The largest encoded block accepted by the decoder.
pub const MAX_BLOCK: usize = 256 << 10;
/// The largest encoded or decoded string literal accepted by an endpoint.
pub const MAX_STRING: usize = huffman::MAX_STRING;
/// The most entry bytes retained in a dynamic table, including overhead.
pub const MAX_TABLE: usize = 64 << 10;
/// The size added to each table entry besides its name and value.
pub const ENTRY_OVERHEAD: usize = 32;

/// Why an HPACK value or block could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends inside an integer or string.
    Truncated,
    /// Bytes follow a complete wire value.
    Trailing,
    /// An integer exceeds `u64` or its prefix width is invalid.
    IntegerOverflow,
    /// A string exceeds its supplied encoded or decoded limit.
    /// Endpoints use [`MAX_STRING`].
    StringTooLong,
    /// A Huffman string has invalid codes, EOS, or padding.
    Huffman,
    /// An index is zero or is absent from a known table.
    Index,
    /// A size update exceeds the acknowledged settings limit.
    TableSize,
    /// Size updates must precede fields. Endpoint validation also permits at most
    /// two updates in nondecreasing order. Those count and order checks are
    /// stricter than RFC 7541 requires of decoders.
    SizeUpdateOrder,
    /// A settings reduction requires a size update at the next block's start.
    MissingSizeUpdate,
    /// The encoded block exceeds [`MAX_BLOCK`].
    BlockTooLong,
    /// A standalone field reads or changes table state, or is not a literal.
    ContextRequired,
    /// The value cannot be written exactly within its limits.
    Unwritable,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated HPACK value",
            Self::Trailing => "trailing HPACK bytes",
            Self::IntegerOverflow => "HPACK integer overflow or invalid prefix",
            Self::StringTooLong => "HPACK string exceeds its limit",
            Self::Huffman => "invalid HPACK Huffman string",
            Self::Index => "invalid HPACK index",
            Self::TableSize => "HPACK size exceeds the settings limit",
            Self::SizeUpdateOrder => "invalid HPACK size update order",
            Self::MissingSizeUpdate => "missing HPACK table size reduction",
            Self::BlockTooLong => "HPACK block exceeds its limit",
            Self::ContextRequired => "HPACK field needs a table context",
            Self::Unwritable => "HPACK value cannot be written",
        })
    }
}
impl core::error::Error for Error {}

/// RFC 7541 Appendix A, in one-based index order.
pub const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// An encoded block, read in order as if its pieces were joined: one
/// slice for a block that came whole, or the fragments it was kept in when
/// it came split, read where they lie. Reading moves past what is read.
#[derive(Clone, Copy, Debug)]
pub struct Block<'a> {
    /// The unread part of the piece being read.
    first: &'a [u8],
    /// The pieces after it.
    rest: &'a [Vec<u8>],
}
impl<'a> Block<'a> {
    /// A block in `pieces`, in order.
    pub fn pieces(pieces: &'a [Vec<u8>]) -> Self {
        match pieces.split_first() {
            Some((first, rest)) => Self { first, rest },
            None => Self::from(&[][..]),
        }
    }

    /// The unread bytes.
    pub fn len(&self) -> usize {
        self.rest.iter().fold(self.first.len(), |len, piece| {
            len.saturating_add(piece.len())
        })
    }

    /// Whether every byte was read.
    pub fn is_empty(&self) -> bool {
        self.first.is_empty() && self.rest.iter().all(Vec::is_empty)
    }

    /// Moves to the next piece that has bytes, if the one being read has
    /// none left.
    fn settle(&mut self) {
        while self.first.is_empty() {
            let Some((next, rest)) = self.rest.split_first() else {
                return;
            };
            self.first = next;
            self.rest = rest;
        }
    }

    fn peek_u8(&mut self) -> Option<u8> {
        self.settle();
        self.first.first().copied()
    }

    fn u8(&mut self) -> Result<u8, Error> {
        let byte = self.peek_u8().ok_or(Error::Truncated)?;
        self.first = &self.first[1..];
        Ok(byte)
    }

    /// The next `len` bytes, wherever they lie, and moves past them.
    fn take(&mut self, len: usize) -> Result<Span<'a>, Error> {
        self.settle();
        let span = Span {
            first: self.first,
            rest: self.rest,
            len,
        };
        let mut left = len;
        while left > self.first.len() {
            left -= self.first.len();
            let (next, rest) = self.rest.split_first().ok_or(Error::Truncated)?;
            self.first = next;
            self.rest = rest;
        }
        self.first = &self.first[left..];
        Ok(span)
    }

    /// An RFC 7541 section 5.1 integer whose first byte has `prefix` bits
    /// of it, read across pieces: at most [`prefix_int::MAX_BYTES`] bytes,
    /// copied out to be read.
    fn integer(&mut self, prefix: u8) -> Result<u64, Error> {
        let mut head = [0; prefix_int::MAX_BYTES];
        let mut ahead = *self;
        let mut n = 0;
        while n < head.len()
            && let Some(byte) = ahead.peek_u8()
        {
            head[n] = byte;
            ahead.first = &ahead.first[1..];
            n += 1;
        }
        let (value, used) = prefix_int::read(&head[..n], prefix).map_err(|error| match error {
            prefix_int::Error::Truncated => Error::Truncated,
            _ => Error::IntegerOverflow,
        })?;
        self.take(used)?;
        Ok(value)
    }

    /// A string literal of at most `limit` encoded octets.
    fn text(&mut self, limit: usize) -> Result<Text<'a>, Error> {
        let coded = self.peek_u8().ok_or(Error::Truncated)? & 0x80 != 0;
        let len = usize::try_from(self.integer(7)?).map_err(|_| Error::StringTooLong)?;
        if len > limit {
            return Err(Error::StringTooLong);
        }
        let octets = self.take(len)?;
        Ok(if coded {
            Text::Huffman(octets)
        } else {
            Text::Raw(octets)
        })
    }

    /// Refuses bytes left after a value that must end its input.
    fn finish(&mut self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}
impl<'a> From<&'a [u8]> for Block<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self {
            first: bytes,
            rest: &[],
        }
    }
}
impl<'a> From<&'a Vec<u8>> for Block<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        Self::from(&bytes[..])
    }
}
impl<'a, const N: usize> From<&'a [u8; N]> for Block<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        Self::from(&bytes[..])
    }
}

/// Octets of a block, borrowed where they lie, which may cross from one
/// of its pieces into the next.
#[derive(Clone, Copy)]
pub struct Span<'a> {
    first: &'a [u8],
    rest: &'a [Vec<u8>],
    len: usize,
}
impl<'a> Span<'a> {
    /// How many octets.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The octets in the pieces they lie in, in order.
    pub fn slices(&self) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let mut left = self.len;
        std::iter::once(self.first)
            .chain(self.rest.iter().map(Vec::as_slice))
            .map_while(move |piece| {
                let here = &piece[..piece.len().min(left)];
                left -= here.len();
                (!here.is_empty() || left > 0).then_some(here)
            })
            .filter(|here| !here.is_empty())
    }

    /// The octets, one at a time.
    pub fn bytes(&self) -> impl Iterator<Item = &'a u8> + use<'a> {
        self.slices().flatten()
    }
}
impl<'a> From<&'a [u8]> for Span<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self {
            first: bytes,
            rest: &[],
            len: bytes.len(),
        }
    }
}
impl PartialEq for Span<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.bytes().eq(other.bytes())
    }
}
impl Eq for Span<'_> {}
impl core::fmt::Debug for Span<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.bytes()).finish()
    }
}

/// A string literal as it is on the wire, borrowed: raw octets, or a
/// Huffman code to decode. Nothing is decoded or copied until the reader
/// says where the octets go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Text<'a> {
    /// The octets themselves.
    Raw(Span<'a>),
    /// The Huffman code of the octets.
    Huffman(Span<'a>),
}
impl Text<'_> {
    /// How many octets the string decodes to, checking its code, with at
    /// most `limit` of them. Allocates nothing.
    pub fn decoded_len(&self, limit: usize) -> Result<usize, Error> {
        match self {
            Text::Raw(octets) if octets.len() > limit => Err(Error::StringTooLong),
            Text::Raw(octets) => Ok(octets.len()),
            Text::Huffman(code) => huffman::decoded_len(code.bytes(), limit).map_err(huffman_error),
        }
    }

    /// Decodes the string into the start of `out` and returns how many
    /// octets it wrote; one longer than `out` is
    /// [`StringTooLong`](Error::StringTooLong). Allocates nothing.
    pub fn decode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Text::Raw(octets) => {
                let mut room = out.get_mut(..octets.len()).ok_or(Error::StringTooLong)?;
                for piece in octets.slices() {
                    let (here, rest) = room.split_at_mut(piece.len());
                    here.copy_from_slice(piece);
                    room = rest;
                }
                Ok(octets.len())
            }
            Text::Huffman(code) => huffman::decode_into(code.bytes(), out).map_err(huffman_error),
        }
    }

    /// The decoded octets, at most `limit` of them, in a vector of their
    /// own.
    pub fn to_vec(&self, limit: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; self.decoded_len(limit)?];
        self.decode_into(&mut out)?;
        Ok(out)
    }
}

fn huffman_error(error: huffman::Error) -> Error {
    match error {
        huffman::Error::TooLong => Error::StringTooLong,
        _ => Error::Huffman,
    }
}

fn put_integer(out: &mut impl Extend<u8>, prefix: u8, flags: u8, value: u64) -> Result<(), Error> {
    prefix_int::write(out, prefix, flags, value).map_err(|_| Error::Unwritable)
}
fn put_string(out: &mut impl Extend<u8>, bytes: &[u8], coded: bool) -> Result<(), Error> {
    let len = huffman::encoded_len(bytes).map_err(|_| Error::Unwritable)?;
    if coded && len < bytes.len() {
        put_integer(out, 7, 0x80, len as u64)?;
        huffman::encode(bytes, out).map_err(|_| Error::Unwritable)?;
    } else {
        put_integer(out, 7, 0, bytes.len() as u64)?;
        out.extend(bytes.iter().copied());
    }
    Ok(())
}

/// A string literal, including its length prefix and Huffman flag on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringLiteral(
    /// Decoded octets, at most [`MAX_STRING`].
    pub Vec<u8>,
);
impl Wire for StringLiteral {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one string. Refuses truncation, trailing bytes, overflow, bad Huffman, and limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut c = Block::from(bytes);
        let value = c.text(MAX_STRING)?.to_vec(MAX_STRING)?;
        c.finish()?;
        Ok(Self(value))
    }

    /// Writes a string, using Huffman when shorter. Refuses more than [`MAX_STRING`] octets.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        put_string(out, &self.0, true)
    }
}

/// A complete header field. Its standalone form uses a literal name without indexing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Name octets, at most [`MAX_STRING`].
    pub name: Vec<u8>,
    /// Value octets, at most [`MAX_STRING`].
    pub value: Vec<u8>,
    /// Preserve the never-indexed representation when forwarding this field.
    pub never_index: bool,
}
impl Field {
    /// Copies a name and value. The writer checks their lengths.
    pub fn new(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
            never_index: false,
        }
    }
}

/// A header field to encode, borrowed from wherever its octets live, so
/// encoding a block copies nothing before it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldRef<'a> {
    /// Name octets, at most [`MAX_STRING`].
    pub name: &'a [u8],
    /// Value octets, at most [`MAX_STRING`].
    pub value: &'a [u8],
    /// Keep the field out of every table.
    pub never_index: bool,
}
impl<'a> FieldRef<'a> {
    /// A field with this name and value, which a table may keep.
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            never_index: false,
        }
    }
}
impl<'a> From<&'a Field> for FieldRef<'a> {
    fn from(field: &'a Field) -> Self {
        Self {
            name: &field.name,
            value: &field.value,
            never_index: field.never_index,
        }
    }
}
impl Wire for Field {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one literal with a new name. Refuses incremental indexing,
    /// table references, nonliterals,
    /// truncation, trailing bytes, bad Huffman, integer overflow, and string limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut c = Block::from(bytes);
        let first = c.u8()?;
        if !matches!(first, 0 | 0x10) {
            return Err(Error::ContextRequired);
        }
        let name = c.text(MAX_STRING)?.to_vec(MAX_STRING)?;
        let value = c.text(MAX_STRING)?.to_vec(MAX_STRING)?;
        c.finish()?;
        Ok(Self {
            name,
            value,
            never_index: first == 0x10,
        })
    }

    /// Writes a literal with a new name. Refuses names or values above [`MAX_STRING`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.name.len() > MAX_STRING || self.value.len() > MAX_STRING {
            return Err(Error::Unwritable);
        }
        let start = out.len();
        let result = (|| {
            out.push(if self.never_index { 0x10 } else { 0 });
            put_string(out, &self.name, true)?;
            put_string(out, &self.value, true)
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }
}

/// A name literal or table reference in an HPACK representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    /// The name carried in this representation, not yet decoded.
    Literal(Text<'a>),
    /// A one-based static or dynamic table index.
    Index(u64),
}

/// The indexing instruction carried by a literal field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indexing {
    /// Insert the field into the dynamic table.
    Incremental,
    /// Leave the table unchanged.
    Without,
    /// Leave the table unchanged and preserve the never-indexed instruction.
    Never,
}

/// One representation as read, before resolving table references or
/// decoding its strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Representation<'a> {
    /// A complete field referenced by its one-based table index.
    Indexed(u64),
    /// A literal field, possibly referencing an existing name.
    Literal {
        /// The literal name or its table index.
        name: Name<'a>,
        /// The value, not yet decoded.
        value: Text<'a>,
        /// The wire instruction for indexing this field.
        indexing: Indexing,
    },
    /// A dynamic table capacity update at the start of a block.
    SizeUpdate(usize),
}

/// Reads a complete block's representations without choosing a table or settings.
/// Integer, string length and block grammar checks are shared by endpoints
/// and captures. Each consumer decodes the strings it uses, which checks
/// their Huffman codes. Settings validation and table knowledge belong to
/// the consumer.
#[derive(Debug)]
pub struct Representations<'a> {
    reader: Block<'a>,
    string_limit: usize,
    fields_started: bool,
    failed: bool,
}
impl<'a> Representations<'a> {
    /// Bounds the encoded block by [`MAX_BLOCK`] and each encoded
    /// string by `string_limit`; a reader bounds decoded strings as it
    /// decodes them ([`Text`]). Updates must precede every field.
    pub fn new(block: impl Into<Block<'a>>, string_limit: usize) -> Result<Self, Error> {
        let block = block.into();
        if block.len() > MAX_BLOCK {
            return Err(Error::BlockTooLong);
        }
        Ok(Self {
            reader: block,
            string_limit,
            fields_started: false,
            failed: false,
        })
    }

    fn read(&mut self) -> Result<Representation<'a>, Error> {
        let first = self.reader.peek_u8().ok_or(Error::Truncated)?;
        if first & 0xe0 == 0x20 {
            if self.fields_started {
                return Err(Error::SizeUpdateOrder);
            }
            let size = usize::try_from(self.reader.integer(5)?).map_err(|_| Error::TableSize)?;
            return Ok(Representation::SizeUpdate(size));
        }
        self.fields_started = true;
        if first & 0x80 != 0 {
            let index = self.reader.integer(7)?;
            if index == 0 {
                return Err(Error::Index);
            }
            return Ok(Representation::Indexed(index));
        }
        let indexing = if first & 0x40 != 0 {
            Indexing::Incremental
        } else if first & 0x10 != 0 {
            Indexing::Never
        } else {
            Indexing::Without
        };
        let index = self.reader.integer(if indexing == Indexing::Incremental {
            6
        } else {
            4
        })?;
        let name = if index == 0 {
            Name::Literal(self.reader.text(self.string_limit)?)
        } else {
            Name::Index(index)
        };
        let value = self.reader.text(self.string_limit)?;
        Ok(Representation::Literal {
            name,
            value,
            indexing,
        })
    }
}
impl<'a> Iterator for Representations<'a> {
    type Item = Result<Representation<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.reader.is_empty() {
            return None;
        }
        let result = self.read();
        self.failed = result.is_err();
        Some(result)
    }
}

/// A known static or dynamic table entry, borrowed without copying its octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Header name octets.
    pub name: &'a [u8],
    /// Header value octets.
    pub value: &'a [u8],
}

/// Known dynamic entries, newest first, with shared name storage.
/// Consumers supply the capacity and track whether older entries are known.
#[derive(Clone, Debug, Default)]
pub struct DynamicTable {
    entries: VecDeque<Slot>,
    size: usize,
}
impl DynamicTable {
    /// Resolves a static or retained dynamic index. A missing dynamic entry
    /// returns `None`; index zero is always an error.
    pub fn get(&self, index: u64) -> Result<Option<Entry<'_>>, Error> {
        if index == 0 {
            return Err(Error::Index);
        }
        if let Some((name, value)) = index
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| STATIC_TABLE.get(n))
        {
            return Ok(Some(Entry {
                name: name.as_bytes(),
                value: value.as_bytes(),
            }));
        }
        Ok(index
            .checked_sub(62)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.entries.get(n))
            .map(|(name, value)| Entry { name, value }))
    }

    /// Resolves a name, sharing storage when it names a retained dynamic entry.
    pub fn name(&self, index: u64) -> Result<Option<Arc<[u8]>>, Error> {
        if index == 0 {
            return Err(Error::Index);
        }
        if let Some((name, _)) = index
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| STATIC_TABLE.get(n))
        {
            return Ok(Some(name.as_bytes().into()));
        }
        Ok(index
            .checked_sub(62)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.entries.get(n))
            .map(|(name, _)| Arc::clone(name)))
    }

    /// Inserts a known field. Call [`Self::evict`] with the consumer's capacity.
    pub fn insert(&mut self, name: Arc<[u8]>, value: Vec<u8>) {
        // The value keeps exactly its own octets.
        let value = value.into_boxed_slice();
        self.size += name.len() + value.len() + ENTRY_OVERHEAD;
        if self.entries.len() == self.entries.capacity() {
            // The slots double, from four, so [`Self::most_held`] bounds
            // them.
            self.entries.reserve_exact(self.entries.capacity().max(4));
        }
        self.entries.push_front((name, value));
    }

    /// Removes oldest entries until their total size fits. Returns whether any
    /// entries were removed, including an inserted entry larger than capacity.
    pub fn evict(&mut self, capacity: usize) -> bool {
        let mut removed = false;
        while self.size > capacity {
            let Some((name, value)) = self.entries.pop_back() else {
                break;
            };
            self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
            removed = true;
        }
        removed
    }

    /// Releases all retained entries and allocated slots.
    pub fn clear(&mut self) {
        self.entries = VecDeque::new();
        self.size = 0;
    }
    /// Retained entry bytes, including [`ENTRY_OVERHEAD`] per entry.
    pub fn size(&self) -> usize {
        self.size
    }
    /// Number of retained entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// The name and value octets of the largest retained entry.
    pub fn largest(&self) -> usize {
        self.entries
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .max()
            .unwrap_or(0)
    }
    /// Whether there are no retained entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Allocated dynamic-table storage: the entry slots, each value, and
    /// each name in its shared allocation, with that allocation's header
    /// and padding. A name entries share is counted for each of them.
    pub fn held(&self) -> usize {
        self.entries.capacity() * size_of::<Slot>()
            + self
                .entries
                .iter()
                .map(|(name, value)| shared_len(name.len()) + value.len())
                .sum::<usize>()
    }
    /// The most the table allocates at any moment from now while each
    /// insert comes after an [`evict`](Self::evict) to `capacity`:
    /// [`most_held`](Self::most_held)`(capacity)`, or more when the slots
    /// grew for a larger capacity before. Slots are never given back, so
    /// those stay beside entries of at most `capacity`. Slots at least as
    /// many as the entries that fit `capacity` never double again; fewer
    /// are a count `most_held` already covers.
    pub fn most_held_at(&self, capacity: usize) -> usize {
        Self::most_held(capacity).max(
            self.entries
                .capacity()
                .saturating_mul(size_of::<Slot>())
                .saturating_add(capacity),
        )
    }
    /// The most the table allocates at any moment while each insert comes
    /// after an [`evict`](Self::evict) that made room for its entry within
    /// `capacity`, as [`Table`] and [`Encoder`] do, if its capacity was
    /// never larger ([`most_held_at`](Self::most_held_at) if it was). The
    /// entries fit `capacity`: at most `capacity / ENTRY_OVERHEAD` of them,
    /// whose octets, with each name's header, come to at most `capacity`.
    /// The slots start at four and double only when an insert finds them
    /// all full, so they reach at most twice the entries. While they
    /// double, the old slots and the new are both allocated. Room was made
    /// first, so the old ones were fewer than the entries that fit: the
    /// most such count of four doubled, three times over, for that moment.
    pub fn most_held(capacity: usize) -> usize {
        let entries = capacity / ENTRY_OVERHEAD;
        let mut old: usize = 0;
        if entries > 4 {
            old = 4;
            while old.saturating_mul(2) < entries {
                old *= 2;
            }
        }
        entries
            .saturating_mul(2)
            .max(4)
            .max(old.saturating_mul(3))
            .saturating_mul(size_of::<Slot>())
            .saturating_add(capacity)
    }
}

/// One dynamic table entry: its name, which entries may share, and its
/// value.
type Slot = (Arc<[u8]>, Box<[u8]>);

/// The most a block decoded from some number of encoded bytes can keep,
/// from [`Table::most_block`]: a bound known before the block is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockBound {
    /// The most headers it keeps.
    pub headers: usize,
    /// The most name and value octets it keeps.
    pub octets: usize,
}
impl BlockBound {
    /// The most the block holds in a [`Fields`] block: its octets, and a
    /// record of their lengths for each header.
    pub fn bytes(&self) -> usize {
        self.headers
            .saturating_mul(fields::RECORD)
            .saturating_add(self.octets)
    }
}

/// The octets of the largest entry in the static table.
fn largest_static() -> usize {
    STATIC_TABLE
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .max()
        .unwrap_or(0)
}

/// An endpoint's complete dynamic table and acknowledged settings.
/// Capture reconstruction uses the neutral [`Representations`] and [`DynamicTable`]
/// primitives with its own incomplete evidence.
#[derive(Clone, Debug)]
pub struct Table {
    table: DynamicTable,
    max: usize,
    settings: usize,
    required_min: Option<usize>,
}
impl Default for Table {
    fn default() -> Self {
        Self::new(4096)
    }
}
impl Table {
    /// Starts with the agreed settings limit, capped at [`MAX_TABLE`].
    /// The table starts at 4096. A limit below 4096 requires a size update
    /// at or below that limit at the start of the first block.
    pub fn new(settings_limit: usize) -> Self {
        let settings_limit = settings_limit.min(MAX_TABLE);
        Self {
            table: DynamicTable::default(),
            max: 4096,
            settings: settings_limit,
            required_min: (settings_limit < 4096).then_some(settings_limit),
        }
    }
    /// Applies an acknowledged SETTINGS_HEADER_TABLE_SIZE, capped at [`MAX_TABLE`].
    /// Multiple changes retain the smallest required reduction.
    pub fn set_settings_limit(&mut self, limit: usize) {
        let limit = limit.min(MAX_TABLE);
        self.settings = limit;
        if limit < self.max {
            self.required_min = Some(self.required_min.map_or(limit, |old| old.min(limit)));
        }
    }
    /// The acknowledged settings bound.
    pub fn settings_limit(&self) -> usize {
        self.settings
    }
    /// The current table maximum.
    pub fn table_capacity(&self) -> usize {
        self.max
    }
    /// Retained entry bytes, including [`ENTRY_OVERHEAD`] per entry.
    pub fn table_size(&self) -> usize {
        self.table.size()
    }
    /// Allocated dynamic-table storage, including spare entry slots.
    pub fn held(&self) -> usize {
        self.table.held()
    }
    /// The most [`held`](Self::held) reaches while neither the settings
    /// limit nor the table's capacity rises above what it is now: the
    /// peer can raise the capacity to the settings limit at any block.
    /// Slots grown before the capacity fell stay, and are counted
    /// ([`DynamicTable::most_held_at`]).
    pub fn most_held(&self) -> usize {
        self.table.most_held_at(self.settings.max(self.max))
    }
    /// The number of retained table entries.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// The most a block of `len` encoded bytes keeps when
    /// [`decode_block`](Self::decode_block) reads it with `limit`, as the
    /// table is now. Every representation takes at least a byte, so there
    /// are at most `len` of them, and each keeps at most one header. A
    /// string literal decodes to at most eight octets for every five bits
    /// it takes, the shortest Huffman code, so the block's literals come
    /// to at most `8 * len / 5` octets. A reference keeps at most the
    /// largest entry it can name: one in the static table, one in the
    /// dynamic table now, or one the block inserts, whose name is a
    /// literal or a name already there and whose value is a literal.
    pub fn most_block(&self, len: usize, limit: usize) -> BlockBound {
        let literals = len.saturating_mul(8) / 5;
        let entry = largest_static()
            .max(self.table.largest())
            .saturating_add(literals.saturating_mul(2));
        BlockBound {
            headers: len.min(MAX_HEADERS),
            octets: len
                .saturating_mul(entry)
                .saturating_add(literals)
                .min(limit.min(MAX_DECODED)),
        }
    }

    /// Reads one complete block into `out`, where it lies: one slice, or
    /// the pieces it was kept in when it came split ([`Block`]), never
    /// joined. It keeps at most `limit.min(MAX_DECODED)` name and value
    /// octets and [`MAX_HEADERS`] headers; `out`'s room is charged to
    /// `budget` as it grows. Each kept
    /// field is decoded straight into `out`'s block, its literals from the
    /// wire and its references from the table, and nothing else is
    /// allocated for it. A field left out, past the limits or for want of
    /// room, is counted in `out` and still checked, and still updates the
    /// table, so the table stays in step. Only an insertion into the table
    /// allocates: its value, and its name unless it shares an entry's.
    /// Errors clear retained entries, and leave `out` with the fields read
    /// before them; an endpoint must close the connection after a
    /// compression error.
    pub fn decode_block<'a>(
        &mut self,
        block: impl Into<Block<'a>>,
        out: &mut Fields,
        budget: &Budget,
        limit: usize,
    ) -> Result<(), Error> {
        let result = self.read_block(block.into(), out, budget, limit.min(MAX_DECODED));
        if result.is_err() {
            self.table.clear();
        }
        result
    }

    fn read_block(
        &mut self,
        block: Block<'_>,
        out: &mut Fields,
        budget: &Budget,
        limit: usize,
    ) -> Result<(), Error> {
        let mut updates = 0;
        let mut previous = 0;
        for representation in Representations::new(block, MAX_STRING)? {
            match representation? {
                Representation::SizeUpdate(size) => {
                    // Endpoint validation deliberately also bounds the number and
                    // order of initial updates, beyond the shared wire grammar.
                    if updates == 2 || (updates == 1 && size < previous) {
                        return Err(Error::SizeUpdateOrder);
                    }
                    if size > self.settings {
                        return Err(Error::TableSize);
                    }
                    if self.required_min.is_some_and(|min| size > min) {
                        return Err(Error::MissingSizeUpdate);
                    }
                    self.required_min = None;
                    self.max = size;
                    self.table.evict(size);
                    updates += 1;
                    previous = size;
                }
                field => {
                    if self.required_min.is_some() {
                        return Err(Error::MissingSizeUpdate);
                    }
                    match field {
                        Representation::Indexed(index) => {
                            let entry = self.table.get(index)?.ok_or(Error::Index)?;
                            let (name, value) =
                                (Text::Raw(entry.name.into()), Text::Raw(entry.value.into()));
                            keep(out, budget, limit, name, value, false)?;
                        }
                        Representation::Literal {
                            name,
                            value,
                            indexing,
                        } => {
                            let never = indexing == Indexing::Never;
                            let text = match name {
                                Name::Literal(text) => text,
                                Name::Index(index) => Text::Raw(
                                    self.table.get(index)?.ok_or(Error::Index)?.name.into(),
                                ),
                            };
                            let size = text.decoded_len(MAX_STRING)?
                                + value.decoded_len(MAX_STRING)?
                                + ENTRY_OVERHEAD;
                            keep(out, budget, limit, text, value, never)?;
                            if indexing == Indexing::Incremental {
                                self.index(name, value, size)?;
                            }
                        }
                        Representation::SizeUpdate(_) => unreachable!(),
                    }
                }
            }
        }
        if self.required_min.is_some() {
            return Err(Error::MissingSizeUpdate);
        }
        Ok(())
    }

    /// Adds a field with incremental indexing whose entry takes `size`
    /// (its name and value octets and [`ENTRY_OVERHEAD`]) to the table.
    fn index(&mut self, name: Name<'_>, value: Text<'_>, size: usize) -> Result<(), Error> {
        if size > self.max {
            // An entry larger than the table empties it and is not added
            // (RFC 7541 section 4.4): nothing is copied for it.
            self.table.evict(0);
            return Ok(());
        }
        // A name the dynamic table holds is shared before the eviction that
        // makes room may remove its entry, which allocates nothing. Any
        // other name is copied after the eviction, so no copy sits beside
        // the entries about to leave, and the table never holds more than
        // its size.
        let held = match name {
            Name::Index(index) if index > STATIC_TABLE.len() as u64 => {
                Some(self.table.name(index)?.ok_or(Error::Index)?)
            }
            _ => None,
        };
        self.table.evict(self.max - size);
        let name = match (held, name) {
            (Some(name), _) => name,
            (None, Name::Literal(text)) => shared(text)?,
            (None, Name::Index(index)) => self.table.name(index)?.ok_or(Error::Index)?,
        };
        self.table.insert(name, value.to_vec(MAX_STRING)?);
        Ok(())
    }
}

/// Keeps a field in `out` if the limits and `budget` allow, decoding its
/// name and value straight into the block. A field left out is still
/// decoded far enough to check it.
fn keep(
    out: &mut Fields,
    budget: &Budget,
    limit: usize,
    name: Text<'_>,
    value: Text<'_>,
    never_index: bool,
) -> Result<(), Error> {
    let n = name.decoded_len(MAX_STRING)?;
    let v = value.decoded_len(MAX_STRING)?;
    if out.len() >= MAX_HEADERS || n.saturating_add(v) > limit.saturating_sub(out.octets()) {
        // At most one omitted header per byte of bounded block input.
        out.leave_out(true);
        return Ok(());
    }
    out.write::<Error>(budget, n + v, never_index, |room| {
        name.decode_into(&mut room[..n])?;
        value.decode_into(&mut room[n..n + v])?;
        Ok((n, v))
    })?;
    Ok(())
}

/// What a shared name of `len` octets allocates: its two counts, then its
/// octets, padded to the counts' alignment.
fn shared_len(len: usize) -> usize {
    (2 * size_of::<usize>() + len).next_multiple_of(align_of::<usize>())
}

// A name's header and padding fit within the overhead each entry is
// counted with, so the entries' storage stays within their size.
const _: () = assert!(2 * size_of::<usize>() + align_of::<usize>() - 1 <= ENTRY_OVERHEAD);

/// A name for a table entry, decoded into an allocation of its own that
/// entries can share.
fn shared(text: Text<'_>) -> Result<Arc<[u8]>, Error> {
    let len = text.decoded_len(MAX_STRING)?;
    let mut name: Arc<[u8]> = std::iter::repeat_n(0, len).collect();
    let place = Arc::get_mut(&mut name).expect("a new name has one holder");
    text.decode_into(place)?;
    Ok(name)
}

/// Encodes complete blocks, using static matches and incremental dynamic entries.
/// Never-indexed fields always remain literals. Huffman is used when shorter.
#[derive(Clone, Debug)]
pub struct Encoder {
    table: Table,
    pending_min: Option<usize>,
    huffman: bool,
}
impl Default for Encoder {
    fn default() -> Self {
        Self::new(4096)
    }
}
impl Encoder {
    /// Starts with an agreed settings limit, capped at [`MAX_TABLE`].
    /// The table starts at 4096. A lower limit queues a size update
    /// at the start of the first block.
    pub fn new(settings_limit: usize) -> Self {
        let mut encoder = Self {
            table: Table::default(),
            pending_min: None,
            huffman: true,
        };
        encoder.set_settings_limit(settings_limit);
        encoder
    }
    /// Enables Huffman coding when it is shorter. Disabling it emits raw literals.
    pub fn set_huffman(&mut self, enabled: bool) {
        self.huffman = enabled;
    }
    /// The retained dynamic table size, including entry overhead.
    pub fn table_size(&self) -> usize {
        self.table.table.size()
    }
    /// Allocated dynamic-table storage, including spare entry slots.
    pub fn held(&self) -> usize {
        self.table.held()
    }
    /// The most [`held`](Self::held) reaches while the table's capacity
    /// stays at most what it is now: it rises only by
    /// [`set_capacity`](Self::set_capacity). Slots grown before the
    /// capacity fell stay, and are counted
    /// ([`DynamicTable::most_held_at`]).
    pub fn most_held(&self) -> usize {
        self.table.table.most_held_at(self.table.max)
    }
    /// Applies the peer's settings limit, capped at [`MAX_TABLE`].
    /// A reduction shrinks the table and queues the required size update.
    /// Send the SETTINGS acknowledgment before the next block: the update
    /// must follow it (RFC 7541 section 4.2). Sent before it, the update can
    /// leave a decoder that follows the RFC, as [`Table`] does, waiting for
    /// a reduction this encoder never sends again.
    pub fn set_settings_limit(&mut self, limit: usize) {
        let limit = limit.min(MAX_TABLE);
        self.table.settings = limit;
        if self.table.max > limit {
            self.resize(limit);
        }
    }
    /// Chooses a table capacity. Refuses a size above the peer's settings limit
    /// or [`MAX_TABLE`], leaving the encoder unchanged.
    pub fn set_capacity(&mut self, capacity: usize) -> Result<(), Error> {
        if capacity > self.table.settings || capacity > MAX_TABLE {
            return Err(Error::TableSize);
        }
        self.resize(capacity);
        Ok(())
    }
    fn resize(&mut self, capacity: usize) {
        self.pending_min = Some(self.pending_min.map_or(capacity, |old| old.min(capacity)));
        self.table.max = capacity;
        self.table.table.evict(capacity);
    }

    /// Appends a complete block. Refuses more than [`MAX_HEADERS`] fields,
    /// strings above [`MAX_STRING`], or total name and value bytes above
    /// [`MAX_DECODED`], with [`Error::Unwritable`]. Both output and table stay
    /// unchanged on error. Field order and never-indexed flags are preserved.
    ///
    /// `fields` is read twice, to check them and then to write them, so it
    /// is anything that can be gone through again: a slice of [`Field`]s,
    /// or a cheap view of fields that live elsewhere, borrowed as
    /// [`FieldRef`]s, so nothing is copied before the block is written.
    pub fn encode_block<'a, I>(&mut self, fields: I, out: &mut Vec<u8>) -> Result<(), Error>
    where
        I: IntoIterator + Clone,
        I::Item: Into<FieldRef<'a>>,
    {
        checked(fields.clone())?;
        // Length checks and fixed prefixes cover all fallible writes below.
        let pending_min = self.pending_min;
        let start = out.len();
        match self.write_block(fields, out) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.pending_min = pending_min;
                out.truncate(start);
                Err(Error::Unwritable)
            }
        }
    }
    /// The most bytes [`encode_block`](Self::encode_block) appends for
    /// `fields` now, found without writing: any size update still owed,
    /// and each field as a literal with a new name behind the largest
    /// index the block can reach, its strings without Huffman coding,
    /// which is used only when shorter. `None` if `encode_block` would
    /// refuse the fields.
    pub fn block_bound<'a, I>(&self, fields: I) -> Option<usize>
    where
        I: IntoIterator,
        I::Item: Into<FieldRef<'a>>,
    {
        let (count, strings) = checked(fields).ok()?;
        let updates = self.pending_min.map_or(0, |min| {
            let capacity = self.table.max;
            prefix_int::len(5, min as u64)
                + if capacity != min {
                    prefix_int::len(5, capacity as u64)
                } else {
                    0
                }
        });
        // Each field the block writes may add an entry before the next.
        let index = STATIC_TABLE.len() + self.table.table.len() + count;
        count
            .checked_mul(prefix_int::len(4, index as u64))?
            .checked_add(strings)?
            .checked_add(updates)
    }
    /// Writes a complete block into the start of `room`, as
    /// [`encode_block`](Self::encode_block) appends one, and returns its
    /// length. Room of [`block_bound`](Self::block_bound) bytes always
    /// holds it. On error, including room too short, `room` may hold part
    /// of a block, and the encoder's table may hold what the part added:
    /// give it room of the bound, or none of what was written goes out.
    /// Allocates nothing but what the table keeps.
    pub fn encode_block_into<'a, I>(&mut self, fields: I, room: &mut [u8]) -> Result<usize, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Into<FieldRef<'a>>,
    {
        checked(fields.clone())?;
        let pending_min = self.pending_min;
        let mut out = Room {
            room,
            at: 0,
            short: false,
        };
        match self.write_block(fields, &mut out) {
            Ok(()) if !out.short => Ok(out.at),
            _ => {
                self.pending_min = pending_min;
                Err(Error::Unwritable)
            }
        }
    }
    fn write_block<'a, I>(&mut self, fields: I, out: &mut impl Extend<u8>) -> Result<(), Error>
    where
        I: IntoIterator,
        I::Item: Into<FieldRef<'a>>,
    {
        if let Some(min) = self.pending_min.take() {
            put_integer(out, 5, 0x20, min as u64)?;
            let capacity = self.table.max;
            if capacity != min {
                put_integer(out, 5, 0x20, capacity as u64)?;
            }
        }
        for field in fields {
            let field: FieldRef<'_> = field.into();
            let entries = STATIC_TABLE
                .iter()
                .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
                .chain(
                    self.table
                        .table
                        .entries
                        .iter()
                        .map(|(n, v)| (n.as_ref(), v.as_ref())),
                );
            let mut name_index = 0;
            let mut exact = None;
            for (i, (name, value)) in entries.enumerate() {
                if name == field.name {
                    if name_index == 0 {
                        name_index = i + 1;
                    }
                    if value == field.value {
                        exact = Some(i + 1);
                        break;
                    }
                }
            }
            if let Some(index) = exact.filter(|_| !field.never_index) {
                put_integer(out, 7, 0x80, index as u64)?;
                continue;
            }
            let (prefix, flags) = if field.never_index {
                (4, 0x10)
            } else if self.table.max == 0 {
                (4, 0)
            } else {
                (6, 0x40)
            };
            put_integer(out, prefix, flags, name_index as u64)?;
            if name_index == 0 {
                put_string(out, field.name, self.huffman)?;
            }
            put_string(out, field.value, self.huffman)?;
            if !field.never_index && self.table.max != 0 {
                let size = field.name.len() + field.value.len() + ENTRY_OVERHEAD;
                if size > self.table.max {
                    // An entry larger than the table empties it and is
                    // not added (RFC 7541 section 4.4), as the decoder
                    // does: nothing is copied for it.
                    self.table.table.evict(0);
                } else {
                    // Room is made first, so the table never holds more
                    // than its size.
                    self.table.table.evict(self.table.max - size);
                    self.table
                        .table
                        .insert(field.name.into(), field.value.to_vec());
                }
            }
        }
        Ok(())
    }
}

/// Room an encoder writes into from its start, noting when it runs short.
struct Room<'a> {
    room: &'a mut [u8],
    at: usize,
    short: bool,
}

impl Extend<u8> for Room<'_> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, bytes: T) {
        for byte in bytes {
            match self.room.get_mut(self.at) {
                Some(place) => {
                    *place = byte;
                    self.at += 1;
                }
                None => self.short = true,
            }
        }
    }
}

/// Checks fields an encoder would write: at most [`MAX_HEADERS`], no
/// string above [`MAX_STRING`], and at most [`MAX_DECODED`] name and value
/// bytes in all. Returns how many there are, and the most bytes their
/// strings take written, length prefixes included.
fn checked<'a, I>(fields: I) -> Result<(usize, usize), Error>
where
    I: IntoIterator,
    I::Item: Into<FieldRef<'a>>,
{
    let (mut count, mut size, mut strings) = (0usize, 0usize, 0usize);
    for field in fields {
        let field: FieldRef<'_> = field.into();
        count += 1;
        size = size
            .checked_add(field.name.len())
            .and_then(|n| n.checked_add(field.value.len()))
            .ok_or(Error::Unwritable)?;
        if count > MAX_HEADERS
            || field.name.len() > MAX_STRING
            || field.value.len() > MAX_STRING
            || size > MAX_DECODED
        {
            return Err(Error::Unwritable);
        }
        for string in [field.name, field.value] {
            strings += prefix_int::len(7, string.len() as u64) + string.len();
        }
    }
    Ok((count, strings))
}

fictionet::codec_from!(Error, Truncated, |_| Error::Truncated);

fictionet::codec_from!(Error, Trailing, |_| Error::Trailing);

/// Bounded proofs over the table, the indexes and size updates, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../verification/hpack-grpc/kani/hpack.rs"]
mod proofs;

/// Bounded proofs that the tables hold no more than is charged for them,
/// with every allocation counted, run with `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`.
#[cfg(kani)]
#[path = "../../../verification/hpack-grpc/kani/resources.rs"]
mod resource_proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::prefix_int::Integer;
    use fictionet::stdlib::test_support::hex;

    fn pairs(h: &[Field]) -> Vec<(&str, &str)> {
        h.iter()
            .map(|h| {
                (
                    std::str::from_utf8(&h.name).unwrap_or("\u{fffd}"),
                    std::str::from_utf8(&h.value).unwrap_or("\u{fffd}"),
                )
            })
            .collect()
    }

    /// RFC 7541 C.4: three requests with Huffman coding, sharing a
    /// dynamic table.
    #[test]
    fn rfc_7541_requests_with_huffman() {
        let mut d = Table::default();
        let h = d.decode_all(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"));
        assert_eq!(
            pairs(&h),
            [
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com")
            ]
        );
        let h = d.decode_all(&hex("8286 84be 5886 a8eb 1064 9cbf"));
        assert_eq!(pairs(&h)[4], ("cache-control", "no-cache"));
        let h = d.decode_all(&hex(
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ));
        assert_eq!(pairs(&h)[2], (":path", "/index.html"));
        assert_eq!(pairs(&h)[4], ("custom-key", "custom-value"));
        assert_eq!(d.table.len(), 3);
    }

    /// RFC 7541 C.6.1: a response, Huffman coded, in a 256-byte table.
    #[test]
    fn rfc_7541_response() {
        let mut d = Table {
            max: 256,
            ..Table::default()
        };
        let h = d
            .decode_all(&hex(
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            ));
        assert_eq!(
            pairs(&h),
            [
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com")
            ]
        );
    }

    /// One 4 KiB entry named 10,000 times would be 40 MB of headers: only
    /// as many as the limit allows are kept, and the rest are counted.
    #[test]
    fn a_block_keeps_only_what_the_limit_allows() {
        let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'v', 4000));
        let mut d = Table::default();
        assert_eq!(d.decode_all(&block).len(), 1);
        let b = d.decode(&vec![0xbe; 10_000], MAX_DECODED).unwrap();
        assert_eq!(b.len(), MAX_DECODED / 4001);
        assert_eq!(b.len() + b.left_out(), 10_000);
        let b = d.decode(&[0xbe; 10], 100).unwrap();
        assert_eq!((b.len(), b.left_out()), (0, 10));
    }

    /// Headers past the limit still change the table: an insertion after
    /// 256 headers is seen by the next block.
    #[test]
    fn headers_past_the_limit_still_update_the_table() {
        let mut d = Table::default();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        let mut block = vec![0x82; 256];
        block.extend(hex("4001 7803 6e65 77")); // x: new
        let b = d.decode(&block, MAX_DECODED).unwrap();
        assert_eq!((b.len(), b.left_out()), (256, 1));
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        assert_eq!(pairs(&d.decode_all(&[0xbf])), [("x", "old")]);
    }

    /// Sizes count octets, not text: a one-byte value that is not UTF-8
    /// takes one byte of the table.
    #[test]
    fn table_sizes_count_octets() {
        let mut d = Table::default();
        // Table size 35, then x: 0xff, which takes 1 + 1 + 32 = 34 bytes.
        d.decode_all(&hex("3f04 4001 7801 ff"));
        let h = d.decode_all(&[0xbe]);
        assert_eq!(pairs(&h), [("x", "\u{fffd}")]);
        assert_eq!(d.table_size(), 34);
    }

    /// A literal that names a long entry shares its name, so a block of
    /// such literals costs no more than its own bytes.
    #[test]
    fn literals_share_long_names() {
        let mut d = Table::new(MAX_TABLE);
        // Size 65,536, then an entry with a 4,000-byte name.
        let mut block = vec![0x3f, 0xe1, 0xff, 0x03, 0x40, 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'n', 4000));
        block.push(0);
        d.decode_all(&block);
        // 3,000 more entries named after the newest, each with no value.
        let b = d.decode(&[0x7e, 0x00].repeat(3000), 0).unwrap();
        assert_eq!(b.left_out(), 3000);
        assert_eq!(d.table.len(), 16);
        assert!(
            d.table
                .entries
                .iter()
                .all(|(n, _)| Arc::ptr_eq(n, &d.table.entries[0].0))
        );
    }

    impl Table {
        /// A block decoded into fields of its own, on a budget with no
        /// limit.
        fn decode(&mut self, b: &[u8], limit: usize) -> Result<Fields, Error> {
            let mut fields = Fields::new();
            self.decode_block(b, &mut fields, &Budget::unlimited(), limit)?;
            Ok(fields)
        }

        fn decode_all(&mut self, b: &[u8]) -> Vec<Field> {
            let block = self.decode(b, MAX_DECODED).unwrap();
            assert_eq!(block.left_out(), 0);
            owned(&block)
        }
    }

    /// The fields of a block as owned fields, marks included.
    fn owned(block: &Fields) -> Vec<Field> {
        block
            .iter_marked()
            .map(|(name, value, never_index)| Field {
                name: name.to_vec(),
                value: value.to_vec(),
                never_index,
            })
            .collect()
    }

    /// The bytes a block's fields take written.
    fn written(block: &Fields) -> usize {
        block.octets() + block.len() * fields::RECORD
    }

    #[test]
    fn rfc_c2_representations() {
        for (bytes, expected, size, never) in [
            (
                "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
                ("custom-key", "custom-header"),
                55,
                false,
            ),
            (
                "040c2f73616d706c652f70617468",
                (":path", "/sample/path"),
                0,
                false,
            ),
            (
                "100870617373776f726406736563726574",
                ("password", "secret"),
                0,
                true,
            ),
            ("82", (":method", "GET"), 0, false),
        ] {
            let mut d = Table::default();
            let b = d.decode(&hex(bytes), MAX_DECODED).unwrap();
            assert_eq!(pairs(&owned(&b)), [expected]);
            assert_eq!(owned(&b)[0].never_index, never);
            assert_eq!(d.table_size(), size);
        }
    }

    #[test]
    fn rfc_c3_c4_request_sequences() {
        let raw = [
            "828684410f7777772e6578616d706c652e636f6d",
            "828684be58086e6f2d6361636865",
            "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        ];
        let coded = [
            "828684418cf1e3c2e5f23a6ba0ab90f4ff",
            "828684be5886a8eb10649cbf",
            "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        ];
        let expected = [
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ],
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ],
            vec![
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ],
        ];
        for (huffman, examples) in [(false, raw), (true, coded)] {
            let mut d = Table::default();
            let mut encoder = Encoder::default();
            encoder.set_huffman(huffman);
            for ((example, fields), size) in examples.iter().zip(&expected).zip([57, 110, 164]) {
                let block = d.decode(&hex(example), MAX_DECODED).unwrap();
                assert_eq!(pairs(&owned(&block)), *fields);
                assert_eq!(d.table_size(), size);
                let fields: Vec<_> = fields.iter().map(|(n, v)| Field::new(n, v)).collect();
                let mut bytes = Vec::new();
                encoder.encode_block(&fields, &mut bytes).unwrap();
                assert_eq!(bytes, hex(example));
                assert_eq!(encoder.table_size(), size);
            }
        }
    }

    /// Random blocks through an encoder and a decoder that share settings:
    /// every block is within the bound found before it was written, a
    /// block of borrowed fields is the same as one of owned fields, and
    /// neither table holds more than its bound.
    #[test]
    fn blocks_and_tables_stay_within_their_bounds() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let names: [&[u8]; 5] = [b":status", b"content-type", b"x-a", b"set-cookie", b"date"];
        let mut widest = 0;
        for seed in 0..32 {
            let rng = SeededEntropy::new(Seed::from_u64(seed));
            let below = |n: usize| rng.random_below(n as u64) as usize;
            let settings = [0, 64, 256, 4096][below(4)];
            let mut encoder = Encoder::new(settings);
            encoder.set_huffman(below(2) == 0);
            let mut decoder = Table::new(settings);
            let (encoder_most, decoder_most) = (encoder.most_held(), decoder.most_held());
            let mut values: Vec<Vec<u8>> = Vec::new();
            for _ in 0..64 {
                let mut fields = Vec::new();
                for _ in 0..below(12) {
                    let name = if below(4) == 0 {
                        let mut name = vec![0; below(40)];
                        rng.fill_random(&mut name);
                        name
                    } else {
                        names[below(names.len())].to_vec()
                    };
                    let value = if !values.is_empty() && below(2) == 0 {
                        values[below(values.len())].clone()
                    } else {
                        let text = below(2) == 0;
                        let mut value = vec![0; below(300)];
                        rng.fill_random(&mut value);
                        if text {
                            value.iter_mut().for_each(|b| *b = b'a' + *b % 26);
                        }
                        values.push(value.clone());
                        value
                    };
                    let mut field = Field::new(name, value);
                    field.never_index = below(8) == 0;
                    fields.push(field);
                }
                let bound = encoder.block_bound(&fields).unwrap();
                let borrowed: Vec<FieldRef<'_>> = fields.iter().map(FieldRef::from).collect();
                let mut twin = encoder.clone();
                let mut out = Vec::new();
                encoder.encode_block(&fields, &mut out).unwrap();
                let mut again = Vec::new();
                twin.encode_block(borrowed.iter().copied(), &mut again)
                    .unwrap();
                assert_eq!(again, out, "borrowed fields encode as owned ones do");
                assert!(out.len() <= bound, "{} past its bound {bound}", out.len());
                widest = widest.max(out.len());
                let block = decoder.decode(&out, MAX_DECODED).unwrap();
                assert_eq!(owned(&block), fields);
                assert!(encoder.held() <= encoder_most);
                assert!(decoder.held() <= decoder_most);
            }
        }
        assert!(widest > 1000, "some blocks were large");
    }

    /// A block read across the pieces it was kept in, cut anywhere, some
    /// pieces empty, decodes as the same block in one slice does: the same
    /// fields, the same table after it, and the same error for a block
    /// cut short or corrupted. Integers and strings cross the cuts.
    #[test]
    fn a_block_in_pieces_decodes_as_the_block_whole() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let rng = SeededEntropy::new(Seed::from_u64(11));
        let below = |n: usize| rng.random_below(n as u64) as usize;
        let mut encoder = Encoder::new(4096);
        let (mut whole, mut cut) = (Table::new(4096), Table::new(4096));
        let mut failed = 0;
        for round in 0..400 {
            encoder.set_huffman(below(2) == 0);
            let fields: Vec<Field> = (0..below(10))
                .map(|i| {
                    let mut value = vec![0; below(400)];
                    rng.fill_random(&mut value);
                    Field::new(format!("x-{}", below(4) + i), value)
                })
                .collect();
            let mut block = Vec::new();
            encoder.encode_block(&fields, &mut block).unwrap();
            if round % 5 == 4 && !block.is_empty() {
                // Cut short or corrupted: both decoders read it alike,
                // and start again if it fails.
                let at = below(block.len());
                match below(2) {
                    0 => block.truncate(at),
                    _ => block[at] ^= 1 << below(8),
                }
            }
            let mut pieces = Vec::new();
            let mut rest = &block[..];
            while !rest.is_empty() || below(4) == 0 {
                let n = below(rest.len().min(64) + 1);
                pieces.push(rest[..n].to_vec());
                rest = &rest[n..];
            }
            let (mut from_whole, mut from_pieces) = (Fields::new(), Fields::new());
            let budget = Budget::unlimited();
            let a = whole.decode_block(&block, &mut from_whole, &budget, MAX_DECODED);
            let b = cut.decode_block(
                Block::pieces(&pieces),
                &mut from_pieces,
                &budget,
                MAX_DECODED,
            );
            assert_eq!(a, b, "round {round}: {pieces:?}");
            assert_eq!(from_whole, from_pieces, "round {round}");
            assert_eq!(whole.table_size(), cut.table_size(), "round {round}");
            assert_eq!(whole.table_len(), cut.table_len(), "round {round}");
            if a.is_err() {
                failed += 1;
                (encoder, whole, cut) = (Encoder::new(4096), Table::new(4096), Table::new(4096));
            }
        }
        assert!(failed > 0, "some blocks failed to decode");
    }

    #[test]
    fn rfc_c5_c6_response_sequences_evict_entries() {
        let raw = [
            "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
            "4803333037c1c0bf",
            "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        ];
        let coded = [
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
            "4883640effc1c0bf",
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        ];
        let expected = [
            vec![
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
            vec![
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ],
            vec![
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                ),
            ],
        ];
        for (huffman, examples) in [(false, raw), (true, coded)] {
            let mut d = Table::new(256);
            d.decode(&update(256), 0).unwrap();
            let mut encoder = Encoder::new(256);
            let mut back = Table::new(256);
            encoder.set_huffman(huffman);
            for ((example, fields), size) in examples.iter().zip(&expected).zip([222, 222, 215]) {
                let block = d.decode(&hex(example), MAX_DECODED).unwrap();
                assert_eq!(pairs(&owned(&block)), *fields);
                assert_eq!(d.table_size(), size);
                let fields: Vec<_> = fields.iter().map(|(n, v)| Field::new(n, v)).collect();
                let mut bytes = Vec::new();
                encoder.encode_block(&fields, &mut bytes).unwrap();
                // The encoder may choose raw strings when Huffman ties their length.
                assert_eq!(back.decode(&bytes, MAX_DECODED).unwrap(), block);
                assert_eq!(encoder.table_size(), size);
            }
            assert_eq!(d.table_len(), 3);
            assert_eq!(d.table.entries.front().unwrap().0.as_ref(), b"set-cookie");
            assert_eq!(d.table.entries.back().unwrap().0.as_ref(), b"date");
        }
    }

    #[test]
    fn strict_literal_writers() {
        use fictionet::stdlib::test_support::assert_write;
        let _ = assert_write(&StringLiteral(vec![0; MAX_STRING + 1]));
        let _ = assert_write(&Field::new(vec![0; MAX_STRING + 1], b""));
        let _ = assert_write(&Field::new(b"", vec![0; MAX_STRING + 1]));
    }

    fn update(size: usize) -> Vec<u8> {
        Integer::<5> {
            flags: 0x20,
            value: size as u64,
        }
        .to_bytes()
        .unwrap()
    }

    #[test]
    fn size_updates_and_settings_reductions() {
        for block in [
            vec![0x82, 0x20],
            vec![0x20, 0x20, 0x20],
            vec![0x21, 0x20],
            hex("3f453082"),
            hex("203fe11f2082"),
        ] {
            assert_eq!(
                Table::default().decode(&block, 0),
                Err(Error::SizeUpdateOrder)
            );
        }
        let mut d = Table::default();
        assert_eq!(d.decode(&update(4097), 0), Err(Error::TableSize));
        assert_eq!(d.table_len(), 0);
        let mut d = Table::default();
        d.set_settings_limit(128);
        d.set_settings_limit(512);
        assert_eq!(d.decode(&update(512), 0), Err(Error::MissingSizeUpdate));
        let mut block = update(128);
        block.extend(update(512));
        block.push(0x82);
        assert!(d.decode(&block, MAX_DECODED).is_ok());
        assert_eq!(d.table_capacity(), 512);
        assert_eq!(d.settings_limit(), 512);
        for bytes in [vec![], vec![0x82]] {
            let mut d = Table::default();
            d.set_settings_limit(0);
            assert_eq!(d.decode(&bytes, 0), Err(Error::MissingSizeUpdate));
        }
        let mut d = Table::new(MAX_TABLE);
        assert!(d.decode(&update(MAX_TABLE), 0).is_ok());
        assert_eq!(Table::new(usize::MAX).settings_limit(), MAX_TABLE);
        assert_eq!(d.decode(&update(MAX_TABLE + 1), 0), Err(Error::TableSize));
    }

    #[test]
    fn zero_capacity_and_oversized_entry_clear_the_table() {
        let mut d = Table::new(64);
        d.decode(&update(64), 0).unwrap();
        d.decode_all(&hex("4001780161"));
        assert_eq!(d.table_size(), 34);
        let mut block = vec![0x40, 1, b'y', 40];
        block.extend([b'v'; 40]);
        d.decode_all(&block);
        assert_eq!(d.table_size(), 0);
        assert_eq!(d.table_len(), 0);
        assert_eq!(d.decode(&[0xbe], 0), Err(Error::Index));
        d.decode(&[0x20], 0).unwrap();
        assert_eq!(d.table_capacity(), 0);
        d.decode_all(&hex("4001780161"));
        assert_eq!(d.table_size(), 0);
    }

    #[test]
    fn zero_capacity_encoder_does_not_allocate_a_table() {
        let mut encoder = Encoder::new(0);
        let mut decoder = Table::new(0);
        let mut bytes = Vec::new();
        encoder
            .encode_block(&[Field::new("x-name", "value")], &mut bytes)
            .unwrap();
        assert_eq!(pairs(&decoder.decode_all(&bytes)), [("x-name", "value")]);
        assert_eq!(encoder.held(), 0);
        assert_eq!(decoder.table_size(), 0);
    }

    #[test]
    fn encoder_new_reduction_matches_acknowledged_settings() {
        let mut d = Table::default();
        d.set_settings_limit(100);
        let mut encoder = Encoder::new(100);
        let mut bytes = Vec::new();
        encoder
            .encode_block(&[Field::new("x-a", "b")], &mut bytes)
            .unwrap();
        assert!((0x20..=0x3f).contains(&bytes[0]));
        assert_eq!(pairs(&d.decode_all(&bytes)), [("x-a", "b")]);
        assert_eq!(encoder.table_size(), d.table_size());
    }

    #[test]
    fn constructors_require_the_initial_reduction() {
        let mut d = Table::new(256);
        assert_eq!(d.table_capacity(), 4096);
        assert_eq!(
            d.decode(&[0x82], MAX_DECODED),
            Err(Error::MissingSizeUpdate)
        );
        let mut d = Table::new(256);
        let mut encoder = Encoder::new(256);
        let mut bytes = Vec::new();
        encoder
            .encode_block(&[Field::new("x-a", "b")], &mut bytes)
            .unwrap();
        assert!((0x20..=0x3f).contains(&bytes[0]));
        assert_eq!(pairs(&d.decode_all(&bytes)), [("x-a", "b")]);
        assert_eq!(encoder.table_size(), d.table_size());
    }

    #[test]
    fn encoder_settings_updates_and_failure_are_transactional() {
        let mut encoder = Encoder::default();
        let mut d = Table::default();
        let fields = [Field::new("x-color", "red")];
        let mut bytes = Vec::new();
        encoder.encode_block(&fields, &mut bytes).unwrap();
        d.decode(&bytes, MAX_DECODED).unwrap();
        encoder.set_settings_limit(0);
        d.set_settings_limit(0);
        encoder.set_settings_limit(256);
        d.set_settings_limit(256);
        encoder.set_capacity(256).unwrap();
        assert_eq!(encoder.set_capacity(257), Err(Error::TableSize));
        let mut out = vec![0xaa];
        assert_eq!(
            encoder.encode_block(&[Field::new("x", vec![0; MAX_DECODED])], &mut out),
            Err(Error::Unwritable)
        );
        assert_eq!(out, [0xaa]);
        assert_eq!(encoder.table_size(), 0);
        out.clear();
        encoder.encode_block(&fields, &mut out).unwrap();
        assert!(out.starts_with(&hex("203fe101")));
        let block = d.decode(&out, MAX_DECODED).unwrap();
        assert_eq!(pairs(&owned(&block)), [("x-color", "red")]);
        assert_eq!(encoder.table_size(), d.table_size());
        let mut secret = Field::new("x-color", "red");
        secret.never_index = true;
        out.clear();
        encoder.encode_block(&[secret], &mut out).unwrap();
        assert!(owned(&d.decode(&out, MAX_DECODED).unwrap())[0].never_index);
        assert_eq!(encoder.table_size(), d.table_size());
    }

    #[test]
    fn string_and_block_limits_and_octets() {
        let field = Field::new([0, 0xff], [0xff, 0, 0x80]);
        assert_eq!(Field::parse(&field.to_bytes().unwrap()).unwrap(), field);
        assert_eq!(Field::parse(&[0x40]), Err(Error::ContextRequired));
        assert_eq!(
            Field::parse(&hex("4001780161")),
            Err(Error::ContextRequired)
        );
        for coded in [
            vec![0x81, 0xff],
            vec![0x81, 0x18],
            vec![0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(StringLiteral::parse(&coded), Err(Error::Huffman));
        }
        let oversized = Integer::<7> {
            flags: 0,
            value: MAX_STRING as u64 + 1,
        }
        .to_bytes()
        .unwrap();
        assert_eq!(StringLiteral::parse(&oversized), Err(Error::StringTooLong));
        let mut expanded = Integer::<7> {
            flags: 0x80,
            value: (MAX_STRING * 5 / 8 + 5) as u64,
        }
        .to_bytes()
        .unwrap();
        expanded.extend(vec![0; MAX_STRING * 5 / 8 + 5]);
        assert_eq!(StringLiteral::parse(&expanded), Err(Error::StringTooLong));
        assert_eq!(
            Table::default().decode(&vec![0x82; MAX_BLOCK + 1], 0),
            Err(Error::BlockTooLong)
        );
        let block = Table::default().decode(&vec![0x82; MAX_BLOCK], 0).unwrap();
        assert_eq!(block.left_out(), MAX_BLOCK);
    }

    /// Two encoders in step write the same random blocks, one appending
    /// to a vector and one into room of the block's bound: the same bytes,
    /// the same tables, and room one byte short of what the block takes is
    /// refused.
    #[test]
    fn encoding_into_room_writes_what_appending_writes() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let rng = SeededEntropy::new(Seed::from_u64(29));
        let (mut appending, mut filling) = (Encoder::new(4096), Encoder::new(4096));
        for round in 0..400 {
            let huffman = round % 3 != 0;
            appending.set_huffman(huffman);
            filling.set_huffman(huffman);
            if round % 50 == 7 {
                appending.set_settings_limit(1024);
                filling.set_settings_limit(1024);
            }
            let fields: Vec<Field> = (0..rng.random_below(12))
                .map(|i| {
                    let mut value = vec![0; rng.random_below(80) as usize];
                    rng.fill_random(&mut value);
                    let mut field = Field::new(format!("x-{}", (i + round) % 9), value);
                    field.never_index = rng.random_below(5) == 0;
                    field
                })
                .collect();
            let mut appended = Vec::new();
            let bound = appending.block_bound(&fields).unwrap();
            appending.encode_block(&fields, &mut appended).unwrap();
            if let Some(short) = appended.len().checked_sub(1) {
                let mut probe = filling.clone();
                let mut room = vec![0; short];
                assert!(probe.encode_block_into(&fields, &mut room).is_err());
            }
            let mut room = vec![0; bound];
            let written = filling.encode_block_into(&fields, &mut room).unwrap();
            assert_eq!(&room[..written], &appended[..]);
            assert_eq!(appending.table_size(), filling.table_size());
        }
    }

    /// Two decoders read the same random blocks, one with all the memory
    /// it wants and one whose budget refuses room at random: wherever a
    /// field was refused room, the other keeps it; every field kept is the
    /// one the other kept at that place; each refusal is counted; and the
    /// two tables never differ, so every later block decodes alike.
    #[test]
    fn a_refused_field_leaves_the_table_in_step() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let rng = SeededEntropy::new(Seed::from_u64(23));
        let mut encoder = Encoder::new(4096);
        encoder.set_huffman(true);
        let (mut full, mut tight) = (Table::new(4096), Table::new(4096));
        for round in 0..300 {
            let fields: Vec<Field> = (0..rng.random_below(10))
                .map(|i| {
                    let value = vec![b'a' + (round % 26) as u8; rng.random_below(200) as usize];
                    Field::new(format!("x-{}", (i + round) % 7), value)
                })
                .collect();
            let mut bytes = Vec::new();
            encoder.encode_block(&fields, &mut bytes).unwrap();
            let all = full.decode(&bytes, MAX_DECODED).unwrap();
            let budget = Budget::new(rng.random_below(1200) as usize);
            let mut some = Fields::new();
            tight
                .decode_block(&bytes, &mut some, &budget, MAX_DECODED)
                .unwrap();
            assert_eq!(owned(&all), fields);
            assert_eq!(some.len() + some.refused(), fields.len());
            assert_eq!(some.over(), 0);
            // Each kept field is one the other kept, in the same order.
            let mut expected = all.iter();
            for field in some.iter() {
                assert!(expected.by_ref().any(|other| other == field));
            }
            assert_eq!(budget.used(), some.charged());
            assert_eq!(full.table.entries, tight.table.entries);
            assert_eq!(full.table_size(), tight.table_size());
        }
    }

    /// A decoded block keeps at most what [`Table::most_block`] said before
    /// it was read: over blocks from an encoder that indexes fields and
    /// refers back to them, under several limits, and over blocks of
    /// one-byte references to the largest entry, which keep the most per
    /// encoded byte.
    #[test]
    fn decoded_blocks_keep_at_most_their_bound() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        fn check(table: &mut Table, bytes: &[u8], limit: usize) -> Fields {
            let bound = table.most_block(bytes.len(), limit);
            let block = table.decode(bytes, limit).unwrap();
            assert!(block.len() <= bound.headers);
            assert!(
                written(&block) <= bound.bytes(),
                "{} encoded bytes keep {}, more than the bound {}",
                bytes.len(),
                written(&block),
                bound.bytes()
            );
            block
        }
        let rng = SeededEntropy::new(Seed::from_u64(11));
        let mut encoder = Encoder::new(4096);
        let mut table = Table::new(4096);
        let values: Vec<Vec<u8>> = (0..8)
            .map(|i| vec![b'a' + i as u8; rng.random_below(600) as usize])
            .collect();
        for round in 0..400 {
            let fields: Vec<Field> = (0..rng.random_below(16))
                .map(|_| {
                    let name = format!("x-{}", rng.random_below(6));
                    Field::new(name, &values[rng.random_below(8) as usize])
                })
                .collect();
            let mut bytes = Vec::new();
            encoder.encode_block(&fields, &mut bytes).unwrap();
            check(&mut table, &bytes, [64, 1024, MAX_DECODED][round % 3]);
        }
        // The newest dynamic entry is index 62: each byte 0xbe names it whole.
        let mut bytes = Vec::new();
        encoder
            .encode_block(&[Field::new("x-big", vec![b'v'; 3000])], &mut bytes)
            .unwrap();
        check(&mut table, &bytes, MAX_DECODED);
        let references = check(&mut table, &[0xbe; 20], MAX_DECODED);
        assert_eq!(references.left_out(), 0, "every reference was kept");
    }
}
