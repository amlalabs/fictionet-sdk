//! HPACK header compression for HTTP/2 (RFC 7541).
//!
//! Keep one [`Table`] and [`Encoder`] per direction. Pass complete header
//! blocks to [`Table::decode_block`]; HTTP/2 framing supplies their boundaries.
//! [`Table::set_settings_limit`] applies an acknowledged header table setting.
//! [`Table::for_observation`] handles captures with missing settings or blocks.
//! Call [`Table::forget`] after a gap to avoid reading stale table entries.
//! Names and values stay as octets. Text conversion belongs to the caller.
//! A server using this module must advertise SETTINGS_HEADER_TABLE_SIZE
//! at most [`MAX_TABLE`].
//!
//! ```
//! use fictionet::stdlib::hpack::{Table, Encoder, Field, MAX_DECODED};
//! let mut encoder = Encoder::new(4096);
//! let fields = [Field::new(":method", "GET"), Field::new("x-color", "blue")];
//! let mut bytes = Vec::new();
//! encoder.encode_block(&fields, &mut bytes)?;
//! let block = Table::new(4096).decode_block(&bytes, MAX_DECODED)?;
//! assert_eq!(block.headers[1].value.as_deref(), Some(b"blue".as_slice()));
//! # Ok::<(), fictionet::stdlib::hpack::Error>(())
//! ```

use fictionet::stdlib::codec::{Reader, Trailing, Truncated};

use fictionet::stdlib::{codec::Wire, huffman, prefix_int};
use std::collections::VecDeque;
use std::sync::Arc;

/// The most headers retained from a decoded block or accepted by the encoder.
pub const MAX_HEADERS: usize = 256;
/// The most retained name and value octets in one decoded or encoded block.
pub const MAX_DECODED: usize = 64 << 10;
/// The largest encoded block accepted by the decoder.
pub const MAX_BLOCK: usize = 256 << 10;
/// The largest encoded or decoded string literal in strict mode.
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
    /// A string exceeds its encoded or decoded limit. Strict mode uses
    /// [`MAX_STRING`]; observation uses `MAX_BLOCK * 8 / 5`.
    StringTooLong,
    /// A Huffman string has invalid codes, EOS, or padding.
    Huffman,
    /// An index is zero or is absent from a known table.
    Index,
    /// A size update exceeds the acknowledged settings limit.
    TableSize,
    /// Strict mode requires size updates before fields. It also permits at most
    /// two updates in nondecreasing order. The count and order checks are
    /// stricter than RFC 7541 requires of decoders. Observation skips these checks.
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

trait ReadFields<'a> {
    fn integer(&mut self, prefix: u8) -> Result<u64, Error>;
    fn string(&mut self, limit: usize) -> Result<Vec<u8>, Error>;
}

impl<'a> ReadFields<'a> for Reader<'a> {
    fn integer(&mut self, prefix: u8) -> Result<u64, Error> {
        let bytes = self.clone().rest();
        let (value, used) = prefix_int::read(bytes, prefix).map_err(|error| match error {
            prefix_int::Error::Truncated => Error::Truncated,
            _ => Error::IntegerOverflow,
        })?;
        self.skip(used)?;
        Ok(value)
    }

    fn string(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let coded = self.peek_u8().ok_or(Error::Truncated)? & 0x80 != 0;
        let len = usize::try_from(self.integer(7)?).map_err(|_| Error::StringTooLong)?;
        if len > limit {
            return Err(Error::StringTooLong);
        }
        self.position()
            .checked_add(len)
            .ok_or(Error::StringTooLong)?;
        let bytes = self.take(len)?;
        if coded {
            huffman::decode_limited(bytes, limit).map_err(|e| match e {
                huffman::Error::TooLong => Error::StringTooLong,
                _ => Error::Huffman,
            })
        } else {
            Ok(bytes.to_vec())
        }
    }
}

fn put_integer(out: &mut Vec<u8>, prefix: u8, flags: u8, value: u64) -> Result<(), Error> {
    prefix_int::write(out, prefix, flags, value).map_err(|_| Error::Unwritable)
}
fn put_string(out: &mut Vec<u8>, bytes: &[u8], coded: bool) -> Result<(), Error> {
    let len = huffman::encoded_len(bytes).map_err(|_| Error::Unwritable)?;
    if coded && len < bytes.len() {
        put_integer(out, 7, 0x80, len as u64)?;
        huffman::encode(bytes, out).map_err(|_| Error::Unwritable)?;
    } else {
        put_integer(out, 7, 0, bytes.len() as u64)?;
        out.extend_from_slice(bytes);
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
        let mut c = Reader::new(bytes);
        let value = c.string(MAX_STRING)?;
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
impl Wire for Field {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one literal with a new name. Refuses incremental indexing,
    /// table references, nonliterals,
    /// truncation, trailing bytes, bad Huffman, integer overflow, and string limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut c = Reader::new(bytes);
        let first = c.u8()?;
        if !matches!(first, 0 | 0x10) {
            return Err(Error::ContextRequired);
        }
        let name = c.string(MAX_STRING)?;
        let value = c.string(MAX_STRING)?;
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

/// A decoded field. Missing octets refer to entries lost from a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The name, or `None` if the referenced entry is unknown.
    pub name: Option<Vec<u8>>,
    /// The value, or `None` if the referenced entry is unknown.
    pub value: Option<Vec<u8>>,
    /// Whether the literal was marked never indexed.
    pub never_index: bool,
}
/// The retained part of one decoded header block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// Headers in wire order, up to [`MAX_HEADERS`] and the caller's byte limit.
    pub headers: Vec<Header>,
    /// Headers processed for table updates but omitted from `headers`.
    pub more: usize,
}
impl Block {
    fn keep(
        &mut self,
        limit: usize,
        used: &mut usize,
        name: Option<&[u8]>,
        value: Option<&[u8]>,
        never_index: bool,
    ) {
        let len = name
            .map_or(0, <[u8]>::len)
            .saturating_add(value.map_or(0, <[u8]>::len));
        if self.headers.len() >= MAX_HEADERS || len > limit.saturating_sub(*used) {
            // At most one omitted header per byte of bounded block input.
            self.more = self.more.saturating_add(1);
            return;
        }
        *used += len;
        self.headers.push(Header {
            name: name.map(<[u8]>::to_vec),
            value: value.map(<[u8]>::to_vec),
            never_index,
        });
    }
}

/// Reads complete blocks while retaining one direction's bounded dynamic table.
#[derive(Clone, Debug)]
pub struct Table {
    table: VecDeque<(Arc<[u8]>, Vec<u8>)>,
    size: usize,
    max: Option<usize>,
    unsure: bool,
    settings: Option<usize>,
    required_min: Option<usize>,
}
impl Default for Table {
    fn default() -> Self {
        Self::new(4096)
    }
}

enum Entry<'a> {
    Known(&'a [u8], &'a [u8]),
    Dynamic(&'a Arc<[u8]>, &'a [u8]),
    Unknown,
}
impl Table {
    /// Starts with the agreed settings limit, capped at [`MAX_TABLE`].
    /// The table starts at 4096. A limit below 4096 requires a size update
    /// at or below that limit at the start of the first block.
    pub fn new(settings_limit: usize) -> Self {
        let settings_limit = settings_limit.min(MAX_TABLE);
        Self {
            table: VecDeque::new(),
            size: 0,
            max: Some(4096),
            unsure: false,
            settings: Some(settings_limit),
            required_min: (settings_limit < 4096).then_some(settings_limit),
        }
    }
    /// Starts a capture decoder without a known settings bound. Tables larger
    /// than [`MAX_TABLE`] retain their newest entries and mark older ones unknown.
    /// Strings may expand to `MAX_BLOCK * 8 / 5` decoded octets.
    /// Size updates may follow fields, repeat, or decrease.
    /// Block syntax and the derived string limit are still checked.
    pub fn for_observation() -> Self {
        Self {
            settings: None,
            ..Self::default()
        }
    }

    /// Applies an acknowledged SETTINGS_HEADER_TABLE_SIZE, capped at [`MAX_TABLE`].
    /// A reduction below the current maximum requires an update at the next
    /// block's start. Multiple changes retain the smallest required reduction.
    pub fn set_settings_limit(&mut self, limit: usize) {
        let limit = limit.min(MAX_TABLE);
        self.settings = Some(limit);
        if self.max.is_none_or(|max| limit < max) {
            self.required_min = Some(self.required_min.map_or(limit, |old| old.min(limit)));
        }
    }
    /// The settings bound, or `None` when observing without settings.
    pub fn settings_limit(&self) -> Option<usize> {
        self.settings
    }
    /// The current table maximum, or `None` after missing a block.
    pub fn table_capacity(&self) -> Option<usize> {
        self.max
    }
    /// The retained table size, including [`ENTRY_OVERHEAD`] per entry.
    pub fn table_size(&self) -> usize {
        self.size
    }
    /// The number of retained table entries.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }
    /// Whether older dynamic entries may be unknown.
    pub fn is_unsure(&self) -> bool {
        self.unsure
    }

    /// Discards entries and the last size update after a missing or malformed block.
    /// Settings bounds remain in effect. Later references to lost entries are unknown.
    pub fn forget(&mut self) {
        self.table.clear();
        self.size = 0;
        self.unsure = true;
        self.max = None;
    }

    /// Reads one complete block, retaining at most `limit.min(MAX_DECODED)`
    /// name and value octets and [`MAX_HEADERS`] headers. Omitted headers still
    /// update the table. Refuses malformed input, size update violations,
    /// string limits, and input above [`MAX_BLOCK`]. Errors forget the table.
    pub fn decode_block(&mut self, bytes: &[u8], limit: usize) -> Result<Block, Error> {
        let result = self.read_block(bytes, limit.min(MAX_DECODED));
        if result.is_err() {
            self.forget();
        }
        result
    }

    fn get(&self, index: u64) -> Result<Entry<'_>, Error> {
        if index == 0 {
            return Err(Error::Index);
        }
        if let Some(index) = index.checked_sub(1).and_then(|n| usize::try_from(n).ok())
            && let Some((name, value)) = STATIC_TABLE.get(index)
        {
            return Ok(Entry::Known(name.as_bytes(), value.as_bytes()));
        }
        let entry = index
            .checked_sub(62)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| self.table.get(n));
        match entry {
            Some((name, value)) => Ok(Entry::Dynamic(name, value)),
            None if self.unsure => Ok(Entry::Unknown),
            None => Err(Error::Index),
        }
    }
    fn pop(&mut self) {
        if let Some((name, value)) = self.table.pop_back() {
            self.size = self
                .size
                .saturating_sub(name.len() + value.len() + ENTRY_OVERHEAD);
        }
    }
    fn evict(&mut self) {
        while self.max.is_some_and(|max| self.size > max) {
            self.pop();
        }
        while self.size > MAX_TABLE {
            self.pop();
            self.unsure = true;
        }
        if self
            .max
            .is_some_and(|max| self.size.saturating_add(ENTRY_OVERHEAD) > max)
        {
            self.unsure = false;
        }
    }
    fn insert(&mut self, name: Arc<[u8]>, value: Vec<u8>) {
        // Each string is bounded by MAX_BLOCK * 8 / 5 and the old size by MAX_TABLE.
        self.size += name.len() + value.len() + ENTRY_OVERHEAD;
        self.table.push_front((name, value));
        self.evict();
    }
    fn read_block(&mut self, bytes: &[u8], limit: usize) -> Result<Block, Error> {
        if bytes.len() > MAX_BLOCK {
            return Err(Error::BlockTooLong);
        }
        let mut out = Block::default();
        let mut used = 0;
        let mut c = Reader::new(bytes);
        let string_limit = if self.settings.is_none() {
            MAX_BLOCK * 8 / 5
        } else {
            MAX_STRING
        };
        let mut fields_started = false;
        let mut updates = 0;
        let mut previous = 0;
        while c.position() < bytes.len() {
            let first = c.peek_u8().ok_or(Error::Truncated)?;
            if first & 0xe0 == 0x20 {
                let size = usize::try_from(c.integer(5)?).map_err(|_| Error::TableSize)?;
                if self.settings.is_some()
                    && (fields_started || updates == 2 || (updates == 1 && size < previous))
                {
                    return Err(Error::SizeUpdateOrder);
                }
                if self.settings.is_some_and(|limit| size > limit) {
                    return Err(Error::TableSize);
                }
                if self.required_min.is_some_and(|min| size > min) {
                    return Err(Error::MissingSizeUpdate);
                }
                self.required_min = None;
                self.max = Some(size);
                self.evict();
                updates += 1;
                previous = size;
                continue;
            }
            if self.required_min.is_some() {
                return Err(Error::MissingSizeUpdate);
            }
            fields_started = true;
            if first & 0x80 != 0 {
                match self.get(c.integer(7)?)? {
                    Entry::Known(n, v) => out.keep(limit, &mut used, Some(n), Some(v), false),
                    Entry::Dynamic(n, v) => out.keep(limit, &mut used, Some(n), Some(v), false),
                    Entry::Unknown => out.keep(limit, &mut used, None, None, false),
                }
            } else {
                let indexing = first & 0x40 != 0;
                let never_index = !indexing && first & 0x10 != 0;
                let index = c.integer(if indexing { 6 } else { 4 })?;
                let name: Option<Arc<[u8]>> = match index {
                    0 => Some(c.string(string_limit)?.into()),
                    n => match self.get(n)? {
                        Entry::Known(name, _) => Some(name.into()),
                        Entry::Dynamic(name, _) => Some(name.clone()),
                        Entry::Unknown => None,
                    },
                };
                let value = c.string(string_limit)?;
                out.keep(limit, &mut used, name.as_deref(), Some(&value), never_index);
                match (indexing, name) {
                    (true, Some(name)) => self.insert(name, value),
                    (true, None) => self.forget(),
                    (false, _) => {}
                }
            }
        }
        if self.required_min.is_some() {
            return Err(Error::MissingSizeUpdate);
        }
        Ok(out)
    }
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
        self.table.size
    }
    /// Applies the peer's settings limit, capped at [`MAX_TABLE`].
    /// A reduction shrinks the table and queues the required size update.
    pub fn set_settings_limit(&mut self, limit: usize) {
        let limit = limit.min(MAX_TABLE);
        self.table.settings = Some(limit);
        if self.table.max.is_some_and(|max| max > limit) {
            self.resize(limit);
        }
    }
    /// Chooses a table capacity. Refuses a size above the peer's settings limit
    /// or [`MAX_TABLE`], leaving the encoder unchanged.
    pub fn set_capacity(&mut self, capacity: usize) -> Result<(), Error> {
        if capacity > self.table.settings.unwrap_or(0) || capacity > MAX_TABLE {
            return Err(Error::TableSize);
        }
        self.resize(capacity);
        Ok(())
    }
    fn resize(&mut self, capacity: usize) {
        self.pending_min = Some(self.pending_min.map_or(capacity, |old| old.min(capacity)));
        self.table.max = Some(capacity);
        self.table.evict();
    }

    /// Appends a complete block. Refuses more than [`MAX_HEADERS`] fields,
    /// strings above [`MAX_STRING`], or total name and value bytes above
    /// [`MAX_DECODED`], with [`Error::Unwritable`]. Both output and table stay
    /// unchanged on error. Field order and never-indexed flags are preserved.
    pub fn encode_block(&mut self, fields: &[Field], out: &mut Vec<u8>) -> Result<(), Error> {
        if fields.len() > MAX_HEADERS {
            return Err(Error::Unwritable);
        }
        let mut size = 0usize;
        for field in fields {
            size = size
                .checked_add(field.name.len())
                .and_then(|n| n.checked_add(field.value.len()))
                .ok_or(Error::Unwritable)?;
            if field.name.len() > MAX_STRING || field.value.len() > MAX_STRING || size > MAX_DECODED
            {
                return Err(Error::Unwritable);
            }
        }
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
    fn write_block(&mut self, fields: &[Field], out: &mut Vec<u8>) -> Result<(), Error> {
        if let Some(min) = self.pending_min.take() {
            put_integer(out, 5, 0x20, min as u64)?;
            let capacity = self.table.max.unwrap_or(0);
            if capacity != min {
                put_integer(out, 5, 0x20, capacity as u64)?;
            }
        }
        for field in fields {
            let entries = STATIC_TABLE
                .iter()
                .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
                .chain(
                    self.table
                        .table
                        .iter()
                        .map(|(n, v)| (n.as_ref(), v.as_slice())),
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
            } else {
                (6, 0x40)
            };
            put_integer(out, prefix, flags, name_index as u64)?;
            if name_index == 0 {
                put_string(out, &field.name, self.huffman)?;
            }
            put_string(out, &field.value, self.huffman)?;
            if !field.never_index {
                self.table
                    .insert(field.name.as_slice().into(), field.value.clone());
            }
        }
        Ok(())
    }
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self {
        Error::Truncated
    }
}

impl From<Trailing> for Error {
    #[inline]
    fn from(_: Trailing) -> Self {
        Error::Trailing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::prefix_int::Integer;
    use fictionet::stdlib::test_support::hex;

    fn pairs(h: &[Header]) -> Vec<(&str, &str)> {
        h.iter()
            .map(|h| {
                (
                    h.name
                        .as_deref()
                        .map(|b| std::str::from_utf8(b).unwrap_or("\u{fffd}"))
                        .unwrap_or(""),
                    h.value
                        .as_deref()
                        .map(|b| std::str::from_utf8(b).unwrap_or("\u{fffd}"))
                        .unwrap_or(""),
                )
            })
            .collect()
    }

    /// RFC 7541 C.4: three requests with Huffman coding, sharing a
    /// dynamic table.
    #[test]
    fn rfc_7541_requests_with_huffman() {
        let mut d = Table::for_observation();
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
            max: Some(256),
            ..Table::for_observation()
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

    #[test]
    fn broken_blocks_forget_the_table() {
        for bytes in [vec![0xff], vec![0x41, 0x85, 0xff]] {
            let mut d = Table::for_observation();
            d.decode_all(&hex("400178036f6c64"));
            assert_eq!(d.table_len(), 1);
            assert!(d.decode_block(&bytes, MAX_DECODED).is_err());
            assert!(d.is_unsure());
            assert_eq!(d.table_len(), 0);
            assert_eq!(d.table_size(), 0);
            assert_eq!(d.table_capacity(), None);
        }
        assert!(huffman::decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
    }

    /// One 4 KiB entry named 10,000 times would be 40 MB of headers: only
    /// as many as the limit allows are kept, and the rest are counted.
    #[test]
    fn a_block_keeps_only_what_the_limit_allows() {
        let mut block = vec![0x40, 0x01, b'x', 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'v', 4000));
        let mut d = Table::for_observation();
        assert_eq!(d.decode_all(&block).len(), 1);
        let b = d.decode_block(&vec![0xbe; 10_000], MAX_DECODED).unwrap();
        assert_eq!(b.headers.len(), MAX_DECODED / 4001);
        assert_eq!(b.headers.len() + b.more, 10_000);
        let b = d.decode_block(&[0xbe; 10], 100).unwrap();
        assert_eq!((b.headers.len(), b.more), (0, 10));
    }

    /// Headers past the limit still change the table: an insertion after
    /// 256 headers is seen by the next block.
    #[test]
    fn headers_past_the_limit_still_update_the_table() {
        let mut d = Table::for_observation();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        let mut block = vec![0x82; 256];
        block.extend(hex("4001 7803 6e65 77")); // x: new
        let b = d.decode_block(&block, MAX_DECODED).unwrap();
        assert_eq!((b.headers.len(), b.more), (256, 1));
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        assert_eq!(pairs(&d.decode_all(&[0xbf])), [("x", "old")]);
    }

    /// Sizes count octets, not text: a one-byte value that is not UTF-8
    /// takes one byte of the table.
    #[test]
    fn table_sizes_count_octets() {
        let mut d = Table::for_observation();
        // Table size 35, then x: 0xff, which takes 1 + 1 + 32 = 34 bytes.
        d.decode_all(&hex("3f04 4001 7801 ff"));
        let h = d.decode_all(&[0xbe]);
        assert_eq!(pairs(&h), [("x", "\u{fffd}")]);
        assert_eq!(d.size, 34);
    }

    /// A block that was not decoded leaves the table unknown: entries
    /// added later are known, older ones show as unknown, not stale.
    #[test]
    fn a_forgotten_table_shows_unknown_not_stale() {
        let mut d = Table::for_observation();
        d.decode_all(&hex("4001 7803 6f6c 64")); // x: old
        d.forget();
        d.decode_all(&hex("4001 7903 6e65 77")); // y: new
        let b = d.decode_block(&[0xbe, 0xbf, 0x82], MAX_DECODED).unwrap();
        assert_eq!(
            pairs(&b.headers),
            [("y", "new"), ("", ""), (":method", "GET")]
        );
        assert_eq!(
            b.headers
                .iter()
                .map(|h| h.name.is_some())
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        // A literal named after an unknown entry has a known value.
        let b = d.decode_block(&hex("0f30 0161"), MAX_DECODED).unwrap();
        assert_eq!(
            (b.headers[0].name.as_deref(), b.headers[0].value.as_deref()),
            (None, Some(b"a".as_slice()))
        );
        // Once known entries fill the table, nothing older can be left.
        let mut d = Table::for_observation();
        d.forget();
        d.decode_all(&hex("3f3b 4001 7801 61")); // size 90, then x: a (34)
        assert!(d.unsure, "an entry of 32 bytes or more may be left");
        d.decode_all(&hex("4001 7901 62")); // y: b, 68 in all
        assert!(!d.unsure, "no room for an older entry");
        assert!(
            d.decode_block(&[0xc0], MAX_DECODED).is_err(),
            "index 64 cannot exist"
        );
    }

    /// A table larger than the decoder keeps: entries past what it keeps
    /// are unknown, not missing.
    #[test]
    fn a_table_past_what_is_kept_is_unsure() {
        let mut d = Table::for_observation();
        // Size update to 1 MiB: 0x3f, then 1,048,576 - 31 as an integer.
        let mut block = vec![0x3f];
        let mut v = (1usize << 20) - 31;
        while v >= 0x80 {
            block.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        block.push(v as u8);
        d.decode_all(&block);
        // a: 16,000 bytes, a literal of length 127 + 15,873.
        let mut big = vec![0x40, 0x01, b'a', 0x7f, 0x81, 0x7c];
        big.extend(std::iter::repeat_n(b'v', 16_000));
        for _ in 0..5 {
            d.decode_all(&big);
        }
        assert_eq!(d.table.len(), 4, "only 64 KiB is kept");
        assert!(d.unsure);
        let b = d.decode_block(&[0xc2], MAX_DECODED).unwrap(); // index 66, the fifth
        assert!(b.headers[0].value.is_none());
    }

    /// A block not decoded may have changed the table's maximum, so after
    /// it, entries are kept until a size update says what the maximum is.
    #[test]
    fn a_forgotten_table_forgets_its_maximum() {
        let mut d = Table::for_observation();
        d.decode_all(&hex("20")); // size 0
        d.forget(); // the block not decoded set it to 4,096
        d.decode_all(&hex("4001 7803 6e65 77")); // x: new
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "new")]);
        d.decode_all(&hex("3f e11f")); // size 4,096
        assert_eq!(d.max, Some(4096));
    }

    /// A literal that names a long entry shares its name, so a block of
    /// such literals costs no more than its own bytes.
    #[test]
    fn literals_share_long_names() {
        let mut d = Table::for_observation();
        // Size 65,536, then an entry with a 4,000-byte name.
        let mut block = vec![0x3f, 0xe1, 0xff, 0x03, 0x40, 0x7f, 0xa1, 0x1e];
        block.extend(std::iter::repeat_n(b'n', 4000));
        block.push(0);
        d.decode_all(&block);
        // 3,000 more entries named after the newest, each with no value.
        let b = d.decode_block(&[0x7e, 0x00].repeat(3000), 0).unwrap();
        assert_eq!(b.more, 3000);
        assert_eq!(d.table.len(), 16);
        assert!(d.table.iter().all(|(n, _)| Arc::ptr_eq(n, &d.table[0].0)));
    }

    impl Table {
        fn decode_all(&mut self, b: &[u8]) -> Vec<Header> {
            let block = self.decode_block(b, MAX_DECODED).unwrap();
            assert_eq!(block.more, 0);
            block.headers
        }
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
            let b = d.decode_block(&hex(bytes), MAX_DECODED).unwrap();
            assert_eq!(pairs(&b.headers), [expected]);
            assert_eq!(b.headers[0].never_index, never);
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
                let block = d.decode_block(&hex(example), MAX_DECODED).unwrap();
                assert_eq!(pairs(&block.headers), *fields);
                assert_eq!(d.table_size(), size);
                let fields: Vec<_> = fields.iter().map(|(n, v)| Field::new(n, v)).collect();
                let mut bytes = Vec::new();
                encoder.encode_block(&fields, &mut bytes).unwrap();
                assert_eq!(bytes, hex(example));
                assert_eq!(encoder.table_size(), size);
            }
        }
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
            d.decode_block(&update(256), 0).unwrap();
            let mut encoder = Encoder::new(256);
            let mut back = Table::new(256);
            encoder.set_huffman(huffman);
            for ((example, fields), size) in examples.iter().zip(&expected).zip([222, 222, 215]) {
                let block = d.decode_block(&hex(example), MAX_DECODED).unwrap();
                assert_eq!(pairs(&block.headers), *fields);
                assert_eq!(d.table_size(), size);
                let fields: Vec<_> = fields.iter().map(|(n, v)| Field::new(n, v)).collect();
                let mut bytes = Vec::new();
                encoder.encode_block(&fields, &mut bytes).unwrap();
                // The encoder may choose raw strings when Huffman ties their length.
                assert_eq!(back.decode_block(&bytes, MAX_DECODED).unwrap(), block);
                assert_eq!(encoder.table_size(), size);
            }
            assert_eq!(d.table_len(), 3);
            assert_eq!(d.table.front().unwrap().0.as_ref(), b"set-cookie");
            assert_eq!(d.table.back().unwrap().0.as_ref(), b"date");
        }
    }

    #[test]
    fn strict_literal_writers() {
        use fictionet::stdlib::test_support::contract;
        contract::check_wire_value(&StringLiteral(vec![0; MAX_STRING + 1]));
        contract::check_wire_value(&Field::new(vec![0; MAX_STRING + 1], b""));
        contract::check_wire_value(&Field::new(b"", vec![0; MAX_STRING + 1]));
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
        for (block, capacity) in [
            (vec![0x82, 0x20], 0),
            (vec![0x20, 0x20, 0x20], 0),
            (vec![0x21, 0x20], 0),
            (hex("3f453082"), 16),
            (hex("203fe11f2082"), 0),
        ] {
            assert_eq!(
                Table::default().decode_block(&block, 0),
                Err(Error::SizeUpdateOrder)
            );
            let mut observed = Table::for_observation();
            let decoded = observed.decode_block(&block, MAX_DECODED).unwrap();
            assert_eq!(observed.table_capacity(), Some(capacity));
            assert!(!observed.is_unsure());
            if block.contains(&0x82) {
                assert_eq!(pairs(&decoded.headers), [(":method", "GET")]);
            } else {
                assert!(decoded.headers.is_empty());
            }
        }
        let mut d = Table::default();
        assert_eq!(d.decode_block(&update(4097), 0), Err(Error::TableSize));
        assert!(d.is_unsure());
        let mut d = Table::default();
        d.set_settings_limit(128);
        d.set_settings_limit(512);
        assert_eq!(
            d.decode_block(&update(512), 0),
            Err(Error::MissingSizeUpdate)
        );
        let mut block = update(128);
        block.extend(update(512));
        block.push(0x82);
        assert!(d.decode_block(&block, MAX_DECODED).is_ok());
        assert_eq!(d.table_capacity(), Some(512));
        assert_eq!(d.settings_limit(), Some(512));
        for bytes in [vec![], vec![0x82]] {
            let mut d = Table::default();
            d.set_settings_limit(0);
            assert_eq!(d.decode_block(&bytes, 0), Err(Error::MissingSizeUpdate));
        }
        let mut d = Table::new(MAX_TABLE);
        assert!(d.decode_block(&update(MAX_TABLE), 0).is_ok());
        assert_eq!(Table::new(usize::MAX).settings_limit(), Some(MAX_TABLE));
        assert_eq!(
            d.decode_block(&update(MAX_TABLE + 1), 0),
            Err(Error::TableSize)
        );
    }

    #[test]
    fn zero_capacity_and_oversized_entry_clear_the_table() {
        let mut d = Table::new(64);
        d.decode_block(&update(64), 0).unwrap();
        d.decode_all(&hex("4001780161"));
        assert_eq!(d.table_size(), 34);
        let mut block = vec![0x40, 1, b'y', 40];
        block.extend([b'v'; 40]);
        d.decode_all(&block);
        assert_eq!(d.table_size(), 0);
        assert_eq!(d.table_len(), 0);
        assert_eq!(d.decode_block(&[0xbe], 0), Err(Error::Index));
        d.decode_block(&[0x20], 0).unwrap();
        assert!(!d.is_unsure());
        d.decode_all(&hex("4001780161"));
        assert_eq!(d.table_size(), 0);
    }

    #[test]
    fn observation_accepts_huffman_expansion_and_keeps_the_table() {
        let mut d = Table::for_observation();
        d.decode_all(&hex("400178036f6c64")); // x: old
        let mut bytes = vec![0x00, 0x01, b'x'];
        Integer::<7> {
            flags: 0x80,
            value: 60_000,
        }
        .write(&mut bytes)
        .unwrap();
        bytes.extend(vec![0; 60_000]);
        assert!(bytes.len() < 64 << 10);
        let block = d.decode_block(&bytes, MAX_DECODED).unwrap();
        assert_eq!((block.headers.len(), block.more), (0, 1));
        assert!(!d.is_unsure());
        assert_eq!(d.table_len(), 1);
        assert_eq!(d.table_capacity(), Some(4096));
        assert_eq!(pairs(&d.decode_all(&[0xbe])), [("x", "old")]);
        assert_eq!(
            Table::default().decode_block(&bytes, MAX_DECODED),
            Err(Error::StringTooLong)
        );
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
        assert_eq!(d.table_capacity(), Some(4096));
        assert_eq!(
            d.decode_block(&[0x82], MAX_DECODED),
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
        d.decode_block(&bytes, MAX_DECODED).unwrap();
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
        let block = d.decode_block(&out, MAX_DECODED).unwrap();
        assert_eq!(pairs(&block.headers), [("x-color", "red")]);
        assert_eq!(encoder.table_size(), d.table_size());
        let mut secret = Field::new("x-color", "red");
        secret.never_index = true;
        out.clear();
        encoder.encode_block(&[secret], &mut out).unwrap();
        assert!(d.decode_block(&out, MAX_DECODED).unwrap().headers[0].never_index);
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
            Table::default().decode_block(&vec![0x82; MAX_BLOCK + 1], 0),
            Err(Error::BlockTooLong)
        );
        let block = Table::default()
            .decode_block(&vec![0x82; MAX_BLOCK], 0)
            .unwrap();
        assert_eq!(block.more, MAX_BLOCK);
    }
}
