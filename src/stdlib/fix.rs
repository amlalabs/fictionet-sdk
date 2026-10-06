//! FIX tag=value messages, repeating-group views, and caller-driven sessions.
//!
//! The wire rules follow FIX 4.4 Volume 2, “Message Format”, “Data Integrity”,
//! and “Session Protocol”, and FIXT 1.1 (March 2008), “Session Protocol” and
//! “Administrative Messages”. The session also follows FIX Session Layer
//! (June 2020), sections 4.3–4.8 (establishment, termination, liveness, recovery).
//! Public sources: [FIX 4.4 Volume 2](https://www.fixtrading.org/wp-content/uploads/download-manager-files/fix-44_VOL-2_w_Errata_20030618.pdf),
//! [FIXT 1.1](https://www.fixtrading.org/wp-content/uploads/download-manager-files/FIX_Transport_1.1.pdf),
//! and [FIX Session Layer](https://www.fixtrading.org/wp-content/uploads/download-manager-files/FIX_Session_Layer_June_2020.pdf).
//! Application views use the named message tables in the public FIX 4.2
//! specification (May 2001 errata) and FIX 4.4 Volumes 3 and 4 (June 2003 errata).
//! Encoding also follows [FIX TagValue Encoding v1.0](https://www.fixtrading.org/wp-content/uploads/download-manager-files/FIX_TagValue_Encoding_v1.0_June_2020.pdf),
//! sections 4.2–4.3 and 5.1–5.2. [FIX 4.2](https://www.fixtrading.org/wp-content/uploads/download-manager-files/fix-42-with_errata_20010501.pdf)
//! covers repeating groups and the named administrative and application messages.
//! No proprietary dictionary or member-only Word document is included.
//!
//! [`Message`] retains field order. BodyLength and CheckSum are derived, so
//! they are not stored in its field list. [`Frames`] reads complete messages
//! from a [`fictionet::stdlib::codec::Stream`]. Group layouts are supplied by
//! the caller. Application views check message type and expose borrowed values;
//! they do not impose a venue's required fields or trading rules.
//!
//! ```
//! use fictionet::stdlib::{codec::Wire, fix::{Message, NewOrderSingle, Version}};
//! let mut order = NewOrderSingle::builder(Version::Fix44)?;
//! order.cl_ord_id(b"order-7")?.symbol(b"XYZ")?.side(b"1")?
//!     .order_qty(b"100")?.ord_type(b"2")?.price(b"12.50")?;
//! let message = order.finish()?;
//! let bytes = message.to_bytes()?;
//! let parsed = Message::parse(&bytes)?;
//! assert_eq!(NewOrderSingle::view(&parsed)?.cl_ord_id(), Some(&b"order-7"[..]));
//! # Ok::<(), fictionet::stdlib::fix::Error>(())
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};
use std::fmt;

/// The field delimiter, ASCII SOH.
pub const SOH: u8 = 1;
/// Maximum encoded message size, including header and checksum.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
/// Maximum stored fields, excluding derived tags 9 and 10.
pub const MAX_FIELDS: usize = 4096;
/// Maximum bytes in one field value, including a data field.
pub const MAX_VALUE_LENGTH: usize = 256 * 1024;
/// Maximum bytes through the end of BodyLength. Bounds prefix rescanning.
pub const MAX_PREFIX_SIZE: usize = 64;
/// Maximum nested repeating-group depth.
pub const MAX_GROUP_DEPTH: usize = 8;
/// Maximum entries in one repeating group.
pub const MAX_GROUP_COUNT: usize = 1024;
/// Maximum layouts in one caller-supplied layout tree.
pub const MAX_GROUP_LAYOUTS: usize = 128;
/// Maximum member tags in one group layout.
pub const MAX_GROUP_MEMBERS: usize = 256;
/// Maximum sequence numbers in a single replay request or gap fill.
pub const MAX_RESEND_RANGE: u32 = 10_000;
/// Maximum bytes in a session CompID or application version identifier.
pub const MAX_SESSION_ID_LENGTH: usize = 64;
/// Maximum negotiated heartbeat interval, in seconds.
pub const MAX_HEARTBEAT_SECONDS: u32 = 86_400;
/// Maximum actions returned by one session operation.
pub const MAX_ACTIONS: usize = 16;
/// Maximum length of a TestReqID issued or echoed by the session.
pub const MAX_TEST_REQUEST_ID_LENGTH: usize = 64;

/// Standard Length/data pairs through FIX 4.4. Length immediately precedes data.
/// Includes SecureData, Signature, RawData, XmlData, and encoded text fields.
pub const LENGTH_DATA_PAIRS: &[(u32, u32)] = &[
    (90, 91),
    (93, 89),
    (95, 96),
    (212, 213),
    (348, 349),
    (350, 351),
    (352, 353),
    (354, 355),
    (356, 357),
    (358, 359),
    (360, 361),
    (362, 363),
    (364, 365),
    (445, 446),
    (618, 619),
    (621, 622),
];

/// Why a message, layout, or session operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A named storage or count limit was exceeded.
    Limit,
    /// Input ended inside a message or field.
    Incomplete,
    /// Bytes followed the checksum.
    Trailing,
    /// A tag, delimiter, value, or decimal integer was malformed.
    Field,
    /// BeginString, BodyLength, MsgType, or CheckSum had the wrong position.
    Header,
    /// BeginString is outside the supported versions.
    Version,
    /// BodyLength did not describe the bytes before CheckSum.
    BodyLength,
    /// CheckSum was not three decimal digits with the correct value.
    Checksum,
    /// A Length/data pair was absent, misplaced, or inconsistent.
    DataLength,
    /// A group layout, entry count, delimiter, or member order was invalid.
    Group,
    /// A required field was absent.
    Missing(u32),
    /// A singleton field appeared more than once.
    Duplicate(u32),
    /// A typed view was requested for another message type.
    MessageType,
    /// The operation is not allowed in the current session state.
    State,
    /// Caller time moved backward or a timestamp was malformed.
    Time,
    /// A sequence number or replay range was invalid or exhausted.
    Sequence,
    /// Session configuration or incoming session identity was invalid.
    Session,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FIX {self:?}")
    }
}
impl std::error::Error for Error {}

/// Session BeginString values supported by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// FIX 4.2 application and session protocol.
    Fix42,
    /// FIX 4.3 application and session protocol.
    Fix43,
    /// FIX 4.4 application and session protocol.
    Fix44,
    /// FIXT 1.1, with an independently selected application version.
    Fixt11,
}
impl Version {
    /// Returns the BeginString value.
    pub fn begin_string(self) -> &'static [u8] {
        match self {
            Self::Fix42 => b"FIX.4.2",
            Self::Fix43 => b"FIX.4.3",
            Self::Fix44 => b"FIX.4.4",
            Self::Fixt11 => b"FIXT.1.1",
        }
    }
    /// Reads a supported BeginString value.
    pub fn from_begin_string(value: &[u8]) -> Result<Self, Error> {
        match value {
            b"FIX.4.2" => Ok(Self::Fix42),
            b"FIX.4.3" => Ok(Self::Fix43),
            b"FIX.4.4" => Ok(Self::Fix44),
            b"FIXT.1.1" => Ok(Self::Fixt11),
            _ => Err(Error::Version),
        }
    }
}

/// One owned field. Data values can contain SOH and arbitrary octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    tag: u32,
    value: Vec<u8>,
}
impl Field {
    /// Constructs a bounded field. Refuses zero tags, empty values, embedded SOH
    /// in text, and values over [`MAX_VALUE_LENGTH`]. Text remains single-byte
    /// character data; the caller selects its character set.
    pub fn new(tag: u32, value: &[u8]) -> Result<Self, Error> {
        check_field(tag, value)?;
        Ok(Self {
            tag,
            value: value.to_vec(),
        })
    }
    /// The numeric tag.
    pub fn tag(&self) -> u32 {
        self.tag
    }
    /// The field value, without the tag or delimiter.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    /// Reads an unsigned decimal integer with checked arithmetic.
    pub fn unsigned(&self) -> Result<u32, Error> {
        decimal(&self.value)
    }
    fn size(&self) -> usize {
        digits(self.tag as usize) + 2 + self.value.len()
    }
}
fn check_field(tag: u32, value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_VALUE_LENGTH {
        return Err(Error::Limit);
    }
    if tag == 0 {
        return Err(Error::Field);
    }
    if value.is_empty() || (!is_data(tag) && value.contains(&SOH)) {
        return Err(Error::Field);
    }
    Ok(())
}
fn is_data(tag: u32) -> bool {
    LENGTH_DATA_PAIRS.iter().any(|p| p.1 == tag)
}
fn data_tag(tag: u32) -> Option<u32> {
    LENGTH_DATA_PAIRS.iter().find(|p| p.0 == tag).map(|p| p.1)
}
fn decimal(b: &[u8]) -> Result<u32, Error> {
    if b.is_empty() || b.len() > 10 {
        return Err(Error::Field);
    }
    b.iter().try_fold(0u32, |n, b| {
        if !b.is_ascii_digit() {
            return Err(Error::Field);
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(*b - b'0')))
            .ok_or(Error::Field)
    })
}
fn digits(n: usize) -> usize {
    if n == 0 { 1 } else { n.ilog10() as usize + 1 }
}
fn append_field(out: &mut Vec<u8>, tag: u32, value: &[u8]) {
    out.extend_from_slice(tag.to_string().as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(SOH);
}

/// An ordered message. Tags 8 and 35 lead the stored list; tags 9 and 10 are
/// checked on parse and generated on write. Other fields preserve their bytes.
/// Groups stay flat until interpreted with a [`GroupLayout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    fields: Vec<Field>,
    stored_size: usize,
}
impl Message {
    /// Starts a message. Refuses an empty MsgType or one containing SOH.
    pub fn new(version: Version, msg_type: &[u8]) -> Result<Self, Error> {
        let begin = Field::new(8, version.begin_string())?;
        let kind = Field::new(35, msg_type)?;
        let stored_size = begin.size() + kind.size();
        Ok(Self {
            fields: vec![begin, kind],
            stored_size,
        })
    }
    /// Borrows all stored fields in wire order, without derived tags 9 and 10.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    /// Returns the first occurrence of a tag. Use group views for group members.
    pub fn get(&self, tag: u32) -> Option<&[u8]> {
        self.fields.iter().find(|f| f.tag == tag).map(Field::value)
    }
    /// Reads a singleton field and refuses duplicate occurrences.
    pub fn unique(&self, tag: u32) -> Result<Option<&[u8]>, Error> {
        unique(&self.fields, tag)
    }
    /// Returns MsgType.
    pub fn msg_type(&self) -> &[u8] {
        self.get(35).unwrap_or_default()
    }
    /// Returns the version carried by BeginString.
    pub fn version(&self) -> Result<Version, Error> {
        Version::from_begin_string(self.get(8).ok_or(Error::Header)?)
    }
    /// Appends a field. Refuses envelope tags and named size/count limits.
    /// Length/data consistency is checked by `write` or [`Self::validate`].
    /// Failure leaves the message unchanged.
    pub fn push(&mut self, tag: u32, value: &[u8]) -> Result<&mut Self, Error> {
        if matches!(tag, 8 | 9 | 10 | 35) {
            return Err(Error::Header);
        }
        check_field(tag, value)?;
        let size = digits(tag as usize) + 2 + value.len();
        let stored = self.stored_size.checked_add(size).ok_or(Error::Limit)?;
        if self.fields.len() >= MAX_FIELDS
            || stored.saturating_add(MAX_PREFIX_SIZE + 7) > MAX_MESSAGE_SIZE
        {
            return Err(Error::Limit);
        }
        self.fields.push(Field::new(tag, value)?);
        self.stored_size = stored;
        Ok(self)
    }
    /// Appends a standard Length/data pair, deriving the Length value.
    /// Refuses unknown pairs or size limits without changing the message.
    pub fn push_data(&mut self, length_tag: u32, value: &[u8]) -> Result<&mut Self, Error> {
        let tag = data_tag(length_tag).ok_or(Error::DataLength)?;
        let count = self.fields.len();
        let size = self.stored_size;
        let result = self
            .push(length_tag, value.len().to_string().as_bytes())
            .and_then(|m| m.push(tag, value));
        if let Err(e) = result {
            self.fields.truncate(count);
            self.stored_size = size;
            return Err(e);
        }
        Ok(self)
    }
    /// Checks the envelope, Length/data adjacency and named limits.
    /// Dictionary-specific required fields and groups require caller layouts.
    pub fn validate(&self) -> Result<(), Error> {
        self.version()?;
        if self.fields.first().map(Field::tag) != Some(8)
            || self.fields.get(1).map(Field::tag) != Some(35)
        {
            return Err(Error::Header);
        }
        if self.fields.len() > MAX_FIELDS
            || self.stored_size + MAX_PREFIX_SIZE + 7 > MAX_MESSAGE_SIZE
        {
            return Err(Error::Limit);
        }
        let mut pending = None;
        for (i, f) in self.fields.iter().enumerate() {
            check_field(f.tag, &f.value)?;
            if matches!(f.tag, 9 | 10) || (i > 1 && matches!(f.tag, 8 | 35)) {
                return Err(Error::Header);
            }
            if let Some((tag, len)) = pending.take() {
                if f.tag != tag || f.value.len() != len {
                    return Err(Error::DataLength);
                }
            } else if is_data(f.tag) {
                return Err(Error::DataLength);
            }
            if let Some(tag) = data_tag(f.tag) {
                let len = decimal(&f.value).map_err(|_| Error::DataLength)? as usize;
                if len > MAX_VALUE_LENGTH {
                    return Err(Error::Limit);
                }
                pending = Some((tag, len));
            }
        }
        if pending.is_some() {
            return Err(Error::DataLength);
        }
        Ok(())
    }
    /// Validates a group whose count field is at `field_index`, returning
    /// borrowed entry slices. Refuses invalid layouts, counts, and member order.
    pub fn group(&self, field_index: usize, layout: &GroupLayout<'_>) -> Result<Group<'_>, Error> {
        group(&self.fields, field_index, layout)
    }

    /// Checks all top-level groups using a complete caller-supplied layout list.
    /// Refuses duplicate top-level fields, invalid groups, and layout limits.
    /// Required application fields remain caller policy. Unknown count tags
    /// cannot be recognized as groups without a layout.
    pub fn validate_groups(&self, layouts: &[GroupLayout<'_>]) -> Result<(), Error> {
        self.validate()?;
        if layouts.len() > MAX_GROUP_LAYOUTS {
            return Err(Error::Limit);
        }
        let mut total = 0;
        for (i, layout) in layouts.iter().enumerate() {
            if layouts
                .iter()
                .take(i)
                .any(|g| g.count_tag == layout.count_tag)
            {
                return Err(Error::Group);
            }
            check_layout(layout, 1, &mut total)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut at = 0;
        while let Some(field) = self.fields.get(at) {
            if !seen.insert(field.tag) {
                return Err(Error::Duplicate(field.tag));
            }
            if let Some(layout) = layouts.iter().find(|g| g.count_tag == field.tag) {
                at = walk_group(&self.fields, at, layout, 1, &mut |_, _| {})?;
            } else {
                at += 1;
            }
        }
        Ok(())
    }

    /// Parses one exact message and checks its caller-supplied group layouts.
    /// Refuses everything refused by `Wire::parse` or [`Self::validate_groups`].
    pub fn parse_with_groups(bytes: &[u8], layouts: &[GroupLayout<'_>]) -> Result<Self, Error> {
        let message = Self::parse(bytes)?;
        message.validate_groups(layouts)?;
        Ok(message)
    }

    /// Writes after checking all caller-supplied groups and top-level uniqueness.
    /// Any layout, message, or group error leaves the destination unchanged.
    pub fn write_with_groups(
        &self,
        out: &mut Vec<u8>,
        layouts: &[GroupLayout<'_>],
    ) -> Result<(), Error> {
        self.validate_groups(layouts)?;
        self.write(out)
    }
}
fn unique(fields: &[Field], tag: u32) -> Result<Option<&[u8]>, Error> {
    let mut matches = fields.iter().filter(|f| f.tag == tag);
    let value = matches.next().map(Field::value);
    if matches.next().is_some() {
        return Err(Error::Duplicate(tag));
    }
    Ok(value)
}

// Only this fixed-size prefix is rescanned on incremental input.
fn prefix(input: &[u8]) -> Result<Option<(usize, usize)>, Error> {
    let bounded = input
        .get(..input.len().min(MAX_PREFIX_SIZE))
        .ok_or(Error::Header)?;
    let mut ends = bounded
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == SOH)
        .map(|p| p.0);
    let Some(first) = ends.next() else {
        return if input.len() >= MAX_PREFIX_SIZE {
            Err(Error::Header)
        } else {
            Ok(None)
        };
    };
    let begin = bounded
        .get(..first)
        .and_then(|b| b.strip_prefix(b"8="))
        .ok_or(Error::Header)?;
    Version::from_begin_string(begin)?;
    let Some(second) = ends.next() else {
        return if input.len() >= MAX_PREFIX_SIZE {
            Err(Error::Header)
        } else {
            Ok(None)
        };
    };
    let body = bounded
        .get(first + 1..second)
        .and_then(|b| b.strip_prefix(b"9="))
        .ok_or(Error::Header)?;
    let len = decimal(body).map_err(|_| Error::BodyLength)? as usize;
    if len < 5 {
        return Err(Error::BodyLength);
    }
    let start = second + 1;
    let total = start
        .checked_add(len)
        .and_then(|n| n.checked_add(7))
        .ok_or(Error::Limit)?;
    if total > MAX_MESSAGE_SIZE {
        return Err(Error::Limit);
    }
    Ok(Some((start, total)))
}
fn next_field<'a>(
    input: &'a [u8],
    pos: &mut usize,
    raw: Option<(u32, usize)>,
) -> Result<(u32, &'a [u8]), Error> {
    let rest = input.get(*pos..).ok_or(Error::Incomplete)?;
    let eq = rest
        .iter()
        .take(11)
        .position(|b| *b == b'=')
        .ok_or(Error::Field)?;
    let tag_bytes = rest.get(..eq).ok_or(Error::Field)?;
    if tag_bytes.first() == Some(&b'0') {
        return Err(Error::Field);
    }
    let tag = decimal(tag_bytes)?;
    let start = pos.checked_add(eq + 1).ok_or(Error::Limit)?;
    let value_rest = input.get(start..).ok_or(Error::Incomplete)?;
    let len = if let Some((expected, len)) = raw {
        if expected != tag {
            return Err(Error::DataLength);
        }
        len
    } else {
        if is_data(tag) {
            return Err(Error::DataLength);
        }
        value_rest
            .iter()
            .take(MAX_VALUE_LENGTH + 1)
            .position(|b| *b == SOH)
            .ok_or(Error::Field)?
    };
    let end = start.checked_add(len).ok_or(Error::Limit)?;
    if input.get(end) != Some(&SOH) {
        return Err(Error::DataLength);
    }
    let value = input.get(start..end).ok_or(Error::Incomplete)?;
    check_field(tag, value)?;
    *pos = end + 1;
    Ok((tag, value))
}
impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads exactly one message. Refuses truncation, trailing bytes, bad
    /// envelope order, lengths, checksum, fields, data pairs, and named limits.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Limit);
        }
        let (start, total) = prefix(input)?.ok_or(Error::Incomplete)?;
        if input.len() < total {
            return Err(Error::Incomplete);
        }
        if input.len() > total {
            return Err(Error::Trailing);
        }
        let checksum_at = total.checked_sub(7).ok_or(Error::BodyLength)?;
        let trailer = input.get(checksum_at..).ok_or(Error::Incomplete)?;
        let checksum = match trailer {
            [b'1', b'0', b'=', a, b, c, SOH]
                if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() =>
            {
                u32::from(*a - b'0') * 100 + u32::from(*b - b'0') * 10 + u32::from(*c - b'0')
            }
            _ => return Err(Error::Checksum),
        };
        let content = input.get(..checksum_at).ok_or(Error::BodyLength)?;
        if content.last() != Some(&SOH) {
            return Err(Error::BodyLength);
        }
        if content.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) as u32 != checksum {
            return Err(Error::Checksum);
        }
        let mut pos = 0;
        let (tag, begin) = next_field(content, &mut pos, None)?;
        if tag != 8 {
            return Err(Error::Header);
        }
        let version = Version::from_begin_string(begin)?;
        pos = start;
        let (tag, kind) = next_field(content, &mut pos, None)?;
        if tag != 35 {
            return Err(Error::Header);
        }
        let mut message = Self::new(version, kind)?;
        let mut pending = None;
        while pos < checksum_at {
            let (tag, value) = next_field(content, &mut pos, pending.take())?;
            message.push(tag, value)?;
            if let Some(data) = data_tag(tag) {
                let len = decimal(value).map_err(|_| Error::DataLength)? as usize;
                if len > MAX_VALUE_LENGTH {
                    return Err(Error::Limit);
                }
                pending = Some((data, len));
            }
        }
        message.validate()?;
        Ok(message)
    }
    /// Appends one message with computed BodyLength and three-digit CheckSum.
    /// Refuses invalid fields, envelope tags, data pairs, or named limits.
    /// All checks finish before appending; an error leaves `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        let begin = self.fields.first().ok_or(Error::Header)?;
        let body = self
            .stored_size
            .checked_sub(begin.size())
            .ok_or(Error::Header)?;
        let total = self
            .stored_size
            .checked_add(3 + digits(body) + 7)
            .ok_or(Error::Limit)?;
        if total > MAX_MESSAGE_SIZE {
            return Err(Error::Limit);
        }
        let offset = out.len();
        append_field(out, 8, begin.value());
        append_field(out, 9, body.to_string().as_bytes());
        for field in self.fields.iter().skip(1) {
            append_field(out, field.tag, field.value());
        }
        let sum = out
            .get(offset..)
            .unwrap_or_default()
            .iter()
            .fold(0u8, |n, b| n.wrapping_add(*b));
        append_field(
            out,
            10,
            &[b'0' + sum / 100, b'0' + sum / 10 % 10, b'0' + sum % 10],
        );
        Ok(())
    }
}

/// Splits a TCP byte stream using BodyLength. No input bytes are retained.
/// At most [`MAX_PREFIX_SIZE`] header bytes are rescanned per call. The body
/// is parsed only when complete, so one-byte delivery takes linear time.
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;
impl Decode for Frames {
    type Item = Message;
    type Error = Error;
    const NAME: &'static str = "FIX";
    /// The maximum unread input needed before a message or error is returned.
    fn capacity(&self) -> usize {
        MAX_MESSAGE_SIZE
    }
    /// Returns one checked message. Refuses invalid framing or message bytes.
    /// Partial input returns `Need`, including at EOF; the driver reports truncation.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Message>, Error> {
        let Some((_, total)) = prefix(input)? else {
            return Ok(Step::Need);
        };
        let Some(bytes) = input.get(..total) else {
            return Ok(Step::Need);
        };
        Ok(Step::Item(Message::parse(bytes)?, total))
    }
}

/// Caller-supplied NumInGroup layout. `members` lists tags in wire order,
/// beginning with `delimiter_tag`. A nested group's count tag is a member.
/// Validation bounds both depth and the total number of layouts, even for cycles.
#[derive(Clone, Copy)]
pub struct GroupLayout<'a> {
    /// NumInGroup tag.
    pub count_tag: u32,
    /// First field of every entry.
    pub delimiter_tag: u32,
    /// Allowed tags in wire order, including the delimiter and nested count tags.
    pub members: &'a [u32],
    /// Layouts of nested groups.
    pub nested: &'a [GroupLayout<'a>],
}
impl fmt::Debug for GroupLayout<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupLayout")
            .field("count_tag", &self.count_tag)
            .field("delimiter_tag", &self.delimiter_tag)
            .field("member_count", &self.members.len())
            .field("nested_count", &self.nested.len())
            .finish()
    }
}
/// Validated repeating-group entries, borrowing the original fields.
#[derive(Debug)]
pub struct Group<'a> {
    entries: Vec<&'a [Field]>,
    end: usize,
}
impl<'a> Group<'a> {
    /// The entries, each including its delimiter and any nested group fields.
    pub fn entries(&self) -> &[&'a [Field]] {
        &self.entries
    }
    /// Field index just after this group in its input field slice.
    pub fn end_index(&self) -> usize {
        self.end
    }
    /// Reads a nested group in an entry, with indexes relative to that entry.
    pub fn nested(
        &self,
        entry: usize,
        count_index: usize,
        layout: &GroupLayout<'_>,
    ) -> Result<Group<'a>, Error> {
        group(
            self.entries.get(entry).copied().ok_or(Error::Group)?,
            count_index,
            layout,
        )
    }
}
fn check_layout(layout: &GroupLayout<'_>, depth: usize, total: &mut usize) -> Result<(), Error> {
    *total = total.checked_add(1).ok_or(Error::Limit)?;
    if depth > MAX_GROUP_DEPTH
        || *total > MAX_GROUP_LAYOUTS
        || layout.members.len() > MAX_GROUP_MEMBERS
        || layout.nested.len() > MAX_GROUP_LAYOUTS
    {
        return Err(Error::Limit);
    }
    if layout.count_tag == 0
        || layout.members.first() != Some(&layout.delimiter_tag)
        || layout.members.contains(&layout.count_tag)
    {
        return Err(Error::Group);
    }
    for (i, tag) in layout.members.iter().enumerate() {
        if *tag == 0 || layout.members.get(..i).ok_or(Error::Group)?.contains(tag) {
            return Err(Error::Group);
        }
    }
    for (i, child) in layout.nested.iter().enumerate() {
        if !layout.members.contains(&child.count_tag)
            || layout
                .nested
                .iter()
                .take(i)
                .any(|p| p.count_tag == child.count_tag)
        {
            return Err(Error::Group);
        }
        check_layout(child, depth + 1, total)?;
    }
    Ok(())
}
fn group<'a>(
    fields: &'a [Field],
    index: usize,
    layout: &GroupLayout<'_>,
) -> Result<Group<'a>, Error> {
    check_layout(layout, 1, &mut 0)?;
    let mut entries = Vec::new();
    let end = walk_group(fields, index, layout, 1, &mut |start, end| {
        if let Some(slice) = fields.get(start..end) {
            entries.push(slice);
        }
    })?;
    Ok(Group { entries, end })
}
fn walk_group(
    fields: &[Field],
    index: usize,
    layout: &GroupLayout<'_>,
    depth: usize,
    on_entry: &mut dyn FnMut(usize, usize),
) -> Result<usize, Error> {
    if depth > MAX_GROUP_DEPTH {
        return Err(Error::Limit);
    }
    let count = fields
        .get(index)
        .filter(|f| f.tag == layout.count_tag)
        .ok_or(Error::Group)?
        .unsigned()? as usize;
    if count > MAX_GROUP_COUNT {
        return Err(Error::Limit);
    }
    let mut at = index.checked_add(1).ok_or(Error::Group)?;
    for _ in 0..count {
        let start = at;
        if fields.get(at).map(Field::tag) != Some(layout.delimiter_tag) {
            return Err(Error::Group);
        }
        if let Some(child) = layout
            .nested
            .iter()
            .find(|g| g.count_tag == layout.delimiter_tag)
        {
            at = walk_group(fields, at, child, depth + 1, &mut |_, _| {})?;
        } else {
            at += 1;
        }
        let mut previous = 0;
        while let Some(field) = fields.get(at) {
            if field.tag == layout.delimiter_tag {
                break;
            }
            let Some(order) = layout.members.iter().position(|t| *t == field.tag) else {
                break;
            };
            if order <= previous {
                return Err(Error::Group);
            }
            previous = order;
            if let Some(child) = layout.nested.iter().find(|g| g.count_tag == field.tag) {
                at = walk_group(fields, at, child, depth + 1, &mut |_, _| {})?;
            } else {
                at += 1;
            }
        }
        on_entry(start, at);
    }
    if fields
        .get(at)
        .is_some_and(|f| layout.members.contains(&f.tag))
    {
        return Err(Error::Group);
    }
    Ok(at)
}

macro_rules! application_view {
    ($view:ident, $builder:ident, $kind:literal, $description:literal, {$($method:ident: $tag:literal => $doc:literal),* $(,)?}) => {
        #[doc = $description]
        #[doc = " Borrows a Message without copying field data. This is a field view, not a dictionary validator."]
        #[derive(Clone, Copy, Debug)]
        pub struct $view<'a> { message: &'a Message }
        impl<'a> $view<'a> {
            /// Checks MsgType and borrows the message. Other message types are refused.
            pub fn view(message: &'a Message) -> Result<Self, Error> {
                if message.msg_type() != $kind { return Err(Error::MessageType); }
                Ok(Self { message })
            }
            /// Starts a builder backed by one Message. Add session fields through
            /// `field`, or pass the finished body to [`Session::send`].
            pub fn builder(version: Version) -> Result<$builder, Error> {
                Ok($builder { message: Message::new(version, $kind)? })
            }
            /// The underlying ordered message.
            pub fn message(self) -> &'a Message { self.message }
            $(#[doc = $doc]
            pub fn $method(self) -> Option<&'a [u8]> { self.message.get($tag) })*
        }
        #[doc = concat!("Builder for [`", stringify!($view), "`], storing fields only in its Message.")]
        #[derive(Debug)]
        pub struct $builder { message: Message }
        impl $builder {
            /// Appends an extension or group field. Refuses envelope tags and
            /// field limits. Repeated tags are retained in the supplied order.
            pub fn field(&mut self, tag: u32, value: &[u8]) -> Result<&mut Self, Error> {
                self.message.push(tag, value)?; Ok(self)
            }
            $(#[doc = $doc]
            #[doc = " The builder refuses a second occurrence of this singleton."]
            pub fn $method(&mut self, value: &[u8]) -> Result<&mut Self, Error> {
                if self.message.get($tag).is_some() { return Err(Error::Duplicate($tag)); }
                self.field($tag, value)
            })*
            /// Returns the Message after wire validation. Required application
            /// fields, numeric types, and group layouts remain caller policy.
            pub fn finish(self) -> Result<Message, Error> { self.message.validate()?; Ok(self.message) }
        }
    };
}
application_view!(NewOrderSingle, NewOrderSingleBuilder, b"D", "NewOrderSingle (D), FIX 4.2 and FIX 4.4 Volume 4.", {
    cl_ord_id: 11 => "Client order identifier, ClOrdID (11).",
    symbol: 55 => "Instrument symbol (55).",
    side: 54 => "Order side (54).",
    transact_time: 60 => "Transaction timestamp (60).",
    order_qty: 38 => "Order quantity (38), as an exact decimal string.",
    ord_type: 40 => "Order type (40).",
    price: 44 => "Limit price (44), as an exact decimal string.",
    time_in_force: 59 => "Time in force (59).",
    handl_inst: 21 => "Handling instruction (21)."
});
application_view!(ExecutionReport, ExecutionReportBuilder, b"8", "ExecutionReport (8), FIX 4.2 and FIX 4.4 Volume 4.", {
    order_id: 37 => "Order identifier (37).",
    cl_ord_id: 11 => "Client order identifier (11).",
    exec_id: 17 => "Execution identifier (17).",
    exec_type: 150 => "Execution type (150).",
    exec_trans_type: 20 => "FIX 4.2 execution transaction type (20).",
    ord_status: 39 => "Order status (39).",
    symbol: 55 => "Instrument symbol (55).",
    side: 54 => "Order side (54).",
    leaves_qty: 151 => "Remaining quantity (151).",
    cum_qty: 14 => "Cumulative quantity (14).",
    avg_px: 6 => "Average price (6).",
    last_qty: 32 => "Last fill quantity (32).",
    last_px: 31 => "Last fill price (31)."
});
application_view!(OrderCancelRequest, OrderCancelRequestBuilder, b"F", "OrderCancelRequest (F), FIX 4.2 and FIX 4.4 Volume 4.", {
    orig_cl_ord_id: 41 => "Previous client order identifier (41).",
    cl_ord_id: 11 => "New client request identifier (11).",
    order_id: 37 => "Order identifier (37).",
    symbol: 55 => "Instrument symbol (55).",
    side: 54 => "Order side (54).",
    transact_time: 60 => "Transaction timestamp (60).",
    order_qty: 38 => "Order quantity (38)."
});
application_view!(OrderCancelReplaceRequest, OrderCancelReplaceRequestBuilder, b"G", "OrderCancelReplaceRequest (G), FIX 4.2 and FIX 4.4 Volume 4.", {
    orig_cl_ord_id: 41 => "Previous client order identifier (41).",
    cl_ord_id: 11 => "New client order identifier (11).",
    order_id: 37 => "Order identifier (37).",
    symbol: 55 => "Instrument symbol (55).",
    side: 54 => "Order side (54).",
    transact_time: 60 => "Transaction timestamp (60).",
    order_qty: 38 => "Replacement quantity (38).",
    ord_type: 40 => "Replacement order type (40).",
    price: 44 => "Replacement price (44).",
    handl_inst: 21 => "Handling instruction (21)."
});
application_view!(MarketDataRequest, MarketDataRequestBuilder, b"V", "MarketDataRequest (V), FIX 4.2 and FIX 4.4 Volume 3.", {
    md_req_id: 262 => "Market data request identifier (262).",
    subscription_request_type: 263 => "Subscription request type (263).",
    market_depth: 264 => "Requested market depth (264).",
    md_update_type: 265 => "Market data update type (265).",
    aggregated_book: 266 => "Aggregated book flag (266).",
    no_md_entry_types: 267 => "Number of entry types (267); append entries with the builder's field method.",
    no_related_sym: 146 => "Number of instruments (146); append entries with the builder's field method."
});
application_view!(MarketDataSnapshotFullRefresh, MarketDataSnapshotFullRefreshBuilder, b"W", "MarketDataSnapshotFullRefresh (W), FIX 4.2 and FIX 4.4 Volume 3.", {
    md_req_id: 262 => "Market data request identifier (262).",
    symbol: 55 => "Instrument symbol (55).",
    no_md_entries: 268 => "Number of entries (268); interpret with a caller-supplied group layout."
});
application_view!(MarketDataIncrementalRefresh, MarketDataIncrementalRefreshBuilder, b"X", "MarketDataIncrementalRefresh (X), FIX 4.2 and FIX 4.4 Volume 3.", {
    md_req_id: 262 => "Market data request identifier (262).",
    no_md_entries: 268 => "Number of entries (268); interpret with a caller-supplied group layout."
});

/// Which side initiates the Logon exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sends Logon first.
    Initiator,
    /// Waits for Logon, then confirms it.
    Acceptor,
}
/// Connection state. Sequence counters belong to the FIX session and can be
/// saved by the caller and passed to a new machine after a disconnection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// No Logon has been sent or accepted.
    AwaitingLogon,
    /// Waiting for a Logon confirmation.
    LogonSent,
    /// Logon completed; sequence recovery may still be in progress.
    Established,
    /// Logout sent; awaiting the peer's confirmation or timeout.
    LogoutSent,
    /// Caller should close the transport.
    Closed,
}
/// Caller policy for a FIX session. Only unencrypted session payloads
/// (EncryptMethod=0) are supported. Transport security belongs to the caller.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Session BeginString.
    pub version: Version,
    /// Logon role.
    pub role: Role,
    /// Local SenderCompID (49), bounded by [`MAX_SESSION_ID_LENGTH`].
    pub sender_comp_id: String,
    /// Peer TargetCompID (56), bounded by [`MAX_SESSION_ID_LENGTH`].
    pub target_comp_id: String,
    /// Initiator's HeartBtInt. The acceptor adopts it. Zero disables automatic liveness probes.
    pub heartbeat_seconds: u32,
    /// Extra time added to HeartBtInt before TestRequest and its timeout.
    /// Bounded by one day in milliseconds.
    pub transmission_grace_ms: u64,
    /// Logon response timeout, in milliseconds, from construction or start.
    pub logon_timeout_ms: u64,
    /// Logout response timeout, in milliseconds.
    pub logout_timeout_ms: u64,
    /// Permits ResetSeqNumFlag=Y on the initial Logon exchange.
    pub allow_logon_reset: bool,
    /// DefaultApplVerID (1137). Required for FIXT 1.1; absent for FIX 4.x.
    pub default_appl_ver_id: Option<String>,
}
impl SessionConfig {
    /// Creates a policy with 30-second heartbeats, one second of transmission
    /// grace, a 10-second Logon timeout, and a two-second Logout timeout.
    /// FIXT defaults to application version 6 (FIX 4.4).
    pub fn new(version: Version, role: Role, sender: &str, target: &str) -> Result<Self, Error> {
        session_id(sender.as_bytes())?;
        session_id(target.as_bytes())?;
        Ok(Self {
            version,
            role,
            sender_comp_id: sender.into(),
            target_comp_id: target.into(),
            heartbeat_seconds: 30,
            transmission_grace_ms: 1000,
            logon_timeout_ms: 10_000,
            logout_timeout_ms: 2000,
            allow_logon_reset: false,
            default_appl_ver_id: (version == Version::Fixt11).then(|| "6".into()),
        })
    }
    fn validate(&self) -> Result<(), Error> {
        session_id(self.sender_comp_id.as_bytes())?;
        session_id(self.target_comp_id.as_bytes())?;
        if self.heartbeat_seconds > MAX_HEARTBEAT_SECONDS
            || self.transmission_grace_ms > 86_400_000
            || !(1..=86_400_000).contains(&self.logon_timeout_ms)
            || !(1..=86_400_000).contains(&self.logout_timeout_ms)
        {
            return Err(Error::Limit);
        }
        match (&self.default_appl_ver_id, self.version) {
            (Some(id), Version::Fixt11) => session_id(id.as_bytes()),
            (None, v) if v != Version::Fixt11 => Ok(()),
            _ => Err(Error::Session),
        }
    }
}
fn session_id(id: &[u8]) -> Result<(), Error> {
    if id.len() > MAX_SESSION_ID_LENGTH {
        return Err(Error::Limit);
    }
    check_field(49, id)
}
/// Why a transport should be closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Logout completed.
    Logout,
    /// Logon was not completed before the configured deadline.
    LogonTimeout,
    /// Logout was not confirmed before the configured deadline.
    LogoutTimeout,
    /// The peer did not answer a TestRequest before its deadline.
    TestRequestTimeout,
    /// A low sequence number arrived without PossDupFlag.
    SequenceTooLow,
    /// A session identity, Logon, or sequence reset was invalid.
    Protocol,
}
/// Notifications emitted by [`Session`]. They do not retain received messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Logon completed. The peer's FIXT application version is included when present.
    Established {
        /// Peer DefaultApplVerID, at most [`MAX_SESSION_ID_LENGTH`] bytes.
        peer_default_appl_ver_id: Option<Vec<u8>>,
    },
    /// Deliver the current input message to the application.
    Application {
        /// Accepted sequence number.
        sequence: u32,
        /// Whether PossDupFlag was set.
        possible_duplicate: bool,
    },
    /// The current message is ahead of the expected sequence. It is discarded.
    /// The emitted ResendRequest includes this number, so its replay can be delivered.
    Gap {
        /// Next expected sequence number.
        expected: u32,
        /// Observed sequence number.
        received: u32,
    },
    /// A previously consumed sequence number was safely ignored.
    Duplicate(u32),
    /// The caller must replay this inclusive range from its own message store.
    /// Use [`Session::replay`] for retained messages and [`Session::gap_fill`]
    /// for skipped administrative messages or unavailable application messages.
    Resend {
        /// First requested sequence number.
        begin: u32,
        /// Last requested sequence number; never zero and range-bounded.
        end: u32,
    },
    /// A received Reject names an earlier outbound sequence number.
    RejectReceived(u32),
    /// A received message was rejected. The matching Reject is also emitted.
    Rejected {
        /// Rejected sequence number.
        sequence: u32,
        /// Offending field.
        tag: u32,
        /// FIX SessionRejectReason (373).
        reason: u32,
    },
    /// SequenceReset changed the next inbound sequence number.
    SequenceReset {
        /// Previous next expected number.
        previous: u32,
        /// New next expected number.
        next: u32,
        /// True for gap fill, false for reset mode.
        gap_fill: bool,
    },
    /// The caller should close the transport after sending any preceding actions.
    Disconnected(CloseReason),
}
/// A session's ordered output. Send outbound messages before acting on later events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A complete outbound FIX message, ready for [`Wire::write`].
    Send(Message),
    /// A notification for the caller.
    Event(Event),
}
fn action(actions: &mut Vec<Action>, value: Action) -> Result<(), Error> {
    if actions.len() >= MAX_ACTIONS {
        return Err(Error::Limit);
    }
    actions.push(value);
    Ok(())
}

/// A FIX 4.2–4.4 or FIXT 1.1 session without I/O or clocks.
///
/// All time arguments are monotonic milliseconds chosen by the caller.
/// SendingTime is a separately supplied UTC timestamp. Receive operations
/// require wire-valid messages; pass [`Frames`] output directly. The caller
/// authenticates the peer before handing over Logon and owns persistence.
/// Counters advance when output is emitted, so the caller must persist and send
/// each returned message in order. An `Err` leaves the machine unchanged.
///
/// Recovery retains only range counters. Messages above the expected number
/// are requested again, including the first observed high message. The caller
/// supplies replay messages one at a time; no replay store or input queue grows
/// inside the machine. All emitted ranges are at most [`MAX_RESEND_RANGE`].
#[derive(Clone, Debug)]
pub struct Session {
    config: SessionConfig,
    state: SessionState,
    incoming: u32,
    outgoing: u32,
    last_now: u64,
    last_received: u64,
    last_sent: u64,
    state_since: u64,
    heartbeat: u32,
    test: Option<(String, u64)>,
    test_serial: u64,
    gap_high: Option<u32>,
    requested_through: Option<u32>,
    reset_requested: bool,
    replay_remaining: Option<(u32, u32)>,
}
impl Session {
    /// Creates a machine using persisted next inbound and outbound numbers.
    /// Both must be positive and below `u32::MAX`. Validates all config limits.
    pub fn new(
        config: SessionConfig,
        next_inbound: u32,
        next_outbound: u32,
        now_ms: u64,
    ) -> Result<Self, Error> {
        config.validate()?;
        seq(next_inbound)?;
        seq(next_outbound)?;
        let heartbeat = config.heartbeat_seconds;
        Ok(Self {
            config,
            state: SessionState::AwaitingLogon,
            incoming: next_inbound,
            outgoing: next_outbound,
            last_now: now_ms,
            last_received: now_ms,
            last_sent: now_ms,
            state_since: now_ms,
            heartbeat,
            test: None,
            test_serial: 0,
            gap_high: None,
            requested_through: None,
            reset_requested: false,
            replay_remaining: None,
        })
    }
    /// Current connection state.
    pub fn state(&self) -> SessionState {
        self.state
    }
    /// Next inbound sequence number to persist.
    pub fn next_inbound(&self) -> u32 {
        self.incoming
    }
    /// Next outbound sequence number to persist.
    pub fn next_outbound(&self) -> u32 {
        self.outgoing
    }
    /// Negotiated heartbeat interval in seconds.
    pub fn heartbeat_seconds(&self) -> u32 {
        self.heartbeat
    }
    /// Sends an explicit TestRequest, including when HeartBtInt is zero.
    /// Refuses an outstanding probe, a non-established session, or an ID over
    /// [`MAX_TEST_REQUEST_ID_LENGTH`]. The timeout is HeartBtInt plus grace.
    pub fn test_request(
        &mut self,
        id: &[u8],
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.state != SessionState::Established || s.test.is_some() {
                return Err(Error::State);
            }
            if id.len() > MAX_TEST_REQUEST_ID_LENGTH {
                return Err(Error::Limit);
            }
            let id = std::str::from_utf8(id).map_err(|_| Error::Field)?;
            s.emit(b"1", &[(112, id.as_bytes())], now_ms, sending_time, actions)?;
            s.test = Some((id.into(), now_ms));
            Ok(())
        })
    }
    /// Sends the initiator's Logon. Reset requests need explicit config consent.
    /// Refuses another role/state, invalid time, or sequence exhaustion.
    pub fn start(
        &mut self,
        now_ms: u64,
        sending_time: &[u8],
        reset: bool,
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.config.role != Role::Initiator || s.state != SessionState::AwaitingLogon {
                return Err(Error::State);
            }
            if reset && !s.config.allow_logon_reset {
                return Err(Error::Session);
            }
            if reset {
                s.incoming = 1;
                s.outgoing = 1;
            }
            s.reset_requested = reset;
            s.logon(now_ms, sending_time, reset, actions)?;
            s.state = SessionState::LogonSent;
            s.state_since = now_ms;
            Ok(())
        })
    }
    /// Processes a received message. Emits administrative responses and events.
    /// Refuses wire-invalid values and backward caller time transactionally.
    pub fn receive(
        &mut self,
        message: &Message,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        message.validate()?;
        self.transaction(now_ms, sending_time, |s, actions| {
            s.receive_inner(message, now_ms, sending_time, actions)
        })
    }
    /// Advances timers. Sends Heartbeat after outgoing silence, TestRequest
    /// after inbound silence plus grace, and disconnects on expired probes.
    /// Only a Heartbeat with the outstanding TestReqID satisfies a probe.
    pub fn tick(&mut self, now_ms: u64, sending_time: &[u8]) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            match s.state {
                SessionState::Closed => return Ok(()),
                SessionState::AwaitingLogon | SessionState::LogonSent => {
                    if now_ms - s.state_since >= s.config.logon_timeout_ms {
                        s.close(CloseReason::LogonTimeout, actions)?;
                    }
                    return Ok(());
                }
                SessionState::LogoutSent => {
                    if now_ms - s.state_since >= s.config.logout_timeout_ms {
                        s.close(CloseReason::LogoutTimeout, actions)?;
                    }
                    return Ok(());
                }
                SessionState::Established => {}
            }
            let interval = u64::from(s.heartbeat) * 1000;
            let timeout = interval + s.config.transmission_grace_ms;
            if let Some((_, sent)) = &s.test {
                if now_ms - *sent >= timeout {
                    s.fatal(
                        CloseReason::TestRequestTimeout,
                        b"TestRequest timeout",
                        now_ms,
                        sending_time,
                        actions,
                    )?;
                    return Ok(());
                }
            } else if interval != 0 && now_ms - s.last_received >= timeout {
                s.test_serial = s.test_serial.checked_add(1).ok_or(Error::Limit)?;
                let id = s.test_serial.to_string();
                s.emit(b"1", &[(112, id.as_bytes())], now_ms, sending_time, actions)?;
                s.test = Some((id, now_ms));
            }
            if interval != 0 && now_ms - s.last_sent >= interval {
                s.emit(b"0", &[], now_ms, sending_time, actions)?;
            }
            Ok(())
        })
    }
    /// Sends an application body with fresh session header fields. Refuses
    /// administrative MsgTypes, existing session fields, and non-established state.
    pub fn send(
        &mut self,
        body: &Message,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        body.validate()?;
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.state != SessionState::Established {
                return Err(Error::State);
            }
            if admin(body.msg_type()) || body.version()? != s.config.version {
                return Err(Error::MessageType);
            }
            let mut message = s.application_header(
                body.msg_type(),
                s.outgoing,
                sending_time,
                body.unique(1128)?,
            )?;
            for field in body.fields.iter().skip(2) {
                if field.tag == 1128 {
                    continue;
                }
                if session_tag(field.tag) {
                    return Err(Error::Duplicate(field.tag));
                }
                message.push(field.tag, field.value())?;
            }
            s.send_fresh(message, now_ms, actions)
        })
    }
    /// Initiates Logout and waits for confirmation. Refuses a closed or
    /// not-yet-established session, invalid Text, and sequence exhaustion.
    pub fn logout(
        &mut self,
        text: &[u8],
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.state != SessionState::Established {
                return Err(Error::State);
            }
            s.emit(b"5", &[(58, text)], now_ms, sending_time, actions)?;
            s.state = SessionState::LogoutSent;
            s.state_since = now_ms;
            Ok(())
        })
    }
    /// Sends a session Reject for an application-level field validation failure.
    /// `reason` is SessionRejectReason (373); `tag` is RefTagID (371).
    pub fn reject(
        &mut self,
        reference: u32,
        tag: u32,
        reason: u32,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.state != SessionState::Established {
                return Err(Error::State);
            }
            seq(reference)?;
            s.reject_inner(reference, tag, reason, now_ms, sending_time, actions)
        })
    }
    /// Replays a stored application message or Reject at its original MsgSeqNum.
    /// Preserves the original SendingTime in tag 122, sets PossDupFlag, and does
    /// not advance the outbound counter. Refuses other administrative messages,
    /// foreign session identities, unsent numbers, or timestamps before the original.
    pub fn replay(
        &mut self,
        original: &Message,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        original.validate()?;
        self.transaction(now_ms, sending_time, |s, actions| {
            s.recovery_state()?;
            if admin(original.msg_type()) && original.msg_type() != b"3" {
                return Err(Error::MessageType);
            }
            if original.version()? != s.config.version
                || required(original, 49)? != s.config.sender_comp_id.as_bytes()
                || required(original, 56)? != s.config.target_comp_id.as_bytes()
            {
                return Err(Error::Session);
            }
            let number = number(original, 34)?;
            seq(number)?;
            if number >= s.outgoing {
                return Err(Error::Sequence);
            }
            let original_time = original.unique(122)?.unwrap_or(required(original, 52)?);
            if timestamp(original_time)? > timestamp(sending_time)? {
                return Err(Error::Time);
            }
            let mut message = s.application_header(
                original.msg_type(),
                number,
                sending_time,
                original.unique(1128)?,
            )?;
            message.push(43, b"Y")?.push(122, original_time)?;
            for field in original.fields.iter().skip(2) {
                if matches!(field.tag, 49 | 56 | 34 | 52 | 43 | 122 | 1128) {
                    continue;
                }
                message.push(field.tag, field.value())?;
            }
            message.validate()?;
            action(actions, Action::Send(message))?;
            s.last_sent = now_ms;
            Ok(())
        })
    }
    /// Sends a SequenceReset gap fill for `[begin, next)`. Does not advance the
    /// outbound counter. Refuses empty, unsent, or over-limit ranges. The caller
    /// supplies the original timestamp for PossDupFlag/OrigSendingTime.
    pub fn gap_fill(
        &mut self,
        begin: u32,
        next: u32,
        original_time: &[u8],
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            s.recovery_state()?;
            seq(begin)?;
            seq(next)?;
            if next <= begin || next > s.outgoing || next - begin > MAX_RESEND_RANGE {
                return Err(Error::Sequence);
            }
            if timestamp(original_time)? > timestamp(sending_time)? {
                return Err(Error::Time);
            }
            let mut message = s.header(b"4", begin, sending_time)?;
            message
                .push(43, b"Y")?
                .push(122, original_time)?
                .push(123, b"Y")?
                .push(36, next.to_string().as_bytes())?;
            action(actions, Action::Send(message))?;
            s.last_sent = now_ms;
            Ok(())
        })
    }
    /// Sends SequenceReset in disaster-recovery reset mode. The next outbound
    /// sequence becomes `next`. Refuses any decrease or non-established state.
    pub fn reset_sequence(
        &mut self,
        next: u32,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.state != SessionState::Established {
                return Err(Error::State);
            }
            seq(next)?;
            if next <= s.outgoing {
                return Err(Error::Sequence);
            }
            s.emit(
                b"4",
                &[(123, b"N"), (36, next.to_string().as_bytes())],
                now_ms,
                sending_time,
                actions,
            )?;
            s.outgoing = next;
            Ok(())
        })
    }
    fn transaction(
        &mut self,
        now: u64,
        time: &[u8],
        operation: impl FnOnce(&mut Self, &mut Vec<Action>) -> Result<(), Error>,
    ) -> Result<Vec<Action>, Error> {
        if now < self.last_now {
            return Err(Error::Time);
        }
        timestamp(time)?;
        let mut staged = self.clone();
        let mut actions = Vec::new();
        operation(&mut staged, &mut actions)?;
        staged.last_now = now;
        *self = staged;
        Ok(actions)
    }
    fn recovery_state(&self) -> Result<(), Error> {
        if matches!(
            self.state,
            SessionState::Established | SessionState::LogoutSent
        ) {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
    fn header(&self, kind: &[u8], sequence: u32, time: &[u8]) -> Result<Message, Error> {
        self.application_header(kind, sequence, time, None)
    }
    fn application_header(
        &self,
        kind: &[u8],
        sequence: u32,
        time: &[u8],
        appl_version: Option<&[u8]>,
    ) -> Result<Message, Error> {
        seq(sequence)?;
        timestamp(time)?;
        let mut message = Message::new(self.config.version, kind)?;
        message
            .push(49, self.config.sender_comp_id.as_bytes())?
            .push(56, self.config.target_comp_id.as_bytes())?;
        if let Some(version) = appl_version {
            if self.config.version != Version::Fixt11 || admin(kind) {
                return Err(Error::Session);
            }
            session_id(version)?;
            message.push(1128, version)?;
        }
        message
            .push(34, sequence.to_string().as_bytes())?
            .push(52, time)?;
        Ok(message)
    }
    fn send_fresh(
        &mut self,
        message: Message,
        now: u64,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        message.validate()?;
        let next = self.outgoing.checked_add(1).ok_or(Error::Sequence)?;
        seq(next)?;
        action(actions, Action::Send(message))?;
        self.outgoing = next;
        self.last_sent = now;
        Ok(())
    }
    fn emit(
        &mut self,
        kind: &[u8],
        fields: &[(u32, &[u8])],
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        let mut message = self.header(kind, self.outgoing, time)?;
        for (tag, value) in fields {
            message.push(*tag, value)?;
        }
        self.send_fresh(message, now, actions)
    }
    fn logon(
        &mut self,
        now: u64,
        time: &[u8],
        reset: bool,
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        let mut message = self.header(b"A", self.outgoing, time)?;
        message
            .push(98, b"0")?
            .push(108, self.heartbeat.to_string().as_bytes())?;
        if reset {
            message.push(141, b"Y")?;
        }
        if let Some(id) = &self.config.default_appl_ver_id {
            message.push(1137, id.as_bytes())?;
        }
        self.send_fresh(message, now, actions)
    }
    fn close(&mut self, reason: CloseReason, actions: &mut Vec<Action>) -> Result<(), Error> {
        self.state = SessionState::Closed;
        self.test = None;
        action(actions, Action::Event(Event::Disconnected(reason)))
    }
    fn fatal(
        &mut self,
        reason: CloseReason,
        text: &[u8],
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        self.emit(b"5", &[(58, text)], now, time, actions)?;
        self.close(reason, actions)
    }
    fn reject_inner(
        &mut self,
        reference: u32,
        tag: u32,
        reason: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        self.emit(
            b"3",
            &[
                (45, reference.to_string().as_bytes()),
                (371, tag.to_string().as_bytes()),
                (373, reason.to_string().as_bytes()),
            ],
            now,
            time,
            actions,
        )?;
        action(
            actions,
            Action::Event(Event::Rejected {
                sequence: reference,
                tag,
                reason,
            }),
        )
    }
    fn request_gap(
        &mut self,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        if let Some(high) = self.gap_high {
            if self.incoming > high {
                self.gap_high = None;
                self.requested_through = None;
            } else if self.requested_through.is_none_or(|n| self.incoming > n) {
                let end = high.min(self.incoming.saturating_add(MAX_RESEND_RANGE - 1));
                self.emit(
                    b"2",
                    &[
                        (7, self.incoming.to_string().as_bytes()),
                        (16, end.to_string().as_bytes()),
                    ],
                    now,
                    time,
                    actions,
                )?;
                self.requested_through = Some(end);
            }
        }
        Ok(())
    }
    fn receive_inner(
        &mut self,
        message: &Message,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        if self.state == SessionState::Closed {
            return Err(Error::State);
        }
        if message.version()? != self.config.version
            || required(message, 49)? != self.config.target_comp_id.as_bytes()
            || required(message, 56)? != self.config.sender_comp_id.as_bytes()
        {
            return self.fatal(
                CloseReason::Protocol,
                b"Session identity mismatch",
                now,
                time,
                actions,
            );
        }
        if self.config.version == Version::Fixt11 {
            let ordered = message.fields.get(2).map(Field::tag) == Some(49)
                && message.fields.get(3).map(Field::tag) == Some(56);
            let appl = message.unique(1128)?;
            if !ordered
                || (appl.is_some()
                    && (admin(message.msg_type())
                        || message.fields.get(4).map(Field::tag) != Some(1128)))
            {
                return self.fatal(
                    CloseReason::Protocol,
                    b"Invalid FIXT header order",
                    now,
                    time,
                    actions,
                );
            }
            if let Some(value) = appl {
                session_id(value)?;
            }
        }
        let n = number(message, 34)?;
        seq(n)?;
        let kind = message.msg_type();
        let duplicate = flag(message, 43)?;
        let gap_fill = kind == b"4" && flag(message, 123)?;
        let reset_mode = kind == b"4" && !gap_fill;
        let initial = matches!(
            self.state,
            SessionState::AwaitingLogon | SessionState::LogonSent
        );
        if initial && kind != b"A" {
            if kind == b"5" {
                return self.close(CloseReason::Logout, actions);
            }
            return self.fatal(CloseReason::Protocol, b"Logon required", now, time, actions);
        }
        if initial && kind == b"A" {
            let reset = flag(message, 141)?;
            if (reset && (!self.config.allow_logon_reset || n != 1))
                || (self.config.role == Role::Initiator
                    && (self.state != SessionState::LogonSent || reset != self.reset_requested))
            {
                return self.fatal(
                    CloseReason::Protocol,
                    b"Invalid Logon reset",
                    now,
                    time,
                    actions,
                );
            }
            if reset {
                self.incoming = 1;
                if self.config.role == Role::Acceptor {
                    self.outgoing = 1;
                }
            }
        }
        if !reset_mode && n < self.incoming && !duplicate {
            return self.fatal(
                CloseReason::SequenceTooLow,
                b"MsgSeqNum too low",
                now,
                time,
                actions,
            );
        }
        // Validate duplicate timestamps before ignoring their payloads.
        let sent = match required(message, 52).and_then(timestamp) {
            Ok(value) => value,
            Err(_) => return self.reject_input(n, 52, 6, now, time, actions),
        };
        if duplicate {
            let original = match message.unique(122)? {
                Some(value) => match timestamp(value) {
                    Ok(value) => value,
                    Err(_) => return self.reject_input(n, 122, 6, now, time, actions),
                },
                None => return self.reject_input(n, 122, 1, now, time, actions),
            };
            if original > sent {
                return self.reject_input(n, 122, 10, now, time, actions);
            }
        } else if message.unique(122)?.is_some() {
            return self.reject_input(n, 122, 5, now, time, actions);
        }
        self.last_received = now;
        if !reset_mode && n < self.incoming {
            return action(actions, Action::Event(Event::Duplicate(n)));
        }
        if reset_mode {
            let next = number(message, 36)?;
            seq(next)?;
            if next <= self.incoming {
                self.reject_inner(n, 36, 5, now, time, actions)?;
                return self.fatal(
                    CloseReason::Protocol,
                    b"NewSeqNo must increase",
                    now,
                    time,
                    actions,
                );
            }
            let previous = self.incoming;
            self.incoming = next;
            action(
                actions,
                Action::Event(Event::SequenceReset {
                    previous,
                    next,
                    gap_fill: false,
                }),
            )?;
            return self.request_gap(now, time, actions);
        }
        let high = n > self.incoming;
        if high {
            self.gap_high = Some(self.gap_high.unwrap_or(n).max(n));
            action(
                actions,
                Action::Event(Event::Gap {
                    expected: self.incoming,
                    received: n,
                }),
            )?;
        }
        // Logon and ResendRequest must be handled even when above the expected
        // number. A high Logout confirmation ends a locally initiated logout.
        if initial && kind == b"A" {
            if number(message, 98)? != 0 {
                return self.fatal(
                    CloseReason::Protocol,
                    b"EncryptMethod not supported",
                    now,
                    time,
                    actions,
                );
            }
            let heartbeat = number(message, 108)?;
            if heartbeat > MAX_HEARTBEAT_SECONDS {
                return Err(Error::Limit);
            }
            if self.config.role == Role::Initiator && heartbeat != self.heartbeat {
                return self.fatal(
                    CloseReason::Protocol,
                    b"HeartBtInt mismatch",
                    now,
                    time,
                    actions,
                );
            }
            self.heartbeat = heartbeat;
            let peer_version = if self.config.version == Version::Fixt11 {
                let id = required(message, 1137)?;
                session_id(id)?;
                Some(id.to_vec())
            } else {
                None
            };
            if self.config.role == Role::Acceptor {
                self.logon(now, time, flag(message, 141)?, actions)?;
            }
            self.state = SessionState::Established;
            self.state_since = now;
            action(
                actions,
                Action::Event(Event::Established {
                    peer_default_appl_ver_id: peer_version,
                }),
            )?;
        } else if kind == b"A" && !duplicate {
            return self.fatal(
                CloseReason::Protocol,
                b"Unexpected Logon",
                now,
                time,
                actions,
            );
        } else if kind == b"2" && !duplicate {
            self.resend_request(message, n, now, time, actions)?;
        } else if kind == b"5" && !duplicate {
            if self.state == SessionState::LogoutSent {
                if !high {
                    self.incoming = advance(self.incoming)?;
                }
                return self.close(CloseReason::Logout, actions);
            }
            self.request_gap(now, time, actions)?;
            self.emit(b"5", &[], now, time, actions)?;
            if high {
                self.state = SessionState::LogoutSent;
                self.state_since = now;
                return Ok(());
            }
            self.incoming = advance(self.incoming)?;
            return self.close(CloseReason::Logout, actions);
        }
        if high {
            return self.request_gap(now, time, actions);
        }
        if gap_fill {
            let next = number(message, 36)?;
            seq(next)?;
            if next <= self.incoming || next - self.incoming > MAX_RESEND_RANGE {
                self.reject_inner(n, 36, 5, now, time, actions)?;
                return self.fatal(
                    CloseReason::Protocol,
                    b"Invalid gap fill",
                    now,
                    time,
                    actions,
                );
            }
            let previous = self.incoming;
            self.incoming = next;
            action(
                actions,
                Action::Event(Event::SequenceReset {
                    previous,
                    next,
                    gap_fill: true,
                }),
            )?;
        } else {
            self.incoming = advance(self.incoming)?;
            if duplicate && matches!(kind, b"A" | b"0" | b"1" | b"2" | b"5") {
                action(actions, Action::Event(Event::Duplicate(n)))?;
            } else {
                match kind {
                    b"A" | b"2" => {}
                    b"0" => {
                        if let Some((id, _)) = &self.test
                            && message.unique(112)? == Some(id.as_bytes())
                        {
                            self.test = None;
                        }
                    }
                    b"1" => match message.unique(112)? {
                        Some(id) if id.len() <= MAX_TEST_REQUEST_ID_LENGTH => {
                            self.emit(b"0", &[(112, id)], now, time, actions)?
                        }
                        Some(_) => self.reject_inner(n, 112, 5, now, time, actions)?,
                        None => self.reject_inner(n, 112, 1, now, time, actions)?,
                    },
                    b"3" => match number(message, 45).and_then(seq) {
                        Ok(reference) => {
                            action(actions, Action::Event(Event::RejectReceived(reference)))?
                        }
                        Err(_) => self.reject_inner(n, 45, 5, now, time, actions)?,
                    },
                    _ => {
                        if self.state == SessionState::Established {
                            action(
                                actions,
                                Action::Event(Event::Application {
                                    sequence: n,
                                    possible_duplicate: duplicate,
                                }),
                            )?;
                        }
                    }
                }
            }
        }
        self.request_gap(now, time, actions)
    }
    fn reject_input(
        &mut self,
        n: u32,
        tag: u32,
        reason: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        if n == self.incoming {
            self.incoming = advance(self.incoming)?;
        }
        if n > self.incoming {
            self.gap_high = Some(self.gap_high.unwrap_or(n).max(n));
        }
        self.reject_inner(n, tag, reason, now, time, actions)?;
        self.request_gap(now, time, actions)
    }
    fn resend_request(
        &mut self,
        message: &Message,
        n: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action>,
    ) -> Result<(), Error> {
        let begin = number(message, 7)?;
        let requested_end = number(message, 16)?;
        let last = self.outgoing.checked_sub(1).ok_or(Error::Sequence)?;
        let end = if requested_end == 0 {
            last
        } else {
            requested_end.min(last)
        };
        if begin == 0 || begin > end {
            return self.reject_inner(n, 7, 5, now, time, actions);
        }
        let (begin, end) = if let Some((old_begin, old_end)) = self.replay_remaining {
            (begin.min(old_begin), end.max(old_end))
        } else {
            (begin, end)
        };
        self.replay_remaining = Some((begin, end));
        if let Some(event) = self.next_resend_range() {
            action(actions, Action::Event(event))?;
        }
        Ok(())
    }
    /// Takes the next bounded replay work range after a received ResendRequest.
    /// Large requests are split into inclusive ranges of [`MAX_RESEND_RANGE`].
    /// Overlapping pending requests are coalesced. Returns `None` when drained.
    /// This only advances work cursors; it does not advance FIX sequence numbers.
    pub fn next_resend_range(&mut self) -> Option<Event> {
        let (begin, last) = self.replay_remaining?;
        let end = last.min(begin.saturating_add(MAX_RESEND_RANGE - 1));
        self.replay_remaining = if end < last {
            end.checked_add(1).map(|n| (n, last))
        } else {
            None
        };
        Some(Event::Resend { begin, end })
    }
}
fn session_tag(tag: u32) -> bool {
    matches!(tag, 49 | 56 | 34 | 52 | 43 | 122)
}
fn admin(kind: &[u8]) -> bool {
    matches!(kind, b"A" | b"0" | b"1" | b"2" | b"3" | b"4" | b"5")
}
fn required(message: &Message, tag: u32) -> Result<&[u8], Error> {
    message.unique(tag)?.ok_or(Error::Missing(tag))
}
fn number(message: &Message, tag: u32) -> Result<u32, Error> {
    decimal(required(message, tag)?)
}
fn flag(message: &Message, tag: u32) -> Result<bool, Error> {
    match message.unique(tag)? {
        None | Some(b"N") => Ok(false),
        Some(b"Y") => Ok(true),
        _ => Err(Error::Field),
    }
}
fn seq(n: u32) -> Result<u32, Error> {
    if n == 0 || n == u32::MAX {
        Err(Error::Sequence)
    } else {
        Ok(n)
    }
}
fn advance(n: u32) -> Result<u32, Error> {
    seq(n.checked_add(1).ok_or(Error::Sequence)?)
}
/// Maximum bytes in a supported UTC timestamp, through nanosecond precision.
pub const MAX_TIMESTAMP_LENGTH: usize = 27;
fn timestamp(bytes: &[u8]) -> Result<[u32; 7], Error> {
    if !matches!(bytes.len(), 17 | 21 | 24 | MAX_TIMESTAMP_LENGTH)
        || bytes.get(8) != Some(&b'-')
        || bytes.get(11) != Some(&b':')
        || bytes.get(14) != Some(&b':')
    {
        return Err(Error::Time);
    }
    let part = |a, b| decimal(bytes.get(a..b).ok_or(Error::Time)?).map_err(|_| Error::Time);
    let (year, month, day, hour, minute, second) = (
        part(0, 4)?,
        part(4, 6)?,
        part(6, 8)?,
        part(9, 11)?,
        part(12, 14)?,
        part(15, 17)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(Error::Time),
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 60 {
        return Err(Error::Time);
    }
    let fraction = if bytes.len() == 17 {
        0
    } else {
        if bytes.get(17) != Some(&b'.') {
            return Err(Error::Time);
        }
        let fraction = part(18, bytes.len())?;
        fraction
            .checked_mul(10u32.pow((MAX_TIMESTAMP_LENGTH - bytes.len()) as u32))
            .ok_or(Error::Time)?
    };
    Ok([year, month, day, hour, minute, second, fraction])
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Stream,
        contract::{check_decode_with_alloc_limit, check_wire, check_wire_value},
        test_support::decode_all,
    };

    // Exact byte examples using the FIX 4.2 Administrative Messages tables:
    // Logon (p. 27) and Heartbeat (p. 26), and Appendix B checksum calculation.
    const LOGON: &[u8] = b"8=FIX.4.2\x019=65\x0135=A\x0149=SERVER\x0156=CLIENT\x0134=177\x0152=20090107-18:15:16\x0198=0\x01108=30\x0110=062\x01";
    const HEARTBEAT: &[u8] = b"8=FIX.4.2\x019=53\x0135=0\x0149=SERVER\x0156=CLIENT\x0134=178\x0152=20090107-18:15:46\x0110=021\x01";
    const TIME: &[u8] = b"20261006-12:00:00";
    const LATER: &[u8] = b"20261006-12:00:01.000";

    fn checked(actions: &[Action]) {
        assert!(actions.len() <= MAX_ACTIONS);
        for action in actions {
            if let Action::Send(m) = action {
                check_wire_value(m);
                assert!(m.to_bytes().is_ok());
            }
        }
    }
    fn sends(actions: &[Action]) -> Vec<Message> {
        checked(actions);
        actions
            .iter()
            .filter_map(|a| {
                if let Action::Send(m) = a {
                    Some(m.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    fn has_event(actions: &[Action], event: Event) -> bool {
        actions.contains(&Action::Event(event))
    }
    fn inbound(version: Version, kind: &[u8], n: u32, fields: &[(u32, &[u8])]) -> Message {
        let mut m = Message::new(version, kind).unwrap();
        m.push(49, b"PEER")
            .unwrap()
            .push(56, b"LOCAL")
            .unwrap()
            .push(34, n.to_string().as_bytes())
            .unwrap()
            .push(52, LATER)
            .unwrap();
        for (tag, value) in fields {
            m.push(*tag, value).unwrap();
        }
        m
    }
    fn established(version: Version) -> Session {
        let mut s = Session::new(
            SessionConfig::new(version, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        let fields: &[(u32, &[u8])] = if version == Version::Fixt11 {
            &[(98, b"0"), (108, b"30"), (1137, b"6")]
        } else {
            &[(98, b"0"), (108, b"30")]
        };
        let response = s
            .receive(&inbound(version, b"A", 1, fields), 0, TIME)
            .unwrap();
        checked(&response);
        assert_eq!(s.state(), SessionState::Established);
        s
    }
    fn wire_body(body: &[u8]) -> Vec<u8> {
        let mut bytes = b"8=FIX.4.4\x019=".to_vec();
        bytes.extend_from_slice(body.len().to_string().as_bytes());
        bytes.push(SOH);
        bytes.extend_from_slice(body);
        let sum = bytes.iter().fold(0u8, |n, b| n.wrapping_add(*b));
        bytes.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
        bytes
    }

    #[test]
    fn published_message_shapes_exact_bytes_and_contracts() {
        for bytes in [LOGON, HEARTBEAT] {
            let message = Message::parse(bytes).unwrap();
            assert_eq!(message.to_bytes().unwrap(), bytes);
            check_wire::<Message>(bytes);
            check_wire_value(&message);
            check_decode_with_alloc_limit(|| Frames, bytes, 2 * MAX_MESSAGE_SIZE);
            for n in 0..bytes.len() {
                assert!(Message::parse(bytes.get(..n).unwrap()).is_err());
            }
        }
        assert_eq!(Message::parse(LOGON).unwrap().get(108), Some(&b"30"[..]));
        let stream = [LOGON, HEARTBEAT].concat();
        let (messages, failure) = decode_all(|| Frames, &stream);
        assert_eq!(failure, None);
        assert_eq!(messages.len(), 2);
        assert_eq!(Message::parse(&stream), Err(Error::Trailing));
        check_decode_with_alloc_limit(|| Frames, &stream, 2 * MAX_MESSAGE_SIZE);
    }

    #[test]
    fn bad_envelopes_and_checksum_are_refused() {
        for body in [
            &b"49=PEER\x0135=0\x01"[..],
            b"35=0\x0135=A\x01",
            b"35=0\x019=4\x01",
            b"35=0\x018=FIX.4.4\x01",
            b"35=0\x0158=\x01",
            b"35=0\x01058=x\x01",
            b"35=0\x010=x\x01",
            b"35=0\x014294967296=x\x01",
            b"35=0\x0110=001\x01",
        ] {
            let wire = wire_body(body);
            assert!(Message::parse(&wire).is_err(), "{body:?}");
            check_wire::<Message>(&wire);
            check_decode_with_alloc_limit(|| Frames, &wire, 2 * MAX_MESSAGE_SIZE);
        }
        let mut corrupted = LOGON.to_vec();
        *corrupted.last_mut().unwrap() = b'0';
        assert_eq!(Message::parse(&corrupted), Err(Error::Checksum));
        for (from, to) in [
            (b"9=65".as_slice(), b"9=64".as_slice()),
            (b"9=65", b"9=66"),
            (b"10=062", b"10=063"),
        ] {
            let text = String::from_utf8(LOGON.to_vec()).unwrap().replace(
                std::str::from_utf8(from).unwrap(),
                std::str::from_utf8(to).unwrap(),
            );
            assert!(Message::parse(text.as_bytes()).is_err());
        }
        for bytes in [
            b"8=FIX.4.4\x019=9999999999\x01".as_slice(),
            b"8=FIX.4.4\x019=0\x01",
            b"8=FIX.4.4\x019=-1\x01",
        ] {
            assert!(Frames.decode(bytes, false).is_err());
        }
        check_decode_with_alloc_limit(|| Frames, &[b'x'; MAX_PREFIX_SIZE], 2 * MAX_MESSAGE_SIZE);
    }

    #[test]
    fn every_standard_data_pair_handles_delimiters_and_binary() {
        let data = b"a\x01\0\xff10=099\x0135=A\x01=";
        for &(length, tag) in LENGTH_DATA_PAIRS {
            let mut message = Message::new(Version::Fix44, b"A").unwrap();
            message.push_data(length, data).unwrap();
            let wire = message.to_bytes().unwrap();
            assert_eq!(
                Message::parse(&wire).unwrap().get(tag),
                Some(data.as_slice())
            );
            check_wire_value(&message);
            check_decode_with_alloc_limit(|| Frames, &wire, 2 * MAX_MESSAGE_SIZE);
        }
        for body in [
            b"35=A\x0196=abc\x01".as_slice(),
            b"35=A\x0195=3\x0158=abc\x01",
            b"35=A\x0195=2\x0196=abc\x01",
            b"35=A\x0195=9\x0196=abc\x01",
            b"35=A\x0195=0\x0196=\x01",
            b"35=A\x0195=1\x01",
        ] {
            assert!(Message::parse(&wire_body(body)).is_err());
        }
    }

    #[test]
    fn writers_and_builders_roll_back_on_limits_and_invalid_pairs() {
        let mut message = Message::new(Version::Fix44, b"A").unwrap();
        message.push(95, b"3").unwrap().push(96, b"xx").unwrap();
        check_wire_value(&message);
        let mut out = b"prefix".to_vec();
        assert_eq!(message.write(&mut out), Err(Error::DataLength));
        assert_eq!(out, b"prefix");
        let before = message.clone();
        assert!(message.push(58, &[b'x'; MAX_VALUE_LENGTH + 1]).is_err());
        assert_eq!(message, before);
        assert!(message.push_data(95, &[]).is_err());
        assert_eq!(message, before);
        let mut many = Message::new(Version::Fix42, b"W").unwrap();
        for _ in 2..MAX_FIELDS {
            many.push(55, b"X").unwrap();
        }
        let before = many.clone();
        assert!(many.push(55, b"Y").is_err());
        assert_eq!(many, before);
        assert!(many.push_data(95, b"data").is_err());
        assert_eq!(many, before);
        check_wire_value(&many);
        let mut large = Message::new(Version::Fix44, b"A").unwrap();
        let data = vec![b'x'; MAX_VALUE_LENGTH];
        for _ in 0..3 {
            large.push_data(95, &data).unwrap();
        }
        let before = large.clone();
        assert!(large.push_data(95, &data).is_err());
        assert_eq!(large, before);
        check_wire_value(&large);
    }

    #[test]
    fn groups_follow_counts_delimiters_order_and_nesting() {
        let nested = GroupLayout {
            count_tag: 802,
            delimiter_tag: 523,
            members: &[523, 803],
            nested: &[],
        };
        let children = [nested];
        let layout = GroupLayout {
            count_tag: 453,
            delimiter_tag: 448,
            members: &[448, 447, 452, 802],
            nested: &children,
        };
        let mut m = Message::new(Version::Fix44, b"D").unwrap();
        for (tag, value) in [
            (453, "2"),
            (448, "party-a"),
            (447, "D"),
            (452, "1"),
            (802, "2"),
            (523, "sub-a"),
            (803, "1"),
            (523, "sub-b"),
            (803, "2"),
            (448, "party-b"),
            (447, "D"),
            (55, "XYZ"),
        ] {
            m.push(tag, value.as_bytes()).unwrap();
        }
        let g = m.group(2, &layout).unwrap();
        assert_eq!(g.entries().len(), 2);
        assert_eq!(g.end_index(), 13);
        assert_eq!(g.nested(0, 3, &nested).unwrap().entries().len(), 2);
        assert!(std::ptr::eq(
            g.entries().first().unwrap().first().unwrap(),
            m.fields().get(3).unwrap()
        ));
        check_wire_value(&m);
        for fields in [
            vec![(453, "2"), (448, "a")],
            vec![(453, "1"), (447, "D")],
            vec![(453, "1"), (448, "a"), (452, "1"), (447, "D")],
            vec![(453, "1"), (448, "a"), (448, "b")],
            vec![(453, "1025")],
        ] {
            let mut m = Message::new(Version::Fix44, b"D").unwrap();
            for (tag, value) in fields {
                m.push(tag, value.as_bytes()).unwrap();
            }
            assert!(m.group(2, &layout).is_err());
        }
        let mut zero = Message::new(Version::Fix44, b"D").unwrap();
        zero.push(453, b"0").unwrap();
        assert!(zero.group(2, &layout).unwrap().entries().is_empty());
        let invalid = GroupLayout {
            count_tag: 453,
            delimiter_tag: 448,
            members: &[448, 448],
            nested: &[],
        };
        assert!(zero.group(2, &invalid).is_err());
    }

    #[test]
    fn nested_count_can_be_the_entry_delimiter_and_cycles_are_bounded() {
        let inner = [GroupLayout {
            count_tag: 802,
            delimiter_tag: 523,
            members: &[523],
            nested: &[],
        }];
        let outer = GroupLayout {
            count_tag: 453,
            delimiter_tag: 802,
            members: &[802],
            nested: &inner,
        };
        let mut m = Message::new(Version::Fix44, b"D").unwrap();
        m.push(453, b"1")
            .unwrap()
            .push(802, b"1")
            .unwrap()
            .push(523, b"a")
            .unwrap();
        assert_eq!(m.group(2, &outer).unwrap().entries().len(), 1);
        static CYCLE: GroupLayout<'static> = GroupLayout {
            count_tag: 1000,
            delimiter_tag: 1001,
            members: &[1001],
            nested: &CYCLE_CHILD,
        };
        static CYCLE_CHILD: [GroupLayout<'static>; 1] = [GroupLayout {
            count_tag: 1001,
            delimiter_tag: 1000,
            members: &[1000],
            nested: &[CYCLE],
        }];
        assert_eq!(check_layout(&CYCLE, 1, &mut 0), Err(Error::Limit));
    }

    #[test]
    fn application_views_borrow_all_seven_message_types() {
        let mut b = NewOrderSingle::builder(Version::Fix42).unwrap();
        b.cl_ord_id(b"one")
            .unwrap()
            .symbol(b"XYZ")
            .unwrap()
            .order_qty(b"1.25")
            .unwrap();
        assert!(b.cl_ord_id(b"two").is_err());
        let m = b.finish().unwrap();
        let view = NewOrderSingle::view(&m).unwrap();
        assert_eq!(view.order_qty(), Some(b"1.25".as_slice()));
        assert!(std::ptr::eq(view.message(), &m));
        assert!(ExecutionReport::view(&m).is_err());
        let mut b = ExecutionReport::builder(Version::Fix44).unwrap();
        b.exec_id(b"e").unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            ExecutionReport::view(&m).unwrap().exec_id(),
            Some(b"e".as_slice())
        );
        let mut b = OrderCancelRequest::builder(Version::Fix44).unwrap();
        b.orig_cl_ord_id(b"old").unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            OrderCancelRequest::view(&m).unwrap().orig_cl_ord_id(),
            Some(b"old".as_slice())
        );
        let mut b = OrderCancelReplaceRequest::builder(Version::Fix44).unwrap();
        b.price(b"23.50").unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            OrderCancelReplaceRequest::view(&m).unwrap().price(),
            Some(b"23.50".as_slice())
        );
        let mut b = MarketDataRequest::builder(Version::Fix44).unwrap();
        b.no_md_entry_types(b"2")
            .unwrap()
            .field(269, b"0")
            .unwrap()
            .field(269, b"1")
            .unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            MarketDataRequest::view(&m).unwrap().no_md_entry_types(),
            Some(b"2".as_slice())
        );
        let mut b = MarketDataSnapshotFullRefresh::builder(Version::Fix44).unwrap();
        b.no_md_entries(b"1")
            .unwrap()
            .field(269, b"0")
            .unwrap()
            .field(270, b"12.50")
            .unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            MarketDataSnapshotFullRefresh::view(&m)
                .unwrap()
                .no_md_entries(),
            Some(b"1".as_slice())
        );
        let mut b = MarketDataIncrementalRefresh::builder(Version::Fix44).unwrap();
        b.no_md_entries(b"1").unwrap().field(279, b"0").unwrap();
        let m = b.finish().unwrap();
        assert_eq!(
            MarketDataIncrementalRefresh::view(&m)
                .unwrap()
                .no_md_entries(),
            Some(b"1".as_slice())
        );
        check_wire_value(&m);
    }

    #[test]
    fn all_versions_log_on_send_and_log_out() {
        for version in [
            Version::Fix42,
            Version::Fix43,
            Version::Fix44,
            Version::Fixt11,
        ] {
            let mut client = Session::new(
                SessionConfig::new(version, Role::Initiator, "LOCAL", "PEER").unwrap(),
                1,
                1,
                0,
            )
            .unwrap();
            let mut server = Session::new(
                SessionConfig::new(version, Role::Acceptor, "PEER", "LOCAL").unwrap(),
                1,
                1,
                0,
            )
            .unwrap();
            let request = sends(&client.start(0, TIME, false).unwrap()).remove(0);
            let response = sends(&server.receive(&request, 1, TIME).unwrap()).remove(0);
            let actions = client.receive(&response, 2, TIME).unwrap();
            checked(&actions);
            assert_eq!(client.state(), SessionState::Established);
            assert_eq!(client.next_inbound(), 2);
            let app = NewOrderSingle::builder(version).unwrap().finish().unwrap();
            let out = sends(&client.send(&app, 3, TIME).unwrap()).remove(0);
            let events = server.receive(&out, 4, TIME).unwrap();
            assert!(has_event(
                &events,
                Event::Application {
                    sequence: 2,
                    possible_duplicate: false
                }
            ));
            let logout = sends(&client.logout(b"done", 5, TIME).unwrap()).remove(0);
            let actions = server.receive(&logout, 6, TIME).unwrap();
            assert!(has_event(
                &actions,
                Event::Disconnected(CloseReason::Logout)
            ));
            let reply = sends(&actions).remove(0);
            assert!(has_event(
                &client.receive(&reply, 7, TIME).unwrap(),
                Event::Disconnected(CloseReason::Logout)
            ));
            assert_eq!(client.next_inbound(), 3);
            assert_eq!(server.next_inbound(), 4);
        }
    }

    #[test]
    fn heartbeat_test_request_match_timeout_and_zero_interval() {
        let mut s = established(Version::Fix44);
        assert!(s.tick(29_999, TIME).unwrap().is_empty());
        assert_eq!(
            sends(&s.tick(30_000, TIME).unwrap())
                .first()
                .unwrap()
                .msg_type(),
            b"0"
        );
        let test = sends(&s.tick(31_000, TIME).unwrap()).remove(0);
        assert_eq!(test.msg_type(), b"1");
        let mut timed_out = s.clone();
        let wrong = inbound(Version::Fix44, b"0", 2, &[(112, b"wrong")]);
        timed_out.receive(&wrong, 31_100, TIME).unwrap();
        assert!(has_event(
            &timed_out.tick(62_000, TIME).unwrap(),
            Event::Disconnected(CloseReason::TestRequestTimeout)
        ));
        let response = inbound(Version::Fix44, b"0", 2, &[(112, test.get(112).unwrap())]);
        assert!(s.receive(&response, 31_100, TIME).unwrap().is_empty());
        assert!(s.test.is_none());
        let probe = inbound(Version::Fix44, b"1", 3, &[(112, b"peer-probe")]);
        assert_eq!(
            sends(&s.receive(&probe, 32_000, TIME).unwrap())
                .first()
                .unwrap()
                .get(112),
            Some(b"peer-probe".as_slice())
        );
        let mut zero = Session::new(
            SessionConfig::new(Version::Fix42, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        zero.receive(
            &inbound(Version::Fix42, b"A", 1, &[(98, b"0"), (108, b"0")]),
            0,
            TIME,
        )
        .unwrap();
        assert!(zero.tick(1_000_000, TIME).unwrap().is_empty());
        assert_eq!(
            sends(
                &zero
                    .receive(
                        &inbound(Version::Fix42, b"1", 2, &[(112, b"x")]),
                        1_000_001,
                        TIME
                    )
                    .unwrap()
            )
            .first()
            .unwrap()
            .msg_type(),
            b"0"
        );
    }

    #[test]
    fn gaps_request_replay_without_processing_high_messages() {
        let mut s = established(Version::Fix44);
        let high = inbound(Version::Fix44, b"D", 4, &[(11, b"four")]);
        let actions = s.receive(&high, 1, TIME).unwrap();
        let request = sends(&actions).remove(0);
        assert_eq!(request.msg_type(), b"2");
        assert_eq!(request.get(7), Some(b"2".as_slice()));
        assert_eq!(request.get(16), Some(b"4".as_slice()));
        assert!(has_event(
            &actions,
            Event::Gap {
                expected: 2,
                received: 4
            }
        ));
        assert_eq!(s.next_inbound(), 2);
        assert!(sends(&s.receive(&high, 2, TIME).unwrap()).is_empty());
        let gap = inbound(
            Version::Fix44,
            b"4",
            2,
            &[(43, b"Y"), (122, TIME), (123, b"Y"), (36, b"4")],
        );
        let events = s.receive(&gap, 3, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::SequenceReset {
                previous: 2,
                next: 4,
                gap_fill: true
            }
        ));
        let replayed = inbound(
            Version::Fix44,
            b"D",
            4,
            &[(43, b"Y"), (122, TIME), (11, b"four")],
        );
        let actions = s.receive(&replayed, 4, TIME).unwrap();
        assert!(has_event(
            &actions,
            Event::Application {
                sequence: 4,
                possible_duplicate: true
            }
        ));
        assert_eq!(s.next_inbound(), 5);
        assert!(has_event(
            &s.receive(&gap, 5, TIME).unwrap(),
            Event::Duplicate(2)
        ));
        assert_eq!(s.next_inbound(), 5);
    }

    #[test]
    fn duplicates_missing_original_time_and_low_sequences() {
        let mut s = established(Version::Fix44);
        let low = inbound(Version::Fix44, b"D", 1, &[(43, b"Y"), (122, TIME)]);
        assert!(has_event(
            &s.receive(&low, 1, TIME).unwrap(),
            Event::Duplicate(1)
        ));
        assert_eq!(s.next_inbound(), 2);
        let missing = inbound(Version::Fix44, b"D", 2, &[(43, b"Y")]);
        let events = s.receive(&missing, 2, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::Rejected {
                sequence: 2,
                tag: 122,
                reason: 1
            }
        ));
        assert_eq!(s.next_inbound(), 3);
        checked(&events);
        let future = inbound(
            Version::Fix44,
            b"D",
            3,
            &[(43, b"Y"), (122, b"20261006-12:00:02")],
        );
        assert!(has_event(
            &s.receive(&future, 3, TIME).unwrap(),
            Event::Rejected {
                sequence: 3,
                tag: 122,
                reason: 10
            }
        ));
        let low = inbound(Version::Fix44, b"0", 1, &[]);
        let events = s.receive(&low, 4, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::Disconnected(CloseReason::SequenceTooLow)
        ));
        checked(&events);
        assert_eq!(s.state(), SessionState::Closed);
    }

    #[test]
    fn reset_mode_ignores_sequence_but_never_decreases_expected() {
        let mut s = established(Version::Fix44);
        let reset = inbound(Version::Fix44, b"4", 1, &[(36, b"50"), (123, b"N")]);
        let events = s.receive(&reset, 1, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::SequenceReset {
                previous: 2,
                next: 50,
                gap_fill: false
            }
        ));
        let decrease = inbound(Version::Fix44, b"4", 999, &[(36, b"49")]);
        let events = s.receive(&decrease, 2, TIME).unwrap();
        checked(&events);
        assert!(has_event(
            &events,
            Event::Disconnected(CloseReason::Protocol)
        ));
        assert_eq!(s.next_inbound(), 50);
    }

    #[test]
    fn replay_requests_gap_fills_and_rejects() {
        let mut s = established(Version::Fix44);
        let body = NewOrderSingle::builder(Version::Fix44)
            .unwrap()
            .finish()
            .unwrap();
        let original = sends(&s.send(&body, 1, TIME).unwrap()).remove(0);
        let before = s.next_outbound();
        let replayed = sends(&s.replay(&original, 2, LATER).unwrap()).remove(0);
        assert_eq!(replayed.get(34), Some(b"2".as_slice()));
        assert_eq!(replayed.get(43), Some(b"Y".as_slice()));
        assert_eq!(replayed.get(122), Some(TIME));
        assert_eq!(s.next_outbound(), before);
        let gap = sends(&s.gap_fill(1, 2, TIME, 3, LATER).unwrap()).remove(0);
        assert_eq!(gap.get(36), Some(b"2".as_slice()));
        assert_eq!(gap.get(123), Some(b"Y".as_slice()));
        assert_eq!(s.next_outbound(), before);
        let request = inbound(Version::Fix44, b"2", 2, &[(7, b"1"), (16, b"0")]);
        assert!(has_event(
            &s.receive(&request, 4, LATER).unwrap(),
            Event::Resend { begin: 1, end: 2 }
        ));
        let rejected = inbound(Version::Fix44, b"3", 3, &[(45, b"2")]);
        assert!(has_event(
            &s.receive(&rejected, 5, LATER).unwrap(),
            Event::RejectReceived(2)
        ));
        let events = s.reject(3, 55, 1, 6, LATER).unwrap();
        checked(&events);
        let resent = sends(&s.replay(&sends(&events).remove(0), 7, LATER).unwrap()).remove(0);
        assert_eq!(resent.msg_type(), b"3");
        let events = s.reset_sequence(100, 8, LATER).unwrap();
        checked(&events);
        assert_eq!(s.next_outbound(), 100);
        assert!(s.reset_sequence(99, 9, LATER).is_err());
    }

    #[test]
    fn large_replay_ranges_are_drained_in_bounded_chunks() {
        let mut s = established(Version::Fix44);
        s.outgoing = MAX_RESEND_RANGE * 3 + 2;
        let request = inbound(Version::Fix44, b"2", 2, &[(7, b"1"), (16, b"0")]);
        let events = s.receive(&request, 1, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::Resend {
                begin: 1,
                end: MAX_RESEND_RANGE
            }
        ));
        let mut last = MAX_RESEND_RANGE;
        while let Some(Event::Resend { begin, end }) = s.next_resend_range() {
            assert_eq!(begin, last + 1);
            assert!(end - begin < MAX_RESEND_RANGE);
            last = end;
        }
        assert_eq!(last, s.next_outbound() - 1);
        let high = inbound(Version::Fix44, b"D", MAX_RESEND_RANGE + 10, &[]);
        let request = sends(&s.receive(&high, 2, TIME).unwrap()).remove(0);
        assert_eq!(number(&request, 16).unwrap(), MAX_RESEND_RANGE + 2);
        let gap = inbound(
            Version::Fix44,
            b"4",
            3,
            &[
                (36, (MAX_RESEND_RANGE + 3).to_string().as_bytes()),
                (123, b"Y"),
            ],
        );
        let actions = s.receive(&gap, 3, TIME).unwrap();
        let request = sends(&actions).remove(0);
        assert_eq!(number(&request, 7).unwrap(), MAX_RESEND_RANGE + 3);
    }

    #[test]
    fn reset_logon_high_logon_admin_duplicates_and_timeouts() {
        let mut config =
            SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap();
        config.allow_logon_reset = true;
        let mut s = Session::new(config, 50, 60, 0).unwrap();
        let logon = inbound(
            Version::Fix44,
            b"A",
            1,
            &[(98, b"0"), (108, b"30"), (141, b"Y")],
        );
        let reply = sends(&s.receive(&logon, 1, TIME).unwrap()).remove(0);
        assert_eq!(reply.get(141), Some(b"Y".as_slice()));
        assert_eq!(s.next_inbound(), 2);
        assert_eq!(s.next_outbound(), 2);
        let mut s = Session::new(
            SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        let logon = inbound(Version::Fix44, b"A", 4, &[(98, b"0"), (108, b"30")]);
        let messages = sends(&s.receive(&logon, 1, TIME).unwrap());
        assert_eq!(messages.len(), 2);
        assert_eq!(messages.first().unwrap().msg_type(), b"A");
        assert_eq!(messages.get(1).unwrap().msg_type(), b"2");
        let dup = inbound(
            Version::Fix44,
            b"2",
            1,
            &[(43, b"Y"), (122, TIME), (7, b"1"), (16, b"0")],
        );
        assert!(sends(&s.receive(&dup, 2, TIME).unwrap()).is_empty());
        assert_eq!(s.next_inbound(), 2);
        let mut s = established(Version::Fix44);
        checked(&s.logout(b"bye", 1, TIME).unwrap());
        assert!(has_event(
            &s.tick(2001, TIME).unwrap(),
            Event::Disconnected(CloseReason::LogoutTimeout)
        ));
        let mut s = Session::new(
            SessionConfig::new(Version::Fix44, Role::Initiator, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        s.start(0, TIME, false).unwrap();
        assert!(has_event(
            &s.tick(10000, TIME).unwrap(),
            Event::Disconnected(CloseReason::LogonTimeout)
        ));
    }

    #[test]
    fn fixt_application_version_occupies_the_sixth_wire_field() {
        let mut s = established(Version::Fixt11);
        let mut body = Message::new(Version::Fixt11, b"D").unwrap();
        body.push(11, b"order").unwrap().push(1128, b"4").unwrap();
        let outbound = sends(&s.send(&body, 1, TIME).unwrap()).remove(0);
        assert_eq!(outbound.fields().get(4).unwrap().tag(), 1128);
        let replay = sends(&s.replay(&outbound, 2, LATER).unwrap()).remove(0);
        assert_eq!(replay.fields().get(4).unwrap().tag(), 1128);
        let invalid = inbound(Version::Fixt11, b"D", 2, &[(1128, b"4")]);
        assert!(has_event(
            &s.receive(&invalid, 3, TIME).unwrap(),
            Event::Disconnected(CloseReason::Protocol)
        ));
    }

    #[test]
    fn group_validation_and_explicit_test_requests_are_transactional() {
        let layout = GroupLayout {
            count_tag: 384,
            delimiter_tag: 372,
            members: &[372, 385],
            nested: &[],
        };
        // FIX TagValue Encoding 4.3.6, the published two-entry example.
        let wire = wire_body(b"35=A\x01384=2\x01372=6\x01385=R\x01372=7\x01385=R\x01");
        let message = Message::parse_with_groups(&wire, &[layout]).unwrap();
        let mut bytes = vec![123];
        message.write_with_groups(&mut bytes, &[layout]).unwrap();
        assert_eq!(bytes.get(1..).unwrap(), wire);
        assert!(message.validate_groups(&[]).is_err());
        let mut invalid = message.clone();
        invalid.push(372, b"8").unwrap();
        let before = bytes.clone();
        assert!(invalid.write_with_groups(&mut bytes, &[layout]).is_err());
        assert_eq!(bytes, before);
        let mut s = established(Version::Fix44);
        assert_eq!(
            sends(&s.test_request(b"explicit", 1, TIME).unwrap())
                .first()
                .unwrap()
                .get(112),
            Some(b"explicit".as_slice())
        );
        assert!(s.test_request(b"another", 2, TIME).is_err());
        assert!(
            s.test_request(&[b'x'; MAX_TEST_REQUEST_ID_LENGTH + 1], 2, TIME)
                .is_err()
        );
    }

    #[test]
    fn invalid_session_calls_are_transactional_and_time_is_checked() {
        let mut s = established(Version::Fix44);
        s.tick(10, TIME).unwrap();
        let before = (s.next_inbound(), s.next_outbound(), s.last_now);
        assert!(s.tick(9, TIME).is_err());
        assert!(s.tick(11, b"20260230-12:00:00").is_err());
        assert!(s.gap_fill(0, 1, TIME, 11, TIME).is_err());
        assert_eq!((s.next_inbound(), s.next_outbound(), s.last_now), before);
        assert_eq!(
            timestamp(b"20261006-12:00:00").unwrap(),
            timestamp(b"20261006-12:00:00.000000000").unwrap()
        );
        assert!(timestamp(b"20240229-23:59:60.123").is_ok());
        assert!(timestamp(b"20230229-12:00:00").is_err());
        let mut config =
            SessionConfig::new(Version::Fix44, Role::Initiator, "LOCAL", "PEER").unwrap();
        config.heartbeat_seconds = u32::MAX;
        assert!(Session::new(config, 1, 1, 0).is_err());
    }

    #[test]
    fn one_byte_delivery_and_mutations_use_codec_contracts() {
        let mut message = Message::new(Version::Fix44, b"W").unwrap();
        message.push_data(95, &vec![SOH; 32 * 1024]).unwrap();
        let bytes = message.to_bytes().unwrap();
        let mut stream = Stream::new(Frames);
        for b in &bytes {
            assert_eq!(stream.push(&[*b]), 1);
            if let Some(item) = stream.next() {
                assert_eq!(item.unwrap(), message);
            }
        }
        stream.end();
        assert!(stream.next().is_none());
        assert!(stream.failed().is_none());
        assert_eq!(stream.held(), 0);
        for (i, _) in LOGON.iter().enumerate() {
            let mut bytes = LOGON.to_vec();
            if let Some(b) = bytes.get_mut(i) {
                *b ^= 0x80;
            }
            check_wire::<Message>(&bytes);
            check_decode_with_alloc_limit(|| Frames, &bytes, 2 * MAX_MESSAGE_SIZE);
        }
    }
}
