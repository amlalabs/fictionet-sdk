//! FIX tag=value messages, repeating-group views, and caller-driven sessions.
//!
//! `Message` implements `Wire`, `Messages` decodes the stream, and `Session` is
//! a caller-driven state machine for either side. There is no `Service` or live
//! transport. The caller supplies time, authentication decisions, and
//! application behavior.
//!
//! The wire rules follow FIX 4.4 Volume 2, “Standard Message header”,
//! “Data Integrity”, and “Session Protocol”, and FIXT 1.1 (March 2008), “Session Protocol” and
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
//! Volume 2 uses unnumbered section headings. Its numbered test cases are cited
//! below. In-session Logon resets (Session Layer 4.4.2) are not supported;
//! ResetSeqNumFlag is supported only in the initial Logon exchange (4.4.3).
//! Timestamps support seconds through nanoseconds. Picoseconds are refused.
//!
//! [`Message`] retains field order. BodyLength and CheckSum are derived, so
//! they are not stored in its field list. [`Messages`] yields `Result<Message,
//! FieldFault>` from a [`fictionet::stdlib::codec::Stream`]. Pass each item to
//! [`Session::receive_frame`]. A message with a bad field is a [`FieldFault`]
//! item, which holds what a Reject needs; a bad envelope is skipped as garbled,
//! so the stream never ends with an error and the module has no `FrameError`.
//! Group layouts are supplied by
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

use fictionet::stdlib::codec::ascii;
use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::session::Action;
use std::convert::Infallible;
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
/// Maximum sequence numbers in one emitted replay range or outbound gap fill.
/// Received gap fills only move counters and have no range limit.
pub const MAX_RESEND_RANGE: u32 = 10_000;
/// Maximum ResendRequests with the same BeginSeqNo before Logout and close.
/// Bounds repeated failed recovery as recommended by Session Layer 4.5.2.
pub const MAX_RESEND_ATTEMPTS: u32 = 3;
/// Maximum disjoint pending replay ranges retained by a session.
pub const MAX_PENDING_RESENDS: usize = 16;
/// Maximum bytes in a session CompID or application version identifier.
pub const MAX_SESSION_ID_LENGTH: usize = 64;
/// Maximum negotiated heartbeat interval, in seconds.
pub const MAX_HEARTBEAT_SECONDS: u32 = 86_400;
/// Maximum actions returned by one session operation.
pub const MAX_ACTIONS: usize = 16;
/// Maximum length of a TestReqID issued or echoed by the session.
pub const MAX_TEST_REQUEST_ID_LENGTH: usize = 64;
/// Maximum UTC timestamp length, through nanoseconds. Picosecond timestamps
/// (30 bytes) are refused by session operations.
pub const MAX_TIMESTAMP_LENGTH: usize = 27;

/// Standard Length/data pairs through FIX 4.4, plus FIXT/FIX 5.0 extensions.
/// Length immediately precedes data.
/// Includes SecureData, Signature, RawData, XmlData, and encoded text fields.
/// Password pairs follow Session Layer 4.3.10 Table 2 and 9.2. SecurityXML
/// follows [FIX Application Layer Introduction 7.33](https://www.fixtrading.org/wp-content/uploads/download-manager-files/FIX-Latest-Specification-Introduction.pdf).
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
    (1184, 1185),
    (1401, 1402),
    (1403, 1404),
];

/// Why a message, layout, or session operation was refused: the module's
/// error, and the reason inside a [`FieldFault`].
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
    /// Empty data fields are refused too, including `95=0|96=|`. This applies
    /// the no-value rule in FIX 4.4 Vol 2 case 14.d to data as well as text.
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
    ascii::decimal(b, 10, u64::from(u32::MAX))
        .map(|n| n as u32)
        .ok_or(Error::Field)
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
/// Groups stay flat until interpreted with a [`GroupLayout`]. BodyLength may
/// contain leading zeros on input. Writing normalizes this derived field
/// (FIX TagValue Encoding 5.1).
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
        if self.fields.len() >= MAX_FIELDS || self.encoded_size(stored)? > MAX_MESSAGE_SIZE {
            return Err(Error::Limit);
        }
        self.fields.push(Field::new(tag, value)?);
        self.stored_size = stored;
        Ok(self)
    }
    fn encoded_size(&self, stored: usize) -> Result<usize, Error> {
        let begin = self.fields.first().ok_or(Error::Header)?;
        let body = stored.checked_sub(begin.size()).ok_or(Error::Header)?;
        stored.checked_add(3 + digits(body) + 7).ok_or(Error::Limit)
    }
    /// Appends a standard Length/data pair, deriving the Length value.
    /// Refuses empty data, unknown pairs, or size limits without changing the message.
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
        if self.fields.len() > MAX_FIELDS || self.encoded_size(self.stored_size)? > MAX_MESSAGE_SIZE
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
    *pos = end + 1;
    Ok((tag, value))
}
/// A field fault in a message whose envelope and checksum were checked.
/// Pass this item to [`Session::receive_frame`]. The retained fields are bounded
/// by [`MAX_FIELDS`] and [`MAX_MESSAGE_SIZE`]. Unreadable tags are omitted.
/// Parsing stops at an ambiguous data boundary; later bytes are never searched
/// for session headers inside binary data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldFault {
    message: Message,
    tag: Option<u32>,
    reason: u32,
    error: Error,
}
impl FieldFault {
    /// MsgSeqNum when a unique, positive, supported number could be read.
    pub fn sequence(&self) -> Option<u32> {
        number(&self.message, 34).and_then(seq).ok()
    }
    /// MsgType, or an empty slice when its value could not be read.
    pub fn msg_type(&self) -> &[u8] {
        self.message.msg_type()
    }
    /// RefTagID, absent when the tag itself was unreadable.
    pub fn tag(&self) -> Option<u32> {
        self.tag
    }
    /// SessionRejectReason: 4 for an empty value, 0 for an invalid tag, or 5
    /// for an invalid data length or a named limit.
    pub fn reason(&self) -> u32 {
        self.reason
    }
}
impl fmt::Display for FieldFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FIX field {:?}: {} (reason {})",
            self.tag, self.error, self.reason
        )
    }
}
impl std::error::Error for FieldFault {}

// The tag before the first `=` in the next 11 bytes, if it reads as one.
fn leading_tag(rest: &[u8]) -> Option<u32> {
    let eq = rest.iter().take(11).position(|b| *b == b'=')?;
    decimal(rest.get(..eq)?).ok()
}
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

/// Where a whole candidate's fields and trailer lie, found in O(1) after the
/// bounded prefix.
#[derive(Clone, Copy)]
struct Envelope {
    /// Offset of the first field after BodyLength.
    start: usize,
    /// Offset of the `10=` trailer.
    checksum_at: usize,
    /// The CheckSum value the trailer declares.
    checksum: u32,
}

// Cheap envelope checks only: the bounded prefix, the exact length, the
// trailer's shape and position, and MsgType in the first body field. None of
// them reads more than MAX_PREFIX_SIZE + 18 bytes, so Messages runs them on
// every candidate before any work that grows with BodyLength.
fn envelope(input: &[u8]) -> Result<Envelope, Error> {
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
    if checksum_at.checked_sub(1).and_then(|i| input.get(i)) != Some(&SOH) {
        return Err(Error::BodyLength);
    }
    if leading_tag(input.get(start..checksum_at).unwrap_or_default()) != Some(35) {
        return Err(Error::Header);
    }
    Ok(Envelope {
        start,
        checksum_at,
        checksum,
    })
}

// Envelope errors are outer errors. Field failures are per-unit items.
fn parse_frame(input: &[u8]) -> Result<Result<Message, FieldFault>, Error> {
    let envelope = envelope(input)?;
    let content = input.get(..envelope.checksum_at).ok_or(Error::BodyLength)?;
    if u32::from(checksum(content)) != envelope.checksum {
        return Err(Error::Checksum);
    }
    fields(content, envelope.start)
}

// Reads the fields of a candidate whose envelope and checksum were checked.
// Work and allocation are linear in `content`.
fn fields(content: &[u8], start: usize) -> Result<Result<Message, FieldFault>, Error> {
    let checksum_at = content.len();
    let mut pos = 0;
    let (_, begin) = next_field(content, &mut pos, None)?;
    let mut message = Message {
        fields: vec![Field::new(8, begin)?],
        stored_size: 0,
    };
    message.stored_size = message.fields[0].size();
    pos = start;
    let mut pending = None;
    let mut fault = None;
    while pos < checksum_at {
        let at = pos;
        let raw = pending.take();
        let first = at == start;
        let rest = content.get(at..).ok_or(Error::Incomplete)?;
        let tag_hint = leading_tag(rest);
        if first && tag_hint != Some(35) {
            return Err(Error::Header);
        }
        if matches!(tag_hint, Some(8..=10)) || (!first && tag_hint == Some(35)) {
            return Err(Error::Header);
        }
        if message.fields.len() >= MAX_FIELDS {
            fault.get_or_insert((tag_hint, 5, Error::Limit));
            break;
        }
        let (tag, value) = match next_field(content, &mut pos, raw) {
            Ok(field) => field,
            Err(error) => {
                let reason = if matches!(error, Error::DataLength | Error::Limit) {
                    5
                } else {
                    0
                };
                fault.get_or_insert((tag_hint, reason, error));
                // A bad data length makes the following delimiter ambiguous.
                // Stop rather than read apparent headers inside raw bytes.
                if raw.is_some() || tag_hint.is_some_and(is_data) {
                    break;
                }
                let Some(end) = rest.iter().position(|b| *b == SOH) else {
                    break;
                };
                pos = at.checked_add(end + 1).ok_or(Error::Limit)?;
                continue;
            }
        };
        if let Err(error) = check_field(tag, value) {
            let reason = if tag == 0 {
                0
            } else if value.is_empty() {
                4
            } else {
                5
            };
            fault.get_or_insert((Some(tag), reason, error));
        }
        let field = Field {
            tag,
            value: value.to_vec(),
        };
        message.stored_size = message
            .stored_size
            .checked_add(field.size())
            .ok_or(Error::Limit)?;
        message.fields.push(field);
        if let Some(data) = data_tag(tag) {
            match decimal(value) {
                Ok(len) if len as usize <= MAX_VALUE_LENGTH => pending = Some((data, len as usize)),
                _ => {
                    fault.get_or_insert((Some(tag), 5, Error::DataLength));
                    break;
                }
            }
        }
    }
    if let Some((tag, _)) = pending {
        fault.get_or_insert((Some(tag), 5, Error::DataLength));
    }
    Ok(match fault {
        Some((tag, reason, error)) => Err(FieldFault {
            message,
            tag,
            reason,
            error,
        }),
        None => Ok(message),
    })
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads exactly one message. Refuses truncation, trailing bytes, bad
    /// envelope order, lengths, checksum, fields, data pairs, and named limits.
    /// Leading zeros in BodyLength are accepted and normalized on write.
    fn parse(input: &[u8]) -> Result<Self, Error> {
        parse_frame(input)?.map_err(|malformed| malformed.error)
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

/// Bytes of failed-candidate checksum work [`Messages`] may owe before it stops
/// trying overlapping candidates. Each candidate that fails its CheckSum adds
/// its length to a debt, and every byte consumed pays one byte back. While the
/// debt is above this bound, a candidate that fails its CheckSum is skipped
/// whole, by its BodyLength, instead of rescanned from just past its start.
/// Total checksum and parse work is then at most twice the bytes consumed plus
/// this bound plus [`MAX_MESSAGE_SIZE`], for any input and any chunking.
pub const MAX_RESYNC_DEBT: usize = 4 * MAX_MESSAGE_SIZE;

/// Splits a TCP byte stream using BodyLength. No input bytes are retained.
/// At most [`MAX_PREFIX_SIZE`] header bytes are rescanned per call. The body
/// is checked only when complete, and cheap envelope checks (the prefix, the
/// trailer's shape and position, MsgType first) run before any work that grows
/// with BodyLength. Total work is linear in the input for any chunking, also
/// when garbled candidates overlap: see [`MAX_RESYNC_DEBT`].
///
/// A wrong BodyLength is found only when its whole span has arrived. A header
/// that claims up to [`MAX_MESSAGE_SIZE`] bytes holds back the messages after
/// it until that many bytes arrive or the input ends. Pair the stream with the
/// session's TestRequest timer, which ends a silent link.
/// Use [`Self::default`] to start with a zero garbled-message count.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, pump}, fix::Messages};
/// let mut stream = Stream::new(Messages::default());
/// // FIX 4.4 Vol 2 case 3.b: a complete message with an incorrect checksum.
/// pump(&mut stream, b"8=FIX.4.4\x019=5\x0135=0\x0110=164\x01", |_| unreachable!())?;
/// assert_eq!(stream.decoder().garbled(), 1);
/// assert!(stream.failed().is_none());
/// # Ok::<(), fictionet::stdlib::codec::Fail<std::convert::Infallible>>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Messages {
    garbled: u64,
    unsupported_versions: u64,
    resync: bool,
    scanned: usize,
    debt: usize,
    examined: u64,
}
impl Messages {
    /// Number of rejected envelope candidates or runs of noise. A resync scan
    /// counts once across input chunks. Saturates at `u64::MAX`.
    pub fn garbled(&self) -> u64 {
        self.garbled
    }
    /// Unsupported BeginString candidates skipped, saturating at `u64::MAX`.
    /// A caller enforcing FIX 4.4 Vol 2 case 2.i must check this after draining
    /// input. During an established session, call [`Session::logout`] with a
    /// version diagnostic, send its actions, and close the transport. An initial
    /// acceptor instead closes silently (Session Layer 4.6.4). Framing alone
    /// cannot send Logout or decide the session identity policy.
    pub fn unsupported_versions(&self) -> u64 {
        self.unsupported_versions
    }
    /// Candidate bytes checksummed so far, valid or not, saturating at
    /// `u64::MAX`. Field parsing reads at most these bytes again. For observe
    /// layers and work bounds: see [`MAX_RESYNC_DEBT`].
    pub fn examined(&self) -> u64 {
        self.examined
    }
    // Skips to the next `8=FIX` after offset zero, keeping four bytes when a
    // whole marker has not arrived, including across buffer compaction. The
    // cursor is relative to the unread start, so a scan is linear across
    // calls. Returns Need, with no state changed, only when there is nothing
    // to skip yet.
    fn recover(&mut self, input: &[u8], eof: bool) -> Step<Result<Message, FieldFault>> {
        let mut scanned = if self.resync { self.scanned } else { 1 };
        let mut found = false;
        while let Some(window) = input.get(scanned..).and_then(|b| b.get(..5)) {
            if window == b"8=FIX" {
                found = true;
                break;
            }
            scanned += 1;
        }
        let used = if found {
            scanned
        } else if eof {
            input.len()
        } else {
            input.len().saturating_sub(4)
        };
        if used == 0 {
            return Step::Need;
        }
        if !self.resync {
            self.garbled = self.garbled.saturating_add(1);
        }
        self.resync = !found;
        self.scanned = if found {
            0
        } else {
            scanned.saturating_sub(used)
        };
        Step::Skip(used)
    }
    fn step(&mut self, input: &[u8], eof: bool) -> Step<Result<Message, FieldFault>> {
        // A marker kept back by a partial skip may now start the input.
        if self.resync && self.scanned == 0 && input.starts_with(b"8=FIX") {
            self.resync = false;
        }
        if self.resync {
            return self.recover(input, eof);
        }
        let total = match prefix(input) {
            Ok(Some((_, total))) => total,
            Ok(None) => return Step::Need,
            Err(error) => {
                let step = self.recover(input, eof);
                if error == Error::Version && !matches!(step, Step::Need) {
                    self.unsupported_versions = self.unsupported_versions.saturating_add(1);
                }
                return step;
            }
        };
        let Some(bytes) = input.get(..total) else {
            // Stops at the first later marker, and recover then skips to it,
            // so this scan never covers the same bytes twice.
            if eof && input.windows(5).skip(1).any(|b| b == b"8=FIX") {
                return self.recover(input, eof);
            }
            return Step::Need;
        };
        let Ok(envelope) = envelope(bytes) else {
            return self.recover(input, eof);
        };
        let content = bytes.get(..envelope.checksum_at).unwrap_or_default();
        self.examined = self
            .examined
            .saturating_add(u64::try_from(total).unwrap_or(u64::MAX));
        if u32::from(checksum(content)) != envelope.checksum {
            self.debt = self.debt.saturating_add(total);
            if self.debt <= MAX_RESYNC_DEBT {
                return self.recover(input, eof);
            }
            self.garbled = self.garbled.saturating_add(1);
            return Step::Skip(total);
        }
        match fields(content, envelope.start) {
            Ok(item) => Step::Item(item, total),
            // The trailer sits where BodyLength says and the CheckSum covers
            // exactly that span, so the length is confirmed. Skip the frame
            // rather than rescan inside it.
            Err(_) => {
                self.garbled = self.garbled.saturating_add(1);
                Step::Skip(total)
            }
        }
    }
}
impl Decode for Messages {
    type Item = Result<Message, FieldFault>;
    type Error = Infallible;
    const NAME: &'static str = "FIX";
    /// The maximum unread input needed before a message or error is returned.
    fn capacity(&self) -> usize {
        MAX_MESSAGE_SIZE
    }
    /// Returns a checked message or a [`FieldFault`] item.
    /// On an envelope fault, skips to the next `8=FIX` after offset zero,
    /// retaining four bytes for a split marker. Includes bad lengths,
    /// misplaced tags, unsupported versions, and noise (FIX 4.4 Vol 2 cases
    /// 2.d, 2.m, 2.t, 3.b; Session Layer 4.5.2). A failed candidate's
    /// BodyLength is used as the skip distance only when its trailer and
    /// CheckSum both verify, or past [`MAX_RESYNC_DEBT`].
    /// At EOF, searches incomplete candidates for a later frame. Otherwise
    /// partial input returns `Need`; the driver reports any final truncation.
    /// Never returns `Err`.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Infallible> {
        let step = self.step(input, eof);
        if let Step::Item(_, n) | Step::Skip(n) = &step {
            self.debt = self.debt.saturating_sub(*n);
        }
        Ok(step)
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
/// Where a [`Session`] is. Sequence counters belong to the FIX session and can be
/// saved by the caller and passed to a new machine after a disconnection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No Logon has been sent or accepted.
    AwaitingLogon,
    /// Waiting for a Logon confirmation.
    LogonSent,
    /// Logon completed; sequence recovery may still be in progress.
    Established,
    /// Logout sent; awaiting the peer's confirmation or timeout.
    LogoutSent,
    /// Logout response sent; awaiting transport close or timeout. Resend requests
    /// and application messages are still processed (FIX 4.4 Vol 2 case 13b).
    LogoutReceived,
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
    /// Timeout for a Logout response or the peer's transport close, in milliseconds.
    pub logout_timeout_ms: u64,
    /// Maximum absolute difference between inbound SendingTime and the caller's
    /// UTC `sending_time`, in milliseconds. `None` disables the accuracy check.
    /// A violation sends Reject reason 10 then Logout (FIX 4.4 Vol 2 case 2.o).
    /// An invalid initial Logon sends Logout, subject to the identity exceptions
    /// in Session Layer 4.6.4.
    pub sending_time_tolerance_ms: Option<u64>,
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
            sending_time_tolerance_ms: None,
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
    /// A Logout response or the peer's transport close missed its deadline.
    LogoutTimeout,
    /// No non-garbled message arrived before the TestRequest deadline.
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
        /// Offending field, when its tag could be read.
        tag: Option<u32>,
        /// FIX SessionRejectReason (373).
        reason: u32,
    },
    /// SequenceReset increased the next inbound sequence number. An equal
    /// reset-mode NewSeqNo produces no event and changes no counter (Vol 2 11.b).
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
fn action(
    actions: &mut Vec<Action<Message, Event>>,
    value: Action<Message, Event>,
) -> Result<(), Error> {
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
/// use [`Self::receive`] for wire-valid messages or [`Self::receive_frame`] for
/// [`Messages`] items. The caller
/// authenticates the peer before handing over Logon and owns persistence.
/// Counters advance when output is emitted, so the caller must persist and send
/// each returned message in order. An `Err` leaves the machine unchanged.
///
/// Recovery retains only range counters. Messages above the expected number
/// are requested again, including the first observed high message. The caller
/// supplies replay messages one at a time; no replay store or input queue grows
/// inside the machine. At most [`MAX_PENDING_RESENDS`] disjoint ranges are
/// queued. All emitted ranges are at most [`MAX_RESEND_RANGE`]. Drop this
/// machine when the peer closes the transport; persist its counters first.
/// After [`MAX_RESEND_ATTEMPTS`] requests with the same BeginSeqNo, the next
/// failed recovery sends Logout and closes (Session Layer 4.5.2).
/// A high Logout waits for recovery or `logout_timeout_ms` before acknowledgement
/// (4.8.8 Table 3). A second timeout then bounds the wait for transport close.
#[derive(Clone, Debug)]
pub struct Session {
    config: SessionConfig,
    phase: Phase,
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
    resend_begin: u32,
    resend_attempts: u32,
    pending_logout: Option<(u32, u64)>,
    reset_requested: bool,
    replay_ranges: std::collections::VecDeque<(u32, u32)>,
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
            phase: Phase::AwaitingLogon,
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
            resend_begin: 0,
            resend_attempts: 0,
            pending_logout: None,
            reset_requested: false,
            replay_ranges: std::collections::VecDeque::new(),
        })
    }
    /// Where the session is.
    pub fn phase(&self) -> Phase {
        self.phase
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.phase != Phase::Established || s.test.is_some() {
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.config.role != Role::Initiator || s.phase != Phase::AwaitingLogon {
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
            s.phase = Phase::LogonSent;
            s.state_since = now_ms;
            Ok(())
        })
    }
    /// Processes a received message. Emits administrative responses and events.
    /// Peer session faults produce Reject or Logout actions, or a silent close
    /// for an initial acceptor identity fault (Session Layer 4.6.4). Other invalid
    /// initial Logons send Logout before closing (4.3.11; Vol 2 case 1S.d).
    /// These specific rules take precedence over the broad silent-close wording
    /// in 4.3.1. A first message other than Logon still closes silently (1S.b).
    /// Refuses
    /// wire-invalid caller values, closed state, invalid caller time, or local
    /// sequence exhaustion transactionally. Any non-garbled input clears probes.
    pub fn receive(
        &mut self,
        message: &Message,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        message.validate()?;
        self.transaction(now_ms, sending_time, |s, actions| {
            s.receive_inner(message, None, now_ms, sending_time, actions)
        })
    }
    /// Processes an item from [`Messages`], including a field failure in a valid
    /// envelope. Rejects known sequences and advances only the expected number
    /// (FIX 4.4 Vol 2 case 14.d; Session Layer 4.5.4). Missing or unreadable
    /// MsgSeqNum sends Logout and closes (4.5.3). Lower PossDup messages are
    /// ignored before field validation. Refuses the same caller errors as
    /// [`Self::receive`], leaving the session unchanged on `Err`.
    pub fn receive_frame(
        &mut self,
        frame: &Result<Message, FieldFault>,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        match frame {
            Ok(message) => self.receive(message, now_ms, sending_time),
            Err(fault) => self.transaction(now_ms, sending_time, |s, actions| {
                s.receive_inner(&fault.message, Some(fault), now_ms, sending_time, actions)
            }),
        }
    }
    /// Advances timers. Sends Heartbeat after outgoing silence, TestRequest
    /// after inbound silence plus grace, and disconnects on expired probes.
    /// Any non-garbled inbound message satisfies a probe (Vol 2 state row 14).
    pub fn tick(
        &mut self,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            match s.phase {
                Phase::Closed => return Ok(()),
                Phase::AwaitingLogon | Phase::LogonSent => {
                    if now_ms.saturating_sub(s.state_since) >= s.config.logon_timeout_ms {
                        s.close(CloseReason::LogonTimeout, actions)?;
                    }
                    return Ok(());
                }
                Phase::LogoutSent | Phase::LogoutReceived => {
                    if now_ms.saturating_sub(s.state_since) >= s.config.logout_timeout_ms {
                        s.close(CloseReason::LogoutTimeout, actions)?;
                    }
                    return Ok(());
                }
                Phase::Established => {}
            }
            if s.pending_logout.is_some_and(|(_, since)| {
                now_ms.saturating_sub(since) >= s.config.logout_timeout_ms
            }) {
                s.acknowledge_logout(now_ms, sending_time, actions)?;
                return Ok(());
            }
            let interval = u64::from(s.heartbeat) * 1000;
            let timeout = interval.saturating_add(s.config.transmission_grace_ms);
            if let Some((_, sent)) = &s.test {
                if now_ms.saturating_sub(*sent) >= timeout {
                    s.fatal(
                        CloseReason::TestRequestTimeout,
                        b"TestRequest timeout",
                        now_ms,
                        sending_time,
                        actions,
                    )?;
                    return Ok(());
                }
            } else if interval != 0 && now_ms.saturating_sub(s.last_received) >= timeout {
                s.test_serial = s.test_serial.checked_add(1).ok_or(Error::Limit)?;
                let id = s.test_serial.to_string();
                s.emit(b"1", &[(112, id.as_bytes())], now_ms, sending_time, actions)?;
                s.test = Some((id, now_ms));
            }
            if interval != 0 && now_ms.saturating_sub(s.last_sent) >= interval {
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        body.validate()?;
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.phase != Phase::Established {
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
    /// Empty `text` omits optional Text(58), as in Session Layer 9.6.
    pub fn logout(
        &mut self,
        text: &[u8],
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.phase != Phase::Established {
                return Err(Error::State);
            }
            let fields = [(58, text)];
            s.emit(
                b"5",
                if text.is_empty() { &[] } else { &fields },
                now_ms,
                sending_time,
                actions,
            )?;
            s.phase = Phase::LogoutSent;
            s.state_since = now_ms;
            Ok(())
        })
    }
    /// Sends a session Reject for an application-level field validation failure.
    /// `reason` is SessionRejectReason (373); `tag` is RefTagID (371).
    /// Includes diagnostic Text. RefMsgType is omitted because this method has
    /// no input message; Rejects generated by receive operations include it.
    /// Refuses non-established state, invalid reference numbers, caller time,
    /// or local sequence exhaustion without changing the session.
    pub fn reject(
        &mut self,
        reference: u32,
        tag: u32,
        reason: u32,
        now_ms: u64,
        sending_time: &[u8],
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.phase != Phase::Established {
                return Err(Error::State);
            }
            seq(reference)?;
            s.reject_inner(
                (reference, b""),
                Some(tag),
                reason,
                now_ms,
                sending_time,
                actions,
            )
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
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
            let original_time = match original.unique(122)? {
                Some(time) => time,
                None => required(original, 52)?,
            };
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
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
    ) -> Result<Vec<Action<Message, Event>>, Error> {
        self.transaction(now_ms, sending_time, |s, actions| {
            if s.phase != Phase::Established {
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
        operation: impl FnOnce(&mut Self, &mut Vec<Action<Message, Event>>) -> Result<(), Error>,
    ) -> Result<Vec<Action<Message, Event>>, Error> {
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
    fn initial(&self) -> bool {
        matches!(self.phase, Phase::AwaitingLogon | Phase::LogonSent)
    }
    fn recovery_state(&self) -> Result<(), Error> {
        if matches!(
            self.phase,
            Phase::Established | Phase::LogoutSent | Phase::LogoutReceived
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
        actions: &mut Vec<Action<Message, Event>>,
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
        actions: &mut Vec<Action<Message, Event>>,
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
        actions: &mut Vec<Action<Message, Event>>,
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
    fn close(
        &mut self,
        reason: CloseReason,
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        self.phase = Phase::Closed;
        self.test = None;
        action(actions, Action::Event(Event::Disconnected(reason)))
    }
    fn fatal(
        &mut self,
        reason: CloseReason,
        text: &[u8],
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        self.emit(b"5", &[(58, text)], now, time, actions)?;
        self.close(reason, actions)
    }
    fn reject_inner(
        &mut self,
        reference: (u32, &[u8]),
        tag: Option<u32>,
        reason: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        let (sequence, kind) = reference;
        let mut message = self.header(b"3", self.outgoing, time)?;
        message.push(45, sequence.to_string().as_bytes())?;
        if let Some(tag) = tag {
            message.push(371, tag.to_string().as_bytes())?;
        }
        if !kind.is_empty() {
            message.push(372, kind)?;
        }
        message
            .push(373, reason.to_string().as_bytes())?
            .push(58, reject_text(reason))?;
        self.send_fresh(message, now, actions)?;
        action(
            actions,
            Action::Event(Event::Rejected {
                sequence,
                tag,
                reason,
            }),
        )
    }
    fn request_gap(
        &mut self,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        if let Some(high) = self.gap_high {
            if self.incoming > high {
                self.gap_high = None;
                self.requested_through = None;
                self.resend_attempts = 0;
            } else if self.requested_through.is_none_or(|n| self.incoming > n) {
                if self.resend_begin != self.incoming {
                    self.resend_begin = self.incoming;
                    self.resend_attempts = 0;
                }
                if self.resend_attempts >= MAX_RESEND_ATTEMPTS {
                    return self.fatal(
                        CloseReason::Protocol,
                        b"Resend attempt limit",
                        now,
                        time,
                        actions,
                    );
                }
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
                self.resend_attempts += 1;
            }
        }
        if self.pending_logout.is_some_and(|(n, _)| self.incoming > n) {
            self.acknowledge_logout(now, time, actions)?;
        }
        Ok(())
    }
    fn acknowledge_logout(
        &mut self,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        self.emit(b"5", &[], now, time, actions)?;
        self.pending_logout = None;
        self.phase = Phase::LogoutReceived;
        self.state_since = now;
        Ok(())
    }
    fn observe_gap(&mut self, n: u32) {
        self.gap_high = Some(self.gap_high.unwrap_or(n).max(n));
        if self.requested_through.is_some_and(|end| n >= end) {
            self.requested_through = None;
        }
    }
    fn receive_inner(
        &mut self,
        message: &Message,
        fault: Option<&FieldFault>,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        if self.phase == Phase::Closed {
            return Err(Error::State);
        }
        let initial = self.initial();
        let kind = message.msg_type();
        if initial && kind != b"A" {
            if kind == b"5" && self.config.role == Role::Initiator {
                return self.close(CloseReason::Logout, actions);
            }
            if self.config.role == Role::Acceptor {
                return self.close(CloseReason::Protocol, actions);
            }
            return self.fatal(CloseReason::Protocol, b"Logon required", now, time, actions);
        }
        if initial && self.config.role == Role::Initiator && self.phase != Phase::LogonSent {
            return self.fatal(
                CloseReason::Protocol,
                b"Unexpected Logon",
                now,
                time,
                actions,
            );
        }
        // A complete non-garbled message establishes transport liveness, even
        // if a field requires a Reject. FIX 4.4 Vol 2 state matrix row 14.
        self.last_received = now;
        self.test = None;
        // Initial identity faults take precedence over other field failures.
        // Session Layer 4.6.4 restricts the silent-close rule in 4.3.1.
        if initial
            && self.config.role == Role::Acceptor
            && (message.version()? != self.config.version
                || required(message, 49) != Ok(self.config.target_comp_id.as_bytes())
                || required(message, 56) != Ok(self.config.sender_comp_id.as_bytes()))
        {
            return self.close(CloseReason::Protocol, actions);
        }
        let n = match number(message, 34).and_then(seq) {
            Ok(n) => n,
            Err(_) => {
                return self.fatal(
                    CloseReason::Protocol,
                    b"Missing or unreadable MsgSeqNum",
                    now,
                    time,
                    actions,
                );
            }
        };
        // FIX 4.4 Vol 2 cases 2.e/2.f: ignore lower duplicates before Rejects.
        let expected = if initial && flag(message, 141) == Ok(true) {
            1
        } else {
            self.incoming
        };
        if n < expected && flag(message, 43) == Ok(true) {
            return action(actions, Action::Event(Event::Duplicate(n)));
        }
        // A peer field error is a protocol outcome. Only caller misuse returns
        // Err from receive. FIX 4.4 Vol 2 cases 14.b, 14.e, 14.f and 14.h.
        macro_rules! read_input {
            ($result:expr, $tag:expr, $reason:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(error) => {
                        return self.reject_input(
                            (n, kind),
                            Some($tag),
                            reject_reason(error, $reason),
                            now,
                            time,
                            actions,
                        )
                    }
                }
            };
        }
        if message.version()? != self.config.version {
            return self.fatal(
                CloseReason::Protocol,
                b"Session version mismatch",
                now,
                time,
                actions,
            );
        }
        for tag in [49, 56] {
            let actual = read_input!(required(message, tag), tag, 5);
            let expected = if tag == 49 {
                self.config.target_comp_id.as_bytes()
            } else {
                self.config.sender_comp_id.as_bytes()
            };
            if actual != expected {
                if !initial {
                    self.reject_input((n, message.msg_type()), Some(tag), 9, now, time, actions)?;
                }
                return self.fatal(
                    CloseReason::Protocol,
                    b"Session identity mismatch",
                    now,
                    time,
                    actions,
                );
            }
        }
        if let Some(fault) = fault {
            if n < self.incoming && flag(message, 43) != Ok(true) {
                return self.fatal(
                    CloseReason::SequenceTooLow,
                    b"MsgSeqNum too low",
                    now,
                    time,
                    actions,
                );
            }
            return self.reject_input((n, kind), fault.tag, fault.reason, now, time, actions);
        }
        let appl = read_input!(message.unique(1128), 1128, 5);
        if let Some(value) = appl {
            if self.config.version != Version::Fixt11 || admin(kind) {
                return self.reject_input(
                    (n, message.msg_type()),
                    Some(1128),
                    5,
                    now,
                    time,
                    actions,
                );
            }
            read_input!(session_id(value), 1128, 5);
        }
        let duplicate = read_input!(flag(message, 43), 43, 5);
        let reset = read_input!(flag(message, 141), 141, 5);
        let gap_fill = kind == b"4" && read_input!(flag(message, 123), 123, 5);
        let reset_mode = kind == b"4" && !gap_fill;
        let test_id = read_input!(message.unique(112), 112, 5);
        if test_id.is_some_and(|id| id.len() > MAX_TEST_REQUEST_ID_LENGTH) {
            return self.reject_input((n, message.msg_type()), Some(112), 5, now, time, actions);
        }
        if kind == b"1" && test_id.is_none() {
            return self.reject_input((n, message.msg_type()), Some(112), 1, now, time, actions);
        }
        if initial
            && ((reset && (!self.config.allow_logon_reset || n != 1))
                || (self.config.role == Role::Initiator && reset != self.reset_requested))
        {
            return self.fatal(
                CloseReason::Protocol,
                b"Invalid Logon reset",
                now,
                time,
                actions,
            );
        }
        let expected = if initial && reset { 1 } else { self.incoming };
        if !reset_mode && n < expected && !duplicate {
            return self.fatal(
                CloseReason::SequenceTooLow,
                b"MsgSeqNum too low",
                now,
                time,
                actions,
            );
        }
        let sent = read_input!(required(message, 52).and_then(timestamp), 52, 6);
        let original = read_input!(message.unique(122), 122, 6);
        if duplicate {
            let original = read_input!(
                original.ok_or(Error::Missing(122)).and_then(timestamp),
                122,
                6
            );
            // Lower duplicates are ignored, including this ordering check.
            // FIX 4.4 Vol 2 cases 2.e and 2.f.
            if n == expected && original > sent {
                return self.reject_input(
                    (n, message.msg_type()),
                    Some(122),
                    10,
                    now,
                    time,
                    actions,
                );
            }
        } else if original.is_some() {
            return self.reject_input((n, message.msg_type()), Some(122), 5, now, time, actions);
        }
        if let Some(tolerance) = self.config.sending_time_tolerance_ms {
            let distance = timestamp_nanos(sent)?.abs_diff(timestamp_nanos(timestamp(time)?)?);
            if distance > u128::from(tolerance) * 1_000_000 {
                if !initial {
                    self.reject_input((n, message.msg_type()), Some(52), 10, now, time, actions)?;
                }
                return self.fatal(
                    CloseReason::Protocol,
                    b"SendingTime outside tolerance",
                    now,
                    time,
                    actions,
                );
            }
        }
        let mut heartbeat = self.heartbeat;
        let mut peer_version = None;
        if kind == b"A" {
            let encryption = read_input!(number(message, 98), 98, 6);
            if encryption != 0 {
                return self.reject_input((n, message.msg_type()), Some(98), 5, now, time, actions);
            }
            heartbeat = read_input!(number(message, 108), 108, 6);
            if heartbeat > MAX_HEARTBEAT_SECONDS {
                return self.reject_input(
                    (n, message.msg_type()),
                    Some(108),
                    5,
                    now,
                    time,
                    actions,
                );
            }
            if self.config.version == Version::Fixt11 {
                let id = read_input!(required(message, 1137), 1137, 5);
                read_input!(session_id(id), 1137, 5);
                peer_version = Some(id.to_vec());
            }
            if initial && self.config.role == Role::Initiator && heartbeat != self.heartbeat {
                return self.fatal(
                    CloseReason::Protocol,
                    b"HeartBtInt mismatch",
                    now,
                    time,
                    actions,
                );
            }
        }
        // Validate the entire initial Logon before resetting persisted counters.
        if initial && reset {
            self.incoming = 1;
            if self.config.role == Role::Acceptor {
                self.outgoing = 1;
            }
        }
        let next = if kind == b"4" {
            let next = read_input!(number(message, 36), 36, 6);
            if seq(next).is_err() {
                return self.reject_inner((n, message.msg_type()), Some(36), 5, now, time, actions);
            }
            next
        } else {
            0
        };
        if gap_fill && next <= n {
            // FIX 4.4 Vol 2 case 10.e: reject without advancing or closing.
            return self.reject_inner((n, message.msg_type()), Some(36), 5, now, time, actions);
        }
        if !reset_mode && n < self.incoming {
            return action(actions, Action::Event(Event::Duplicate(n)));
        }
        if reset_mode {
            if next < self.incoming {
                return self.reject_inner((n, message.msg_type()), Some(36), 5, now, time, actions);
            }
            if next == self.incoming {
                return Ok(());
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
            self.observe_gap(n);
            action(
                actions,
                Action::Event(Event::Gap {
                    expected: self.incoming,
                    received: n,
                }),
            )?;
        }
        // Logon and ResendRequest are processed even above the expected number.
        if initial && kind == b"A" {
            self.heartbeat = heartbeat;
            if self.config.role == Role::Acceptor {
                self.logon(now, time, reset, actions)?;
            }
            self.phase = Phase::Established;
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
            // Validate before changing either the replay queue or inbound counter.
            read_input!(number(message, 7), 7, 6);
            read_input!(number(message, 16), 16, 6);
            self.resend_request(message, n, now, time, actions)?;
        } else if kind == b"5" && !duplicate {
            if self.phase == Phase::LogoutSent {
                if !high {
                    self.incoming = advance(self.incoming)?;
                }
                return self.close(CloseReason::Logout, actions);
            }
            if self.phase != Phase::LogoutReceived {
                if high {
                    // Preserve the first request's deadline on repeated Logout.
                    self.pending_logout.get_or_insert((n, now));
                    return self.request_gap(now, time, actions);
                }
                self.request_gap(now, time, actions)?;
                self.acknowledge_logout(now, time, actions)?;
            }
            if !high {
                self.incoming = advance(self.incoming)?;
            }
            return Ok(());
        }
        if high {
            return self.request_gap(now, time, actions);
        }
        if gap_fill {
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
                    b"A" | b"2" | b"0" => {}
                    b"1" => {
                        if let Some(id) = test_id {
                            self.emit(b"0", &[(112, id)], now, time, actions)?;
                        }
                    }
                    b"3" => match number(message, 45).and_then(seq) {
                        Ok(reference) => {
                            action(actions, Action::Event(Event::RejectReceived(reference)))?
                        }
                        Err(error) => self.reject_inner(
                            (n, message.msg_type()),
                            Some(45),
                            reject_reason(error, 6),
                            now,
                            time,
                            actions,
                        )?,
                    },
                    _ => {
                        self.recovery_state()?;
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
        self.request_gap(now, time, actions)
    }
    fn reject_input(
        &mut self,
        reference: (u32, &[u8]),
        tag: Option<u32>,
        reason: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
    ) -> Result<(), Error> {
        let (n, _) = reference;
        if self.initial() {
            return self.fatal(CloseReason::Protocol, b"Invalid Logon", now, time, actions);
        }
        if n == self.incoming {
            self.incoming = advance(self.incoming)?;
        }
        if n > self.incoming {
            self.observe_gap(n);
        }
        self.reject_inner(reference, tag, reason, now, time, actions)?;
        self.request_gap(now, time, actions)
    }
    fn resend_request(
        &mut self,
        message: &Message,
        n: u32,
        now: u64,
        time: &[u8],
        actions: &mut Vec<Action<Message, Event>>,
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
            return self.reject_inner((n, message.msg_type()), Some(7), 5, now, time, actions);
        }
        // Merge only overlapping or adjacent ranges. Restart the bounded scan
        // when a merge expands the range, so transitive overlaps also coalesce.
        let (mut begin, mut end) = (begin, end);
        let mut at = 0;
        let mut insert_at = self.replay_ranges.len();
        while let Some(&(old_begin, old_end)) = self.replay_ranges.get(at) {
            if begin <= old_end.saturating_add(1) && old_begin <= end.saturating_add(1) {
                begin = begin.min(old_begin);
                end = end.max(old_end);
                self.replay_ranges.remove(at);
                insert_at = insert_at.min(at);
                at = 0;
            } else {
                at += 1;
            }
        }
        if self.replay_ranges.len() >= MAX_PENDING_RESENDS {
            return self.reject_inner((n, message.msg_type()), Some(7), 5, now, time, actions);
        }
        self.replay_ranges
            .insert(insert_at.min(self.replay_ranges.len()), (begin, end));
        if let Some(event) = self.next_resend_range() {
            action(actions, Action::Event(event))?;
        }
        Ok(())
    }
    /// Takes the next bounded replay work range after a received ResendRequest.
    /// Large requests are split into inclusive ranges of [`MAX_RESEND_RANGE`].
    /// Overlapping or adjacent requests are coalesced. Disjoint requests wait
    /// until earlier work drains. A full [`MAX_PENDING_RESENDS`] queue rejects
    /// a new disjoint request with reason 5. Returns `None` when drained.
    /// This only advances work cursors; it does not advance FIX sequence numbers.
    pub fn next_resend_range(&mut self) -> Option<Event> {
        let (begin, last) = self.replay_ranges.pop_front()?;
        let end = last.min(begin.saturating_add(MAX_RESEND_RANGE - 1));
        if end < last {
            self.replay_ranges.push_front((end.checked_add(1)?, last));
        }
        Some(Event::Resend { begin, end })
    }
}
fn reject_text(reason: u32) -> &'static [u8] {
    match reason {
        0 => b"Invalid tag number",
        1 => b"Required tag missing",
        4 => b"Tag specified without a value",
        5 => b"Value outside allowed range or invalid data length",
        6 => b"Incorrect data format",
        9 => b"CompID problem",
        10 => b"SendingTime accuracy problem",
        13 => b"Tag appears more than once",
        _ => b"Invalid message field",
    }
}
fn reject_reason(error: Error, fallback: u32) -> u32 {
    match error {
        Error::Missing(_) => 1,
        Error::Duplicate(_) => 13,
        Error::Sequence | Error::Limit => 5,
        _ => fallback,
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

fn timestamp_nanos(value: [u32; 7]) -> Result<u128, Error> {
    let [year, month, day, hour, minute, second, fraction] = value;
    let previous = u128::from(year).checked_sub(1).ok_or(Error::Time)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut days = previous * 365 + previous / 4 - previous / 100 + previous / 400;
    for m in 1..month {
        days += match m {
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 31,
        };
    }
    days = days
        .checked_add(u128::from(day))
        .and_then(|n| n.checked_sub(1))
        .ok_or(Error::Time)?;
    // Four-digit years bound the day count. Checked conversions retain the
    // full nanosecond fraction and handle changes of day, month, and year.
    days.checked_mul(24)
        .and_then(|n| n.checked_add(u128::from(hour)))
        .and_then(|n| n.checked_mul(60))
        .and_then(|n| n.checked_add(u128::from(minute)))
        .and_then(|n| n.checked_mul(60))
        .and_then(|n| n.checked_add(u128::from(second)))
        .and_then(|n| n.checked_mul(1_000_000_000))
        .and_then(|n| n.checked_add(u128::from(fraction)))
        .ok_or(Error::Time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Stream;
    use fictionet::stdlib::test_support::check_atomic;
    use fictionet::stdlib::test_support::contract::{
        check_decode_with_alloc_limit, check_wire, check_wire_value,
    };
    use fictionet::stdlib::test_support::decode_all;
    use fictionet::stdlib::test_support::rounds;

    fn event_resend(begin: u32, end: u32) -> Event {
        Event::Resend { begin, end }
    }

    fn event_rejected(sequence: u32, tag: Option<u32>, reason: u32) -> Event {
        Event::Rejected {
            sequence,
            tag,
            reason,
        }
    }

    fn event_application(sequence: u32, possible_duplicate: bool) -> Event {
        Event::Application {
            sequence,
            possible_duplicate,
        }
    }

    const fn group_layout<'a>(
        count_tag: u32,
        delimiter_tag: u32,
        members: &'a [u32],
        nested: &'a [GroupLayout<'a>],
    ) -> GroupLayout<'a> {
        GroupLayout {
            count_tag,
            delimiter_tag,
            members,
            nested,
        }
    }

    // LOGON is the public Wikipedia Financial Information eXchange example
    // (https://en.wikipedia.org/wiki/Financial_Information_eXchange).
    // HEARTBEAT is constructed from it with sequence 178 and time +30 seconds.
    // These are not published FIX conformance test vectors.
    const LOGON: &[u8] = b"8=FIX.4.2\x019=65\x0135=A\x0149=SERVER\x0156=CLIENT\x0134=177\x0152=20090107-18:15:16\x0198=0\x01108=30\x0110=062\x01";
    const HEARTBEAT: &[u8] = b"8=FIX.4.2\x019=53\x0135=0\x0149=SERVER\x0156=CLIENT\x0134=178\x0152=20090107-18:15:46\x0110=021\x01";
    const TIME: &[u8] = b"20261006-12:00:00";
    const LATER: &[u8] = b"20261006-12:00:01.000";

    fn checked(actions: &[Action<Message, Event>]) {
        assert!(actions.len() <= MAX_ACTIONS);
        for action in actions {
            if let Action::Send(m) = action {
                check_wire_value(m);
                assert!(m.to_bytes().is_ok());
            }
        }
    }
    fn sends(actions: &[Action<Message, Event>]) -> Vec<Message> {
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
    fn has_event(actions: &[Action<Message, Event>], event: Event) -> bool {
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
        assert_eq!(s.phase(), Phase::Established);
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

    // Constructed exact-byte fixtures for the cited public session test cases.
    fn received_bytes(
        session: &mut Session,
        bytes: &[u8],
        now: u64,
    ) -> Vec<Action<Message, Event>> {
        check_wire::<Message>(bytes);
        let message = Message::parse(bytes).unwrap();
        let actions = session.receive(&message, now, TIME).unwrap();
        checked(&actions);
        actions
    }

    #[test]
    fn round_two_a_resynchronizes_after_bad_lengths_positions_and_noise() {
        // FIX 4.4 Vol 2 cases 2.m, 2.t; Session Layer 4.5.2.
        let good = b"8=FIX.4.4\x019=5\x0135=0\x0110=163\x01";
        for bad in [
            b"8=FIX.4.4\x019=6\x0135=0\x0110=163\x01".as_slice(),
            b"8=FIX.4.4\x019=5\x0135=0\x0158=x\x0110=000\x01",
            b"8=FIX.4.4\x0135=0\x019=5\x0110=xxx\x01",
            b"x",
        ] {
            let bytes = [bad, good, good].concat();
            let (items, failure) = decode_all(Messages::default, &bytes);
            assert_eq!(failure, None);
            assert_eq!(items.len(), 2);
            for chunks in [1, bytes.len()] {
                let mut stream = Stream::new(Messages::default());
                let mut count = 0;
                for chunk in bytes.chunks(chunks) {
                    fictionet::stdlib::codec::pump(&mut stream, chunk, |_| count += 1).unwrap();
                }
                fictionet::stdlib::codec::finish(&mut stream, |_| count += 1).unwrap();
                assert_eq!(count, 2);
                assert_eq!(stream.decoder().garbled(), 1);
            }
            check_decode_with_alloc_limit(Messages::default, &bytes, 2 * MAX_MESSAGE_SIZE);
        }
        for bad in [
            b"8=FIX.4.4\x019=4\x0135=0\x0110=163\x01".as_slice(),
            b"8=FIX.4.4\x019=50\x0135=0\x0110=163\x01",
            b"8=FIX.4.4\x019=5000\x0135=0\x0110=163\x01",
        ] {
            let bytes = [bad, LOGON].concat();
            let (items, failure) = decode_all(Messages::default, &bytes);
            assert_eq!(failure, None);
            assert_eq!(items.len(), 1);
            check_decode_with_alloc_limit(Messages::default, &bytes, 2 * MAX_MESSAGE_SIZE);
        }
    }

    const HIGH_FOUR: &[u8] = b"8=FIX.4.4\x019=52\x0135=D\x0134=4\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=102\x01";
    const REPLAY_TWO: &[u8] = b"8=FIX.4.4\x019=79\x0135=D\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x0110=147\x01";
    const REPLAY_FOUR: &[u8] = b"8=FIX.4.4\x019=79\x0135=D\x0134=4\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x0110=149\x01";
    const EMPTY_TEXT: &[u8] = b"8=FIX.4.4\x019=56\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0158=\x0110=255\x01";
    const HIGH_LOGOUT: &[u8] = b"8=FIX.4.4\x019=52\x0135=5\x0134=5\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=088\x01";

    #[test]
    fn round_two_b_lost_replay_requests_the_remaining_gap() {
        // Session Layer 4.5.2 and 4.8.2: replay 3 is lost or garbled.
        let mut session = established(Version::Fix44);
        let sent = sends(&received_bytes(&mut session, HIGH_FOUR, 1));
        assert_eq!(sent[0].get(7), Some(b"2".as_slice()));
        assert_eq!(sent[0].get(16), Some(b"4".as_slice()));
        received_bytes(&mut session, REPLAY_TWO, 2);
        let sent = sends(&received_bytes(&mut session, REPLAY_FOUR, 3));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].msg_type(), b"2");
        assert_eq!(sent[0].get(7), Some(b"3".as_slice()));
        assert_eq!(session.next_inbound(), 3);
    }

    #[test]
    fn round_two_b_repeated_resend_requests_are_bounded() {
        // Session Layer 4.5.2 recommends guarding repeated failed recovery.
        let mut session = established(Version::Fix44);
        for now in 1..=u64::from(MAX_RESEND_ATTEMPTS) {
            let sent = sends(&received_bytes(&mut session, HIGH_FOUR, now));
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].msg_type(), b"2");
            assert_eq!(sent[0].get(7), Some(b"2".as_slice()));
        }
        let actions = received_bytes(&mut session, HIGH_FOUR, u64::from(MAX_RESEND_ATTEMPTS) + 1);
        assert_eq!(sends(&actions)[0].msg_type(), b"5");
        assert_eq!(session.phase(), Phase::Closed);
    }

    #[test]
    fn round_two_c_empty_field_is_an_item() {
        // FIX 4.4 Vol 2 case 14.d: a valid envelope requires a field Reject.
        check_wire::<Message>(EMPTY_TEXT);
        let (items, failure) = decode_all(Messages::default, EMPTY_TEXT);
        assert_eq!(failure, None);
        assert_eq!(items.len(), 1);
        let fault = items[0].as_ref().unwrap_err();
        assert_eq!(fault.sequence(), Some(2));
        assert_eq!(
            (fault.msg_type(), fault.tag(), fault.reason()),
            (b"0".as_slice(), Some(58), 4)
        );
        let mut session = established(Version::Fix44);
        let actions = session.receive_frame(&items[0], 1, TIME).unwrap();
        let sent = sends(&actions);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].msg_type(), b"3");
        assert_eq!(sent[0].get(45), Some(b"2".as_slice()));
        assert_eq!(sent[0].get(371), Some(b"58".as_slice()));
        assert_eq!(sent[0].get(372), Some(b"0".as_slice()));
        assert_eq!(sent[0].get(373), Some(b"4".as_slice()));
        assert!(sent[0].get(58).is_some());
        assert_eq!(session.next_inbound(), 3);
        let replay = b"8=FIX.4.4\x019=83\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x0158=\x0110=037\x01";
        let (items, failure) = decode_all(Messages::default, replay);
        assert_eq!(failure, None);
        assert_eq!(
            session.receive_frame(&items[0], 2, TIME).unwrap(),
            [Action::Event(Event::Duplicate(2))]
        );
        assert_eq!(session.next_inbound(), 3);
        check_decode_with_alloc_limit(Messages::default, EMPTY_TEXT, 2 * MAX_MESSAGE_SIZE);
        check_decode_with_alloc_limit(Messages::default, replay, 2 * MAX_MESSAGE_SIZE);
    }

    #[test]
    fn round_two_d_high_logout_waits_for_recovery() {
        // Session Layer 4.8.8 Table 3 and 4.6.3: recover before acknowledging.
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, HIGH_LOGOUT, 1);
        assert!(has_event(
            &actions,
            Event::Gap {
                expected: 2,
                received: 5
            }
        ));
        let sent = sends(&actions);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].msg_type(), b"2");
        assert_eq!(sent[0].get(7), Some(b"2".as_slice()));
        assert_eq!(sent[0].get(16), Some(b"5".as_slice()));
        assert!(sends(&received_bytes(&mut session, REPLAY_TWO, 2)).is_empty());
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=90\x0135=4\x0134=3\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x01123=Y\x0136=6\x0110=135\x01", 3);
        assert_eq!(sends(&actions)[0].msg_type(), b"5");
        assert_eq!(session.next_inbound(), 6);
        assert_eq!(session.phase(), Phase::LogoutReceived);
    }

    #[test]
    fn round_two_d_high_logout_acknowledgement_has_a_deadline() {
        // Session Layer 4.6 and 4.8.8 Table 3: bound the recovery wait.
        let mut session = established(Version::Fix44);
        received_bytes(&mut session, HIGH_LOGOUT, 1);
        assert!(session.tick(2000, TIME).unwrap().is_empty());
        let actions = session.tick(2001, TIME).unwrap();
        assert_eq!(sends(&actions).len(), 1);
        assert_eq!(sends(&actions)[0].msg_type(), b"5");
        assert_eq!(session.phase(), Phase::LogoutReceived);
    }

    #[test]
    fn round_two_c_field_faults_reject_without_garbling() {
        // FIX 4.4 Vol 2 cases 14.a/14.d/14.e; Session Layer 4.5.4.
        for (bytes, tag, reason) in [
            (b"8=FIX.4.4\x019=58\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01abc=1\x0110=235\x01".as_slice(), None, 0),
            (b"8=FIX.4.4\x019=56\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x010=1\x0110=243\x01".as_slice(), Some(0), 0),
            (b"8=FIX.4.4\x019=62\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0195=2\x0196=a\x0110=061\x01".as_slice(), Some(96), 5),
            (b"8=FIX.4.4\x019=61\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0195=0\x0196=\x0110=217\x01".as_slice(), Some(96), 4),
        ] {
            let mut stream = Stream::new(Messages::default());
            assert_eq!(stream.push(bytes), bytes.len());
            let item = stream.next().unwrap().unwrap();
            assert_eq!(stream.decoder().garbled(), 0);
            let fault = item.as_ref().unwrap_err();
            assert_eq!((fault.sequence(), fault.tag(), fault.reason()), (Some(2), tag, reason));
            let mut session = established(Version::Fix44);
            let sent = sends(&session.receive_frame(&item, 1, TIME).unwrap());
            assert_eq!(sent[0].get(371), tag.map(|t| t.to_string()).as_deref().map(str::as_bytes));
            assert_eq!(sent[0].get(373), Some(reason.to_string().as_bytes()));
            assert_eq!(session.next_inbound(), 3);
            assert!(Message::parse(bytes).is_err());
            check_wire::<Message>(bytes);
            check_decode_with_alloc_limit(Messages::default, bytes, 2 * MAX_MESSAGE_SIZE);
        }
        // An empty data value is refused transactionally, like other empty fields.
        let mut message = Message::new(Version::Fix44, b"0").unwrap();
        let before = message.clone();
        assert_eq!(message.push_data(95, b""), Err(Error::Field));
        assert_eq!(message, before);
    }

    #[test]
    fn round_two_c_unreadable_sequence_logs_out_without_consuming_it() {
        // Session Layer 4.5.3: an unreadable 34 is treated as missing.
        for bytes in [
            b"8=FIX.4.4\x019=54\x0135=0\x0134=abc\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=070\x01".as_slice(),
            b"8=FIX.4.4\x019=52\x0135=0\x0134=0\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=078\x01".as_slice(),
            b"8=FIX.4.4\x019=55\x0135=0\x0134=\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0158=\x0110=204\x01".as_slice(),
        ] {
            let (items, failure) = decode_all(Messages::default, bytes);
            assert_eq!(failure, None);
            assert_eq!(items.len(), 1);
            let mut session = established(Version::Fix44);
            let actions = session.receive_frame(&items[0], 1, TIME).unwrap();
            assert_eq!(sends(&actions)[0].msg_type(), b"5");
            assert_eq!(session.phase(), Phase::Closed);
            assert_eq!(session.next_inbound(), 2);
        }
    }

    #[test]
    fn round_two_lower_duplicates_precede_field_rejects() {
        // FIX 4.4 Vol 2 cases 2.e/2.f: no field Reject for consumed duplicates.
        for bytes in [
            b"8=FIX.4.4\x019=68\x0135=4\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01123=X\x0136=7\x0110=098\x01".as_slice(),
            b"8=FIX.4.4\x019=69\x0135=4\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01112=a\x01112=b\x0110=192\x01".as_slice(),
            b"8=FIX.4.4\x019=61\x0135=4\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x0158=\x0110=252\x01".as_slice(),
        ] {
            let (items, failure) = decode_all(Messages::default, bytes);
            assert_eq!(failure, None);
            let mut session = established(Version::Fix44);
            assert_eq!(session.receive_frame(&items[0], 1, TIME).unwrap(), [Action::Event(Event::Duplicate(1))]);
            assert_eq!(session.next_inbound(), 2);
        }
        // A lower replayed Logon also precedes ordinary field validation.
        let mut session = Session::new(
            SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            5,
            7,
            0,
        )
        .unwrap();
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=64\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x0198=bad\x0110=055\x01", 1);
        assert_eq!(actions, [Action::Event(Event::Duplicate(1))]);
        assert_eq!(session.next_inbound(), 5);
    }

    #[test]
    fn round_two_initial_logon_errors_send_logout_except_identity() {
        // Session Layer 4.3.11/4.6.4 and FIX 4.4 Vol 2 case 1S.d.
        for bytes in [
            b"8=FIX.4.4\x019=64\x0135=A\x0134=3\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x0110=126\x01".as_slice(),
            b"8=FIX.4.4\x019=65\x0135=A\x0134=5\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=abc\x0110=068\x01".as_slice(),
            b"8=FIX.4.4\x019=70\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x01141=Y\x0110=166\x01".as_slice(),
        ] {
            let config = SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap();
            let mut session = Session::new(config, 5, 7, 0).unwrap();
            let actions = received_bytes(&mut session, bytes, 1);
            assert_eq!(sends(&actions).len(), 1);
            assert_eq!(sends(&actions)[0].msg_type(), b"5");
            assert_eq!(session.next_inbound(), 5);
            assert_eq!(session.next_outbound(), 8);
            assert_eq!(session.phase(), Phase::Closed);
        }
        let mut session = Session::new(
            SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        let actions = received_bytes(&mut session, b"8=FIX.4.2\x019=64\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x0110=122\x01", 1);
        assert_eq!(
            actions,
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
    }

    #[test]
    fn round_two_unsupported_version_resync_is_observable() {
        // FIX 4.4 Vol 2 case 2.i; Session Layer 4.6.4 (initial identity).
        let bytes = [b"8=FIX.4.1\x019=5\x0135=0\x0110=160\x01".as_slice(), LOGON].concat();
        let mut stream = Stream::new(Messages::default());
        for byte in &bytes {
            fictionet::stdlib::codec::pump(&mut stream, &[*byte], |item| {
                assert_eq!(item, Ok(Message::parse(LOGON).unwrap()));
            })
            .unwrap();
        }
        assert_eq!(stream.decoder().unsupported_versions(), 1);
        assert_eq!(stream.decoder().garbled(), 1);
        check_decode_with_alloc_limit(Messages::default, &bytes, 2 * MAX_MESSAGE_SIZE);
    }

    #[test]
    fn round_two_data_pairs_and_timestamp_precision() {
        // Session Layer 9.2; FIX Application Layer Introduction 7.33.
        for bytes in [
            b"8=FIXT.1.1\x019=21\x0135=A\x011184=3\x011185=a\x01b\x0110=064\x01".as_slice(),
            b"8=FIXT.1.1\x019=21\x0135=A\x011401=3\x011402=a\x01b\x0110=048\x01".as_slice(),
            b"8=FIXT.1.1\x019=21\x0135=A\x011403=3\x011404=a\x01b\x0110=052\x01".as_slice(),
        ] {
            let message = Message::parse(bytes).unwrap();
            assert_eq!(message.to_bytes().unwrap(), bytes);
            check_wire::<Message>(bytes);
            check_wire_value(&message);
            check_decode_with_alloc_limit(Messages::default, bytes, 2 * MAX_MESSAGE_SIZE);
        }
        assert_eq!(
            timestamp(b"20261006-12:00:00.123456789012"),
            Err(Error::Time)
        );
        assert!(timestamp(b"20261006-12:00:00.123456789").is_ok());
    }

    #[test]
    fn round_two_pending_logout_acknowledges_replayed_logout_once() {
        // Session Layer 4.8.8 Table 3: consume the recorded number first.
        let mut session = established(Version::Fix44);
        received_bytes(&mut session, HIGH_LOGOUT, 1);
        let gap = b"8=FIX.4.4\x019=90\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x01123=Y\x0136=5\x0110=133\x01";
        assert!(sends(&received_bytes(&mut session, gap, 2)).is_empty());
        assert_eq!(session.next_inbound(), 5);
        let replay = b"8=FIX.4.4\x019=79\x0135=5\x0134=5\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x0110=135\x01";
        let sent = sends(&received_bytes(&mut session, replay, 3));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].msg_type(), b"5");
        assert_eq!(session.next_inbound(), 6);
        assert!(sends(&received_bytes(&mut session, replay, 4)).is_empty());
        assert_eq!(session.phase(), Phase::LogoutReceived);
    }

    #[test]
    fn round_two_retry_budget_restarts_after_inbound_progress() {
        // Session Layer 4.5.2: only repeated requests with the same begin count.
        let mut session = established(Version::Fix44);
        for now in 1..=u64::from(MAX_RESEND_ATTEMPTS) {
            received_bytes(&mut session, HIGH_FOUR, now);
        }
        let now = u64::from(MAX_RESEND_ATTEMPTS) + 1;
        received_bytes(&mut session, REPLAY_TWO, now);
        let sent = sends(&received_bytes(&mut session, REPLAY_FOUR, now + 1));
        assert_eq!(sent[0].get(7), Some(b"3".as_slice()));
        assert_eq!(session.phase(), Phase::Established);
    }

    #[test]
    fn review_a_fixt_headers_accept_tag_order() {
        // Session Layer 8.5: only 8, 9, 35 have fixed header positions.
        let mut session = Session::new(
            SessionConfig::new(Version::Fixt11, Role::Acceptor, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        received_bytes(&mut session, b"8=FIXT.1.1\x019=71\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x011137=6\x0110=008\x01", 0);
        assert_eq!(session.phase(), Phase::Established);
        assert!(received_bytes(&mut session, b"8=FIXT.1.1\x019=52\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=158\x01", 1).is_empty());
        assert_eq!(session.next_inbound(), 3);
    }

    #[test]
    fn review_b_acceptor_first_message_closes_without_sending() {
        // Session Layer 4.3.1; FIX 4.4 Vol 2 cases 1S.b and 1S.c.
        for bytes in [b"8=FIX.4.4\x019=52\x0135=0\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=079\x01".as_slice(), b"8=FIX.4.4\x019=64\x0135=A\x0134=1\x0149=EVIL\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x0110=128\x01"] {
            let mut session = Session::new(
                SessionConfig::new(Version::Fix44, Role::Acceptor, "LOCAL", "PEER").unwrap(),
                1, 1, 0,
            ).unwrap();
            assert_eq!(received_bytes(&mut session, bytes, 1),
                [Action::Event(Event::Disconnected(CloseReason::Protocol))]);
            assert_eq!((session.next_inbound(), session.next_outbound()), (1, 1));
        }
    }

    #[test]
    fn review_c_invalid_logon_timestamps_never_send_reject_first() {
        // Session Layer 4.3.11 and 4.6.4; FIX 4.4 Vol 2 cases 1S.d and 1B.e.
        for role in [Role::Acceptor, Role::Initiator] {
            for bytes in [b"8=FIX.4.4\x019=52\x0135=A\x0134=1\x0149=PEER\x0152=bad\x0156=LOCAL\x0198=0\x01108=30\x01141=Y\x0110=185\x01".as_slice(), b"8=FIX.4.4\x019=83\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=bad\x0198=0\x01108=30\x01141=Y\x0110=162\x01", b"8=FIX.4.4\x019=97\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:02\x0198=0\x01108=30\x01141=Y\x0110=215\x01"] {
                let mut config = SessionConfig::new(Version::Fix44, role, "LOCAL", "PEER").unwrap();
                config.allow_logon_reset = true;
                let mut session = Session::new(config, 7, 9, 0).unwrap();
                if role == Role::Initiator { session.start(0, TIME, true).unwrap(); }
                let before = (session.next_inbound(), session.next_outbound());
                let actions = received_bytes(&mut session, bytes, 1);
                assert_eq!(session.phase(), Phase::Closed);
                let sent = sends(&actions);
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].msg_type(), b"5");
                assert_eq!(session.next_inbound(), before.0);
                assert_eq!(session.next_outbound(), before.1 + 1);
            }
        }
    }

    #[test]
    fn review_d_reset_equal_is_noop() {
        // FIX 4.4 Vol 2 case 11.b: equal NewSeqNo is accepted.
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=57\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0136=2\x0110=050\x01", 1);
        assert!(sends(&actions).is_empty());
        assert_eq!(session.phase(), Phase::Established);
        assert_eq!((session.next_inbound(), session.next_outbound()), (2, 2));
    }

    #[test]
    fn review_d_invalid_reset_and_gap_fill_only_reject() {
        // FIX 4.4 Vol 2 cases 11.c and 10.e: no disconnect or inbound change.
        for bytes in [b"8=FIX.4.4\x019=57\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0136=1\x0110=049\x01".as_slice(), b"8=FIX.4.4\x019=63\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01123=Y\x0136=2\x0110=092\x01", b"8=FIX.4.4\x019=63\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01123=Y\x0136=1\x0110=091\x01"] {
            let mut session = established(Version::Fix44);
            let actions = received_bytes(&mut session, bytes, 1);
            let sent = sends(&actions);
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].msg_type(), b"3");
            assert_eq!(sent[0].get(373), Some(b"5".as_slice()));
            assert_eq!(session.phase(), Phase::Established);
            assert_eq!(session.next_inbound(), 2);
        }
    }

    #[test]
    fn review_d_large_gap_fill_moves_only_counters() {
        // FIX 4.4 Vol 2 case 10.b: no bound on an inbound gap's size.
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=67\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01123=Y\x0136=10003\x0110=034\x01", 1);
        assert!(sends(&actions).is_empty());
        assert_eq!(session.phase(), Phase::Established);
        assert_eq!(session.next_inbound(), 10003);
    }

    #[test]
    fn review_e_logout_response_waits_and_serves_resends() {
        // FIX 4.4 Vol 2 state matrix row 15 and case 13b.
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=52\x0135=5\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=085\x01", 1);
        assert_eq!(sends(&actions)[0].msg_type(), b"5");
        assert_ne!(session.phase(), Phase::Closed);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Event(Event::Disconnected(_))))
        );
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=61\x0135=2\x0134=3\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x017=1\x0116=0\x0110=206\x01", 2);
        assert!(has_event(&actions, event_resend(1, 2)));
        assert!(session.tick(2000, TIME).unwrap().is_empty());
        assert!(has_event(
            &session.tick(2001, TIME).unwrap(),
            Event::Disconnected(CloseReason::LogoutTimeout)
        ));
    }

    #[test]
    fn review_f_application_traffic_satisfies_probe() {
        // FIX 4.4 Vol 2 state matrix row 14: any non-garbled inbound message.
        let mut session = established(Version::Fix44);
        session.test_request(b"probe", 0, TIME).unwrap();
        received_bytes(&mut session, b"8=FIX.4.4\x019=52\x0135=8\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=088\x01", 1000);
        for second in 2..=65u32 {
            let app = inbound(Version::Fix44, b"8", second + 1, &[]);
            let now = u64::from(second) * 1000;
            session.receive(&app, now, TIME).unwrap();
            checked(&session.tick(now, TIME).unwrap());
            assert_eq!(session.phase(), Phase::Established);
        }
    }

    #[test]
    fn review_g_garbled_frames_do_not_end_stream() {
        // FIX 4.4 Vol 2 cases 2.d, 2.m, 2.t, 3.b: discard then continue.
        let mut bad_checksum = HEARTBEAT.to_vec();
        let digit = bad_checksum.len() - 2;
        bad_checksum[digit] = b'2';
        let malformed = b"8=FIX.4.4\x019=52\x0149=PEER\x0135=0\x0134=2\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=080\x01";
        for bad in [bad_checksum.as_slice(), malformed] {
            let wire = [bad, LOGON].concat();
            let (messages, failure) = decode_all(Messages::default, &wire);
            assert_eq!(failure, None);
            assert_eq!(messages, [Ok(Message::parse(LOGON).unwrap())]);
            check_decode_with_alloc_limit(Messages::default, &wire, 2 * MAX_MESSAGE_SIZE);
        }
    }

    #[test]
    fn review_h_application_delivered_while_logout_sent() {
        // Session Layer state 16 and section 4.6.3: deliver during recovery.
        let mut session = established(Version::Fix44);
        session.logout(b"bye", 0, TIME).unwrap();
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=52\x0135=8\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=088\x01", 1);
        assert!(has_event(&actions, event_application(2, false)));
        assert_eq!(session.next_inbound(), 3);
    }

    #[test]
    fn malformed_peer_fields_reject_and_do_not_reopen_consumed_gaps() {
        // FIX 4.4 Vol 2 cases 14.b, 14.e, 14.f, 14.h; Session Layer 4.5.4.
        for (bytes, version, tag, reason) in [
            (b"8=FIX.4.4\x019=57\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=X\x0110=082\x01".as_slice(), Version::Fix44, 43, 5),
            (b"8=FIX.4.4\x019=70\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x01141=X\x0110=166\x01".as_slice(), Version::Fix44, 141, 5),
            (b"8=FIX.4.4\x019=62\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=N\x0143=Y\x0110=066\x01".as_slice(), Version::Fix44, 43, 13),
            (b"8=FIX.4.4\x019=64\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01112=a\x01112=b\x0110=186\x01".as_slice(), Version::Fix44, 112, 13),
            (b"8=FIX.4.4\x019=101\x0135=0\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:00\x01122=20261006-12:00:00\x0110=201\x01".as_slice(), Version::Fix44, 122, 13),
            (b"8=FIX.4.4\x019=67\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=86401\x0110=032\x01".as_slice(), Version::Fix44, 108, 5),
            (b"8=FIX.4.4\x019=57\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x0110=069\x01".as_slice(), Version::Fix44, 108, 1),
            (b"8=FIX.4.4\x019=59\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01108=30\x0110=162\x01".as_slice(), Version::Fix44, 98, 1),
            (b"8=FIX.4.4\x019=64\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=x\x01108=30\x0110=197\x01".as_slice(), Version::Fix44, 98, 6),
            (b"8=FIX.4.4\x019=63\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=x\x0110=145\x01".as_slice(), Version::Fix44, 108, 6),
            (b"8=FIX.4.4\x019=57\x0135=2\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0116=0\x0110=044\x01".as_slice(), Version::Fix44, 7, 1),
            (b"8=FIX.4.4\x019=61\x0135=2\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x017=1\x0116=x\x0110=021\x01".as_slice(), Version::Fix44, 16, 6),
            (b"8=FIX.4.4\x019=57\x0135=4\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0136=x\x0110=120\x01".as_slice(), Version::Fix44, 36, 6),
            (b"8=FIXT.1.1\x019=64\x0135=A\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x0110=203\x01".as_slice(), Version::Fixt11, 1137, 1),
        ] {
            let mut session = established(version);
            let actions = received_bytes(&mut session, bytes, 1);
            assert!(has_event(&actions, event_rejected(2, Some(tag), reason)), "{tag}");
            assert_eq!(sends(&actions)[0].get(373), Some(reason.to_string().as_bytes()));
            assert_eq!(session.next_inbound(), 3);
            assert_eq!(session.phase(), Phase::Established);
            // Repeating the same malformed sequence cannot trigger its own
            // ResendRequest again, or roll back the previous inbound advance.
            let again = received_bytes(&mut session, bytes, 2);
            assert!(sends(&again).iter().all(|m| m.msg_type() != b"2"));
            assert!(session.next_inbound() >= 3);
        }
    }

    #[test]
    fn invalid_initial_logon_fields_send_logout_without_resetting_counters() {
        // Session Layer 4.3.11/4.6.4. Validate before applying ResetSeqNumFlag.
        for role in [Role::Acceptor, Role::Initiator] {
            for bytes in [
                b"8=FIXT.1.1\x019=77\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x01141=X\x011137=6\x0110=058\x01".as_slice(),
                b"8=FIXT.1.1\x019=80\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=86401\x01141=Y\x011137=6\x0110=213\x01".as_slice(),
                b"8=FIXT.1.1\x019=70\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01141=Y\x011137=6\x0110=250\x01".as_slice(),
                b"8=FIXT.1.1\x019=72\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x01108=30\x01141=Y\x011137=6\x0110=087\x01".as_slice(),
                b"8=FIXT.1.1\x019=70\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x01141=Y\x0110=244\x01".as_slice(),
            ] {
                let mut config = SessionConfig::new(Version::Fixt11, role, "LOCAL", "PEER").unwrap();
                config.allow_logon_reset = true;
                let mut session = Session::new(config, 7, 9, 0).unwrap();
                if role == Role::Initiator { session.start(0, TIME, true).unwrap(); }
                let before = (session.next_inbound(), session.next_outbound());
                let actions = received_bytes(&mut session, bytes, 1);
                assert_eq!(session.phase(), Phase::Closed);
                assert_eq!(sends(&actions).len(), 1);
                assert_eq!(sends(&actions)[0].msg_type(), b"5");
                assert_eq!(session.next_inbound(), before.0);
                assert_eq!(session.next_outbound(), before.1 + 1);
            }
        }
    }

    #[test]
    fn missing_sequence_is_fatal_and_compid_mismatch_rejects_before_logout() {
        // Session Layer 4.5.3; FIX 4.4 Vol 2 case 2.k.
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=47\x0135=0\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=125\x01", 1);
        assert_eq!(sends(&actions).len(), 1);
        assert_eq!(sends(&actions)[0].msg_type(), b"5");
        assert_eq!(session.phase(), Phase::Closed);
        assert_eq!(session.next_inbound(), 2);
        let mut session = established(Version::Fix44);
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=52\x0135=0\x0134=2\x0149=EVIL\x0152=20261006-12:00:01.000\x0156=LOCAL\x0110=084\x01", 1);
        let sent = sends(&actions);
        assert_eq!(
            sent.iter().map(Message::msg_type).collect::<Vec<_>>(),
            [b"3", b"5"]
        );
        assert_eq!(sent[0].get(373), Some(b"9".as_slice()));
        assert_eq!(session.next_inbound(), 3);
        assert_eq!(session.phase(), Phase::Closed);
    }

    #[test]
    fn lower_duplicates_ignore_timestamp_order() {
        // FIX 4.4 Vol 2 cases 2.e and 2.f.
        let mut session = established(Version::Fix44);
        assert_eq!(received_bytes(&mut session, b"8=FIX.4.4\x019=79\x0135=8\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0143=Y\x01122=20261006-12:00:02\x0110=136\x01", 1), [Action::Event(Event::Duplicate(1))]);
        assert_eq!(session.next_inbound(), 2);
    }

    #[test]
    fn sending_time_tolerance_is_optional_and_handles_calendar_boundaries() {
        // FIX 4.4 Vol 2 case 2.o; Session Layer 4.2.3.
        let bytes = b"8=FIX.4.4\x019=52\x0135=8\x0134=2\x0149=PEER\x0152=20261231-23:59:00.000\x0156=LOCAL\x0110=103\x01";
        let message = Message::parse(bytes).unwrap();
        let mut session = established(Version::Fix44);
        assert!(has_event(
            &session.receive(&message, 1, TIME).unwrap(),
            event_application(2, false)
        ));
        for (time, accepted) in [
            (b"20270101-00:01:00.000".as_slice(), true),
            (b"20270101-00:01:00.001".as_slice(), false),
            (b"20261231-23:56:59.999".as_slice(), false),
        ] {
            let mut session = established(Version::Fix44);
            session.config.sending_time_tolerance_ms = Some(120_000);
            let actions = session.receive(&message, 1, time).unwrap();
            checked(&actions);
            if accepted {
                assert!(sends(&actions).is_empty());
                assert_eq!(session.phase(), Phase::Established);
            } else {
                let sent = sends(&actions);
                assert_eq!(sent.len(), 2);
                assert_eq!(sent[0].get(373), Some(b"10".as_slice()));
                assert_eq!(sent[1].msg_type(), b"5");
                assert_eq!(session.phase(), Phase::Closed);
            }
            assert_eq!(session.next_inbound(), 3);
        }
    }

    #[test]
    fn logout_can_omit_text_and_replay_can_use_original_time_alone() {
        // Session Layer 9.6 (optional Text), 4.8.4 (original timestamp).
        let mut session = established(Version::Fix44);
        assert!(
            sends(&session.logout(b"", 1, TIME).unwrap())[0]
                .get(58)
                .is_none()
        );
        let stored = Message::parse(b"8=FIX.4.4\x019=49\x0135=8\x0134=1\x0149=LOCAL\x0156=PEER\x01122=20261006-12:00:00\x0110=204\x01").unwrap();
        let actions = session.replay(&stored, 2, LATER).unwrap();
        assert_eq!(sends(&actions)[0].get(122), Some(TIME));
    }

    #[test]
    fn initiator_logon_before_start_names_unexpected_logon() {
        let mut session = Session::new(
            SessionConfig::new(Version::Fix44, Role::Initiator, "LOCAL", "PEER").unwrap(),
            1,
            1,
            0,
        )
        .unwrap();
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=64\x0135=A\x0134=1\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x0198=0\x01108=30\x0110=124\x01", 1);
        assert_eq!(
            sends(&actions)[0].get(58),
            Some(b"Unexpected Logon".as_slice())
        );
    }

    #[test]
    fn resend_disjoint_ranges_stay_queued_and_touching_ranges_merge() {
        // Session Layer 4.8.3: replay only the requested inclusive ranges.
        let mut session = established(Version::Fix44);
        session.outgoing = 40_001;
        let first = received_bytes(&mut session, b"8=FIX.4.4\x019=69\x0135=2\x0134=2\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x017=10005\x0116=40000\x0110=094\x01", 1);
        assert!(has_event(&first, event_resend(10005, 20004)));
        let second = received_bytes(&mut session, b"8=FIX.4.4\x019=61\x0135=2\x0134=3\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x017=1\x0116=3\x0110=209\x01", 2);
        assert!(has_event(&second, event_resend(20005, 30004)));
        assert_eq!(
            session.next_resend_range(),
            Some(event_resend(30005, 40000))
        );
        assert_eq!(session.next_resend_range(), Some(event_resend(1, 3)));
        assert_eq!(session.next_resend_range(), None);
        session.replay_ranges.push_back((10001, 20000));
        let actions = received_bytes(&mut session, b"8=FIX.4.4\x019=69\x0135=2\x0134=4\x0149=PEER\x0152=20261006-12:00:01.000\x0156=LOCAL\x017=20001\x0116=20003\x0110=094\x01", 3);
        assert!(has_event(&actions, event_resend(10001, 20000)));
        assert_eq!(
            session.next_resend_range(),
            Some(event_resend(20001, 20003))
        );
        assert_eq!(session.next_resend_range(), None);
    }

    #[test]
    fn bodylength_leading_zeros_normalize_and_encoded_limit_is_exact() {
        // FIX TagValue Encoding 5.1: BodyLength is derived.
        let bytes = b"8=FIX.4.4\x019=005\x0135=0\x0110=003\x01";
        let parsed = Message::parse(bytes).unwrap();
        assert_eq!(
            parsed.to_bytes().unwrap(),
            b"8=FIX.4.4\x019=5\x0135=0\x0110=163\x01"
        );
        check_wire::<Message>(bytes);
        let mut message = Message::new(Version::Fix44, b"8").unwrap();
        for _ in 0..3 {
            message.push(58, &vec![b'x'; MAX_VALUE_LENGTH]).unwrap();
        }
        // The final BodyLength has seven digits; the fourth field adds four
        // bytes for its tag, equals sign, and delimiter.
        let remaining =
            MAX_MESSAGE_SIZE - message.stored_size - (3 + digits(MAX_MESSAGE_SIZE) + 7) - 4;
        message.push(58, &vec![b'x'; remaining]).unwrap();
        let wire = message.to_bytes().unwrap();
        assert_eq!(wire.len(), MAX_MESSAGE_SIZE);
        check_wire::<Message>(&wire);
        check_wire_value(&message);
        assert_eq!(Message::parse(&wire), Ok(message.clone()));
        assert_eq!(message.push(58, b"x"), Err(Error::Limit));
        let mut frames = Messages::default();
        assert!(matches!(
            frames.decode(&wire, false),
            Ok(Step::Item(_, MAX_MESSAGE_SIZE))
        ));
    }

    // Pumps `bytes` in 64 KiB chunks and finishes. Returns the decoder, the
    // item count, and the work bound MAX_RESYNC_DEBT documents.
    fn pump_bounded(bytes: &[u8]) -> (Messages, usize, u64) {
        let mut stream = Stream::new(Messages::default());
        let mut count = 0;
        for chunk in bytes.chunks(64 * 1024) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let n = stream.push(rest);
                rest = &rest[n..];
                while let Some(item) = stream.next() {
                    assert!(item.is_ok());
                    count += 1;
                }
            }
        }
        // A final incomplete candidate is reported as truncation.
        if let Err(failure) = fictionet::stdlib::codec::finish(&mut stream, |_| count += 1) {
            assert!(matches!(
                failure,
                fictionet::stdlib::codec::Fail::Truncated { .. }
            ));
        }
        let bound = 2 * bytes.len() as u64 + (MAX_RESYNC_DEBT + MAX_MESSAGE_SIZE) as u64;
        (*stream.decoder(), count, bound)
    }

    #[test]
    fn periodic_overlapping_candidates_take_linear_work() {
        // The reviewed input: every 26 bytes a candidate whose BodyLength, a
        // multiple of 26, lands its trailer on a later `10=000`. Its first
        // body field is not MsgType, so the cheap checks refuse it unread.
        let period = b"8=FIX.4.4\x019=988000\x0110=000\x01";
        assert_eq!(period.len(), 26);
        let (frames, count, _) = pump_bounded(&period.repeat(rounds(76_000)));
        assert_eq!((count, frames.examined()), (0, 0));
        // With MsgType first, every candidate passes the cheap checks and
        // fails only its CheckSum, after a fold of about 1 MB.
        let period = b"8=FIX.4.4\x019=988006\x0135=0\x0110=000\x01";
        assert_eq!(period.len(), 31);
        assert_eq!((19 + 988_006 + 7) % 31, 0);
        let bytes = period.repeat(rounds(64_000));
        let (frames, count, bound) = pump_bounded(&bytes);
        assert_eq!(count, 0);
        assert!(frames.garbled() > 0);
        assert!(frames.examined() > 0);
        assert!(
            frames.examined() <= bound,
            "{} > {bound}",
            frames.examined()
        );
    }

    #[test]
    fn overlapping_headers_over_a_shared_region_take_linear_work() {
        // K headers whose raw data jumps to one region of valid fields. The
        // region ends in a late envelope fault, and each candidate ends at its
        // own trailer with a valid CheckSum.
        fn build(k: usize, fields: usize) -> Vec<u8> {
            let header = |body: usize, data: usize| {
                format!("8=FIX.4.4\x019={body:07}\x0135=0\x0195={data:07}\x0196=").into_bytes()
            };
            let width = header(0, 0).len();
            let mut region = vec![SOH];
            for _ in 0..fields {
                region.extend_from_slice(b"1=");
                region.extend_from_slice(&[b'a'; 100]);
                region.push(SOH);
            }
            region.extend_from_slice(b"9=1\x01");
            let headers = k * width;
            let mut bytes = vec![0; headers];
            bytes.extend_from_slice(&region);
            // Candidate i starts at i * width and ends at trailer i.
            let mut ends = Vec::new();
            for i in 0..k {
                let at = bytes.len();
                ends.push(at);
                bytes.extend_from_slice(b"10=000\x01");
                let start = i * width;
                let prefix_len = "8=FIX.4.4\x019=0000000\x01".len();
                let body = at - (start + prefix_len);
                let data = headers - (start + width);
                bytes[start..start + width].copy_from_slice(&header(body, data));
            }
            // Earlier trailers fall inside later candidates, so fill them in order.
            for (i, at) in ends.iter().enumerate() {
                let sum = checksum(&bytes[i * width..*at]);
                bytes[at + 3..at + 6].copy_from_slice(format!("{sum:03}").as_bytes());
            }
            bytes
        }
        let small = build(20, 40);
        // Candidate 0 passes its CheckSum and fails only at the late `9=1`.
        assert_eq!(
            Message::parse(&small[..small.len() - 19 * 7]),
            Err(Error::Header)
        );
        check_decode_with_alloc_limit(Messages::default, &small, 2 * MAX_MESSAGE_SIZE);
        let bytes = build(2000, 4000);
        assert!(bytes.len() <= MAX_MESSAGE_SIZE);
        let (frames, count, bound) = pump_bounded(&bytes);
        assert_eq!(count, 0);
        assert!(
            frames.examined() <= bound,
            "{} > {bound}",
            frames.examined()
        );
        assert!(frames.garbled() <= 2);
    }

    #[test]
    fn candidates_sharing_one_trailer_take_linear_work() {
        // Many headers point at one trailer. Almost all fail their CheckSum.
        let k = 20_000;
        let header = |body: usize| format!("8=FIX.4.4\x019={body:07}\x0135=0\x01").into_bytes();
        let width = header(0).len();
        let filler = b"58=x\x01";
        let trailer_at = k * width + filler.len();
        let prefix_len = "8=FIX.4.4\x019=0000000\x01".len();
        let mut bytes = Vec::new();
        for i in 0..k {
            bytes.extend_from_slice(&header(trailer_at - (i * width + prefix_len)));
        }
        bytes.extend_from_slice(filler);
        bytes.extend_from_slice(b"10=000\x01");
        assert!(bytes.len() <= MAX_MESSAGE_SIZE);
        let (frames, _, bound) = pump_bounded(&bytes);
        assert!(
            frames.examined() <= bound,
            "{} > {bound}",
            frames.examined()
        );
    }

    #[test]
    fn need_leaves_resync_state_unchanged_and_skips_are_never_empty() {
        let mut frames = Messages::default();
        assert_eq!(frames.decode(b"8=X\x01", false), Ok(Step::Need));
        assert_eq!((frames.garbled(), frames.unsupported_versions()), (0, 0));
        assert!(!frames.resync);
        assert_eq!(frames.decode(b"8=X\x01y", false), Ok(Step::Skip(1)));
        assert_eq!((frames.garbled(), frames.unsupported_versions()), (1, 1));
        // A marker kept back by a partial skip is read in place, not skipped by 0.
        let good = b"8=FIX.4.4\x019=5\x0135=0\x0110=163\x01";
        let mut frames = Messages::default();
        assert_eq!(frames.decode(b"x\x01xxx8=FI", false), Ok(Step::Skip(5)));
        assert!(matches!(
            frames.decode(good, false),
            Ok(Step::Item(Ok(_), n)) if n == good.len()
        ));
        assert_eq!(frames.garbled(), 1);
    }

    #[test]
    fn garbled_count_tracks_skips_and_saturates() {
        // FIX 4.4 Vol 2 case 3.b: invalid checksum, not an empty field.
        let bad = b"8=FIX.4.4\x019=5\x0135=0\x0110=164\x01";
        let mut frames = Messages::default();
        assert_eq!(frames.decode(bad, true), Ok(Step::Skip(bad.len())));
        assert_eq!(frames.garbled(), 1);
        let mut frames = Messages {
            garbled: u64::MAX,
            ..Messages::default()
        };
        assert_eq!(frames.decode(bad, true), Ok(Step::Skip(bad.len())));
        assert_eq!(frames.garbled(), u64::MAX);
    }

    #[test]
    fn public_example_and_derived_heartbeat_exact_bytes_and_contracts() {
        for bytes in [LOGON, HEARTBEAT] {
            let message = Message::parse(bytes).unwrap();
            assert_eq!(message.to_bytes().unwrap(), bytes);
            check_wire::<Message>(bytes);
            check_wire_value(&message);
            check_decode_with_alloc_limit(Messages::default, bytes, 2 * MAX_MESSAGE_SIZE);
            for n in 0..bytes.len() {
                assert!(Message::parse(bytes.get(..n).unwrap()).is_err());
            }
        }
        assert_eq!(Message::parse(LOGON).unwrap().get(108), Some(&b"30"[..]));
        let stream = [LOGON, HEARTBEAT].concat();
        let (messages, failure) = decode_all(Messages::default, &stream);
        assert_eq!(failure, None);
        assert_eq!(messages.len(), 2);
        assert_eq!(Message::parse(&stream), Err(Error::Trailing));
        check_decode_with_alloc_limit(Messages::default, &stream, 2 * MAX_MESSAGE_SIZE);
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
            check_decode_with_alloc_limit(Messages::default, &wire, 2 * MAX_MESSAGE_SIZE);
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
            assert!(matches!(
                Messages::default().decode(bytes, false),
                Ok(Step::Skip(_))
            ));
        }
        check_decode_with_alloc_limit(
            Messages::default,
            &[b'x'; MAX_PREFIX_SIZE],
            2 * MAX_MESSAGE_SIZE,
        );
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
            check_decode_with_alloc_limit(Messages::default, &wire, 2 * MAX_MESSAGE_SIZE);
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
        let nested = group_layout(802, 523, &[523, 803], &[]);
        let children = [nested];
        let layout = group_layout(453, 448, &[448, 447, 452, 802], &children);
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
        let invalid = group_layout(453, 448, &[448, 448], &[]);
        assert!(zero.group(2, &invalid).is_err());
    }

    #[test]
    fn nested_count_can_be_the_entry_delimiter_and_cycles_are_bounded() {
        let inner = [group_layout(802, 523, &[523], &[])];
        let outer = group_layout(453, 802, &[802], &inner);
        let mut m = Message::new(Version::Fix44, b"D").unwrap();
        m.push(453, b"1")
            .unwrap()
            .push(802, b"1")
            .unwrap()
            .push(523, b"a")
            .unwrap();
        assert_eq!(m.group(2, &outer).unwrap().entries().len(), 1);
        static CYCLE: GroupLayout<'static> = group_layout(1000, 1001, &[1001], &CYCLE_CHILD);
        static CYCLE_CHILD: [GroupLayout<'static>; 1] =
            [group_layout(1001, 1000, &[1000], &[CYCLE])];
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
            assert_eq!(client.phase(), Phase::Established);
            assert_eq!(client.next_inbound(), 2);
            let app = NewOrderSingle::builder(version).unwrap().finish().unwrap();
            let out = sends(&client.send(&app, 3, TIME).unwrap()).remove(0);
            let events = server.receive(&out, 4, TIME).unwrap();
            assert!(has_event(&events, event_application(2, false)));
            let logout = sends(&client.logout(b"done", 5, TIME).unwrap()).remove(0);
            let actions = server.receive(&logout, 6, TIME).unwrap();
            assert_eq!(server.phase(), Phase::LogoutReceived);
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
        assert_eq!(
            sends(&s.receive(&high, 2, TIME).unwrap())[0].get(7),
            Some(b"2".as_slice())
        );
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
        assert!(has_event(&actions, event_application(4, true)));
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
        assert!(has_event(&events, event_rejected(2, Some(122), 1)));
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
            event_rejected(3, Some(122), 10)
        ));
        let low = inbound(Version::Fix44, b"0", 1, &[]);
        let events = s.receive(&low, 4, TIME).unwrap();
        assert!(has_event(
            &events,
            Event::Disconnected(CloseReason::SequenceTooLow)
        ));
        checked(&events);
        assert_eq!(s.phase(), Phase::Closed);
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
        assert!(has_event(&events, event_rejected(999, Some(36), 5)));
        assert_eq!(s.phase(), Phase::Established);
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
            event_resend(1, 2)
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
        assert!(has_event(&events, event_resend(1, MAX_RESEND_RANGE)));
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
    fn fixt_writer_orders_application_version_but_reader_accepts_other_positions() {
        let mut s = established(Version::Fixt11);
        let mut body = Message::new(Version::Fixt11, b"D").unwrap();
        body.push(11, b"order").unwrap().push(1128, b"4").unwrap();
        let outbound = sends(&s.send(&body, 1, TIME).unwrap()).remove(0);
        assert_eq!(outbound.fields().get(4).unwrap().tag(), 1128);
        let replay = sends(&s.replay(&outbound, 2, LATER).unwrap()).remove(0);
        assert_eq!(replay.fields().get(4).unwrap().tag(), 1128);
        let reordered = inbound(Version::Fixt11, b"D", 2, &[(1128, b"4")]);
        assert!(has_event(
            &s.receive(&reordered, 3, TIME).unwrap(),
            event_application(2, false)
        ));
    }

    #[test]
    fn group_validation_and_explicit_test_requests_are_transactional() {
        let layout = group_layout(384, 372, &[372, 385], &[]);
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
        let capture = |s: &Session| (s.next_inbound(), s.next_outbound(), s.last_now);
        assert!(check_atomic(&mut s, |s| s.tick(9, TIME), capture).is_err());
        assert!(check_atomic(&mut s, |s| s.tick(11, b"20260230-12:00:00"), capture).is_err());
        assert!(check_atomic(&mut s, |s| s.gap_fill(0, 1, TIME, 11, TIME), capture).is_err());
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
        let mut stream = Stream::new(Messages::default());
        for b in &bytes {
            assert_eq!(stream.push(&[*b]), 1);
            if let Some(item) = stream.next() {
                assert_eq!(item.unwrap(), Ok(message.clone()));
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
            check_decode_with_alloc_limit(Messages::default, &bytes, 2 * MAX_MESSAGE_SIZE);
        }
    }
}
