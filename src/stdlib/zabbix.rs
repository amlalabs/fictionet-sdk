//! The Zabbix protocol: reading and writing packets and the JSON messages
//! agents, senders and servers exchange, with no I/O.
//!
//! Zabbix monitors servers and network gear. An agent on each host answers
//! the server's questions on TCP port 10050, and agents in active mode,
//! along with tools like `zabbix_sender`, push values to the server on
//! port 10051. Each message goes in a packet: the four bytes `ZBXD`, a
//! flags byte, then the data length and a reserved length, little-endian.
//! The lengths take 4 bytes each, or 8 each when the large packet flag is
//! set. When the compression flag is set the data is zlib-compressed and
//! the reserved length is its size before compression. This module follows
//! the "Header and data length" and "Protocols" sections of the Zabbix
//! manual.
//!
//! Nothing here reads a socket. A world that plays a Zabbix server
//! passes the bytes a [`tcp`](crate::stdlib::tcp) connection reads to a
//! [`Stream<Frames>`](super::codec::Stream), gets [`Packet`]s back,
//! reads each one's [`Message`], and writes the reply's bytes back to
//! the connection. Compressed data is reported with
//! [`Packet::is_compressed`] and left as it came; it is not
//! decompressed. A message keeps its JSON text as it was sent and names
//! only its kind, so world code reads the rest with whatever JSON reader it
//! likes.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A decoder takes a size limit and refuses a packet whose data
//! would pass it, before the data comes.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
//! use fictionet::stdlib::zabbix::{Frames, Kind, Message};
//!
//! // What zabbix_sender sends for one value.
//! let json = br#"{"request":"sender data","data":[{"host":"web1","key":"cpu","value":"0.5"}]}"#;
//! let mut sent = b"ZBXD\x01".to_vec();
//! sent.extend_from_slice(&(json.len() as u32).to_le_bytes());
//! sent.extend_from_slice(&[0, 0, 0, 0]);
//! sent.extend_from_slice(json);
//!
//! let mut stream = Stream::new(Frames::new());
//! let mut packets = Vec::new();
//! pump(&mut stream, &sent, |packet| packets.push(packet)).unwrap();
//! finish(&mut stream, |_| unreachable!()).unwrap();
//! let packet = packets.pop().unwrap();
//! assert!(!packet.is_compressed());
//! let message = Message::parse(&packet.data).unwrap();
//! assert_eq!(message.kind(), &Kind::SenderData);
//! assert_eq!(message.json().as_bytes(), json);
//!
//! let reply = Message::response(true, Some("processed: 1; failed: 0; total: 1")).unwrap();
//! let bytes = reply.to_packet().to_bytes().unwrap();
//! assert_eq!(&bytes[..5], b"ZBXD\x01");
//! assert_eq!(&bytes[13..], br#"{"response":"success","info":"processed: 1; failed: 0; total: 1"}"#);
//! ```

extern crate alloc;

use super::codec::{Decode, Step, Wire};
use alloc::{format, string::{String, ToString}, vec::Vec};

/// The TCP port a Zabbix agent listens on for the server's questions.
pub const AGENT_PORT: u16 = 10050;
/// The TCP port a Zabbix server or proxy listens on for pushed data.
pub const SERVER_PORT: u16 = 10051;
/// The four bytes every packet starts with.
pub const MAGIC: [u8; 4] = *b"ZBXD";
/// The header's length when its lengths take 4 bytes each.
pub const HEADER_LEN: usize = 13;
/// The header's length when the large packet flag is set and its lengths
/// take 8 bytes each.
pub const LARGE_HEADER_LEN: usize = 21;
/// The most data one packet may carry: 1 GiB, the limit Zabbix itself
/// sets on what it receives.
pub const MAX_DATA: usize = 1 << 30;
/// The size limit used by [`Frames::new`].
pub const DEFAULT_LIMIT: usize = 16 << 20;
/// How deeply arrays and objects may nest in a message's JSON.
pub const MAX_DEPTH: usize = 64;

/// The bits of the header's flags byte.
pub mod flags {
    /// Set on every packet: this is the Zabbix communications protocol.
    pub const PROTOCOL: u8 = 0x01;
    /// The data is zlib-compressed.
    pub const COMPRESSED: u8 = 0x02;
    /// The lengths take 8 bytes each instead of 4.
    pub const LARGE: u8 = 0x04;
    /// Every bit this module knows.
    pub const KNOWN: u8 = PROTOCOL | COMPRESSED | LARGE;
}

/// Why bytes are not a Zabbix packet. Whatever the reason, the connection holds no
/// more packets a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The packet did not start with `ZBXD`.
    Magic,
    /// The flags byte lacked the protocol bit, or had a bit this module
    /// does not know.
    Flags(u8),
    /// The data length was over the size limit.
    TooLarge {
        /// The data length the header gave.
        len: u64,
        /// The limit it passed.
        limit: usize,
    },
    /// The reserved length was over the size limit. Zabbix checks it
    /// whether or not the data is compressed.
    ReservedTooLarge {
        /// The reserved length the header gave.
        len: u64,
        /// The limit it passed.
        limit: usize,
    },
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketError::Unwritable => f.write_str("value cannot be written without changing it"),
            PacketError::Magic => f.write_str("packet does not start with ZBXD"),
            PacketError::Flags(b) => write!(f, "flags byte {b:#04x} is not a Zabbix protocol packet"),
            PacketError::TooLarge { len, limit } => write!(f, "data length {len} is over the limit of {limit}"),
            PacketError::ReservedTooLarge { len, limit } => {
                write!(f, "reserved length {len} is over the limit of {limit}")
            }
        }
    }
}

impl core::error::Error for PacketError {}

/// A packet header: the flags and the two lengths that follow `ZBXD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The flags byte; see [`flags`].
    pub flags: u8,
    /// How many bytes of data follow the header.
    pub data_len: u64,
    /// The data's size before compression when it is compressed, and
    /// usually 0 when it is not.
    pub reserved: u64,
}

impl Header {
    /// Reads the header at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the header and its length.
    /// A wrong magic or flags byte is reported as soon as it comes. The
    /// lengths are not checked against any limit here.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Header, usize)>, PacketError> {
        let n = b.len().min(MAGIC.len());
        if b[..n] != MAGIC[..n] {
            return Err(PacketError::Magic);
        }
        let Some(&flag_byte) = b.get(4) else {
            return Ok(None);
        };
        if flag_byte & flags::PROTOCOL == 0 || flag_byte & !flags::KNOWN != 0 {
            return Err(PacketError::Flags(flag_byte));
        }
        let large = flag_byte & flags::LARGE != 0;
        let (len, width) = if large { (LARGE_HEADER_LEN, 8) } else { (HEADER_LEN, 4) };
        if b.len() < len {
            return Ok(None);
        }
        let data_len = le(&b[5..5 + width]);
        let reserved = le(&b[5 + width..len]);
        Ok(Some((Header { flags: flag_byte, data_len, reserved }, len)))
    }
}

impl Wire for Header {
    type ParseError = PacketParseError;
    type WriteError = PacketError;

    /// Reads exactly one header. Refuses wrong magic, invalid flags,
    /// incomplete input, and trailing bytes. Lengths have no size limit here.
    fn parse(b: &[u8]) -> Result<Self, PacketParseError> {
        match Self::parse_prefix(b).map_err(PacketParseError::Packet)? {
            Some((header, used)) if used == b.len() => Ok(header),
            Some(_) => Err(PacketParseError::Trailing),
            None => Err(PacketParseError::Truncated),
        }
    }

    /// Appends the header. Refuses invalid flags and lengths that need
    /// the large flag when it is absent, without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), PacketError> {
        if self.flags & flags::PROTOCOL == 0 || self.flags & !flags::KNOWN != 0
            || (self.flags & flags::LARGE == 0
                && (self.data_len > u64::from(u32::MAX) || self.reserved > u64::from(u32::MAX)))
        {
            return Err(PacketError::Unwritable);
        }
        out.extend_from_slice(&MAGIC);
        out.push(self.flags);
        if self.flags & flags::LARGE != 0 {
            out.extend_from_slice(&self.data_len.to_le_bytes());
            out.extend_from_slice(&self.reserved.to_le_bytes());
        } else {
            out.extend_from_slice(&(self.data_len as u32).to_le_bytes());
            out.extend_from_slice(&(self.reserved as u32).to_le_bytes());
        }
        Ok(())
    }
}

fn le(b: &[u8]) -> u64 {
    b.iter().rev().fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
}

/// One Zabbix packet: the header's flags and reserved length, and the data.
/// The data length is worked out from the data, so it is not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The flags byte; see [`flags`].
    pub flags: u8,
    /// The reserved length: the data's size before compression when it is
    /// compressed.
    pub reserved: u64,
    /// The data as it came, still compressed if it was.
    pub data: Vec<u8>,
}

impl Packet {
    /// A packet of uncompressed data with a 4-byte-length header.
    pub fn new(data: Vec<u8>) -> Packet {
        Packet { flags: flags::PROTOCOL, reserved: 0, data }
    }

    /// Reads one packet prefix with data up to `limit` bytes. A limit over
    /// [`MAX_DATA`] counts as [`MAX_DATA`]. The reserved length must be
    /// within the limit too, as Zabbix requires, since it is the size the
    /// data will have once decompressed.
    fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, PacketError> {
        let limit = limit.min(MAX_DATA);
        let Some((header, used)) = Header::parse_prefix(b)? else {
            return Ok(None);
        };
        let len = match usize::try_from(header.data_len) {
            Ok(n) if n <= limit => n,
            _ => return Err(PacketError::TooLarge { len: header.data_len, limit }),
        };
        if !usize::try_from(header.reserved).is_ok_and(|n| n <= limit) {
            return Err(PacketError::ReservedTooLarge { len: header.reserved, limit });
        }
        let Some(end) = used.checked_add(len) else {
            return Err(PacketError::TooLarge { len: header.data_len, limit });
        };
        let Some(data) = b.get(used..end) else {
            return Ok(None);
        };
        Ok(Some((Packet { flags: header.flags, reserved: header.reserved, data: data.to_vec() }, end)))
    }

    /// Whether the data is zlib-compressed. This module does not
    /// decompress it.
    pub fn is_compressed(&self) -> bool {
        self.flags & flags::COMPRESSED != 0
    }

    /// Whether the header's lengths take 8 bytes each.
    pub fn is_large(&self) -> bool {
        self.flags & flags::LARGE != 0
    }

    /// The data's size before compression, as the sender gave it, if the
    /// data is compressed.
    pub fn uncompressed_len(&self) -> Option<u64> {
        self.is_compressed().then_some(self.reserved)
    }
}

/// Why an exact [`Wire`] parse did not read one complete Zabbix packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketParseError {
    /// The packet header is invalid.
    Packet(PacketError),
    /// The input ended before a complete packet, including empty input.
    Truncated,
    /// Bytes follow the first complete packet.
    Trailing,
}

impl core::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Packet(e) => e.fmt(f),
            Self::Truncated => f.write_str("input ended before a complete Zabbix packet"),
            Self::Trailing => f.write_str("bytes follow the Zabbix packet"),
        }
    }
}

impl core::error::Error for PacketParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Packet(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

impl Wire for Packet {
    type ParseError = PacketParseError;
    type WriteError = PacketError;

    /// Reads exactly one packet. Refuses wrong magic, invalid flags,
    /// lengths over [`MAX_DATA`], incomplete input, and trailing bytes.
    /// The reserved length is checked even for uncompressed data.
    fn parse(b: &[u8]) -> Result<Self, PacketParseError> {
        match Self::parse_limited(b, MAX_DATA).map_err(PacketParseError::Packet)? {
            Some((packet, used)) if used == b.len() => Ok(packet),
            Some(_) => Err(PacketParseError::Trailing),
            None => Err(PacketParseError::Truncated),
        }
    }

    /// Appends the header and data. Refuses invalid flags and data or
    /// reserved lengths over [`MAX_DATA`] without changing `out`.
    /// Compressed bytes remain unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), PacketError> {
        if self.data.len() > MAX_DATA || self.reserved > MAX_DATA as u64 {
            return Err(PacketError::Unwritable);
        }
        let header = Header { flags: self.flags, data_len: self.data.len() as u64, reserved: self.reserved };
        header.write(out)?;
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Reads Zabbix packets without holding input bytes.
///
/// Use with [`super::codec::Stream`] for input bounded by [`LARGE_HEADER_LEN`]
/// plus [`Self::limit`]. Partial packets return [`Step::Need`], including at
/// EOF. The stream reports truncation at EOF and framing errors once.
/// Compressed payloads remain bytes. Body parsing stays separate.
/// [`Wire`] accepts data up to [`MAX_DATA`], but [`Frames::new`] refuses data
/// over [`DEFAULT_LIMIT`]; use [`Frames::with_limit`] for larger packets.
///
/// ```
/// use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
/// use fictionet::stdlib::zabbix::{Frames, Packet};
///
/// let packet = Packet::new(b"hello".to_vec());
/// let bytes = Wire::to_bytes(&packet)?;
/// let mut stream = Stream::new(Frames::with_limit(16));
/// let mut packets = Vec::new();
/// pump(&mut stream, &bytes[..3], |packet| packets.push(packet))?;
/// pump(&mut stream, &bytes[3..], |packet| packets.push(packet))?;
/// finish(&mut stream, |packet| packets.push(packet))?;
/// assert_eq!(packets, [packet]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Accepts packets with data and reserved lengths up to [`DEFAULT_LIMIT`].
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_LIMIT)
    }

    /// Sets the data and reserved length limit, clamped to [`MAX_DATA`].
    /// Zero accepts only empty data and a zero reserved length. Oversized
    /// lengths are refused from the header, before the data arrives.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_DATA) }
    }

    /// The maximum data and reserved length, excluding the header.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Frames {
    type Item = Packet;
    type Error = PacketError;
    const NAME: &'static str = "Zabbix";

    fn capacity(&self) -> usize {
        LARGE_HEADER_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, PacketError> {
        Ok(match Packet::parse_limited(input, self.limit)? {
            Some((packet, used)) => Step::Item(packet, used),
            None => Step::Need,
        })
    }
}

/// What a JSON message is, from its top-level `request` or `response`
/// member.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `"request":"active checks"`: an active agent asks which items to
    /// collect.
    ActiveChecks,
    /// `"request":"agent data"`: an active agent sends the values it
    /// collected.
    AgentData,
    /// `"request":"sender data"`: `zabbix_sender` or a similar tool sends
    /// values for trapper items.
    SenderData,
    /// Any other request, with its name.
    OtherRequest(String),
    /// A reply, with its `response` member, usually `success` or `failed`.
    Response(String),
}

/// Why bytes are not a Zabbix JSON message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// The bytes are not UTF-8.
    Utf8,
    /// The JSON is malformed at this byte offset.
    Syntax(usize),
    /// Arrays and objects nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The JSON is not an object.
    NotObject,
    /// The object has no string `request` or `response` member.
    NoKind,
    /// The JSON would be longer than [`MAX_DATA`] bytes.
    TooLong,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MessageError::Utf8 => f.write_str("message is not UTF-8"),
            MessageError::Syntax(at) => write!(f, "malformed JSON at byte {at}"),
            MessageError::TooDeep => write!(f, "JSON nests deeper than {MAX_DEPTH}"),
            MessageError::NotObject => f.write_str("JSON is not an object"),
            MessageError::NoKind => f.write_str("JSON object has no request or response member"),
            MessageError::TooLong => write!(f, "JSON is longer than {MAX_DATA} bytes"),
        }
    }
}

impl core::error::Error for MessageError {}

/// One value `zabbix_sender` sends: which host and item it is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderValue {
    /// The host's name as the server knows it.
    pub host: String,
    /// The item key.
    pub key: String,
    /// The value, as text.
    pub value: String,
}

/// One value an active agent sends, with its place in the agent's buffer
/// and when it was collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentValue {
    /// The host's name as the server knows it.
    pub host: String,
    /// The item key.
    pub key: String,
    /// The value, as text.
    pub value: String,
    /// The value's number, counting up within a session, so the server
    /// can drop values it has already seen.
    pub id: u64,
    /// When it was collected, in seconds since the Unix epoch.
    pub clock: u64,
    /// The nanoseconds past `clock`.
    pub ns: u32,
}

/// A Zabbix JSON message: its kind and its JSON text as it was sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    kind: Kind,
    json: String,
}

impl Wire for Message {
    type ParseError = MessageError;
    type WriteError = core::convert::Infallible;

    /// Reads a message from a packet's uncompressed data. The JSON must be
    /// well formed, be an object, and have a string `request` or
    /// `response` member at the top level. If it has both, `request`
    /// decides the kind. If a member appears twice, the first one counts,
    /// and if that one is not a string it names no kind.
    /// Refuses invalid UTF-8, invalid JSON, excess depth or length, and a missing kind.
    fn parse(data: &[u8]) -> Result<Message, MessageError> {
        if data.len() > MAX_DATA {
            return Err(MessageError::TooLong);
        }
        let json = core::str::from_utf8(data).map_err(|_| MessageError::Utf8)?;
        let (request, response) = scan(json.as_bytes())?;
        let kind = match (request, response) {
            (Some(r), _) => match r.as_str() {
                "active checks" => Kind::ActiveChecks,
                "agent data" => Kind::AgentData,
                "sender data" => Kind::SenderData,
                _ => Kind::OtherRequest(r),
            },
            (None, Some(r)) => Kind::Response(r),
            (None, None) => return Err(MessageError::NoKind),
        };
        Ok(Message { kind, json: json.to_string() })
    }

    /// Appends the original JSON text. Refuses no constructed values.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(self.json.as_bytes());
        Ok(())
    }
}

impl Message {
    /// What the message is.
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// The JSON text, as it was sent or written.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// The JSON text, taken out of the message without a copy.
    pub fn into_json(self) -> String {
        self.json
    }

    /// The message in a packet of uncompressed data.
    pub fn to_packet(&self) -> Packet {
        Packet::new(self.json.as_bytes().to_vec())
    }

    /// An active agent's request for the items to collect for `host`.
    pub fn active_checks(host: &str) -> Result<Message, MessageError> {
        let mut j = String::from(r#"{"request":"active checks","host":"#);
        push_str(&mut j, host)?;
        j.push('}');
        Message::finish(Kind::ActiveChecks, j)
    }

    /// A sender's values for trapper items.
    pub fn sender_data(values: &[SenderValue]) -> Result<Message, MessageError> {
        let mut j = String::from(r#"{"request":"sender data","data":["#);
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                j.push(',');
            }
            j.push_str(r#"{"host":"#);
            push_str(&mut j, &v.host)?;
            j.push_str(r#","key":"#);
            push_str(&mut j, &v.key)?;
            j.push_str(r#","value":"#);
            push_str(&mut j, &v.value)?;
            j.push('}');
            if j.len() > MAX_DATA {
                return Err(MessageError::TooLong);
            }
        }
        j.push_str("]}");
        Message::finish(Kind::SenderData, j)
    }

    /// An active agent's collected values, in session `session`, sent at
    /// `clock` seconds and `ns` nanoseconds. The caller gives the time,
    /// since this module reads no clock.
    pub fn agent_data(session: &str, values: &[AgentValue], clock: u64, ns: u32) -> Result<Message, MessageError> {
        let mut j = String::from(r#"{"request":"agent data","session":"#);
        push_str(&mut j, session)?;
        j.push_str(r#","data":["#);
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                j.push(',');
            }
            j.push_str(r#"{"host":"#);
            push_str(&mut j, &v.host)?;
            j.push_str(r#","key":"#);
            push_str(&mut j, &v.key)?;
            j.push_str(r#","value":"#);
            push_str(&mut j, &v.value)?;
            j.push_str(&format!(r#","id":{},"clock":{},"ns":{}}}"#, v.id, v.clock, v.ns));
            if j.len() > MAX_DATA {
                return Err(MessageError::TooLong);
            }
        }
        j.push_str(&format!(r#"],"clock":{clock},"ns":{ns}}}"#));
        Message::finish(Kind::AgentData, j)
    }

    /// A server's reply: `success` or `failed`, with an optional `info`
    /// text such as `processed: 1; failed: 0; total: 1`.
    pub fn response(success: bool, info: Option<&str>) -> Result<Message, MessageError> {
        let word = if success { "success" } else { "failed" };
        let mut j = format!(r#"{{"response":"{word}""#);
        if let Some(info) = info {
            j.push_str(r#","info":"#);
            push_str(&mut j, info)?;
        }
        j.push('}');
        Message::finish(Kind::Response(word.to_string()), j)
    }

    fn finish(kind: Kind, json: String) -> Result<Message, MessageError> {
        if json.len() > MAX_DATA {
            return Err(MessageError::TooLong);
        }
        Ok(Message { kind, json })
    }
}

/// Appends `s` as a JSON string, quoted and escaped.
fn push_str(out: &mut String, s: &str) -> Result<(), MessageError> {
    let length = s.chars().try_fold(2usize, |n, c| {
        n.checked_add(match c {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
    }).and_then(|n| out.len().checked_add(n));
    if length.is_none_or(|n| n > MAX_DATA) {
        return Err(MessageError::TooLong);
    }
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(())
}

/// Checks that `b` is one JSON value, and an object, and returns the
/// values of its first top-level `request` and `response` members, each
/// only if it is a string. It loops instead of
/// recursing, with a stack no deeper than [`MAX_DEPTH`].
fn scan(b: &[u8]) -> Result<(Option<String>, Option<String>), MessageError> {
    let mut s = Scanner { b, i: 0 };
    s.ws();
    // Any well-formed JSON value is read to the end first, so text that is
    // not JSON at all is a syntax error rather than "not an object".
    let object = s.peek() == Some(b'{');
    let mut request = None;
    let mut response = None;
    // true for an object, false for an array.
    let mut stack: Vec<bool> = Vec::new();
    // The top-level key whose value comes next, if it is the first
    // `request` or `response` member.
    let mut pending: Option<String> = None;
    // Whether a top-level `request` and `response` member have come yet.
    let mut seen = [false; 2];
    'value: loop {
        // A value is expected.
        s.ws();
        let at = s.i;
        match s.peek() {
            Some(b'{') => {
                s.i += 1;
                pending = None;
                if stack.len() >= MAX_DEPTH {
                    return Err(MessageError::TooDeep);
                }
                stack.push(true);
                s.ws();
                if s.peek() == Some(b'}') {
                    s.i += 1;
                    stack.pop();
                } else {
                    let key = s.key()?;
                    if stack.len() == 1 {
                        pending = claim(key, &mut seen);
                    }
                    continue 'value;
                }
            }
            Some(b'[') => {
                s.i += 1;
                pending = None;
                if stack.len() >= MAX_DEPTH {
                    return Err(MessageError::TooDeep);
                }
                stack.push(false);
                s.ws();
                if s.peek() == Some(b']') {
                    s.i += 1;
                    stack.pop();
                } else {
                    continue 'value;
                }
            }
            Some(b'"') => {
                let v = s.string()?;
                match pending.take().as_deref() {
                    Some("request") => request = Some(v),
                    Some("response") => response = Some(v),
                    _ => {}
                }
            }
            Some(b'-' | b'0'..=b'9') => {
                pending = None;
                s.number()?;
            }
            Some(b't') => {
                pending = None;
                s.literal(b"true")?;
            }
            Some(b'f') => {
                pending = None;
                s.literal(b"false")?;
            }
            Some(b'n') => {
                pending = None;
                s.literal(b"null")?;
            }
            _ => return Err(MessageError::Syntax(at)),
        }
        // A value ended.
        loop {
            s.ws();
            let Some(&top) = stack.last() else {
                // The top-level object ended.
                return if s.i != b.len() {
                    Err(MessageError::Syntax(s.i))
                } else if !object {
                    Err(MessageError::NotObject)
                } else {
                    Ok((request, response))
                };
            };
            match s.peek() {
                Some(b',') => {
                    s.i += 1;
                    if top {
                        s.ws();
                        let key = s.key()?;
                        if stack.len() == 1 {
                            pending = claim(key, &mut seen);
                        }
                    }
                    continue 'value;
                }
                Some(b'}') if top => {
                    s.i += 1;
                    stack.pop();
                }
                Some(b']') if !top => {
                    s.i += 1;
                    stack.pop();
                }
                _ => return Err(MessageError::Syntax(s.i)),
            }
        }
    }
}

/// Keeps a top-level key only if it is the first `request` or the first
/// `response` member, so a later one never stands in for an earlier one.
fn claim(key: String, seen: &mut [bool; 2]) -> Option<String> {
    let slot = match key.as_str() {
        "request" => &mut seen[0],
        "response" => &mut seen[1],
        _ => return None,
    };
    if core::mem::replace(slot, true) { None } else { Some(key) }
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// An object key, then the colon after it.
    fn key(&mut self) -> Result<String, MessageError> {
        if self.peek() != Some(b'"') {
            return Err(MessageError::Syntax(self.i));
        }
        let key = self.string()?;
        self.ws();
        if self.peek() != Some(b':') {
            return Err(MessageError::Syntax(self.i));
        }
        self.i += 1;
        Ok(key)
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), MessageError> {
        if self.b.get(self.i..).is_some_and(|rest| rest.starts_with(word)) {
            self.i += word.len();
            Ok(())
        } else {
            Err(MessageError::Syntax(self.i))
        }
    }

    fn digits(&mut self) -> usize {
        let from = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - from
    }

    fn number(&mut self) -> Result<(), MessageError> {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(MessageError::Syntax(self.i)),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(MessageError::Syntax(self.i));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(MessageError::Syntax(self.i));
            }
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, MessageError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = match self.peek() {
                Some(c @ b'0'..=b'9') => c - b'0',
                Some(c @ b'a'..=b'f') => c - b'a' + 10,
                Some(c @ b'A'..=b'F') => c - b'A' + 10,
                _ => return Err(MessageError::Syntax(self.i)),
            };
            v = (v << 4) | u32::from(d);
            self.i += 1;
        }
        Ok(v)
    }

    /// A string starting at the opening quote, decoded. The input is
    /// already known to be UTF-8, so bytes copied whole stay UTF-8.
    fn string(&mut self) -> Result<String, MessageError> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let at = self.i;
            let Some(c) = self.peek() else {
                return Err(MessageError::Syntax(at));
            };
            self.i += 1;
            match c {
                b'"' => break,
                0..=0x1f => return Err(MessageError::Syntax(at)),
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(MessageError::Syntax(self.i));
                    };
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&hi) {
                                if self.peek() != Some(b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                                    return Err(MessageError::Syntax(self.i));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(MessageError::Syntax(self.i));
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            match char::from_u32(code) {
                                Some(ch) => ch,
                                None => return Err(MessageError::Syntax(self.i)),
                            }
                        }
                        _ => return Err(MessageError::Syntax(self.i - 1)),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| MessageError::Utf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Fail, Stream, contract, pump, finish, test_support::{Lcg, mutate, decode_all}};

    fn packet_bytes(flags: u8, data: &[u8], reserved: u32) -> Vec<u8> {
        let mut v = b"ZBXD".to_vec();
        v.push(flags);
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&reserved.to_le_bytes());
        v.extend_from_slice(data);
        v
    }

    // The manual's Python example builds a packet as
    // b"ZBXD\1" + struct.pack("<II", len(data), 0) + data.
    #[test]
    fn header_example() {
        let data = b"agent.ping";
        let bytes = packet_bytes(1, data, 0);
        assert_eq!(&bytes[..13], b"ZBXD\x01\x0a\x00\x00\x00\x00\x00\x00\x00");
        let p = Packet::parse(&bytes).unwrap();

        assert_eq!(p, Packet::new(data.to_vec()));
        assert_eq!(p.to_bytes().unwrap(), bytes);
        assert!(!p.is_compressed());
        assert!(!p.is_large());
        assert_eq!(p.uncompressed_len(), None);
    }

    #[test]
    fn compressed_and_large_headers() {
        // Compressed: the reserved length is the size before compression.
        let bytes = packet_bytes(0x03, &[0x78, 0x9c, 1, 2], 100);
        let p = Packet::parse(&bytes).unwrap();
        assert!(p.is_compressed());
        assert_eq!(p.uncompressed_len(), Some(100));
        assert_eq!(p.data, [0x78, 0x9c, 1, 2]);
        assert_eq!(p.to_bytes().unwrap(), bytes);

        // Large: 8-byte lengths.
        let mut big = b"ZBXD\x05".to_vec();
        big.extend_from_slice(&3u64.to_le_bytes());
        big.extend_from_slice(&0u64.to_le_bytes());
        big.extend_from_slice(b"abc");
        let h = Header::parse(&big[..LARGE_HEADER_LEN]).unwrap();
        assert_eq!(h, Header { flags: 5, data_len: 3, reserved: 0 });
        let p = Packet::parse(&big).unwrap();

        assert!(p.is_large());
        assert_eq!(p.to_bytes().unwrap(), big);

        // Large lengths require an explicit large flag.
        let h = Header { flags: 0x03, data_len: 1, reserved: 1 << 40 };
        contract::check_wire_value(&h);
        assert_eq!(h.to_bytes(), Err(PacketError::Unwritable));
        let h = Header { flags: 0x07, ..h };
        contract::check_wire_value(&h);
        assert_eq!(Header::parse(&h.to_bytes().unwrap()), Ok(h));
        let p = Packet { flags: 0xf8, reserved: 0, data: vec![] };
        contract::check_wire_value(&p);
        assert_eq!(p.to_bytes(), Err(PacketError::Unwritable));
    }

    #[test]
    fn packet_errors() {
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"ZBXE", false), Err(PacketError::Magic));
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"X", false), Err(PacketError::Magic));
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"HTTP/1.1", false), Err(PacketError::Magic));
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"ZBXD\x00", false), Err(PacketError::Flags(0)));
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"ZBXD\x02", false), Err(PacketError::Flags(2)));
        assert_eq!(Frames::with_limit(MAX_DATA).decode(b"ZBXD\x09", false), Err(PacketError::Flags(9)));
        let bytes = packet_bytes(1, b"hello", 0);
        assert_eq!(Frames::with_limit(4).decode(&bytes, false), Err(PacketError::TooLarge { len: 5, limit: 4 }));
        assert!(matches!(Frames::with_limit(5).decode(&bytes, false).unwrap(), Step::Item(_, _)));
        // Over the limit is known from the header alone.
        assert_eq!(Frames::with_limit(4).decode(&bytes[..13], false), Err(PacketError::TooLarge { len: 5, limit: 4 }));
        let mut huge = b"ZBXD\x05".to_vec();
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        huge.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(Frames::with_limit(MAX_DATA).decode(&huge, false), Err(PacketError::TooLarge { len: u64::MAX, limit: MAX_DATA }));
        // A limit over MAX_DATA counts as MAX_DATA.
        assert_eq!(Frames::with_limit(usize::MAX).limit(), MAX_DATA);
        for e in [PacketError::Magic, PacketError::Flags(0), PacketError::TooLarge { len: 1, limit: 0 }] {
            assert!(!e.to_string().is_empty());
        }
    }

    // Zabbix checks the reserved length against its maximum too, whether
    // or not the data is compressed.
    #[test]
    fn reserved_length_is_checked_against_the_limit() {
        let bytes = packet_bytes(3, &[0x78, 0x9c], 100);
        assert_eq!(Frames::with_limit(99).decode(&bytes, false), Err(PacketError::ReservedTooLarge { len: 100, limit: 99 }));
        assert!(matches!(Frames::with_limit(100).decode(&bytes, false).unwrap(), Step::Item(_, _)));
        // Known from the header alone.
        assert_eq!(Frames::with_limit(99).decode(&bytes[..13], false), Err(PacketError::ReservedTooLarge { len: 100, limit: 99 }));
        let plain = packet_bytes(1, b"x", 5);
        assert_eq!(Frames::with_limit(4).decode(&plain, false), Err(PacketError::ReservedTooLarge { len: 5, limit: 4 }));
        let mut d = Stream::new(Frames::with_limit(10));
        assert_eq!(d.push(&packet_bytes(3, &[1], 11)[..13]), 13);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(PacketError::ReservedTooLarge { len: 11, limit: 10 }))));
        assert!(d.next().is_none());
        let p = Packet { flags: 0x03, reserved: 1 << 40, data: vec![1] };
        contract::check_wire_value(&p);
        assert_eq!(p.to_bytes(), Err(PacketError::Unwritable));
        assert!(!PacketError::ReservedTooLarge { len: 1, limit: 0 }.to_string().is_empty());
    }

    // Text that is not JSON at all is a syntax error, not "not an object".
    #[test]
    fn malformed_json_is_a_syntax_error() {
        use MessageError::*;
        assert_eq!(Message::parse(b"abc"), Err(Syntax(0)));
        assert_eq!(Message::parse(b"agent.ping"), Err(Syntax(0)));
        assert_eq!(Message::parse(b"[1,"), Err(Syntax(3)));
        assert_eq!(Message::parse(b"\"abc"), Err(Syntax(4)));
        assert_eq!(Message::parse(b"[1] x"), Err(Syntax(4)));
        assert_eq!(Message::parse(b" [1] "), Err(NotObject));
        assert_eq!(Message::parse(b"12"), Err(NotObject));
        assert_eq!(Message::parse(b"null"), Err(NotObject));
    }

    // Parse says the first of a repeated member counts. A later string
    // must not stand in for a first one that is not a string.
    #[test]
    fn first_member_counts_even_when_not_a_string() {
        use MessageError::*;
        assert_eq!(Message::parse(br#"{"request":1,"request":"x"}"#), Err(NoKind));
        assert_eq!(Message::parse(br#"{"response":null,"response":"success"}"#), Err(NoKind));
        let m = Message::parse(br#"{"request":[],"response":"failed","request":"active checks"}"#).unwrap();
        assert_eq!(m.kind(), &Kind::Response("failed".into()));
        let m = Message::parse(br#"{"request":{"a":"b"},"request":"x","response":"success"}"#).unwrap();
        assert_eq!(m.kind(), &Kind::Response("success".into()));
    }

    #[test]
    fn every_truncated_prefix_needs_more() {
        let mut large = b"ZBXD\x07".to_vec();
        large.extend_from_slice(&4u64.to_le_bytes());
        large.extend_from_slice(&9u64.to_le_bytes());
        large.extend_from_slice(b"wxyz");
        for bytes in [packet_bytes(1, b"{\"request\":\"active checks\",\"host\":\"a\"}", 0), large] {
            for n in 0..bytes.len() {
                assert_eq!(Frames::new().decode(&bytes[..n], false), Ok(Step::Need), "{n} bytes");
                assert_eq!(Packet::parse(&bytes[..n]), Err(PacketParseError::Truncated));
            }
            assert!(Packet::parse(&bytes).is_ok());
        }
        let json = br#"{"request":"agent data","data":[{"a":[1.5e3,true,null,"\u00e9"]}]}"#;
        assert!(Message::parse(json).is_ok());
        for n in 0..json.len() {
            assert!(Message::parse(&json[..n]).is_err(), "{n} bytes");
        }
    }

    // Message examples from the manual's protocol pages.
    #[test]
    fn message_examples() {
        let m = Message::parse(br#"{"request":"sender data","data":[{"host":"<hostname>","key":"trap","value":"test value"}]}"#).unwrap();
        assert_eq!(m.kind(), &Kind::SenderData);
        let m = Message::parse(
            br#"{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.060753"}"#,
        )
        .unwrap();
        assert_eq!(m.kind(), &Kind::Response("success".into()));
        let m = Message::parse(br#"{"request":"active checks","host":"Zabbix server","host_metadata":"mysql,nginx","hostinterface":"zabbix.server.lan","ip":"159.168.1.1","port":12050}"#).unwrap();
        assert_eq!(m.kind(), &Kind::ActiveChecks);
        let m = Message::parse(br#"{"request":"agent data","session":"1234456akdsjhfoui","data":[{"host":"Zabbix server","key":"agent.version","value":"2.4.0","id":1,"clock":1400675595,"ns":76808644}],"clock":1400675595,"ns":78211329}"#).unwrap();
        assert_eq!(m.kind(), &Kind::AgentData);
        let m = Message::parse(br#" { "request" : "proxy config" } "#).unwrap();
        assert_eq!(m.kind(), &Kind::OtherRequest("proxy config".into()));
        // Escapes in the kind are decoded; the first member wins; a
        // nested request does not count.
        let m = Message::parse(br#"{"x":{"request":"no"},"request":"sender\u0020data","request":"later"}"#).unwrap();
        assert_eq!(m.kind(), &Kind::SenderData);
        let m = Message::parse(br#"{"response":"failed","request":"active checks"}"#).unwrap();
        assert_eq!(m.kind(), &Kind::ActiveChecks);
        let m = Message::parse(br#"{"k":"\ud83d\ude00","request":"\ud83d\ude00"}"#).unwrap();
        assert_eq!(m.kind(), &Kind::OtherRequest("\u{1f600}".into()));
    }

    #[test]
    fn message_errors() {
        use MessageError::*;
        assert_eq!(Message::parse(b"{\"request\":\"\xff\"}"), Err(Utf8));
        assert_eq!(Message::parse(b""), Err(Syntax(0)));
        assert_eq!(Message::parse(b"  "), Err(Syntax(2)));
        assert_eq!(Message::parse(b"[]"), Err(NotObject));
        assert_eq!(Message::parse(b"\"request\""), Err(NotObject));
        assert_eq!(Message::parse(b"{}"), Err(NoKind));
        assert_eq!(Message::parse(br#"{"request":1}"#), Err(NoKind));
        assert_eq!(Message::parse(br#"{"a":{"request":"x"}}"#), Err(NoKind));
        let deep = format!("{{\"request\":\"x\",\"a\":{}{}}}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert_eq!(Message::parse(deep.as_bytes()), Err(TooDeep));
        let ok = format!("{{\"request\":\"x\",\"a\":{}{}}}", "[".repeat(MAX_DEPTH - 1), "]".repeat(MAX_DEPTH - 1));
        assert!(Message::parse(ok.as_bytes()).is_ok());
        for bad in [
            &br#"{"request":"x",}"#[..],
            br#"{"request":"x"} x"#,
            br#"{"request":"x"}}"#,
            br#"{"request" "x"}"#,
            br#"{request:"x"}"#,
            br#"{"request":"x","a":01}"#,
            br#"{"request":"x","a":1.}"#,
            br#"{"request":"x","a":1e}"#,
            br#"{"request":"x","a":-}"#,
            br#"{"request":"x","a":tru}"#,
            br#"{"request":"x","a":[1,]}"#,
            br#"{"request":"x","a":[1}"#,
            br#"{"request":"x","a":"\q"}"#,
            br#"{"request":"x","a":"\u12"}"#,
            br#"{"request":"x","a":"\ud800"}"#,
            br#"{"request":"x","a":"\ud800\u0041"}"#,
            br#"{"request":"x","a":"\udc00"}"#,
            b"{\"request\":\"x\",\"a\":\"\x01\"}",
            br#"{"request":"x","a":+1}"#,
        ] {
            assert!(matches!(Message::parse(bad), Err(Syntax(_))), "{}", String::from_utf8_lossy(bad));
        }
        for e in [Utf8, Syntax(3), TooDeep, NotObject, NoKind, TooLong] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_round_trip() {
        let m = Message::active_checks("web \"1\"\n\u{1}").unwrap();
        assert_eq!(m.json(), r#"{"request":"active checks","host":"web \"1\"\n\u0001"}"#);
        let sv = SenderValue { host: "h".into(), key: "k[\\]".into(), value: "v\t".into() };
        let av = AgentValue { host: "h".into(), key: "agent.version".into(), value: "7.0".into(), id: 1, clock: 1400675595, ns: 76808644 };
        let all = [
            m,
            Message::sender_data(&[sv.clone(), sv]).unwrap(),
            Message::sender_data(&[]).unwrap(),
            Message::agent_data("s", &[av.clone(), av], 1400675595, 78211329).unwrap(),
            Message::response(true, Some("processed: 1; failed: 0; total: 1")).unwrap(),
            Message::response(false, None).unwrap(),
        ];
        for m in all {
            let bytes = m.to_packet().to_bytes().unwrap();
            let p = Packet::parse(&bytes).unwrap();

            assert_eq!(Message::parse(&p.data).unwrap(), m);
        }
        let m = Message::response(true, None).unwrap();
        assert_eq!(m.clone().into_json(), m.json());
        assert_eq!(
            Message::sender_data(&[SenderValue { host: "a".into(), key: "b".into(), value: "c".into() }]).unwrap().json(),
            r#"{"request":"sender data","data":[{"host":"a","key":"b","value":"c"}]}"#
        );
    }

    #[test]
    fn stream_splits_packets() {
        let a = Message::active_checks("a").unwrap().to_packet();
        let b = Packet { flags: 3, reserved: 7, data: vec![1, 2, 3] };
        let mut bytes = a.to_bytes().unwrap();
        b.write(&mut bytes).unwrap();
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * Frames::new().capacity());
        assert_eq!(decode_all(Frames::new, &bytes), (vec![a, b], None));
        let mut d = Stream::new(Frames::with_limit(4));
        assert_eq!(d.push(&packet_bytes(1, b"hello", 0)[..13]), 13);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(PacketError::TooLarge { len: 5, limit: 4 }))));
        assert_eq!(d.push(&bytes), bytes.len());
        assert!(d.next().is_none());
        assert_eq!(d.buffered(), 13);
    }

    #[test]
    fn stream_reads_many_small_packets_in_linear_time() {
        let one = Packet::new(vec![b'x'; 3]).to_bytes().unwrap();
        let bytes = one.repeat(200_000);
        let started = std::time::Instant::now();
        let mut stream = Stream::new(Frames::new());
        let mut n = 0;
        pump(&mut stream, &bytes, |_| n += 1).unwrap();
        finish(&mut stream, |_| n += 1).unwrap();
        assert_eq!(n, 200_000);
        assert_eq!(stream.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    fn check_stream(data: &[u8], limit: usize) {
        contract::check_decode_with_alloc_limit(|| Frames::with_limit(limit), data, 2 * Frames::with_limit(limit).capacity());
        contract::check_wire::<Packet>(data);
        contract::check_wire::<Header>(data);
        contract::check_wire::<Message>(data);
        for p in decode_all(|| Frames::with_limit(limit), data).0 {
            contract::check_wire_value(&p);
            if let Ok(m) = Message::parse(&p.data) {
                assert_eq!(m.json().as_bytes(), &p.data[..]);
                contract::check_wire_value(&m);
                assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
            }
        }
        // Writers take any text, and what they write reads back.
        let text = String::from_utf8_lossy(data);
        let m = Message::active_checks(&text).unwrap();
        assert_eq!(Message::parse(m.json().as_bytes()), Ok(m));
        let m = Message::response(false, Some(&text)).unwrap();
        assert_eq!(Message::parse(&m.to_packet().data), Ok(m));
        let v = SenderValue { host: text.to_string(), key: text.to_string(), value: text.to_string() };
        let m = Message::sender_data(&[v]).unwrap();
        assert_eq!(Message::parse(m.json().as_bytes()), Ok(m));
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg::new(0x5e_ed2a_bb1c);
        let seeds: Vec<Vec<u8>> = vec![
            packet_bytes(1, br#"{"request":"sender data","data":[{"host":"h","key":"k","value":"1"}]}"#, 0),
            packet_bytes(3, &[0x78, 0x9c, 0, 0], 40),
            Packet { flags: 5, reserved: 0, data: br#"{"response":"success"}"#.to_vec() }.to_bytes().unwrap(),
            Message::agent_data("s", &[], 1, 2).unwrap().to_packet().to_bytes().unwrap(),
        ];
        let alphabet = b"{}[]\":,\\ -0123456789.eEtrufalsnquxdABZD\x01\x05\x07";
        for round in 0..6000 {
            let mut buf = Vec::new();
            match round % 3 {
                0 => {
                    // Random bytes, often starting with a header.
                    if r.coin() {
                        buf.extend_from_slice(b"ZBXD");
                        buf.push([1, 3, 5, 7, 0, 9][r.index(6)]);
                        let n = r.index(40) as u32;
                        buf.extend_from_slice(&n.to_le_bytes());
                        buf.extend_from_slice(&[0; 4]);
                    }
                    buf.extend(r.bytes(59));
                }
                1 => {
                    // Valid packets, joined, then mutated.
                    for _ in 0..1 + r.index(3) {
                        buf.extend_from_slice(&seeds[r.index(seeds.len())]);
                    }
                    mutate(&mut r, &mut buf);
                }
                _ => {
                    // JSON-shaped text, alone and in a packet.
                    let mut j = b"{\"request\":".to_vec();
                    for _ in 0..r.index(40) {
                        j.push(alphabet[r.index(alphabet.len())]);
                    }
                    let _ = Message::parse(&j);
                    buf = packet_bytes(1, &j, 0);
                }
            }
            check_stream(&buf, [4, 30, DEFAULT_LIMIT][r.index(3)]);
        }
    }
}
