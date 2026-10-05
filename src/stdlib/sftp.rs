//! SFTP version 3: reading and writing packets, requests and responses,
//! with no I/O.
//!
//! SFTP is how most file transfers over SSH happen. The client opens an
//! SSH channel, asks for the `sftp` subsystem, and then sends requests
//! (open a file, read 32 KiB at an offset, list a directory) as packets.
//! The server answers each one by its request id. This module follows
//! draft-ietf-secsh-filexfer-02, which describes version 3, the version
//! OpenSSH and almost every other implementation speak.
//!
//! Nothing here reads a socket. A world that plays a file server feeds
//! the bytes it reads from the SSH channel to a [`Decoder`], gets
//! [`Packet`]s back, reads each one's [`Request`], and writes the bytes of
//! a [`Response`] back to the channel. Which files exist, what they hold
//! and who may touch them is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Each field has a limit (see [`MAX_PATH`], [`MAX_DATA`] and the
//! others), and a reader refuses a field over its limit. Writers cut a
//! field to its limit, so what they write always reads back. A STATUS
//! message or language tag is cut where a UTF-8 character starts, so
//! valid text stays valid.
//!
//! New stacks use [`Frames`] with [`codec::Stream`](super::codec::Stream)
//! for bounded input and EOF checks. [`Packet`] implements [`Wire`] for
//! exact parsing and transactional writing. [`Packet::to_bytes`] still
//! clips oversized bodies. [`Decoder`] keeps its repeated errors and
//! discards buffered bytes on failure.
//!
//! ```
//! use fictionet::stdlib::sftp::{Attrs, Decoder, Packet, Request, Response, Status, VERSION};
//!
//! /// A server holding one file, `/motd`, 12 bytes long.
//! fn answer(packet: &Packet) -> Response {
//!     match Request::parse(packet) {
//!         // Like OpenSSH, answer every INIT with version 3, the only
//!         // version these packets are laid out for.
//!         Ok(Request::Init { .. }) => Response::Version { version: VERSION, extensions: Vec::new() },
//!         Ok(Request::Stat { id, path }) | Ok(Request::Lstat { id, path }) => {
//!             if path == b"/motd" {
//!                 let attrs = Attrs { size: Some(12), permissions: Some(0o100644), ..Attrs::default() };
//!                 Response::Attrs { id, attrs }
//!             } else {
//!                 Response::status(id, Status::NoSuchFile, "No such file")
//!             }
//!         }
//!         Ok(other) => Response::status(other.id().unwrap_or(0), Status::OpUnsupported, "Not here"),
//!         Err(e) => Response::status(packet.id().unwrap_or(0), e.status(), "Bad packet"),
//!     }
//! }
//!
//! let mut decoder = Decoder::new();
//! // INIT, version 3: length 5, type 1, then the version.
//! assert_eq!(decoder.feed(&[0, 0, 0, 5, 1, 0, 0, 0, 3]), 9);
//! let init = decoder.next_packet().unwrap().unwrap();
//! assert_eq!(answer(&init).to_bytes(), [0, 0, 0, 5, 2, 0, 0, 0, 3]);
//!
//! // STAT /motd, request id 1.
//! let bytes = Request::Stat { id: 1, path: b"/motd".to_vec() }.to_bytes();
//! assert_eq!(decoder.feed(&bytes), bytes.len());
//! let stat = decoder.next_packet().unwrap().unwrap();
//! assert_eq!(
//!     answer(&stat).to_bytes(),
//!     [
//!         0, 0, 0, 21, // length
//!         105, // ATTRS
//!         0, 0, 0, 1, // request id
//!         0, 0, 0, 5, // flags: SIZE and PERMISSIONS
//!         0, 0, 0, 0, 0, 0, 0, 12, // size
//!         0, 0, 0x81, 0xa4, // permissions: a regular file, rw-r--r--
//!     ]
//! );
//! ```

use super::codec::{Decode, Step, Wire};

/// The SSH subsystem name a client asks for to start SFTP.
pub const SUBSYSTEM: &str = "sftp";
/// The protocol version this module reads and writes.
pub const VERSION: u32 = 3;

/// The longest packet: the value of the length field, which counts the
/// type byte and the body. OpenSSH uses the same limit.
pub const MAX_PACKET: usize = 256 * 1024;
/// The length field before each packet.
pub const LENGTH_LEN: usize = 4;
/// The longest wire packet, including its four-byte length field.
/// This is the default input capacity of [`Frames`].
pub const MAX_FRAME: usize = LENGTH_LEN + MAX_PACKET;
/// The most bytes of file data one WRITE, DATA or EXTENDED packet may
/// carry. A server should not answer a READ with more.
pub const MAX_DATA: usize = 255 * 1024;
/// The longest path, file name or long name.
pub const MAX_PATH: usize = 4096;
/// The longest handle. The specification sets this limit.
pub const MAX_HANDLE: usize = 256;
/// The longest extension name, extended request name or extended
/// attribute type.
pub const MAX_EXTENSION_NAME: usize = 256;
/// The longest status message, language tag, or extension data in INIT,
/// VERSION or attributes.
pub const MAX_TEXT: usize = 1024;
/// The most extensions one INIT or VERSION packet may carry.
pub const MAX_EXTENSIONS: usize = 64;
/// The most extended attributes one set of attributes may carry.
pub const MAX_ATTR_EXTENSIONS: usize = 16;
/// The most entries one NAME packet may carry.
pub const MAX_NAMES: usize = 1024;

/// Packet type numbers.
pub mod packet_type {
    #![allow(missing_docs)]
    pub const INIT: u8 = 1;
    pub const VERSION: u8 = 2;
    pub const OPEN: u8 = 3;
    pub const CLOSE: u8 = 4;
    pub const READ: u8 = 5;
    pub const WRITE: u8 = 6;
    pub const LSTAT: u8 = 7;
    pub const FSTAT: u8 = 8;
    pub const SETSTAT: u8 = 9;
    pub const FSETSTAT: u8 = 10;
    pub const OPENDIR: u8 = 11;
    pub const READDIR: u8 = 12;
    pub const REMOVE: u8 = 13;
    pub const MKDIR: u8 = 14;
    pub const RMDIR: u8 = 15;
    pub const REALPATH: u8 = 16;
    pub const STAT: u8 = 17;
    pub const RENAME: u8 = 18;
    pub const READLINK: u8 = 19;
    pub const SYMLINK: u8 = 20;
    pub const STATUS: u8 = 101;
    pub const HANDLE: u8 = 102;
    pub const DATA: u8 = 103;
    pub const NAME: u8 = 104;
    pub const ATTRS: u8 = 105;
    pub const EXTENDED: u8 = 200;
    pub const EXTENDED_REPLY: u8 = 201;
}

/// The flags of an OPEN request, which say how to open the file.
pub mod open_flags {
    /// Open for reading.
    pub const READ: u32 = 0x01;
    /// Open for writing.
    pub const WRITE: u32 = 0x02;
    /// Every write goes to the end of the file, whatever its offset.
    pub const APPEND: u32 = 0x04;
    /// Create the file if it does not exist.
    pub const CREAT: u32 = 0x08;
    /// Cut an existing file to length 0. Needs `CREAT`.
    pub const TRUNC: u32 = 0x10;
    /// Fail if the file exists. Needs `CREAT`.
    pub const EXCL: u32 = 0x20;
}

/// The flags at the start of a set of attributes, which say which fields
/// follow.
pub mod attr_flags {
    /// The size follows.
    pub const SIZE: u32 = 0x0000_0001;
    /// The owner's user and group ids follow.
    pub const UIDGID: u32 = 0x0000_0002;
    /// The permission bits follow.
    pub const PERMISSIONS: u32 = 0x0000_0004;
    /// The access and modification times follow.
    pub const ACMODTIME: u32 = 0x0000_0008;
    /// A count of extended attributes follows, then each one.
    pub const EXTENDED: u32 = 0x8000_0000;
    /// Every flag version 3 defines.
    pub const ALL: u32 = SIZE | UIDGID | PERMISSIONS | ACMODTIME | EXTENDED;
}

/// One SFTP packet: its type and the bytes after the type. The length
/// field is worked out from the body, so it is not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The packet type, one of [`packet_type`].
    pub kind: u8,
    /// Everything after the type byte.
    pub body: Vec<u8>,
}

/// Why bytes are not an SFTP packet. Either way, the channel holds no
/// more packets a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// The length field was 0, so there is no type byte.
    Empty,
    /// The length field was over the limit.
    TooLong(u32),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::Empty => f.write_str("packet length 0, with no type byte"),
            PacketError::TooLong(n) => write!(f, "packet length {n}, over the limit"),
        }
    }
}

impl std::error::Error for PacketError {}

/// Why an exact [`Wire`] parse did not read one complete packet.
/// [`Packet::parse`] keeps its separate prefix parsing behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketParseError {
    /// The packet length is invalid.
    Frame(PacketError),
    /// The input ended before a complete packet, including empty input.
    Truncated,
    /// Bytes follow the first complete packet.
    Trailing,
}

impl core::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("input ended before a complete SFTP packet"),
            Self::Trailing => f.write_str("bytes follow the SFTP packet"),
        }
    }
}

impl core::error::Error for PacketParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

impl Packet {
    /// Reads the packet at the start of `b`, with a length of at most
    /// [`MAX_PACKET`]. It returns `Ok(None)` if `b` holds only part of
    /// one, and otherwise the packet and how many bytes of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, PacketError> {
        Packet::parse_limited(b, MAX_PACKET)
    }

    /// Like [`Packet::parse`], with a length of at most `limit` instead.
    /// A limit over [`MAX_PACKET`] counts as [`MAX_PACKET`].
    pub fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, PacketError> {
        let limit = limit.min(MAX_PACKET);
        let Some(head) = b.get(..LENGTH_LEN) else { return Ok(None) };
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let n = usize::try_from(length).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(PacketError::Empty);
        }
        if n > limit {
            return Err(PacketError::TooLong(length));
        }
        let Some(rest) = b.get(LENGTH_LEN..LENGTH_LEN + n) else { return Ok(None) };
        let packet = Packet { kind: rest[0], body: rest[1..].to_vec() };
        Ok(Some((packet, LENGTH_LEN + n)))
    }

    /// The packet's bytes: the length, the type, then the body. A body
    /// longer than a packet can hold is cut to fit.
    pub fn to_bytes(&self) -> Vec<u8> {
        let body = &self.body[..self.body.len().min(MAX_PACKET - 1)];
        let mut out = Vec::with_capacity(LENGTH_LEN + 1 + body.len());
        put_u32(&mut out, (body.len() + 1) as u32);
        out.push(self.kind);
        out.extend_from_slice(body);
        out
    }

    /// The request id: the body's first four bytes. INIT and VERSION have
    /// none, and a body shorter than four bytes has none. A server that
    /// cannot read a request uses this to answer it.
    pub fn id(&self) -> Option<u32> {
        if self.kind == packet_type::INIT || self.kind == packet_type::VERSION {
            return None;
        }
        let b = self.body.get(..4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl Wire for Packet {
    type ParseError = PacketParseError;
    type WriteError = PacketError;

    /// Reads exactly one packet. Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, PacketParseError> {
        match Packet::parse(b).map_err(PacketParseError::Frame)? {
            Some((packet, used)) if used == b.len() => Ok(packet),
            Some(_) => Err(PacketParseError::Trailing),
            None => Err(PacketParseError::Truncated),
        }
    }

    /// Appends at most [`MAX_FRAME`] bytes. Refuses oversized bodies
    /// before changing `out`. An unrepresentable length
    /// is reported as [`PacketError::TooLong`] with `u32::MAX`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), PacketError> {
        let len = self.body.len().saturating_add(1);
        let length = u32::try_from(len).map_err(|_| PacketError::TooLong(u32::MAX))?;
        if len > MAX_PACKET {
            return Err(PacketError::TooLong(length));
        }
        out.extend_from_slice(&length.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

/// Reads SFTP packets without holding input bytes.
///
/// Use with [`codec::Stream`](super::codec::Stream) for a buffer bounded
/// by [`LENGTH_LEN`] plus [`limit`](Self::limit). Oversized packets are
/// refused from the length field. Partial packets return [`Step::Need`],
/// including at EOF, so the stream reports truncation. Packet bodies
/// remain bytes for [`Request::parse`] or [`Response::parse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Reads packets whose type and body occupy at most [`MAX_PACKET`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_PACKET)
    }

    /// Sets the length-field limit, counting the type byte and body.
    /// Clamps it to [`MAX_PACKET`]. Zero refuses every packet from its
    /// length field; capacity still includes [`LENGTH_LEN`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_PACKET) }
    }

    /// The maximum type and body size, excluding the length field.
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
    const NAME: &'static str = "SFTP";

    fn capacity(&self) -> usize {
        LENGTH_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, PacketError> {
        Ok(match Packet::parse_limited(input, self.limit)? {
            Some((packet, used)) => Step::Item(packet, used),
            None => Step::Need,
        })
    }
}

/// Splits an SFTP byte stream into packets. Feed it the bytes the channel
/// reads, in order, and take packets out until it has none.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    limit: usize,
    failed: Option<PacketError>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, taking packets up to [`MAX_PACKET`].
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_PACKET)
    }

    /// A decoder taking packets whose length field is at most `limit`. A
    /// limit over [`MAX_PACKET`] counts as [`MAX_PACKET`].
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, limit: limit.min(MAX_PACKET), failed: None }
    }

    /// Takes bytes read from the channel, from the start of `bytes`, and
    /// returns how many it took. It takes them all unless that would make
    /// it hold more than one packet of its limit, length field included.
    /// Then take packets out and feed it the rest. When it takes no
    /// bytes, it holds a whole packet or a broken length field, so a loop
    /// of feeding and taking out always ends. After a [`PacketError`] the
    /// stream cannot be read any further, and it takes and drops every
    /// byte.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let room = (LENGTH_LEN + self.limit).saturating_sub(self.buffered());
        let n = bytes.len().min(room);
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder never holds more than one packet's
    /// bytes beyond what has been taken out.
    pub fn next_packet(&mut self) -> Option<Result<Packet, PacketError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Packet::parse_limited(&self.buf[self.start..], self.limit) {
            Ok(Some((packet, used))) => {
                self.start += used;
                Some(Ok(packet))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

/// Why a packet's body is not the request or response its type says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The type is not one this reader knows: a response type given to
    /// [`Request::parse`], a request type given to [`Response::parse`], or
    /// a number version 3 does not define.
    UnknownType(u8),
    /// The body ended inside a field.
    Truncated,
    /// Bytes were left after the last field.
    Trailing,
    /// A string or the raw data of an EXTENDED or EXTENDED_REPLY was
    /// longer than its limit, or the body was longer than a packet can
    /// hold.
    TooLong,
    /// A count of names or extended attributes was over its limit.
    TooMany,
    /// A set of attributes had flags version 3 does not define, so the
    /// fields after them cannot be read.
    AttrFlags(u32),
}

impl ParseError {
    /// The status a server answers a request it cannot read with:
    /// [`Status::OpUnsupported`] for an unknown type and
    /// [`Status::BadMessage`] for the rest.
    pub fn status(self) -> Status {
        match self {
            ParseError::UnknownType(_) => Status::OpUnsupported,
            _ => Status::BadMessage,
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownType(t) => write!(f, "packet type {t} is not known here"),
            ParseError::Truncated => f.write_str("the packet ended inside a field"),
            ParseError::Trailing => f.write_str("bytes after the last field"),
            ParseError::TooLong => f.write_str("a field or the body over its limit"),
            ParseError::TooMany => f.write_str("a count over its limit"),
            ParseError::AttrFlags(x) => write!(f, "attribute flags {x:#x} are not defined in version 3"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The status codes a STATUS response carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The request succeeded.
    Ok,
    /// A read or READDIR reached the end: there is no more data or no
    /// more names.
    Eof,
    /// The file or directory does not exist.
    NoSuchFile,
    /// The user may not do this.
    PermissionDenied,
    /// The request failed for a reason no other code covers.
    Failure,
    /// The packet was badly formed.
    BadMessage,
    /// There is no connection to the server. Only a client makes this up.
    NoConnection,
    /// The connection to the server was lost. Only a client makes this up.
    ConnectionLost,
    /// The server does not support the operation.
    OpUnsupported,
    /// Any other code. A code another variant names, such as
    /// `Other(2)`, is written as that code and reads back as that variant.
    Other(u32),
}

impl Status {
    /// The status code's number.
    pub fn code(self) -> u32 {
        match self {
            Status::Ok => 0,
            Status::Eof => 1,
            Status::NoSuchFile => 2,
            Status::PermissionDenied => 3,
            Status::Failure => 4,
            Status::BadMessage => 5,
            Status::NoConnection => 6,
            Status::ConnectionLost => 7,
            Status::OpUnsupported => 8,
            Status::Other(c) => c,
        }
    }

    /// The status for code `c`.
    pub fn from_code(c: u32) -> Status {
        match c {
            0 => Status::Ok,
            1 => Status::Eof,
            2 => Status::NoSuchFile,
            3 => Status::PermissionDenied,
            4 => Status::Failure,
            5 => Status::BadMessage,
            6 => Status::NoConnection,
            7 => Status::ConnectionLost,
            8 => Status::OpUnsupported,
            c => Status::Other(c),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Status::Ok => "ok",
            Status::Eof => "end of file",
            Status::NoSuchFile => "no such file",
            Status::PermissionDenied => "permission denied",
            Status::Failure => "failure",
            Status::BadMessage => "bad message",
            Status::NoConnection => "no connection",
            Status::ConnectionLost => "connection lost",
            Status::OpUnsupported => "operation unsupported",
            Status::Other(c) => return write!(f, "status code {c}"),
        };
        f.write_str(name)
    }
}

/// A name and its data: an extension in INIT or VERSION, or an extended
/// attribute.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extension {
    /// The name, such as `posix-rename@openssh.com`. At most
    /// [`MAX_EXTENSION_NAME`] bytes.
    pub name: Vec<u8>,
    /// The data. At most [`MAX_TEXT`] bytes.
    pub data: Vec<u8>,
}

/// A file's attributes. Each field is there only if its flag is set; the
/// flags are worked out from which fields are `Some`, so they are not
/// kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    /// The size in bytes.
    pub size: Option<u64>,
    /// The owner's user id and group id.
    pub uid_gid: Option<(u32, u32)>,
    /// The file type and permission bits, as in POSIX `st_mode`.
    pub permissions: Option<u32>,
    /// The access time and modification time, in seconds since 1970.
    pub times: Option<(u32, u32)>,
    /// Extended attributes. Up to [`MAX_ATTR_EXTENSIONS`] are written.
    pub extended: Vec<Extension>,
}

impl Attrs {
    /// The flags these attributes are written with.
    pub fn flags(&self) -> u32 {
        let mut f = 0;
        if self.size.is_some() {
            f |= attr_flags::SIZE;
        }
        if self.uid_gid.is_some() {
            f |= attr_flags::UIDGID;
        }
        if self.permissions.is_some() {
            f |= attr_flags::PERMISSIONS;
        }
        if self.times.is_some() {
            f |= attr_flags::ACMODTIME;
        }
        if !self.extended.is_empty() {
            f |= attr_flags::EXTENDED;
        }
        f
    }

    fn read(r: &mut Reader<'_>) -> Result<Attrs, ParseError> {
        let flags = r.u32()?;
        if flags & !attr_flags::ALL != 0 {
            return Err(ParseError::AttrFlags(flags));
        }
        let mut a = Attrs::default();
        if flags & attr_flags::SIZE != 0 {
            a.size = Some(r.u64()?);
        }
        if flags & attr_flags::UIDGID != 0 {
            a.uid_gid = Some((r.u32()?, r.u32()?));
        }
        if flags & attr_flags::PERMISSIONS != 0 {
            a.permissions = Some(r.u32()?);
        }
        if flags & attr_flags::ACMODTIME != 0 {
            a.times = Some((r.u32()?, r.u32()?));
        }
        if flags & attr_flags::EXTENDED != 0 {
            let count = r.u32()?;
            if usize::try_from(count).map_or(true, |c| c > MAX_ATTR_EXTENSIONS) {
                return Err(ParseError::TooMany);
            }
            for _ in 0..count {
                a.extended.push(r.extension()?);
            }
        }
        Ok(a)
    }

    fn write(&self, out: &mut Vec<u8>) {
        put_u32(out, self.flags());
        if let Some(s) = self.size {
            out.extend_from_slice(&s.to_be_bytes());
        }
        if let Some((u, g)) = self.uid_gid {
            put_u32(out, u);
            put_u32(out, g);
        }
        if let Some(p) = self.permissions {
            put_u32(out, p);
        }
        if let Some((at, mt)) = self.times {
            put_u32(out, at);
            put_u32(out, mt);
        }
        if !self.extended.is_empty() {
            let ext = &self.extended[..self.extended.len().min(MAX_ATTR_EXTENSIONS)];
            put_u32(out, ext.len() as u32);
            for e in ext {
                put_extension(out, e);
            }
        }
    }
}

/// One entry of a NAME response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameEntry {
    /// The file name: within a directory for READDIR, or a whole path for
    /// REALPATH and READLINK. At most [`MAX_PATH`] bytes.
    pub filename: Vec<u8>,
    /// The line `ls -l` would print for the file. Clients show it but must
    /// not read it. At most [`MAX_PATH`] bytes.
    pub longname: Vec<u8>,
    /// The file's attributes.
    pub attrs: Attrs,
}

impl NameEntry {
    fn write(&self, out: &mut Vec<u8>) {
        put_str(out, &self.filename, MAX_PATH);
        put_str(out, &self.longname, MAX_PATH);
        self.attrs.write(out);
    }
}

/// How many of `names`, from the first, one NAME response carries. The
/// rest do not fit in one packet, and a server sends them in answer to
/// the next READDIR.
pub fn names_that_fit(names: &[NameEntry]) -> usize {
    // The type byte, the request id and the count.
    let mut used = 1 + 4 + 4;
    let mut entry = Vec::new();
    for (i, n) in names.iter().take(MAX_NAMES).enumerate() {
        entry.clear();
        n.write(&mut entry);
        used += entry.len();
        if used > MAX_PACKET {
            return i;
        }
    }
    names.len().min(MAX_NAMES)
}

/// A request: what a client asks a server to do. Every request but INIT
/// carries an id the server copies into its response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Request {
    /// INIT: the client's highest `version`, and the `extensions` it
    /// offers. The first packet of a session. A reader skips extensions
    /// over their limits, as it would any it does not know.
    Init { version: u32, extensions: Vec<Extension> },
    /// OPEN: open the file at `path` with [`open_flags`] `flags`, and set
    /// `attrs` if it is created. Answered with HANDLE or STATUS.
    Open { id: u32, path: Vec<u8>, flags: u32, attrs: Attrs },
    /// CLOSE: close `handle`. Answered with STATUS.
    Close { id: u32, handle: Vec<u8> },
    /// READ: read up to `len` bytes at `offset`. Answered with DATA, or
    /// STATUS (EOF at the end of the file).
    Read { id: u32, handle: Vec<u8>, offset: u64, len: u32 },
    /// WRITE: write `data` at `offset`. Answered with STATUS.
    Write { id: u32, handle: Vec<u8>, offset: u64, data: Vec<u8> },
    /// LSTAT: the attributes of `path`, not following a final symbolic
    /// link. Answered with ATTRS or STATUS.
    Lstat { id: u32, path: Vec<u8> },
    /// FSTAT: the attributes of the open file `handle`. Answered with
    /// ATTRS or STATUS.
    Fstat { id: u32, handle: Vec<u8> },
    /// SETSTAT: set `attrs` on `path`. Answered with STATUS.
    Setstat { id: u32, path: Vec<u8>, attrs: Attrs },
    /// FSETSTAT: set `attrs` on the open file `handle`. Answered with
    /// STATUS.
    Fsetstat { id: u32, handle: Vec<u8>, attrs: Attrs },
    /// OPENDIR: open the directory at `path` for listing. Answered with
    /// HANDLE or STATUS.
    Opendir { id: u32, path: Vec<u8> },
    /// READDIR: the next names in the directory `handle`. Answered with
    /// NAME, or STATUS (EOF when there are no more).
    Readdir { id: u32, handle: Vec<u8> },
    /// REMOVE: remove the file at `path`. Answered with STATUS.
    Remove { id: u32, path: Vec<u8> },
    /// MKDIR: make a directory at `path` with `attrs`. Answered with
    /// STATUS.
    Mkdir { id: u32, path: Vec<u8>, attrs: Attrs },
    /// RMDIR: remove the directory at `path`. Answered with STATUS.
    Rmdir { id: u32, path: Vec<u8> },
    /// REALPATH: the absolute, canonical form of `path`. Answered with a
    /// NAME of one entry, or STATUS.
    Realpath { id: u32, path: Vec<u8> },
    /// STAT: the attributes of `path`, following symbolic links. Answered
    /// with ATTRS or STATUS.
    Stat { id: u32, path: Vec<u8> },
    /// RENAME: rename `from` to `to`. Answered with STATUS.
    Rename { id: u32, from: Vec<u8>, to: Vec<u8> },
    /// READLINK: the target of the symbolic link at `path`. Answered with
    /// a NAME of one entry, or STATUS.
    Readlink { id: u32, path: Vec<u8> },
    /// SYMLINK: make a symbolic link at `linkpath` pointing to
    /// `targetpath`, in the order the specification gives. OpenSSH sends
    /// the two the other way round, target first. Answered with STATUS.
    Symlink { id: u32, linkpath: Vec<u8>, targetpath: Vec<u8> },
    /// EXTENDED: the request `name` (such as `statvfs@openssh.com`), with
    /// `data` laid out as that request defines. Answered with
    /// EXTENDED_REPLY or STATUS.
    Extended { id: u32, name: Vec<u8>, data: Vec<u8> },
}

impl Request {
    /// Reads the request in `packet`. A server answers a request it cannot
    /// read with the status [`ParseError::status`] gives, using
    /// [`Packet::id`] for the id.
    pub fn parse(packet: &Packet) -> Result<Request, ParseError> {
        use packet_type as t;
        let mut r = Reader::new(packet)?;
        if packet.kind == t::INIT {
            let version = r.u32()?;
            let extensions = r.extensions()?;
            return Ok(Request::Init { version, extensions });
        }
        if !matches!(packet.kind, t::OPEN..=t::SYMLINK | t::EXTENDED) {
            return Err(ParseError::UnknownType(packet.kind));
        }
        let id = r.u32()?;
        let req = match packet.kind {
            t::OPEN => Request::Open { id, path: r.path()?, flags: r.u32()?, attrs: Attrs::read(&mut r)? },
            t::CLOSE => Request::Close { id, handle: r.handle()? },
            t::READ => Request::Read { id, handle: r.handle()?, offset: r.u64()?, len: r.u32()? },
            t::WRITE => Request::Write { id, handle: r.handle()?, offset: r.u64()?, data: r.string(MAX_DATA)? },
            t::LSTAT => Request::Lstat { id, path: r.path()? },
            t::FSTAT => Request::Fstat { id, handle: r.handle()? },
            t::SETSTAT => Request::Setstat { id, path: r.path()?, attrs: Attrs::read(&mut r)? },
            t::FSETSTAT => Request::Fsetstat { id, handle: r.handle()?, attrs: Attrs::read(&mut r)? },
            t::OPENDIR => Request::Opendir { id, path: r.path()? },
            t::READDIR => Request::Readdir { id, handle: r.handle()? },
            t::REMOVE => Request::Remove { id, path: r.path()? },
            t::MKDIR => Request::Mkdir { id, path: r.path()?, attrs: Attrs::read(&mut r)? },
            t::RMDIR => Request::Rmdir { id, path: r.path()? },
            t::REALPATH => Request::Realpath { id, path: r.path()? },
            t::STAT => Request::Stat { id, path: r.path()? },
            t::RENAME => Request::Rename { id, from: r.path()?, to: r.path()? },
            t::READLINK => Request::Readlink { id, path: r.path()? },
            t::SYMLINK => Request::Symlink { id, linkpath: r.path()?, targetpath: r.path()? },
            _ => {
                let name = r.string(MAX_EXTENSION_NAME)?;
                let data = r.rest();
                if data.len() > MAX_DATA {
                    return Err(ParseError::TooLong);
                }
                Request::Extended { id, name, data: data.to_vec() }
            }
        };
        r.end()?;
        Ok(req)
    }

    /// The request's packet type.
    pub fn kind(&self) -> u8 {
        use packet_type as t;
        match self {
            Request::Init { .. } => t::INIT,
            Request::Open { .. } => t::OPEN,
            Request::Close { .. } => t::CLOSE,
            Request::Read { .. } => t::READ,
            Request::Write { .. } => t::WRITE,
            Request::Lstat { .. } => t::LSTAT,
            Request::Fstat { .. } => t::FSTAT,
            Request::Setstat { .. } => t::SETSTAT,
            Request::Fsetstat { .. } => t::FSETSTAT,
            Request::Opendir { .. } => t::OPENDIR,
            Request::Readdir { .. } => t::READDIR,
            Request::Remove { .. } => t::REMOVE,
            Request::Mkdir { .. } => t::MKDIR,
            Request::Rmdir { .. } => t::RMDIR,
            Request::Realpath { .. } => t::REALPATH,
            Request::Stat { .. } => t::STAT,
            Request::Rename { .. } => t::RENAME,
            Request::Readlink { .. } => t::READLINK,
            Request::Symlink { .. } => t::SYMLINK,
            Request::Extended { .. } => t::EXTENDED,
        }
    }

    /// The request id. INIT has none.
    pub fn id(&self) -> Option<u32> {
        match self {
            Request::Init { .. } => None,
            Request::Open { id, .. }
            | Request::Close { id, .. }
            | Request::Read { id, .. }
            | Request::Write { id, .. }
            | Request::Lstat { id, .. }
            | Request::Fstat { id, .. }
            | Request::Setstat { id, .. }
            | Request::Fsetstat { id, .. }
            | Request::Opendir { id, .. }
            | Request::Readdir { id, .. }
            | Request::Remove { id, .. }
            | Request::Mkdir { id, .. }
            | Request::Rmdir { id, .. }
            | Request::Realpath { id, .. }
            | Request::Stat { id, .. }
            | Request::Rename { id, .. }
            | Request::Readlink { id, .. }
            | Request::Symlink { id, .. }
            | Request::Extended { id, .. } => Some(*id),
        }
    }

    /// The request's packet, for a world that plays a client. Each field
    /// is cut to its limit and only the first [`MAX_EXTENSIONS`]
    /// extensions are written, so the packet always reads back.
    pub fn to_packet(&self) -> Packet {
        let mut b = Vec::new();
        if let Some(id) = self.id() {
            put_u32(&mut b, id);
        }
        match self {
            Request::Init { version, extensions } => {
                put_u32(&mut b, *version);
                put_extensions(&mut b, extensions);
            }
            Request::Open { path, flags, attrs, .. } => {
                put_str(&mut b, path, MAX_PATH);
                put_u32(&mut b, *flags);
                attrs.write(&mut b);
            }
            Request::Close { handle, .. } | Request::Fstat { handle, .. } | Request::Readdir { handle, .. } => {
                put_str(&mut b, handle, MAX_HANDLE);
            }
            Request::Read { handle, offset, len, .. } => {
                put_str(&mut b, handle, MAX_HANDLE);
                b.extend_from_slice(&offset.to_be_bytes());
                put_u32(&mut b, *len);
            }
            Request::Write { handle, offset, data, .. } => {
                put_str(&mut b, handle, MAX_HANDLE);
                b.extend_from_slice(&offset.to_be_bytes());
                put_str(&mut b, data, MAX_DATA);
            }
            Request::Lstat { path, .. }
            | Request::Opendir { path, .. }
            | Request::Remove { path, .. }
            | Request::Rmdir { path, .. }
            | Request::Realpath { path, .. }
            | Request::Stat { path, .. }
            | Request::Readlink { path, .. } => put_str(&mut b, path, MAX_PATH),
            Request::Setstat { path, attrs, .. } | Request::Mkdir { path, attrs, .. } => {
                put_str(&mut b, path, MAX_PATH);
                attrs.write(&mut b);
            }
            Request::Fsetstat { handle, attrs, .. } => {
                put_str(&mut b, handle, MAX_HANDLE);
                attrs.write(&mut b);
            }
            Request::Rename { from: a, to: z, .. } | Request::Symlink { linkpath: a, targetpath: z, .. } => {
                put_str(&mut b, a, MAX_PATH);
                put_str(&mut b, z, MAX_PATH);
            }
            Request::Extended { name, data, .. } => {
                put_str(&mut b, name, MAX_EXTENSION_NAME);
                b.extend_from_slice(&data[..data.len().min(MAX_DATA)]);
            }
        }
        Packet { kind: self.kind(), body: b }
    }

    /// The request's bytes, with the length in front.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_packet().to_bytes()
    }
}

/// A response: what a server answers. Every response but VERSION carries
/// the id of the request it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Response {
    /// VERSION: the `version` the session will use, and the `extensions`
    /// the server offers. The specification asks for the lower of the
    /// client's version and the server's. This module writes only version
    /// 3 packets, so a server built on it answers 3, as OpenSSH does.
    Version { version: u32, extensions: Vec<Extension> },
    /// STATUS: how a request ended, with a `message` for people to read
    /// and the `language` tag it is written in. Both may be empty.
    Status { id: u32, status: Status, message: Vec<u8>, language: Vec<u8> },
    /// HANDLE: the `handle` of a file or directory just opened.
    Handle { id: u32, handle: Vec<u8> },
    /// DATA: bytes read from a file.
    Data { id: u32, data: Vec<u8> },
    /// NAME: names, for READDIR, REALPATH and READLINK. Only the entries
    /// [`names_that_fit`] counts are written.
    Name { id: u32, names: Vec<NameEntry> },
    /// ATTRS: a file's attributes, for STAT, LSTAT and FSTAT.
    Attrs { id: u32, attrs: Attrs },
    /// EXTENDED_REPLY: the answer to an EXTENDED request, laid out as that
    /// request defines.
    ExtendedReply { id: u32, data: Vec<u8> },
}

impl Response {
    /// A STATUS response with `message` and an English language tag. A
    /// message over [`MAX_TEXT`] bytes is cut where a character starts,
    /// as it would be when written, before it is copied.
    pub fn status(id: u32, status: Status, message: &str) -> Response {
        let message = cut_text(message.as_bytes(), MAX_TEXT).to_vec();
        Response::Status { id, status, message, language: b"en".to_vec() }
    }

    /// Reads the response in `packet`. A STATUS that stops after its code,
    /// as some old servers send, reads with an empty message and language
    /// tag.
    pub fn parse(packet: &Packet) -> Result<Response, ParseError> {
        use packet_type as t;
        let mut r = Reader::new(packet)?;
        let resp = match packet.kind {
            t::VERSION => {
                let version = r.u32()?;
                let extensions = r.extensions()?;
                return Ok(Response::Version { version, extensions });
            }
            t::STATUS => {
                let (id, status) = (r.u32()?, Status::from_code(r.u32()?));
                if r.b.is_empty() {
                    return Ok(Response::Status { id, status, message: Vec::new(), language: Vec::new() });
                }
                Response::Status { id, status, message: r.string(MAX_TEXT)?, language: r.string(MAX_TEXT)? }
            }
            t::HANDLE => Response::Handle { id: r.u32()?, handle: r.handle()? },
            t::DATA => Response::Data { id: r.u32()?, data: r.string(MAX_DATA)? },
            t::NAME => {
                let (id, count) = (r.u32()?, r.u32()?);
                if usize::try_from(count).map_or(true, |c| c > MAX_NAMES) {
                    return Err(ParseError::TooMany);
                }
                let mut names = Vec::new();
                for _ in 0..count {
                    let (filename, longname) = (r.path()?, r.path()?);
                    names.push(NameEntry { filename, longname, attrs: Attrs::read(&mut r)? });
                }
                Response::Name { id, names }
            }
            t::ATTRS => Response::Attrs { id: r.u32()?, attrs: Attrs::read(&mut r)? },
            t::EXTENDED_REPLY => {
                let id = r.u32()?;
                let data = r.rest();
                if data.len() > MAX_DATA {
                    return Err(ParseError::TooLong);
                }
                Response::ExtendedReply { id, data: data.to_vec() }
            }
            k => return Err(ParseError::UnknownType(k)),
        };
        r.end()?;
        Ok(resp)
    }

    /// The response's packet type.
    pub fn kind(&self) -> u8 {
        use packet_type as t;
        match self {
            Response::Version { .. } => t::VERSION,
            Response::Status { .. } => t::STATUS,
            Response::Handle { .. } => t::HANDLE,
            Response::Data { .. } => t::DATA,
            Response::Name { .. } => t::NAME,
            Response::Attrs { .. } => t::ATTRS,
            Response::ExtendedReply { .. } => t::EXTENDED_REPLY,
        }
    }

    /// The id of the request this answers. VERSION has none.
    pub fn id(&self) -> Option<u32> {
        match self {
            Response::Version { .. } => None,
            Response::Status { id, .. }
            | Response::Handle { id, .. }
            | Response::Data { id, .. }
            | Response::Name { id, .. }
            | Response::Attrs { id, .. }
            | Response::ExtendedReply { id, .. } => Some(*id),
        }
    }

    /// The response's packet. Each field is cut to its limit, and only the
    /// names and extensions that fit are written, so the packet always
    /// reads back.
    pub fn to_packet(&self) -> Packet {
        let mut b = Vec::new();
        if let Some(id) = self.id() {
            put_u32(&mut b, id);
        }
        match self {
            Response::Version { version, extensions } => {
                put_u32(&mut b, *version);
                put_extensions(&mut b, extensions);
            }
            Response::Status { status, message, language, .. } => {
                put_u32(&mut b, status.code());
                put_text(&mut b, message);
                put_text(&mut b, language);
            }
            Response::Handle { handle, .. } => put_str(&mut b, handle, MAX_HANDLE),
            Response::Data { data, .. } => put_str(&mut b, data, MAX_DATA),
            Response::Name { names, .. } => {
                let names = &names[..names_that_fit(names)];
                put_u32(&mut b, names.len() as u32);
                for n in names {
                    n.write(&mut b);
                }
            }
            Response::Attrs { attrs, .. } => attrs.write(&mut b),
            Response::ExtendedReply { data, .. } => b.extend_from_slice(&data[..data.len().min(MAX_DATA)]),
        }
        Packet { kind: self.kind(), body: b }
    }

    /// The response's bytes, with the length in front.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_packet().to_bytes()
    }
}

/// Reads fields from a packet body, front to back.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader of `packet`'s body. A body longer than a packet can hold
    /// is refused, so whatever reads from it can be written again.
    fn new(packet: &'a Packet) -> Result<Reader<'a>, ParseError> {
        if packet.body.len() >= MAX_PACKET {
            return Err(ParseError::TooLong);
        }
        Ok(Reader { b: &packet.body })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if n > self.b.len() {
            return Err(ParseError::Truncated);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// A string: a 4-byte length, then that many bytes, at most `max`.
    fn string(&mut self, max: usize) -> Result<Vec<u8>, ParseError> {
        let n = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if n > max {
            return Err(ParseError::TooLong);
        }
        Ok(self.take(n)?.to_vec())
    }

    fn path(&mut self) -> Result<Vec<u8>, ParseError> {
        self.string(MAX_PATH)
    }

    fn handle(&mut self) -> Result<Vec<u8>, ParseError> {
        self.string(MAX_HANDLE)
    }

    fn extension(&mut self) -> Result<Extension, ParseError> {
        Ok(Extension { name: self.string(MAX_EXTENSION_NAME)?, data: self.string(MAX_TEXT)? })
    }

    /// A string of any length that fits in the body, not copied.
    fn raw_string(&mut self) -> Result<&'a [u8], ParseError> {
        let n = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        self.take(n)
    }

    /// Extension pairs up to the end of the body. The specification says
    /// to ignore extensions a reader does not know, so a pair over a
    /// limit, or past the first [`MAX_EXTENSIONS`], is skipped rather
    /// than refused. The body bounds what is read.
    fn extensions(&mut self) -> Result<Vec<Extension>, ParseError> {
        let mut out = Vec::new();
        while !self.b.is_empty() {
            let (name, data) = (self.raw_string()?, self.raw_string()?);
            if out.len() < MAX_EXTENSIONS && name.len() <= MAX_EXTENSION_NAME && data.len() <= MAX_TEXT {
                out.push(Extension { name: name.to_vec(), data: data.to_vec() });
            }
        }
        Ok(out)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }

    fn end(&self) -> Result<(), ParseError> {
        if self.b.is_empty() { Ok(()) } else { Err(ParseError::Trailing) }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// A string cut to `max` bytes, with its length in front. Every limit fits
/// in a u32.
fn put_str(out: &mut Vec<u8>, s: &[u8], max: usize) {
    let s = &s[..s.len().min(max)];
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

/// The longest start of `s`, at most `max` bytes, that does not end
/// inside a UTF-8 character. Bytes that are not UTF-8 are cut at `max`.
fn cut_text(s: &[u8], max: usize) -> &[u8] {
    if s.len() <= max {
        return s;
    }
    // A UTF-8 character has at most three continuation bytes.
    let mut n = max;
    for _ in 0..3 {
        if n == 0 || s[n] & 0xc0 != 0x80 {
            break;
        }
        n -= 1;
    }
    if s[n] & 0xc0 == 0x80 { &s[..max] } else { &s[..n] }
}

/// A STATUS message or language tag, cut by [`cut_text`].
fn put_text(out: &mut Vec<u8>, s: &[u8]) {
    put_str(out, cut_text(s, MAX_TEXT), MAX_TEXT);
}

fn put_extension(out: &mut Vec<u8>, e: &Extension) {
    put_str(out, &e.name, MAX_EXTENSION_NAME);
    put_str(out, &e.data, MAX_TEXT);
}

fn put_extensions(out: &mut Vec<u8>, extensions: &[Extension]) {
    for e in extensions.iter().take(MAX_EXTENSIONS) {
        put_extension(out, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> Vec<u8> {
        v.to_vec()
    }

    fn full_attrs() -> Attrs {
        Attrs {
            size: Some(0x0102_0304_0506_0708),
            uid_gid: Some((1000, 100)),
            permissions: Some(0o100644),
            times: Some((1_700_000_000, 1_700_000_001)),
            extended: vec![Extension { name: s(b"x@example.com"), data: s(b"v") }],
        }
    }

    fn requests() -> Vec<Request> {
        let a = full_attrs();
        let h = s(b"h1");
        vec![
            Request::Init { version: 3, extensions: vec![] },
            Request::Init { version: 6, extensions: vec![Extension { name: s(b"a@b"), data: s(b"1") }] },
            Request::Open { id: 1, path: s(b"/f"), flags: open_flags::READ | open_flags::WRITE, attrs: a.clone() },
            Request::Open { id: 1, path: s(b"/f"), flags: open_flags::READ, attrs: Attrs::default() },
            Request::Close { id: 2, handle: h.clone() },
            Request::Read { id: 3, handle: h.clone(), offset: 1 << 40, len: 32768 },
            Request::Write { id: 4, handle: h.clone(), offset: 7, data: s(b"hello") },
            Request::Lstat { id: 5, path: s(b"/l") },
            Request::Fstat { id: 6, handle: h.clone() },
            Request::Setstat { id: 7, path: s(b"/s"), attrs: a.clone() },
            Request::Fsetstat { id: 8, handle: h.clone(), attrs: a.clone() },
            Request::Opendir { id: 9, path: s(b"/") },
            Request::Readdir { id: 10, handle: h.clone() },
            Request::Remove { id: 11, path: s(b"/r") },
            Request::Mkdir { id: 12, path: s(b"/d"), attrs: Attrs { permissions: Some(0o755), ..Attrs::default() } },
            Request::Rmdir { id: 13, path: s(b"/d") },
            Request::Realpath { id: 14, path: s(b".") },
            Request::Stat { id: 15, path: s(b"/s") },
            Request::Rename { id: 16, from: s(b"/a"), to: s(b"/b") },
            Request::Readlink { id: 17, path: s(b"/ln") },
            Request::Symlink { id: 18, linkpath: s(b"/ln"), targetpath: s(b"/t") },
            Request::Extended { id: 19, name: s(b"statvfs@openssh.com"), data: s(b"\0\0\0\x01/") },
            Request::Extended { id: 20, name: s(b"x"), data: vec![] },
        ]
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Version { version: 3, extensions: vec![] },
            Response::Version {
                version: 3,
                extensions: vec![
                    Extension { name: s(b"posix-rename@openssh.com"), data: s(b"1") },
                    Extension { name: s(b"statvfs@openssh.com"), data: s(b"2") },
                ],
            },
            Response::status(1, Status::Ok, "Success"),
            Response::Status { id: 2, status: Status::Other(99), message: vec![], language: vec![] },
            Response::Handle { id: 3, handle: s(b"\0\0\0\x01") },
            Response::Data { id: 4, data: s(b"file contents") },
            Response::Data { id: 4, data: vec![] },
            Response::Name { id: 5, names: vec![] },
            Response::Name {
                id: 6,
                names: vec![
                    NameEntry { filename: s(b"a"), longname: s(b"-rw-r--r-- 1 u g 0 Jan 1 a"), attrs: full_attrs() },
                    NameEntry { filename: s(b"b"), longname: vec![], attrs: Attrs::default() },
                ],
            },
            Response::Attrs { id: 7, attrs: full_attrs() },
            Response::Attrs { id: 7, attrs: Attrs { size: Some(1), ..Attrs::default() } },
            Response::ExtendedReply { id: 8, data: s(b"anything") },
        ]
    }

    // Layouts from draft-ietf-secsh-filexfer-02, sections 3 to 7.

    #[test]
    fn init_and_version_bytes() {
        let init = Request::Init { version: 3, extensions: vec![] };
        assert_eq!(init.to_bytes(), [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        let v = Response::Version { version: 3, extensions: vec![Extension { name: s(b"a"), data: s(b"bc") }] };
        assert_eq!(v.to_bytes(), [0, 0, 0, 16, 2, 0, 0, 0, 3, 0, 0, 0, 1, b'a', 0, 0, 0, 2, b'b', b'c']);
        assert_eq!(v.id(), None);
        assert_eq!(Packet { kind: 1, body: vec![0, 0, 0, 3] }.id(), None);
    }

    #[test]
    fn open_bytes() {
        let req = Request::Open {
            id: 0x0a0b0c0d,
            path: s(b"/x"),
            flags: open_flags::WRITE | open_flags::CREAT | open_flags::TRUNC,
            attrs: Attrs { permissions: Some(0o644), ..Attrs::default() },
        };
        let bytes = [
            0, 0, 0, 23, 3, 0x0a, 0x0b, 0x0c, 0x0d, 0, 0, 0, 2, b'/', b'x', 0, 0, 0, 0x1a, 0, 0, 0, 4, 0, 0, 0x01, 0xa4,
        ];
        assert_eq!(req.to_bytes(), bytes);
        let (p, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(p.id(), Some(0x0a0b0c0d));
        assert_eq!(Request::parse(&p), Ok(req));
    }

    #[test]
    fn read_status_and_attrs_bytes() {
        let req = Request::Read { id: 1, handle: s(b"h"), offset: 0x100, len: 0x8000 };
        assert_eq!(req.to_packet().body, [0, 0, 0, 1, 0, 0, 0, 1, b'h', 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 0]);
        let eof = Response::status(1, Status::Eof, "");
        assert_eq!(eof.to_packet().body, [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, b'e', b'n']);
        // A STATUS with no message and no language tag, as old servers send.
        let short = Packet { kind: packet_type::STATUS, body: vec![0, 0, 0, 1, 0, 0, 0, 2] };
        assert_eq!(
            Response::parse(&short),
            Ok(Response::Status { id: 1, status: Status::NoSuchFile, message: vec![], language: vec![] })
        );
        let attrs = full_attrs();
        let mut body = Vec::new();
        attrs.write(&mut body);
        assert_eq!(&body[..4], &[0x80, 0, 0, 0x0f]);
        assert_eq!(body.len(), 4 + 8 + 8 + 4 + 8 + 4 + (4 + 13) + (4 + 1));
    }

    #[test]
    fn requests_round_trip() {
        for req in requests() {
            let bytes = req.to_bytes();
            let (p, used) = Packet::parse(&bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(p.kind, req.kind());
            assert_eq!(p.id(), req.id());
            assert_eq!(Request::parse(&p).as_ref(), Ok(&req), "{req:?}");
            // A request is not a response.
            assert_eq!(Response::parse(&p), Err(ParseError::UnknownType(p.kind)));
        }
    }

    #[test]
    fn responses_round_trip() {
        for resp in responses() {
            let bytes = resp.to_bytes();
            let (p, used) = Packet::parse(&bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(p.kind, resp.kind());
            assert_eq!(p.id(), resp.id());
            assert_eq!(Response::parse(&p).as_ref(), Ok(&resp), "{resp:?}");
            assert_eq!(Request::parse(&p), Err(ParseError::UnknownType(p.kind)));
        }
    }

    #[test]
    fn status_codes() {
        for c in 0..=300u32 {
            assert_eq!(Status::from_code(c).code(), c);
        }
        assert_eq!(Status::from_code(u32::MAX).code(), u32::MAX);
        assert_eq!(Status::from_code(8), Status::OpUnsupported);
        // Other with a named code reads back as the named variant.
        let p = Response::Status { id: 1, status: Status::Other(2), message: vec![], language: vec![] }.to_packet();
        assert!(matches!(Response::parse(&p), Ok(Response::Status { status: Status::NoSuchFile, .. })));
        assert_eq!(Status::NoSuchFile.to_string(), "no such file");
        assert_eq!(ParseError::UnknownType(77).status(), Status::OpUnsupported);
        assert_eq!(ParseError::Truncated.status(), Status::BadMessage);
    }

    #[test]
    fn every_attribute_combination() {
        for mask in 0..32u32 {
            let attrs = Attrs {
                size: (mask & 1 != 0).then_some(5),
                uid_gid: (mask & 2 != 0).then_some((1, 2)),
                permissions: (mask & 4 != 0).then_some(0o40755),
                times: (mask & 8 != 0).then_some((3, 4)),
                extended: if mask & 16 != 0 { vec![Extension::default()] } else { vec![] },
            };
            let resp = Response::Attrs { id: mask, attrs: attrs.clone() };
            let p = resp.to_packet();
            assert_eq!(Response::parse(&p), Ok(resp));
            let flags = u32::from_be_bytes([p.body[4], p.body[5], p.body[6], p.body[7]]);
            assert_eq!(flags, attrs.flags());
        }
        // The EXTENDED flag with a count of 0 reads as no extended attributes.
        let p = Packet { kind: packet_type::ATTRS, body: vec![0, 0, 0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0] };
        assert_eq!(Response::parse(&p), Ok(Response::Attrs { id: 1, attrs: Attrs::default() }));
    }

    #[test]
    fn packet_errors() {
        assert_eq!(Packet::parse(&[0, 0, 0, 0]), Err(PacketError::Empty));
        assert_eq!(Packet::parse(&[0, 4, 0, 1]), Err(PacketError::TooLong(0x40001)));
        assert_eq!(Packet::parse(&[0xff, 0xff, 0xff, 0xff]), Err(PacketError::TooLong(u32::MAX)));
        assert_eq!(Packet::parse(&[0, 4, 0, 0]), Ok(None));
        assert_eq!(Packet::parse_limited(&[0, 0, 0, 9], 8), Err(PacketError::TooLong(9)));
        assert_eq!(Packet::parse_limited(&[0, 0, 0, 8], 8), Ok(None));
        // A limit over MAX_PACKET counts as MAX_PACKET.
        assert_eq!(Packet::parse_limited(&[0, 4, 0, 1], usize::MAX), Err(PacketError::TooLong(0x40001)));
        assert_eq!(Packet::parse(&[0, 0, 0, 1, 7, 9]), Ok(Some((Packet { kind: 7, body: vec![] }, 5))));
        assert!(PacketError::Empty.to_string().contains("0"));
    }

    #[test]
    fn parse_errors() {
        let p = |kind: u8, body: &[u8]| Packet { kind, body: body.to_vec() };
        let t = packet_type::STAT;
        // Unknown types.
        assert_eq!(Request::parse(&p(0, &[])), Err(ParseError::UnknownType(0)));
        assert_eq!(Request::parse(&p(21, &[0, 0, 0, 1])), Err(ParseError::UnknownType(21)));
        assert_eq!(Request::parse(&p(packet_type::EXTENDED_REPLY, &[])), Err(ParseError::UnknownType(201)));
        assert_eq!(Response::parse(&p(100, &[])), Err(ParseError::UnknownType(100)));
        // Truncated: no id, a short path, a path length past the end.
        assert_eq!(Request::parse(&p(t, &[0, 0])), Err(ParseError::Truncated));
        assert_eq!(Request::parse(&p(t, &[0, 0, 0, 1, 0, 0])), Err(ParseError::Truncated));
        assert_eq!(Request::parse(&p(t, &[0, 0, 0, 1, 0, 0, 0, 2, b'/'])), Err(ParseError::Truncated));
        // Trailing bytes.
        assert_eq!(Request::parse(&p(t, &[0, 0, 0, 1, 0, 0, 0, 1, b'/', 0])), Err(ParseError::Trailing));
        assert_eq!(Response::parse(&p(packet_type::HANDLE, &[0, 0, 0, 1, 0, 0, 0, 0, 1])), Err(ParseError::Trailing));
        // Strings over their limits.
        let len = |n: usize| (n as u32).to_be_bytes();
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(&len(MAX_PATH + 1));
        body.extend(std::iter::repeat_n(b'a', MAX_PATH + 1));
        assert_eq!(Request::parse(&p(t, &body)), Err(ParseError::TooLong));
        body.truncate(4);
        body.extend_from_slice(&len(MAX_HANDLE + 1));
        assert_eq!(Request::parse(&p(packet_type::CLOSE, &body)), Err(ParseError::TooLong));
        body.truncate(4);
        body.extend_from_slice(&len(MAX_EXTENSION_NAME + 1));
        assert_eq!(Request::parse(&p(packet_type::EXTENDED, &body)), Err(ParseError::TooLong));
        let mut ext = vec![0, 0, 0, 1, 0, 0, 0, 1, b'x'];
        ext.resize(ext.len() + MAX_DATA + 1, 0);
        assert_eq!(Request::parse(&p(packet_type::EXTENDED, &ext)), Err(ParseError::TooLong));
        let mut reply = vec![0, 0, 0, 1];
        reply.resize(4 + MAX_DATA + 1, 0);
        assert_eq!(Response::parse(&p(packet_type::EXTENDED_REPLY, &reply)), Err(ParseError::TooLong));
        let mut data = vec![0, 0, 0, 1];
        data.extend_from_slice(&len(MAX_DATA + 1));
        assert_eq!(Response::parse(&p(packet_type::DATA, &data)), Err(ParseError::TooLong));
        let mut status = vec![0, 0, 0, 1, 0, 0, 0, 0];
        status.extend_from_slice(&len(MAX_TEXT + 1));
        assert_eq!(Response::parse(&p(packet_type::STATUS, &status)), Err(ParseError::TooLong));
        assert_eq!(Response::parse(&p(packet_type::STATUS, &[0, 0, 0, 1, 0, 0, 0, 0, 0])), Err(ParseError::Truncated));
        // Counts over their limits.
        let mut names = vec![0, 0, 0, 1];
        names.extend_from_slice(&len(MAX_NAMES + 1));
        assert_eq!(Response::parse(&p(packet_type::NAME, &names)), Err(ParseError::TooMany));
        let mut attrs = vec![0, 0, 0, 1, 0x80, 0, 0, 0];
        attrs.extend_from_slice(&len(MAX_ATTR_EXTENSIONS + 1));
        assert_eq!(Response::parse(&p(packet_type::ATTRS, &attrs)), Err(ParseError::TooMany));
        let mut init = vec![0, 0, 0, 3];
        for _ in 0..=MAX_EXTENSIONS {
            init.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        }
        // Extensions past the limit are skipped, not refused.
        let Ok(Request::Init { extensions, .. }) = Request::parse(&p(packet_type::INIT, &init)) else { panic!() };
        assert_eq!(extensions.len(), MAX_EXTENSIONS);
        // Attribute flags version 3 does not define.
        assert_eq!(
            Response::parse(&p(packet_type::ATTRS, &[0, 0, 0, 1, 0, 0, 0, 0x10])),
            Err(ParseError::AttrFlags(0x10))
        );
        assert!(ParseError::AttrFlags(0x10).to_string().contains("0x10"));
        // A body longer than a packet can hold.
        let huge = p(packet_type::EXTENDED_REPLY, &vec![0; MAX_PACKET]);
        assert_eq!(Response::parse(&huge), Err(ParseError::TooLong));
        assert_eq!(Request::parse(&Packet { kind: packet_type::EXTENDED, ..huge }), Err(ParseError::TooLong));
        // TooLong also covers raw data and whole bodies, not only strings.
        assert_eq!(ParseError::TooLong.to_string(), "a field or the body over its limit");
    }

    #[test]
    fn every_truncated_prefix() {
        let packets: Vec<(Packet, bool)> = requests()
            .iter()
            .map(|r| (r.to_packet(), true))
            .chain(responses().iter().map(|r| (r.to_packet(), false)))
            .collect();
        for (p, is_request) in &packets {
            let bytes = p.to_bytes();
            for n in 0..bytes.len() {
                assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{p:?} at {n}");
            }
            let parse = |q: &Packet| {
                if *is_request {
                    Request::parse(q).map(|r| r.to_packet())
                } else {
                    Response::parse(q).map(|r| r.to_packet())
                }
            };
            assert_eq!(parse(p).as_ref(), Ok(p));
            for n in 0..p.body.len() {
                let short = Packet { kind: p.kind, body: p.body[..n].to_vec() };
                // Bodies that end in a list or in raw data can stop early
                // and still be well formed, but never read as the whole
                // one. A STATUS may stop after its code, and then reads
                // with an empty message and language tag. The rest fail.
                let got = parse(&short);
                let short_status = p.kind == packet_type::STATUS && n == 8;
                if !short_status {
                    assert_ne!(got.as_ref(), Ok(p), "{p:?} at {n}");
                }
                let open_ended = matches!(
                    p.kind,
                    packet_type::INIT | packet_type::VERSION | packet_type::EXTENDED | packet_type::EXTENDED_REPLY
                );
                if !open_ended && !short_status {
                    assert!(got.is_err(), "{p:?} at {n}");
                }
            }
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = Request::Init { version: 3, extensions: vec![] }.to_bytes();
        let b = Request::Stat { id: 1, path: s(b"/etc/passwd") }.to_bytes();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::default();
        let mut got = Vec::new();
        for byte in &stream {
            assert_eq!(d.feed(std::slice::from_ref(byte)), 1);
            while let Some(p) = d.next_packet() {
                got.push(Request::parse(&p.unwrap()).unwrap());
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[1], Request::Stat { id: 1, path: s(b"/etc/passwd") });
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        assert_eq!(d.feed(&[0, 0, 0, 0, 1]), 5);
        assert_eq!(d.next_packet(), Some(Err(PacketError::Empty)));
        assert_eq!(d.feed(&a), a.len());
        assert_eq!(d.next_packet(), Some(Err(PacketError::Empty)));
        assert_eq!(d.buffered(), 0);
        // A decoder with a lower limit.
        let mut small = Decoder::with_limit(8);
        assert_eq!(small.feed(&b), LENGTH_LEN + 8);
        assert!(matches!(small.next_packet(), Some(Err(PacketError::TooLong(_)))));
        let mut half = Decoder::new();
        assert_eq!(half.feed(&b[..6]), 6);
        assert_eq!(half.next_packet(), None);
        assert_eq!(half.buffered(), 6);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        let one = Request::Readdir { id: 1, handle: s(b"d") }.to_bytes();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        let (mut rest, mut n) = (&stream[..], 0);
        while !rest.is_empty() {
            rest = &rest[d.feed(rest)..];
            while let Some(p) = d.next_packet() {
                p.unwrap();
                n += 1;
            }
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn writers_cap_what_they_write() {
        let check_req = |r: &Request| {
            let bytes = r.to_bytes();
            assert!(bytes.len() <= LENGTH_LEN + MAX_PACKET);
            let (p, _) = Packet::parse(&bytes).unwrap().unwrap();
            Request::parse(&p).unwrap()
        };
        let check_resp = |r: &Response| {
            let bytes = r.to_bytes();
            assert!(bytes.len() <= LENGTH_LEN + MAX_PACKET);
            let (p, _) = Packet::parse(&bytes).unwrap().unwrap();
            Response::parse(&p).unwrap()
        };
        let big = vec![b'a'; 2 * MAX_PACKET];
        let many_ext: Vec<Extension> =
            (0..200).map(|_| Extension { name: big[..1000].to_vec(), data: big[..5000].to_vec() }).collect();
        let big_attrs = Attrs { size: Some(1), extended: many_ext.clone(), ..full_attrs() };
        let Request::Write { handle, data, .. } =
            check_req(&Request::Write { id: 1, handle: big.clone(), offset: 0, data: big.clone() })
        else {
            panic!()
        };
        assert_eq!((handle.len(), data.len()), (MAX_HANDLE, MAX_DATA));
        let Request::Extended { name, data, .. } =
            check_req(&Request::Extended { id: 1, name: big.clone(), data: big.clone() })
        else {
            panic!()
        };
        assert_eq!((name.len(), data.len()), (MAX_EXTENSION_NAME, MAX_DATA));
        let Request::Open { path, attrs, .. } =
            check_req(&Request::Open { id: 1, path: big.clone(), flags: 0, attrs: big_attrs.clone() })
        else {
            panic!()
        };
        assert_eq!(path.len(), MAX_PATH);
        assert_eq!(attrs.extended.len(), MAX_ATTR_EXTENSIONS);
        assert_eq!(attrs.extended[0].name.len(), MAX_EXTENSION_NAME);
        assert_eq!(attrs.extended[0].data.len(), MAX_TEXT);
        check_req(&Request::Rename { id: 1, from: big.clone(), to: big.clone() });
        let Request::Init { extensions, .. } = check_req(&Request::Init { version: 3, extensions: many_ext.clone() })
        else {
            panic!()
        };
        assert_eq!(extensions.len(), MAX_EXTENSIONS);
        check_resp(&Response::Version { version: 3, extensions: many_ext.clone() });
        check_resp(&Response::Status { id: 1, status: Status::Failure, message: big.clone(), language: big.clone() });
        check_resp(&Response::Handle { id: 1, handle: big.clone() });
        check_resp(&Response::Data { id: 1, data: big.clone() });
        check_resp(&Response::ExtendedReply { id: 1, data: big.clone() });
        check_resp(&Response::Attrs { id: 1, attrs: big_attrs.clone() });
        // Big names: only some fit in one packet.
        let entry = NameEntry { filename: big.clone(), longname: big.clone(), attrs: big_attrs.clone() };
        let names = vec![entry; 50];
        let fit = names_that_fit(&names);
        assert!(fit > 0 && fit < 50, "{fit}");
        let Response::Name { names: back, .. } = check_resp(&Response::Name { id: 1, names: names.clone() }) else {
            panic!()
        };
        assert_eq!(back.len(), fit);
        // Small names: the count limit.
        let small = vec![NameEntry::default(); MAX_NAMES + 10];
        assert_eq!(names_that_fit(&small), MAX_NAMES);
        let Response::Name { names: back, .. } = check_resp(&Response::Name { id: 1, names: small }) else { panic!() };
        assert_eq!(back.len(), MAX_NAMES);
        assert_eq!(names_that_fit(&[]), 0);
        // A packet with a body too big is cut to fit.
        let p = Packet { kind: 9, body: big.clone() };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), LENGTH_LEN + MAX_PACKET);
        assert!(Packet::parse(&bytes).unwrap().is_some());
    }

    #[test]
    fn decoder_holds_at_most_one_packet() {
        // Feeding without taking packets out must not grow the buffer
        // past one packet of the decoder's limit.
        let one = Request::Readdir { id: 1, handle: s(b"d") }.to_bytes();
        let mut d = Decoder::with_limit(64);
        let mut taken = 0;
        for _ in 0..1000 {
            taken += d.feed(&one);
        }
        assert!(d.buffered() <= LENGTH_LEN + 64, "{}", d.buffered());
        assert_eq!(taken, d.buffered());
        // Feeding and taking out in turn reads every packet.
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 100).collect();
        let mut d = Decoder::with_limit(64);
        let (mut rest, mut n) = (&stream[..], 0);
        loop {
            let used = d.feed(rest);
            rest = &rest[used..];
            while let Some(p) = d.next_packet() {
                p.unwrap();
                n += 1;
            }
            if rest.is_empty() {
                break;
            }
            assert!(used > 0);
        }
        assert_eq!(n, 100);
        // A broken stream takes and drops every byte.
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[0, 0, 0, 0]), 4);
        assert_eq!(d.next_packet(), Some(Err(PacketError::Empty)));
        assert_eq!(d.feed(&[0; 100]), 100);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn status_text_is_cut_at_a_character() {
        let text = "a".repeat(MAX_TEXT - 1) + "\u{e9}";
        let resp = Response::status(1, Status::Failure, &text);
        let Response::Status { message, .. } = &resp else { panic!() };
        // The constructor copies no more than it writes.
        assert!(message.len() <= MAX_TEXT, "{}", message.len());
        let written = |r: &Response| {
            let Ok(Response::Status { message, language, .. }) = Response::parse(&r.to_packet()) else { panic!() };
            (message, language)
        };
        let (m, _) = written(&resp);
        assert_eq!(std::str::from_utf8(&m), Ok(&text[..MAX_TEXT - 1]));
        let long = Response::Status {
            id: 1,
            status: Status::Failure,
            message: text.clone().into_bytes(),
            language: text.clone().into_bytes(),
        };
        let (m, l) = written(&long);
        assert!(std::str::from_utf8(&m).is_ok() && std::str::from_utf8(&l).is_ok());
        assert_eq!(m.len(), MAX_TEXT - 1);
        // Four-byte characters, and a message that fits, are kept whole.
        let wide = "\u{1f600}".repeat(300);
        let (m, _) = written(&Response::status(1, Status::Failure, &wide));
        assert_eq!(m, wide.as_bytes()[..MAX_TEXT].to_vec());
        let (m, _) = written(&Response::status(1, Status::Ok, "\u{e9}t\u{e9}"));
        assert_eq!(m, "\u{e9}t\u{e9}".as_bytes());
        // Bytes that are not UTF-8 are cut at the limit.
        let bad = Response::Status { id: 1, status: Status::Ok, message: vec![0x80; 2000], language: vec![] };
        assert_eq!(written(&bad).0.len(), MAX_TEXT);
    }

    #[test]
    fn unknown_extensions_over_the_limits_are_skipped() {
        let mut body = vec![0, 0, 0, 3];
        let ext = |b: &mut Vec<u8>, name: &[u8], data_len: usize| {
            b.extend_from_slice(&(name.len() as u32).to_be_bytes());
            b.extend_from_slice(name);
            b.extend_from_slice(&(data_len as u32).to_be_bytes());
            b.extend(std::iter::repeat_n(b'z', data_len));
        };
        ext(&mut body, b"x@example.com", MAX_TEXT + 1);
        ext(&mut body, &[b'n'; MAX_EXTENSION_NAME + 1], 1);
        ext(&mut body, b"posix-rename@openssh.com", 1);
        for kind in [packet_type::INIT, packet_type::VERSION] {
            let p = Packet { kind, body: body.clone() };
            let kept = vec![Extension { name: s(b"posix-rename@openssh.com"), data: s(b"z") }];
            if kind == packet_type::INIT {
                assert_eq!(Request::parse(&p), Ok(Request::Init { version: 3, extensions: kept }));
            } else {
                assert_eq!(Response::parse(&p), Ok(Response::Version { version: 3, extensions: kept }));
            }
        }
        // Past MAX_EXTENSIONS, the rest are skipped too.
        let mut many = vec![0, 0, 0, 3];
        for _ in 0..MAX_EXTENSIONS + 5 {
            ext(&mut many, b"a", 0);
        }
        let Ok(Request::Init { extensions, .. }) = Request::parse(&Packet { kind: packet_type::INIT, body: many })
        else {
            panic!()
        };
        assert_eq!(extensions.len(), MAX_EXTENSIONS);
        // A pair that runs past the end is still an error.
        let mut cut = vec![0, 0, 0, 3];
        ext(&mut cut, b"a", 10);
        cut.truncate(cut.len() - 1);
        assert_eq!(Request::parse(&Packet { kind: packet_type::INIT, body: cut }), Err(ParseError::Truncated));
    }

    /// A deterministic generator, so a failure repeats.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
    }

    #[test]
    fn random_bytes_never_panic_and_round_trip() {
        let mut rng = Lcg(0x5f7f);
        let seeds: Vec<Vec<u8>> =
            requests().iter().map(|r| r.to_bytes()).chain(responses().iter().map(|r| r.to_bytes())).collect();
        for round in 0..6000 {
            // Half the inputs are mutated real packets, half are noise.
            let mut buf = if round % 2 == 0 {
                seeds[rng.next() as usize % seeds.len()].clone()
            } else {
                let len = rng.next() as usize % 64;
                (0..len).map(|_| rng.next() as u8).collect()
            };
            for _ in 0..rng.next() % 4 {
                if !buf.is_empty() {
                    let i = rng.next() as usize % buf.len();
                    buf[i] = rng.next() as u8;
                }
            }
            if rng.next().is_multiple_of(8) {
                let cut = rng.next() as usize % (buf.len() + 1);
                buf.truncate(cut);
            }
            // Whole, and a byte at a time.
            let mut whole = Decoder::new();
            assert_eq!(whole.feed(&buf), buf.len());
            let mut packets = Vec::new();
            while let Some(Ok(p)) = whole.next_packet() {
                packets.push(p);
            }
            let mut bytewise = Decoder::new();
            let mut again = Vec::new();
            for b in &buf {
                assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
                while let Some(Ok(p)) = bytewise.next_packet() {
                    again.push(p);
                }
            }
            assert_eq!(packets, again);
            for p in &packets {
                let bytes = p.to_bytes();
                assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
                if let Ok(req) = Request::parse(p) {
                    assert_eq!(Request::parse(&req.to_packet()), Ok(req));
                }
                if let Ok(resp) = Response::parse(p) {
                    assert_eq!(Response::parse(&resp.to_packet()), Ok(resp));
                }
            }
            // Any bytes as the body of every type.
            for kind in 0..=255u8 {
                let p = Packet { kind, body: buf.clone() };
                if let Ok(req) = Request::parse(&p) {
                    assert_eq!(Request::parse(&req.to_packet()), Ok(req));
                }
                if let Ok(resp) = Response::parse(&p) {
                    assert_eq!(Response::parse(&resp.to_packet()), Ok(resp));
                }
            }
        }
    }
}
