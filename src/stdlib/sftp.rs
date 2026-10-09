//! SFTP version 3: reading and writing packets, requests and responses,
//! with no I/O.
//!
//! A real client such as OpenSSH's sftp stops at SSH key exchange before it
//! can send SFTP requests, unless the world supplies an SSH transport and
//! channel from elsewhere.
//!
//! `Packet` implements `Wire` and supports `codec::Frames<Packet>`. Request and
//! response helpers interpret its payload. There is no file-transfer session,
//! filesystem `Service`, SSH channel implementation, or encrypted transport.
//!
//! SFTP is how most file transfers over SSH happen. The client opens an
//! SSH channel, asks for the `sftp` subsystem, and then sends requests
//! (open a file, read 32 KiB at an offset, list a directory) as packets.
//! The server answers each one by its request id. This module follows
//! draft-ietf-secsh-filexfer-02, which describes version 3, the version
//! OpenSSH and almost every other implementation speak.
//!
//! The stdlib provides no SSH channel; a world with an external SSH
//! transport passes bytes from its channel
//! to [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream), gets
//! [`Packet`]s back, reads each one's [`Request`], and writes the bytes of
//! a [`Response`] back to the channel. Which files exist, what they hold
//! and who may touch them is up to world code.
//!
//! Each field has a limit (see [`MAX_PATH`], [`MAX_DATA`] and the
//! others), and readers and writers refuse fields over their limits.
//! Writers leave the destination unchanged when a value cannot be written.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::sftp::{Attrs, Packet, Request, Response, Status, VERSION};
//! use fictionet::stdlib::codec::{Stream, Wire};
//!
//! /// A server holding one file, `/motd`, 12 bytes long.
//! fn answer(packet: &Packet) -> Response {
//!     match Request::from_packet(packet) {
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
//! let mut stream = Stream::new(Frames::<Packet>::new());
//! // INIT, version 3: length 5, type 1, then the version.
//! assert_eq!(stream.push(&[0, 0, 0, 5, 1, 0, 0, 0, 3]), 9);
//! let init = stream.next().unwrap().unwrap();
//! assert_eq!(answer(&init).to_bytes().unwrap(), [0, 0, 0, 5, 2, 0, 0, 0, 3]);
//!
//! // STAT /motd, request id 1.
//! let bytes = Request::Stat { id: 1, path: b"/motd".to_vec() }.to_bytes().unwrap();
//! assert_eq!(stream.push(&bytes), bytes.len());
//! let stat = stream.next().unwrap().unwrap();
//! assert_eq!(
//!     answer(&stat).to_bytes().unwrap(),
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

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Reader, Trailing, Truncated, Wire};

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
/// This is the default input capacity of [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames).
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
    /// INIT packet.
    pub const INIT: u8 = 1;
    /// VERSION packet.
    pub const VERSION: u8 = 2;
    /// OPEN packet.
    pub const OPEN: u8 = 3;
    /// CLOSE packet.
    pub const CLOSE: u8 = 4;
    /// READ packet.
    pub const READ: u8 = 5;
    /// WRITE packet.
    pub const WRITE: u8 = 6;
    /// LSTAT packet.
    pub const LSTAT: u8 = 7;
    /// FSTAT packet.
    pub const FSTAT: u8 = 8;
    /// SETSTAT packet.
    pub const SETSTAT: u8 = 9;
    /// FSETSTAT packet.
    pub const FSETSTAT: u8 = 10;
    /// OPENDIR packet.
    pub const OPENDIR: u8 = 11;
    /// READDIR packet.
    pub const READDIR: u8 = 12;
    /// REMOVE packet.
    pub const REMOVE: u8 = 13;
    /// MKDIR packet.
    pub const MKDIR: u8 = 14;
    /// RMDIR packet.
    pub const RMDIR: u8 = 15;
    /// REALPATH packet.
    pub const REALPATH: u8 = 16;
    /// STAT packet.
    pub const STAT: u8 = 17;
    /// RENAME packet.
    pub const RENAME: u8 = 18;
    /// READLINK packet.
    pub const READLINK: u8 = 19;
    /// SYMLINK packet.
    pub const SYMLINK: u8 = 20;
    /// STATUS packet.
    pub const STATUS: u8 = 101;
    /// HANDLE packet.
    pub const HANDLE: u8 = 102;
    /// DATA packet.
    pub const DATA: u8 = 103;
    /// NAME packet.
    pub const NAME: u8 = 104;
    /// ATTRS packet.
    pub const ATTRS: u8 = 105;
    /// EXTENDED packet.
    pub const EXTENDED: u8 = 200;
    /// EXTENDED_REPLY packet.
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

impl Packet {
    fn parse_prefix(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, Error> {
        let limit = limit.min(MAX_PACKET);
        let Some(head) = b.get(..LENGTH_LEN) else {
            return Ok(None);
        };
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let n = usize::try_from(length).unwrap_or(usize::MAX);
        if n == 0 {
            return Err(Error::Empty);
        }
        if n > limit {
            return Err(Error::PacketTooLong(length));
        }
        let Some(rest) = b.get(LENGTH_LEN..LENGTH_LEN + n) else {
            return Ok(None);
        };
        let packet = Packet {
            kind: rest[0],
            body: rest[1..].to_vec(),
        };
        Ok(Some((packet, LENGTH_LEN + n)))
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
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet. Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Packet::parse_prefix(b, MAX_PACKET)? {
            Some((packet, used)) if used == b.len() => Ok(packet),
            Some(_) => Err(Error::PacketTrailing),
            None => Err(Error::PacketTruncated),
        }
    }

    /// Appends at most [`MAX_FRAME`] bytes. Refuses oversized bodies
    /// with [`Error::Unwritable`] before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = self.body.len().saturating_add(1);
        let length = u32::try_from(len).map_err(|_| Error::Unwritable)?;
        if len > MAX_PACKET {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&length.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Reads SFTP packets without holding input bytes.
    ///
    /// Use with [`codec::Stream`](fictionet::stdlib::codec::Stream) for a buffer bounded
    /// by [`LENGTH_LEN`] plus [`limit`](fictionet::stdlib::codec::Frames::limit). Oversized packets are
    /// refused from the length field. Partial packets return [`fictionet::stdlib::codec::Step::Need`],
    /// including at EOF, so the stream reports truncation. Packet bodies
    /// remain bytes for [`Request::from_packet`] or [`Response::from_packet`].
    Packet => (Packet, Error, usize);
    name = "SFTP";
    default { MAX_PACKET }
    normalize(limit) { limit.min(MAX_PACKET) }
    capacity(limit) { let limit = *limit;
        LENGTH_LEN.saturating_add(limit) }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        Packet::parse_prefix(input, limit)
    }
}

/// Why bytes are not an SFTP packet, why a packet's body is not the
/// request or response its type says, or why a value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The length field was 0, so there is no type byte. The channel
    /// holds no more packets a reader can find, and a real server closes
    /// it.
    Empty,
    /// The length field was over the limit. As with [`Error::Empty`], a
    /// real server closes the channel.
    PacketTooLong(u32),
    /// The input ended before a complete packet, including empty input.
    PacketTruncated,
    /// Bytes follow the first complete packet.
    PacketTrailing,
    /// The type is not one this reader knows: a response type given to
    /// [`Request::from_packet`], a request type given to [`Response::from_packet`], or
    /// a number version 3 does not define.
    UnknownType(u8),
    /// The value cannot be written without changing it.
    Unwritable,
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

impl Error {
    /// The status a server answers a request it cannot read with:
    /// [`Status::OpUnsupported`] for an unknown type and
    /// [`Status::BadMessage`] for the rest.
    pub fn status(self) -> Status {
        match self {
            Error::UnknownType(_) => Status::OpUnsupported,
            _ => Status::BadMessage,
        }
    }
}

fictionet::error_display!(Error, f, {
    Error::Empty => f.write_str("packet length 0, with no type byte"),
    Error::PacketTooLong(n) => write!(f, "packet length {n}, over the limit"),
    Error::PacketTruncated => f.write_str("input ended before a complete SFTP packet"),
    Error::PacketTrailing => f.write_str("bytes follow the SFTP packet"),
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
    Error::UnknownType(t) => write!(f, "packet type {t} is not known here"),
    Error::Truncated => f.write_str("the packet ended inside a field"),
    Error::Trailing => f.write_str("bytes after the last field"),
    Error::TooLong => f.write_str("a field or the body over its limit"),
    Error::TooMany => f.write_str("a count over its limit"),
    Error::AttrFlags(x) => write!(f, "attribute flags {x:#x} are not defined in version 3"),
});

fictionet::open_enum! {
    /// The status codes a STATUS response carries.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Status: u32 {
        /// The request succeeded.
        Ok = 0,
        /// A read or READDIR reached the end: there is no more data or no
        /// more names.
        Eof = 1,
        /// The file or directory does not exist.
        NoSuchFile = 2,
        /// The user may not do this.
        PermissionDenied = 3,
        /// The request failed for a reason no other code covers.
        Failure = 4,
        /// The packet was badly formed.
        BadMessage = 5,
        /// There is no connection to the server. Only a client makes this up.
        NoConnection = 6,
        /// The connection to the server was lost. Only a client makes this up.
        ConnectionLost = 7,
        /// The server does not support the operation.
        OpUnsupported = 8,
        ;
        /// Any code above 8. Writers refuse codes named by another variant.
        Other,
    }
    [
        /// The status code's number.
    ] [
        /// The status for code `c`.
    ]
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
    /// Extended attributes. At most [`MAX_ATTR_EXTENSIONS`] may be written.
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

    fn read(r: &mut Reader<'_>) -> Result<Attrs, Error> {
        let flags = r.u32_be()?;
        if flags & !attr_flags::ALL != 0 {
            return Err(Error::AttrFlags(flags));
        }
        let mut a = Attrs::default();
        if flags & attr_flags::SIZE != 0 {
            a.size = Some(r.u64_be()?);
        }
        if flags & attr_flags::UIDGID != 0 {
            a.uid_gid = Some((r.u32_be()?, r.u32_be()?));
        }
        if flags & attr_flags::PERMISSIONS != 0 {
            a.permissions = Some(r.u32_be()?);
        }
        if flags & attr_flags::ACMODTIME != 0 {
            a.times = Some((r.u32_be()?, r.u32_be()?));
        }
        if flags & attr_flags::EXTENDED != 0 {
            let count = r.u32_be()?;
            if usize::try_from(count).map_or(true, |c| c > MAX_ATTR_EXTENSIONS) {
                return Err(Error::TooMany);
            }
            for _ in 0..count {
                a.extended.push(r.extension()?);
            }
        }
        Ok(a)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.extended.len() > MAX_ATTR_EXTENSIONS {
            return Err(Error::Unwritable);
        }
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
            let ext = &self.extended;
            put_u32(out, ext.len() as u32);
            for e in ext {
                put_extension(out, e)?;
            }
        }
        Ok(())
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
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        put_str(out, &self.filename, MAX_PATH)?;
        put_str(out, &self.longname, MAX_PATH)?;
        self.attrs.encode(out)?;
        Ok(())
    }
}

/// How many entries from the start of `names` fit in one NAME response.
/// Stops at the first entry that cannot be written unchanged or would
/// exceed [`MAX_PACKET`], and never counts more than [`MAX_NAMES`].
/// A server can send the remaining entries in a later READDIR response.
pub fn names_that_fit(names: &[NameEntry]) -> usize {
    // The type byte, request id, and entry count.
    let mut used = 1usize + 4 + 4;
    let mut entry = Vec::new();
    for (i, name) in names.iter().take(MAX_NAMES).enumerate() {
        entry.clear();
        if name.encode(&mut entry).is_err() {
            return i;
        }
        let Some(total) = used.checked_add(entry.len()).filter(|&n| n <= MAX_PACKET) else {
            return i;
        };
        used = total;
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
    Init {
        version: u32,
        extensions: Vec<Extension>,
    },
    /// OPEN: open the file at `path` with [`open_flags`] `flags`, and set
    /// `attrs` if it is created. Answered with HANDLE or STATUS.
    Open {
        id: u32,
        path: Vec<u8>,
        flags: u32,
        attrs: Attrs,
    },
    /// CLOSE: close `handle`. Answered with STATUS.
    Close { id: u32, handle: Vec<u8> },
    /// READ: read up to `len` bytes at `offset`. Answered with DATA, or
    /// STATUS (EOF at the end of the file).
    Read {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        len: u32,
    },
    /// WRITE: write `data` at `offset`. Answered with STATUS.
    Write {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        data: Vec<u8>,
    },
    /// LSTAT: the attributes of `path`, not following a final symbolic
    /// link. Answered with ATTRS or STATUS.
    Lstat { id: u32, path: Vec<u8> },
    /// FSTAT: the attributes of the open file `handle`. Answered with
    /// ATTRS or STATUS.
    Fstat { id: u32, handle: Vec<u8> },
    /// SETSTAT: set `attrs` on `path`. Answered with STATUS.
    Setstat {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
    /// FSETSTAT: set `attrs` on the open file `handle`. Answered with
    /// STATUS.
    Fsetstat {
        id: u32,
        handle: Vec<u8>,
        attrs: Attrs,
    },
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
    Mkdir {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
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
    Symlink {
        id: u32,
        linkpath: Vec<u8>,
        targetpath: Vec<u8>,
    },
    /// EXTENDED: the request `name` (such as `statvfs@openssh.com`), with
    /// `data` laid out as that request defines. Answered with
    /// EXTENDED_REPLY or STATUS.
    Extended {
        id: u32,
        name: Vec<u8>,
        data: Vec<u8>,
    },
}

impl Request {
    /// Reads the request in `packet`. A server answers a request it cannot
    /// read with the status [`Error::status`] gives, using
    /// [`Packet::id`] for the id.
    pub fn from_packet(packet: &Packet) -> Result<Request, Error> {
        use packet_type as t;
        let mut r = packet_reader(packet)?;
        if packet.kind == t::INIT {
            let version = r.u32_be()?;
            let extensions = r.extensions()?;
            return Ok(Request::Init {
                version,
                extensions,
            });
        }
        if !matches!(packet.kind, t::OPEN..=t::SYMLINK | t::EXTENDED) {
            return Err(Error::UnknownType(packet.kind));
        }
        let id = r.u32_be()?;
        let req = match packet.kind {
            t::OPEN => Request::Open {
                id,
                path: r.path()?,
                flags: r.u32_be()?,
                attrs: Attrs::read(&mut r)?,
            },
            t::CLOSE => Request::Close {
                id,
                handle: r.handle()?,
            },
            t::READ => Request::Read {
                id,
                handle: r.handle()?,
                offset: r.u64_be()?,
                len: r.u32_be()?,
            },
            t::WRITE => Request::Write {
                id,
                handle: r.handle()?,
                offset: r.u64_be()?,
                data: r.string(MAX_DATA)?,
            },
            t::LSTAT => Request::Lstat {
                id,
                path: r.path()?,
            },
            t::FSTAT => Request::Fstat {
                id,
                handle: r.handle()?,
            },
            t::SETSTAT => Request::Setstat {
                id,
                path: r.path()?,
                attrs: Attrs::read(&mut r)?,
            },
            t::FSETSTAT => Request::Fsetstat {
                id,
                handle: r.handle()?,
                attrs: Attrs::read(&mut r)?,
            },
            t::OPENDIR => Request::Opendir {
                id,
                path: r.path()?,
            },
            t::READDIR => Request::Readdir {
                id,
                handle: r.handle()?,
            },
            t::REMOVE => Request::Remove {
                id,
                path: r.path()?,
            },
            t::MKDIR => Request::Mkdir {
                id,
                path: r.path()?,
                attrs: Attrs::read(&mut r)?,
            },
            t::RMDIR => Request::Rmdir {
                id,
                path: r.path()?,
            },
            t::REALPATH => Request::Realpath {
                id,
                path: r.path()?,
            },
            t::STAT => Request::Stat {
                id,
                path: r.path()?,
            },
            t::RENAME => Request::Rename {
                id,
                from: r.path()?,
                to: r.path()?,
            },
            t::READLINK => Request::Readlink {
                id,
                path: r.path()?,
            },
            t::SYMLINK => Request::Symlink {
                id,
                linkpath: r.path()?,
                targetpath: r.path()?,
            },
            _ => {
                let name = r.string(MAX_EXTENSION_NAME)?;
                let data = r.rest();
                if data.len() > MAX_DATA {
                    return Err(Error::TooLong);
                }
                Request::Extended {
                    id,
                    name,
                    data: data.to_vec(),
                }
            }
        };
        r.finish()?;
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

    /// Builds the request packet. Refuses fields or lists over their limits.
    pub fn to_packet(&self) -> Result<Packet, Error> {
        let mut b = Vec::new();
        if let Some(id) = self.id() {
            put_u32(&mut b, id);
        }
        match self {
            Request::Init {
                version,
                extensions,
            } => {
                put_u32(&mut b, *version);
                put_extensions(&mut b, extensions)?;
            }
            Request::Open {
                path, flags, attrs, ..
            } => {
                put_str(&mut b, path, MAX_PATH)?;
                put_u32(&mut b, *flags);
                attrs.encode(&mut b)?;
            }
            Request::Close { handle, .. }
            | Request::Fstat { handle, .. }
            | Request::Readdir { handle, .. } => {
                put_str(&mut b, handle, MAX_HANDLE)?;
            }
            Request::Read {
                handle,
                offset,
                len,
                ..
            } => {
                put_str(&mut b, handle, MAX_HANDLE)?;
                b.extend_from_slice(&offset.to_be_bytes());
                put_u32(&mut b, *len);
            }
            Request::Write {
                handle,
                offset,
                data,
                ..
            } => {
                put_str(&mut b, handle, MAX_HANDLE)?;
                b.extend_from_slice(&offset.to_be_bytes());
                put_str(&mut b, data, MAX_DATA)?;
            }
            Request::Lstat { path, .. }
            | Request::Opendir { path, .. }
            | Request::Remove { path, .. }
            | Request::Rmdir { path, .. }
            | Request::Realpath { path, .. }
            | Request::Stat { path, .. }
            | Request::Readlink { path, .. } => put_str(&mut b, path, MAX_PATH)?,
            Request::Setstat { path, attrs, .. } | Request::Mkdir { path, attrs, .. } => {
                put_str(&mut b, path, MAX_PATH)?;
                attrs.encode(&mut b)?;
            }
            Request::Fsetstat { handle, attrs, .. } => {
                put_str(&mut b, handle, MAX_HANDLE)?;
                attrs.encode(&mut b)?;
            }
            Request::Rename { from: a, to: z, .. }
            | Request::Symlink {
                linkpath: a,
                targetpath: z,
                ..
            } => {
                put_str(&mut b, a, MAX_PATH)?;
                put_str(&mut b, z, MAX_PATH)?;
            }
            Request::Extended { name, data, .. } => {
                put_str(&mut b, name, MAX_EXTENSION_NAME)?;
                put_raw(&mut b, data, MAX_DATA)?;
            }
        }
        if b.len() >= MAX_PACKET {
            return Err(Error::Unwritable);
        }
        Ok(Packet {
            kind: self.kind(),
            body: b,
        })
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
    Version {
        version: u32,
        extensions: Vec<Extension>,
    },
    /// STATUS: how a request ended, with a `message` for people to read
    /// and the `language` tag it is written in. Both may be empty.
    Status {
        id: u32,
        status: Status,
        message: Vec<u8>,
        language: Vec<u8>,
    },
    /// HANDLE: the `handle` of a file or directory just opened.
    Handle { id: u32, handle: Vec<u8> },
    /// DATA: bytes read from a file.
    Data { id: u32, data: Vec<u8> },
    /// NAME: names, for READDIR, REALPATH and READLINK. The list must fit
    /// within one packet and contain at most [`MAX_NAMES`] entries.
    Name { id: u32, names: Vec<NameEntry> },
    /// ATTRS: a file's attributes, for STAT, LSTAT and FSTAT.
    Attrs { id: u32, attrs: Attrs },
    /// EXTENDED_REPLY: the answer to an EXTENDED request, laid out as that
    /// request defines.
    ExtendedReply { id: u32, data: Vec<u8> },
}

impl Response {
    /// A STATUS response with the complete message and an English language tag.
    /// Writing refuses a message over [`MAX_TEXT`] bytes.
    pub fn status(id: u32, status: Status, message: &str) -> Response {
        let message = message.as_bytes().to_vec();
        Response::Status {
            id,
            status,
            message,
            language: b"en".to_vec(),
        }
    }

    /// Reads the response in `packet`. A STATUS that stops after its code,
    /// as some old servers send, reads with an empty message and language
    /// tag.
    pub fn from_packet(packet: &Packet) -> Result<Response, Error> {
        use packet_type as t;
        let mut r = packet_reader(packet)?;
        let resp = match packet.kind {
            t::VERSION => {
                let version = r.u32_be()?;
                let extensions = r.extensions()?;
                return Ok(Response::Version {
                    version,
                    extensions,
                });
            }
            t::STATUS => {
                let (id, status) = (r.u32_be()?, Status::from_code(r.u32_be()?));
                if r.is_empty() {
                    return Ok(Response::Status {
                        id,
                        status,
                        message: Vec::new(),
                        language: Vec::new(),
                    });
                }
                Response::Status {
                    id,
                    status,
                    message: r.string(MAX_TEXT)?,
                    language: r.string(MAX_TEXT)?,
                }
            }
            t::HANDLE => Response::Handle {
                id: r.u32_be()?,
                handle: r.handle()?,
            },
            t::DATA => Response::Data {
                id: r.u32_be()?,
                data: r.string(MAX_DATA)?,
            },
            t::NAME => {
                let (id, count) = (r.u32_be()?, r.u32_be()?);
                if usize::try_from(count).map_or(true, |c| c > MAX_NAMES) {
                    return Err(Error::TooMany);
                }
                let mut names = Vec::new();
                for _ in 0..count {
                    let (filename, longname) = (r.path()?, r.path()?);
                    names.push(NameEntry {
                        filename,
                        longname,
                        attrs: Attrs::read(&mut r)?,
                    });
                }
                Response::Name { id, names }
            }
            t::ATTRS => Response::Attrs {
                id: r.u32_be()?,
                attrs: Attrs::read(&mut r)?,
            },
            t::EXTENDED_REPLY => {
                let id = r.u32_be()?;
                let data = r.rest();
                if data.len() > MAX_DATA {
                    return Err(Error::TooLong);
                }
                Response::ExtendedReply {
                    id,
                    data: data.to_vec(),
                }
            }
            k => return Err(Error::UnknownType(k)),
        };
        r.finish()?;
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

    /// Builds the response packet. Refuses fields or lists over their limits.
    pub fn to_packet(&self) -> Result<Packet, Error> {
        let mut b = Vec::new();
        if let Some(id) = self.id() {
            put_u32(&mut b, id);
        }
        match self {
            Response::Version {
                version,
                extensions,
            } => {
                put_u32(&mut b, *version);
                put_extensions(&mut b, extensions)?;
            }
            Response::Status {
                status,
                message,
                language,
                ..
            } => {
                if matches!(status, Status::Other(0..=8)) {
                    return Err(Error::Unwritable);
                }
                put_u32(&mut b, status.code());
                put_str(&mut b, message, MAX_TEXT)?;
                put_str(&mut b, language, MAX_TEXT)?;
            }
            Response::Handle { handle, .. } => put_str(&mut b, handle, MAX_HANDLE)?,
            Response::Data { data, .. } => put_str(&mut b, data, MAX_DATA)?,
            Response::Name { names, .. } => {
                if names.len() > MAX_NAMES {
                    return Err(Error::Unwritable);
                }
                put_u32(&mut b, names.len() as u32);
                for n in names {
                    n.encode(&mut b)?;
                }
            }
            Response::Attrs { attrs, .. } => attrs.encode(&mut b)?,
            Response::ExtendedReply { data, .. } => put_raw(&mut b, data, MAX_DATA)?,
        }
        if b.len() >= MAX_PACKET {
            return Err(Error::Unwritable);
        }
        Ok(Packet {
            kind: self.kind(),
            body: b,
        })
    }
}

trait ReadFields<'a> {
    fn string(&mut self, max: usize) -> Result<Vec<u8>, Error>;
    fn path(&mut self) -> Result<Vec<u8>, Error>;
    fn handle(&mut self) -> Result<Vec<u8>, Error>;
    fn extension(&mut self) -> Result<Extension, Error>;
    fn raw_string(&mut self) -> Result<&'a [u8], Error>;
    fn extensions(&mut self) -> Result<Vec<Extension>, Error>;
}

impl<'a> ReadFields<'a> for Reader<'a> {
    /// A string: a 4-byte length, then that many bytes, at most `max`.
    fn string(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let n = usize::try_from(self.u32_be()?).unwrap_or(usize::MAX);
        if n > max {
            return Err(Error::TooLong);
        }
        Ok(self.take(n)?.to_vec())
    }

    fn path(&mut self) -> Result<Vec<u8>, Error> {
        self.string(MAX_PATH)
    }

    fn handle(&mut self) -> Result<Vec<u8>, Error> {
        self.string(MAX_HANDLE)
    }

    fn extension(&mut self) -> Result<Extension, Error> {
        Ok(Extension {
            name: self.string(MAX_EXTENSION_NAME)?,
            data: self.string(MAX_TEXT)?,
        })
    }

    /// A string of any length that fits in the body, not copied.
    fn raw_string(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.u32_be()?).unwrap_or(usize::MAX);
        self.take(n).map_err(Error::from)
    }

    /// Extension pairs up to the end of the body. The specification says
    /// to ignore extensions a reader does not know, so a pair over a
    /// limit, or past the first [`MAX_EXTENSIONS`], is skipped rather
    /// than refused. The body bounds what is read.
    fn extensions(&mut self) -> Result<Vec<Extension>, Error> {
        let mut out = Vec::new();
        while !self.is_empty() {
            let (name, data) = (self.raw_string()?, self.raw_string()?);
            if out.len() < MAX_EXTENSIONS
                && name.len() <= MAX_EXTENSION_NAME
                && data.len() <= MAX_TEXT
            {
                out.push(Extension {
                    name: name.to_vec(),
                    data: data.to_vec(),
                });
            }
        }
        Ok(out)
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_raw(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), Error> {
    if bytes.len() > max || bytes.len() > (MAX_PACKET - 1).saturating_sub(out.len()) {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_str(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), Error> {
    if bytes.len() > max
        || bytes.len().saturating_add(4) > (MAX_PACKET - 1).saturating_sub(out.len())
    {
        return Err(Error::Unwritable);
    }
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_extension(out: &mut Vec<u8>, extension: &Extension) -> Result<(), Error> {
    put_str(out, &extension.name, MAX_EXTENSION_NAME)?;
    put_str(out, &extension.data, MAX_TEXT)
}

fn put_extensions(out: &mut Vec<u8>, extensions: &[Extension]) -> Result<(), Error> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(Error::Unwritable);
    }
    for extension in extensions {
        put_extension(out, extension)?;
    }
    Ok(())
}

macro_rules! packet_wire {
    ($($ty:ty),+ $(,)?) => {$ (
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            /// Reads exactly one packet. Refuses incomplete or trailing bytes,
            /// unknown packet types, and fields beyond their protocol limits.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_packet(&Packet::parse(bytes)?)
            }

            /// Appends a complete packet. Refuses oversized fields or lists
            /// and status codes that would change the value when read back.
            /// Leaves the destination unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                self.to_packet()?.write(out).map_err(|_| Error::Unwritable)
            }
        }
    )+};
}
packet_wire!(Request, Response);

impl Wire for Attrs {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads attributes. Refuses unknown flags, excess fields, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let value = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }

    /// Appends attributes. Refuses oversized extension fields or lists.
    /// Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

fictionet::codec_from!(Error, Truncated, |_| Error::Truncated);

fictionet::codec_from!(Error, Trailing, |_| Error::Trailing);

fn packet_reader(packet: &Packet) -> Result<Reader<'_>, Error> {
    if packet.body.len() >= MAX_PACKET {
        return Err(Error::TooLong);
    }
    Ok(Reader::new(&packet.body))
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{Packet, Request, Response};
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    /// Checks typed packet readers and writers.
    pub fn check_packet(packet: &Packet) {
        if let Ok(request) = Request::from_packet(packet) {
            assert!(request.to_bytes().is_ok(), "{request:?}");
            contract::check_wire_value(&request);
        }
        if let Ok(response) = Response::from_packet(packet) {
            assert!(response.to_bytes().is_ok(), "{response:?}");
            contract::check_wire_value(&response);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::harness::check_packet;
    use super::*;
    use fictionet::stdlib::codec::{Decode, Step};
    use fictionet::stdlib::codec::{Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn s(v: &[u8]) -> Vec<u8> {
        v.to_vec()
    }

    fn full_attrs() -> Attrs {
        Attrs {
            size: Some(0x0102_0304_0506_0708),
            uid_gid: Some((1000, 100)),
            permissions: Some(0o100644),
            times: Some((1_700_000_000, 1_700_000_001)),
            extended: vec![Extension {
                name: s(b"x@example.com"),
                data: s(b"v"),
            }],
        }
    }

    fn requests() -> Vec<Request> {
        let a = full_attrs();
        let h = s(b"h1");
        vec![
            Request::Init {
                version: 3,
                extensions: vec![],
            },
            Request::Init {
                version: 6,
                extensions: vec![Extension {
                    name: s(b"a@b"),
                    data: s(b"1"),
                }],
            },
            Request::Open {
                id: 1,
                path: s(b"/f"),
                flags: open_flags::READ | open_flags::WRITE,
                attrs: a.clone(),
            },
            Request::Open {
                id: 1,
                path: s(b"/f"),
                flags: open_flags::READ,
                attrs: Attrs::default(),
            },
            Request::Close {
                id: 2,
                handle: h.clone(),
            },
            Request::Read {
                id: 3,
                handle: h.clone(),
                offset: 1 << 40,
                len: 32768,
            },
            Request::Write {
                id: 4,
                handle: h.clone(),
                offset: 7,
                data: s(b"hello"),
            },
            Request::Lstat {
                id: 5,
                path: s(b"/l"),
            },
            Request::Fstat {
                id: 6,
                handle: h.clone(),
            },
            Request::Setstat {
                id: 7,
                path: s(b"/s"),
                attrs: a.clone(),
            },
            Request::Fsetstat {
                id: 8,
                handle: h.clone(),
                attrs: a.clone(),
            },
            Request::Opendir {
                id: 9,
                path: s(b"/"),
            },
            Request::Readdir {
                id: 10,
                handle: h.clone(),
            },
            Request::Remove {
                id: 11,
                path: s(b"/r"),
            },
            Request::Mkdir {
                id: 12,
                path: s(b"/d"),
                attrs: Attrs {
                    permissions: Some(0o755),
                    ..Attrs::default()
                },
            },
            Request::Rmdir {
                id: 13,
                path: s(b"/d"),
            },
            Request::Realpath {
                id: 14,
                path: s(b"."),
            },
            Request::Stat {
                id: 15,
                path: s(b"/s"),
            },
            Request::Rename {
                id: 16,
                from: s(b"/a"),
                to: s(b"/b"),
            },
            Request::Readlink {
                id: 17,
                path: s(b"/ln"),
            },
            Request::Symlink {
                id: 18,
                linkpath: s(b"/ln"),
                targetpath: s(b"/t"),
            },
            Request::Extended {
                id: 19,
                name: s(b"statvfs@openssh.com"),
                data: s(b"\0\0\0\x01/"),
            },
            Request::Extended {
                id: 20,
                name: s(b"x"),
                data: vec![],
            },
        ]
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Version {
                version: 3,
                extensions: vec![],
            },
            Response::Version {
                version: 3,
                extensions: vec![
                    Extension {
                        name: s(b"posix-rename@openssh.com"),
                        data: s(b"1"),
                    },
                    Extension {
                        name: s(b"statvfs@openssh.com"),
                        data: s(b"2"),
                    },
                ],
            },
            Response::status(1, Status::Ok, "Success"),
            Response::Status {
                id: 2,
                status: Status::Other(99),
                message: vec![],
                language: vec![],
            },
            Response::Handle {
                id: 3,
                handle: s(b"\0\0\0\x01"),
            },
            Response::Data {
                id: 4,
                data: s(b"file contents"),
            },
            Response::Data {
                id: 4,
                data: vec![],
            },
            Response::Name {
                id: 5,
                names: vec![],
            },
            Response::Name {
                id: 6,
                names: vec![
                    NameEntry {
                        filename: s(b"a"),
                        longname: s(b"-rw-r--r-- 1 u g 0 Jan 1 a"),
                        attrs: full_attrs(),
                    },
                    NameEntry {
                        filename: s(b"b"),
                        longname: vec![],
                        attrs: Attrs::default(),
                    },
                ],
            },
            Response::Attrs {
                id: 7,
                attrs: full_attrs(),
            },
            Response::Attrs {
                id: 7,
                attrs: Attrs {
                    size: Some(1),
                    ..Attrs::default()
                },
            },
            Response::ExtendedReply {
                id: 8,
                data: s(b"anything"),
            },
        ]
    }

    // Layouts from draft-ietf-secsh-filexfer-02, sections 3 to 7.

    #[test]
    fn init_and_version_bytes() {
        let init = Request::Init {
            version: 3,
            extensions: vec![],
        };
        assert_eq!(init.to_bytes().unwrap(), [0, 0, 0, 5, 1, 0, 0, 0, 3]);
        let v = Response::Version {
            version: 3,
            extensions: vec![Extension {
                name: s(b"a"),
                data: s(b"bc"),
            }],
        };
        assert_eq!(
            v.to_bytes().unwrap(),
            [
                0, 0, 0, 16, 2, 0, 0, 0, 3, 0, 0, 0, 1, b'a', 0, 0, 0, 2, b'b', b'c'
            ]
        );
        assert_eq!(v.id(), None);
        assert_eq!(
            Packet {
                kind: 1,
                body: vec![0, 0, 0, 3]
            }
            .id(),
            None
        );
    }

    #[test]
    fn open_bytes() {
        let req = Request::Open {
            id: 0x0a0b0c0d,
            path: s(b"/x"),
            flags: open_flags::WRITE | open_flags::CREAT | open_flags::TRUNC,
            attrs: Attrs {
                permissions: Some(0o644),
                ..Attrs::default()
            },
        };
        let bytes = [
            0, 0, 0, 23, 3, 0x0a, 0x0b, 0x0c, 0x0d, 0, 0, 0, 2, b'/', b'x', 0, 0, 0, 0x1a, 0, 0, 0,
            4, 0, 0, 0x01, 0xa4,
        ];
        assert_eq!(req.to_bytes().unwrap(), bytes);
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.id(), Some(0x0a0b0c0d));
        assert_eq!(Request::from_packet(&p), Ok(req));
    }

    #[test]
    fn read_status_and_attrs_bytes() {
        let req = Request::Read {
            id: 1,
            handle: s(b"h"),
            offset: 0x100,
            len: 0x8000,
        };
        assert_eq!(
            req.to_packet().unwrap().body,
            [
                0, 0, 0, 1, 0, 0, 0, 1, b'h', 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x80, 0
            ]
        );
        let eof = Response::status(1, Status::Eof, "");
        assert_eq!(
            eof.to_packet().unwrap().body,
            [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, b'e', b'n']
        );
        // A STATUS with no message and no language tag, as old servers send.
        let short = Packet {
            kind: packet_type::STATUS,
            body: vec![0, 0, 0, 1, 0, 0, 0, 2],
        };
        assert_eq!(
            Response::from_packet(&short),
            Ok(Response::Status {
                id: 1,
                status: Status::NoSuchFile,
                message: vec![],
                language: vec![]
            })
        );
        let attrs = full_attrs();
        let mut body = Vec::new();
        attrs.write(&mut body).unwrap();
        assert_eq!(&body[..4], &[0x80, 0, 0, 0x0f]);
        assert_eq!(body.len(), 4 + 8 + 8 + 4 + 8 + 4 + (4 + 13) + (4 + 1));
    }

    #[test]
    fn requests_round_trip() {
        for req in requests() {
            let bytes = req.to_bytes().unwrap();
            let p = Packet::parse(&bytes).unwrap();
            assert_eq!(p.kind, req.kind());
            assert_eq!(p.id(), req.id());
            assert_eq!(Request::from_packet(&p).as_ref(), Ok(&req), "{req:?}");
            // A request is not a response.
            assert_eq!(Response::from_packet(&p), Err(Error::UnknownType(p.kind)));
        }
    }

    #[test]
    fn responses_round_trip() {
        for resp in responses() {
            let bytes = resp.to_bytes().unwrap();
            let p = Packet::parse(&bytes).unwrap();
            assert_eq!(p.kind, resp.kind());
            assert_eq!(p.id(), resp.id());
            assert_eq!(Response::from_packet(&p).as_ref(), Ok(&resp), "{resp:?}");
            assert_eq!(Request::from_packet(&p), Err(Error::UnknownType(p.kind)));
        }
    }

    #[test]
    fn status_codes() {
        for c in 0..=300u32 {
            assert_eq!(Status::from_code(c).code(), c);
        }
        assert_eq!(Status::from_code(u32::MAX).code(), u32::MAX);
        assert_eq!(Status::from_code(8), Status::OpUnsupported);
        for code in 0..=8 {
            let response = Response::Status {
                id: 1,
                status: Status::Other(code),
                message: vec![],
                language: vec![],
            };
            assert_eq!(response.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&response);
        }
        assert_eq!(Status::NoSuchFile.to_string(), "no such file");
        assert_eq!(Error::UnknownType(77).status(), Status::OpUnsupported);
        assert_eq!(Error::Truncated.status(), Status::BadMessage);
    }

    #[test]
    fn every_attribute_combination() {
        for mask in 0..32u32 {
            let attrs = Attrs {
                size: (mask & 1 != 0).then_some(5),
                uid_gid: (mask & 2 != 0).then_some((1, 2)),
                permissions: (mask & 4 != 0).then_some(0o40755),
                times: (mask & 8 != 0).then_some((3, 4)),
                extended: if mask & 16 != 0 {
                    vec![Extension::default()]
                } else {
                    vec![]
                },
            };
            let resp = Response::Attrs {
                id: mask,
                attrs: attrs.clone(),
            };
            let p = resp.to_packet().unwrap();
            assert_eq!(Response::from_packet(&p), Ok(resp));
            let flags = u32::from_be_bytes([p.body[4], p.body[5], p.body[6], p.body[7]]);
            assert_eq!(flags, attrs.flags());
        }
        // The EXTENDED flag with a count of 0 reads as no extended attributes.
        let p = Packet {
            kind: packet_type::ATTRS,
            body: vec![0, 0, 0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            Response::from_packet(&p),
            Ok(Response::Attrs {
                id: 1,
                attrs: Attrs::default()
            })
        );
    }

    #[test]
    fn packet_errors() {
        for (bytes, error) in [
            (&[0, 0, 0, 0][..], Error::Empty),
            (&[0, 4, 0, 1][..], Error::PacketTooLong(0x40001)),
            (&[0xff; 4][..], Error::PacketTooLong(u32::MAX)),
        ] {
            assert_eq!(Packet::parse(bytes), Err(error));
        }
        assert_eq!(
            Frames::<Packet>::new().decode(&[0, 4, 0, 0], false),
            Ok(Step::Need)
        );
        assert_eq!(
            Frames::<Packet>::with_limit(8).decode(&[0, 0, 0, 9], false),
            Err(Error::PacketTooLong(9))
        );
        assert_eq!(
            Frames::<Packet>::with_limit(8).decode(&[0, 0, 0, 8], false),
            Ok(Step::Need)
        );
        assert_eq!(
            Frames::<Packet>::with_limit(usize::MAX).decode(&[0, 4, 0, 1], false),
            Err(Error::PacketTooLong(0x40001))
        );
        fictionet::assert_cases!(Packet::parse;
            (&[0, 0, 0, 1, 7, 9]) => Err(Error::PacketTrailing),
            (&[0, 0, 0, 1, 7]) => Ok(Packet { kind: 7, body: vec![] }),
        );
        assert!(Error::Empty.to_string().contains('0'));
    }

    #[test]
    fn parse_errors() {
        let p = |kind: u8, body: &[u8]| Packet {
            kind,
            body: body.to_vec(),
        };
        let t = packet_type::STAT;
        // Unknown types.
        assert_eq!(Request::from_packet(&p(0, &[])), Err(Error::UnknownType(0)));
        assert_eq!(
            Request::from_packet(&p(21, &[0, 0, 0, 1])),
            Err(Error::UnknownType(21))
        );
        assert_eq!(
            Request::from_packet(&p(packet_type::EXTENDED_REPLY, &[])),
            Err(Error::UnknownType(201))
        );
        assert_eq!(
            Response::from_packet(&p(100, &[])),
            Err(Error::UnknownType(100))
        );
        // Truncated: no id, a short path, a path length past the end.
        fictionet::assert_cases!(Request::from_packet;
            (&p(t, &[0, 0])) => Err(Error::Truncated),
            (&p(t, &[0, 0, 0, 1, 0, 0])) => Err(Error::Truncated),
            (&p(t, &[0, 0, 0, 1, 0, 0, 0, 2, b'/'])) => Err(Error::Truncated),
            // Trailing bytes.
            (&p(t, &[0, 0, 0, 1, 0, 0, 0, 1, b'/', 0])) => Err(Error::Trailing),
        );
        assert_eq!(
            Response::from_packet(&p(packet_type::HANDLE, &[0, 0, 0, 1, 0, 0, 0, 0, 1])),
            Err(Error::Trailing)
        );
        // Strings over their limits.
        let len = |n: usize| (n as u32).to_be_bytes();
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(&len(MAX_PATH + 1));
        body.extend(std::iter::repeat_n(b'a', MAX_PATH + 1));
        assert_eq!(Request::from_packet(&p(t, &body)), Err(Error::TooLong));
        body.truncate(4);
        body.extend_from_slice(&len(MAX_HANDLE + 1));
        assert_eq!(
            Request::from_packet(&p(packet_type::CLOSE, &body)),
            Err(Error::TooLong)
        );
        body.truncate(4);
        body.extend_from_slice(&len(MAX_EXTENSION_NAME + 1));
        assert_eq!(
            Request::from_packet(&p(packet_type::EXTENDED, &body)),
            Err(Error::TooLong)
        );
        let mut ext = vec![0, 0, 0, 1, 0, 0, 0, 1, b'x'];
        ext.resize(ext.len() + MAX_DATA + 1, 0);
        assert_eq!(
            Request::from_packet(&p(packet_type::EXTENDED, &ext)),
            Err(Error::TooLong)
        );
        let mut reply = vec![0, 0, 0, 1];
        reply.resize(4 + MAX_DATA + 1, 0);
        assert_eq!(
            Response::from_packet(&p(packet_type::EXTENDED_REPLY, &reply)),
            Err(Error::TooLong)
        );
        let mut data = vec![0, 0, 0, 1];
        data.extend_from_slice(&len(MAX_DATA + 1));
        assert_eq!(
            Response::from_packet(&p(packet_type::DATA, &data)),
            Err(Error::TooLong)
        );
        let mut status = vec![0, 0, 0, 1, 0, 0, 0, 0];
        status.extend_from_slice(&len(MAX_TEXT + 1));
        assert_eq!(
            Response::from_packet(&p(packet_type::STATUS, &status)),
            Err(Error::TooLong)
        );
        assert_eq!(
            Response::from_packet(&p(packet_type::STATUS, &[0, 0, 0, 1, 0, 0, 0, 0, 0])),
            Err(Error::Truncated)
        );
        // Counts over their limits.
        let mut names = vec![0, 0, 0, 1];
        names.extend_from_slice(&len(MAX_NAMES + 1));
        assert_eq!(
            Response::from_packet(&p(packet_type::NAME, &names)),
            Err(Error::TooMany)
        );
        let mut attrs = vec![0, 0, 0, 1, 0x80, 0, 0, 0];
        attrs.extend_from_slice(&len(MAX_ATTR_EXTENSIONS + 1));
        assert_eq!(
            Response::from_packet(&p(packet_type::ATTRS, &attrs)),
            Err(Error::TooMany)
        );
        let mut init = vec![0, 0, 0, 3];
        for _ in 0..=MAX_EXTENSIONS {
            init.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        }
        // Extensions past the limit are skipped, not refused.
        let Ok(Request::Init { extensions, .. }) =
            Request::from_packet(&p(packet_type::INIT, &init))
        else {
            panic!()
        };
        assert_eq!(extensions.len(), MAX_EXTENSIONS);
        // Attribute flags version 3 does not define.
        assert_eq!(
            Response::from_packet(&p(packet_type::ATTRS, &[0, 0, 0, 1, 0, 0, 0, 0x10])),
            Err(Error::AttrFlags(0x10))
        );
        assert!(Error::AttrFlags(0x10).to_string().contains("0x10"));
        // A body longer than a packet can hold.
        let huge = p(packet_type::EXTENDED_REPLY, &vec![0; MAX_PACKET]);
        assert_eq!(Response::from_packet(&huge), Err(Error::TooLong));
        assert_eq!(
            Request::from_packet(&Packet {
                kind: packet_type::EXTENDED,
                ..huge
            }),
            Err(Error::TooLong)
        );
        // TooLong also covers raw data and whole bodies, not only strings.
        assert_eq!(
            Error::TooLong.to_string(),
            "a field or the body over its limit"
        );
    }

    #[test]
    fn every_truncated_prefix() {
        let packets: Vec<(Packet, bool)> = requests()
            .iter()
            .map(|r| (r.to_packet().unwrap(), true))
            .chain(responses().iter().map(|r| (r.to_packet().unwrap(), false)))
            .collect();
        for (p, is_request) in &packets {
            let bytes = p.to_bytes().unwrap();
            for n in 0..bytes.len() {
                assert_eq!(
                    Packet::parse(&bytes[..n]),
                    Err(Error::PacketTruncated),
                    "{p:?} at {n}"
                );
                assert_eq!(
                    Frames::<Packet>::new().decode(&bytes[..n], false),
                    Ok(Step::Need)
                );
            }
            let parse = |q: &Packet| {
                if *is_request {
                    Request::from_packet(q).map(|r| r.to_packet().unwrap())
                } else {
                    Response::from_packet(q).map(|r| r.to_packet().unwrap())
                }
            };
            assert_eq!(parse(p).as_ref(), Ok(p));
            for n in 0..p.body.len() {
                let short = Packet {
                    kind: p.kind,
                    body: p.body[..n].to_vec(),
                };
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
                    packet_type::INIT
                        | packet_type::VERSION
                        | packet_type::EXTENDED
                        | packet_type::EXTENDED_REPLY
                );
                if !open_ended && !short_status {
                    assert!(got.is_err(), "{p:?} at {n}");
                }
            }
        }
    }

    #[test]
    fn stream_splits_packets_and_reports_terminal_errors_once() {
        let a = Request::Init {
            version: 3,
            extensions: vec![],
        }
        .to_bytes()
        .unwrap();
        let stat = Request::Stat {
            id: 1,
            path: s(b"/etc/passwd"),
        };
        let b = stat.to_bytes().unwrap();
        let bytes = [&a[..], &b].concat();
        contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &bytes, 2 * MAX_FRAME);
        let (packets, failure) = decode_all(Frames::<Packet>::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(packets.len(), 2);
        assert_eq!(Request::from_packet(&packets[1]), Ok(stat));
        let mut stream = Stream::new(Frames::<Packet>::new());
        assert_eq!(stream.push(&[0, 0, 0, 0, 1]), 5);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::Empty))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(Error::Empty)));
        assert!(matches!(
            decode_all(|| Frames::<Packet>::with_limit(8), &b).1,
            Some(Fail::Protocol(Error::PacketTooLong(_)))
        ));
        assert_eq!(
            decode_all(Frames::<Packet>::new, &b[..6]).1,
            Some(Fail::Truncated { unread: 6 })
        );
    }

    #[test]
    fn stream_takes_many_small_packets_in_linear_time() {
        assert_linear(
            "stream_takes_many_small_packets_in_linear_time",
            rounds(50_000),
            |size| {
                let one = Request::Readdir {
                    id: 1,
                    handle: s(b"d"),
                }
                .to_bytes()
                .unwrap();
                let (packets, failure) = decode_all(Frames::<Packet>::new, &one.repeat(size));
                assert_eq!(failure, None);
                assert_eq!(packets.len(), size);
            },
        );
    }

    #[test]
    fn writers_refuse_values_they_would_shorten() {
        fn refused<T: Wire<WriteError = Error> + std::fmt::Debug + PartialEq>(value: T) {
            assert_eq!(contract::check_refused(&value), Error::Unwritable);
            contract::check_wire_value(&value);
        }
        let big = vec![b'a'; 2 * MAX_PACKET];
        let many_ext = vec![
            Extension {
                name: vec![0; 1000],
                data: vec![0; 5000]
            };
            200
        ];
        let attrs = Attrs {
            extended: many_ext.clone(),
            ..full_attrs()
        };
        refused(Request::Write {
            id: 1,
            handle: big.clone(),
            offset: 0,
            data: big.clone(),
        });
        refused(Request::Extended {
            id: 1,
            name: big.clone(),
            data: big.clone(),
        });
        refused(Request::Open {
            id: 1,
            path: big.clone(),
            flags: 0,
            attrs: attrs.clone(),
        });
        refused(Request::Rename {
            id: 1,
            from: big.clone(),
            to: big.clone(),
        });
        refused(Request::Init {
            version: 3,
            extensions: many_ext.clone(),
        });
        refused(Response::Version {
            version: 3,
            extensions: many_ext,
        });
        refused(Response::Status {
            id: 1,
            status: Status::Failure,
            message: big.clone(),
            language: big.clone(),
        });
        refused(Response::Handle {
            id: 1,
            handle: big.clone(),
        });
        refused(Response::Data {
            id: 1,
            data: big.clone(),
        });
        refused(Response::ExtendedReply {
            id: 1,
            data: big.clone(),
        });
        refused(Response::Attrs {
            id: 1,
            attrs: attrs.clone(),
        });
        refused(Response::Name {
            id: 1,
            names: vec![
                NameEntry {
                    filename: big.clone(),
                    longname: big.clone(),
                    attrs
                };
                50
            ],
        });
        refused(Response::Name {
            id: 1,
            names: vec![NameEntry::default(); MAX_NAMES + 1],
        });
        let entry = NameEntry {
            filename: vec![0; MAX_PATH],
            longname: vec![0; MAX_PATH],
            attrs: Attrs::default(),
        };
        refused(Response::Name {
            id: 1,
            names: vec![entry; 50],
        });
        let packet = Packet { kind: 9, body: big };
        assert!(packet.to_bytes().is_err());
        contract::check_wire_value(&packet);
        for value in [
            Response::Name {
                id: 1,
                names: vec![],
            },
            Response::Name {
                id: 1,
                names: vec![NameEntry::default(); MAX_NAMES],
            },
            Response::Data {
                id: 1,
                data: vec![0; MAX_DATA],
            },
            Response::Handle {
                id: 1,
                handle: vec![0; MAX_HANDLE],
            },
        ] {
            assert_eq!(Response::parse(&value.to_bytes().unwrap()), Ok(value));
        }
        for (name_len, data_len, count) in [
            (MAX_EXTENSION_NAME + 1, 0, 1),
            (0, MAX_TEXT + 1, 1),
            (0, 0, MAX_ATTR_EXTENSIONS + 1),
        ] {
            refused(Attrs {
                extended: vec![
                    Extension {
                        name: vec![0; name_len],
                        data: vec![0; data_len]
                    };
                    count
                ],
                ..Attrs::default()
            });
        }
    }

    #[test]
    fn name_prefix_fits_without_changing_entries() {
        let fits = |names: &[NameEntry]| {
            let fit = names_that_fit(names);
            let response = Response::Name {
                id: 1,
                names: names[..fit].to_vec(),
            };
            assert_eq!(Response::parse(&response.to_bytes().unwrap()), Ok(response));
            if fit < names.len() {
                let next = Response::Name {
                    id: 1,
                    names: names[..fit + 1].to_vec(),
                };
                let mut out = vec![7];
                assert_eq!(next.write(&mut out), Err(Error::Unwritable));
                assert_eq!(out, [7]);
            }
            fit
        };
        let big = NameEntry {
            filename: vec![b'f'; MAX_PATH],
            longname: vec![b'l'; MAX_PATH],
            attrs: full_attrs(),
        };
        let names = vec![big; 50];
        let fit = fits(&names);
        assert!(fit > 0 && fit < names.len());
        assert_eq!(fits(&vec![NameEntry::default(); MAX_NAMES + 1]), MAX_NAMES);
        assert_eq!(fits(&[]), 0);
        for bad in [
            NameEntry {
                filename: vec![0; MAX_PATH + 1],
                ..NameEntry::default()
            },
            NameEntry {
                longname: vec![0; MAX_PATH + 1],
                ..NameEntry::default()
            },
            NameEntry {
                attrs: Attrs {
                    extended: vec![Extension::default(); MAX_ATTR_EXTENSIONS + 1],
                    ..Attrs::default()
                },
                ..NameEntry::default()
            },
            NameEntry {
                attrs: Attrs {
                    extended: vec![Extension {
                        name: vec![0; MAX_EXTENSION_NAME + 1],
                        data: vec![],
                    }],
                    ..Attrs::default()
                },
                ..NameEntry::default()
            },
            NameEntry {
                attrs: Attrs {
                    extended: vec![Extension {
                        name: vec![],
                        data: vec![0; MAX_TEXT + 1],
                    }],
                    ..Attrs::default()
                },
                ..NameEntry::default()
            },
        ] {
            assert_eq!(fits(std::slice::from_ref(&bad)), 0);
            assert_eq!(fits(&[NameEntry::default(), bad, NameEntry::default()]), 1);
        }
    }

    #[test]
    fn stream_holds_at_most_one_packet() {
        let one = Request::Readdir {
            id: 1,
            handle: s(b"d"),
        }
        .to_bytes()
        .unwrap();
        let bytes = one.repeat(100);
        contract::check_decode_with_alloc_limit(
            || Frames::<Packet>::with_limit(64),
            &bytes,
            2 * (LENGTH_LEN + 64),
        );
        assert_eq!(
            decode_all(|| Frames::<Packet>::with_limit(64), &bytes)
                .0
                .len(),
            100
        );
        let mut stream = Stream::new(Frames::<Packet>::with_limit(64));
        assert_eq!(stream.push(&bytes), LENGTH_LEN + 64);
        assert_eq!(stream.push(&one), 0);
    }

    #[test]
    fn status_text_is_preserved_or_refused() {
        for text in ["a".repeat(MAX_TEXT - 1) + "é", "😀".repeat(300)] {
            let response = Response::status(1, Status::Failure, &text);
            let Response::Status { message, .. } = &response else {
                panic!()
            };
            assert_eq!(message, text.as_bytes());
            assert_eq!(response.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&response);
            let language = Response::Status {
                id: 1,
                status: Status::Failure,
                message: vec![],
                language: text.into_bytes(),
            };
            assert_eq!(language.to_bytes(), Err(Error::Unwritable));
        }
        let response = Response::status(1, Status::Ok, "été");
        assert_eq!(Response::parse(&response.to_bytes().unwrap()), Ok(response));
        for n in [MAX_TEXT, MAX_TEXT + 1] {
            let response = Response::Status {
                id: 1,
                status: Status::Ok,
                message: vec![0x80; n],
                language: vec![],
            };
            assert_eq!(response.to_bytes().is_ok(), n == MAX_TEXT);
            contract::check_wire_value(&response);
        }
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
            let p = Packet {
                kind,
                body: body.clone(),
            };
            let kept = vec![Extension {
                name: s(b"posix-rename@openssh.com"),
                data: s(b"z"),
            }];
            if kind == packet_type::INIT {
                assert_eq!(
                    Request::from_packet(&p),
                    Ok(Request::Init {
                        version: 3,
                        extensions: kept
                    })
                );
            } else {
                assert_eq!(
                    Response::from_packet(&p),
                    Ok(Response::Version {
                        version: 3,
                        extensions: kept
                    })
                );
            }
        }
        // Past MAX_EXTENSIONS, the rest are skipped too.
        let mut many = vec![0, 0, 0, 3];
        for _ in 0..MAX_EXTENSIONS + 5 {
            ext(&mut many, b"a", 0);
        }
        let Ok(Request::Init { extensions, .. }) = Request::from_packet(&Packet {
            kind: packet_type::INIT,
            body: many,
        }) else {
            panic!()
        };
        assert_eq!(extensions.len(), MAX_EXTENSIONS);
        // A pair that runs past the end is still an error.
        let mut cut = vec![0, 0, 0, 3];
        ext(&mut cut, b"a", 10);
        cut.truncate(cut.len() - 1);
        assert_eq!(
            Request::from_packet(&Packet {
                kind: packet_type::INIT,
                body: cut
            }),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn generated_inputs_obey_contracts() {
        let mut rng = Lcg::new(0x5f7f);
        let seeds: Vec<Vec<u8>> = requests()
            .iter()
            .map(|r| r.to_bytes().unwrap())
            .chain(responses().iter().map(|r| r.to_bytes().unwrap()))
            .collect();
        for _ in 0..6000 {
            let mut bytes = if rng.coin() {
                seeds[rng.index(seeds.len())].clone()
            } else {
                rng.bytes(64)
            };
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &bytes, 2 * MAX_FRAME);
            contract::check_wire::<Packet>(&bytes);
            contract::check_wire::<Request>(&bytes);
            contract::check_wire::<Response>(&bytes);
            contract::check_wire::<Attrs>(&bytes);
            for kind in 0..=255 {
                let packet = Packet {
                    kind,
                    body: bytes.clone(),
                };
                check_packet(&packet);
            }
        }
    }
}
