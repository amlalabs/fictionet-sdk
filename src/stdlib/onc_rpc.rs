//! ONC RPC and XDR: reading and writing calls, replies, and TCP records
//! with no I/O. [`portmap`](fictionet::stdlib::portmap) handles portmap procedures.
//!
//! `Message`, `Fragment`, and `Record` implement `Wire`. `Fragments`,
//! `records`, and `messages` decode and assemble TCP records. There is no
//! client or server call session, `Service`, authentication verification, or
//! live transport. Procedure dispatch belongs to the caller.
//!
//! ONC RPC (Open Network Computing Remote Procedure Call, first Sun RPC)
//! is how NFS, NIS and the network lock manager talk. A client calls a
//! procedure of a program by number, and the server answers with a reply
//! that carries the results or says why there are none. Every message is
//! written in XDR (External Data Representation): big-endian 4-byte units,
//! with opaque data and strings padded to a multiple of 4. Over UDP each
//! datagram holds one message. Over TCP each message is a record, sent as
//! one or more fragments behind a 4-byte record mark. A client finds which
//! port a program listens on by asking the portmapper (version 2) or
//! rpcbind (versions 3 and 4) on port 111. This module follows RFC 4506
//! for XDR, RFC 5531 for ONC RPC and record marking, and RFC 1833 for
//! portmap and rpcbind.
//!
//! For TCP, [`Stream<Fragments>`](fictionet::stdlib::codec::Stream) reads record
//! fragments; [`records`] joins them and [`messages`] reads each RPC header.
//! UDP datagrams contain one [`Message`]. [`Reader`] and [`Writer`] handle
//! XDR arguments and results.
//! [`Writer::finish`] reports values that exceed its record budget.
//! World code selects the program, procedure, and reply.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Assembled, Wire};
//! use fictionet::stdlib::onc_rpc::{
//!     records, Body, Call, Record, Message, MAX_RECORD,
//!     Reply, IPPROTO_TCP,
//! };
//!
//! use fictionet::stdlib::portmap::{Mapping, silent_on_failure, Request, PmapRequest, PmapResult};
//!
//! /// A portmapper that knows one program: NFS version 3 on TCP port 2049.
//! /// `None` means it sends no reply.
//! fn answer(call: &Call) -> Option<Reply> {
//!     Some(match Request::from_call(call) {
//!         Ok(Request::Pmap(PmapRequest::GetPort(m))) => {
//!             let nfs = m.program == 100_003 && m.version == 3 && m.protocol == IPPROTO_TCP;
//!             Reply::success(PmapResult::Port(if nfs { 2049 } else { 0 }).to_bytes().unwrap())
//!         }
//!         Ok(Request::Pmap(PmapRequest::Null)) => Reply::success(Vec::new()),
//!         // Refuse to register or list anything.
//!         Ok(_) => Reply::success(vec![0, 0, 0, 0]),
//!         // It forwards no calls, and a CALLIT that fails gets no reply.
//!         Err(_) if silent_on_failure(call) => return None,
//!         Err(error) => error.reply(),
//!     })
//! }
//!
//! // A client asks, over TCP, which port NFS version 3 uses. Call 7.
//! let mapping = Mapping { program: 100_003, version: 3, protocol: IPPROTO_TCP, port: 0 };
//! let request = Request::Pmap(PmapRequest::GetPort(mapping)).call(7).unwrap();
//! let mut decoder = Stream::new(records(MAX_RECORD));
//! let bytes = Record::from_message(&request).unwrap().to_bytes().unwrap();
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let Assembled::Message(record) = decoder.next().unwrap().unwrap();
//! let message = Message::parse(&record).unwrap();
//! let Body::Call(call) = &message.body else { panic!("not a call") };
//! let reply = message.reply(answer(call).unwrap());
//! // Call 7, a reply, accepted, an AUTH_NONE verifier, success, port 2049.
//! assert_eq!(
//!     reply.to_bytes().unwrap(),
//!     [0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1]
//! );
//! ```

use fictionet::stdlib::codec::{self, Assemble, AssembleError, Assembled, Decode, Step, Wire, Reader as ByteReader, Truncated};
use core::convert::Infallible;

/// The port the portmapper and rpcbind listen on, over TCP and UDP.
pub const PORT: u16 = 111;
/// The ONC RPC version every call names (RFC 5531).
pub const RPC_VERSION: u32 = 2;
/// The program number of the portmapper and of rpcbind.
pub const PMAP_PROGRAM: u32 = 100_000;
/// The portmapper's version (RFC 1833, section 3).
pub const PMAP_VERSION: u32 = 2;
/// The lowest rpcbind version (RFC 1833, section 2).
pub const RPCB_VERSION_LOW: u32 = 3;
/// The highest rpcbind version (RFC 1833, section 2).
pub const RPCB_VERSION_HIGH: u32 = 4;
/// The protocol number a [`Mapping`](fictionet::stdlib::portmap::Mapping) gives for TCP.
pub const IPPROTO_TCP: u32 = 6;
/// The protocol number a [`Mapping`](fictionet::stdlib::portmap::Mapping) gives for UDP.
pub const IPPROTO_UDP: u32 = 17;

/// The longest body of a credential or verifier (RFC 5531, section 8.2).
pub const MAX_AUTH_BODY: usize = 400;
/// The longest machine name in AUTH_SYS credentials.
pub const MAX_MACHINE_NAME: usize = 255;
/// The most supplementary group IDs in AUTH_SYS credentials.
pub const MAX_GIDS: usize = 16;
/// The longest string in an rpcbind request or reply: a network ID, a
/// universal address or an owner.
pub const MAX_RPCB_STRING: usize = 255;
/// The most items [`Reader::array`] makes room for before it reads them.
/// A longer array grows as its items read, so a count alone never sizes
/// an allocation. It is also the most items an array may have when they
/// take fewer than 4 bytes each, such as fixed opaque data of length 0.
pub const MAX_ARRAY_RESERVE: usize = 1024;
/// The most bytes [`Reader::array`] makes room for before it reads its
/// items, however large each item is in memory.
const MAX_RESERVE_BYTES: usize = 1 << 16;

/// The longest record [`records`] assembles. A caller may choose a lower
/// limit, never a higher one.
pub const MAX_RECORD: usize = 1 << 21;
/// The longest fragment a record mark can describe: its low 31 bits.
pub const MAX_FRAGMENT: u32 = 0x7fff_ffff;
/// The record mark's high bit, set on a record's last fragment.
pub const LAST_FRAGMENT: u32 = 0x8000_0000;
/// The length of a TCP record mark, in bytes.
pub const RECORD_MARK_LEN: usize = 4;

/// Authentication flavors (RFC 5531, section 8.2, and the IANA registry).
pub mod flavor {
    #![allow(missing_docs)]
    pub const NONE: u32 = 0;
    pub const SYS: u32 = 1;
    pub const SHORT: u32 = 2;
    pub const DH: u32 = 3;
    pub const RPCSEC_GSS: u32 = 6;
}

/// Procedure numbers of the portmapper (version 2) and rpcbind (versions
/// 3 and 4). GETPORT and GETADDR share a number.
pub mod procedure {
    #![allow(missing_docs)]
    pub const NULL: u32 = 0;
    pub const SET: u32 = 1;
    pub const UNSET: u32 = 2;
    pub const GETPORT: u32 = 3;
    pub const GETADDR: u32 = 3;
    pub const DUMP: u32 = 4;
    pub const CALLIT: u32 = 5;
}

/// Why bytes are not the XDR a reader expected or a TCP record, or why a
/// value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes ended before the value did, or before a complete TCP
    /// record mark or payload arrived.
    Short,
    /// A padding byte after opaque data or a string was not zero.
    Padding,
    /// A boolean was neither 0 nor 1.
    Bool(u32),
    /// An enum or union discriminant had a value the type does not have.
    Discriminant(u32),
    /// The field length, item count, or attempted total buffer length that
    /// exceeded its limit. Values above `u32::MAX` are reported as `u32::MAX`.
    TooLong(u32),
    /// A string was not UTF-8.
    Utf8,
    /// A value would read back differently.
    Unwritable,
    /// Bytes were left over after the value, the fragment or the record:
    /// this many.
    Trailing(usize),
    /// A message or authentication field to write exceeds its named limit.
    FieldTooLong {
        /// The maximum bytes or entries for that field.
        limit: usize,
    },
    /// The fragments of one record add up to more than the limit, which
    /// is given. A real server closes the connection.
    RecordTooLong(usize),
    /// Storage for a record could not be allocated.
    Allocation,
    /// The input ended before a record's final fragment, even for an
    /// empty record.
    Incomplete {
        /// Payload bytes awaiting a final fragment.
        held: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Short => f.write_str("XDR ended early"),
            Error::Padding => f.write_str("XDR padding byte not zero"),
            Error::Bool(n) => write!(f, "XDR boolean {n}, not 0 or 1"),
            Error::Discriminant(n) => write!(f, "XDR discriminant {n} not known"),
            Error::TooLong(n) => write!(f, "XDR length or count {n} over the limit"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Utf8 => f.write_str("XDR string not UTF-8"),
            Error::Trailing(n) => write!(f, "{n} bytes after the XDR value or RPC record"),
            Error::FieldTooLong { limit } => write!(f, "RPC message field exceeds {limit}"),
            Error::RecordTooLong(limit) => write!(f, "RPC record over the limit of {limit} bytes"),
            Error::Allocation => f.write_str("RPC record allocation failed"),
            Error::Incomplete { held } => write!(f, "incomplete RPC record of {held} bytes"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads XDR values from bytes, in order. Each method reads one value and
/// moves past it. After an error the reader's position is unspecified, so
/// a caller stops there.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    cursor: ByteReader<'a>,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { cursor: ByteReader::new(buf) }
    }

    /// How many bytes have been read.
    #[inline]
    pub fn position(&self) -> usize {
        self.cursor.position()
    }

    /// The bytes not yet read.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        self.cursor.clone().rest()
    }

    /// Takes every byte not yet read, such as a call's arguments.
    #[inline]
    pub fn rest(&mut self) -> &'a [u8] {
        self.cursor.rest()
    }

    /// Checks that every byte has been read.
    #[inline]
    pub fn finish(&self) -> Result<(), Error> {
        self.cursor.finish().map_err(|e| Error::Trailing(e.0))
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.cursor.take(n).map_err(Error::from)
    }

    /// An unsigned integer: 4 bytes.
    #[inline]
    pub fn uint(&mut self) -> Result<u32, Error> {
        self.cursor.u32_be().map_err(Error::from)
    }

    /// A signed integer: 4 bytes, two's complement.
    pub fn int(&mut self) -> Result<i32, Error> {
        Ok(self.uint()? as i32)
    }

    /// An unsigned hyper integer: 8 bytes.
    pub fn uhyper(&mut self) -> Result<u64, Error> {
        let hi = u64::from(self.uint()?);
        let lo = u64::from(self.uint()?);
        Ok(hi << 32 | lo)
    }

    /// A hyper integer: 8 bytes, two's complement.
    pub fn hyper(&mut self) -> Result<i64, Error> {
        Ok(self.uhyper()? as i64)
    }

    /// A boolean: an integer that is 0 or 1.
    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.uint()? {
            0 => Ok(false),
            1 => Ok(true),
            n => Err(Error::Bool(n)),
        }
    }

    /// An enum: a signed integer. Which values the enum has is up to the
    /// caller.
    pub fn enumeration(&mut self) -> Result<i32, Error> {
        self.int()
    }

    /// Fixed-length opaque data of `n` bytes, then the zero bytes that pad
    /// it to a multiple of 4.
    pub fn opaque_fixed(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let data = self.take(n)?;
        let pad = self.take(padding(n))?;
        if pad.iter().any(|&b| b != 0) {
            return Err(Error::Padding);
        }
        Ok(data)
    }

    /// Variable-length opaque data of at most `max` bytes: a length, the
    /// bytes, and zero padding. A longer length is [`Error::TooLong`].
    pub fn opaque(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let len = self.uint()?;
        let n = usize::try_from(len).map_err(|_| Error::TooLong(len))?;
        if n > max {
            return Err(Error::TooLong(len));
        }
        self.opaque_fixed(n)
    }

    /// A string of at most `max` bytes, written like variable-length
    /// opaque data. It must be UTF-8.
    pub fn string(&mut self, max: usize) -> Result<&'a str, Error> {
        std::str::from_utf8(self.opaque(max)?).map_err(|_| Error::Utf8)
    }

    /// A variable-length array of at most `max` items, each read by `item`.
    /// A count above both [`MAX_ARRAY_RESERVE`] and a quarter of the bytes
    /// left is refused before any items are read. Room is made up front
    /// for at most [`MAX_ARRAY_RESERVE`] items and 64 KiB.
    pub fn array<T>(
        &mut self,
        max: usize,
        mut item: impl FnMut(&mut Reader<'a>) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let count = self.uint()?;
        let n = usize::try_from(count).map_err(|_| Error::TooLong(count))?;
        if n > max {
            return Err(Error::TooLong(count));
        }
        if n > MAX_ARRAY_RESERVE && n > self.remaining().len() / 4 {
            return Err(Error::Short);
        }
        let mut out = Vec::with_capacity(reserve::<T>(n));
        for _ in 0..n {
            out.push(item(self)?);
        }
        Ok(out)
    }

    /// Reads a linked list (a chain of optional items) of at most `max`
    /// items, in a loop, not by recursion. The items, each with the word
    /// before it, take at most `max_bytes`.
    pub fn list<T>(
        &mut self,
        max: usize,
        max_bytes: usize,
        mut item: impl FnMut(&mut Reader<'a>) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let start = self.position();
        let mut out = Vec::new();
        while self.bool()? {
            if out.len() >= max {
                return Err(Error::TooLong(
                    u32::try_from(out.len())
                        .unwrap_or(u32::MAX)
                        .saturating_add(1),
                ));
            }
            out.push(item(self)?);
            let used = self.position() - start;
            if used > max_bytes {
                return Err(Error::TooLong(u32::try_from(used).unwrap_or(u32::MAX)));
            }
        }
        Ok(out)
    }

    /// An optional value: a boolean, then the value if it is 1.
    pub fn optional<T>(
        &mut self,
        item: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        if self.bool()? {
            Ok(Some(item(self)?))
        } else {
            Ok(None)
        }
    }
}

/// Writes XDR values under the [`MAX_RECORD`] byte limit.
/// Methods can be chained. The first error is returned by [`Writer::finish`].
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    error: Option<Error>,
}

impl Writer {
    /// A writer holding no bytes.
    pub fn new() -> Writer {
        Writer::default()
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the complete bytes, or the first error. Invalid values are never returned.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.buf),
        }
    }

    /// Finishes an XDR value and checks it with its procedure-specific reader.
    /// A value that would read differently returns [`Error::Unwritable`].
    pub fn finish_value<T: PartialEq>(
        self,
        value: &T,
        read: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<Vec<u8>, Error> {
        let bytes = self.finish()?;
        if read(&bytes).as_ref() != Ok(value) {
            return Err(Error::Unwritable);
        }
        Ok(bytes)
    }

    /// Refuses this value. The first error is returned by [`Self::finish`].
    pub fn reject(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Appends bytes within the record budget.
    /// An error carries the total length the append would produce.
    fn append(&mut self, bytes: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let total = self.buf.len().checked_add(bytes.len());
        if total.is_none_or(|n| n > MAX_RECORD) {
            let length = total
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(u32::MAX);
            self.reject(Error::TooLong(length));
            return;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// An unsigned integer: 4 bytes.
    pub fn uint(&mut self, v: u32) -> &mut Writer {
        self.append(&v.to_be_bytes());
        self
    }

    /// A signed integer: 4 bytes, two's complement.
    pub fn int(&mut self, v: i32) -> &mut Writer {
        self.append(&v.to_be_bytes());
        self
    }

    /// An unsigned hyper integer: 8 bytes.
    pub fn uhyper(&mut self, v: u64) -> &mut Writer {
        self.append(&v.to_be_bytes());
        self
    }

    /// A hyper integer: 8 bytes, two's complement.
    pub fn hyper(&mut self, v: i64) -> &mut Writer {
        self.append(&v.to_be_bytes());
        self
    }

    /// A boolean: 0 or 1.
    pub fn bool(&mut self, v: bool) -> &mut Writer {
        self.uint(u32::from(v))
    }

    /// An enum: a signed integer.
    pub fn enumeration(&mut self, v: i32) -> &mut Writer {
        self.int(v)
    }

    /// Fixed-length opaque data, padded with zeros to a multiple of 4.
    pub fn opaque_fixed(&mut self, data: &[u8]) -> &mut Writer {
        self.append(data);
        self.append(&[0; 3][..padding(data.len())]);
        self
    }

    /// Variable-length opaque data: a length, the bytes, and padding. Data
    /// above the length or buffer limit records an error.
    pub fn opaque(&mut self, data: &[u8]) -> &mut Writer {
        let Ok(len) = u32::try_from(data.len()) else {
            self.reject(Error::TooLong(u32::MAX));
            return self;
        };
        self.uint(len);
        self.opaque_fixed(data)
    }

    /// Appends a complete linked list within its count and byte limits.
    pub fn list<'a, T: 'a>(
        &mut self,
        items: impl IntoIterator<Item = &'a T>,
        max: usize,
        max_bytes: usize,
        mut item: impl FnMut(&mut Writer, &T),
    ) {
        let mut used = 0usize;
        for (written, value) in items.into_iter().enumerate() {
            if written >= max {
                self.reject(Error::TooLong(
                    u32::try_from(written).unwrap_or(u32::MAX),
                ));
                return;
            }
            let mut one = Writer::new();
            one.bool(true);
            item(&mut one, value);
            let one = match one.finish() {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.reject(error);
                    return;
                }
            };
            let Some(total) = used.checked_add(one.len()).filter(|n| *n <= max_bytes) else {
                self.reject(Error::TooLong(
                    u32::try_from(max_bytes).unwrap_or(u32::MAX),
                ));
                return;
            };
            self.opaque_fixed(&one);
            used = total;
        }
        self.bool(false);
    }

    /// Appends bounded opaque data, or records a writer error.
    #[inline]
    pub fn opaque_bounded(&mut self, bytes: &[u8], max: usize) {
        if let Err(error) = self.try_opaque(bytes, max) {
            self.reject(error);
        }
    }

    /// Appends bounded opaque data. A field over `max` is refused before writing.
    /// Buffer errors are still reported by [`Self::finish`].
    #[inline]
    pub fn try_opaque(&mut self, bytes: &[u8], max: usize) -> Result<(), Error> {
        if bytes.len() > max {
            return Err(Error::TooLong(u32::try_from(bytes.len()).unwrap_or(u32::MAX)));
        }
        self.opaque(bytes);
        Ok(())
    }

    /// Writes a linked list, returning `too_many` before writing if its count exceeds `max`.
    /// Callback errors are returned unchanged.
    pub fn try_list<T, E>(
        &mut self,
        max: usize,
        too_many: E,
        items: &[T],
        mut item: impl FnMut(&mut Writer, &T) -> Result<(), E>,
    ) -> Result<(), E> {
        if items.len() > max {
            return Err(too_many);
        }
        for i in items {
            self.bool(true);
            item(self, i)?;
        }
        self.bool(false);
        Ok(())
    }

    /// A string, written like variable-length opaque data.
    pub fn string(&mut self, s: &str) -> &mut Writer {
        self.opaque(s.as_bytes())
    }

    /// A variable-length array: a count, then each item written by `item`.
    /// An array of more than [`MAX_ARRAY_RESERVE`] items must have items of
    /// at least 4 bytes, as almost every XDR type has, or
    /// [`Reader::array`] refuses the count.
    pub fn array<T>(&mut self, items: &[T], mut item: impl FnMut(&mut Writer, &T)) -> &mut Writer {
        let Ok(len) = u32::try_from(items.len()) else {
            self.reject(Error::TooLong(u32::MAX));
            return self;
        };
        self.uint(len);
        for i in items {
            if self.error.is_some() {
                break;
            }
            let before = self.buf.len();
            item(self, i);
            if items.len() > MAX_ARRAY_RESERVE && self.buf.len().saturating_sub(before) < 4 {
                self.reject(Error::TooLong(len));
                break;
            }
        }
        self
    }

    /// An optional value: a boolean, then the value if there is one.
    pub fn optional<T>(
        &mut self,
        value: Option<&T>,
        item: impl FnOnce(&mut Writer, &T),
    ) -> &mut Writer {
        self.bool(value.is_some());
        if let Some(v) = value {
            item(self, v);
        }
        self
    }
}

/// How many of `n` items of type `T` to make room for before reading them.
fn reserve<T>(n: usize) -> usize {
    n.min(MAX_ARRAY_RESERVE)
        .min(MAX_RESERVE_BYTES / std::mem::size_of::<T>().max(1))
}

/// How many zero bytes pad `n` bytes to a multiple of 4.
fn padding(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// AUTH_SYS credentials: who the caller says it is, on Unix terms. The
/// server has no way to check them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthSys {
    /// A number the caller chose, often the time.
    pub stamp: u32,
    /// The caller's host name, at most [`MAX_MACHINE_NAME`] bytes.
    pub machine_name: String,
    /// The caller's user ID.
    pub uid: u32,
    /// The caller's group ID.
    pub gid: u32,
    /// Further group IDs, at most [`MAX_GIDS`].
    pub gids: Vec<u32>,
}

impl AuthSys {
    /// Reads AUTH_SYS credentials from the whole of `body`.
    pub fn parse(body: &[u8]) -> Result<AuthSys, Error> {
        let mut r = Reader::new(body);
        let stamp = r.uint()?;
        let machine_name = r.string(MAX_MACHINE_NAME)?.to_string();
        let uid = r.uint()?;
        let gid = r.uint()?;
        let gids = r.array(MAX_GIDS, Reader::uint)?;
        r.finish()?;
        Ok(AuthSys {
            stamp,
            machine_name,
            uid,
            gid,
            gids,
        })
    }
}

impl Wire for AuthSys {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the complete AUTH_SYS body. Short fields return [`Error::Short`];
    /// nonzero padding returns [`Error::Padding`]; invalid UTF-8 returns
    /// [`Error::Utf8`]. A name above [`MAX_MACHINE_NAME`] or group count
    /// above [`MAX_GIDS`] returns [`Error::TooLong`]. Extra bytes return
    /// [`Error::Trailing`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(bytes)
    }
    /// Appends AUTH_SYS credentials. A name above [`MAX_MACHINE_NAME`] or
    /// a group count above [`MAX_GIDS`] returns [`Error::TooLong`].
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.machine_name.len() > MAX_MACHINE_NAME || self.gids.len() > MAX_GIDS {
            return Err(Error::TooLong(
                u32::try_from(self.machine_name.len().max(self.gids.len())).unwrap_or(u32::MAX),
            ));
        }
        let mut w = Writer::new();
        w.uint(self.stamp)
            .string(&self.machine_name)
            .uint(self.uid)
            .uint(self.gid);
        w.array(&self.gids, |w, group| {
            w.uint(*group);
        });
        out.extend_from_slice(&w.finish()?);
        Ok(())
    }
}

/// A credential or verifier: an authentication flavor and its body.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Auth {
    /// AUTH_NONE with an empty body: no authentication.
    None,
    /// AUTH_SYS with a body that reads as [`AuthSys`].
    Sys(AuthSys),
    /// Any other flavor, AUTH_NONE with a body, or AUTH_SYS with a body
    /// that does not read as [`AuthSys`]. RFC 5531 (section 10.1) leaves
    /// the body of AUTH_NONE undefined, so one with a body is still no
    /// authentication and a server may take it. A server refuses an
    /// AUTH_SYS body that does not read with [`AuthStat::BadCred`] for a
    /// credential and [`AuthStat::BadVerf`] for a verifier. The body is at
    /// most [`MAX_AUTH_BODY`] bytes.
    /// A value that would parse as [`Auth::None`] or [`Auth::Sys`] is
    /// refused by the writer.
    Other {
        /// The flavor, as in [`flavor`].
        flavor: u32,
        /// The body, unread.
        body: Vec<u8>,
    },
}

impl Auth {
    /// The flavor number.
    pub fn flavor(&self) -> u32 {
        match self {
            Auth::None => flavor::NONE,
            Auth::Sys(_) => flavor::SYS,
            Auth::Other { flavor, .. } => *flavor,
        }
    }

    /// Reads a credential or verifier: a flavor and a body of at most
    /// [`MAX_AUTH_BODY`] bytes.
    pub fn read(r: &mut Reader<'_>) -> Result<Auth, Error> {
        let flavor = r.uint()?;
        let body = r.opaque(MAX_AUTH_BODY)?;
        Ok(match flavor {
            flavor::NONE if body.is_empty() => Auth::None,
            flavor::SYS => match AuthSys::parse(body) {
                Ok(sys) => Auth::Sys(sys),
                Err(_) => Auth::Other {
                    flavor,
                    body: body.to_vec(),
                },
            },
            _ => Auth::Other {
                flavor,
                body: body.to_vec(),
            },
        })
    }

    /// Appends authentication fields after checking their limits.
    /// A value that would read differently sets [`Error::Unwritable`].
    /// Retrieve any error with [`Writer::finish`].
    pub fn write(&self, w: &mut Writer) {
        if auth_wire_len(self).is_err() {
            w.reject(Error::Unwritable);
            return;
        }
        let body = match self {
            Auth::None => Vec::new(),
            Auth::Sys(sys) => match sys.to_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    w.reject(error);
                    return;
                }
            },
            Auth::Other { body, .. } => body.clone(),
        };
        w.uint(self.flavor()).opaque(&body);
    }
}

/// One ONC RPC message: a call or a reply, and the transaction ID that
/// matches them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Chosen by the client and copied into the reply.
    pub xid: u32,
    /// The call or the reply.
    pub body: Body,
}

/// What a message is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// A client asks a server to run a procedure.
    Call(Call),
    /// A server answers a call.
    Reply(Reply),
}

/// A call: which procedure to run, who asks, and the arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The RPC version. A server answers anything but [`RPC_VERSION`]
    /// with [`Reject::RpcMismatch`].
    pub rpc_version: u32,
    /// The program number, such as 100003 for NFS.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// The procedure number within that version.
    pub procedure: u32,
    /// Who the caller says it is.
    pub cred: Auth,
    /// What backs the credential up, for flavors that have one.
    pub verf: Auth,
    /// The procedure's arguments, in XDR, unread.
    pub args: Vec<u8>,
}

impl Call {
    /// A call with RPC version 2 and AUTH_NONE for both credential and
    /// verifier.
    pub fn new(program: u32, version: u32, procedure: u32, args: Vec<u8>) -> Call {
        Call {
            rpc_version: RPC_VERSION,
            program,
            version,
            procedure,
            cred: Auth::None,
            verf: Auth::None,
            args,
        }
    }
}

/// A reply: whether the server took the call, and what came of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The server took the call.
    Accepted {
        /// The server's verifier.
        verf: Auth,
        /// What came of it.
        status: Accept,
    },
    /// The server refused the call.
    Denied(Reject),
}

impl Reply {
    /// A reply that took the call and ran it, with these results in XDR
    /// and an AUTH_NONE verifier.
    pub fn success(results: Vec<u8>) -> Reply {
        Reply::accepted(Accept::Success(results))
    }

    /// A reply that took the call, with this status and an AUTH_NONE
    /// verifier.
    pub fn accepted(status: Accept) -> Reply {
        Reply::Accepted {
            verf: Auth::None,
            status,
        }
    }
}

/// What came of a call the server took (accept_stat).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accept {
    /// The procedure ran. Its results, in XDR, unread.
    Success(Vec<u8>),
    /// The server does not have the program.
    ProgUnavail,
    /// The server does not have that version of the program. It has the
    /// versions from `low` to `high`.
    ProgMismatch {
        /// The lowest version the server has.
        low: u32,
        /// The highest version the server has.
        high: u32,
    },
    /// The program does not have the procedure.
    ProcUnavail,
    /// The server could not read the arguments.
    GarbageArgs,
    /// The server failed, for example while allocating memory.
    SystemErr,
}

impl Accept {
    /// The accept_stat number.
    pub fn code(&self) -> u32 {
        match self {
            Accept::Success(_) => 0,
            Accept::ProgUnavail => 1,
            Accept::ProgMismatch { .. } => 2,
            Accept::ProcUnavail => 3,
            Accept::GarbageArgs => 4,
            Accept::SystemErr => 5,
        }
    }
}

/// Why a server refused a call (reject_stat).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The call's RPC version was not one the server has. It has the
    /// versions from `low` to `high`.
    RpcMismatch {
        /// The lowest RPC version the server has.
        low: u32,
        /// The highest RPC version the server has.
        high: u32,
    },
    /// The server refused the credentials.
    AuthError(AuthStat),
}

/// Why a server refused credentials (auth_stat, RFC 5531, section 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthStat {
    /// No error.
    Ok,
    /// The credentials were malformed.
    BadCred,
    /// The client must start a new session.
    RejectedCred,
    /// The verifier was malformed.
    BadVerf,
    /// The verifier expired or was replayed.
    RejectedVerf,
    /// The server wants a stronger flavor.
    TooWeak,
    /// The server's response verifier was bad.
    InvalidResp,
    /// The reason is not known.
    Failed,
    /// A Kerberos error.
    KerbGeneric,
    /// The Kerberos credentials expired.
    TimeExpire,
    /// A problem with the Kerberos ticket file.
    TktFile,
    /// The Kerberos authenticator could not be decoded.
    Decode,
    /// The Kerberos ticket names the wrong network address.
    NetAddr,
    /// RPCSEC_GSS: no credentials for the user.
    GssCredProblem,
    /// RPCSEC_GSS: the context has a problem.
    GssCtxProblem,
    /// Any other number. One built with a number from 0 to 14 reads back
    /// as the status with that name.
    Other(u32),
}

impl AuthStat {
    /// The auth_stat number.
    pub fn code(self) -> u32 {
        match self {
            AuthStat::Ok => 0,
            AuthStat::BadCred => 1,
            AuthStat::RejectedCred => 2,
            AuthStat::BadVerf => 3,
            AuthStat::RejectedVerf => 4,
            AuthStat::TooWeak => 5,
            AuthStat::InvalidResp => 6,
            AuthStat::Failed => 7,
            AuthStat::KerbGeneric => 8,
            AuthStat::TimeExpire => 9,
            AuthStat::TktFile => 10,
            AuthStat::Decode => 11,
            AuthStat::NetAddr => 12,
            AuthStat::GssCredProblem => 13,
            AuthStat::GssCtxProblem => 14,
            AuthStat::Other(n) => n,
        }
    }

    /// The status with number `n`. Numbers this module has no name for
    /// become [`AuthStat::Other`].
    pub fn from_code(n: u32) -> AuthStat {
        match n {
            0 => AuthStat::Ok,
            1 => AuthStat::BadCred,
            2 => AuthStat::RejectedCred,
            3 => AuthStat::BadVerf,
            4 => AuthStat::RejectedVerf,
            5 => AuthStat::TooWeak,
            6 => AuthStat::InvalidResp,
            7 => AuthStat::Failed,
            8 => AuthStat::KerbGeneric,
            9 => AuthStat::TimeExpire,
            10 => AuthStat::TktFile,
            11 => AuthStat::Decode,
            12 => AuthStat::NetAddr,
            13 => AuthStat::GssCredProblem,
            14 => AuthStat::GssCtxProblem,
            n => AuthStat::Other(n),
        }
    }
}

impl Message {
    /// Reads the message that is the whole of `b`: one UDP datagram or one
    /// TCP record. A call's arguments and a successful reply's results are
    /// the bytes after the header. Any other message must end where its
    /// last field does.
    pub fn parse(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_RECORD {
            return Err(Error::TooLong(
                u32::try_from(b.len()).unwrap_or(u32::MAX),
            ));
        }
        let mut r = Reader::new(b);
        let xid = r.uint()?;
        let body = match r.uint()? {
            0 => {
                let rpc_version = r.uint()?;
                let program = r.uint()?;
                let version = r.uint()?;
                let procedure = r.uint()?;
                let cred = Auth::read(&mut r)?;
                let verf = Auth::read(&mut r)?;
                let args = r.rest().to_vec();
                Body::Call(Call {
                    rpc_version,
                    program,
                    version,
                    procedure,
                    cred,
                    verf,
                    args,
                })
            }
            1 => Body::Reply(match r.uint()? {
                0 => {
                    let verf = Auth::read(&mut r)?;
                    let status = match r.uint()? {
                        0 => Accept::Success(r.rest().to_vec()),
                        1 => Accept::ProgUnavail,
                        2 => Accept::ProgMismatch {
                            low: r.uint()?,
                            high: r.uint()?,
                        },
                        3 => Accept::ProcUnavail,
                        4 => Accept::GarbageArgs,
                        5 => Accept::SystemErr,
                        n => return Err(Error::Discriminant(n)),
                    };
                    Reply::Accepted { verf, status }
                }
                1 => Reply::Denied(match r.uint()? {
                    0 => Reject::RpcMismatch {
                        low: r.uint()?,
                        high: r.uint()?,
                    },
                    1 => Reject::AuthError(AuthStat::from_code(r.uint()?)),
                    n => return Err(Error::Discriminant(n)),
                }),
                n => return Err(Error::Discriminant(n)),
            }),
            n => return Err(Error::Discriminant(n)),
        };
        r.finish()?;
        Ok(Message { xid, body })
    }

    /// A message that answers this one with `reply`, with the same
    /// transaction ID.
    pub fn reply(&self, reply: Reply) -> Message {
        Message {
            xid: self.xid,
            body: Body::Reply(reply),
        }
    }
}

fn auth_wire_len(auth: &Auth) -> Result<usize, Error> {
    let body_len = match auth {
        Auth::None => 0,
        Auth::Sys(sys) => {
            if sys.machine_name.len() > MAX_MACHINE_NAME {
                return Err(Error::FieldTooLong {
                    limit: MAX_MACHINE_NAME,
                });
            }
            if sys.gids.len() > MAX_GIDS {
                return Err(Error::FieldTooLong { limit: MAX_GIDS });
            }
            20usize
                .saturating_add(sys.machine_name.len())
                .saturating_add(padding(sys.machine_name.len()))
                .saturating_add(sys.gids.len().saturating_mul(4))
        }
        Auth::Other { flavor, body } => {
            if body.len() > MAX_AUTH_BODY {
                return Err(Error::FieldTooLong {
                    limit: MAX_AUTH_BODY,
                });
            }
            if (*flavor == flavor::NONE && body.is_empty())
                || (*flavor == flavor::SYS && AuthSys::parse(body).is_ok())
            {
                return Err(Error::Unwritable);
            }
            body.len()
        }
    };
    Ok(8usize
        .saturating_add(body_len)
        .saturating_add(padding(body_len)))
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one UDP datagram or TCP record. Input above [`MAX_RECORD`] or
    /// authentication bodies above [`MAX_AUTH_BODY`] return [`Error::TooLong`].
    /// Short fields, nonzero padding, and unknown union tags return
    /// [`Error::Short`], [`Error::Padding`], and [`Error::Discriminant`].
    /// Bytes after a call header or successful reply are arguments or results.
    /// Extra bytes after any other reply return [`Error::Trailing`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Message::parse(bytes)
    }

    /// Appends one RPC message. Messages above [`MAX_RECORD`], authentication
    /// bodies above [`MAX_AUTH_BODY`], names above [`MAX_MACHINE_NAME`], or
    /// group counts above [`MAX_GIDS`] return [`Error::FieldTooLong`].
    /// An `Other` authentication or status value that aliases a typed variant
    /// returns [`Error::Unwritable`].
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let size = match &self.body {
            Body::Call(call) => 24usize
                .saturating_add(auth_wire_len(&call.cred)?)
                .saturating_add(auth_wire_len(&call.verf)?)
                .saturating_add(call.args.len()),
            Body::Reply(Reply::Accepted { verf, status }) => 16usize
                .saturating_add(auth_wire_len(verf)?)
                .saturating_add(match status {
                    Accept::Success(results) => results.len(),
                    Accept::ProgMismatch { .. } => 8,
                    _ => 0,
                }),
            Body::Reply(Reply::Denied(Reject::RpcMismatch { .. })) => 24,
            Body::Reply(Reply::Denied(Reject::AuthError(status))) => {
                if AuthStat::from_code(status.code()) != *status {
                    return Err(Error::Unwritable);
                }
                20
            }
        };
        if size > MAX_RECORD {
            return Err(Error::FieldTooLong { limit: MAX_RECORD });
        }

        let mut w = Writer::new();
        w.uint(self.xid);
        match &self.body {
            Body::Call(c) => {
                w.uint(0)
                    .uint(c.rpc_version)
                    .uint(c.program)
                    .uint(c.version)
                    .uint(c.procedure);
                c.cred.write(&mut w);
                c.verf.write(&mut w);
                let mut bytes = w
                    .finish()
                    .map_err(|_| Error::FieldTooLong { limit: MAX_RECORD })?;
                bytes.extend_from_slice(&c.args);
                out.extend_from_slice(&bytes);
                return Ok(());
            }
            Body::Reply(Reply::Accepted { verf, status }) => {
                w.uint(1).uint(0);
                verf.write(&mut w);
                w.uint(status.code());
                match status {
                    Accept::Success(results) => {
                        let mut bytes = w
                            .finish()
                            .map_err(|_| Error::FieldTooLong { limit: MAX_RECORD })?;
                        bytes.extend_from_slice(results);
                        out.extend_from_slice(&bytes);
                        return Ok(());
                    }
                    Accept::ProgMismatch { low, high } => {
                        w.uint(*low).uint(*high);
                    }
                    _ => {}
                }
            }
            Body::Reply(Reply::Denied(reject)) => {
                w.uint(1).uint(1);
                match reject {
                    Reject::RpcMismatch { low, high } => w.uint(0).uint(*low).uint(*high),
                    Reject::AuthError(stat) => w.uint(1).uint(stat.code()),
                };
            }
        }
        out.extend_from_slice(
            &w.finish()
                .map_err(|_| Error::FieldTooLong { limit: MAX_RECORD })?,
        );
        Ok(())
    }
}

/// One TCP record fragment, without its record mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Whether this fragment ends the current record.
    pub last: bool,
    /// Payload bytes, bounded by the decoder's record limit.
    pub data: Vec<u8>,
}

/// Reads TCP record marks and their payloads without retaining input.
///
/// The record limit bounds both each fragment and their sum. An oversized
/// record is refused from its mark, before its payload arrives. Only a
/// byte count is retained; [`records`] joins the payloads with [`Assemble`].
#[derive(Clone, Debug)]
pub struct Fragments {
    limit: usize,
    record_len: usize,
}

impl Wire for Fragment {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one fragment. A declared payload above [`MAX_RECORD`]
    /// returns [`Error::RecordTooLong`].
    /// Short input returns [`Error::Short`]; bytes after the
    /// fragment return [`Error::Trailing`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Fragments::new()
            .decode(bytes, true)
?
        {
            Step::Item(fragment, used) if used == bytes.len() => Ok(fragment),
            Step::Item(_, used) => {
                Err(Error::Trailing(bytes.len().saturating_sub(used)))
            }
            _ => Err(Error::Short),
        }
    }

    /// Appends a record mark and payload. A payload above [`MAX_RECORD`]
    /// returns [`Error::RecordTooLong`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_fragment(&self.data, self.last, out)
    }
}

/// Appends one bounded fragment without changing `out` on error.
fn write_fragment(data: &[u8], last: bool, out: &mut Vec<u8>) -> Result<(), Error> {
    if data.len() > MAX_RECORD {
        return Err(Error::RecordTooLong(MAX_RECORD));
    }
    let len = u32::try_from(data.len()).map_err(|_| Error::RecordTooLong(MAX_RECORD))?;
    let mark = len | if last { LAST_FRAGMENT } else { 0 };
    out.extend_from_slice(&mark.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

impl Fragments {
    /// Creates a fragment decoder with a record limit of [`MAX_RECORD`].
    pub fn new() -> Self {
        Self::with_limit(MAX_RECORD)
    }

    /// Sets the record limit, clamped to [`MAX_RECORD`]. Zero permits only
    /// empty fragments. Input capacity also includes [`RECORD_MARK_LEN`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_RECORD),
            record_len: 0,
        }
    }

    /// The maximum sum of payload bytes in one record.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Fragments {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Fragments {
    type Item = Fragment;
    type Error = Error;
    const NAME: &'static str = "ONC RPC record marking";

    fn capacity(&self) -> usize {
        self.limit.saturating_add(RECORD_MARK_LEN)
    }

    /// Reads one fragment. A fragment or record length above the configured
    /// limit returns [`Error::RecordTooLong`] before reading the payload.
    /// Partial input returns [`Step::Need`], including at EOF.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Fragment>, Error> {
        let Some(mark) = input.get(..RECORD_MARK_LEN) else {
            return Ok(Step::Need);
        };
        let mut bytes = [0; RECORD_MARK_LEN];
        bytes.copy_from_slice(mark);
        let mark = u32::from_be_bytes(bytes);
        let len =
            usize::try_from(mark & MAX_FRAGMENT).map_err(|_| Error::RecordTooLong(self.limit))?;
        let total = self
            .record_len
            .checked_add(len)
            .ok_or(Error::RecordTooLong(self.limit))?;
        if total > self.limit {
            return Err(Error::RecordTooLong(self.limit));
        }
        let used = RECORD_MARK_LEN
            .checked_add(len)
            .ok_or(Error::RecordTooLong(self.limit))?;
        let Some(data) = input.get(RECORD_MARK_LEN..used) else {
            return Ok(Step::Need);
        };
        let last = mark & LAST_FRAGMENT != 0;
        self.record_len = if last { 0 } else { total };
        Ok(Step::Item(
            Fragment {
                last,
                data: data.to_vec(),
            },
            used,
        ))
    }
}

/// TCP records assembled by the shared codec stage.
///
/// Items are [`Assembled::Message`]. The `Whole` variant is uninhabited.
/// Use [`records`] to apply the same limit to fragments and assembly.
pub type Records = Assemble<Fragments, fn(Fragment) -> codec::Fragment<Infallible>>;

/// Joins TCP fragments into records under `limit`, clamped to [`MAX_RECORD`].
///
/// Unread input is bounded by `limit + RECORD_MARK_LEN`. Assembly holds
/// at most `limit` payload bytes. EOF inside a fragment is reported by
/// [`codec::Stream`] as [`codec::Fail::Truncated`]. EOF after a nonfinal
/// fragment is [`AssembleError::Incomplete`], including empty fragments.
pub fn records(limit: usize) -> Records {
    let fragments = Fragments::with_limit(limit);
    let limit = fragments.limit();
    Assemble::new(fragments, limit, |f| codec::Fragment::Part {
        data: f.data,
        last: f.last,
    })
}

/// Decodes TCP records and parses each as an RPC message.
///
/// Invalid messages are error items, so the next record can still be read.
/// Record marking errors end the stream. Use [`Decode::map`] with a closure
/// to read program arguments from each [`Body::Call`].
pub fn messages(
    limit: usize,
) -> impl Decode<Item = Result<Message, Error>, Error = AssembleError<Error>> {
    records(limit).map(|record| match record {
        Assembled::Message(bytes) => <Message as Wire>::parse(&bytes),
        Assembled::Whole(never) => match never {},
    })
}

/// A complete TCP record's payload, bounded by [`MAX_RECORD`].
///
/// [`Wire::parse`] accepts exactly one record, with any number of fragments.
/// [`Record::write`] emits one final fragment and refuses oversized payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record(
    /// Payload bytes without TCP record marks.
    pub Vec<u8>,
);

impl Record {
    /// Wraps a complete RPC message for TCP. Invalid message fields return
    /// the same [`Error`] as [`Message::write`].
    pub fn from_message(message: &Message) -> Result<Self, Error> {
        message.to_bytes().map(Self)
    }
}

impl Wire for Record {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads all fragments of exactly one record. A fragment or their sum
    /// above [`MAX_RECORD`] returns [`Error::RecordTooLong`]. An assembly
    /// that ends before its final fragment is [`Error::Incomplete`].
    /// A partial mark or payload returns [`Error::Short`];
    /// bytes after the final fragment return [`Error::Trailing`].
    fn parse(mut input: &[u8]) -> Result<Self, Error> {
        let mut decoder = records(MAX_RECORD);
        loop {
            match decoder.decode(input, true).map_err(|e| match e {
                AssembleError::Inner(e) => e,
                AssembleError::TooLong { limit } => Error::RecordTooLong(limit),
                AssembleError::Allocation => Error::Allocation,
                AssembleError::Incomplete { held } => Error::Incomplete { held },
            })? {
                Step::Item(Assembled::Message(data), used) => {
                    let trailing = input.len().saturating_sub(used);
                    return if trailing == 0 {
                        Ok(Self(data))
                    } else {
                        Err(Error::Trailing(trailing))
                    };
                }
                Step::Item(Assembled::Whole(never), _) => match never {},
                Step::Skip(used) => input = input.get(used..).ok_or(Error::Short)?,
                Step::Need | Step::End => return Err(Error::Short),
            }
        }
    }

    /// Appends a record mark and payload. A payload above [`MAX_RECORD`]
    /// returns [`Error::RecordTooLong`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_fragment(&self.0, true, out)
    }
}

/// Encodes one complete record in fragments of at most `fragment_len` bytes.
/// A zero fragment size becomes one. Sizes above [`MAX_FRAGMENT`] use that
/// limit. Records above [`MAX_RECORD`] return an error. An empty record
/// has one empty final fragment.
pub fn encode_fragments(record: &[u8], fragment_len: usize) -> Result<Vec<u8>, Error> {
    if record.len() > MAX_RECORD {
        return Err(Error::RecordTooLong(MAX_RECORD));
    }
    let size = fragment_len.clamp(1, MAX_FRAGMENT as usize);
    let count = record.len().div_ceil(size).max(1);
    let mut out = Vec::with_capacity(record.len().saturating_add(count.saturating_mul(4)));
    let mut chunks = record.chunks(size).peekable();
    if chunks.peek().is_none() {
        write_fragment(&[], true, &mut out)?;
    }
    while let Some(chunk) = chunks.next() {
        write_fragment(chunk, chunks.peek().is_none(), &mut out)?;
    }
    Ok(out)
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self { Error::Short }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::codec::{Fail, Stream, contract, finish, pump, test_support};
    use fictionet::stdlib::portmap::{
        self, Mapping, Rpcb, silent_on_failure, PmapRequest, PmapResult, Request, RpcbRequest, RpcbResult,
    };
    use std::net::SocketAddr;

    #[test]
    fn codec_fragments_and_records() {
        let payload = b"fragmented RPC payload";
        let mut wire = vec![0; RECORD_MARK_LEN]; // Empty nonfinal fragment.
        wire.extend(encode_fragments(payload, 3).unwrap());
        wire.extend(Record((b"").to_vec()).to_bytes().unwrap());
        contract::check_decode_with_alloc_limit(
            || Fragments::with_limit(payload.len()),
            &wire,
            2 * (payload.len() + RECORD_MARK_LEN),
        );
        contract::check_decode_with_held_limit(
            || super::records(payload.len()),
            &wire,
            payload.len(),
        );

        let mut stream = Stream::new(super::records(payload.len()));
        let mut items = Vec::new();
        for byte in &wire {
            assert_eq!(
                pump(&mut stream, core::slice::from_ref(byte), |item| items
                    .push(item)),
                Ok(1)
            );
            assert!(stream.buffered() <= payload.len() + RECORD_MARK_LEN);
            assert!(stream.held() <= payload.len());
        }
        assert_eq!(finish(&mut stream, |item| items.push(item)), Ok(()));
        assert_eq!(
            items,
            vec![
                Assembled::Message(payload.to_vec()),
                Assembled::Message(Vec::new())
            ]
        );
    }

    #[test]
    fn codec_record_limits_are_checked_from_marks() {
        let mut fragments = Fragments::with_limit(3);
        assert_eq!(
            fragments.decode(&[0, 0, 0, 2, 1, 2], false),
            Ok(Step::Item(
                Fragment {
                    last: false,
                    data: vec![1, 2]
                },
                6
            ))
        );
        assert_eq!(
            fragments.decode(&[0x80, 0, 0, 2], false),
            Err(Error::RecordTooLong(3))
        );
        assert_eq!(
            Fragments::with_limit(usize::MAX).capacity(),
            MAX_RECORD + RECORD_MARK_LEN
        );

        let wire = [0, 0, 0, 2, 1, 2, 0x80, 0, 0, 2];
        contract::check_decode_with_alloc_limit(
            || super::records(3),
            &wire,
            2 * (3 + RECORD_MARK_LEN),
        );
        let mut stream = Stream::new(super::records(3));
        let error = Fail::Protocol(AssembleError::Inner(Error::RecordTooLong(3)));
        assert_eq!(pump(&mut stream, &wire, |_| {}), Err(error.clone()));
        assert_eq!(stream.failed(), Some(&error));
        assert!(stream.next().is_none());
        assert_eq!(stream.push(b"ignored"), 7);

        // The generic stage still enforces its own limit independently.
        let mut smaller =
            Assemble::new(
                Fragments::with_limit(8),
                1,
                |f: Fragment| codec::Fragment::<Infallible>::Part {
                    data: f.data,
                    last: f.last,
                },
            );
        assert_eq!(
            smaller.decode(&Record((b"ab").to_vec()).to_bytes().unwrap(), false),
            Err(AssembleError::TooLong { limit: 1 })
        );
    }

    #[test]
    fn codec_record_eof_and_zero_limit() {
        for payload in [b"".as_slice(), b"a".as_slice()] {
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(payload);
            let mut stream = Stream::new(super::records(8));
            assert_eq!(
                pump(&mut stream, &wire, |_| panic!("nonfinal fragment")),
                Ok(wire.len())
            );
            assert_eq!(
                finish(&mut stream, |_| panic!("unfinished record")),
                Err(Fail::Protocol(AssembleError::Incomplete {
                    held: payload.len()
                }))
            );
        }
        for partial in [b"\x80".as_slice(), b"\x80\0\0\x02x".as_slice()] {
            let mut stream = Stream::new(super::records(8));
            assert_eq!(
                pump(&mut stream, partial, |_| panic!("partial fragment")),
                Ok(partial.len())
            );
            assert_eq!(
                finish(&mut stream, |_| panic!("partial fragment")),
                Err(Fail::Truncated {
                    unread: partial.len()
                })
            );
        }
        contract::check_decode(|| super::records(0), &[0, 0, 0, 0, 0x80, 0, 0, 0]);
        contract::check_decode(|| super::records(0), &[0, 0, 0, 1]);
        let mut empty = Stream::new(super::records(0));
        assert_eq!(finish(&mut empty, |_| panic!("empty stream")), Ok(()));
    }

    #[test]
    fn codec_record_wire_is_exact_and_strict() {
        for data in [Vec::new(), b"record".to_vec(), vec![7; MAX_RECORD]] {
            let record = Record(data.clone());
            contract::check_wire_value(&record);
            let segmented = encode_fragments(&data, 127).unwrap();
            assert_eq!(Record::parse(&segmented), Ok(record));
            contract::check_wire::<Record>(&segmented);
        }
        let oversized = Record(vec![3; MAX_RECORD + 1]);
        let mut out = vec![1, 2, 3];
        assert_eq!(
            oversized.write(&mut out),
            Err(Error::RecordTooLong(MAX_RECORD))
        );
        assert_eq!(out, [1, 2, 3]);
        assert_eq!(oversized.to_bytes(), Err(Error::RecordTooLong(MAX_RECORD)));
        let mut trailing = Record((b"a").to_vec()).to_bytes().unwrap();
        trailing.extend(Record((b"b").to_vec()).to_bytes().unwrap());
        assert_eq!(Record::parse(&trailing), Err(Error::Trailing(5)));
        assert_eq!(Record::parse(&[]), Err(Error::Short));
        assert_eq!(
            Record::parse(&[0, 0, 0, 0]),
            Err(Error::Incomplete {
                held: 0
            })
        );
    }

    #[test]
    fn codec_message_wire_round_trips() {
        let call = Message::parse(&nfs_call_bytes()).unwrap();
        contract::check_wire::<Message>(&nfs_call_bytes());
        let mut messages = vec![call.clone()];
        for status in [
            Accept::Success(vec![1, 2, 3]),
            Accept::ProgUnavail,
            Accept::ProgMismatch { low: 3, high: 4 },
            Accept::ProcUnavail,
            Accept::GarbageArgs,
            Accept::SystemErr,
        ] {
            messages.push(call.reply(Reply::accepted(status)));
        }
        messages.push(call.reply(Reply::Denied(Reject::RpcMismatch { low: 2, high: 2 })));
        for code in 0..=15 {
            messages.push(call.reply(Reply::Denied(Reject::AuthError(AuthStat::from_code(code)))));
        }
        let max_auth = Auth::Sys(AuthSys {
            stamp: 1,
            machine_name: "a".repeat(MAX_MACHINE_NAME),
            uid: 2,
            gid: 3,
            gids: vec![4; MAX_GIDS],
        });
        for auth in [
            max_auth,
            Auth::Other {
                flavor: 99,
                body: vec![5; MAX_AUTH_BODY],
            },
            Auth::Other {
                flavor: flavor::NONE,
                body: vec![1],
            },
            Auth::Other {
                flavor: flavor::SYS,
                body: vec![1],
            },
        ] {
            let mut c = Call::new(1, 2, 3, vec![4]);
            c.cred = auth.clone();
            c.verf = auth.clone();
            messages.push(Message {
                xid: 7,
                body: Body::Call(c),
            });
            messages.push(call.reply(Reply::Accepted {
                verf: auth,
                status: Accept::Success(vec![9]),
            }));
        }
        for message in messages {
            contract::check_wire_value(&message);
            assert_eq!(
                <Message as Wire>::to_bytes(&message),
                Ok(message.to_bytes().unwrap())
            );
        }
    }

    #[test]
    fn codec_message_writer_refuses_loss_and_rolls_back() {
        let sys = AuthSys {
            stamp: 1,
            machine_name: "host".into(),
            uid: 2,
            gid: 3,
            gids: vec![],
        };
        let mut long_name = sys.clone();
        long_name.machine_name = "x".repeat(MAX_MACHINE_NAME + 1);
        let mut long_groups = sys.clone();
        long_groups.gids = vec![0; MAX_GIDS + 1];
        for (auth, error) in [
            (
                Auth::Sys(long_name),
                Error::FieldTooLong {
                    limit: MAX_MACHINE_NAME,
                },
            ),
            (
                Auth::Sys(long_groups),
                Error::FieldTooLong { limit: MAX_GIDS },
            ),
            (
                Auth::Other {
                    flavor: 99,
                    body: vec![0; MAX_AUTH_BODY + 1],
                },
                Error::FieldTooLong {
                    limit: MAX_AUTH_BODY,
                },
            ),
            (
                Auth::Other {
                    flavor: flavor::NONE,
                    body: vec![],
                },
                Error::Unwritable,
            ),
            (
                Auth::Other {
                    flavor: flavor::SYS,
                    body: sys.to_bytes().unwrap(),
                },
                Error::Unwritable,
            ),
        ] {
            let mut call = Call::new(1, 2, 3, Vec::new());
            call.cred = auth.clone();
            for message in [
                Message {
                    xid: 1,
                    body: Body::Call(call.clone()),
                },
                Message {
                    xid: 1,
                    body: Body::Call(Call {
                        cred: Auth::None,
                        verf: auth.clone(),
                        ..call
                    }),
                },
                Message {
                    xid: 1,
                    body: Body::Reply(Reply::Accepted {
                        verf: auth,
                        status: Accept::ProgUnavail,
                    }),
                },
            ] {
                let mut out = vec![1, 2, 3];
                assert_eq!(message.write(&mut out), Err(error));
                assert_eq!(out, [1, 2, 3]);
                contract::check_wire_value(&message);
                assert_eq!(message.to_bytes(), Err(error));
            }
        }
        let alias = Message {
            xid: 1,
            body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::Other(0)))),
        };
        assert_eq!(
            alias.write(&mut Vec::new()),
            Err(Error::Unwritable)
        );
        contract::check_wire_value(&alias);
    }

    #[test]
    fn codec_message_size_includes_the_header() {
        for message in [
            Message {
                xid: 1,
                body: Body::Call(Call::new(1, 2, 3, vec![0; MAX_RECORD - 40])),
            },
            Message {
                xid: 2,
                body: Body::Reply(Reply::success(vec![0; MAX_RECORD - 24])),
            },
        ] {
            assert_eq!(
                <Message as Wire>::to_bytes(&message).unwrap().len(),
                MAX_RECORD
            );
            contract::check_wire_value(&message);
            let mut too_long = message.clone();
            match &mut too_long.body {
                Body::Call(call) => call.args.push(1),
                Body::Reply(Reply::Accepted {
                    status: Accept::Success(data),
                    ..
                }) => data.push(1),
                _ => unreachable!(),
            }
            let mut out = vec![42];
            assert_eq!(
                too_long.write(&mut out),
                Err(Error::FieldTooLong { limit: MAX_RECORD })
            );
            assert_eq!(out, [42]);
            assert_eq!(
                too_long.to_bytes(),
                Err(Error::FieldTooLong { limit: MAX_RECORD })
            );
        }
    }

    /// RFC 4506, section 7: the "sillyprog" file.
    const FILE: [u8; 48] = [
        0, 0, 0, 9, b's', b'i', b'l', b'l', b'y', b'p', b'r', b'o', b'g', 0, 0, 0, // filename
        0, 0, 0, 2, // type EXEC
        0, 0, 0, 4, b'l', b'i', b's', b'p', // interpretor
        0, 0, 0, 4, b'j', b'o', b'h', b'n', // owner
        0, 0, 0, 6, b'(', b'q', b'u', b'i', b't', b')', 0, 0, // data
    ];

    fn read_file(b: &[u8]) -> Result<(String, i32, String, String, Vec<u8>), Error> {
        let mut r = Reader::new(b);
        let name = r.string(255)?.to_string();
        let kind = r.enumeration()?;
        if kind != 2 {
            return Err(Error::Discriminant(kind as u32));
        }
        let interp = r.string(255)?.to_string();
        let owner = r.string(255)?.to_string();
        let data = r.opaque(1024)?.to_vec();
        r.finish()?;
        Ok((name, kind, interp, owner, data))
    }

    #[test]
    fn rfc4506_file_example() {
        let (name, kind, interp, owner, data) = read_file(&FILE).unwrap();
        assert_eq!(
            (name.as_str(), kind, interp.as_str(), owner.as_str()),
            ("sillyprog", 2, "lisp", "john")
        );
        assert_eq!(data, b"(quit)");
        let mut w = Writer::new();
        w.string(&name)
            .enumeration(kind)
            .string(&interp)
            .string(&owner)
            .opaque(&data);
        assert_eq!(w.finish().unwrap(), FILE);
        // Every truncated prefix ends early.
        for n in 0..FILE.len() {
            assert_eq!(read_file(&FILE[..n]), Err(Error::Short), "{n} bytes");
        }
    }

    #[test]
    fn basic_types() {
        let mut w = Writer::new();
        w.int(-2)
            .uint(0xdead_beef)
            .hyper(-3)
            .uhyper(0x0102_0304_0506_0708)
            .bool(true)
            .bool(false);
        w.opaque_fixed(&[1, 2, 3, 4, 5]);
        let bytes = w.finish().unwrap();
        assert_eq!(&bytes[..4], &[0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(
            &bytes[8..16],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd]
        );
        assert_eq!(&bytes[16..24], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[32..], &[1, 2, 3, 4, 5, 0, 0, 0]);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.int(), Ok(-2));
        assert_eq!(r.uint(), Ok(0xdead_beef));
        assert_eq!(r.hyper(), Ok(-3));
        assert_eq!(r.uhyper(), Ok(0x0102_0304_0506_0708));
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.bool(), Ok(false));
        assert_eq!(r.opaque_fixed(5), Ok(&[1u8, 2, 3, 4, 5][..]));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.position(), bytes.len());
    }

    #[test]
    fn arrays_and_optionals() {
        let mut w = Writer::new();
        w.array(&[7u32, 8, 9], |w, v| {
            w.uint(*v);
        });
        w.optional(Some(&5u32), |w, v| {
            w.uint(*v);
        });
        w.optional(None::<&u32>, |w, v| {
            w.uint(*v);
        });
        let bytes = w.finish().unwrap();
        assert_eq!(
            bytes,
            [
                0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0
            ]
        );
        let mut r = Reader::new(&bytes);
        assert_eq!(r.array(3, Reader::uint), Ok(vec![7, 8, 9]));
        assert_eq!(r.optional(Reader::uint), Ok(Some(5)));
        assert_eq!(r.optional(Reader::uint), Ok(None));
        assert_eq!(r.finish(), Ok(()));
        // Over the caller's limit, and a count the bytes cannot hold.
        assert_eq!(
            Reader::new(&bytes).array(2, Reader::uint),
            Err(Error::TooLong(3))
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).array(usize::MAX, Reader::uint),
            Err(Error::Short)
        );
    }

    #[test]
    fn xdr_errors() {
        assert_eq!(Reader::new(&[0, 0, 0]).uint(), Err(Error::Short));
        assert_eq!(Reader::new(&[0, 0, 0, 2]).bool(), Err(Error::Bool(2)));
        assert_eq!(
            Reader::new(&[0, 0, 0, 1, 7, 0, 1, 0]).opaque(4),
            Err(Error::Padding)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0]).opaque(4),
            Err(Error::TooLong(5))
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 2, 0xc3, 0x28, 0, 0]).string(4),
            Err(Error::Utf8)
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).opaque(usize::MAX),
            Err(Error::Short)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 0, 1]).optional(Reader::uint),
            Ok(None)
        );
        let mut r = Reader::new(&[0, 0, 0, 0, 1]);
        r.uint().unwrap();
        assert_eq!(r.finish(), Err(Error::Trailing(1)));
        assert_eq!(r.rest(), &[1]);
        assert_eq!(r.finish(), Ok(()));
        // Errors have messages.
        assert!(!Error::Trailing(3).to_string().is_empty());
        assert!(!Error::RecordTooLong(8).to_string().is_empty());
    }

    /// A call to NFS version 3, GETATTR, with AUTH_SYS, written out by hand.
    fn nfs_call_bytes() -> Vec<u8> {
        let mut b = vec![
            0x12, 0x34, 0x56, 0x78, // xid
            0, 0, 0, 0, // CALL
            0, 0, 0, 2, // rpcvers
            0, 1, 0x86, 0xa3, // program 100003
            0, 0, 0, 3, // version
            0, 0, 0, 1, // procedure GETATTR
            0, 0, 0, 1, // AUTH_SYS
            0, 0, 0, 32, // body length
            0, 0, 0, 9, // stamp
            0, 0, 0, 5, b'h', b'o', b's', b't', b'1', 0, 0, 0, // machine name
            0, 0, 3, 0xe8, // uid 1000
            0, 0, 0, 100, // gid 100
            0, 0, 0, 1, 0, 0, 0, 10, // gids [10]
            0, 0, 0, 0, 0, 0, 0, 0, // verifier AUTH_NONE
        ];
        b.extend_from_slice(&[0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd]); // a file handle
        b
    }

    #[test]
    fn call_with_auth_sys() {
        let bytes = nfs_call_bytes();
        let m = Message::parse(&bytes).unwrap();
        let sys = AuthSys {
            stamp: 9,
            machine_name: "host1".into(),
            uid: 1000,
            gid: 100,
            gids: vec![10],
        };
        let call = Call {
            rpc_version: 2,
            program: 100_003,
            version: 3,
            procedure: 1,
            cred: Auth::Sys(sys),
            verf: Auth::None,
            args: vec![0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd],
        };
        assert_eq!(
            m,
            Message {
                xid: 0x1234_5678,
                body: Body::Call(call)
            }
        );
        assert_eq!(m.to_bytes().unwrap(), bytes);
        // Every truncated prefix up to the arguments fails, and none panics.
        for n in 0..bytes.len() {
            let r = Message::parse(&bytes[..n]);
            if n < bytes.len() - 8 {
                assert_eq!(r, Err(Error::Short), "{n} bytes");
            } else {
                assert!(r.is_ok());
            }
        }
    }

    #[test]
    fn auth_bodies_that_do_not_read() {
        // AUTH_NONE with a body, and AUTH_SYS with a short body, stay as
        // they are.
        let mut w = Writer::new();
        Auth::Other {
            flavor: 0,
            body: vec![1, 2, 3, 4],
        }
        .write(&mut w);
        Auth::Other {
            flavor: 1,
            body: vec![0, 0, 0, 1],
        }
        .write(&mut w);
        Auth::Other {
            flavor: flavor::RPCSEC_GSS,
            body: vec![9; 12],
        }
        .write(&mut w);
        let bytes = w.finish().unwrap();
        let mut r = Reader::new(&bytes);
        assert_eq!(
            Auth::read(&mut r),
            Ok(Auth::Other {
                flavor: 0,
                body: vec![1, 2, 3, 4]
            })
        );
        assert_eq!(
            Auth::read(&mut r),
            Ok(Auth::Other {
                flavor: 1,
                body: vec![0, 0, 0, 1]
            })
        );
        assert_eq!(Auth::read(&mut r).unwrap().flavor(), 6);
        // A body over 400 bytes.
        let mut w = Writer::new();
        w.uint(1).opaque(&[0; 404]);
        assert_eq!(
            Auth::read(&mut Reader::new(&w.finish().unwrap())),
            Err(Error::TooLong(404))
        );
    }

    #[test]
    fn every_reply_status() {
        let replies = [
            Reply::success(vec![0, 0, 0, 1]),
            Reply::accepted(Accept::ProgUnavail),
            Reply::accepted(Accept::ProgMismatch { low: 2, high: 4 }),
            Reply::accepted(Accept::ProcUnavail),
            Reply::accepted(Accept::GarbageArgs),
            Reply::accepted(Accept::SystemErr),
            Reply::Denied(Reject::RpcMismatch { low: 2, high: 2 }),
        ];
        let stats = (0..=15).map(|n| Reply::Denied(Reject::AuthError(AuthStat::from_code(n))));
        for reply in replies.into_iter().chain(stats) {
            let m = Message {
                xid: 42,
                body: Body::Reply(reply),
            };
            let bytes = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes), Ok(m.clone()));
            for n in 0..bytes.len() {
                let r = Message::parse(&bytes[..n]);
                let success = matches!(
                    m.body,
                    Body::Reply(Reply::Accepted {
                        status: Accept::Success(_),
                        ..
                    })
                );
                if !(success && n >= 24) {
                    assert_eq!(r, Err(Error::Short), "{m:?} at {n}");
                }
            }
        }
        // Spot check one layout: denied, AUTH_ERROR, AUTH_TOOWEAK.
        let m = Message {
            xid: 1,
            body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::TooWeak))),
        };
        assert_eq!(
            m.to_bytes().unwrap(),
            [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 5]
        );
        for n in 0..=100 {
            assert_eq!(AuthStat::from_code(n).code(), n);
        }
        assert_eq!(Accept::Success(vec![]).code(), 0);
    }

    #[test]
    fn message_errors() {
        let d = Error::Discriminant;
        assert_eq!(Message::parse(&[0, 0, 0, 1, 0, 0, 0, 2]), Err(d(2)));
        assert_eq!(
            Message::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2]),
            Err(d(2))
        );
        let accepted = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut b = accepted.to_vec();
        b.extend_from_slice(&[0, 0, 0, 6]);
        assert_eq!(Message::parse(&b), Err(d(6)));
        assert_eq!(
            Message::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2]),
            Err(d(2))
        );
        // Bytes after a reply that has no results.
        let mut b = accepted.to_vec();
        b.extend_from_slice(&[0, 0, 0, 1, 9]);
        assert_eq!(Message::parse(&b), Err(Error::Trailing(1)));
        // A message reply keeps the xid.
        let call = Request::Pmap(PmapRequest::Null).call(77).unwrap();
        assert_eq!(call.reply(Reply::success(vec![])).xid, 77);
    }

    #[test]
    fn record_fragments_round_trip() {
        let msg = nfs_call_bytes();
        let one = Record(msg.clone()).to_bytes().unwrap();
        assert_eq!(&one[..4], &(LAST_FRAGMENT | msg.len() as u32).to_be_bytes());
        let mut bytes = one.clone();
        bytes.extend(encode_fragments(&msg, 5).unwrap());
        bytes.extend(Record(Vec::new()).to_bytes().unwrap());
        contract::check_decode(|| super::records(MAX_RECORD), &bytes);
        let mut stream = Stream::new(super::records(MAX_RECORD));
        let mut got = Vec::new();
        codec::pump(&mut stream, &bytes, |item| got.push(item)).unwrap();
        codec::finish(&mut stream, |item| got.push(item)).unwrap();
        assert_eq!(
            got,
            [
                Assembled::Message(msg.clone()),
                Assembled::Message(msg),
                Assembled::Message(vec![])
            ]
        );
        for n in 0..one.len() {
            let mut stream = Stream::new(super::records(MAX_RECORD));
            assert_eq!(stream.push(&one[..n]), n);
            assert_eq!(stream.next(), None);
        }
        assert_eq!(Record(vec![]).to_bytes().unwrap(), [0x80, 0, 0, 0]);
        assert_eq!(
            encode_fragments(&[1, 2], 0).unwrap(),
            [0, 0, 0, 1, 1, 0x80, 0, 0, 1, 2]
        );
    }

    #[test]
    fn record_limit() {
        let mut stream = Stream::new(super::records(10));
        let bytes = encode_fragments(&[0; 10], 4).unwrap();
        let mut got = Vec::new();
        codec::pump(&mut stream, &bytes, |item| got.push(item)).unwrap();
        assert_eq!(got, [Assembled::Message(vec![0; 10])]);
        let error = codec::pump(
            &mut stream,
            &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 3],
            |_| panic!(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            Fail::Protocol(AssembleError::Inner(Error::RecordTooLong(10)))
        );
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        assert_eq!(stream.push(&[0; 100]), 100);
        let mut stream = Stream::new(super::records(MAX_RECORD));
        assert_eq!(stream.push(&[0xff; 4]), 4);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(AssembleError::Inner(
                Error::RecordTooLong(MAX_RECORD)
            ))))
        );
        assert_eq!(Fragments::with_limit(usize::MAX).limit(), MAX_RECORD);
    }

    #[test]
    fn noncanonical_authentication_is_refused() {
        let sys = AuthSys {
            stamp: 1,
            machine_name: "m".into(),
            uid: 2,
            gid: 3,
            gids: vec![4],
        };
        for auth in [
            Auth::Other {
                flavor: 0,
                body: vec![],
            },
            Auth::Other {
                flavor: 1,
                body: sys.to_bytes().unwrap(),
            },
        ] {
            let mut call = Call::new(1, 2, 3, vec![]);
            call.cred = auth;
            let message = Message {
                xid: 1,
                body: Body::Call(call),
            };
            assert_eq!(
                message.to_bytes(),
                Err(Error::Unwritable)
            );
            contract::check_wire_value(&message);
        }
        let message = Message {
            xid: 1,
            body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::Other(5)))),
        };
        assert_eq!(
            message.to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(AuthSys::parse(&sys.to_bytes().unwrap()), Ok(sys));
    }

    #[test]
    fn array_count_does_not_size_the_allocation() {
        // A count of a million, with the bytes to back it, and items that
        // are large in memory. The first item fails, so nothing is kept.
        let mut bytes = (1u32 << 20).to_be_bytes().to_vec();
        bytes.resize(4 + (4 << 20), 0);
        let big = |r: &mut Reader<'_>| -> Result<[u8; 1 << 16], Error> {
            r.uint()?;
            Err(Error::Padding)
        };
        assert_eq!(
            Reader::new(&bytes).array(usize::MAX, big),
            Err(Error::Padding)
        );
        // Items that read still all come back.
        assert_eq!(
            Reader::new(&bytes)
                .array(usize::MAX, Reader::uint)
                .map(|v| v.len()),
            Ok(1 << 20)
        );
    }

    #[test]
    fn many_small_records_take_linear_time() {
        let count = 1 << 21;
        let mut stream = Stream::new(super::records(64));
        let mut got = 0;
        codec::pump(&mut stream, &[0x80, 0, 0, 0].repeat(count), |item| {
            assert_eq!(item, Assembled::Message(vec![]));
            got += 1;
        })
        .unwrap();
        assert_eq!(got, count);
        let mut items = Vec::new();
        codec::pump(
            &mut stream,
            &encode_fragments(&[1, 2, 3], 2).unwrap(),
            |item| items.push(item),
        )
        .unwrap();
        assert_eq!(items, [Assembled::Message(vec![1, 2, 3])]);
        assert_eq!(stream.buffered(), 0);
    }

    #[test]
    fn stream_stops_after_a_broken_mark() {
        let mut stream = Stream::new(super::records(8));
        let mut bytes = Record(vec![1, 2]).to_bytes().unwrap();
        bytes.extend_from_slice(&[0, 0, 0, 4, 9, 9, 9, 9, 0x80, 0, 0, 5]);
        bytes.extend_from_slice(&[7; 100]);
        let mut items = Vec::new();
        let error = codec::pump(&mut stream, &bytes, |item| items.push(item)).unwrap_err();
        assert_eq!(items, [Assembled::Message(vec![1, 2])]);
        assert_eq!(
            error,
            Fail::Protocol(AssembleError::Inner(Error::RecordTooLong(8)))
        );
        assert!(stream.buffered() <= 12);
        assert_eq!(stream.push(&[0; 1024]), 1024);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
    }

    #[test]
    fn stream_clears_assembly_after_a_long_record() {
        let mut stream = Stream::new(super::records(MAX_RECORD));
        let bytes = encode_fragments(&vec![5; 1 << 20], 4096).unwrap();
        let mut lengths = Vec::new();
        codec::pump(&mut stream, &bytes, |item| {
            let Assembled::Message(data) = item;
            lengths.push(data.len());
        })
        .unwrap();
        assert_eq!(lengths, [1 << 20]);
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.held(), 0);
        let bytes = Record(vec![1]).to_bytes().unwrap();
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(Assembled::Message(vec![1]))));
    }

    #[test]
    fn stream_reports_incomplete_records_at_eof() {
        for bytes in [
            &[0, 0, 0, 0][..],
            &[0, 0, 0, 0, 0x80, 0, 0][..],
            &[0x80, 0, 0, 4, 1][..],
        ] {
            contract::check_decode(|| super::records(MAX_RECORD), bytes);
            let mut stream = Stream::new(super::records(MAX_RECORD));
            assert_eq!(stream.push(bytes), bytes.len());
            assert_eq!(stream.next(), None);
            stream.end();
            assert!(stream.next().unwrap().is_err());
            assert_eq!(stream.next(), None);
        }
        let bytes = [0, 0, 0, 0, 0x80, 0, 0, 0];
        assert_eq!(Record::parse(&bytes), Ok(Record(vec![])));
    }

    #[test]
    fn record_writers_refuse_excess_data() {
        let record = Record(vec![3; MAX_RECORD]);
        for bytes in [
            record.to_bytes().unwrap(),
            encode_fragments(&record.0, 1 << 16).unwrap(),
        ] {
            assert_eq!(Record::parse(&bytes), Ok(record.clone()));
        }
        let record = Record(vec![3; MAX_RECORD + 1]);
        assert_eq!(record.to_bytes(), Err(Error::RecordTooLong(MAX_RECORD)));
        assert_eq!(
            encode_fragments(&record.0, 1 << 16),
            Err(Error::RecordTooLong(MAX_RECORD))
        );
    }

    #[test]
    fn arrays_of_items_with_no_bytes() {
        // Fixed opaque data of length 0 takes no bytes (RFC 4506, 4.9).
        let mut w = Writer::new();
        w.array(&[(); 3], |w, _| {
            w.opaque_fixed(&[]);
        });
        let bytes = w.finish().unwrap();
        assert_eq!(bytes, [0, 0, 0, 3]);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.array(3, |r| r.opaque_fixed(0)), Ok(vec![&[][..]; 3]));
        assert_eq!(r.finish(), Ok(()));
        let full = (MAX_ARRAY_RESERVE as u32).to_be_bytes();
        assert_eq!(
            Reader::new(&full)
                .array(usize::MAX, |r| r.opaque_fixed(0))
                .map(|v| v.len()),
            Ok(MAX_ARRAY_RESERVE)
        );
        // Past that, a count still needs 4 bytes an item.
        let over = (MAX_ARRAY_RESERVE as u32 + 1).to_be_bytes();
        assert_eq!(
            Reader::new(&over).array(usize::MAX, |r| r.opaque_fixed(0)),
            Err(Error::Short)
        );
        // Items that need bytes still end early.
        assert_eq!(
            Reader::new(&[0, 0, 0, 2, 0, 0, 0, 1]).array(9, Reader::uint),
            Err(Error::Short)
        );
    }

    #[test]
    fn array_room_is_bounded_in_bytes() {
        assert!(reserve::<[u8; 1 << 16]>(1024) * (1 << 16) <= MAX_RESERVE_BYTES);
        assert!(reserve::<[u8; 1 << 20]>(1024) <= 1);
        assert_eq!(reserve::<u32>(5), 5);
        assert_eq!(reserve::<u32>(1 << 20), MAX_ARRAY_RESERVE);
        assert_eq!(reserve::<()>(1 << 20), MAX_ARRAY_RESERVE);
    }

    #[test]
    fn callit_and_bcast_fail_without_a_reply() {
        let call = |version, procedure| Call::new(PMAP_PROGRAM, version, procedure, vec![]);
        for version in 2..=4 {
            assert!(silent_on_failure(&call(version, procedure::CALLIT)));
            for p in [0, 1, 2, 3, 4, 6, 10] {
                assert!(!silent_on_failure(&call(version, p)));
            }
        }
        assert!(!silent_on_failure(&call(5, procedure::CALLIT)));
        assert!(!silent_on_failure(&Call::new(
            100_003,
            3,
            procedure::CALLIT,
            vec![]
        )));
    }

    #[test]
    fn portmap_getport() {
        let request = Request::Pmap(PmapRequest::GetPort(Mapping {
            program: 100_003,
            version: 3,
            protocol: IPPROTO_UDP,
            port: 0,
        }));
        let m = request.call(1).unwrap();
        let bytes = m.to_bytes().unwrap();
        #[rustfmt::skip]
        let expect = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 3,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 17, 0, 0, 0, 0,
        ];
        assert_eq!(bytes, expect);
        let Body::Call(call) = Message::parse(&bytes).unwrap().body else {
            panic!()
        };
        assert_eq!(Request::from_call(&call).unwrap().call(1).unwrap(), m);
        assert_eq!(
            PmapResult::parse(
                procedure::GETPORT,
                &PmapResult::Port(2049).to_bytes().unwrap()
            ),
            Ok(PmapResult::Port(2049))
        );
        assert_eq!(
            PmapResult::parse(procedure::GETPORT, &[0, 0, 8]),
            Err(portmap::Error::Xdr(Error::Short))
        );
    }

    #[test]
    fn portmap_requests_and_errors() {
        let map = Mapping {
            program: 100_005,
            version: 1,
            protocol: IPPROTO_TCP,
            port: 635,
        };
        for req in [
            PmapRequest::Null,
            PmapRequest::Set(map),
            PmapRequest::Unset(map),
            PmapRequest::Dump,
        ] {
            let req = Request::Pmap(req);
            let call = req.to_call().unwrap();
            assert_eq!(Request::from_call(&call), Ok(req));
        }
        let mut call = Request::Pmap(PmapRequest::Set(map)).to_call().unwrap();
        call.program = 100_003;
        assert_eq!(Request::from_call(&call), Err(portmap::Error::Program(100_003)));
        call.program = PMAP_PROGRAM;
        call.version = 5;
        assert_eq!(Request::from_call(&call), Err(portmap::Error::Version(5)));
        call.version = 2;
        call.procedure = 6;
        assert_eq!(Request::from_call(&call), Err(portmap::Error::Procedure(6)));
        call.procedure = procedure::SET;
        call.args.pop();
        assert_eq!(
            Request::from_call(&call),
            Err(portmap::Error::Xdr(Error::Short))
        );
        call.procedure = procedure::NULL;
        assert_eq!(
            Request::from_call(&call),
            Err(portmap::Error::Xdr(Error::Trailing(call.args.len())))
        );
        assert_eq!(
            PmapResult::parse(procedure::SET, &PmapResult::Bool(true).to_bytes().unwrap()),
            Ok(PmapResult::Bool(true))
        );
        assert_eq!(
            PmapResult::parse(procedure::SET, &[0, 0, 0, 3]),
            Err(portmap::Error::Xdr(Error::Bool(3)))
        );
        let maps = PmapResult::Dump(vec![map; 3]);
        assert_eq!(
            PmapResult::parse(procedure::DUMP, &maps.to_bytes().unwrap()),
            Ok(maps)
        );
        assert_eq!(
            PmapResult::parse(procedure::DUMP, &[0, 0, 0, 0]),
            Ok(PmapResult::Dump(vec![]))
        );
        assert!(
            PmapResult::Dump(vec![map; portmap::MAX_LIST + 5])
                .to_bytes()
                .is_err()
        );
        let mut over = Writer::new();
        for _ in 0..=portmap::MAX_LIST {
            over.bool(true);
            map.write(&mut over);
        }
        over.bool(false);
        assert!(matches!(
            PmapResult::parse(procedure::DUMP, over.as_bytes()),
            Err(portmap::Error::Xdr(Error::TooLong(_)))
        ));
        assert_eq!(
            PmapResult::parse(procedure::DUMP, &[0, 0, 0, 1, 0, 0]),
            Err(portmap::Error::Xdr(Error::Short))
        );
    }

    #[test]
    fn rpcbind() {
        let b = Rpcb {
            program: 100_003,
            version: 3,
            netid: "tcp".into(),
            addr: String::new(),
            owner: "superuser".into(),
        };
        let request = Request::Rpcb {
            version: 4,
            request: RpcbRequest::GetAddr(b.clone()),
        };
        let call = request.to_call().unwrap();
        #[rustfmt::skip]
        assert_eq!(call.args, [
            0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 3, b't', b'c', b'p', 0, 0, 0, 0, 0,
            0, 0, 0, 9, b's', b'u', b'p', b'e', b'r', b'u', b's', b'e', b'r', 0, 0, 0,
        ]);
        assert_eq!(Request::from_call(&call), Ok(request));
        for request in [
            RpcbRequest::Null,
            RpcbRequest::Set(b.clone()),
            RpcbRequest::Unset(b.clone()),
        ] {
            let req = Request::Rpcb {
                version: 3,
                request,
            };
            assert_eq!(Request::from_call(&req.to_call().unwrap()), Ok(req));
        }
        let mut c = call;
        c.version = 5;
        assert_eq!(Request::from_call(&c), Err(portmap::Error::Version(5)));
        c.version = 3;
        c.procedure = 9;
        assert_eq!(Request::from_call(&c), Err(portmap::Error::Procedure(9)));
        c.procedure = 3;
        c.args.truncate(10);
        assert_eq!(
            Request::from_call(&c),
            Err(portmap::Error::Xdr(Error::Short))
        );
        c.program = 7;
        assert_eq!(Request::from_call(&c), Err(portmap::Error::Program(7)));
        let addr: SocketAddr = "10.0.0.5:2049".parse().unwrap();
        let u = portmap::format_uaddr(addr);
        assert_eq!(u, "10.0.0.5.8.1");
        let result = RpcbResult::Addr(u.clone());
        assert_eq!(
            RpcbResult::parse(procedure::GETADDR, &result.to_bytes().unwrap()),
            Ok(result)
        );
        assert_eq!(portmap::parse_uaddr(&u), Some(addr));
        let v6: SocketAddr = "[fe80::1]:111".parse().unwrap();
        assert_eq!(portmap::format_uaddr(v6), "fe80::1.0.111");
        assert_eq!(portmap::parse_uaddr("fe80::1.0.111"), Some(v6));
        for bad in [
            "",
            "10.0.0.5",
            "10.0.0.5.256.1",
            "10.0.0.5.+8.1",
            "x.1.2",
            "10.0.0.5.8.",
        ] {
            assert_eq!(portmap::parse_uaddr(bad), None, "{bad}");
        }
    }

    #[test]
    fn writers_refuse_excess_fields() {
        let sys = AuthSys {
            stamp: 0,
            machine_name: "é".repeat(200),
            uid: 0,
            gid: 0,
            gids: vec![1; 40],
        };
        assert!(sys.to_bytes().is_err());
        let call = Call {
            cred: Auth::Sys(sys),
            ..Call::new(1, 1, 1, vec![])
        };
        let message = Message {
            xid: 0,
            body: Body::Call(call),
        };
        assert!(message.to_bytes().is_err());
        contract::check_wire_value(&message);
        let other = Auth::Other {
            flavor: 9,
            body: vec![1; 1000],
        };
        let mut writer = Writer::new();
        other.write(&mut writer);
        assert!(writer.finish().is_err());
        let long = Rpcb {
            program: 1,
            version: 1,
            netid: "n".repeat(999),
            addr: "a".into(),
            owner: "o".into(),
        };
        assert!(RpcbRequest::Set(long).to_args().is_err());
        assert!(RpcbResult::Addr("z".repeat(999)).to_bytes().is_err());
        let mut writer = Writer::new();
        writer.opaque_fixed(&vec![0; MAX_RECORD + 1]);
        assert!(writer.finish().is_err());
        let mut writer = Writer::new();
        writer.opaque_fixed(&vec![0; MAX_RECORD]);
        assert_eq!(writer.as_bytes().len(), MAX_RECORD);
        writer.uint(1).uhyper(2);
        assert_eq!(writer.as_bytes().len(), MAX_RECORD);
        assert_eq!(
            writer.finish(),
            Err(Error::TooLong((MAX_RECORD + 4) as u32))
        );
    }

    fn random_auth(rng: &mut Lcg) -> Auth {
        match rng.below(4) {
            0 => Auth::None,
            1 => Auth::Sys(AuthSys {
                stamp: (rng.next() as u32),
                machine_name: rng.text(7),
                uid: (rng.below(2000) as u32),
                gid: (rng.below(200) as u32),
                gids: (0..rng.below(4)).map(|_| rng.below(100) as u32).collect(),
            }),
            _ => Auth::Other {
                flavor: (rng.below(8) as u32),
                body: rng.bytes(11),
            },
        }
    }

    /// A random message that is well formed, so a mutation of it reaches
    /// deep into the parser.
    fn random_message(rng: &mut Lcg) -> Message {
        let words = |rng: &mut Lcg| -> Vec<u8> {
            let mut w = Writer::new();
            for _ in 0..rng.below(6) {
                w.uint(if !rng.coin() {
                    rng.below(4) as u32
                } else {
                    rng.next() as u32
                });
            }
            w.finish().unwrap()
        };
        let body = match rng.below(4) {
            0 => {
                let map = Mapping {
                    program: (rng.below(3) as u32),
                    version: (rng.below(4) as u32),
                    protocol: 6,
                    port: (rng.below(3) as u32),
                };
                let req = match rng.below(5) {
                    0 => PmapRequest::Null,
                    1 => PmapRequest::Set(map),
                    2 => PmapRequest::Unset(map),
                    3 => PmapRequest::GetPort(map),
                    _ => PmapRequest::Dump,
                };
                let mut call = Call::new(
                    PMAP_PROGRAM,
                    2 + (rng.below(3) as u32),
                    req.procedure(),
                    req.to_args().unwrap(),
                );
                call.cred = random_auth(rng);
                Body::Call(call)
            }
            1 => {
                let mut call = Call::new(
                    (rng.below(3) as u32) + 100_000,
                    rng.below(5) as u32,
                    rng.below(6) as u32,
                    words(rng),
                );
                call.cred = random_auth(rng);
                call.verf = random_auth(rng);
                Body::Call(call)
            }
            2 => {
                let status = match rng.below(6) {
                    0 => Accept::Success(words(rng)),
                    1 => Accept::ProgUnavail,
                    2 => Accept::ProgMismatch {
                        low: (rng.below(4) as u32),
                        high: (rng.below(4) as u32),
                    },
                    3 => Accept::ProcUnavail,
                    4 => Accept::GarbageArgs,
                    _ => Accept::SystemErr,
                };
                Body::Reply(Reply::Accepted {
                    verf: random_auth(rng),
                    status,
                })
            }
            _ => Body::Reply(Reply::Denied(if !rng.coin() {
                Reject::RpcMismatch {
                    low: (rng.below(4) as u32),
                    high: (rng.below(4) as u32),
                }
            } else {
                Reject::AuthError(AuthStat::from_code(rng.below(20) as u32))
            })),
        };
        Message {
            xid: (rng.next() as u32),
            body,
        }
    }

    /// The bytes of a random message, often changed: a byte flipped, cut
    /// short, or with bytes added.
    fn random_bytes(rng: &mut Lcg) -> Vec<u8> {
        let message = random_message(rng);
        contract::check_wire_value(&message);
        let mut b = message.to_bytes().unwrap_or_default();
        for _ in 0..rng.below(3) {
            test_support::mutate(rng, &mut b);
        }
        b
    }

    #[test]
    fn fuzz_parse_and_round_trip() {
        let mut rng = Lcg::new(0x5531_4506);
        let mut parsed = 0;
        for _ in 0..20_000 {
            let bytes = random_bytes(&mut rng);
            if let Ok(m) = Message::parse(&bytes) {
                parsed += 1;
                assert_eq!(m.to_bytes().unwrap(), bytes);
                if let Body::Call(call) = &m.body
                    && let Ok(req) = Request::from_call(call)
                {
                    assert_eq!(Request::from_call(&req.to_call().unwrap()), Ok(req));
                }
            }
            let _ = PmapResult::parse(procedure::DUMP, &bytes);
            let _ = AuthSys::parse(&bytes);
            let _ = RpcbResult::parse(procedure::GETADDR, &bytes);
            let mut r = Reader::new(&bytes);
            let _ = r.array(64, |r| r.optional(|r| r.opaque(64).map(<[u8]>::to_vec)));
            let limit = rng.index(64);
            contract::check_decode(|| super::records(limit), &bytes);
            contract::check_wire::<Message>(&bytes);
            contract::check_wire::<Record>(&bytes);
            let wire = encode_fragments(&bytes, 1 + rng.index(16)).unwrap();
            assert_eq!(Record::parse(&wire), Ok(Record(bytes.clone())));
        }
        assert!(parsed > 500, "only {parsed} messages parsed");
    }
}
