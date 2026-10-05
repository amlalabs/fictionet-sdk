//! ONC RPC and XDR: reading and writing calls, replies, TCP records and
//! portmap requests, with no I/O.
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
//! Nothing here reads a socket. A world that plays an RPC server feeds the
//! bytes a TCP connection reads to a [`Decoder`] and gets records back, or
//! takes each UDP datagram as it is. It reads each one with
//! [`Message::parse`], works out the [`Reply`], and sends back the bytes of
//! [`Message::to_bytes`], inside [`encode_record`] on TCP. What programs
//! exist, and what their procedures do, is up to world code. [`Reader`] and
//! [`Writer`] read and write the XDR of a procedure's arguments and
//! results. [`PortmapRequest`] and [`RpcbRequest`] read the requests a
//! portmapper answers.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Opaque data, strings, arrays and records all have limits, given
//! below as constants or by the caller, and the writers clip what they
//! write to the limits the readers apply.
//!
//! New stream users can use [`Fragments`], [`records`], or [`messages`]
//! with [`codec::Stream`]. [`Record::write`] and [`Wire`] for [`Message`]
//! are strict. Existing `feed`, `to_bytes`, and encoding functions retain
//! their original behavior, including clipping and repeated errors.
//!
//! ```
//! use fictionet::stdlib::onc_rpc::{
//!     encode_port, encode_record, silent_on_failure, Body, Call, Decoder, Mapping, Message,
//!     PortmapRequest, Reply, IPPROTO_TCP,
//! };
//!
//! /// A portmapper that knows one program: NFS version 3 on TCP port 2049.
//! /// `None` means it sends no reply.
//! fn answer(call: &Call) -> Option<Reply> {
//!     Some(match PortmapRequest::parse(call) {
//!         Ok(PortmapRequest::GetPort(m)) => {
//!             let nfs = m.program == 100_003 && m.version == 3 && m.protocol == IPPROTO_TCP;
//!             Reply::success(encode_port(if nfs { 2049 } else { 0 }))
//!         }
//!         Ok(PortmapRequest::Null) => Reply::success(Vec::new()),
//!         // Refuse to register or list anything.
//!         Ok(_) => Reply::success(vec![0, 0, 0, 0]),
//!         // It forwards no calls, and a CALLIT that fails gets no reply.
//!         Err(_) if silent_on_failure(call) => return None,
//!         Err(status) => Reply::accepted(status),
//!     })
//! }
//!
//! // A client asks, over TCP, which port NFS version 3 uses. Call 7.
//! let mapping = Mapping { program: 100_003, version: 3, protocol: IPPROTO_TCP, port: 0 };
//! let request = PortmapRequest::GetPort(mapping).call(7);
//! let mut decoder = Decoder::new();
//! decoder.feed(&encode_record(&request.to_bytes()));
//! let record = decoder.next_record().unwrap().unwrap();
//! let message = Message::parse(&record).unwrap();
//! let Body::Call(call) = &message.body else { panic!("not a call") };
//! let reply = message.reply(answer(call).unwrap());
//! // Call 7, a reply, accepted, an AUTH_NONE verifier, success, port 2049.
//! assert_eq!(
//!     reply.to_bytes(),
//!     [0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1]
//! );
//! ```

use std::net::{IpAddr, SocketAddr};

use super::codec::{self, Assemble, AssembleError, Assembled, Decode, Step, Wire};
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
/// The protocol number a [`Mapping`] gives for TCP.
pub const IPPROTO_TCP: u32 = 6;
/// The protocol number a [`Mapping`] gives for UDP.
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
/// The most mappings [`parse_dump`] reads from a portmapper's list.
pub const MAX_DUMP: usize = 1024;
/// The longest record a [`Decoder`] puts together. A decoder may be given
/// a lower limit, never a higher one.
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

/// Why bytes are not the XDR a reader expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdrError {
    /// The bytes ended before the value did.
    Short,
    /// A padding byte after opaque data or a string was not zero.
    Padding,
    /// A boolean was neither 0 nor 1.
    Bool(u32),
    /// An enum or union discriminant had a value the type does not have.
    Discriminant(u32),
    /// A length or count was above the limit for that field.
    TooLong(u32),
    /// A string was not UTF-8.
    Utf8,
    /// Bytes were left over after the value: this many.
    Trailing(usize),
}

impl std::fmt::Display for XdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XdrError::Short => f.write_str("XDR ended early"),
            XdrError::Padding => f.write_str("XDR padding byte not zero"),
            XdrError::Bool(n) => write!(f, "XDR boolean {n}, not 0 or 1"),
            XdrError::Discriminant(n) => write!(f, "XDR discriminant {n} not known"),
            XdrError::TooLong(n) => write!(f, "XDR length or count {n} over the limit"),
            XdrError::Utf8 => f.write_str("XDR string not UTF-8"),
            XdrError::Trailing(n) => write!(f, "{n} bytes after the XDR value"),
        }
    }
}

impl std::error::Error for XdrError {}

/// Reads XDR values from bytes, in order. Each method reads one value and
/// moves past it. After an error the reader's position is unspecified, so
/// a caller stops there.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// How many bytes have been read.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// Takes every byte not yet read, such as a call's arguments.
    pub fn rest(&mut self) -> &'a [u8] {
        let r = self.remaining();
        self.pos = self.buf.len();
        r
    }

    /// Checks that every byte has been read.
    pub fn finish(&self) -> Result<(), XdrError> {
        match self.remaining().len() {
            0 => Ok(()),
            n => Err(XdrError::Trailing(n)),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let end = self.pos.checked_add(n).ok_or(XdrError::Short)?;
        let b = self.buf.get(self.pos..end).ok_or(XdrError::Short)?;
        self.pos = end;
        Ok(b)
    }

    /// An unsigned integer: 4 bytes.
    pub fn uint(&mut self) -> Result<u32, XdrError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A signed integer: 4 bytes, two's complement.
    pub fn int(&mut self) -> Result<i32, XdrError> {
        Ok(self.uint()? as i32)
    }

    /// An unsigned hyper integer: 8 bytes.
    pub fn uhyper(&mut self) -> Result<u64, XdrError> {
        let hi = u64::from(self.uint()?);
        let lo = u64::from(self.uint()?);
        Ok(hi << 32 | lo)
    }

    /// A hyper integer: 8 bytes, two's complement.
    pub fn hyper(&mut self) -> Result<i64, XdrError> {
        Ok(self.uhyper()? as i64)
    }

    /// A boolean: an integer that is 0 or 1.
    pub fn bool(&mut self) -> Result<bool, XdrError> {
        match self.uint()? {
            0 => Ok(false),
            1 => Ok(true),
            n => Err(XdrError::Bool(n)),
        }
    }

    /// An enum: a signed integer. Which values the enum has is up to the
    /// caller.
    pub fn enumeration(&mut self) -> Result<i32, XdrError> {
        self.int()
    }

    /// Fixed-length opaque data of `n` bytes, then the zero bytes that pad
    /// it to a multiple of 4.
    pub fn opaque_fixed(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let data = self.take(n)?;
        let pad = self.take(padding(n))?;
        if pad.iter().any(|&b| b != 0) {
            return Err(XdrError::Padding);
        }
        Ok(data)
    }

    /// Variable-length opaque data of at most `max` bytes: a length, the
    /// bytes, and padding.
    pub fn opaque(&mut self, max: usize) -> Result<&'a [u8], XdrError> {
        let len = self.uint()?;
        let n = usize::try_from(len).map_err(|_| XdrError::TooLong(len))?;
        if n > max {
            return Err(XdrError::TooLong(len));
        }
        self.opaque_fixed(n)
    }

    /// A string of at most `max` bytes, written like variable-length
    /// opaque data. It must be UTF-8.
    pub fn string(&mut self, max: usize) -> Result<&'a str, XdrError> {
        std::str::from_utf8(self.opaque(max)?).map_err(|_| XdrError::Utf8)
    }

    /// A variable-length array of at most `max` items, each read by
    /// `item`. Almost every XDR item takes at least 4 bytes, so a count
    /// above both [`MAX_ARRAY_RESERVE`] and a quarter of the bytes left is
    /// refused before anything is read. Up to [`MAX_ARRAY_RESERVE`] items
    /// may take fewer bytes, even none. Room is made up front for at most
    /// [`MAX_ARRAY_RESERVE`] items and at most 64 KiB.
    pub fn array<T>(
        &mut self,
        max: usize,
        mut item: impl FnMut(&mut Reader<'a>) -> Result<T, XdrError>,
    ) -> Result<Vec<T>, XdrError> {
        let count = self.uint()?;
        let n = usize::try_from(count).map_err(|_| XdrError::TooLong(count))?;
        if n > max {
            return Err(XdrError::TooLong(count));
        }
        if n > MAX_ARRAY_RESERVE && n > self.remaining().len() / 4 {
            return Err(XdrError::Short);
        }
        let mut out = Vec::with_capacity(reserve::<T>(n));
        for _ in 0..n {
            out.push(item(self)?);
        }
        Ok(out)
    }

    /// An optional value: a boolean, then the value if it is 1.
    pub fn optional<T>(
        &mut self,
        item: impl FnOnce(&mut Reader<'a>) -> Result<T, XdrError>,
    ) -> Result<Option<T>, XdrError> {
        if self.bool()? { Ok(Some(item(self)?)) } else { Ok(None) }
    }
}

/// Writes XDR values, in order, into a growing buffer. Each method returns
/// the writer, so calls can be chained.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
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

    /// Gives up the bytes written.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// An unsigned integer: 4 bytes.
    pub fn uint(&mut self, v: u32) -> &mut Writer {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A signed integer: 4 bytes, two's complement.
    pub fn int(&mut self, v: i32) -> &mut Writer {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// An unsigned hyper integer: 8 bytes.
    pub fn uhyper(&mut self, v: u64) -> &mut Writer {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A hyper integer: 8 bytes, two's complement.
    pub fn hyper(&mut self, v: i64) -> &mut Writer {
        self.buf.extend_from_slice(&v.to_be_bytes());
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
        self.buf.extend_from_slice(data);
        self.buf.extend_from_slice(&[0; 3][..padding(data.len())]);
        self
    }

    /// Variable-length opaque data: a length, the bytes, and padding. Data
    /// past 2^32 - 1 bytes is left out, since no length can count it. A
    /// reader with a lower limit refuses what is longer, so callers clip
    /// to it first.
    pub fn opaque(&mut self, data: &[u8]) -> &mut Writer {
        let data = &data[..data.len().min(u32::MAX as usize)];
        self.uint(data.len() as u32);
        self.opaque_fixed(data)
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
        let items = &items[..items.len().min(u32::MAX as usize)];
        self.uint(items.len() as u32);
        for i in items {
            item(self, i);
        }
        self
    }

    /// An optional value: a boolean, then the value if there is one.
    pub fn optional<T>(&mut self, value: Option<&T>, item: impl FnOnce(&mut Writer, &T)) -> &mut Writer {
        self.bool(value.is_some());
        if let Some(v) = value {
            item(self, v);
        }
        self
    }
}

/// How many of `n` items of type `T` to make room for before reading them.
fn reserve<T>(n: usize) -> usize {
    n.min(MAX_ARRAY_RESERVE).min(MAX_RESERVE_BYTES / std::mem::size_of::<T>().max(1))
}

/// How many zero bytes pad `n` bytes to a multiple of 4.
fn padding(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// The longest prefix of `s` of at most `max` bytes that ends on a
/// character boundary.
fn clip(s: &str, max: usize) -> &str {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
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
    pub fn parse(body: &[u8]) -> Result<AuthSys, XdrError> {
        let mut r = Reader::new(body);
        let stamp = r.uint()?;
        let machine_name = r.string(MAX_MACHINE_NAME)?.to_string();
        let uid = r.uint()?;
        let gid = r.uint()?;
        let gids = r.array(MAX_GIDS, Reader::uint)?;
        r.finish()?;
        Ok(AuthSys { stamp, machine_name, uid, gid, gids })
    }

    /// The credentials' bytes. A machine name or group list over its limit
    /// is cut to it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.uint(self.stamp).string(clip(&self.machine_name, MAX_MACHINE_NAME)).uint(self.uid).uint(self.gid);
        w.array(&self.gids[..self.gids.len().min(MAX_GIDS)], |w, g| {
            w.uint(*g);
        });
        w.finish()
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
    /// One built with flavor 0 and no body, or with flavor 1 and a body
    /// that reads as [`AuthSys`], writes the same bytes as [`Auth::None`]
    /// or [`Auth::Sys`] and reads back as that.
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
    pub fn read(r: &mut Reader<'_>) -> Result<Auth, XdrError> {
        let flavor = r.uint()?;
        let body = r.opaque(MAX_AUTH_BODY)?;
        Ok(match flavor {
            flavor::NONE if body.is_empty() => Auth::None,
            flavor::SYS => match AuthSys::parse(body) {
                Ok(sys) => Auth::Sys(sys),
                Err(_) => Auth::Other { flavor, body: body.to_vec() },
            },
            _ => Auth::Other { flavor, body: body.to_vec() },
        })
    }

    /// Writes the flavor and body. A body over [`MAX_AUTH_BODY`] bytes is
    /// cut to it. AUTH_SYS credentials within their limits always fit.
    pub fn write(&self, w: &mut Writer) {
        let sys;
        let body: &[u8] = match self {
            Auth::None => &[],
            Auth::Sys(s) => {
                sys = s.to_bytes();
                &sys
            }
            Auth::Other { body, .. } => body,
        };
        w.uint(self.flavor()).opaque(&body[..body.len().min(MAX_AUTH_BODY)]);
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
        Call { rpc_version: RPC_VERSION, program, version, procedure, cred: Auth::None, verf: Auth::None, args }
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
        Reply::Accepted { verf: Auth::None, status }
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
    pub fn parse(b: &[u8]) -> Result<Message, XdrError> {
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
                Body::Call(Call { rpc_version, program, version, procedure, cred, verf, args })
            }
            1 => Body::Reply(match r.uint()? {
                0 => {
                    let verf = Auth::read(&mut r)?;
                    let status = match r.uint()? {
                        0 => Accept::Success(r.rest().to_vec()),
                        1 => Accept::ProgUnavail,
                        2 => Accept::ProgMismatch { low: r.uint()?, high: r.uint()? },
                        3 => Accept::ProcUnavail,
                        4 => Accept::GarbageArgs,
                        5 => Accept::SystemErr,
                        n => return Err(XdrError::Discriminant(n)),
                    };
                    Reply::Accepted { verf, status }
                }
                1 => Reply::Denied(match r.uint()? {
                    0 => Reject::RpcMismatch { low: r.uint()?, high: r.uint()? },
                    1 => Reject::AuthError(AuthStat::from_code(r.uint()?)),
                    n => return Err(XdrError::Discriminant(n)),
                }),
                n => return Err(XdrError::Discriminant(n)),
            }),
            n => return Err(XdrError::Discriminant(n)),
        };
        r.finish()?;
        Ok(Message { xid, body })
    }

    /// The message's bytes. They always read back with [`Message::parse`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.uint(self.xid);
        match &self.body {
            Body::Call(c) => {
                w.uint(0).uint(c.rpc_version).uint(c.program).uint(c.version).uint(c.procedure);
                c.cred.write(&mut w);
                c.verf.write(&mut w);
                let mut out = w.finish();
                out.extend_from_slice(&c.args);
                return out;
            }
            Body::Reply(Reply::Accepted { verf, status }) => {
                w.uint(1).uint(0);
                verf.write(&mut w);
                w.uint(status.code());
                match status {
                    Accept::Success(results) => {
                        let mut out = w.finish();
                        out.extend_from_slice(results);
                        return out;
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
        w.finish()
    }

    /// A message that answers this one with `reply`, with the same
    /// transaction ID.
    pub fn reply(&self, reply: Reply) -> Message {
        Message { xid: self.xid, body: Body::Reply(reply) }
    }

    /// Appends this message without clipping or normalizing its fields.
    ///
    /// Refuses messages over [`MAX_RECORD`], authentication fields over
    /// their named limits, and aliases that parse as another enum variant.
    /// An error leaves `out` unchanged. [`Self::to_bytes`] keeps its original
    /// clipping behavior. This is also the writer used by [`Wire`].
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), MessageWriteError> {
        let size = match &self.body {
            Body::Call(call) => 24usize
                .saturating_add(auth_wire_len(&call.cred)?)
                .saturating_add(auth_wire_len(&call.verf)?)
                .saturating_add(call.args.len()),
            Body::Reply(Reply::Accepted { verf, status }) => {
                16usize.saturating_add(auth_wire_len(verf)?).saturating_add(match status {
                    Accept::Success(results) => results.len(),
                    Accept::ProgMismatch { .. } => 8,
                    _ => 0,
                })
            }
            Body::Reply(Reply::Denied(Reject::RpcMismatch { .. })) => 24,
            Body::Reply(Reply::Denied(Reject::AuthError(status))) => {
                if AuthStat::from_code(status.code()) != *status {
                    return Err(MessageWriteError::NonCanonical);
                }
                20
            }
        };
        if size > MAX_RECORD {
            return Err(MessageWriteError::TooLong { limit: MAX_RECORD });
        }
        // Validation bounds this temporary by MAX_RECORD and makes the
        // legacy serializer exact for this value.
        out.extend_from_slice(&self.to_bytes());
        Ok(())
    }
}

/// Why a strict RPC message writer refused a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageWriteError {
    /// A message or authentication field exceeds its named limit.
    TooLong {
        /// The maximum bytes or entries for that field.
        limit: usize,
    },
    /// An authentication variant would parse as another variant.
    NonCanonical,
}

impl core::fmt::Display for MessageWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { limit } => write!(f, "RPC message field exceeds {limit}"),
            Self::NonCanonical => f.write_str("RPC authentication variant would change on parsing"),
        }
    }
}

impl core::error::Error for MessageWriteError {}

fn auth_wire_len(auth: &Auth) -> Result<usize, MessageWriteError> {
    let body_len = match auth {
        Auth::None => 0,
        Auth::Sys(sys) => {
            if sys.machine_name.len() > MAX_MACHINE_NAME {
                return Err(MessageWriteError::TooLong { limit: MAX_MACHINE_NAME });
            }
            if sys.gids.len() > MAX_GIDS {
                return Err(MessageWriteError::TooLong { limit: MAX_GIDS });
            }
            20usize
                .saturating_add(sys.machine_name.len())
                .saturating_add(padding(sys.machine_name.len()))
                .saturating_add(sys.gids.len().saturating_mul(4))
        }
        Auth::Other { flavor, body } => {
            if body.len() > MAX_AUTH_BODY {
                return Err(MessageWriteError::TooLong { limit: MAX_AUTH_BODY });
            }
            if (*flavor == flavor::NONE && body.is_empty())
                || (*flavor == flavor::SYS && AuthSys::parse(body).is_ok())
            {
                return Err(MessageWriteError::NonCanonical);
            }
            body.len()
        }
    };
    Ok(8usize.saturating_add(body_len).saturating_add(padding(body_len)))
}

impl Wire for Message {
    type ParseError = XdrError;
    type WriteError = MessageWriteError;

    /// Reads one RPC message of at most [`MAX_RECORD`] bytes.
    /// The inherent [`Message::parse`] retains its original size policy.
    fn parse(bytes: &[u8]) -> Result<Self, XdrError> {
        if bytes.len() > MAX_RECORD {
            return Err(XdrError::TooLong(u32::try_from(bytes.len()).unwrap_or(u32::MAX)));
        }
        Message::parse(bytes)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), MessageWriteError> {
        self.write(out)
    }
}

/// Why a TCP stream holds no more records a reader can find. A real
/// server closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The fragments of one record add up to more than the decoder's limit,
    /// which is given.
    TooLong(usize),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::TooLong(limit) => write!(f, "RPC record over the limit of {limit} bytes"),
        }
    }
}

impl std::error::Error for RecordError {}

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

impl Fragments {
    /// Creates a fragment decoder with a record limit of [`MAX_RECORD`].
    pub fn new() -> Self {
        Self::with_limit(MAX_RECORD)
    }

    /// Sets the record limit, clamped to [`MAX_RECORD`]. Zero permits only
    /// empty fragments. Input capacity also includes [`RECORD_MARK_LEN`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_RECORD), record_len: 0 }
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
    type Error = RecordError;
    const NAME: &'static str = "ONC RPC record marking";

    fn capacity(&self) -> usize {
        self.limit.saturating_add(RECORD_MARK_LEN)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Fragment>, RecordError> {
        let Some(mark) = input.get(..RECORD_MARK_LEN) else { return Ok(Step::Need) };
        let mut bytes = [0; RECORD_MARK_LEN];
        bytes.copy_from_slice(mark);
        let mark = u32::from_be_bytes(bytes);
        let len = usize::try_from(mark & MAX_FRAGMENT).map_err(|_| RecordError::TooLong(self.limit))?;
        let total = self.record_len.checked_add(len).ok_or(RecordError::TooLong(self.limit))?;
        if total > self.limit {
            return Err(RecordError::TooLong(self.limit));
        }
        let used = RECORD_MARK_LEN.checked_add(len).ok_or(RecordError::TooLong(self.limit))?;
        let Some(data) = input.get(RECORD_MARK_LEN..used) else { return Ok(Step::Need) };
        let last = mark & LAST_FRAGMENT != 0;
        self.record_len = if last { 0 } else { total };
        Ok(Step::Item(Fragment { last, data: data.to_vec() }, used))
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
    Assemble::new(fragments, limit, |f| codec::Fragment::Part { data: f.data, last: f.last })
}

/// Decodes TCP records and parses each as an RPC message.
///
/// Invalid messages are error items, so the next record can still be read.
/// Record marking errors end the stream. Use [`Decode::map`] with a closure
/// to read program arguments from each [`Body::Call`].
pub fn messages(
    limit: usize,
) -> impl Decode<Item = Result<Message, XdrError>, Error = AssembleError<RecordError>> {
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

/// Why bytes do not contain exactly one complete TCP record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordParseError {
    /// A record mark or unfinished assembly was refused.
    Framing(AssembleError<RecordError>),
    /// The input ended before a complete record arrived.
    Truncated,
    /// Bytes followed the record's final fragment.
    Trailing(usize),
}

impl core::fmt::Display for RecordParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Framing(e) => e.fmt(f),
            Self::Truncated => f.write_str("RPC record ended early"),
            Self::Trailing(n) => write!(f, "{n} bytes after the RPC record"),
        }
    }
}

impl core::error::Error for RecordParseError {}

impl Record {
    /// Appends one final fragment. Refuses payloads over [`MAX_RECORD`]
    /// without changing `out`. Unlike [`encode_record`], this never clips.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.0.len() > MAX_RECORD {
            return Err(RecordError::TooLong(MAX_RECORD));
        }
        let len = u32::try_from(self.0.len()).map_err(|_| RecordError::TooLong(MAX_RECORD))?;
        out.extend_from_slice(&(LAST_FRAGMENT | len).to_be_bytes());
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

impl Wire for Record {
    type ParseError = RecordParseError;
    type WriteError = RecordError;

    fn parse(mut input: &[u8]) -> Result<Self, RecordParseError> {
        let mut decoder = records(MAX_RECORD);
        loop {
            match decoder.decode(input, true).map_err(RecordParseError::Framing)? {
                Step::Item(Assembled::Message(data), used) => {
                    let trailing = input.len().saturating_sub(used);
                    return if trailing == 0 {
                        Ok(Self(data))
                    } else {
                        Err(RecordParseError::Trailing(trailing))
                    };
                }
                Step::Item(Assembled::Whole(never), _) => match never {},
                Step::Skip(used) => input = input.get(used..).ok_or(RecordParseError::Truncated)?,
                Step::Need | Step::End => return Err(RecordParseError::Truncated),
            }
        }
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        self.write(out)
    }
}

/// Splits a TCP byte stream into records, putting each record's fragments
/// together. Feed it the bytes a connection reads, in order, and take
/// records out until it has none. It holds every byte fed until a call to
/// [`Decoder::next_record`] takes it out, so a world calls that after each
/// feed. Then it holds at most the limit, plus 4 bytes, plus the bytes of
/// the latest feed. A feed stops at a record mark that passes the limit
/// and drops what follows, so bytes after a broken mark are never held.
#[derive(Clone, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet read start. Bytes before it are dropped in
    /// `feed` once they are half the buffer, so taking out many small
    /// records costs time in proportion to their bytes.
    start: usize,
    record: Vec<u8>,
    limit: usize,
    failed: Option<RecordError>,
    /// What `feed` has seen of the marks in the bytes it kept.
    scan: Scan,
}

/// How far [`Decoder::feed`] has checked the record marks in the stream.
#[derive(Clone, Debug, Default)]
struct Scan {
    /// Bytes of the current fragment's data still to come.
    skip: usize,
    /// The bytes of a record mark that has not all come.
    mark: [u8; 4],
    have: usize,
    /// The bytes of the fragments of a record not yet whole.
    record: usize,
    /// Whether a fragment has come whose record has no last fragment yet.
    open: bool,
    /// Whether a mark has passed the limit. Later bytes are dropped.
    stopped: bool,
}

/// The most spare room a [`Decoder`] keeps once it holds no bytes.
const RETAIN: usize = 1 << 16;

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, with a limit of [`MAX_RECORD`].
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_RECORD)
    }

    /// A decoder that refuses records longer than `limit` bytes, or
    /// [`MAX_RECORD`] if that is lower.
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder {
            buf: Vec::new(),
            start: 0,
            record: Vec::new(),
            limit: limit.min(MAX_RECORD),
            failed: None,
            scan: Scan::default(),
        }
    }

    /// The longest record this decoder accepts.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Adds bytes read from the connection. Bytes after a record mark that
    /// passes the limit are dropped, since the stream cannot be read past
    /// it; [`Decoder::next_record`] reports the error when it reaches the
    /// mark.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() || self.scan.stopped {
            return;
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let s = &mut self.scan;
        let mut i = 0;
        while i < bytes.len() {
            if s.skip > 0 {
                let n = s.skip.min(bytes.len() - i);
                s.skip -= n;
                i += n;
                continue;
            }
            s.mark[s.have] = bytes[i];
            s.have += 1;
            i += 1;
            if s.have == 4 {
                s.have = 0;
                let mark = u32::from_be_bytes(s.mark);
                let len = (mark & MAX_FRAGMENT) as usize;
                if len > self.limit - s.record {
                    s.stopped = true;
                    break;
                }
                s.skip = len;
                s.open = mark & LAST_FRAGMENT == 0;
                s.record = if s.open { s.record + len } else { 0 };
            }
        }
        self.buf.extend_from_slice(&bytes[..i]);
    }

    /// The next whole record, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A record that would pass the limit fails as soon
    /// as the record mark that passes it comes, before its data does.
    pub fn next_record(&mut self) -> Option<Result<Vec<u8>, RecordError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let mut at = self.start;
        let result = loop {
            let Some(mark) = self.buf.get(at..at + 4) else { break None };
            let mark = u32::from_be_bytes([mark[0], mark[1], mark[2], mark[3]]);
            let len = (mark & MAX_FRAGMENT) as usize;
            if len > self.limit - self.record.len() {
                let e = RecordError::TooLong(self.limit);
                self.failed = Some(e);
                break Some(Err(e));
            }
            let start = at + 4;
            let Some(data) = self.buf.get(start..start + len) else { break None };
            self.record.extend_from_slice(data);
            at = start + len;
            if mark & LAST_FRAGMENT != 0 {
                break Some(Ok(std::mem::take(&mut self.record)));
            }
        };
        if self.failed.is_some() {
            self.buf = Vec::new();
            self.start = 0;
            self.record = Vec::new();
            self.scan = Scan::default();
        } else if at == self.buf.len() {
            // Every byte held has been read: start again, and give back
            // the room a long record took.
            self.buf.clear();
            self.start = 0;
            if self.buf.capacity() > RETAIN {
                self.buf = Vec::new();
            }
        } else {
            self.start = at;
        }
        result
    }

    /// Whether the stream stopped partway through a record: bytes are held,
    /// or a fragment has come whose record has no last fragment yet. A
    /// connection that closes while this is true closed in the middle of
    /// a record. After a [`RecordError`] it is false.
    pub fn mid_record(&self) -> bool {
        self.failed.is_none() && (self.buffered() > 0 || self.scan.open)
    }

    /// How many bytes are held: fragments of a record not yet whole, and
    /// bytes not yet read.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start + self.record.len()
    }
}

/// A record's bytes for TCP, in one fragment. A record over [`MAX_RECORD`]
/// bytes is cut to it, so a [`Decoder`] always reads the bytes back when
/// its limit is at least the record's length.
pub fn encode_record(record: &[u8]) -> Vec<u8> {
    encode_fragments(record, MAX_FRAGMENT as usize)
}

/// A record's bytes for TCP, split into fragments of at most
/// `fragment_len` bytes. A length of 0 is taken as 1, and one above
/// [`MAX_FRAGMENT`] as that. An empty record is one empty last fragment. A
/// record over [`MAX_RECORD`] bytes is cut to it, as no decoder reads more.
pub fn encode_fragments(record: &[u8], fragment_len: usize) -> Vec<u8> {
    let record = &record[..record.len().min(MAX_RECORD)];
    let size = fragment_len.clamp(1, MAX_FRAGMENT as usize);
    let count = record.len().div_ceil(size).max(1);
    let mut out = Vec::with_capacity(record.len().saturating_add(count.saturating_mul(4)));
    let mut chunks = record.chunks(size).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&LAST_FRAGMENT.to_be_bytes());
    }
    while let Some(chunk) = chunks.next() {
        let last = if chunks.peek().is_none() { LAST_FRAGMENT } else { 0 };
        out.extend_from_slice(&(last | chunk.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// A portmapper mapping: a program and version, a protocol, and the port
/// it listens on (RFC 1833, section 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mapping {
    /// The program number.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// [`IPPROTO_TCP`] or [`IPPROTO_UDP`].
    pub protocol: u32,
    /// The port. GETPORT and UNSET ignore it.
    pub port: u32,
}

impl Mapping {
    /// Reads a mapping from the reader.
    pub fn read(r: &mut Reader<'_>) -> Result<Mapping, XdrError> {
        Ok(Mapping { program: r.uint()?, version: r.uint()?, protocol: r.uint()?, port: r.uint()? })
    }

    /// Writes the mapping.
    pub fn write(&self, w: &mut Writer) {
        w.uint(self.program).uint(self.version).uint(self.protocol).uint(self.port);
    }
}

/// An rpcbind registration: a program and version, the network it is on,
/// its address there, and who registered it (RFC 1833, section 2.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rpcb {
    /// The program number.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// The network ID, such as "tcp", "udp", "tcp6" or "udp6".
    pub netid: String,
    /// The universal address, such as "10.0.0.5.8.1" for port 2049. See
    /// [`universal_address`].
    pub addr: String,
    /// Who registered it, usually a user ID as a string.
    pub owner: String,
}

impl Rpcb {
    /// Reads a registration from the reader. Each string may have at most
    /// [`MAX_RPCB_STRING`] bytes.
    pub fn read(r: &mut Reader<'_>) -> Result<Rpcb, XdrError> {
        Ok(Rpcb {
            program: r.uint()?,
            version: r.uint()?,
            netid: r.string(MAX_RPCB_STRING)?.to_string(),
            addr: r.string(MAX_RPCB_STRING)?.to_string(),
            owner: r.string(MAX_RPCB_STRING)?.to_string(),
        })
    }

    /// Writes the registration. Strings over [`MAX_RPCB_STRING`] bytes
    /// are cut to it.
    pub fn write(&self, w: &mut Writer) {
        w.uint(self.program).uint(self.version);
        for s in [&self.netid, &self.addr, &self.owner] {
            w.string(clip(s, MAX_RPCB_STRING));
        }
    }
}

/// A call to the portmapper, version 2, that this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortmapRequest {
    /// Procedure 0: does nothing, returns nothing.
    Null,
    /// Procedure 1: register a mapping. Returns a boolean.
    Set(Mapping),
    /// Procedure 2: remove the mappings for a program and version. Returns
    /// a boolean.
    Unset(Mapping),
    /// Procedure 3: the port of a program, version and protocol. Returns a
    /// port, 0 if there is none ([`encode_port`]).
    GetPort(Mapping),
    /// Procedure 4: every mapping. Returns a list ([`encode_dump`]).
    Dump,
}

impl PortmapRequest {
    /// Reads the request a call makes. When the call is not one, the error
    /// is the status a portmapper replies with: the wrong program, a
    /// version other than 2, a procedure this module does not read, or
    /// arguments that do not read. CALLIT is one this module does not
    /// read, and a portmapper sends no reply at all when CALLIT fails, so
    /// a server checks [`silent_on_failure`] before it replies. A server
    /// that also plays rpcbind checks the version first and sends calls
    /// for 3 and 4 to [`RpcbRequest::parse`].
    pub fn parse(call: &Call) -> Result<PortmapRequest, Accept> {
        if call.program != PMAP_PROGRAM {
            return Err(Accept::ProgUnavail);
        }
        if call.version != PMAP_VERSION {
            return Err(Accept::ProgMismatch { low: PMAP_VERSION, high: PMAP_VERSION });
        }
        let mut r = Reader::new(&call.args);
        let request = match call.procedure {
            procedure::NULL => PortmapRequest::Null,
            procedure::SET => PortmapRequest::Set(Mapping::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            procedure::UNSET => PortmapRequest::Unset(Mapping::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            procedure::GETPORT => PortmapRequest::GetPort(Mapping::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            procedure::DUMP => PortmapRequest::Dump,
            _ => return Err(Accept::ProcUnavail),
        };
        r.finish().map_err(|_| Accept::GarbageArgs)?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            PortmapRequest::Null => procedure::NULL,
            PortmapRequest::Set(_) => procedure::SET,
            PortmapRequest::Unset(_) => procedure::UNSET,
            PortmapRequest::GetPort(_) => procedure::GETPORT,
            PortmapRequest::Dump => procedure::DUMP,
        }
    }

    /// The call's arguments.
    pub fn to_args(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if let PortmapRequest::Set(m) | PortmapRequest::Unset(m) | PortmapRequest::GetPort(m) = self {
            m.write(&mut w);
        }
        w.finish()
    }

    /// A call message that makes this request, with AUTH_NONE.
    pub fn call(&self, xid: u32) -> Message {
        let call = Call::new(PMAP_PROGRAM, PMAP_VERSION, self.procedure(), self.to_args());
        Message { xid, body: Body::Call(call) }
    }
}

/// A call to rpcbind, version 3 or 4, that this module reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcbRequest {
    /// Procedure 0: does nothing, returns nothing.
    Null,
    /// Procedure 1: register an address. Returns a boolean.
    Set(Rpcb),
    /// Procedure 2: remove registrations. Returns a boolean.
    Unset(Rpcb),
    /// Procedure 3: the universal address of a program and version on a
    /// network, or "" if there is none ([`encode_address`]).
    GetAddr(Rpcb),
}

impl RpcbRequest {
    /// Reads the request a call makes. When the call is not one, the error
    /// is the status rpcbind replies with: the wrong program, a version
    /// other than 3 or 4, a procedure this module does not read, or
    /// arguments that do not read. CALLIT and BCAST (procedure 5) are not
    /// read, and rpcbind sends no reply at all when they fail, so a server
    /// checks [`silent_on_failure`] before it replies.
    pub fn parse(call: &Call) -> Result<RpcbRequest, Accept> {
        if call.program != PMAP_PROGRAM {
            return Err(Accept::ProgUnavail);
        }
        if !(RPCB_VERSION_LOW..=RPCB_VERSION_HIGH).contains(&call.version) {
            return Err(Accept::ProgMismatch { low: RPCB_VERSION_LOW, high: RPCB_VERSION_HIGH });
        }
        let mut r = Reader::new(&call.args);
        let request = match call.procedure {
            procedure::NULL => RpcbRequest::Null,
            procedure::SET => RpcbRequest::Set(Rpcb::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            procedure::UNSET => RpcbRequest::Unset(Rpcb::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            procedure::GETADDR => RpcbRequest::GetAddr(Rpcb::read(&mut r).map_err(|_| Accept::GarbageArgs)?),
            _ => return Err(Accept::ProcUnavail),
        };
        r.finish().map_err(|_| Accept::GarbageArgs)?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            RpcbRequest::Null => procedure::NULL,
            RpcbRequest::Set(_) => procedure::SET,
            RpcbRequest::Unset(_) => procedure::UNSET,
            RpcbRequest::GetAddr(_) => procedure::GETADDR,
        }
    }

    /// The call's arguments.
    pub fn to_args(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if let RpcbRequest::Set(b) | RpcbRequest::Unset(b) | RpcbRequest::GetAddr(b) = self {
            b.write(&mut w);
        }
        w.finish()
    }

    /// A call message that makes this request to rpcbind `version`, with
    /// AUTH_NONE.
    pub fn call(&self, xid: u32, version: u32) -> Message {
        let call = Call::new(PMAP_PROGRAM, version, self.procedure(), self.to_args());
        Message { xid, body: Body::Call(call) }
    }
}

/// Whether a call gets no reply when it fails: the portmapper's CALLIT and
/// rpcbind's CALLIT and BCAST, all procedure 5 of program 100000 (RFC 1833,
/// sections 2.2.1, 2.2.2 and 3.2). They reply only when the call they
/// forward succeeds. rpcbind's INDIRECT replies with its errors.
pub fn silent_on_failure(call: &Call) -> bool {
    call.program == PMAP_PROGRAM
        && (PMAP_VERSION..=RPCB_VERSION_HIGH).contains(&call.version)
        && call.procedure == procedure::CALLIT
}

/// The results of SET and UNSET: a boolean.
pub fn encode_bool(v: bool) -> Vec<u8> {
    Writer::new().bool(v).as_bytes().to_vec()
}

/// Reads the results of SET or UNSET.
pub fn parse_bool(results: &[u8]) -> Result<bool, XdrError> {
    let mut r = Reader::new(results);
    let v = r.bool()?;
    r.finish()?;
    Ok(v)
}

/// The results of the portmapper's GETPORT: a port, or 0 for none.
pub fn encode_port(port: u32) -> Vec<u8> {
    port.to_be_bytes().to_vec()
}

/// Reads the results of the portmapper's GETPORT.
pub fn parse_port(results: &[u8]) -> Result<u32, XdrError> {
    let mut r = Reader::new(results);
    let v = r.uint()?;
    r.finish()?;
    Ok(v)
}

/// The results of rpcbind's GETADDR: a universal address, or "" for none.
/// An address over [`MAX_RPCB_STRING`] bytes is cut to it.
pub fn encode_address(addr: &str) -> Vec<u8> {
    Writer::new().string(clip(addr, MAX_RPCB_STRING)).as_bytes().to_vec()
}

/// Reads the results of rpcbind's GETADDR.
pub fn parse_address(results: &[u8]) -> Result<String, XdrError> {
    let mut r = Reader::new(results);
    let v = r.string(MAX_RPCB_STRING)?.to_string();
    r.finish()?;
    Ok(v)
}

/// The results of the portmapper's DUMP: a list of mappings, each behind a
/// 1, ended by a 0. Mappings past [`MAX_DUMP`] are left out.
pub fn encode_dump(mappings: &[Mapping]) -> Vec<u8> {
    let mut w = Writer::new();
    for m in &mappings[..mappings.len().min(MAX_DUMP)] {
        w.bool(true);
        m.write(&mut w);
    }
    w.bool(false);
    w.finish()
}

/// Reads the results of the portmapper's DUMP. A list longer than
/// [`MAX_DUMP`] is refused.
pub fn parse_dump(results: &[u8]) -> Result<Vec<Mapping>, XdrError> {
    let mut r = Reader::new(results);
    let mut out = Vec::new();
    while r.bool()? {
        if out.len() == MAX_DUMP {
            return Err(XdrError::TooLong(MAX_DUMP as u32 + 1));
        }
        out.push(Mapping::read(&mut r)?);
    }
    r.finish()?;
    Ok(out)
}

/// The universal address of an IP address and port (RFC 5665, sections
/// 5.2.3.3 and 5.2.3.4): the address as text, then the port's high and
/// low bytes in decimal, all joined by dots. 10.0.0.5 port 2049 is
/// "10.0.0.5.8.1". The format has no place for an IPv6 scope ID, so it is
/// left out.
pub fn universal_address(addr: SocketAddr) -> String {
    let [hi, lo] = addr.port().to_be_bytes();
    format!("{}.{hi}.{lo}", addr.ip())
}

/// Reads a universal address. It returns `None` for anything else.
pub fn parse_universal_address(s: &str) -> Option<SocketAddr> {
    let mut parts = s.rsplitn(3, '.');
    let lo = byte(parts.next()?)?;
    let hi = byte(parts.next()?)?;
    let ip: IpAddr = parts.next()?.parse().ok()?;
    Some(SocketAddr::new(ip, u16::from_be_bytes([hi, lo])))
}

/// A byte in decimal, digits only.
fn byte(s: &str) -> Option<u8> {
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Fail, Stream, contract, finish, pump};

    #[test]
    fn codec_fragments_and_records() {
        let payload = b"fragmented RPC payload";
        let mut wire = vec![0; RECORD_MARK_LEN]; // Empty nonfinal fragment.
        wire.extend(encode_fragments(payload, 3));
        wire.extend(encode_record(b""));
        contract::check_decode(|| Fragments::with_limit(payload.len()), &wire);
        contract::check_decode_with_held_limit(|| super::records(payload.len()), &wire, payload.len());

        let mut stream = Stream::new(super::records(payload.len()));
        let mut items = Vec::new();
        for byte in &wire {
            assert_eq!(pump(&mut stream, core::slice::from_ref(byte), |item| items.push(item)), Ok(1));
            assert!(stream.buffered() <= payload.len() + RECORD_MARK_LEN);
            assert!(stream.held() <= payload.len());
        }
        assert_eq!(finish(&mut stream, |item| items.push(item)), Ok(()));
        assert_eq!(items, vec![Assembled::Message(payload.to_vec()), Assembled::Message(Vec::new())]);
    }

    #[test]
    fn codec_record_limits_are_checked_from_marks() {
        let mut fragments = Fragments::with_limit(3);
        assert_eq!(
            fragments.decode(&[0, 0, 0, 2, 1, 2], false),
            Ok(Step::Item(Fragment { last: false, data: vec![1, 2] }, 6))
        );
        assert_eq!(fragments.decode(&[0x80, 0, 0, 2], false), Err(RecordError::TooLong(3)));
        assert_eq!(Fragments::with_limit(usize::MAX).capacity(), MAX_RECORD + RECORD_MARK_LEN);

        let wire = [0, 0, 0, 2, 1, 2, 0x80, 0, 0, 2];
        contract::check_decode(|| super::records(3), &wire);
        let mut stream = Stream::new(super::records(3));
        let error = Fail::Protocol(AssembleError::Inner(RecordError::TooLong(3)));
        assert_eq!(pump(&mut stream, &wire, |_| {}), Err(error.clone()));
        assert_eq!(stream.failed(), Some(&error));
        assert!(stream.next().is_none());
        assert_eq!(stream.push(b"ignored"), 7);

        // The generic stage still enforces its own limit independently.
        let mut smaller =
            Assemble::new(Fragments::with_limit(8), 1, |f: Fragment| codec::Fragment::<Infallible>::Part {
                data: f.data,
                last: f.last,
            });
        assert_eq!(smaller.decode(&encode_record(b"ab"), false), Err(AssembleError::TooLong { limit: 1 }));
    }

    #[test]
    fn codec_record_eof_and_zero_limit() {
        for payload in [b"".as_slice(), b"a".as_slice()] {
            let mut wire = (payload.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(payload);
            let mut stream = Stream::new(super::records(8));
            assert_eq!(pump(&mut stream, &wire, |_| panic!("nonfinal fragment")), Ok(wire.len()));
            assert_eq!(
                finish(&mut stream, |_| panic!("unfinished record")),
                Err(Fail::Protocol(AssembleError::Incomplete { held: payload.len() }))
            );
        }
        for partial in [b"\x80".as_slice(), b"\x80\0\0\x02x".as_slice()] {
            let mut stream = Stream::new(super::records(8));
            assert_eq!(pump(&mut stream, partial, |_| panic!("partial fragment")), Ok(partial.len()));
            assert_eq!(
                finish(&mut stream, |_| panic!("partial fragment")),
                Err(Fail::Truncated { unread: partial.len() })
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
            let segmented = encode_fragments(&data, 127);
            assert_eq!(Record::parse(&segmented), Ok(record));
            contract::check_wire::<Record>(&segmented);
        }
        let oversized = Record(vec![3; MAX_RECORD + 1]);
        let mut out = vec![1, 2, 3];
        assert_eq!(oversized.write(&mut out), Err(RecordError::TooLong(MAX_RECORD)));
        assert_eq!(out, [1, 2, 3]);
        // The old encoder still clips at its original limit.
        assert_eq!(Record::parse(&encode_record(&oversized.0)), Ok(Record(vec![3; MAX_RECORD])));
        let mut trailing = encode_record(b"a");
        trailing.extend(encode_record(b"b"));
        assert_eq!(Record::parse(&trailing), Err(RecordParseError::Trailing(5)));
        assert_eq!(Record::parse(&[]), Err(RecordParseError::Truncated));
        assert_eq!(
            Record::parse(&[0, 0, 0, 0]),
            Err(RecordParseError::Framing(AssembleError::Incomplete { held: 0 }))
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
            Auth::Other { flavor: 99, body: vec![5; MAX_AUTH_BODY] },
            Auth::Other { flavor: flavor::NONE, body: vec![1] },
            Auth::Other { flavor: flavor::SYS, body: vec![1] },
        ] {
            let mut c = Call::new(1, 2, 3, vec![4]);
            c.cred = auth.clone();
            c.verf = auth.clone();
            messages.push(Message { xid: 7, body: Body::Call(c) });
            messages.push(call.reply(Reply::Accepted { verf: auth, status: Accept::Success(vec![9]) }));
        }
        for message in messages {
            contract::check_wire_value(&message);
            assert_eq!(<Message as Wire>::to_bytes(&message), Ok(message.to_bytes()));
        }
    }

    #[test]
    fn codec_message_writer_refuses_loss_and_rolls_back() {
        let sys = AuthSys { stamp: 1, machine_name: "host".into(), uid: 2, gid: 3, gids: vec![] };
        let mut long_name = sys.clone();
        long_name.machine_name = "x".repeat(MAX_MACHINE_NAME + 1);
        let mut long_groups = sys.clone();
        long_groups.gids = vec![0; MAX_GIDS + 1];
        for (auth, error) in [
            (Auth::Sys(long_name), MessageWriteError::TooLong { limit: MAX_MACHINE_NAME }),
            (Auth::Sys(long_groups), MessageWriteError::TooLong { limit: MAX_GIDS }),
            (
                Auth::Other { flavor: 99, body: vec![0; MAX_AUTH_BODY + 1] },
                MessageWriteError::TooLong { limit: MAX_AUTH_BODY },
            ),
            (Auth::Other { flavor: flavor::NONE, body: vec![] }, MessageWriteError::NonCanonical),
            (Auth::Other { flavor: flavor::SYS, body: sys.to_bytes() }, MessageWriteError::NonCanonical),
        ] {
            let mut call = Call::new(1, 2, 3, Vec::new());
            call.cred = auth.clone();
            for message in [
                Message { xid: 1, body: Body::Call(call.clone()) },
                Message { xid: 1, body: Body::Call(Call { cred: Auth::None, verf: auth.clone(), ..call }) },
                Message {
                    xid: 1,
                    body: Body::Reply(Reply::Accepted { verf: auth, status: Accept::ProgUnavail }),
                },
            ] {
                let mut out = vec![1, 2, 3];
                assert_eq!(message.write(&mut out), Err(error));
                assert_eq!(out, [1, 2, 3]);
                contract::check_wire_value(&message);
                // The legacy writer still emits its original normalized value.
                assert!(Message::parse(&message.to_bytes()).is_ok());
            }
        }
        let alias =
            Message { xid: 1, body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::Other(0)))) };
        assert_eq!(alias.write(&mut Vec::new()), Err(MessageWriteError::NonCanonical));
        contract::check_wire_value(&alias);
    }

    #[test]
    fn codec_message_size_includes_the_header() {
        for message in [
            Message { xid: 1, body: Body::Call(Call::new(1, 2, 3, vec![0; MAX_RECORD - 40])) },
            Message { xid: 2, body: Body::Reply(Reply::success(vec![0; MAX_RECORD - 24])) },
        ] {
            assert_eq!(<Message as Wire>::to_bytes(&message).unwrap().len(), MAX_RECORD);
            contract::check_wire_value(&message);
            let mut too_long = message.clone();
            match &mut too_long.body {
                Body::Call(call) => call.args.push(1),
                Body::Reply(Reply::Accepted { status: Accept::Success(data), .. }) => data.push(1),
                _ => unreachable!(),
            }
            let mut out = vec![42];
            assert_eq!(too_long.write(&mut out), Err(MessageWriteError::TooLong { limit: MAX_RECORD }));
            assert_eq!(out, [42]);
            let bytes = too_long.to_bytes();
            assert!(Message::parse(&bytes).is_ok());
            assert_eq!(<Message as Wire>::parse(&bytes), Err(XdrError::TooLong((MAX_RECORD + 1) as u32)));
        }
    }

    /// A small deterministic generator for the fuzz loop.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
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

    fn read_file(b: &[u8]) -> Result<(String, i32, String, String, Vec<u8>), XdrError> {
        let mut r = Reader::new(b);
        let name = r.string(255)?.to_string();
        let kind = r.enumeration()?;
        if kind != 2 {
            return Err(XdrError::Discriminant(kind as u32));
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
        assert_eq!((name.as_str(), kind, interp.as_str(), owner.as_str()), ("sillyprog", 2, "lisp", "john"));
        assert_eq!(data, b"(quit)");
        let mut w = Writer::new();
        w.string(&name).enumeration(kind).string(&interp).string(&owner).opaque(&data);
        assert_eq!(w.finish(), FILE);
        // Every truncated prefix ends early.
        for n in 0..FILE.len() {
            assert_eq!(read_file(&FILE[..n]), Err(XdrError::Short), "{n} bytes");
        }
    }

    #[test]
    fn basic_types() {
        let mut w = Writer::new();
        w.int(-2).uint(0xdead_beef).hyper(-3).uhyper(0x0102_0304_0506_0708).bool(true).bool(false);
        w.opaque_fixed(&[1, 2, 3, 4, 5]);
        let bytes = w.finish();
        assert_eq!(&bytes[..4], &[0xff, 0xff, 0xff, 0xfe]);
        assert_eq!(&bytes[8..16], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd]);
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
        let bytes = w.finish();
        assert_eq!(bytes, [0, 0, 0, 3, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 0]);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.array(3, Reader::uint), Ok(vec![7, 8, 9]));
        assert_eq!(r.optional(Reader::uint), Ok(Some(5)));
        assert_eq!(r.optional(Reader::uint), Ok(None));
        assert_eq!(r.finish(), Ok(()));
        // Over the caller's limit, and a count the bytes cannot hold.
        assert_eq!(Reader::new(&bytes).array(2, Reader::uint), Err(XdrError::TooLong(3)));
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).array(usize::MAX, Reader::uint), Err(XdrError::Short));
    }

    #[test]
    fn xdr_errors() {
        assert_eq!(Reader::new(&[0, 0, 0]).uint(), Err(XdrError::Short));
        assert_eq!(Reader::new(&[0, 0, 0, 2]).bool(), Err(XdrError::Bool(2)));
        assert_eq!(Reader::new(&[0, 0, 0, 1, 7, 0, 1, 0]).opaque(4), Err(XdrError::Padding));
        assert_eq!(Reader::new(&[0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0]).opaque(4), Err(XdrError::TooLong(5)));
        assert_eq!(Reader::new(&[0, 0, 0, 2, 0xc3, 0x28, 0, 0]).string(4), Err(XdrError::Utf8));
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).opaque(usize::MAX), Err(XdrError::Short));
        assert_eq!(Reader::new(&[0, 0, 0, 0, 1]).optional(Reader::uint), Ok(None));
        let mut r = Reader::new(&[0, 0, 0, 0, 1]);
        r.uint().unwrap();
        assert_eq!(r.finish(), Err(XdrError::Trailing(1)));
        assert_eq!(r.rest(), &[1]);
        assert_eq!(r.finish(), Ok(()));
        // Errors have messages.
        assert!(!XdrError::Trailing(3).to_string().is_empty());
        assert!(!RecordError::TooLong(8).to_string().is_empty());
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
        let sys = AuthSys { stamp: 9, machine_name: "host1".into(), uid: 1000, gid: 100, gids: vec![10] };
        let call = Call {
            rpc_version: 2,
            program: 100_003,
            version: 3,
            procedure: 1,
            cred: Auth::Sys(sys),
            verf: Auth::None,
            args: vec![0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd],
        };
        assert_eq!(m, Message { xid: 0x1234_5678, body: Body::Call(call) });
        assert_eq!(m.to_bytes(), bytes);
        // Every truncated prefix up to the arguments fails, and none panics.
        for n in 0..bytes.len() {
            let r = Message::parse(&bytes[..n]);
            if n < bytes.len() - 8 {
                assert_eq!(r, Err(XdrError::Short), "{n} bytes");
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
        Auth::Other { flavor: 0, body: vec![1, 2, 3, 4] }.write(&mut w);
        Auth::Other { flavor: 1, body: vec![0, 0, 0, 1] }.write(&mut w);
        Auth::Other { flavor: flavor::RPCSEC_GSS, body: vec![9; 12] }.write(&mut w);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(Auth::read(&mut r), Ok(Auth::Other { flavor: 0, body: vec![1, 2, 3, 4] }));
        assert_eq!(Auth::read(&mut r), Ok(Auth::Other { flavor: 1, body: vec![0, 0, 0, 1] }));
        assert_eq!(Auth::read(&mut r).unwrap().flavor(), 6);
        // A body over 400 bytes.
        let mut w = Writer::new();
        w.uint(1).opaque(&[0; 404]);
        assert_eq!(Auth::read(&mut Reader::new(&w.finish())), Err(XdrError::TooLong(404)));
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
            let m = Message { xid: 42, body: Body::Reply(reply) };
            let bytes = m.to_bytes();
            assert_eq!(Message::parse(&bytes), Ok(m.clone()));
            for n in 0..bytes.len() {
                let r = Message::parse(&bytes[..n]);
                let success = matches!(m.body, Body::Reply(Reply::Accepted { status: Accept::Success(_), .. }));
                if !(success && n >= 24) {
                    assert_eq!(r, Err(XdrError::Short), "{m:?} at {n}");
                }
            }
        }
        // Spot check one layout: denied, AUTH_ERROR, AUTH_TOOWEAK.
        let m = Message { xid: 1, body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::TooWeak))) };
        assert_eq!(m.to_bytes(), [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 5]);
        for n in 0..=100 {
            assert_eq!(AuthStat::from_code(n).code(), n);
        }
        assert_eq!(Accept::Success(vec![]).code(), 0);
    }

    #[test]
    fn message_errors() {
        let d = XdrError::Discriminant;
        assert_eq!(Message::parse(&[0, 0, 0, 1, 0, 0, 0, 2]), Err(d(2)));
        assert_eq!(Message::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2]), Err(d(2)));
        let accepted = [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut b = accepted.to_vec();
        b.extend_from_slice(&[0, 0, 0, 6]);
        assert_eq!(Message::parse(&b), Err(d(6)));
        assert_eq!(Message::parse(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2]), Err(d(2)));
        // Bytes after a reply that has no results.
        let mut b = accepted.to_vec();
        b.extend_from_slice(&[0, 0, 0, 1, 9]);
        assert_eq!(Message::parse(&b), Err(XdrError::Trailing(1)));
        // A message reply keeps the xid.
        let call = PortmapRequest::Null.call(77);
        assert_eq!(call.reply(Reply::success(vec![])).xid, 77);
    }

    #[test]
    fn records() {
        let msg = nfs_call_bytes();
        // One fragment.
        let one = encode_record(&msg);
        assert_eq!(&one[..4], &(0x8000_0000u32 | msg.len() as u32).to_be_bytes());
        // Many fragments, fed one byte at a time.
        let many = encode_fragments(&msg, 5);
        let mut stream = one.clone();
        stream.extend_from_slice(&many);
        stream.extend_from_slice(&encode_record(&[]));
        assert_eq!(encode_record(&[]), [0x80, 0, 0, 0]);
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for b in &stream {
            d.feed(std::slice::from_ref(b));
            while let Some(r) = d.next_record() {
                got.push(r.unwrap());
            }
        }
        assert_eq!(got, [msg.clone(), msg.clone(), vec![]]);
        assert_eq!(d.buffered(), 0);
        // All at once.
        let mut d = Decoder::default();
        d.feed(&stream);
        assert_eq!(d.next_record(), Some(Ok(msg.clone())));
        assert_eq!(d.next_record(), Some(Ok(msg.clone())));
        assert_eq!(d.next_record(), Some(Ok(vec![])));
        assert_eq!(d.next_record(), None);
        // Every truncated prefix waits.
        for n in 0..one.len() {
            let mut d = Decoder::new();
            d.feed(&one[..n]);
            assert_eq!(d.next_record(), None, "{n} bytes");
        }
        // Zero is taken as 1.
        assert_eq!(encode_fragments(&[1, 2], 0), [0, 0, 0, 1, 1, 0x80, 0, 0, 1, 2]);
    }

    #[test]
    fn record_limit() {
        let mut d = Decoder::with_limit(10);
        assert_eq!(d.limit(), 10);
        d.feed(&encode_fragments(&[0; 10], 4));
        assert_eq!(d.next_record(), Some(Ok(vec![0; 10])));
        // The limit counts every fragment, and fails at the mark.
        d.feed(&[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 3]);
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong(10))));
        d.feed(&encode_record(&[1]));
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong(10))));
        assert_eq!(d.buffered(), 0);
        // A huge mark fails at once.
        let mut d = Decoder::new();
        d.feed(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong(MAX_RECORD))));
        assert_eq!(Decoder::with_limit(usize::MAX).limit(), MAX_RECORD);
    }

    #[test]
    fn values_that_share_bytes() {
        // These write the same bytes as a named value and read back as it.
        let read = |a: &Auth| {
            let mut w = Writer::new();
            a.write(&mut w);
            Auth::read(&mut Reader::new(w.as_bytes())).unwrap()
        };
        assert_eq!(read(&Auth::Other { flavor: 0, body: vec![] }), Auth::None);
        let sys = AuthSys { stamp: 1, machine_name: "m".into(), uid: 2, gid: 3, gids: vec![4] };
        assert_eq!(read(&Auth::Other { flavor: 1, body: sys.to_bytes() }), Auth::Sys(sys.clone()));
        assert_eq!(read(&Auth::Sys(sys.clone())), Auth::Sys(sys));
        let m = Message { xid: 1, body: Body::Reply(Reply::Denied(Reject::AuthError(AuthStat::Other(5)))) };
        let Body::Reply(Reply::Denied(Reject::AuthError(s))) = Message::parse(&m.to_bytes()).unwrap().body else {
            panic!()
        };
        assert_eq!(s, AuthStat::TooWeak);
        // A decoder can be cloned partway through a record.
        let mut d = Decoder::new();
        d.feed(&encode_fragments(&[1, 2, 3, 4], 2)[..6]);
        assert_eq!(d.next_record(), None);
        let mut e = d.clone();
        e.feed(&[0x80, 0, 0, 2, 3, 4]);
        assert_eq!(e.next_record(), Some(Ok(vec![1, 2, 3, 4])));
        assert_eq!(d.buffered(), 2);
    }

    #[test]
    fn array_count_does_not_size_the_allocation() {
        // A count of a million, with the bytes to back it, and items that
        // are large in memory. The first item fails, so nothing is kept.
        let mut w = Writer::new();
        w.uint(1 << 20).opaque_fixed(&vec![0; 4 << 20]);
        let bytes = w.finish();
        let big = |r: &mut Reader<'_>| -> Result<[u8; 1 << 16], XdrError> {
            r.uint()?;
            Err(XdrError::Padding)
        };
        assert_eq!(Reader::new(&bytes).array(usize::MAX, big), Err(XdrError::Padding));
        // Items that read still all come back.
        assert_eq!(Reader::new(&bytes).array(usize::MAX, Reader::uint).map(|v| v.len()), Ok(1 << 20));
    }

    #[test]
    fn many_small_records_take_linear_time() {
        // Two million empty records in one feed. Moving the bytes left
        // after each record would copy about 8 TB here.
        let n = 1 << 21;
        let mut d = Decoder::new();
        d.feed(&[0x80, 0, 0, 0].repeat(n));
        let mut count = 0;
        while let Some(r) = d.next_record() {
            assert_eq!(r, Ok(vec![]));
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        // Bytes fed after records were taken out still read.
        d.feed(&encode_fragments(&[1, 2, 3], 2));
        assert_eq!(d.next_record(), Some(Ok(vec![1, 2, 3])));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_drops_bytes_after_a_broken_mark() {
        // A mark that passes the limit, then a megabyte: only the mark is
        // kept, and later feeds are dropped.
        let mut d = Decoder::new();
        let mut bytes = vec![0xff; 4];
        bytes.extend_from_slice(&[0; 1 << 20]);
        d.feed(&bytes);
        assert_eq!(d.buffered(), 4);
        d.feed(&[0; 1 << 10]);
        assert_eq!(d.buffered(), 4);
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong(MAX_RECORD))));
        // Records before the broken mark in the same feed still come out.
        let mut d = Decoder::with_limit(8);
        let mut stream = encode_record(&[1, 2]);
        stream.extend_from_slice(&[0, 0, 0, 4, 9, 9, 9, 9, 0x80, 0, 0, 5]);
        stream.extend_from_slice(&[7; 100]);
        d.feed(&stream);
        assert_eq!(d.buffered(), stream.len() - 100);
        assert_eq!(d.next_record(), Some(Ok(vec![1, 2])));
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong(8))));
    }

    #[test]
    fn decoder_gives_back_room_after_a_long_record() {
        let mut d = Decoder::new();
        d.feed(&encode_record(&vec![5; 1 << 20]));
        assert_eq!(d.next_record().map(|r| r.map(|r| r.len())), Some(Ok(1 << 20)));
        assert_eq!(d.buffered(), 0);
        assert!(d.buf.capacity() <= RETAIN, "{} bytes kept", d.buf.capacity());
        d.feed(&encode_record(&[1]));
        assert_eq!(d.next_record(), Some(Ok(vec![1])));
    }

    #[test]
    fn decoder_tells_a_cut_record_at_the_end() {
        let mut d = Decoder::new();
        assert!(!d.mid_record());
        // An empty fragment that is not the last: nothing is held, but the
        // record has begun.
        d.feed(&[0, 0, 0, 0]);
        assert_eq!(d.next_record(), None);
        assert_eq!(d.buffered(), 0);
        assert!(d.mid_record());
        d.feed(&[0x80, 0, 0]);
        assert!(d.mid_record());
        d.feed(&[0]);
        assert_eq!(d.next_record(), Some(Ok(vec![])));
        assert!(!d.mid_record());
        d.feed(&[0x80, 0, 0, 4, 1]);
        assert_eq!(d.next_record(), None);
        assert!(d.mid_record());
    }

    #[test]
    fn long_records_encode_to_what_a_decoder_reads() {
        for record in [vec![3; MAX_RECORD], vec![3; MAX_RECORD + 1]] {
            for bytes in [encode_record(&record), encode_fragments(&record, 1 << 16)] {
                let mut d = Decoder::new();
                d.feed(&bytes);
                assert_eq!(d.next_record(), Some(Ok(vec![3; MAX_RECORD])));
            }
        }
    }

    #[test]
    fn arrays_of_items_with_no_bytes() {
        // Fixed opaque data of length 0 takes no bytes (RFC 4506, 4.9).
        let mut w = Writer::new();
        w.array(&[(); 3], |w, _| {
            w.opaque_fixed(&[]);
        });
        let bytes = w.finish();
        assert_eq!(bytes, [0, 0, 0, 3]);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.array(3, |r| r.opaque_fixed(0)), Ok(vec![&[][..]; 3]));
        assert_eq!(r.finish(), Ok(()));
        let full = (MAX_ARRAY_RESERVE as u32).to_be_bytes();
        assert_eq!(Reader::new(&full).array(usize::MAX, |r| r.opaque_fixed(0)).map(|v| v.len()), Ok(MAX_ARRAY_RESERVE));
        // Past that, a count still needs 4 bytes an item.
        let over = (MAX_ARRAY_RESERVE as u32 + 1).to_be_bytes();
        assert_eq!(Reader::new(&over).array(usize::MAX, |r| r.opaque_fixed(0)), Err(XdrError::Short));
        // Items that need bytes still end early.
        assert_eq!(Reader::new(&[0, 0, 0, 2, 0, 0, 0, 1]).array(9, Reader::uint), Err(XdrError::Short));
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
        assert!(!silent_on_failure(&Call::new(100_003, 3, procedure::CALLIT, vec![])));
    }

    #[test]
    fn portmap_getport() {
        // GETPORT for NFS 3 on UDP, as a client sends it.
        let m =
            PortmapRequest::GetPort(Mapping { program: 100_003, version: 3, protocol: IPPROTO_UDP, port: 0 }).call(1);
        let bytes = m.to_bytes();
        #[rustfmt::skip]
        let expect = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 3,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 17, 0, 0, 0, 0,
        ];
        assert_eq!(bytes, expect);
        let Body::Call(call) = Message::parse(&bytes).unwrap().body else { panic!() };
        let req = PortmapRequest::parse(&call).unwrap();
        assert_eq!(req.call(1), m);
        assert_eq!(parse_port(&encode_port(2049)), Ok(2049));
        assert_eq!(parse_port(&[0, 0, 8]), Err(XdrError::Short));
    }

    #[test]
    fn portmap_requests_and_errors() {
        let map = Mapping { program: 100_005, version: 1, protocol: IPPROTO_TCP, port: 635 };
        for req in [PortmapRequest::Null, PortmapRequest::Set(map), PortmapRequest::Unset(map), PortmapRequest::Dump] {
            let Body::Call(call) = req.call(3).body else { panic!() };
            assert_eq!(PortmapRequest::parse(&call), Ok(req));
        }
        let mut call = Call::new(PMAP_PROGRAM, 2, procedure::SET, PortmapRequest::Set(map).to_args());
        call.program = 100_003;
        assert_eq!(PortmapRequest::parse(&call), Err(Accept::ProgUnavail));
        call.program = PMAP_PROGRAM;
        call.version = 3;
        assert_eq!(PortmapRequest::parse(&call), Err(Accept::ProgMismatch { low: 2, high: 2 }));
        call.version = 2;
        call.procedure = procedure::CALLIT;
        assert_eq!(PortmapRequest::parse(&call), Err(Accept::ProcUnavail));
        call.procedure = procedure::SET;
        call.args.pop();
        assert_eq!(PortmapRequest::parse(&call), Err(Accept::GarbageArgs));
        call.procedure = procedure::NULL;
        assert_eq!(PortmapRequest::parse(&call), Err(Accept::GarbageArgs));
        // Results.
        assert_eq!(parse_bool(&encode_bool(true)), Ok(true));
        assert_eq!(parse_bool(&[0, 0, 0, 3]), Err(XdrError::Bool(3)));
        let maps = vec![map; 3];
        assert_eq!(parse_dump(&encode_dump(&maps)), Ok(maps));
        assert_eq!(parse_dump(&[0, 0, 0, 0]), Ok(vec![]));
        let long = encode_dump(&vec![map; MAX_DUMP + 5]);
        assert_eq!(parse_dump(&long).unwrap().len(), MAX_DUMP);
        let mut over = Writer::new();
        for _ in 0..=MAX_DUMP {
            over.bool(true);
            map.write(&mut over);
        }
        over.bool(false);
        assert!(matches!(parse_dump(over.as_bytes()), Err(XdrError::TooLong(_))));
        assert_eq!(parse_dump(&[0, 0, 0, 1, 0, 0]), Err(XdrError::Short));
    }

    #[test]
    fn rpcbind() {
        let b =
            Rpcb { program: 100_003, version: 3, netid: "tcp".into(), addr: String::new(), owner: "superuser".into() };
        let m = RpcbRequest::GetAddr(b.clone()).call(5, 4);
        let Body::Call(call) = &m.body else { panic!() };
        #[rustfmt::skip]
        assert_eq!(call.args, [
            0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 3, b't', b'c', b'p', 0, 0, 0, 0, 0,
            0, 0, 0, 9, b's', b'u', b'p', b'e', b'r', b'u', b's', b'e', b'r', 0, 0, 0,
        ]);
        assert_eq!(RpcbRequest::parse(call), Ok(RpcbRequest::GetAddr(b.clone())));
        for req in [RpcbRequest::Null, RpcbRequest::Set(b.clone()), RpcbRequest::Unset(b.clone())] {
            let Body::Call(call) = req.call(1, 3).body else { panic!() };
            assert_eq!(RpcbRequest::parse(&call), Ok(req));
        }
        let mut c = call.clone();
        c.version = 2;
        assert_eq!(RpcbRequest::parse(&c), Err(Accept::ProgMismatch { low: 3, high: 4 }));
        c.version = 4;
        c.procedure = 9;
        assert_eq!(RpcbRequest::parse(&c), Err(Accept::ProcUnavail));
        c.procedure = 3;
        c.args.truncate(10);
        assert_eq!(RpcbRequest::parse(&c), Err(Accept::GarbageArgs));
        c.program = 7;
        assert_eq!(RpcbRequest::parse(&c), Err(Accept::ProgUnavail));
        // GETADDR results and universal addresses.
        let addr: SocketAddr = "10.0.0.5:2049".parse().unwrap();
        let u = universal_address(addr);
        assert_eq!(u, "10.0.0.5.8.1");
        assert_eq!(parse_address(&encode_address(&u)), Ok(u.clone()));
        assert_eq!(parse_universal_address(&u), Some(addr));
        let v6: SocketAddr = "[fe80::1]:111".parse().unwrap();
        assert_eq!(universal_address(v6), "fe80::1.0.111");
        assert_eq!(parse_universal_address("fe80::1.0.111"), Some(v6));
        for bad in ["", "10.0.0.5", "10.0.0.5.256.1", "10.0.0.5.+8.1", "x.1.2", "10.0.0.5.8."] {
            assert_eq!(parse_universal_address(bad), None, "{bad}");
        }
    }

    #[test]
    fn writers_cap_what_they_write() {
        let sys = AuthSys { stamp: 0, machine_name: "é".repeat(200), uid: 0, gid: 0, gids: vec![1; 40] };
        let call = Call { cred: Auth::Sys(sys), ..Call::new(1, 1, 1, vec![]) };
        let bytes = Message { xid: 0, body: Body::Call(call) }.to_bytes();
        let Body::Call(back) = Message::parse(&bytes).unwrap().body else { panic!() };
        let Auth::Sys(s) = back.cred else { panic!("not AUTH_SYS") };
        assert_eq!(s.machine_name.len(), 254);
        assert_eq!(s.gids.len(), MAX_GIDS);
        let other = Auth::Other { flavor: 9, body: vec![1; 1000] };
        let mut w = Writer::new();
        other.write(&mut w);
        let Auth::Other { body, .. } = Auth::read(&mut Reader::new(w.as_bytes())).unwrap() else { panic!() };
        assert_eq!(body.len(), MAX_AUTH_BODY);
        let long = Rpcb { program: 1, version: 1, netid: "n".repeat(999), addr: "a".into(), owner: "o".into() };
        let args = RpcbRequest::Set(long).to_args();
        let Rpcb { netid, .. } = Rpcb::read(&mut Reader::new(&args)).unwrap();
        assert_eq!(netid.len(), MAX_RPCB_STRING);
        assert_eq!(parse_address(&encode_address(&"z".repeat(999))).unwrap().len(), MAX_RPCB_STRING);
    }

    fn random_auth(rng: &mut Lcg) -> Auth {
        match rng.below(4) {
            0 => Auth::None,
            1 => Auth::Sys(AuthSys {
                stamp: rng.next(),
                machine_name: "h".repeat(rng.below(8) as usize),
                uid: rng.below(2000),
                gid: rng.below(200),
                gids: (0..rng.below(4)).map(|_| rng.below(100)).collect(),
            }),
            _ => Auth::Other { flavor: rng.below(8), body: (0..rng.below(12)).map(|_| rng.next() as u8).collect() },
        }
    }

    /// A random message that is well formed, so a mutation of it reaches
    /// deep into the parser.
    fn random_message(rng: &mut Lcg) -> Message {
        let words = |rng: &mut Lcg| -> Vec<u8> {
            let mut w = Writer::new();
            for _ in 0..rng.below(6) {
                w.uint(if rng.below(2) == 0 { rng.below(4) } else { rng.next() });
            }
            w.finish()
        };
        let body = match rng.below(4) {
            0 => {
                let map = Mapping { program: rng.below(3), version: rng.below(4), protocol: 6, port: rng.below(3) };
                let req = match rng.below(5) {
                    0 => PortmapRequest::Null,
                    1 => PortmapRequest::Set(map),
                    2 => PortmapRequest::Unset(map),
                    3 => PortmapRequest::GetPort(map),
                    _ => PortmapRequest::Dump,
                };
                let mut call = Call::new(PMAP_PROGRAM, 2 + rng.below(3), req.procedure(), req.to_args());
                call.cred = random_auth(rng);
                Body::Call(call)
            }
            1 => {
                let mut call = Call::new(rng.below(3) + 100_000, rng.below(5), rng.below(6), words(rng));
                call.cred = random_auth(rng);
                call.verf = random_auth(rng);
                Body::Call(call)
            }
            2 => {
                let status = match rng.below(6) {
                    0 => Accept::Success(words(rng)),
                    1 => Accept::ProgUnavail,
                    2 => Accept::ProgMismatch { low: rng.below(4), high: rng.below(4) },
                    3 => Accept::ProcUnavail,
                    4 => Accept::GarbageArgs,
                    _ => Accept::SystemErr,
                };
                Body::Reply(Reply::Accepted { verf: random_auth(rng), status })
            }
            _ => Body::Reply(Reply::Denied(if rng.below(2) == 0 {
                Reject::RpcMismatch { low: rng.below(4), high: rng.below(4) }
            } else {
                Reject::AuthError(AuthStat::from_code(rng.below(20)))
            })),
        };
        Message { xid: rng.next(), body }
    }

    /// The bytes of a random message, often changed: a byte flipped, cut
    /// short, or with bytes added.
    fn random_bytes(rng: &mut Lcg) -> Vec<u8> {
        let mut b = random_message(rng).to_bytes();
        for _ in 0..rng.below(3) {
            match rng.below(4) {
                0 if !b.is_empty() => {
                    let i = rng.below(b.len() as u32) as usize;
                    b[i] = rng.next() as u8;
                }
                1 => b.truncate(rng.below(b.len() as u32 + 1) as usize),
                2 => b.push(rng.next() as u8),
                _ => {}
            }
        }
        b
    }

    #[test]
    fn fuzz_parse_and_round_trip() {
        let mut rng = Lcg(0x5531_4506);
        let mut parsed = 0;
        for _ in 0..20_000 {
            let bytes = random_bytes(&mut rng);
            if let Ok(m) = Message::parse(&bytes) {
                parsed += 1;
                assert_eq!(m.to_bytes(), bytes);
                if let Body::Call(call) = &m.body {
                    if let Ok(req) = PortmapRequest::parse(call) {
                        let Body::Call(again) = req.call(m.xid).body else { panic!() };
                        assert_eq!(PortmapRequest::parse(&again), Ok(req));
                    }
                    if let Ok(req) = RpcbRequest::parse(call) {
                        let Body::Call(again) = req.call(m.xid, call.version).body else { panic!() };
                        assert_eq!(RpcbRequest::parse(&again), Ok(req));
                    }
                }
            }
            let _ = parse_dump(&bytes);
            let _ = AuthSys::parse(&bytes);
            let _ = parse_address(&bytes);
            let mut r = Reader::new(&bytes);
            let _ = r.array(64, |r| r.optional(|r| r.opaque(64).map(<[u8]>::to_vec)));
            // The same bytes as a TCP stream, whole and one byte at a time.
            let limit = rng.below(64) as usize;
            let mut whole = Decoder::with_limit(limit);
            whole.feed(&bytes);
            let mut a = Vec::new();
            while let Some(Ok(rec)) = whole.next_record() {
                a.push(rec);
            }
            let mut bytewise = Decoder::with_limit(limit);
            let mut b = Vec::new();
            for byte in &bytes {
                bytewise.feed(std::slice::from_ref(byte));
                while let Some(Ok(rec)) = bytewise.next_record() {
                    b.push(rec);
                }
            }
            assert_eq!(a, b);
            assert_eq!(whole.next_record(), bytewise.next_record());
            // Real records, split into fragments, read back.
            let mut d = Decoder::new();
            d.feed(&encode_fragments(&bytes, 1 + rng.below(16) as usize));
            assert_eq!(d.next_record(), Some(Ok(bytes.clone())));
            for rec in &a {
                assert!(rec.len() <= limit);
                let mut d = Decoder::with_limit(limit);
                d.feed(&encode_fragments(rec, 1 + rng.below(8) as usize));
                assert_eq!(d.next_record(), Some(Ok(rec.clone())));
            }
        }
        assert!(parsed > 500, "only {parsed} messages parsed");
    }
}
