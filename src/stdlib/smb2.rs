//! SMB2 and SMB3: reading and writing messages, compound chains and their
//! bodies, with no I/O.
//!
//! SMB is how Windows shares files, printers and named pipes. A client opens
//! a TCP connection to port 445, negotiates a dialect, sets up a session
//! (authentication rides inside it as opaque security blobs), connects to a
//! share, then creates, reads, writes and closes files on it. SMB 3 is the
//! same protocol with later dialects. Each message starts with a 64-byte
//! header that carries the command, the status, credits and a message ID,
//! and is followed by a body whose layout depends on the command. Several
//! messages may travel together in one compound chain, each header pointing
//! at the next. Over TCP each chain sits behind a 4-byte header: a zero byte
//! and a 24-bit length. This module follows Microsoft's MS-SMB2
//! specification, sections 2.1 and 2.2.
//!
//! Nothing here reads a socket. A world that plays a file server feeds the
//! bytes it reads from a TCP connection to a [`Decoder`], gets the payload of
//! each transport frame back, reads it as a [`Packet`], reads each
//! [`Message`]'s [`Request`], and writes the bytes of its replies back to
//! the connection. Which dialects, users, shares and files exist, and what
//! each request does to them, is up to world code.
//!
//! Signing and encryption are not done here. A message's signature is kept
//! as 16 bytes, and encrypted and compressed messages are read as their
//! headers with the rest kept as bytes. Security blobs (SPNEGO, NTLM,
//! Kerberos), information classes, directory entries and FSCTL buffers are
//! kept as bytes too.
//!
//! Every reader checks lengths and offsets, because the agent can send any
//! bytes it likes. Bytes that break the specification are an [`Error`].
//! Writers return an [`EncodeError`] rather than write bytes a reader would
//! refuse or read back as something else.
//!
//! ```
//! use fictionet::stdlib::smb2::{
//!     Decoder, Header, Message, NegotiateRequest, NegotiateResponse, Packet, Request, Response,
//!     command, dialect, status,
//! };
//!
//! // A client offers SMB 2.1 and SMB 3.0.2.
//! let negotiate = Request::Negotiate(NegotiateRequest {
//!     dialects: vec![dialect::SMB_2_1, dialect::SMB_3_0_2],
//!     ..NegotiateRequest::default()
//! });
//! let hello = Message::from_request(Header::new(command::NEGOTIATE, 0), &negotiate).unwrap();
//! let bytes = Packet::Smb2(vec![hello]).to_frame().unwrap();
//!
//! // The world reads it, in two pieces.
//! let mut decoder = Decoder::new();
//! assert_eq!(decoder.feed(&bytes[..10]), 10);
//! assert_eq!(decoder.next_frame(), None);
//! assert_eq!(decoder.feed(&bytes[10..]), bytes.len() - 10);
//! let payload = decoder.next_frame().unwrap().unwrap();
//! let Packet::Smb2(messages) = Packet::parse(&payload).unwrap() else { panic!() };
//! let Ok(Request::Negotiate(offer)) = messages[0].request() else { panic!() };
//!
//! // It picks the highest dialect it speaks, up to SMB 3.0.2.
//! let chosen = offer.dialects.iter().copied().filter(|&d| d <= dialect::SMB_3_0_2).max().unwrap();
//! assert_eq!(chosen, dialect::SMB_3_0_2);
//! let answer = Response::Negotiate(NegotiateResponse {
//!     dialect: chosen,
//!     max_read_size: 65536,
//!     ..NegotiateResponse::default()
//! });
//! let reply = Message::reply_to(&messages[0].header, status::SUCCESS, &answer).unwrap();
//! let out = Packet::Smb2(vec![reply]).to_frame().unwrap();
//! // A 129-byte message: the 64-byte header and a 65-byte body.
//! assert_eq!(out[..8], [0, 0, 0, 129, 0xfe, b'S', b'M', b'B']);
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port SMB servers listen on for direct TCP.
pub const PORT: u16 = 445;
/// The length of the direct TCP header, before each frame's payload.
pub const FRAME_HEADER_LEN: usize = 4;
/// The longest payload a frame may carry here: 8 MiB of data, the most
/// one READ or WRITE usually moves, and 64 KiB for headers and bodies. The
/// transport's own limit is 16 MiB; frames past this one are refused.
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024 + 64 * 1024;
/// The most bytes a [`Decoder`] holds that have not been taken out: one
/// longest frame.
pub const MAX_BUFFERED: usize = FRAME_HEADER_LEN + MAX_MESSAGE;
/// The length of an SMB2 header.
pub const HEADER_LEN: usize = 64;
/// The length of an SMB2 transform header, before the encrypted message.
pub const TRANSFORM_HEADER_LEN: usize = 52;
/// The length of an unchained compression transform header.
pub const COMPRESSION_HEADER_LEN: usize = 16;
/// The most messages one compound chain may hold.
pub const MAX_CHAIN: usize = 512;
/// The TREE_CONNECT request flag that says a request extension starts the
/// Buffer, SMB 3.1.1 only.
pub const TREE_CONNECT_EXTENSION_PRESENT: u16 = 0x0004;
/// The length of a TREE_CONNECT request extension's header, before its
/// PathName: TreeConnectContextOffset, TreeConnectContextCount and 10
/// reserved bytes.
pub const TREE_CONNECT_EXTENSION_LEN: usize = 16;

/// The protocol IDs that start a payload.
pub mod protocol {
    /// An SMB2 header.
    pub const SMB2: [u8; 4] = [0xfe, b'S', b'M', b'B'];
    /// A transform header: an encrypted message follows.
    pub const TRANSFORM: [u8; 4] = [0xfd, b'S', b'M', b'B'];
    /// A compression transform header: a compressed message follows.
    pub const COMPRESSION: [u8; 4] = [0xfc, b'S', b'M', b'B'];
    /// An SMB1 header. Clients that also speak SMB1 open with an SMB1
    /// NEGOTIATE that offers "SMB 2.???".
    pub const SMB1: [u8; 4] = [0xff, b'S', b'M', b'B'];
}

/// Command codes.
pub mod command {
    #![allow(missing_docs)]
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const LOGOFF: u16 = 0x0002;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const TREE_DISCONNECT: u16 = 0x0004;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const FLUSH: u16 = 0x0007;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const LOCK: u16 = 0x000a;
    pub const IOCTL: u16 = 0x000b;
    pub const CANCEL: u16 = 0x000c;
    pub const ECHO: u16 = 0x000d;
    pub const QUERY_DIRECTORY: u16 = 0x000e;
    pub const CHANGE_NOTIFY: u16 = 0x000f;
    pub const QUERY_INFO: u16 = 0x0010;
    pub const SET_INFO: u16 = 0x0011;
    pub const OPLOCK_BREAK: u16 = 0x0012;
    pub const SERVER_TO_CLIENT_NOTIFICATION: u16 = 0x0013;
}

/// Header flags.
pub mod flags {
    /// The message is a response.
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    /// The header is the async form: it carries an async ID, not a tree ID.
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    /// In a compound chain: this request works on the session, tree and
    /// file of the one before it.
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    /// The message is signed.
    pub const SIGNED: u32 = 0x0000_0008;
    /// The message's priority, SMB 3.1.1 only.
    pub const PRIORITY_MASK: u32 = 0x0000_0070;
    /// The path is a DFS path.
    pub const DFS_OPERATIONS: u32 = 0x1000_0000;
    /// The request is sent again, after a lost connection.
    pub const REPLAY_OPERATION: u32 = 0x2000_0000;
}

/// Dialect revisions.
pub mod dialect {
    #![allow(missing_docs)]
    pub const SMB_2_0_2: u16 = 0x0202;
    pub const SMB_2_1: u16 = 0x0210;
    pub const SMB_3_0: u16 = 0x0300;
    pub const SMB_3_0_2: u16 = 0x0302;
    pub const SMB_3_1_1: u16 = 0x0311;
    /// Sent in reply to an SMB1 NEGOTIATE: the client should negotiate
    /// again with SMB2.
    pub const WILDCARD: u16 = 0x02ff;
}

/// Status codes worlds often answer with. Any other `u32` is allowed.
pub mod status {
    #![allow(missing_docs)]
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103;
    pub const NOTIFY_ENUM_DIR: u32 = 0x0000_010c;
    pub const BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const STOPPED_ON_SYMLINK: u32 = 0x8000_002d;
    pub const NOT_IMPLEMENTED: u32 = 0xc000_0002;
    pub const INVALID_HANDLE: u32 = 0xc000_0008;
    pub const INVALID_PARAMETER: u32 = 0xc000_000d;
    pub const NO_SUCH_FILE: u32 = 0xc000_000f;
    pub const END_OF_FILE: u32 = 0xc000_0011;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;
    pub const ACCESS_DENIED: u32 = 0xc000_0022;
    pub const OBJECT_NAME_INVALID: u32 = 0xc000_0033;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xc000_0035;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xc000_003a;
    pub const SHARING_VIOLATION: u32 = 0xc000_0043;
    pub const LOGON_FAILURE: u32 = 0xc000_006d;
    pub const NOT_SUPPORTED: u32 = 0xc000_00bb;
    pub const NETWORK_NAME_DELETED: u32 = 0xc000_00c9;
    pub const BAD_NETWORK_NAME: u32 = 0xc000_00cc;
    pub const CANCELLED: u32 = 0xc000_0120;
    pub const FILE_CLOSED: u32 = 0xc000_0128;
    pub const USER_SESSION_DELETED: u32 = 0xc000_0203;
}

/// Global capabilities, in NEGOTIATE.
pub mod capability {
    #![allow(missing_docs)]
    pub const DFS: u32 = 0x01;
    pub const LEASING: u32 = 0x02;
    pub const LARGE_MTU: u32 = 0x04;
    pub const MULTI_CHANNEL: u32 = 0x08;
    pub const PERSISTENT_HANDLES: u32 = 0x10;
    pub const DIRECTORY_LEASING: u32 = 0x20;
    pub const ENCRYPTION: u32 = 0x40;
    pub const NOTIFICATIONS: u32 = 0x80;
}

/// Security mode bits, in NEGOTIATE and SESSION_SETUP.
pub mod security_mode {
    #![allow(missing_docs)]
    pub const SIGNING_ENABLED: u16 = 0x01;
    pub const SIGNING_REQUIRED: u16 = 0x02;
}

/// Negotiate context types, SMB 3.1.1 only.
pub mod negotiate_context {
    #![allow(missing_docs)]
    pub const PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
    pub const ENCRYPTION_CAPABILITIES: u16 = 0x0002;
    pub const COMPRESSION_CAPABILITIES: u16 = 0x0003;
    pub const NETNAME_NEGOTIATE_CONTEXT_ID: u16 = 0x0005;
    pub const TRANSPORT_CAPABILITIES: u16 = 0x0006;
    pub const RDMA_TRANSFORM_CAPABILITIES: u16 = 0x0007;
    pub const SIGNING_CAPABILITIES: u16 = 0x0008;
    /// The one preauthentication hash, SHA-512.
    pub const SHA_512: u16 = 0x0001;
}

/// Create context names, as they travel.
pub mod create_context {
    #![allow(missing_docs)]
    pub const EA_BUFFER: &[u8] = b"ExtA";
    pub const SD_BUFFER: &[u8] = b"SecD";
    pub const DURABLE_HANDLE_REQUEST: &[u8] = b"DHnQ";
    pub const DURABLE_HANDLE_RECONNECT: &[u8] = b"DHnC";
    pub const ALLOCATION_SIZE: &[u8] = b"AlSi";
    pub const QUERY_MAXIMAL_ACCESS: &[u8] = b"MxAc";
    pub const TIMEWARP_TOKEN: &[u8] = b"TWrp";
    pub const QUERY_ON_DISK_ID: &[u8] = b"QFid";
    pub const REQUEST_LEASE: &[u8] = b"RqLs";
    pub const DURABLE_HANDLE_REQUEST_V2: &[u8] = b"DH2Q";
    pub const DURABLE_HANDLE_RECONNECT_V2: &[u8] = b"DH2C";
}

/// Share types, in a TREE_CONNECT response.
pub mod share_type {
    #![allow(missing_docs)]
    pub const DISK: u8 = 0x01;
    pub const PIPE: u8 = 0x02;
    pub const PRINT: u8 = 0x03;
}

/// Why bytes are not an SMB direct TCP frame. Either way, the connection
/// holds no more frames a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The first byte was not 0.
    Type(u8),
    /// The length was more than [`MAX_MESSAGE`].
    Length(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Type(t) => write!(f, "frame type {t:#04x}, not 0"),
            FrameError::Length(n) => write!(f, "frame length {n}, more than {MAX_MESSAGE}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why bytes are not an SMB2 message, chain or body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before a fixed part does.
    Truncated,
    /// The payload starts with no protocol ID this module reads.
    Protocol([u8; 4]),
    /// The payload is longer than [`MAX_MESSAGE`].
    TooLong,
    /// A header's StructureSize was not 64.
    HeaderSize(u16),
    /// A body's StructureSize was not the one its command has.
    StructureSize(u16),
    /// A NextCommand that is below 64, not a multiple of 8, or past the
    /// end of the payload.
    NextCommand(u32),
    /// A compound chain of more than [`MAX_CHAIN`] messages.
    TooMany,
    /// An offset and length that point outside the message, into its
    /// header or into the body's fixed part. Also a list that claims more
    /// than its bytes hold: a create context's Next that points at no
    /// further context, error contexts past the error data, or a chained
    /// compression payload too short for its OriginalPayloadSize. Also an
    /// IOCTL request whose OutputCount is not 0, or an extended
    /// TREE_CONNECT request whose path is not after the extension's
    /// 16-byte header.
    Buffer,
    /// Two buffers of one body that share bytes, or contexts that start
    /// before the end of the buffer they follow: the dialect list, the
    /// security buffer or the file name. A create context's name and data
    /// over the same bytes count too, as does IOCTL response output that
    /// starts before the end of the input.
    Overlap,
    /// Negotiate contexts, create contexts, or a create context's Next,
    /// NameOffset or DataOffset that are not 8-byte aligned, and the same
    /// for a CREATE request's file name and an IOCTL response's output.
    /// The value is the offset.
    Align(u32),
    /// A UTF-16 string with an odd number of bytes.
    OddString,
    /// A LOCK request with no locks.
    NoLocks,
    /// A NEGOTIATE request with no dialects.
    NoDialects,
    /// Compression flags not allowed where they are: an unchained header
    /// needs 0, the first chained payload 1, and each later one 0.
    CompressionFlags(u16),
    /// An unchained compression header whose algorithm is NONE.
    CompressionAlgorithm,
    /// A transform header whose Flags (EncryptionAlgorithm in SMB 3.0) is
    /// not 0x0001. The value is the field.
    TransformFlags(u16),
    /// An SMB 3.1.1 NEGOTIATE response whose contexts break MS-SMB2
    /// section 3.2.5.2: not exactly one preauthentication integrity
    /// context, or more than one encryption, compression, RDMA transform,
    /// signing or transport context.
    NegotiateContexts,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("the bytes end inside a fixed part"),
            Error::Protocol(p) => write!(f, "protocol ID {p:02x?} is not SMB2"),
            Error::TooLong => write!(f, "a payload longer than {MAX_MESSAGE} bytes"),
            Error::HeaderSize(n) => write!(f, "header StructureSize {n}, not 64"),
            Error::StructureSize(n) => write!(f, "body StructureSize {n} does not match the command"),
            Error::NextCommand(n) => write!(f, "NextCommand {n} is not a valid offset"),
            Error::TooMany => write!(f, "a compound chain of more than {MAX_CHAIN} messages"),
            Error::Buffer => f.write_str("an offset and length outside the message or inside a fixed part"),
            Error::Overlap => f.write_str("two buffers of one body overlap or are out of order"),
            Error::Align(n) => write!(f, "offset {n} is not 8-byte aligned"),
            Error::OddString => f.write_str("a UTF-16 string of an odd number of bytes"),
            Error::NoLocks => f.write_str("a LOCK request with no locks"),
            Error::NoDialects => f.write_str("a NEGOTIATE request with no dialects"),
            Error::CompressionFlags(x) => write!(f, "compression flags {x:#06x} are not allowed here"),
            Error::CompressionAlgorithm => f.write_str("an unchained compression header with algorithm NONE"),
            Error::TransformFlags(x) => write!(f, "transform header flags {x:#06x}, not 0x0001"),
            Error::NegotiateContexts => {
                f.write_str("an SMB 3.1.1 NEGOTIATE response with missing or repeated contexts")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Why a writer refused a value: its bytes would break the specification,
/// or a reader would read them back as something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A buffer or list too long for its length field, or a message longer
    /// than [`MAX_MESSAGE`].
    TooLong,
    /// A body that does not go with the command: a typed request or
    /// response given another command, or an `Other` value given a command
    /// this module reads as a typed one.
    Command(u16),
    /// A response body that does not go with the status: an error body
    /// where the status says a typed one is read, or the other way round.
    Status(u32),
    /// A header whose ASYNC_COMMAND flag does not match its [`Target`].
    AsyncFlag,
    /// An empty compound chain, or a chained compression header with no
    /// payloads.
    Empty,
    /// Negotiate contexts without SMB 3.1.1, or a client start time with
    /// it. Also an SMB 3.1.1 NEGOTIATE response whose contexts a client
    /// must refuse (see [`Error::NegotiateContexts`]).
    Dialect,
    /// A compression header whose flags break the rules: an unchained
    /// header with algorithm NONE, or chained payloads whose first flags
    /// are not exactly [`COMPRESSION_FLAG_CHAINED`] or whose later flags
    /// are not 0. Also a chained payload of LZNT1, LZ77, LZ77+Huffman or
    /// LZ4 with fewer than the 4 bytes of its OriginalPayloadSize.
    Chained,
    /// SMB1 bytes that do not start with the SMB1 protocol ID.
    Protocol,
    /// A LOCK request with no locks.
    NoLocks,
    /// A NEGOTIATE request with no dialects.
    NoDialects,
    /// An unchained compression offset past the end of its data.
    Offset,
    /// A transform header whose flags are not 0x0001, or with no
    /// encrypted message after it.
    Transform,
    /// READ or WRITE channel information with channel 0, NONE, which
    /// carries none.
    Channel,
    /// Error data that does not hold the error contexts its count claims,
    /// each 8-byte aligned.
    ErrorContexts,
    /// An IOCTL request with output bytes: its OutputCount must be 0.
    IoctlOutput,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLong => f.write_str("too long for its length field or for one message"),
            EncodeError::Command(c) => write!(f, "this body does not go with command {c:#06x}"),
            EncodeError::Status(s) => write!(f, "this response body does not go with status {s:#010x}"),
            EncodeError::AsyncFlag => f.write_str("the ASYNC_COMMAND flag does not match the header's target"),
            EncodeError::Empty => f.write_str("an empty chain"),
            EncodeError::Dialect => f.write_str("negotiate contexts and the dialects disagree"),
            EncodeError::Chained => f.write_str("the compression header's flags or algorithm break the rules"),
            EncodeError::Protocol => f.write_str("SMB1 bytes must start with the SMB1 protocol ID"),
            EncodeError::NoLocks => f.write_str("a LOCK request needs at least one lock"),
            EncodeError::NoDialects => f.write_str("a NEGOTIATE request needs at least one dialect"),
            EncodeError::Offset => f.write_str("an offset past the end of the data"),
            EncodeError::Transform => f.write_str("a transform header needs flags 0x0001 and an encrypted message"),
            EncodeError::Channel => f.write_str("channel information needs a channel other than NONE"),
            EncodeError::ErrorContexts => f.write_str("the error data does not hold the error contexts counted"),
            EncodeError::IoctlOutput => f.write_str("an IOCTL request carries no output bytes"),
        }
    }
}

impl std::error::Error for EncodeError {}

// ---------------------------------------------------------------------
// Framing

/// Reads the direct TCP frame at the start of `b`. It returns `Ok(None)` if
/// `b` holds only part of one, and otherwise the frame's payload and how
/// many bytes of `b` it took.
pub fn parse_frame(b: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    let Some(&first) = b.first() else { return Ok(None) };
    if first != 0 {
        return Err(FrameError::Type(first));
    }
    if b.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    let length = (usize::from(b[1]) << 16) | (usize::from(b[2]) << 8) | usize::from(b[3]);
    if length > MAX_MESSAGE {
        return Err(FrameError::Length(length));
    }
    let end = FRAME_HEADER_LEN + length;
    match b.get(FRAME_HEADER_LEN..end) {
        Some(payload) => Ok(Some((payload, end))),
        None => Ok(None),
    }
}

/// The direct TCP frame that carries `payload`. A payload longer than
/// [`MAX_MESSAGE`] is an error.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if payload.len() > MAX_MESSAGE {
        return Err(EncodeError::TooLong);
    }
    let n = payload.len() as u32;
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(0);
    out.extend_from_slice(&n.to_be_bytes()[1..]);
    out.extend_from_slice(payload);
    Ok(out)
}

/// One direct TCP frame with an uninterpreted payload.
///
/// [`Wire`] includes the four-byte transport header. Interpret the payload
/// with [`Packet::parse`]. A payload error does not prevent finding the next
/// frame. Empty payloads are allowed, as in [`parse_frame`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Payload bytes, limited to [`MAX_MESSAGE`] on read and write.
    pub payload: Vec<u8>,
}

/// Why an exact [`Wire`] parse did not contain one complete TCP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The transport header was invalid.
    Frame(FrameError),
    /// The input ended before a complete frame.
    Incomplete,
    /// Bytes followed the complete frame.
    Trailing {
        /// Number of bytes after the frame.
        remaining: usize,
    },
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete SMB direct TCP frame"),
            Self::Trailing { remaining } => write!(f, "{remaining} bytes after SMB direct TCP frame"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = EncodeError;

    /// Reads exactly one transport frame of at most [`MAX_BUFFERED`] bytes.
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        match parse_frame(bytes).map_err(FrameParseError::Frame)? {
            Some((payload, used)) if used == bytes.len() => Ok(Self { payload: payload.to_vec() }),
            Some((_, used)) => Err(FrameParseError::Trailing { remaining: bytes.len().saturating_sub(used) }),
            None => Err(FrameParseError::Incomplete),
        }
    }

    /// Appends the transport header and payload. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(&frame(&self.payload)?);
        Ok(())
    }
}

/// Reads direct TCP frames without retaining input.
///
/// Use with [`super::codec::Stream`] for a buffer bounded by [`MAX_BUFFERED`].
/// The four-byte header suffices to refuse a payload above [`MAX_MESSAGE`].
/// Partial frames return [`Step::Need`], including at EOF, so the driver
/// reports truncation. Framing errors end the stream and are reported once.
/// Map items through [`Packet::parse`] to receive payload errors as items.
/// The legacy [`Decoder`] remains separate to preserve repeated errors and
/// buffer clearing on failure.
///
/// ```
/// use fictionet::stdlib::{codec::{Decode, Stream, Wire}, smb2::{Frame, Frames, Packet}};
/// let bytes = Wire::to_bytes(&Frame { payload: b"\xffSMBhello".to_vec() })?;
/// let mut stream = Stream::new(Frames::new().map(|f| Packet::parse(&f.payload)));
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert!(matches!(stream.next(), Some(Ok(Ok(Packet::Smb1(_))))));
/// # Ok::<(), fictionet::stdlib::smb2::EncodeError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a frame decoder with no retained state.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = FrameError;
    const NAME: &'static str = "SMB direct TCP";

    fn capacity(&self) -> usize {
        MAX_BUFFERED
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, FrameError> {
        Ok(match parse_frame(input)? {
            Some((payload, used)) => Step::Item(Frame { payload: payload.to_vec() }, used),
            None => Step::Need,
        })
    }
}

/// Splits an SMB direct TCP byte stream into frame payloads. Feed it the
/// bytes a connection reads, in order, and take payloads out until it has
/// none.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer.
    start: usize,
    failed: Option<FrameError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than [`MAX_BUFFERED`] bytes. Then take payloads
    /// out with [`Decoder::next_frame`] and feed it the rest. Once it is
    /// full, `next_frame` always gives a payload or an error, so a loop of
    /// feeding and taking out always ends. After a [`FrameError`] the
    /// stream cannot be read any further, and every byte is taken and
    /// dropped.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(MAX_BUFFERED.saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The payload of the next whole frame, if one has come. It returns
    /// `None` when it needs more bytes, and keeps returning the same error
    /// once the stream has broken.
    pub fn next_frame(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match parse_frame(&self.buf[self.start..]) {
            Ok(Some((payload, used))) => {
                let payload = payload.to_vec();
                self.start += used;
                Some(Ok(payload))
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

    /// How many bytes are held, waiting for the rest of a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

// ---------------------------------------------------------------------
// Payloads

/// What one frame's payload holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// One SMB2 message, or a compound chain of them.
    Smb2(Vec<Message>),
    /// An encrypted message behind its transform header.
    Transform(Transform),
    /// A compressed message behind its compression transform header.
    Compressed(Compressed),
    /// An SMB1 message, kept whole as bytes, protocol ID included.
    Smb1(Vec<u8>),
}

impl Packet {
    /// Reads a frame's payload, by its protocol ID. A payload longer than
    /// [`MAX_MESSAGE`] is refused.
    pub fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let id: [u8; 4] = arr(b, 0)?;
        match id {
            protocol::SMB2 => Ok(Packet::Smb2(parse_chain(b)?)),
            protocol::TRANSFORM => Ok(Packet::Transform(Transform::parse(b)?)),
            protocol::COMPRESSION => Ok(Packet::Compressed(Compressed::parse(b)?)),
            protocol::SMB1 => Ok(Packet::Smb1(b.to_vec())),
            other => Err(Error::Protocol(other)),
        }
    }

    /// The payload's bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let out = match self {
            Packet::Smb2(messages) => write_chain(messages)?,
            Packet::Transform(t) => t.to_bytes()?,
            Packet::Compressed(c) => c.to_bytes()?,
            Packet::Smb1(b) => {
                if !b.starts_with(&protocol::SMB1) {
                    return Err(EncodeError::Protocol);
                }
                too_long(b.len())?;
                b.clone()
            }
        };
        if out.len() > MAX_MESSAGE {
            return Err(EncodeError::TooLong);
        }
        Ok(out)
    }

    /// The payload's bytes in a direct TCP frame, ready for the connection.
    pub fn to_frame(&self) -> Result<Vec<u8>, EncodeError> {
        frame(&self.to_bytes()?)
    }
}

/// The SMB2 transform header, with the encrypted message after it kept as
/// bytes. Its reserved field is not kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transform {
    /// The AES-CCM or AES-GCM signature over the header and message.
    pub signature: [u8; 16],
    /// The nonce: 11 bytes for CCM, 12 for GCM, padded with zeros.
    pub nonce: [u8; 16],
    /// The length of the message once decrypted.
    pub original_size: u32,
    /// Always 0x0001: Encrypted in SMB 3.1.1, AES-128-CCM in SMB 3.0 and
    /// 3.0.2, where the field is called EncryptionAlgorithm. Readers and
    /// writers refuse any other value.
    pub flags: u16,
    /// The session whose keys encrypted the message.
    pub session_id: u64,
    /// The encrypted message, at least one byte.
    pub data: Vec<u8>,
}

impl Transform {
    /// Reads a transform header and what follows it. Following MS-SMB2
    /// section 3.3.5.2.1.1, flags other than 0x0001 are an error, and so is
    /// a header with no message after it ([`Error::Truncated`]).
    pub fn parse(b: &[u8]) -> Result<Transform, Error> {
        if arr::<4>(b, 0)? != protocol::TRANSFORM {
            return Err(Error::Protocol(arr(b, 0)?));
        }
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        if b.len() <= TRANSFORM_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let flags = le16(b, 42)?;
        if flags != 1 {
            return Err(Error::TransformFlags(flags));
        }
        Ok(Transform {
            signature: arr(b, 4)?,
            nonce: arr(b, 20)?,
            original_size: le32(b, 36)?,
            flags,
            session_id: le64(b, 44)?,
            data: b[TRANSFORM_HEADER_LEN..].to_vec(),
        })
    }

    /// The header's bytes, then the data. Flags other than 0x0001, empty
    /// data, or a payload longer than [`MAX_MESSAGE`] are an error.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.flags != 1 || self.data.is_empty() {
            return Err(EncodeError::Transform);
        }
        too_long(TRANSFORM_HEADER_LEN.saturating_add(self.data.len()))?;
        let mut out = Vec::with_capacity(TRANSFORM_HEADER_LEN + self.data.len());
        out.extend_from_slice(&protocol::TRANSFORM);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.original_size.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

/// The compression transform header's flag that marks the chained form.
pub const COMPRESSION_FLAG_CHAINED: u16 = 0x0001;

/// A compression transform header, with the compressed bytes kept as they
/// are. Which form it is shows in the flags at offset 10: 0 means the
/// unchained form, and [`COMPRESSION_FLAG_CHAINED`] the chained form. Any
/// other flags there are an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Compressed {
    /// One compressed segment.
    Unchained {
        /// The length of the message once decompressed.
        original_size: u32,
        /// The compression algorithm's ID. It is never 0, NONE.
        algorithm: u16,
        /// How many bytes of `data` are not compressed, before the
        /// compressed ones.
        offset: u32,
        /// Everything after the 16-byte header.
        data: Vec<u8>,
    },
    /// A chain of payloads, each compressed its own way.
    Chained {
        /// The length of the message once decompressed.
        original_size: u32,
        /// The payloads. The first has flags [`COMPRESSION_FLAG_CHAINED`],
        /// and the rest have flags 0.
        payloads: Vec<ChainedPayload>,
    },
}

/// One payload of a chained compression header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainedPayload {
    /// The compression algorithm's ID.
    pub algorithm: u16,
    /// The payload's flags: [`COMPRESSION_FLAG_CHAINED`] for the first
    /// payload of a chain, 0 for the rest.
    pub flags: u16,
    /// The payload's bytes, with its OriginalPayloadSize first when the
    /// algorithm has one: LZNT1 1, LZ77 2, LZ77+Huffman 3 and LZ4 5, whose
    /// data is therefore at least 4 bytes.
    pub data: Vec<u8>,
}

impl ChainedPayload {
    /// The fewest bytes the payload's data holds: the 4 bytes of
    /// OriginalPayloadSize for the algorithms that have it (MS-SMB2
    /// section 2.2.42.2.1), and none for the rest.
    fn min_len(&self) -> usize {
        if matches!(self.algorithm, 1 | 2 | 3 | 5) { 4 } else { 0 }
    }
}

impl Compressed {
    /// Reads a compression transform header and what follows it.
    pub fn parse(b: &[u8]) -> Result<Compressed, Error> {
        if arr::<4>(b, 0)? != protocol::COMPRESSION {
            return Err(Error::Protocol(arr(b, 0)?));
        }
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let original_size = le32(b, 4)?;
        let flags = le16(b, 10)?;
        if flags == 0 {
            if b.len() < COMPRESSION_HEADER_LEN {
                return Err(Error::Truncated);
            }
            let algorithm = le16(b, 8)?;
            if algorithm == 0 {
                return Err(Error::CompressionAlgorithm);
            }
            let offset = le32(b, 12)?;
            let data = b[COMPRESSION_HEADER_LEN..].to_vec();
            if offset as usize > data.len() {
                return Err(Error::Buffer);
            }
            return Ok(Compressed::Unchained { original_size, algorithm, offset, data });
        }
        if flags != COMPRESSION_FLAG_CHAINED {
            return Err(Error::CompressionFlags(flags));
        }
        let mut payloads = Vec::new();
        let mut at = 8;
        while at < b.len() {
            let algorithm = le16(b, at)?;
            let flags = le16(b, at + 2)?;
            if at > 8 && flags != 0 {
                return Err(Error::CompressionFlags(flags));
            }
            let len = le32(b, at + 4)? as usize;
            let start = at + 8;
            let end = start.checked_add(len).ok_or(Error::Buffer)?;
            let data = b.get(start..end).ok_or(Error::Buffer)?.to_vec();
            let payload = ChainedPayload { algorithm, flags, data };
            if payload.data.len() < payload.min_len() {
                return Err(Error::Buffer);
            }
            payloads.push(payload);
            at = end;
        }
        Ok(Compressed::Chained { original_size, payloads })
    }

    /// The header's bytes, then the data.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        out.extend_from_slice(&protocol::COMPRESSION);
        match self {
            Compressed::Unchained { original_size, algorithm, offset, data } => {
                if *algorithm == 0 {
                    return Err(EncodeError::Chained);
                }
                if *offset as usize > data.len() {
                    return Err(EncodeError::Offset);
                }
                too_long(COMPRESSION_HEADER_LEN.saturating_add(data.len()))?;
                out.extend_from_slice(&original_size.to_le_bytes());
                out.extend_from_slice(&algorithm.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&offset.to_le_bytes());
                out.extend_from_slice(data);
            }
            Compressed::Chained { original_size, payloads } => {
                let Some(first) = payloads.first() else { return Err(EncodeError::Empty) };
                if first.flags != COMPRESSION_FLAG_CHAINED
                    || payloads[1..].iter().any(|p| p.flags != 0)
                    || payloads.iter().any(|p| p.data.len() < p.min_len())
                {
                    return Err(EncodeError::Chained);
                }
                out.extend_from_slice(&original_size.to_le_bytes());
                for p in payloads {
                    too_long(out.len().saturating_add(8).saturating_add(p.data.len()))?;
                    out.extend_from_slice(&p.algorithm.to_le_bytes());
                    out.extend_from_slice(&p.flags.to_le_bytes());
                    out.extend_from_slice(&(p.data.len() as u32).to_le_bytes());
                    out.extend_from_slice(&p.data);
                }
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Headers and chains

/// What a header names besides the session: a tree, in the sync form, or
/// an operation still in progress, in the async form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The sync form, the usual one.
    Sync {
        /// Reserved; some clients put a process ID here.
        process_id: u32,
        /// The tree (share connection) the message works on.
        tree_id: u32,
    },
    /// The async form, with [`flags::ASYNC_COMMAND`] set: an interim
    /// response, the final response after it, or a CANCEL of it.
    Async {
        /// The ID the server gave the operation.
        async_id: u64,
    },
}

impl Default for Target {
    fn default() -> Target {
        Target::Sync { process_id: 0, tree_id: 0 }
    }
}

/// The 64-byte SMB2 header, without the protocol ID, StructureSize and
/// NextCommand, which are fixed or worked out when written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// How many credits the message costs. Reserved in SMB 2.0.2.
    pub credit_charge: u16,
    /// In a response, the status. In a request, 0, or in SMB 3.x the
    /// ChannelSequence in its low 16 bits.
    pub status: u32,
    /// The command; see [`command`].
    pub command: u16,
    /// Credits asked for, in a request, or granted, in a response.
    pub credits: u16,
    /// See [`flags`]. [`flags::ASYNC_COMMAND`] must match `target`.
    pub flags: u32,
    /// Chosen by the client and copied into the response.
    pub message_id: u64,
    /// The tree, or the async operation.
    pub target: Target,
    /// The session the message works on.
    pub session_id: u64,
    /// The signature, or zeros when the message is not signed.
    pub signature: [u8; 16],
}

impl Header {
    /// A sync request header for `command` with `message_id`, asking for
    /// one credit, with everything else 0.
    pub fn new(command: u16, message_id: u64) -> Header {
        Header { command, message_id, credits: 1, ..Header::default() }
    }

    /// The header of a response to this request: the same command,
    /// message ID, session and target, with `status`, the response flag,
    /// the request's async and related flags, and the credits the request
    /// asked for, at least one. It is not signed.
    pub fn reply(&self, status: u32) -> Header {
        Header {
            credit_charge: self.credit_charge,
            status,
            command: self.command,
            credits: self.credits.max(1),
            flags: flags::SERVER_TO_REDIR | (self.flags & (flags::ASYNC_COMMAND | flags::RELATED_OPERATIONS)),
            message_id: self.message_id,
            target: self.target,
            session_id: self.session_id,
            signature: [0; 16],
        }
    }

    /// Whether this is a response's header.
    pub fn is_response(&self) -> bool {
        self.flags & flags::SERVER_TO_REDIR != 0
    }

    /// Reads a header from the start of `b`, and its NextCommand.
    pub fn parse(b: &[u8]) -> Result<(Header, u32), Error> {
        let id: [u8; 4] = arr(b, 0)?;
        if id != protocol::SMB2 {
            return Err(Error::Protocol(id));
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let size = le16(b, 4)?;
        if size != HEADER_LEN as u16 {
            return Err(Error::HeaderSize(size));
        }
        let flags = le32(b, 16)?;
        let target = if flags & flags::ASYNC_COMMAND != 0 {
            Target::Async { async_id: le64(b, 32)? }
        } else {
            Target::Sync { process_id: le32(b, 32)?, tree_id: le32(b, 36)? }
        };
        let header = Header {
            credit_charge: le16(b, 6)?,
            status: le32(b, 8)?,
            command: le16(b, 12)?,
            credits: le16(b, 14)?,
            flags,
            message_id: le64(b, 24)?,
            target,
            session_id: le64(b, 40)?,
            signature: arr(b, 48)?,
        };
        Ok((header, le32(b, 20)?))
    }

    /// The header's 64 bytes, with `next_command` as its NextCommand.
    pub fn to_bytes(&self, next_command: u32) -> Result<[u8; HEADER_LEN], EncodeError> {
        let is_async = self.flags & flags::ASYNC_COMMAND != 0;
        let mut out = [0u8; HEADER_LEN];
        match (self.target, is_async) {
            (Target::Async { async_id }, true) => out[32..40].copy_from_slice(&async_id.to_le_bytes()),
            (Target::Sync { process_id, tree_id }, false) => {
                out[32..36].copy_from_slice(&process_id.to_le_bytes());
                out[36..40].copy_from_slice(&tree_id.to_le_bytes());
            }
            _ => return Err(EncodeError::AsyncFlag),
        }
        out[0..4].copy_from_slice(&protocol::SMB2);
        out[4..6].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[6..8].copy_from_slice(&self.credit_charge.to_le_bytes());
        out[8..12].copy_from_slice(&self.status.to_le_bytes());
        out[12..14].copy_from_slice(&self.command.to_le_bytes());
        out[14..16].copy_from_slice(&self.credits.to_le_bytes());
        out[16..20].copy_from_slice(&self.flags.to_le_bytes());
        out[20..24].copy_from_slice(&next_command.to_le_bytes());
        out[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        out[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        out[48..64].copy_from_slice(&self.signature);
        Ok(out)
    }
}

/// One SMB2 message: its header and its body's bytes. Offsets inside a
/// body count from the start of the header, as on the wire. In a compound
/// chain, the body of each message but the last runs to the next header,
/// padding included.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The header.
    pub header: Header,
    /// The body's bytes.
    pub body: Vec<u8>,
}

impl Message {
    /// Reads the message's body as the request its header's command names.
    pub fn request(&self) -> Result<Request, Error> {
        Request::parse(self.header.command, &self.body)
    }

    /// Reads the message's body as the response its header's command and
    /// status name.
    pub fn response(&self) -> Result<Response, Error> {
        Response::parse(self.header.command, self.header.status, &self.body)
    }

    /// A request message: `header` with the body of `request`. The header's
    /// command must be the request's.
    pub fn from_request(header: Header, request: &Request) -> Result<Message, EncodeError> {
        if header.command != request.command() {
            return Err(EncodeError::Command(header.command));
        }
        Ok(Message { header, body: request.to_body()? })
    }

    /// The message that answers the request with header `request` with
    /// `response`, under `status`. See [`Header::reply`].
    pub fn reply_to(request: &Header, status: u32, response: &Response) -> Result<Message, EncodeError> {
        let header = request.reply(status);
        Ok(Message { body: response.to_body(header.command, status)?, header })
    }

    /// The message's bytes, alone: its NextCommand is 0.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        write_chain(std::slice::from_ref(self))
    }
}

/// Reads an SMB2 payload: one message, or a compound chain of them linked
/// by NextCommand. Each NextCommand must be a multiple of 8, at least 64,
/// and inside the payload. A payload longer than [`MAX_MESSAGE`] is
/// refused.
pub fn parse_chain(b: &[u8]) -> Result<Vec<Message>, Error> {
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut out = Vec::new();
    let mut rest = b;
    loop {
        if out.len() == MAX_CHAIN {
            return Err(Error::TooMany);
        }
        let (header, next) = Header::parse(rest)?;
        if next == 0 {
            out.push(Message { header, body: rest[HEADER_LEN..].to_vec() });
            return Ok(out);
        }
        let n = next as usize;
        if n < HEADER_LEN || !n.is_multiple_of(8) || n > rest.len() {
            return Err(Error::NextCommand(next));
        }
        out.push(Message { header, body: rest[HEADER_LEN..n].to_vec() });
        rest = &rest[n..];
    }
}

/// Writes one message or a compound chain. Each message but the last is
/// padded with zeros to a multiple of 8 bytes, and its NextCommand points
/// past the padding. A message read from a chain already ends on a multiple
/// of 8, so it gets no padding and reads back the same.
pub fn write_chain(messages: &[Message]) -> Result<Vec<u8>, EncodeError> {
    if messages.is_empty() {
        return Err(EncodeError::Empty);
    }
    if messages.len() > MAX_CHAIN {
        return Err(EncodeError::TooLong);
    }
    let mut out = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        let last = i + 1 == messages.len();
        let len = HEADER_LEN.checked_add(m.body.len()).ok_or(EncodeError::TooLong)?;
        let padded = if last { len } else { len.checked_next_multiple_of(8).ok_or(EncodeError::TooLong)? };
        too_long(out.len().saturating_add(padded))?;
        let next = if last { 0 } else { padded as u32 };
        out.extend_from_slice(&m.header.to_bytes(next)?);
        out.extend_from_slice(&m.body);
        out.resize(out.len() + (padded - len), 0);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Shared body parts

/// A file handle: two 64-bit halves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FileId {
    /// The half that survives a reconnect, for durable handles.
    pub persistent: u64,
    /// The half that lasts as long as the open.
    pub volatile: u64,
}

impl FileId {
    /// The FileId that, in a compound request, means "the file the request
    /// before this one opened".
    pub const RELATED: FileId = FileId { persistent: u64::MAX, volatile: u64::MAX };

    fn read(b: &[u8], at: usize) -> Result<FileId, Error> {
        Ok(FileId { persistent: le64(b, at)?, volatile: le64(b, at + 8)? })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.persistent.to_le_bytes());
        out.extend_from_slice(&self.volatile.to_le_bytes());
    }
}

/// A file's times, sizes and attributes, as CREATE and CLOSE responses carry
/// them. Times count 100-nanosecond intervals since 1601.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileInfo {
    /// When the file was created.
    pub creation_time: u64,
    /// When it was last read.
    pub last_access_time: u64,
    /// When it was last written.
    pub last_write_time: u64,
    /// When its data or metadata last changed.
    pub change_time: u64,
    /// The bytes it takes on disk.
    pub allocation_size: u64,
    /// Its length.
    pub end_of_file: u64,
    /// Its FILE_ATTRIBUTE_ bits.
    pub file_attributes: u32,
}

impl FileInfo {
    /// Reads the 52 bytes from `at`: four times, two sizes, attributes.
    fn read(b: &[u8], at: usize) -> Result<FileInfo, Error> {
        Ok(FileInfo {
            creation_time: le64(b, at)?,
            last_access_time: le64(b, at + 8)?,
            last_write_time: le64(b, at + 16)?,
            change_time: le64(b, at + 24)?,
            allocation_size: le64(b, at + 32)?,
            end_of_file: le64(b, at + 40)?,
            file_attributes: le32(b, at + 48)?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        for t in [
            self.creation_time,
            self.last_access_time,
            self.last_write_time,
            self.change_time,
            self.allocation_size,
            self.end_of_file,
        ] {
            out.extend_from_slice(&t.to_le_bytes());
        }
        out.extend_from_slice(&self.file_attributes.to_le_bytes());
    }
}

/// A negotiate context, SMB 3.1.1 only: its type (see
/// [`negotiate_context`]) and its data as bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegotiateContext {
    /// The context type.
    pub kind: u16,
    /// The data, at most 65535 bytes.
    pub data: Vec<u8>,
}

impl NegotiateContext {
    /// A preauthentication integrity context: hash algorithm IDs (see
    /// [`negotiate_context::SHA_512`]) and a salt. Lists too long for the
    /// context's 16-bit counts and length are an error.
    pub fn preauth_integrity(hashes: &[u16], salt: &[u8]) -> Result<NegotiateContext, EncodeError> {
        let mut data = Vec::new();
        put16(&mut data, fit16(hashes.len())?);
        put16(&mut data, fit16(salt.len())?);
        for h in hashes {
            put16(&mut data, *h);
        }
        data.extend_from_slice(salt);
        fit16(data.len())?;
        Ok(NegotiateContext { kind: negotiate_context::PREAUTH_INTEGRITY_CAPABILITIES, data })
    }

    /// The hash algorithm IDs and salt of a preauthentication integrity
    /// context, or `None` if it is another type or its counts do not fit
    /// its data.
    pub fn preauth_integrity_parts(&self) -> Option<(Vec<u16>, Vec<u8>)> {
        if self.kind != negotiate_context::PREAUTH_INTEGRITY_CAPABILITIES {
            return None;
        }
        let d = &self.data;
        let hashes = usize::from(le16(d, 0).ok()?);
        let salt = usize::from(le16(d, 2).ok()?);
        let list = (0..hashes).map(|i| le16(d, 4 + 2 * i).ok()).collect::<Option<Vec<u16>>>()?;
        let start = 4 + 2 * hashes;
        Some((list, d.get(start..start + salt)?.to_vec()))
    }

    /// A context that is a 16-bit count and a list of 16-bit IDs, as the
    /// encryption and signing capabilities are. A list too long for the
    /// context's 16-bit length is an error.
    pub fn algorithms(kind: u16, ids: &[u16]) -> Result<NegotiateContext, EncodeError> {
        let mut data = Vec::new();
        put16(&mut data, fit16(ids.len())?);
        for id in ids {
            put16(&mut data, *id);
        }
        fit16(data.len())?;
        Ok(NegotiateContext { kind, data })
    }

    /// The IDs of a context written by [`NegotiateContext::algorithms`], or
    /// `None` if its count does not fit its data.
    pub fn algorithm_list(&self) -> Option<Vec<u16>> {
        let n = usize::from(le16(&self.data, 0).ok()?);
        (0..n).map(|i| le16(&self.data, 2 + 2 * i).ok()).collect()
    }
}

/// A create context: a name (see [`create_context`]) and data, both bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateContext {
    /// The name, usually four ASCII letters.
    pub name: Vec<u8>,
    /// The data.
    pub data: Vec<u8>,
}

/// One byte range of a LOCK request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lock {
    /// Where the range starts.
    pub offset: u64,
    /// How long it is.
    pub length: u64,
    /// SHARED 1, EXCLUSIVE 2, UNLOCK 4, FAIL_IMMEDIATELY 0x10.
    pub flags: u32,
}

/// The string `s` as UTF-16 code units, as SMB2 carries names and paths.
pub fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// UTF-16 code units as a string, with unpaired surrogates replaced.
pub fn utf16_lossy(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

// ---------------------------------------------------------------------
// Request bodies

/// A NEGOTIATE request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegotiateRequest {
    /// See [`security_mode`].
    pub security_mode: u16,
    /// See [`capability`].
    pub capabilities: u32,
    /// The client's GUID.
    pub client_guid: [u8; 16],
    /// The dialects offered, at least one; see [`dialect`].
    pub dialects: Vec<u16>,
    /// Without SMB 3.1.1 among the dialects, the ClientStartTime field.
    /// With it, 0, since the field holds the contexts' offset and count.
    pub client_start_time: u64,
    /// Negotiate contexts, only with SMB 3.1.1 among the dialects.
    pub contexts: Vec<NegotiateContext>,
}

/// A SESSION_SETUP request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSetupRequest {
    /// 0x01 binds a new channel to an existing session.
    pub flags: u8,
    /// See [`security_mode`]; one byte here.
    pub security_mode: u8,
    /// See [`capability`].
    pub capabilities: u32,
    /// Reserved.
    pub channel: u32,
    /// A session the client had before, so the server can drop it.
    pub previous_session_id: u64,
    /// The authentication token, usually SPNEGO.
    pub security_buffer: Vec<u8>,
}

/// A TREE_CONNECT request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreeConnectRequest {
    /// SMB 3.1.1 flags: CLUSTER_RECONNECT 1, REDIRECT_TO_OWNER 2,
    /// EXTENSION_PRESENT 4. With EXTENSION_PRESENT, the Buffer starts with
    /// the request extension of MS-SMB2 section 2.2.9.1: `path` is read
    /// from the offset and length as given, after the extension's 16-byte
    /// header, and the extension's tree connect contexts are not read. The
    /// writer then writes an extension with no contexts and the path at
    /// its PathName.
    pub flags: u16,
    /// The share's path, such as `\\server\share`, in UTF-16.
    pub path: Vec<u16>,
}

/// A CREATE request: open or create a file, directory or pipe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateRequest {
    /// The oplock asked for: none 0, II 1, exclusive 8, batch 9, lease 0xff.
    pub oplock_level: u8,
    /// Anonymous 0, identification 1, impersonation 2, delegate 3.
    pub impersonation_level: u32,
    /// The access mask asked for.
    pub desired_access: u32,
    /// FILE_ATTRIBUTE_ bits for a new file.
    pub file_attributes: u32,
    /// FILE_SHARE_ bits: read 1, write 2, delete 4.
    pub share_access: u32,
    /// SUPERSEDE 0, OPEN 1, CREATE 2, OPEN_IF 3, OVERWRITE 4,
    /// OVERWRITE_IF 5.
    pub create_disposition: u32,
    /// FILE_ create option bits.
    pub create_options: u32,
    /// The path relative to the share, in UTF-16. Empty means the share's
    /// root.
    pub name: Vec<u16>,
    /// Create contexts.
    pub contexts: Vec<CreateContext>,
}

/// A READ request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadRequest {
    /// Where the client wants the data in the response, from the header.
    pub padding: u8,
    /// SMB 3.x read flags.
    pub flags: u8,
    /// How many bytes to read.
    pub length: u32,
    /// Where to read from.
    pub offset: u64,
    /// The file.
    pub file_id: FileId,
    /// The fewest bytes that count as success.
    pub minimum_count: u32,
    /// The RDMA channel, or 0.
    pub channel: u32,
    /// How many more bytes the client plans to read.
    pub remaining_bytes: u32,
    /// RDMA channel information, as bytes. With channel 0, NONE, the
    /// reader ignores ReadChannelInfoOffset and ReadChannelInfoLength, as
    /// MS-SMB2 section 2.2.19 says a server must, so this is empty, and
    /// the writer refuses anything else.
    pub channel_info: Vec<u8>,
}

/// A WRITE request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteRequest {
    /// Where to write.
    pub offset: u64,
    /// The file.
    pub file_id: FileId,
    /// The RDMA channel, or 0.
    pub channel: u32,
    /// How many more bytes the client plans to write.
    pub remaining_bytes: u32,
    /// WRITE_THROUGH 1, WRITE_UNBUFFERED 2.
    pub flags: u32,
    /// The bytes to write.
    pub data: Vec<u8>,
    /// RDMA channel information, as bytes. With channel 0, NONE, the
    /// reader ignores WriteChannelInfoOffset and WriteChannelInfoLength,
    /// as MS-SMB2 section 2.2.21 says a server must, so this is empty, and
    /// the writer refuses anything else.
    pub channel_info: Vec<u8>,
}

/// A LOCK request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LockRequest {
    /// The lock sequence number and index, as one field.
    pub lock_sequence: u32,
    /// The file.
    pub file_id: FileId,
    /// The ranges, at least one.
    pub locks: Vec<Lock>,
}

/// An IOCTL request: a file system or device control code with input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IoctlRequest {
    /// The FSCTL or IOCTL code.
    pub ctl_code: u32,
    /// The file, or all ones for codes that need none.
    pub file_id: FileId,
    /// The input buffer.
    pub input: Vec<u8>,
    /// The most input bytes the response may echo.
    pub max_input_response: u32,
    /// Always empty: MS-SMB2 section 2.2.31 says a client must set
    /// OutputCount to 0. Readers refuse a nonzero OutputCount and writers
    /// refuse output bytes.
    pub output: Vec<u8>,
    /// The most output bytes the response may carry.
    pub max_output_response: u32,
    /// 1 when `ctl_code` is an FSCTL.
    pub flags: u32,
}

/// A QUERY_DIRECTORY request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryDirectoryRequest {
    /// The FileInformationClass of the entries asked for.
    pub file_information_class: u8,
    /// RESTART_SCANS 1, RETURN_SINGLE_ENTRY 2, INDEX_SPECIFIED 4, REOPEN 0x10.
    pub flags: u8,
    /// Where to resume, with INDEX_SPECIFIED.
    pub file_index: u32,
    /// The directory.
    pub file_id: FileId,
    /// The search pattern, such as `*`, in UTF-16.
    pub pattern: Vec<u16>,
    /// The most bytes of entries the response may carry.
    pub output_buffer_length: u32,
}

/// A CHANGE_NOTIFY request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeNotifyRequest {
    /// WATCH_TREE 1.
    pub flags: u16,
    /// The most bytes of changes the response may carry.
    pub output_buffer_length: u32,
    /// The directory.
    pub file_id: FileId,
    /// FILE_NOTIFY_CHANGE_ bits.
    pub completion_filter: u32,
}

/// A QUERY_INFO request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryInfoRequest {
    /// FILE 1, FILESYSTEM 2, SECURITY 3, QUOTA 4.
    pub info_type: u8,
    /// The information class within the type.
    pub file_info_class: u8,
    /// The most bytes the response may carry.
    pub output_buffer_length: u32,
    /// Input, for quota and extended attribute queries.
    pub input: Vec<u8>,
    /// Which security information, for SECURITY.
    pub additional_information: u32,
    /// Flags for extended attribute queries.
    pub flags: u32,
    /// The file.
    pub file_id: FileId,
}

/// A SET_INFO request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetInfoRequest {
    /// FILE 1, FILESYSTEM 2, SECURITY 3, QUOTA 4.
    pub info_type: u8,
    /// The information class within the type.
    pub file_info_class: u8,
    /// Which security information, for SECURITY.
    pub additional_information: u32,
    /// The file.
    pub file_id: FileId,
    /// The information to set, as bytes.
    pub data: Vec<u8>,
}

/// A request body, read by its command. Reserved fields are not kept, and
/// are written as zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Offer dialects and capabilities.
    Negotiate(NegotiateRequest),
    /// Authenticate, one security token at a time.
    SessionSetup(SessionSetupRequest),
    /// End the session.
    Logoff,
    /// Connect to a share.
    TreeConnect(TreeConnectRequest),
    /// Disconnect from the tree in the header.
    TreeDisconnect,
    /// Open or create a file.
    Create(CreateRequest),
    /// Close a file.
    Close {
        /// 1 asks for the file's attributes back.
        flags: u16,
        /// The file.
        file_id: FileId,
    },
    /// Flush a file's data to disk.
    Flush {
        /// The file.
        file_id: FileId,
    },
    /// Read from a file.
    Read(ReadRequest),
    /// Write to a file.
    Write(WriteRequest),
    /// Lock or unlock byte ranges.
    Lock(LockRequest),
    /// A file system or device control.
    Ioctl(IoctlRequest),
    /// Cancel the request with the header's message ID or async ID.
    Cancel,
    /// Check the connection is alive.
    Echo,
    /// List a directory.
    QueryDirectory(QueryDirectoryRequest),
    /// Watch a directory for changes.
    ChangeNotify(ChangeNotifyRequest),
    /// Read a file's or volume's information.
    QueryInfo(QueryInfoRequest),
    /// Change a file's or volume's information.
    SetInfo(SetInfoRequest),
    /// A command this module does not read, such as OPLOCK_BREAK, with its
    /// body unread.
    Other {
        /// The command code.
        command: u16,
        /// The body's bytes.
        body: Vec<u8>,
    },
}

impl Request {
    /// The command code this request is sent with.
    pub fn command(&self) -> u16 {
        match self {
            Request::Negotiate(_) => command::NEGOTIATE,
            Request::SessionSetup(_) => command::SESSION_SETUP,
            Request::Logoff => command::LOGOFF,
            Request::TreeConnect(_) => command::TREE_CONNECT,
            Request::TreeDisconnect => command::TREE_DISCONNECT,
            Request::Create(_) => command::CREATE,
            Request::Close { .. } => command::CLOSE,
            Request::Flush { .. } => command::FLUSH,
            Request::Read(_) => command::READ,
            Request::Write(_) => command::WRITE,
            Request::Lock(_) => command::LOCK,
            Request::Ioctl(_) => command::IOCTL,
            Request::Cancel => command::CANCEL,
            Request::Echo => command::ECHO,
            Request::QueryDirectory(_) => command::QUERY_DIRECTORY,
            Request::ChangeNotify(_) => command::CHANGE_NOTIFY,
            Request::QueryInfo(_) => command::QUERY_INFO,
            Request::SetInfo(_) => command::SET_INFO,
            Request::Other { command, .. } => *command,
        }
    }

    /// Reads the body of a request for `command`. Bytes past what the body
    /// uses, such as padding before the next message of a chain, are
    /// ignored.
    ///
    /// Each buffer that is not empty must start after the body's fixed
    /// part, and the buffers of one body must not overlap. Negotiate and
    /// create contexts must be 8-byte aligned and come after the dialect
    /// list or the file name. So the writer, which puts buffers right after
    /// the fixed part, never writes a body longer than the one it read,
    /// with one exception: a create context may put its data before its
    /// name, and the writer puts the name first, so a CREATE whose last
    /// create context came that way can write back up to 7 bytes longer.
    /// A body longer than [`MAX_MESSAGE`] is refused.
    pub fn parse(command: u16, b: &[u8]) -> Result<Request, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        Ok(match command {
            command::NEGOTIATE => {
                fixed(b, 36)?;
                let count = usize::from(le16(b, 2)?);
                if count == 0 {
                    return Err(Error::NoDialects);
                }
                let dialects = (0..count).map(|i| le16(b, 36 + 2 * i)).collect::<Result<Vec<u16>, Error>>()?;
                let (client_start_time, contexts) = if dialects.contains(&dialect::SMB_3_1_1) {
                    // The dialect list, as a buffer, from byte 36 of the body.
                    let list = (HEADER_LEN as u32 + 36, 2 * count as u32);
                    (0, negotiate_contexts(b, le32(b, 28)?, le16(b, 32)?, list)?)
                } else {
                    (le64(b, 28)?, Vec::new())
                };
                Request::Negotiate(NegotiateRequest {
                    security_mode: le16(b, 4)?,
                    capabilities: le32(b, 8)?,
                    client_guid: arr(b, 12)?,
                    dialects,
                    client_start_time,
                    contexts,
                })
            }
            command::SESSION_SETUP => {
                fixed(b, 25)?;
                Request::SessionSetup(SessionSetupRequest {
                    flags: b[2],
                    security_mode: b[3],
                    capabilities: le32(b, 4)?,
                    channel: le32(b, 8)?,
                    previous_session_id: le64(b, 16)?,
                    security_buffer: buffer(b, le16(b, 12)?.into(), le16(b, 14)?.into())?.to_vec(),
                })
            }
            command::LOGOFF => {
                fixed(b, 4)?;
                Request::Logoff
            }
            command::TREE_CONNECT => {
                fixed(b, 9)?;
                let flags = le16(b, 2)?;
                let path = (u32::from(le16(b, 4)?), u32::from(le16(b, 6)?));
                if flags & TREE_CONNECT_EXTENSION_PRESENT != 0 {
                    // The extension's 16-byte header comes first, at 72.
                    if b.len() < 8 + TREE_CONNECT_EXTENSION_LEN
                        || (path.1 != 0 && path.0 < (HEADER_LEN + 8 + TREE_CONNECT_EXTENSION_LEN) as u32)
                    {
                        return Err(Error::Buffer);
                    }
                }
                Request::TreeConnect(TreeConnectRequest { flags, path: string(buffer(b, path.0, path.1)?)? })
            }
            command::TREE_DISCONNECT => {
                fixed(b, 4)?;
                Request::TreeDisconnect
            }
            command::CREATE => {
                fixed(b, 57)?;
                // 2.2.13: the request's Buffer is at least one byte.
                if b.len() < 57 {
                    return Err(Error::Truncated);
                }
                let name = (u32::from(le16(b, 44)?), u32::from(le16(b, 46)?));
                if name.1 != 0 && !name.0.is_multiple_of(8) {
                    return Err(Error::Align(name.0));
                }
                let region = (le32(b, 48)?, le32(b, 52)?);
                let name_bytes = buffer(b, name.0, name.1)?;
                let region_bytes = buffer(b, region.0, region.1)?;
                if region.1 != 0 {
                    contexts_after(region.0, name)?;
                }
                Request::Create(CreateRequest {
                    oplock_level: b[3],
                    impersonation_level: le32(b, 4)?,
                    desired_access: le32(b, 24)?,
                    file_attributes: le32(b, 28)?,
                    share_access: le32(b, 32)?,
                    create_disposition: le32(b, 36)?,
                    create_options: le32(b, 40)?,
                    name: string(name_bytes)?,
                    contexts: create_contexts(region_bytes)?,
                })
            }
            command::CLOSE => {
                fixed(b, 24)?;
                Request::Close { flags: le16(b, 2)?, file_id: FileId::read(b, 8)? }
            }
            command::FLUSH => {
                fixed(b, 24)?;
                Request::Flush { file_id: FileId::read(b, 8)? }
            }
            command::READ => {
                fixed(b, 49)?;
                let channel = le32(b, 36)?;
                // With channel NONE the server ignores the channel info.
                let channel_info = if channel == 0 {
                    Vec::new()
                } else {
                    buffer(b, le16(b, 44)?.into(), le16(b, 46)?.into())?.to_vec()
                };
                Request::Read(ReadRequest {
                    padding: b[2],
                    flags: b[3],
                    length: le32(b, 4)?,
                    offset: le64(b, 8)?,
                    file_id: FileId::read(b, 16)?,
                    minimum_count: le32(b, 32)?,
                    channel,
                    remaining_bytes: le32(b, 40)?,
                    channel_info,
                })
            }
            command::WRITE => {
                fixed(b, 49)?;
                let data = (u32::from(le16(b, 2)?), le32(b, 4)?);
                let channel = le32(b, 32)?;
                // With channel NONE the server ignores the channel info.
                let info = if channel == 0 { (0, 0) } else { (u32::from(le16(b, 40)?), u32::from(le16(b, 42)?)) };
                let (data_bytes, info_bytes) = (buffer(b, data.0, data.1)?, buffer(b, info.0, info.1)?);
                apart(data, info)?;
                Request::Write(WriteRequest {
                    offset: le64(b, 8)?,
                    file_id: FileId::read(b, 16)?,
                    channel,
                    remaining_bytes: le32(b, 36)?,
                    flags: le32(b, 44)?,
                    data: data_bytes.to_vec(),
                    channel_info: info_bytes.to_vec(),
                })
            }
            command::LOCK => {
                fixed(b, 48)?;
                let count = usize::from(le16(b, 2)?);
                if count == 0 {
                    return Err(Error::NoLocks);
                }
                // Each lock is 24 bytes, its last 4 reserved.
                if b.len() < 24 + 24 * count {
                    return Err(Error::Truncated);
                }
                let locks = (0..count)
                    .map(|i| {
                        let at = 24 + 24 * i;
                        Ok(Lock { offset: le64(b, at)?, length: le64(b, at + 8)?, flags: le32(b, at + 16)? })
                    })
                    .collect::<Result<Vec<Lock>, Error>>()?;
                Request::Lock(LockRequest { lock_sequence: le32(b, 4)?, file_id: FileId::read(b, 8)?, locks })
            }
            command::IOCTL => {
                fixed(b, 57)?;
                // 2.2.31: the client MUST set OutputCount to 0.
                if le32(b, 40)? != 0 {
                    return Err(Error::Buffer);
                }
                let input = buffer(b, le32(b, 24)?, le32(b, 28)?)?;
                Request::Ioctl(IoctlRequest {
                    ctl_code: le32(b, 4)?,
                    file_id: FileId::read(b, 8)?,
                    input: input.to_vec(),
                    max_input_response: le32(b, 32)?,
                    output: Vec::new(),
                    max_output_response: le32(b, 44)?,
                    flags: le32(b, 48)?,
                })
            }
            command::CANCEL => {
                fixed(b, 4)?;
                Request::Cancel
            }
            command::ECHO => {
                fixed(b, 4)?;
                Request::Echo
            }
            command::QUERY_DIRECTORY => {
                fixed(b, 33)?;
                Request::QueryDirectory(QueryDirectoryRequest {
                    file_information_class: b[2],
                    flags: b[3],
                    file_index: le32(b, 4)?,
                    file_id: FileId::read(b, 8)?,
                    pattern: string(buffer(b, le16(b, 24)?.into(), le16(b, 26)?.into())?)?,
                    output_buffer_length: le32(b, 28)?,
                })
            }
            command::CHANGE_NOTIFY => {
                fixed(b, 32)?;
                Request::ChangeNotify(ChangeNotifyRequest {
                    flags: le16(b, 2)?,
                    output_buffer_length: le32(b, 4)?,
                    file_id: FileId::read(b, 8)?,
                    completion_filter: le32(b, 24)?,
                })
            }
            command::QUERY_INFO => {
                fixed(b, 41)?;
                Request::QueryInfo(QueryInfoRequest {
                    info_type: b[2],
                    file_info_class: b[3],
                    output_buffer_length: le32(b, 4)?,
                    input: buffer(b, le16(b, 8)?.into(), le32(b, 12)?)?.to_vec(),
                    additional_information: le32(b, 16)?,
                    flags: le32(b, 20)?,
                    file_id: FileId::read(b, 24)?,
                })
            }
            command::SET_INFO => {
                fixed(b, 33)?;
                Request::SetInfo(SetInfoRequest {
                    info_type: b[2],
                    file_info_class: b[3],
                    data: buffer(b, le16(b, 8)?.into(), le32(b, 4)?)?.to_vec(),
                    additional_information: le32(b, 12)?,
                    file_id: FileId::read(b, 16)?,
                })
            }
            command => Request::Other { command, body: b.to_vec() },
        })
    }

    /// The request's body bytes, with buffers right after the fixed part.
    /// A WRITE puts its data first, unless that would push the channel
    /// info's 16-bit offset past 65535. An `Other` request with a command this module reads as a typed one
    /// is an error, as is a buffer too long for its length field.
    pub fn to_body(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Vec::new();
        match self {
            Request::Negotiate(r) => {
                if r.dialects.is_empty() {
                    return Err(EncodeError::NoDialects);
                }
                let has_311 = r.dialects.contains(&dialect::SMB_3_1_1);
                if (!has_311 && !r.contexts.is_empty()) || (has_311 && r.client_start_time != 0) {
                    return Err(EncodeError::Dialect);
                }
                put16(&mut w, 36);
                put16(&mut w, fit16(r.dialects.len())?);
                put16(&mut w, r.security_mode);
                put16(&mut w, 0);
                put32(&mut w, r.capabilities);
                w.extend_from_slice(&r.client_guid);
                put64(&mut w, r.client_start_time);
                for d in &r.dialects {
                    put16(&mut w, *d);
                }
                if !r.contexts.is_empty() {
                    pad8(&mut w);
                    let at = fit32(at(&w))?;
                    let count = fit16(r.contexts.len())?;
                    write_negotiate_contexts(&mut w, &r.contexts)?;
                    w[28..32].copy_from_slice(&at.to_le_bytes());
                    w[32..34].copy_from_slice(&count.to_le_bytes());
                }
            }
            Request::SessionSetup(r) => {
                put16(&mut w, 25);
                w.push(r.flags);
                w.push(r.security_mode);
                put32(&mut w, r.capabilities);
                put32(&mut w, r.channel);
                put16(&mut w, 88);
                put16(&mut w, fit16(r.security_buffer.len())?);
                put64(&mut w, r.previous_session_id);
                w.extend_from_slice(&r.security_buffer);
            }
            Request::Logoff | Request::TreeDisconnect | Request::Cancel | Request::Echo => put32(&mut w, 4),
            Request::TreeConnect(r) => {
                let path = string16(&r.path)?;
                let extended = r.flags & TREE_CONNECT_EXTENSION_PRESENT != 0;
                put16(&mut w, 9);
                put16(&mut w, r.flags);
                put16(&mut w, if extended { (HEADER_LEN + 8 + TREE_CONNECT_EXTENSION_LEN) as u16 } else { 72 });
                put16(&mut w, fit16(path.len())?);
                if extended {
                    // An extension with no tree connect contexts: offset
                    // 0, count 0 and the reserved bytes, all zeros.
                    w.resize(w.len() + TREE_CONNECT_EXTENSION_LEN, 0);
                }
                w.extend_from_slice(&path);
            }
            Request::Create(r) => {
                let name = string16(&r.name)?;
                put16(&mut w, 57);
                w.push(0);
                w.push(r.oplock_level);
                put32(&mut w, r.impersonation_level);
                put64(&mut w, 0);
                put64(&mut w, 0);
                for v in [r.desired_access, r.file_attributes, r.share_access, r.create_disposition, r.create_options] {
                    put32(&mut w, v);
                }
                put16(&mut w, 120);
                put16(&mut w, fit16(name.len())?);
                put64(&mut w, 0);
                w.extend_from_slice(&name);
                write_create_contexts(&mut w, &r.contexts, 48)?;
            }
            Request::Close { flags, file_id } => {
                put16(&mut w, 24);
                put16(&mut w, *flags);
                put32(&mut w, 0);
                file_id.write(&mut w);
            }
            Request::Flush { file_id } => {
                put16(&mut w, 24);
                put16(&mut w, 0);
                put32(&mut w, 0);
                file_id.write(&mut w);
            }
            Request::Read(r) => {
                put16(&mut w, 49);
                w.push(r.padding);
                w.push(r.flags);
                put32(&mut w, r.length);
                put64(&mut w, r.offset);
                r.file_id.write(&mut w);
                put32(&mut w, r.minimum_count);
                put32(&mut w, r.channel);
                put32(&mut w, r.remaining_bytes);
                let info = !r.channel_info.is_empty();
                if info && r.channel == 0 {
                    return Err(EncodeError::Channel);
                }
                put16(&mut w, if info { 112 } else { 0 });
                put16(&mut w, fit16(r.channel_info.len())?);
                w.extend_from_slice(&r.channel_info);
            }
            Request::Write(r) => {
                if r.channel == 0 && !r.channel_info.is_empty() {
                    return Err(EncodeError::Channel);
                }
                // Both offsets are 16 bits. The data goes first unless that
                // pushes the channel info's offset past 65535.
                let info_len = fit16(r.channel_info.len())?;
                let data_first = r.channel_info.is_empty() || fit16(112 + r.data.len()).is_ok();
                let (data_at, info_at) = if data_first {
                    let info_at = if r.channel_info.is_empty() { 0 } else { fit16(112 + r.data.len())? };
                    (112, info_at)
                } else {
                    (fit16(112 + r.channel_info.len())?, 112)
                };
                put16(&mut w, 49);
                put16(&mut w, data_at);
                put32(&mut w, fit32(r.data.len())?);
                put64(&mut w, r.offset);
                r.file_id.write(&mut w);
                put32(&mut w, r.channel);
                put32(&mut w, r.remaining_bytes);
                put16(&mut w, info_at);
                put16(&mut w, info_len);
                put32(&mut w, r.flags);
                if data_first {
                    w.extend_from_slice(&r.data);
                    w.extend_from_slice(&r.channel_info);
                } else {
                    w.extend_from_slice(&r.channel_info);
                    w.extend_from_slice(&r.data);
                }
            }
            Request::Lock(r) => {
                if r.locks.is_empty() {
                    return Err(EncodeError::NoLocks);
                }
                put16(&mut w, 48);
                put16(&mut w, fit16(r.locks.len())?);
                put32(&mut w, r.lock_sequence);
                r.file_id.write(&mut w);
                for l in &r.locks {
                    put64(&mut w, l.offset);
                    put64(&mut w, l.length);
                    put32(&mut w, l.flags);
                    put32(&mut w, 0);
                }
            }
            Request::Ioctl(r) => {
                if !r.output.is_empty() {
                    return Err(EncodeError::IoctlOutput);
                }
                put16(&mut w, 57);
                put16(&mut w, 0);
                put32(&mut w, r.ctl_code);
                r.file_id.write(&mut w);
                put32(&mut w, 120);
                put32(&mut w, fit32(r.input.len())?);
                put32(&mut w, r.max_input_response);
                put32(&mut w, 0);
                put32(&mut w, 0);
                put32(&mut w, r.max_output_response);
                put32(&mut w, r.flags);
                put32(&mut w, 0);
                w.extend_from_slice(&r.input);
            }
            Request::QueryDirectory(r) => {
                let pattern = string16(&r.pattern)?;
                put16(&mut w, 33);
                w.push(r.file_information_class);
                w.push(r.flags);
                put32(&mut w, r.file_index);
                r.file_id.write(&mut w);
                put16(&mut w, 96);
                put16(&mut w, fit16(pattern.len())?);
                put32(&mut w, r.output_buffer_length);
                w.extend_from_slice(&pattern);
            }
            Request::ChangeNotify(r) => {
                put16(&mut w, 32);
                put16(&mut w, r.flags);
                put32(&mut w, r.output_buffer_length);
                r.file_id.write(&mut w);
                put32(&mut w, r.completion_filter);
                put32(&mut w, 0);
            }
            Request::QueryInfo(r) => {
                put16(&mut w, 41);
                w.push(r.info_type);
                w.push(r.file_info_class);
                put32(&mut w, r.output_buffer_length);
                put16(&mut w, 104);
                put16(&mut w, 0);
                put32(&mut w, fit32(r.input.len())?);
                put32(&mut w, r.additional_information);
                put32(&mut w, r.flags);
                r.file_id.write(&mut w);
                w.extend_from_slice(&r.input);
            }
            Request::SetInfo(r) => {
                put16(&mut w, 33);
                w.push(r.info_type);
                w.push(r.file_info_class);
                put32(&mut w, fit32(r.data.len())?);
                put16(&mut w, 96);
                put16(&mut w, 0);
                put32(&mut w, r.additional_information);
                r.file_id.write(&mut w);
                w.extend_from_slice(&r.data);
            }
            Request::Other { command, body } => {
                if known(*command) {
                    return Err(EncodeError::Command(*command));
                }
                too_long(body.len())?;
                return Ok(body.clone());
            }
        }
        finish(&mut w);
        Ok(w)
    }
}

// ---------------------------------------------------------------------
// Response bodies

/// A NEGOTIATE response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegotiateResponse {
    /// See [`security_mode`].
    pub security_mode: u16,
    /// The dialect chosen; see [`dialect`].
    pub dialect: u16,
    /// The server's GUID.
    pub server_guid: [u8; 16],
    /// See [`capability`].
    pub capabilities: u32,
    /// The largest IOCTL, QUERY_INFO or SET_INFO buffer the server takes.
    pub max_transact_size: u32,
    /// The largest READ the server answers.
    pub max_read_size: u32,
    /// The largest WRITE the server takes.
    pub max_write_size: u32,
    /// The server's clock.
    pub system_time: u64,
    /// When the server started, or 0.
    pub server_start_time: u64,
    /// The first authentication token, usually SPNEGO with the mechanisms
    /// the server offers.
    pub security_buffer: Vec<u8>,
    /// Negotiate contexts, only when `dialect` is SMB 3.1.1. Then, as
    /// MS-SMB2 section 3.2.5.2 has a client check, exactly one
    /// preauthentication integrity context, and at most one each of the
    /// encryption, compression, RDMA transform, signing and transport
    /// contexts.
    pub contexts: Vec<NegotiateContext>,
}

/// A CREATE response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateResponse {
    /// The oplock granted.
    pub oplock_level: u8,
    /// REPARSEPOINT 1, in SMB 3.x.
    pub flags: u8,
    /// SUPERSEDED 0, OPENED 1, CREATED 2, OVERWRITTEN 3.
    pub create_action: u32,
    /// The file's times, sizes and attributes.
    pub info: FileInfo,
    /// The handle.
    pub file_id: FileId,
    /// Create contexts in reply to the request's.
    pub contexts: Vec<CreateContext>,
}

/// A TREE_CONNECT response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreeConnectResponse {
    /// See [`share_type`].
    pub share_type: u8,
    /// SHI1005 share flags.
    pub share_flags: u32,
    /// DFS 0x8, CONTINUOUS_AVAILABILITY 0x10, and others.
    pub capabilities: u32,
    /// The access the user has to the share.
    pub maximal_access: u32,
}

/// An IOCTL response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IoctlResponse {
    /// The code, as in the request.
    pub ctl_code: u32,
    /// The file, as in the request.
    pub file_id: FileId,
    /// Input echoed back, usually empty.
    pub input: Vec<u8>,
    /// The output.
    pub output: Vec<u8>,
    /// Reserved.
    pub flags: u32,
}

/// An error response, sent with a failing status, and as the interim
/// response with [`status::PENDING`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrorResponse {
    /// In SMB 3.1.1, how many error contexts `data` holds.
    pub context_count: u8,
    /// The error data, as bytes: error contexts, or symbolic link or
    /// buffer size details, or nothing. With a nonzero `context_count`,
    /// it starts with that many error contexts (MS-SMB2 section 2.2.2.1),
    /// each an ErrorDataLength, an ErrorId and that many bytes, each
    /// starting 8-byte aligned. Readers and writers check that they fit;
    /// their contents are not read.
    pub data: Vec<u8>,
}

/// A response body, read by its command and status. Reserved fields are
/// not kept, and are written as zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// NEGOTIATE: the dialect chosen and the server's limits.
    Negotiate(NegotiateResponse),
    /// SESSION_SETUP.
    SessionSetup {
        /// IS_GUEST 1, IS_NULL 2, ENCRYPT_DATA 4.
        session_flags: u16,
        /// The server's next authentication token.
        security_buffer: Vec<u8>,
    },
    /// LOGOFF.
    Logoff,
    /// TREE_CONNECT: the share's type and the user's access.
    TreeConnect(TreeConnectResponse),
    /// TREE_DISCONNECT.
    TreeDisconnect,
    /// CREATE: the handle and the file's details.
    Create(CreateResponse),
    /// CLOSE.
    Close {
        /// 1 when `info` holds the file's attributes when it was closed.
        flags: u16,
        /// The file's times, sizes and attributes, or zeros.
        info: FileInfo,
    },
    /// FLUSH.
    Flush,
    /// READ.
    Read {
        /// The bytes read.
        data: Vec<u8>,
        /// How many more bytes an RDMA read has left.
        data_remaining: u32,
        /// SMB 3.1.1 flags; 0 otherwise.
        flags: u32,
    },
    /// WRITE.
    Write {
        /// How many bytes were written.
        count: u32,
        /// Reserved; 0.
        remaining: u32,
    },
    /// LOCK.
    Lock,
    /// IOCTL: the output of the control.
    Ioctl(IoctlResponse),
    /// ECHO.
    Echo,
    /// QUERY_DIRECTORY.
    QueryDirectory {
        /// The directory entries, as bytes.
        data: Vec<u8>,
    },
    /// CHANGE_NOTIFY.
    ChangeNotify {
        /// The FILE_NOTIFY_INFORMATION entries, as bytes.
        data: Vec<u8>,
    },
    /// QUERY_INFO.
    QueryInfo {
        /// The information, as bytes.
        data: Vec<u8>,
    },
    /// SET_INFO.
    SetInfo,
    /// The error body, for any command: see [`Response::parse`] for when a
    /// body is one.
    Error(ErrorResponse),
    /// A command this module does not read, with its body unread.
    Other {
        /// The body's bytes.
        body: Vec<u8>,
    },
}

impl Response {
    /// Reads the body of a response to `command` sent with `status`.
    ///
    /// Whether the body is an [`ErrorResponse`] depends on both, following
    /// MS-SMB2 section 3.3.4.4. With status 0 it never is. For a command
    /// this module reads, any other status is a failure and gets an error
    /// body, except for the ones that section lists. Those are
    /// [`status::MORE_PROCESSING_REQUIRED`] for SESSION_SETUP,
    /// [`status::BUFFER_OVERFLOW`] for QUERY_INFO and
    /// [`status::NOTIFY_ENUM_DIR`] for CHANGE_NOTIFY, which always get the
    /// command's own body, and [`status::BUFFER_OVERFLOW`] for READ and
    /// IOCTL and [`status::INVALID_PARAMETER`] for IOCTL (a server-side
    /// copy), which get it when its StructureSize is the command's own:
    /// these statuses also come as plain failures. For a command this
    /// module does not read, the body is an error body when its
    /// StructureSize is 9.
    ///
    /// Buffers follow the same rules as in [`Request::parse`]. A body
    /// longer than [`MAX_MESSAGE`] is refused.
    pub fn parse(command: u16, status: u32, b: &[u8]) -> Result<Response, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        if error_body(command, status, le16(b, 0).ok()) {
            fixed(b, 9)?;
            let n = le32(b, 4)? as usize;
            let data = b.get(8..8usize.checked_add(n).ok_or(Error::Buffer)?).ok_or(Error::Buffer)?;
            if !error_contexts_fit(b[2], data) {
                return Err(Error::Buffer);
            }
            return Ok(Response::Error(ErrorResponse { context_count: b[2], data: data.to_vec() }));
        }
        Ok(match command {
            command::NEGOTIATE => {
                fixed(b, 65)?;
                let dialect = le16(b, 4)?;
                let security = (u32::from(le16(b, 56)?), u32::from(le16(b, 58)?));
                let security_buffer = buffer(b, security.0, security.1)?.to_vec();
                let contexts = if dialect == dialect::SMB_3_1_1 {
                    let contexts = negotiate_contexts(b, le32(b, 60)?, le16(b, 6)?, security)?;
                    if !response_contexts_ok(&contexts) {
                        return Err(Error::NegotiateContexts);
                    }
                    contexts
                } else {
                    Vec::new()
                };
                Response::Negotiate(NegotiateResponse {
                    security_mode: le16(b, 2)?,
                    dialect,
                    server_guid: arr(b, 8)?,
                    capabilities: le32(b, 24)?,
                    max_transact_size: le32(b, 28)?,
                    max_read_size: le32(b, 32)?,
                    max_write_size: le32(b, 36)?,
                    system_time: le64(b, 40)?,
                    server_start_time: le64(b, 48)?,
                    security_buffer,
                    contexts,
                })
            }
            command::SESSION_SETUP => {
                fixed(b, 9)?;
                Response::SessionSetup {
                    session_flags: le16(b, 2)?,
                    security_buffer: buffer(b, le16(b, 4)?.into(), le16(b, 6)?.into())?.to_vec(),
                }
            }
            command::LOGOFF => fixed(b, 4).map(|_| Response::Logoff)?,
            command::TREE_CONNECT => {
                fixed(b, 16)?;
                Response::TreeConnect(TreeConnectResponse {
                    share_type: b[2],
                    share_flags: le32(b, 4)?,
                    capabilities: le32(b, 8)?,
                    maximal_access: le32(b, 12)?,
                })
            }
            command::TREE_DISCONNECT => fixed(b, 4).map(|_| Response::TreeDisconnect)?,
            command::CREATE => {
                fixed(b, 89)?;
                // FileInfo's layout here: four times and two sizes at 8, then
                // attributes at 56 and 4 reserved bytes before the FileId.
                Response::Create(CreateResponse {
                    oplock_level: b[2],
                    flags: b[3],
                    create_action: le32(b, 4)?,
                    info: FileInfo::read(b, 8)?,
                    file_id: FileId::read(b, 64)?,
                    contexts: {
                        let region = (le32(b, 80)?, le32(b, 84)?);
                        let bytes = buffer(b, region.0, region.1)?;
                        if region.1 != 0 {
                            contexts_after(region.0, (0, 0))?;
                        }
                        create_contexts(bytes)?
                    },
                })
            }
            command::CLOSE => {
                fixed(b, 60)?;
                Response::Close { flags: le16(b, 2)?, info: FileInfo::read(b, 8)? }
            }
            command::FLUSH => fixed(b, 4).map(|_| Response::Flush)?,
            command::READ => {
                fixed(b, 17)?;
                Response::Read {
                    data: buffer(b, b[2].into(), le32(b, 4)?)?.to_vec(),
                    data_remaining: le32(b, 8)?,
                    flags: le32(b, 12)?,
                }
            }
            command::WRITE => {
                fixed(b, 17)?;
                Response::Write { count: le32(b, 4)?, remaining: le32(b, 8)? }
            }
            command::LOCK => fixed(b, 4).map(|_| Response::Lock)?,
            command::IOCTL => {
                fixed(b, 49)?;
                let input = (le32(b, 24)?, le32(b, 28)?);
                let output = (le32(b, 32)?, le32(b, 36)?);
                let (input_bytes, output_bytes) = (buffer(b, input.0, input.1)?, buffer(b, output.0, output.1)?);
                // 2.2.32: output starts at the end of the input rounded up
                // to a multiple of 8. Padding past that is allowed.
                if output.1 != 0 {
                    if !output.0.is_multiple_of(8) {
                        return Err(Error::Align(output.0));
                    }
                    if input.1 != 0 && u64::from(output.0) < u64::from(input.0) + u64::from(input.1) {
                        return Err(Error::Overlap);
                    }
                }
                Response::Ioctl(IoctlResponse {
                    ctl_code: le32(b, 4)?,
                    file_id: FileId::read(b, 8)?,
                    input: input_bytes.to_vec(),
                    output: output_bytes.to_vec(),
                    flags: le32(b, 40)?,
                })
            }
            command::ECHO => fixed(b, 4).map(|_| Response::Echo)?,
            command::QUERY_DIRECTORY => Response::QueryDirectory { data: output(b)? },
            command::CHANGE_NOTIFY => Response::ChangeNotify { data: output(b)? },
            command::QUERY_INFO => Response::QueryInfo { data: output(b)? },
            command::SET_INFO => fixed(b, 2).map(|_| Response::SetInfo)?,
            _ => Response::Other { body: b.to_vec() },
        })
    }

    /// The command this response answers, or `None` for an error body or
    /// an `Other` one, which may answer any.
    pub fn command(&self) -> Option<u16> {
        Some(match self {
            Response::Negotiate(_) => command::NEGOTIATE,
            Response::SessionSetup { .. } => command::SESSION_SETUP,
            Response::Logoff => command::LOGOFF,
            Response::TreeConnect(_) => command::TREE_CONNECT,
            Response::TreeDisconnect => command::TREE_DISCONNECT,
            Response::Create(_) => command::CREATE,
            Response::Close { .. } => command::CLOSE,
            Response::Flush => command::FLUSH,
            Response::Read { .. } => command::READ,
            Response::Write { .. } => command::WRITE,
            Response::Lock => command::LOCK,
            Response::Ioctl(_) => command::IOCTL,
            Response::Echo => command::ECHO,
            Response::QueryDirectory { .. } => command::QUERY_DIRECTORY,
            Response::ChangeNotify { .. } => command::CHANGE_NOTIFY,
            Response::QueryInfo { .. } => command::QUERY_INFO,
            Response::SetInfo => command::SET_INFO,
            Response::Error(_) | Response::Other { .. } => return None,
        })
    }

    /// The response's body bytes, for a response to `command` with
    /// `status`. It is an error if [`Response::parse`] would read the bytes
    /// back as another kind of body: a typed response for another command,
    /// an `Other` one for a command this module reads, or an error body
    /// where the status calls for a typed one, or the other way round.
    pub fn to_body(&self, command: u16, status: u32) -> Result<Vec<u8>, EncodeError> {
        match self.command() {
            Some(c) if c != command => return Err(EncodeError::Command(command)),
            None if matches!(self, Response::Other { .. }) && own_size(command).is_some() => {
                return Err(EncodeError::Command(command));
            }
            _ => {}
        }
        let w = self.write()?;
        let is_error = matches!(self, Response::Error(_));
        if error_body(command, status, le16(&w, 0).ok()) != is_error {
            return Err(EncodeError::Status(status));
        }
        Ok(w)
    }

    fn write(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Vec::new();
        match self {
            Response::Negotiate(r) => {
                let is_311 = r.dialect == dialect::SMB_3_1_1;
                if (!is_311 && !r.contexts.is_empty()) || (is_311 && !response_contexts_ok(&r.contexts)) {
                    return Err(EncodeError::Dialect);
                }
                put16(&mut w, 65);
                put16(&mut w, r.security_mode);
                put16(&mut w, r.dialect);
                put16(&mut w, 0);
                w.extend_from_slice(&r.server_guid);
                for v in [r.capabilities, r.max_transact_size, r.max_read_size, r.max_write_size] {
                    put32(&mut w, v);
                }
                put64(&mut w, r.system_time);
                put64(&mut w, r.server_start_time);
                put16(&mut w, 128);
                put16(&mut w, fit16(r.security_buffer.len())?);
                put32(&mut w, 0);
                w.extend_from_slice(&r.security_buffer);
                if !r.contexts.is_empty() {
                    pad8(&mut w);
                    let at = fit32(at(&w))?;
                    let count = fit16(r.contexts.len())?;
                    write_negotiate_contexts(&mut w, &r.contexts)?;
                    w[6..8].copy_from_slice(&count.to_le_bytes());
                    w[60..64].copy_from_slice(&at.to_le_bytes());
                }
            }
            Response::SessionSetup { session_flags, security_buffer } => {
                put16(&mut w, 9);
                put16(&mut w, *session_flags);
                put16(&mut w, 72);
                put16(&mut w, fit16(security_buffer.len())?);
                w.extend_from_slice(security_buffer);
            }
            Response::Logoff | Response::TreeDisconnect | Response::Flush | Response::Lock | Response::Echo => {
                put32(&mut w, 4)
            }
            Response::TreeConnect(r) => {
                put16(&mut w, 16);
                w.push(r.share_type);
                w.push(0);
                put32(&mut w, r.share_flags);
                put32(&mut w, r.capabilities);
                put32(&mut w, r.maximal_access);
            }
            Response::Create(r) => {
                put16(&mut w, 89);
                w.push(r.oplock_level);
                w.push(r.flags);
                put32(&mut w, r.create_action);
                r.info.write(&mut w);
                put32(&mut w, 0);
                r.file_id.write(&mut w);
                put64(&mut w, 0);
                write_create_contexts(&mut w, &r.contexts, 80)?;
            }
            Response::Close { flags, info } => {
                put16(&mut w, 60);
                put16(&mut w, *flags);
                put32(&mut w, 0);
                info.write(&mut w);
            }
            Response::Read { data, data_remaining, flags } => {
                put16(&mut w, 17);
                w.push(80);
                w.push(0);
                put32(&mut w, fit32(data.len())?);
                put32(&mut w, *data_remaining);
                put32(&mut w, *flags);
                w.extend_from_slice(data);
            }
            Response::Write { count, remaining } => {
                put16(&mut w, 17);
                put16(&mut w, 0);
                put32(&mut w, *count);
                put32(&mut w, *remaining);
                put32(&mut w, 0);
            }
            Response::Ioctl(r) => {
                put16(&mut w, 49);
                put16(&mut w, 0);
                put32(&mut w, r.ctl_code);
                r.file_id.write(&mut w);
                // The output starts 8-byte aligned after the input, and
                // its offset is 0 when there is none.
                let input_end = fit32(112 + r.input.len())?;
                let out_at = if r.output.is_empty() { 0 } else { input_end.next_multiple_of(8) };
                put32(&mut w, 112);
                put32(&mut w, fit32(r.input.len())?);
                put32(&mut w, out_at);
                put32(&mut w, fit32(r.output.len())?);
                put32(&mut w, r.flags);
                put32(&mut w, 0);
                w.extend_from_slice(&r.input);
                if !r.output.is_empty() {
                    too_long(HEADER_LEN.saturating_add(out_at as usize).saturating_add(r.output.len()))?;
                    w.resize(out_at as usize - HEADER_LEN, 0);
                    w.extend_from_slice(&r.output);
                }
            }
            Response::QueryDirectory { data } | Response::ChangeNotify { data } | Response::QueryInfo { data } => {
                put16(&mut w, 9);
                put16(&mut w, 72);
                put32(&mut w, fit32(data.len())?);
                w.extend_from_slice(data);
            }
            Response::SetInfo => put16(&mut w, 2),
            Response::Error(e) => {
                if !error_contexts_fit(e.context_count, &e.data) {
                    return Err(EncodeError::ErrorContexts);
                }
                put16(&mut w, 9);
                w.push(e.context_count);
                w.push(0);
                put32(&mut w, fit32(e.data.len())?);
                w.extend_from_slice(&e.data);
            }
            Response::Other { body } => {
                too_long(body.len())?;
                return Ok(body.clone());
            }
        }
        finish(&mut w);
        Ok(w)
    }
}

/// Whether a response to `command` with `status`, whose body starts with
/// StructureSize `size`, is an error body. See [`Response::parse`].
fn error_body(command: u16, status: u32, size: Option<u16>) -> bool {
    if status == status::SUCCESS {
        return false;
    }
    let Some(own) = own_size(command) else { return size == Some(9) };
    match (command, status) {
        (command::SESSION_SETUP, status::MORE_PROCESSING_REQUIRED)
        | (command::QUERY_INFO, status::BUFFER_OVERFLOW)
        | (command::CHANGE_NOTIFY, status::NOTIFY_ENUM_DIR) => false,
        (command::READ, status::BUFFER_OVERFLOW)
        | (command::IOCTL, status::BUFFER_OVERFLOW | status::INVALID_PARAMETER) => size != Some(own),
        _ => true,
    }
}

/// Whether `data` starts with `count` SMB2 ERROR Context structures, each
/// 8-byte aligned from the start of the error data, which is itself
/// 8-byte aligned from the start of the ERROR response (MS-SMB2 section
/// 2.2.2). Bytes after the last context are not read.
fn error_contexts_fit(count: u8, data: &[u8]) -> bool {
    let mut at = 0usize;
    for i in 0..count {
        if i > 0 {
            at = at.next_multiple_of(8);
        }
        let Ok(len) = le32(data, at) else { return false };
        if le32(data, at + 4).is_err() {
            return false;
        }
        let Some(end) = (at + 8).checked_add(len as usize) else { return false };
        if end > data.len() {
            return false;
        }
        at = end;
    }
    true
}

/// Whether an SMB 3.1.1 NEGOTIATE response's contexts pass the checks of
/// MS-SMB2 section 3.2.5.2: exactly one preauthentication integrity
/// context, and at most one each of the encryption, compression, RDMA
/// transform, signing and transport contexts.
fn response_contexts_ok(contexts: &[NegotiateContext]) -> bool {
    use negotiate_context::*;
    let count = |kind: u16| contexts.iter().filter(|c| c.kind == kind).count();
    count(PREAUTH_INTEGRITY_CAPABILITIES) == 1
        && [
            ENCRYPTION_CAPABILITIES,
            COMPRESSION_CAPABILITIES,
            RDMA_TRANSFORM_CAPABILITIES,
            SIGNING_CAPABILITIES,
            TRANSPORT_CAPABILITIES,
        ]
        .iter()
        .all(|&kind| count(kind) <= 1)
}

/// The StructureSize of the typed response body for `command`, if this
/// module reads one.
fn own_size(command: u16) -> Option<u16> {
    Some(match command {
        command::NEGOTIATE => 65,
        command::SESSION_SETUP | command::QUERY_DIRECTORY | command::CHANGE_NOTIFY | command::QUERY_INFO => 9,
        command::LOGOFF | command::TREE_DISCONNECT | command::FLUSH | command::LOCK | command::ECHO => 4,
        command::TREE_CONNECT => 16,
        command::CREATE => 89,
        command::CLOSE => 60,
        command::READ | command::WRITE => 17,
        command::IOCTL => 49,
        command::SET_INFO => 2,
        _ => return None,
    })
}

/// Whether this module reads `command` as a typed request.
fn known(command: u16) -> bool {
    command <= command::SET_INFO
}

// ---------------------------------------------------------------------
// Helpers

/// Checks a body's StructureSize, and that it holds the fixed part: the
/// StructureSize rounded down to even.
fn fixed(b: &[u8], size: u16) -> Result<(), Error> {
    let found = le16(b, 0)?;
    if found != size {
        return Err(Error::StructureSize(found));
    }
    if b.len() < usize::from(size & !1) {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// A QUERY_DIRECTORY, CHANGE_NOTIFY or QUERY_INFO response's output.
fn output(b: &[u8]) -> Result<Vec<u8>, Error> {
    fixed(b, 9)?;
    Ok(buffer(b, le16(b, 2)?.into(), le32(b, 4)?)?.to_vec())
}

/// The bytes at `offset`, counted from the header's start, and `len` long.
/// An empty buffer may have any offset. Any other starts at or after the
/// end of the body's fixed part, its StructureSize rounded down to even,
/// so a writer that puts it right after the fixed part never makes the
/// body longer.
fn buffer(b: &[u8], offset: u32, len: u32) -> Result<&[u8], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    let fixed = usize::from(le16(b, 0)? & !1);
    let start = (offset as usize).checked_sub(HEADER_LEN).ok_or(Error::Buffer)?;
    if start < fixed {
        return Err(Error::Buffer);
    }
    let end = start.checked_add(len as usize).ok_or(Error::Buffer)?;
    b.get(start..end).ok_or(Error::Buffer)
}

/// Checks that two buffers, each an offset and a length, share no bytes.
/// An empty buffer shares none.
fn apart(a: (u32, u32), b: (u32, u32)) -> Result<(), Error> {
    let end = |(o, l): (u32, u32)| u64::from(o) + u64::from(l);
    if a.1 == 0 || b.1 == 0 || end(a) <= u64::from(b.0) || end(b) <= u64::from(a.0) {
        Ok(())
    } else {
        Err(Error::Overlap)
    }
}

/// Checks that contexts at `offset` start 8-byte aligned and at or after
/// the end of the buffer `before`, an offset and a length. An empty
/// buffer before them puts no limit on where they start.
fn contexts_after(offset: u32, before: (u32, u32)) -> Result<(), Error> {
    if !offset.is_multiple_of(8) {
        return Err(Error::Align(offset));
    }
    if before.1 != 0 && u64::from(offset) < u64::from(before.0) + u64::from(before.1) {
        return Err(Error::Overlap);
    }
    Ok(())
}

/// UTF-16LE bytes as code units.
fn string(b: &[u8]) -> Result<Vec<u16>, Error> {
    if !b.len().is_multiple_of(2) {
        return Err(Error::OddString);
    }
    Ok(b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect())
}

/// Code units as UTF-16LE bytes for a 16-bit length field, checked
/// before any bytes are made.
fn string16(units: &[u16]) -> Result<Vec<u8>, EncodeError> {
    fit16(units.len().saturating_mul(2))?;
    Ok(unstring(units))
}

/// Code units as UTF-16LE bytes.
fn unstring(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

/// Negotiate contexts: `count` of them from `offset`, each 8-byte aligned
/// from the header's start. The first starts after the body's fixed part
/// and after the buffer `before` (see [`contexts_after`]).
fn negotiate_contexts(b: &[u8], offset: u32, count: u16, before: (u32, u32)) -> Result<Vec<NegotiateContext>, Error> {
    let mut out = Vec::new();
    if count == 0 {
        return Ok(out);
    }
    let fixed = usize::from(le16(b, 0)? & !1);
    let mut at = (offset as usize).checked_sub(HEADER_LEN).ok_or(Error::Buffer)?;
    if at < fixed {
        return Err(Error::Buffer);
    }
    contexts_after(offset, before)?;
    for i in 0..count {
        if i > 0 {
            at = at.checked_next_multiple_of(8).ok_or(Error::Buffer)?;
        }
        let kind = le16(b, at).map_err(|_| Error::Buffer)?;
        let len = usize::from(le16(b, at.checked_add(2).ok_or(Error::Buffer)?).map_err(|_| Error::Buffer)?);
        let start = at.checked_add(8).ok_or(Error::Buffer)?;
        let end = start.checked_add(len).ok_or(Error::Buffer)?;
        let data = b.get(start..end).ok_or(Error::Buffer)?;
        out.push(NegotiateContext { kind, data: data.to_vec() });
        at = end;
    }
    Ok(out)
}

fn write_negotiate_contexts(w: &mut Vec<u8>, contexts: &[NegotiateContext]) -> Result<(), EncodeError> {
    for (i, c) in contexts.iter().enumerate() {
        if i > 0 {
            pad8(w);
        }
        put16(w, c.kind);
        put16(w, fit16(c.data.len())?);
        put32(w, 0);
        w.extend_from_slice(&c.data);
        too_long(w.len())?;
    }
    Ok(())
}

/// Create contexts in `region`, each linked to the next by its Next field,
/// a multiple of 8. A Next that is not 0 must point at another context
/// inside the region. A context's name and data must lie inside it, each
/// 8-byte aligned and after its 16-byte header, in either order and apart,
/// as MS-SMB2 section 2.2.13.2 lays them out. So the bytes copied out are
/// never more than the region holds.
fn create_contexts(region: &[u8]) -> Result<Vec<CreateContext>, Error> {
    let mut out = Vec::new();
    if region.is_empty() {
        return Ok(out);
    }
    let mut at = 0;
    loop {
        let rest = region.get(at..).ok_or(Error::Buffer)?;
        if rest.len() < 16 {
            return Err(Error::Buffer);
        }
        let next = le32(rest, 0)? as usize;
        let this = if next == 0 {
            rest
        } else if next >= 16 && next <= rest.len() {
            &rest[..next]
        } else {
            return Err(Error::Buffer);
        };
        if !next.is_multiple_of(8) {
            return Err(Error::Align(next as u32));
        }
        let field = |off: usize, len: usize| -> Result<Vec<u8>, Error> {
            if len == 0 {
                return Ok(Vec::new());
            }
            Ok(this.get(off..off.checked_add(len).ok_or(Error::Buffer)?).ok_or(Error::Buffer)?.to_vec())
        };
        let (name_at, name_len) = (le16(rest, 4)?, le16(rest, 6)?);
        let (data_at, data_len) = (le16(rest, 10)?, le32(rest, 12)?);
        if name_len != 0 {
            if name_at < 16 {
                return Err(Error::Buffer);
            }
            if name_at % 8 != 0 {
                return Err(Error::Align(name_at.into()));
            }
        }
        // DataOffset is ignored when DataLength is 0.
        if data_len != 0 {
            if data_at < 16 {
                return Err(Error::Buffer);
            }
            if data_at % 8 != 0 {
                return Err(Error::Align(data_at.into()));
            }
            apart((name_at.into(), name_len.into()), (data_at.into(), data_len))?;
        }
        let name = field(usize::from(name_at), usize::from(name_len))?;
        let data = field(usize::from(data_at), data_len as usize)?;
        out.push(CreateContext { name, data });
        if next == 0 {
            return Ok(out);
        }
        at += next;
    }
}

/// Writes create contexts after the bytes already in `w`, 8-byte aligned,
/// and puts their offset and length at `field` in the fixed part.
fn write_create_contexts(w: &mut Vec<u8>, contexts: &[CreateContext], field: usize) -> Result<(), EncodeError> {
    if contexts.is_empty() {
        return Ok(());
    }
    pad8(w);
    let start = w.len();
    for (i, c) in contexts.iter().enumerate() {
        let here = w.len();
        let name_end = 16usize.checked_add(c.name.len()).ok_or(EncodeError::TooLong)?;
        let data_at = if c.data.is_empty() { 0 } else { name_end.next_multiple_of(8) };
        let size = if c.data.is_empty() { name_end } else { data_at.saturating_add(c.data.len()) };
        too_long(here.saturating_add(size))?;
        let last = i + 1 == contexts.len();
        let next = if last { 0 } else { fit32(size.next_multiple_of(8))? };
        put32(w, next);
        put16(w, 16);
        put16(w, fit16(c.name.len())?);
        put16(w, 0);
        put16(w, fit16(data_at)?);
        put32(w, fit32(c.data.len())?);
        w.extend_from_slice(&c.name);
        if !c.data.is_empty() {
            w.resize(here + data_at, 0);
            w.extend_from_slice(&c.data);
        }
        if !last {
            w.resize(here + size.next_multiple_of(8), 0);
        }
    }
    let at = fit32(HEADER_LEN + start)?;
    let len = fit32(w.len() - start)?;
    w[field..field + 4].copy_from_slice(&at.to_le_bytes());
    w[field + 4..field + 8].copy_from_slice(&len.to_le_bytes());
    Ok(())
}

/// Ends a body: one whose StructureSize is odd counts one byte of its
/// buffer, so a body with an empty buffer gets a zero byte.
fn finish(w: &mut Vec<u8>) {
    if let Ok(size) = le16(w, 0)
        && size % 2 == 1
        && w.len() < usize::from(size)
    {
        w.push(0);
    }
}

/// Where the next byte of a body goes, counted from the header's start.
fn at(w: &[u8]) -> usize {
    HEADER_LEN + w.len()
}

/// Pads a body with zeros until its next byte is 8-byte aligned from the
/// header's start.
fn pad8(w: &mut Vec<u8>) {
    w.resize(w.len().next_multiple_of(8), 0);
}

fn too_long(n: usize) -> Result<(), EncodeError> {
    if n > MAX_MESSAGE { Err(EncodeError::TooLong) } else { Ok(()) }
}

fn fit16(n: usize) -> Result<u16, EncodeError> {
    u16::try_from(n).map_err(|_| EncodeError::TooLong)
}

fn fit32(n: usize) -> Result<u32, EncodeError> {
    too_long(n)?;
    u32::try_from(n).map_err(|_| EncodeError::TooLong)
}

fn put16(w: &mut Vec<u8>, v: u16) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn put32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn put64(w: &mut Vec<u8>, v: u64) {
    w.extend_from_slice(&v.to_le_bytes());
}

fn arr<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    let end = at.checked_add(N).ok_or(Error::Truncated)?;
    b.get(at..end).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated)
}

fn le16(b: &[u8], at: usize) -> Result<u16, Error> {
    arr(b, at).map(u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> Result<u32, Error> {
    arr(b, at).map(u32::from_le_bytes)
}

fn le64(b: &[u8], at: usize) -> Result<u64, Error> {
    arr(b, at).map(u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The byte layouts below are built field by field from MS-SMB2,
    // section 2.2, not with this module's writers.

    /// A sync header, field by field.
    fn header_bytes(
        command: u16,
        status: u32,
        flags: u32,
        next: u32,
        message_id: u64,
        tree: u32,
        session: u64,
    ) -> Vec<u8> {
        let mut b = vec![0xfe, b'S', b'M', b'B'];
        b.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        b.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
        b.extend_from_slice(&status.to_le_bytes());
        b.extend_from_slice(&command.to_le_bytes());
        b.extend_from_slice(&31u16.to_le_bytes()); // CreditRequest
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&next.to_le_bytes());
        b.extend_from_slice(&message_id.to_le_bytes());
        b.extend_from_slice(&0xfeffu32.to_le_bytes()); // Reserved (process ID)
        b.extend_from_slice(&tree.to_le_bytes());
        b.extend_from_slice(&session.to_le_bytes());
        b.extend_from_slice(&[0; 16]);
        b
    }

    fn le(v: &[u64], widths: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for (x, w) in v.iter().zip(widths) {
            out.extend_from_slice(&x.to_le_bytes()[..*w]);
        }
        out
    }

    fn u16s(s: &str) -> Vec<u8> {
        unstring(&utf16(s))
    }

    #[test]
    fn doc_example() {
        let negotiate = Request::Negotiate(NegotiateRequest {
            dialects: vec![dialect::SMB_2_1, dialect::SMB_3_0_2],
            ..NegotiateRequest::default()
        });
        let hello = Message::from_request(Header::new(command::NEGOTIATE, 0), &negotiate).unwrap();
        let bytes = Packet::Smb2(vec![hello]).to_frame().unwrap();
        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(&bytes[..10]), 10);
        assert_eq!(decoder.next_frame(), None);
        assert_eq!(decoder.feed(&bytes[10..]), bytes.len() - 10);
        let payload = decoder.next_frame().unwrap().unwrap();
        let Packet::Smb2(messages) = Packet::parse(&payload).unwrap() else { panic!() };
        let Ok(Request::Negotiate(offer)) = messages[0].request() else { panic!() };
        let chosen = offer.dialects.iter().copied().filter(|&d| d <= dialect::SMB_3_0_2).max().unwrap();
        assert_eq!(chosen, dialect::SMB_3_0_2);
        let answer = Response::Negotiate(NegotiateResponse {
            dialect: chosen,
            max_read_size: 65536,
            ..NegotiateResponse::default()
        });
        let reply = Message::reply_to(&messages[0].header, status::SUCCESS, &answer).unwrap();
        let out = Packet::Smb2(vec![reply]).to_frame().unwrap();
        assert_eq!(out[..8], [0, 0, 0, 129, 0xfe, b'S', b'M', b'B']);
        // The reply's header: the response flag, the same message ID.
        let Packet::Smb2(back) = Packet::parse(&out[4..]).unwrap() else { panic!() };
        assert!(back[0].header.is_response());
        assert_eq!(back[0].response(), Ok(answer));
    }

    #[test]
    fn sync_and_async_headers() {
        let b = header_bytes(command::READ, 0, flags::SIGNED, 0, 7, 0x0001_0001, 0x4000_0000_0001);
        let (h, next) = Header::parse(&b).unwrap();
        assert_eq!(next, 0);
        assert_eq!(h.command, command::READ);
        assert_eq!(h.credit_charge, 1);
        assert_eq!(h.credits, 31);
        assert_eq!(h.message_id, 7);
        assert_eq!(h.target, Target::Sync { process_id: 0xfeff, tree_id: 0x0001_0001 });
        assert_eq!(h.session_id, 0x4000_0000_0001);
        assert_eq!(h.to_bytes(0).unwrap()[..], b[..]);
        // The async form: bytes 32..40 are the async ID.
        let mut a = b.clone();
        a[16..20].copy_from_slice(&(flags::ASYNC_COMMAND | flags::SERVER_TO_REDIR).to_le_bytes());
        a[8..12].copy_from_slice(&status::PENDING.to_le_bytes());
        let (h, _) = Header::parse(&a).unwrap();
        assert_eq!(h.target, Target::Async { async_id: 0x0001_0001_0000_feff });
        assert!(h.is_response());
        assert_eq!(h.to_bytes(0).unwrap()[..], a[..]);
        // The flag and the target must agree.
        let mut wrong = h;
        wrong.target = Target::default();
        assert_eq!(wrong.to_bytes(0), Err(EncodeError::AsyncFlag));
        let mut wrong = Header::new(command::ECHO, 1);
        wrong.target = Target::Async { async_id: 1 };
        assert_eq!(wrong.to_bytes(0), Err(EncodeError::AsyncFlag));
    }

    #[test]
    fn reply_headers() {
        let mut req = Header::new(command::CREATE, 9);
        req.credits = 0;
        req.flags = flags::RELATED_OPERATIONS | flags::SIGNED | flags::DFS_OPERATIONS;
        req.target = Target::Sync { process_id: 0, tree_id: 5 };
        req.session_id = 77;
        let r = req.reply(status::ACCESS_DENIED);
        assert_eq!(r.flags, flags::SERVER_TO_REDIR | flags::RELATED_OPERATIONS);
        assert_eq!(r.credits, 1);
        assert_eq!((r.message_id, r.session_id, r.target, r.status), (9, 77, req.target, status::ACCESS_DENIED));
    }

    #[test]
    fn negotiate_request_311_example() {
        // Dialects 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1, then two contexts:
        // preauth SHA-512 with a 4-byte salt, and the AES-128-GCM cipher.
        let mut body = le(&[36, 5, 1, 0, 0x7f], &[2, 2, 2, 2, 4]);
        body.extend_from_slice(&[0xaa; 16]);
        body.extend_from_slice(&[0; 8]); // context offset and count, set below
        for d in [0x202u64, 0x210, 0x300, 0x302, 0x311] {
            body.extend_from_slice(&le(&[d], &[2]));
        }
        // 46 bytes so far; contexts start 8-aligned from the header, at 112.
        body.resize(48, 0);
        body[28..32].copy_from_slice(&112u32.to_le_bytes());
        body[32..34].copy_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&le(&[1, 10, 0, 1, 4, 1], &[2, 2, 4, 2, 2, 2]));
        body.extend_from_slice(&[1, 2, 3, 4]);
        body.extend_from_slice(&[0; 6]); // pad to 8
        body.extend_from_slice(&le(&[2, 4, 0, 1, 2], &[2, 2, 4, 2, 2]));
        let req = Request::parse(command::NEGOTIATE, &body).unwrap();
        let Request::Negotiate(n) = &req else { panic!() };
        assert_eq!(n.dialects, [0x202, 0x210, 0x300, 0x302, 0x311]);
        assert_eq!(n.security_mode, security_mode::SIGNING_ENABLED);
        assert_eq!(n.capabilities, 0x7f);
        assert_eq!(n.client_guid, [0xaa; 16]);
        assert_eq!(n.contexts.len(), 2);
        assert_eq!(n.contexts[0].preauth_integrity_parts(), Some((vec![negotiate_context::SHA_512], vec![1, 2, 3, 4])));
        assert_eq!(n.contexts[1].kind, negotiate_context::ENCRYPTION_CAPABILITIES);
        assert_eq!(n.contexts[1].algorithm_list(), Some(vec![2]));
        // The writer lays it out the same way.
        assert_eq!(req.to_body().unwrap(), body);
        assert_eq!(NegotiateContext::preauth_integrity(&[1], &[1, 2, 3, 4]).unwrap(), n.contexts[0]);
        assert_eq!(NegotiateContext::algorithms(2, &[2]).unwrap(), n.contexts[1]);
        assert_eq!(n.contexts[1].preauth_integrity_parts(), None);
        assert_eq!(NegotiateContext::algorithms(2, &[0; 40000]), Err(EncodeError::TooLong));
        assert_eq!(NegotiateContext::preauth_integrity(&[], &[0; 70000]), Err(EncodeError::TooLong));
        assert_eq!(NegotiateContext { kind: 2, data: vec![5, 0] }.algorithm_list(), None);
    }

    #[test]
    fn negotiate_request_without_311_keeps_start_time() {
        let mut body = le(&[36, 1, 2, 0, 0], &[2, 2, 2, 2, 4]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&0x1234u64.to_le_bytes());
        body.extend_from_slice(&0x202u16.to_le_bytes());
        let req = Request::parse(command::NEGOTIATE, &body).unwrap();
        let Request::Negotiate(n) = &req else { panic!() };
        assert_eq!(n.client_start_time, 0x1234);
        assert!(n.contexts.is_empty());
        assert_eq!(req.to_body().unwrap(), body);
        // Contexts need 3.1.1, and 3.1.1 leaves no room for a start time.
        let bad = NegotiateRequest { dialects: vec![0x202], contexts: vec![NegotiateContext::default()], ..n.clone() };
        assert_eq!(Request::Negotiate(bad).to_body(), Err(EncodeError::Dialect));
        let bad = NegotiateRequest { dialects: vec![0x311], ..n.clone() };
        assert_eq!(Request::Negotiate(bad).to_body(), Err(EncodeError::Dialect));
        let bad =
            NegotiateResponse { dialect: 0x302, contexts: vec![NegotiateContext::default()], ..Default::default() };
        assert_eq!(Response::Negotiate(bad).to_body(0, 0), Err(EncodeError::Dialect));
    }

    #[test]
    fn negotiate_response_example() {
        let mut body = le(&[65, 1, 0x311, 1], &[2, 2, 2, 2]);
        body.extend_from_slice(&[0x11; 16]);
        body.extend_from_slice(&le(&[0x2f, 0x80_0000, 0x80_0000, 0x80_0000, 132, 0], &[4, 4, 4, 4, 8, 8]));
        body.extend_from_slice(&le(&[128, 3, 136], &[2, 2, 4]));
        body.extend_from_slice(&[0x60, 0x48, 0x06]); // the start of a SPNEGO blob
        body.resize(72, 0); // 64 + 72 = 136
        body.extend_from_slice(&le(&[1, 38, 0, 1, 32, 1], &[2, 2, 4, 2, 2, 2]));
        body.extend_from_slice(&[9; 32]);
        let resp = Response::parse(command::NEGOTIATE, 0, &body).unwrap();
        let Response::Negotiate(n) = &resp else { panic!() };
        assert_eq!(n.dialect, dialect::SMB_3_1_1);
        assert_eq!(n.max_read_size, 0x80_0000);
        assert_eq!(n.system_time, 132);
        assert_eq!(n.security_buffer, [0x60, 0x48, 0x06]);
        assert_eq!(n.contexts[0].preauth_integrity_parts(), Some((vec![1], vec![9; 32])));
        assert_eq!(resp.to_body(0, 0).unwrap(), body);
    }

    #[test]
    fn session_setup_examples() {
        let mut body = le(&[25, 0, 1, 1, 0, 88, 4, 0], &[2, 1, 1, 4, 4, 2, 2, 8]);
        body.extend_from_slice(b"NTLM");
        let req = Request::parse(command::SESSION_SETUP, &body).unwrap();
        let want = SessionSetupRequest {
            security_mode: 1,
            capabilities: 1,
            security_buffer: b"NTLM".to_vec(),
            ..Default::default()
        };
        assert_eq!(req, Request::SessionSetup(want));
        assert_eq!(req.to_body().unwrap(), body);
        // The challenge goes back with MORE_PROCESSING_REQUIRED and a
        // SESSION_SETUP body, not an error body.
        let mut body = le(&[9, 0, 72, 2], &[2, 2, 2, 2]);
        body.extend_from_slice(&[0xa1, 0x00]);
        let resp = Response::parse(command::SESSION_SETUP, status::MORE_PROCESSING_REQUIRED, &body).unwrap();
        assert_eq!(resp, Response::SessionSetup { session_flags: 0, security_buffer: vec![0xa1, 0] });
        assert_eq!(resp.to_body(command::SESSION_SETUP, status::MORE_PROCESSING_REQUIRED).unwrap(), body);
        // The same bytes with LOGON_FAILURE are an error body.
        assert!(matches!(
            Response::parse(command::SESSION_SETUP, status::LOGON_FAILURE, &body),
            Ok(Response::Error(_)) | Err(_)
        ));
        assert_eq!(
            resp.to_body(command::SESSION_SETUP, status::LOGON_FAILURE),
            Err(EncodeError::Status(status::LOGON_FAILURE))
        );
    }

    #[test]
    fn tree_connect_examples() {
        let path = u16s("\\\\fs1\\IPC$");
        let mut body = le(&[9, 0, 72, path.len() as u64], &[2, 2, 2, 2]);
        body.extend_from_slice(&path);
        let req = Request::parse(command::TREE_CONNECT, &body).unwrap();
        let Request::TreeConnect(t) = &req else { panic!() };
        assert_eq!(utf16_lossy(&t.path), "\\\\fs1\\IPC$");
        assert_eq!(req.to_body().unwrap(), body);
        let body = le(&[16, 2, 0, 0x30, 0, 0x1f01ff], &[2, 1, 1, 4, 4, 4]);
        let resp = Response::parse(command::TREE_CONNECT, 0, &body).unwrap();
        assert_eq!(
            resp,
            Response::TreeConnect(TreeConnectResponse {
                share_type: share_type::PIPE,
                share_flags: 0x30,
                capabilities: 0,
                maximal_access: 0x1f01ff
            })
        );
        assert_eq!(resp.to_body(command::TREE_CONNECT, 0).unwrap(), body);
        // A bad share is an error body with one zero byte of data.
        let err = Response::Error(ErrorResponse::default());
        let bytes = err.to_body(command::TREE_CONNECT, status::BAD_NETWORK_NAME).unwrap();
        assert_eq!(bytes, [9, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Response::parse(command::TREE_CONNECT, status::BAD_NETWORK_NAME, &bytes), Ok(err));
    }

    fn create_request() -> CreateRequest {
        CreateRequest {
            oplock_level: 0xff,
            impersonation_level: 2,
            desired_access: 0x0012_0089,
            file_attributes: 0,
            share_access: 7,
            create_disposition: 1,
            create_options: 0x20,
            name: utf16("docs\\plan.txt"),
            contexts: vec![
                CreateContext { name: create_context::QUERY_MAXIMAL_ACCESS.to_vec(), data: vec![] },
                CreateContext { name: create_context::REQUEST_LEASE.to_vec(), data: vec![7; 32] },
            ],
        }
    }

    #[test]
    fn create_examples() {
        let name = u16s("docs\\plan.txt"); // 26 bytes
        let mut body = le(
            &[57, 0, 0xff, 2, 0, 0, 0x0012_0089, 0, 7, 1, 0x20, 120, 26, 152, 0],
            &[2, 1, 1, 4, 8, 8, 4, 4, 4, 4, 4, 2, 2, 4, 4],
        );
        body.extend_from_slice(&name);
        body.resize(88, 0); // 64 + 88 = 152, 8-aligned
        // MxAc: no data, Next 24 (20 rounded up).
        body.extend_from_slice(&le(&[24, 16, 4, 0, 0, 0], &[4, 2, 2, 2, 2, 4]));
        body.extend_from_slice(b"MxAc");
        body.resize(88 + 24, 0);
        // RqLs: name at 16, data at 24, last.
        body.extend_from_slice(&le(&[0, 16, 4, 0, 24, 32], &[4, 2, 2, 2, 2, 4]));
        body.extend_from_slice(b"RqLs");
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[7; 32]);
        let len = (body.len() - 88) as u32;
        body[52..56].copy_from_slice(&len.to_le_bytes());
        let req = Request::parse(command::CREATE, &body).unwrap();
        assert_eq!(req, Request::Create(create_request()));
        assert_eq!(req.to_body().unwrap(), body);

        let resp = Response::Create(CreateResponse {
            oplock_level: 0,
            flags: 0,
            create_action: 1,
            info: FileInfo {
                creation_time: 1,
                last_access_time: 2,
                last_write_time: 3,
                change_time: 4,
                allocation_size: 4096,
                end_of_file: 10,
                file_attributes: 0x20,
            },
            file_id: FileId { persistent: 5, volatile: 6 },
            contexts: vec![CreateContext { name: b"MxAc".to_vec(), data: vec![0, 0, 0, 0, 0xff, 1, 0x1f, 0] }],
        });
        let bytes = resp.to_body(command::CREATE, 0).unwrap();
        assert_eq!(le16(&bytes, 0), Ok(89));
        assert_eq!(le32(&bytes, 56), Ok(0x20)); // FileAttributes
        assert_eq!(le64(&bytes, 64), Ok(5)); // FileId
        assert_eq!(le32(&bytes, 80), Ok(152)); // CreateContextsOffset
        assert_eq!(Response::parse(command::CREATE, 0, &bytes), Ok(resp));
        // Without contexts: the fixed part and one zero byte.
        let plain = Response::Create(CreateResponse::default());
        assert_eq!(plain.to_body(command::CREATE, 0).unwrap().len(), 89);
    }

    #[test]
    fn close_flush_echo_and_friends() {
        let fid = FileId { persistent: 1, volatile: 2 };
        let mut body = le(&[24, 1, 0, 1, 2], &[2, 2, 4, 8, 8]);
        assert_eq!(Request::parse(command::CLOSE, &body), Ok(Request::Close { flags: 1, file_id: fid }));
        assert_eq!(Request::Close { flags: 1, file_id: fid }.to_body().unwrap(), body);
        body[2] = 0;
        assert_eq!(Request::parse(command::FLUSH, &body), Ok(Request::Flush { file_id: fid }));
        assert_eq!(Request::Flush { file_id: fid }.to_body().unwrap(), body);
        let info = FileInfo { end_of_file: 9, file_attributes: 0x80, ..Default::default() };
        let mut close = le(&[60, 1, 0, 0, 0, 0, 0, 0, 9, 0x80], &[2, 2, 4, 8, 8, 8, 8, 8, 8, 4]);
        let resp = Response::parse(command::CLOSE, 0, &close).unwrap();
        assert_eq!(resp, Response::Close { flags: 1, info });
        assert_eq!(resp.to_body(command::CLOSE, 0).unwrap(), close);
        close.pop();
        assert_eq!(Response::parse(command::CLOSE, 0, &close), Err(Error::Truncated));
        let four = [4, 0, 0, 0];
        for (c, req, resp) in [
            (command::LOGOFF, Request::Logoff, Some(Response::Logoff)),
            (command::TREE_DISCONNECT, Request::TreeDisconnect, Some(Response::TreeDisconnect)),
            (command::ECHO, Request::Echo, Some(Response::Echo)),
            (command::CANCEL, Request::Cancel, None),
        ] {
            assert_eq!(Request::parse(c, &four), Ok(req.clone()));
            assert_eq!(req.to_body().unwrap(), four);
            if let Some(r) = resp {
                assert_eq!(Response::parse(c, 0, &four), Ok(r.clone()));
                assert_eq!(r.to_body(c, 0).unwrap(), four);
            }
        }
        assert_eq!(Response::parse(command::FLUSH, 0, &four), Ok(Response::Flush));
        assert_eq!(Response::parse(command::LOCK, 0, &four), Ok(Response::Lock));
        assert_eq!(Response::parse(command::SET_INFO, 0, &[2, 0]), Ok(Response::SetInfo));
        assert_eq!(Response::SetInfo.to_body(command::SET_INFO, 0).unwrap(), [2, 0]);
        // CANCEL has no response body of its own.
        assert_eq!(Response::parse(command::CANCEL, 0, &four), Ok(Response::Other { body: four.to_vec() }));
    }

    #[test]
    fn read_and_write_examples() {
        let mut body = le(&[49, 0x50, 0, 0x10000, 4096, 1, 2, 1, 0, 0, 0, 0], &[2, 1, 1, 4, 8, 8, 8, 4, 4, 4, 2, 2]);
        body.push(0);
        let req = Request::parse(command::READ, &body).unwrap();
        let want = ReadRequest {
            padding: 0x50,
            length: 0x10000,
            offset: 4096,
            file_id: FileId { persistent: 1, volatile: 2 },
            minimum_count: 1,
            ..Default::default()
        };
        assert_eq!(req, Request::Read(want));
        assert_eq!(req.to_body().unwrap(), body);
        let mut body = le(&[17, 80, 0, 5, 0, 0], &[2, 1, 1, 4, 4, 4]);
        body.extend_from_slice(b"hello");
        let resp = Response::parse(command::READ, 0, &body).unwrap();
        assert_eq!(resp, Response::Read { data: b"hello".to_vec(), data_remaining: 0, flags: 0 });
        assert_eq!(resp.to_body(command::READ, 0).unwrap(), body);
        // BUFFER_OVERFLOW on a pipe read still carries a READ body.
        assert_eq!(Response::parse(command::READ, status::BUFFER_OVERFLOW, &body), Ok(resp));

        let mut body = le(&[49, 112, 3, 10, 1, 2, 0, 0, 0, 0, 1], &[2, 2, 4, 8, 8, 8, 4, 4, 2, 2, 4]);
        body.extend_from_slice(b"abc");
        let req = Request::parse(command::WRITE, &body).unwrap();
        let want = WriteRequest {
            offset: 10,
            file_id: FileId { persistent: 1, volatile: 2 },
            flags: 1,
            data: b"abc".to_vec(),
            ..Default::default()
        };
        assert_eq!(req, Request::Write(want.clone()));
        assert_eq!(req.to_body().unwrap(), body);
        let with_info = Request::Write(WriteRequest { channel: 1, channel_info: vec![1, 2, 3, 4], ..want });
        assert_eq!(Request::parse(command::WRITE, &with_info.to_body().unwrap()), Ok(with_info));
        let body = le(&[17, 0, 3, 0, 0, 0], &[2, 2, 4, 4, 2, 2]);
        let resp = Response::parse(command::WRITE, 0, &body).unwrap();
        assert_eq!(resp, Response::Write { count: 3, remaining: 0 });
        let mut padded = body.clone();
        padded.push(0);
        assert_eq!(resp.to_body(command::WRITE, 0).unwrap(), padded);
        // A write past the end of the message is refused.
        let mut short = le(&[49, 112, 30], &[2, 2, 4]);
        short.resize(49, 0);
        assert_eq!(Request::parse(command::WRITE, &short), Err(Error::Buffer));
    }

    #[test]
    fn lock_example() {
        let mut body = le(&[48, 2, 0, 1, 2], &[2, 2, 4, 8, 8]);
        body.extend_from_slice(&le(&[0, 10, 2, 0], &[8, 8, 4, 4]));
        body.extend_from_slice(&le(&[100, 1, 0x11, 0], &[8, 8, 4, 4]));
        let req = Request::parse(command::LOCK, &body).unwrap();
        let Request::Lock(l) = &req else { panic!() };
        assert_eq!(l.locks, [Lock { offset: 0, length: 10, flags: 2 }, Lock { offset: 100, length: 1, flags: 0x11 }]);
        assert_eq!(req.to_body().unwrap(), body);
        // A lock without its 4 reserved bytes is cut short.
        assert_eq!(Request::parse(command::LOCK, &body[..body.len() - 1]), Err(Error::Truncated));
        // A count past the locks there are.
        body[2] = 3;
        assert_eq!(Request::parse(command::LOCK, &body), Err(Error::Truncated));
        body[2] = 0;
        assert_eq!(Request::parse(command::LOCK, &body), Err(Error::NoLocks));
        assert_eq!(Request::Lock(LockRequest::default()).to_body(), Err(EncodeError::NoLocks));
    }

    #[test]
    fn ioctl_examples() {
        // FSCTL_VALIDATE_NEGOTIATE_INFO with 4 input bytes.
        let mut body = le(
            &[57, 0, 0x0014_0204, u64::MAX, u64::MAX, 120, 4, 0, 0, 0, 24, 1, 0],
            &[2, 2, 4, 8, 8, 4, 4, 4, 4, 4, 4, 4, 4],
        );
        body.extend_from_slice(&[1, 2, 3, 4]);
        let req = Request::parse(command::IOCTL, &body).unwrap();
        let Request::Ioctl(i) = &req else { panic!() };
        assert_eq!(i.file_id, FileId::RELATED);
        assert_eq!(i.input, [1, 2, 3, 4]);
        assert_eq!(i.max_output_response, 24);
        assert_eq!(req.to_body().unwrap(), body);
        let resp = Response::Ioctl(IoctlResponse { ctl_code: 0x0014_0204, output: vec![5; 24], ..Default::default() });
        let bytes = resp.to_body(command::IOCTL, 0).unwrap();
        assert_eq!(le32(&bytes, 32), Ok(112));
        assert_eq!(Response::parse(command::IOCTL, 0, &bytes), Ok(resp.clone()));
        // An IOCTL body may come with a failing status, as copychunk does.
        let b = resp.to_body(command::IOCTL, status::INVALID_PARAMETER).unwrap();
        assert_eq!(Response::parse(command::IOCTL, status::INVALID_PARAMETER, &b), Ok(resp));
    }

    #[test]
    fn directory_notify_and_info_examples() {
        let star = u16s("*");
        let mut body = le(&[33, 0x25, 1, 0, 1, 2, 96, 2, 65536], &[2, 1, 1, 4, 8, 8, 2, 2, 4]);
        body.extend_from_slice(&star);
        let req = Request::parse(command::QUERY_DIRECTORY, &body).unwrap();
        let Request::QueryDirectory(q) = &req else { panic!() };
        assert_eq!((q.file_information_class, q.flags, q.pattern.clone()), (0x25, 1, utf16("*")));
        assert_eq!(req.to_body().unwrap(), body);
        let body = le(&[32, 1, 4096, 1, 2, 0x17, 0], &[2, 2, 4, 8, 8, 4, 4]);
        let req = Request::parse(command::CHANGE_NOTIFY, &body).unwrap();
        let Request::ChangeNotify(c) = &req else { panic!() };
        assert_eq!((c.flags, c.output_buffer_length, c.completion_filter), (1, 4096, 0x17));
        assert_eq!(req.to_body().unwrap(), body);
        let mut body = le(&[41, 1, 5, 1024, 104, 0, 0, 0, 0, 1, 2], &[2, 1, 1, 4, 2, 2, 4, 4, 4, 8, 8]);
        body.push(0);
        let req = Request::parse(command::QUERY_INFO, &body).unwrap();
        let Request::QueryInfo(q) = &req else { panic!() };
        assert_eq!((q.info_type, q.file_info_class, q.output_buffer_length), (1, 5, 1024));
        assert_eq!(req.to_body().unwrap(), body);
        let mut body = le(&[33, 1, 20, 8, 96, 0, 0, 1, 2], &[2, 1, 1, 4, 2, 2, 4, 8, 8]);
        body.extend_from_slice(&1234u64.to_le_bytes());
        let req = Request::parse(command::SET_INFO, &body).unwrap();
        let Request::SetInfo(s) = &req else { panic!() };
        assert_eq!((s.info_type, s.file_info_class, s.data.clone()), (1, 20, 1234u64.to_le_bytes().to_vec()));
        assert_eq!(req.to_body().unwrap(), body);
        for c in [command::QUERY_DIRECTORY, command::CHANGE_NOTIFY, command::QUERY_INFO] {
            let mut body = le(&[9, 72, 3], &[2, 2, 4]);
            body.extend_from_slice(&[1, 2, 3]);
            let resp = Response::parse(c, 0, &body).unwrap();
            assert_eq!(resp.to_body(c, 0).unwrap(), body);
            assert_eq!(resp.command(), Some(c));
        }
        // NO_MORE_FILES ends a listing with an error body.
        let end = Response::parse(command::QUERY_DIRECTORY, status::NO_MORE_FILES, &[9, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(end, Ok(Response::Error(ErrorResponse::default())));
        // QUERY_INFO with BUFFER_OVERFLOW carries what fit.
        let body =
            Response::QueryInfo { data: vec![1; 8] }.to_body(command::QUERY_INFO, status::BUFFER_OVERFLOW).unwrap();
        assert_eq!(
            Response::parse(command::QUERY_INFO, status::BUFFER_OVERFLOW, &body),
            Ok(Response::QueryInfo { data: vec![1; 8] })
        );
    }

    #[test]
    fn error_bodies_and_pending() {
        let mut body = le(&[9, 0, 0, 4], &[2, 1, 1, 4]);
        body.extend_from_slice(&[0x10, 0, 0, 0]);
        let resp = Response::parse(command::READ, status::END_OF_FILE, &body).unwrap();
        assert_eq!(resp, Response::Error(ErrorResponse { context_count: 0, data: vec![0x10, 0, 0, 0] }));
        assert_eq!(resp.to_body(command::READ, status::END_OF_FILE).unwrap(), body);
        assert_eq!(resp.command(), None);
        // An interim response.
        let pending = Response::Error(ErrorResponse::default());
        let b = pending.to_body(command::CHANGE_NOTIFY, status::PENDING).unwrap();
        assert_eq!(Response::parse(command::CHANGE_NOTIFY, status::PENDING, &b), Ok(pending.clone()));
        // An error body never goes with success.
        assert_eq!(pending.to_body(command::READ, 0), Err(EncodeError::Status(0)));
        // A ByteCount past the end.
        body[4] = 9;
        assert_eq!(Response::parse(command::READ, status::END_OF_FILE, &body), Err(Error::Buffer));
        // For commands this module does not read, StructureSize 9 decides.
        assert_eq!(
            Response::parse(command::OPLOCK_BREAK, status::ACCESS_DENIED, &[9, 0, 0, 0, 0, 0, 0, 0, 0]),
            Ok(Response::Error(ErrorResponse::default()))
        );
        assert_eq!(
            Response::parse(command::OPLOCK_BREAK, status::ACCESS_DENIED, &[24, 0, 1]),
            Ok(Response::Other { body: vec![24, 0, 1] })
        );
    }

    #[test]
    fn others_and_commands() {
        let body = vec![24, 0, 1, 0, 0, 0, 0, 0];
        let req = Request::parse(command::OPLOCK_BREAK, &body).unwrap();
        assert_eq!(req, Request::Other { command: command::OPLOCK_BREAK, body: body.clone() });
        assert_eq!(req.to_body().unwrap(), body);
        assert_eq!(Request::Other { command: command::READ, body: vec![] }.to_body(), Err(EncodeError::Command(8)));
        assert_eq!(Response::Other { body: vec![4, 0] }.to_body(command::ECHO, 0), Err(EncodeError::Command(13)));
        assert_eq!(Response::Echo.to_body(command::LOGOFF, 0), Err(EncodeError::Command(2)));
        assert_eq!(
            Message::from_request(Header::new(command::ECHO, 1), &Request::Logoff),
            Err(EncodeError::Command(command::ECHO))
        );
        // An Other body with status 0 and an odd StructureSize is kept as is.
        let odd = Response::Other { body: vec![9, 0] };
        assert_eq!(odd.to_body(0x99, 0), Ok(vec![9, 0]));
        assert_eq!(odd.to_body(0x99, 1), Err(EncodeError::Status(1)));
    }

    /// CREATE, READ and CLOSE in one compound chain, related.
    fn chain() -> Vec<Message> {
        let mut h = Header::new(command::CREATE, 4);
        h.session_id = 9;
        h.target = Target::Sync { process_id: 0, tree_id: 1 };
        let create = Message::from_request(h, &Request::Create(create_request())).unwrap();
        let mut h = Header { command: command::READ, message_id: 5, flags: flags::RELATED_OPERATIONS, ..h };
        let read = Request::Read(ReadRequest { length: 100, file_id: FileId::RELATED, ..Default::default() });
        let read = Message::from_request(h, &read).unwrap();
        h.command = command::CLOSE;
        h.message_id = 6;
        let close = Message::from_request(h, &Request::Close { flags: 0, file_id: FileId::RELATED }).unwrap();
        vec![create, read, close]
    }

    #[test]
    fn compound_chains() {
        let messages = chain();
        let bytes = write_chain(&messages).unwrap();
        let back = parse_chain(&bytes).unwrap();
        assert_eq!(back.len(), 3);
        // The READ body (49 bytes) was padded to 56 to keep the CLOSE aligned.
        let first = le32(&bytes, 20).unwrap() as usize;
        assert_eq!(first % 8, 0);
        let second = le32(&bytes, first + 20).unwrap() as usize;
        assert_eq!(second, 64 + 56);
        assert_eq!(le32(&bytes, first + second + 20), Ok(0));
        assert_eq!(back[1].body.len(), 56);
        assert_eq!(back[1].request(), messages[1].request());
        assert_eq!(back[2], messages[2]);
        // Read back, the chain writes the same bytes.
        assert_eq!(write_chain(&back).unwrap(), bytes);
        // Bad NextCommand values.
        for next in [8u32, 63, 65, 100, bytes.len() as u32 + 8] {
            let mut b = bytes.clone();
            b[20..24].copy_from_slice(&next.to_le_bytes());
            assert_eq!(parse_chain(&b), Err(Error::NextCommand(next)), "{next}");
        }
        assert_eq!(write_chain(&[]), Err(EncodeError::Empty));
        // The longest chain reads; one more is refused.
        let echo = Message::from_request(Header::new(command::ECHO, 0), &Request::Echo).unwrap();
        let many = vec![echo; MAX_CHAIN];
        let b = write_chain(&many).unwrap();
        assert_eq!(parse_chain(&b).unwrap().len(), MAX_CHAIN);
        let mut more = b.clone();
        let last = more.len() - 68;
        more[last + 20..last + 24].copy_from_slice(&72u32.to_le_bytes());
        more.resize(more.len() + 4, 0);
        more.extend_from_slice(&b[..68]);
        assert_eq!(parse_chain(&more), Err(Error::TooMany));
        let mut too_many = many;
        too_many.push(too_many[0].clone());
        assert_eq!(write_chain(&too_many), Err(EncodeError::TooLong));
    }

    #[test]
    fn transform_and_compression_headers() {
        let t = Transform {
            signature: [1; 16],
            nonce: [2; 16],
            original_size: 100,
            flags: 1,
            session_id: 9,
            data: vec![3; 100],
        };
        let b = t.to_bytes().unwrap();
        assert_eq!(b[..4], protocol::TRANSFORM);
        assert_eq!(le32(&b, 36), Ok(100));
        assert_eq!(le16(&b, 42), Ok(1));
        assert_eq!(le64(&b, 44), Ok(9));
        assert_eq!(Packet::parse(&b), Ok(Packet::Transform(t)));
        assert_eq!(Packet::parse(&b[..51]), Err(Error::Truncated));
        // 3.3.5.2.1.1: a header with no message after it.
        assert_eq!(Packet::parse(&b[..52]), Err(Error::Truncated));

        let c = Compressed::Unchained { original_size: 400, algorithm: 1, offset: 2, data: vec![9; 10] };
        let b = c.to_bytes().unwrap();
        assert_eq!(b[..16], [0xfc, b'S', b'M', b'B', 0x90, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(Packet::parse(&b), Ok(Packet::Compressed(c)));
        let bad = Compressed::Unchained { original_size: 0, algorithm: 0, offset: 0, data: vec![] };
        assert_eq!(bad.to_bytes(), Err(EncodeError::Chained));
        let bad = Compressed::Unchained { original_size: 0, algorithm: 1, offset: 1, data: vec![] };
        assert_eq!(bad.to_bytes(), Err(EncodeError::Offset));
        let mut b =
            Compressed::Unchained { original_size: 0, algorithm: 1, offset: 0, data: vec![] }.to_bytes().unwrap();
        b[12] = 1;
        assert_eq!(Compressed::parse(&b), Err(Error::Buffer));

        let c = Compressed::Chained {
            original_size: 300,
            payloads: vec![
                ChainedPayload { algorithm: 0, flags: 1, data: vec![1; 64] },
                ChainedPayload { algorithm: 4, flags: 0, data: vec![2; 8] },
            ],
        };
        let b = c.to_bytes().unwrap();
        assert_eq!(b[4..16], [0x2c, 1, 0, 0, 0, 0, 1, 0, 64, 0, 0, 0]);
        assert_eq!(Packet::parse(&b), Ok(Packet::Compressed(c)));
        assert_eq!(Compressed::parse(&b[..b.len() - 1]), Err(Error::Buffer));
        assert_eq!(Compressed::parse(&b[..b.len() - 13]), Err(Error::Truncated));
        let empty = Compressed::Chained { original_size: 0, payloads: vec![] };
        assert_eq!(empty.to_bytes(), Err(EncodeError::Empty));
        let unflagged = Compressed::Chained { original_size: 0, payloads: vec![ChainedPayload::default()] };
        assert_eq!(unflagged.to_bytes(), Err(EncodeError::Chained));
    }

    #[test]
    fn packets_by_protocol() {
        let smb1 = [0xff, b'S', b'M', b'B', 0x72];
        assert_eq!(Packet::parse(&smb1), Ok(Packet::Smb1(smb1.to_vec())));
        assert_eq!(Packet::Smb1(smb1.to_vec()).to_bytes().unwrap(), smb1);
        assert_eq!(Packet::Smb1(vec![1, 2, 3]).to_bytes(), Err(EncodeError::Protocol));
        assert_eq!(Packet::parse(b"GET /"), Err(Error::Protocol(*b"GET ")));
        assert_eq!(Packet::parse(&[0xfe, b'S']), Err(Error::Truncated));
        assert_eq!(Packet::parse(&vec![0xff; MAX_MESSAGE + 1]), Err(Error::TooLong));
        let mut h = header_bytes(0, 0, 0, 0, 0, 0, 0);
        h[4] = 65;
        assert_eq!(Packet::parse(&h), Err(Error::HeaderSize(65)));
        assert_eq!(Packet::parse(&h[..63]), Err(Error::Truncated));
        let big = Packet::Smb1([&smb1[..4], &vec![0; MAX_MESSAGE][..]].concat());
        assert_eq!(big.to_bytes(), Err(EncodeError::TooLong));
        let big = Message { header: Header::new(0x99, 0), body: vec![0; MAX_MESSAGE] };
        assert_eq!(big.to_bytes(), Err(EncodeError::TooLong));
    }

    #[test]
    fn body_errors() {
        // Wrong StructureSize, and a fixed part cut short.
        assert_eq!(Request::parse(command::ECHO, &[5, 0, 0, 0]), Err(Error::StructureSize(5)));
        assert_eq!(Request::parse(command::ECHO, &[4, 0, 0]), Err(Error::Truncated));
        assert_eq!(Request::parse(command::ECHO, &[4]), Err(Error::Truncated));
        // A buffer whose offset points into the header, or past the end.
        let mut b = le(&[9, 0, 8, 2], &[2, 2, 2, 2]);
        b.extend_from_slice(&[0, 0]);
        assert_eq!(Request::parse(command::TREE_CONNECT, &b), Err(Error::Buffer));
        b[4] = 72;
        b[6] = 4;
        assert_eq!(Request::parse(command::TREE_CONNECT, &b), Err(Error::Buffer));
        // An odd UTF-16 length.
        b[6] = 1;
        assert_eq!(Request::parse(command::TREE_CONNECT, &b), Err(Error::OddString));
        // Create contexts that run off their region, or link backwards.
        let mut body = Request::Create(create_request()).to_body().unwrap();
        let ctx = le32(&body, 48).unwrap() as usize - 64;
        body[ctx] = 8; // Next below 16
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        body[ctx] = 0xf0;
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        let mut body = Request::Create(create_request()).to_body().unwrap();
        body[ctx + 6] = 30; // name past its context
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        let n = body.len();
        body[52..56].copy_from_slice(&((n - ctx) as u32 - 4).to_le_bytes());
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        // A context region of a few bytes.
        let mut body = Request::Create(create_request()).to_body().unwrap();
        body[52..56].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        // Negotiate contexts past the end.
        let req = Request::Negotiate(NegotiateRequest {
            dialects: vec![0x311],
            contexts: vec![NegotiateContext { kind: 1, data: vec![1; 6] }],
            ..Default::default()
        });
        let mut body = req.to_body().unwrap();
        body[32] = 2;
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::Buffer));
        body[32] = 1;
        body[28] = 8;
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::Buffer));
        // Dialects past the end.
        let mut body =
            Request::Negotiate(NegotiateRequest { dialects: vec![0x202], ..Default::default() }).to_body().unwrap();
        body[2] = 2;
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::Truncated));
        // Writers refuse what will not fit a field.
        let long = Request::SessionSetup(SessionSetupRequest { security_buffer: vec![0; 70000], ..Default::default() });
        assert_eq!(long.to_body(), Err(EncodeError::TooLong));
        let long = Request::TreeConnect(TreeConnectRequest { flags: 0, path: vec![0x41; 40000] });
        assert_eq!(long.to_body(), Err(EncodeError::TooLong));
        let long = Request::Write(WriteRequest {
            data: vec![0; 70000],
            channel: 1,
            channel_info: vec![1; 65500],
            ..Default::default()
        });
        assert_eq!(long.to_body(), Err(EncodeError::TooLong));
        let long = Response::Read { data: vec![0; MAX_MESSAGE + 1], data_remaining: 0, flags: 0 };
        assert_eq!(long.to_body(command::READ, 0), Err(EncodeError::TooLong));
    }

    #[test]
    fn frames_and_errors() {
        let payload = [0xfe, b'S', b'M', b'B'];
        let f = frame(&payload).unwrap();
        assert_eq!(f, [0, 0, 0, 4, 0xfe, b'S', b'M', b'B']);
        for n in 0..f.len() {
            assert_eq!(parse_frame(&f[..n]), Ok(None), "{n}");
        }
        assert_eq!(parse_frame(&f), Ok(Some((&payload[..], 8))));
        assert_eq!(parse_frame(&[0x85]), Err(FrameError::Type(0x85)));
        assert_eq!(parse_frame(&[0, 0xff, 0xff, 0xff]), Err(FrameError::Length(0xff_ffff)));
        assert_eq!(frame(&vec![0; MAX_MESSAGE + 1]), Err(EncodeError::TooLong));
        let longest = frame(&vec![7; MAX_MESSAGE]).unwrap();
        assert_eq!(parse_frame(&longest).unwrap().unwrap().1, MAX_BUFFERED);
        // An empty frame is a frame.
        assert_eq!(parse_frame(&[0, 0, 0, 0]), Ok(Some((&[][..], 4))));
        for e in [FrameError::Type(1), FrameError::Length(2)] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = Packet::Smb2(chain()).to_frame().unwrap();
        let b = Packet::Smb2(vec![Message::from_request(Header::new(command::ECHO, 7), &Request::Echo).unwrap()])
            .to_frame()
            .unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            assert_eq!(d.feed(std::slice::from_ref(byte)), 1);
            while let Some(f) = d.next_frame() {
                got.push(Packet::parse(&f.unwrap()).unwrap());
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], Packet::Smb2(parse_chain(&a[4..]).unwrap()));
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken, and drops what comes after.
        assert_eq!(d.feed(&[0x81, 0, 0, 0]), 4);
        assert_eq!(d.next_frame(), Some(Err(FrameError::Type(0x81))));
        assert_eq!(d.feed(&a), a.len());
        assert_eq!(d.next_frame(), Some(Err(FrameError::Type(0x81))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_holds_at_most_max_buffered() {
        let mut d = Decoder::new();
        let big = frame(&vec![1; MAX_MESSAGE]).unwrap();
        let stream: Vec<u8> = big.iter().chain(&big).copied().collect();
        assert_eq!(d.feed(&stream), MAX_BUFFERED);
        assert_eq!(d.feed(&stream[MAX_BUFFERED..]), 0);
        assert_eq!(d.next_frame().unwrap().unwrap().len(), MAX_MESSAGE);
        assert_eq!(d.feed(&stream[MAX_BUFFERED..]), MAX_BUFFERED);
        assert!(d.next_frame().unwrap().is_ok());
        assert_eq!(d.next_frame(), None);
    }

    #[test]
    fn decoder_takes_many_small_frames_in_linear_time() {
        let one = frame(&[0xff, b'S', b'M', b'B']).unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        let mut rest = &stream[..];
        let mut n = 0;
        while !rest.is_empty() {
            rest = &rest[d.feed(rest)..];
            while let Some(f) = d.next_frame() {
                f.unwrap();
                n += 1;
            }
        }
        assert_eq!(n, 200_000);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn displays() {
        let errors = [
            Error::Truncated,
            Error::Protocol([1, 2, 3, 4]),
            Error::TooLong,
            Error::HeaderSize(1),
            Error::StructureSize(1),
            Error::NextCommand(1),
            Error::TooMany,
            Error::Buffer,
            Error::Overlap,
            Error::Align(3),
            Error::OddString,
            Error::NoLocks,
            Error::NoDialects,
            Error::CompressionFlags(2),
            Error::CompressionAlgorithm,
            Error::TransformFlags(0),
            Error::NegotiateContexts,
        ];
        for e in errors {
            assert!(!e.to_string().is_empty());
        }
        let encode = [
            EncodeError::TooLong,
            EncodeError::Command(1),
            EncodeError::Status(1),
            EncodeError::AsyncFlag,
            EncodeError::Empty,
            EncodeError::Dialect,
            EncodeError::Chained,
            EncodeError::Protocol,
            EncodeError::NoLocks,
            EncodeError::NoDialects,
            EncodeError::Offset,
            EncodeError::Transform,
            EncodeError::Channel,
            EncodeError::ErrorContexts,
            EncodeError::IoctlOutput,
        ];
        for e in encode {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn notify_enum_dir_is_a_change_notify_body() {
        // 3.3.4.4: STATUS_NOTIFY_ENUM_DIR in CHANGE_NOTIFY is not a failure.
        let mut b = le(&[9, 72, 0], &[2, 2, 4]);
        b.push(0);
        assert_eq!(
            Response::parse(command::CHANGE_NOTIFY, status::NOTIFY_ENUM_DIR, &b),
            Ok(Response::ChangeNotify { data: vec![] })
        );
        let resp = Response::ChangeNotify { data: vec![1; 4] };
        let body = resp.to_body(command::CHANGE_NOTIFY, status::NOTIFY_ENUM_DIR).unwrap();
        assert_eq!(Response::parse(command::CHANGE_NOTIFY, status::NOTIFY_ENUM_DIR, &body), Ok(resp));
        let error = Response::Error(ErrorResponse::default());
        assert_eq!(
            error.to_body(command::CHANGE_NOTIFY, status::NOTIFY_ENUM_DIR),
            Err(EncodeError::Status(status::NOTIFY_ENUM_DIR))
        );
        // Under any other failure it is read as an error body, and these
        // bytes, read that way, claim 72 error contexts in no data.
        assert_eq!(Response::parse(command::CHANGE_NOTIFY, status::ACCESS_DENIED, &b), Err(Error::Buffer));
    }

    #[test]
    fn negotiate_needs_a_dialect() {
        // 2.2.3: DialectCount MUST be greater than 0.
        let mut body = le(&[36, 0, 0, 0, 0], &[2, 2, 2, 2, 4]);
        body.extend_from_slice(&[0; 24]);
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::NoDialects));
        assert_eq!(Request::Negotiate(NegotiateRequest::default()).to_body(), Err(EncodeError::NoDialects));
    }

    #[test]
    fn compression_flags_and_algorithms() {
        // 2.2.42.1: unchained Flags MUST be NONE.
        let mut b = [0xfc, b'S', b'M', b'B', 9, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0];
        assert_eq!(Compressed::parse(&b), Err(Error::CompressionFlags(2)));
        b[10] = 3;
        assert_eq!(Compressed::parse(&b), Err(Error::CompressionFlags(3)));
        // Its algorithm is never NONE.
        b[10] = 0;
        b[8] = 0;
        assert_eq!(Compressed::parse(&b), Err(Error::CompressionAlgorithm));
        // 2.2.42.2.1: payloads after the first have Flags NONE.
        let mut b = vec![0xfc, b'S', b'M', b'B', 9, 0, 0, 0];
        b.extend_from_slice(&le(&[0, 1, 1], &[2, 2, 4]));
        b.push(7);
        b.extend_from_slice(&le(&[0, 1, 1], &[2, 2, 4]));
        b.push(8);
        assert_eq!(Compressed::parse(&b), Err(Error::CompressionFlags(1)));
        b[19] = 0;
        assert!(Compressed::parse(&b).is_ok());
        let first = ChainedPayload { algorithm: 0, flags: COMPRESSION_FLAG_CHAINED, data: vec![7] };
        let later = ChainedPayload { algorithm: 0, flags: COMPRESSION_FLAG_CHAINED, data: vec![8] };
        let bad = Compressed::Chained { original_size: 9, payloads: vec![first.clone(), later] };
        assert_eq!(bad.to_bytes(), Err(EncodeError::Chained));
        let odd = ChainedPayload { flags: 3, ..first };
        assert_eq!(Compressed::Chained { original_size: 9, payloads: vec![odd] }.to_bytes(), Err(EncodeError::Chained));
    }

    #[test]
    fn write_puts_channel_info_first_when_data_is_long() {
        // Channel info at 112, then 70000 bytes of data at 116: both
        // offsets fit their 16-bit fields, so the writer must find a layout.
        let mut body = le(&[49, 116, 70000, 0, 0, 0, 1, 0, 112, 4, 0], &[2, 2, 4, 8, 8, 8, 4, 4, 2, 2, 4]);
        body.extend_from_slice(&[1, 2, 3, 4]);
        body.extend_from_slice(&vec![9; 70000]);
        let req = Request::parse(command::WRITE, &body).unwrap();
        assert_eq!(req.to_body().unwrap(), body);
        // Both too long for any layout: refused.
        let w = WriteRequest { data: vec![0; 70000], channel: 1, channel_info: vec![1; 65500], ..Default::default() };
        assert_eq!(Request::Write(w).to_body(), Err(EncodeError::TooLong));
    }

    #[test]
    fn buffers_stay_out_of_the_fixed_part_and_apart() {
        // QUERY_INFO output at offset 64: inside the fixed part.
        let mut b = le(&[9, 64, 9], &[2, 2, 4]);
        b.push(0);
        assert_eq!(Response::parse(command::QUERY_INFO, 0, &b), Err(Error::Buffer));
        b[2] = 72;
        b[4] = 1;
        assert_eq!(Response::parse(command::QUERY_INFO, 0, &b), Ok(Response::QueryInfo { data: vec![0] }));
        // A READ response whose DataOffset points into its fixed part.
        let mut r = le(&[17, 64, 0, 4, 0, 0], &[2, 1, 1, 4, 4, 4]);
        r.push(0);
        assert_eq!(Response::parse(command::READ, 0, &r), Err(Error::Buffer));
        // IOCTL input and output over the same bytes would write back twice
        // as long; they are refused. (A request has no output at all.)
        let resp = Response::Ioctl(IoctlResponse { output: vec![1; 8], ..Default::default() });
        let mut body = resp.to_body(command::IOCTL, 0).unwrap();
        body[24..28].copy_from_slice(&112u32.to_le_bytes());
        body[28..32].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(Response::parse(command::IOCTL, 0, &body), Err(Error::Overlap));
        // WRITE data and channel info over the same bytes.
        let req = Request::Write(WriteRequest {
            data: vec![1; 8],
            channel: 1,
            channel_info: vec![2; 4],
            ..Default::default()
        });
        let mut body = req.to_body().unwrap();
        body[40..42].copy_from_slice(&116u16.to_le_bytes());
        assert_eq!(Request::parse(command::WRITE, &body), Err(Error::Overlap));
        // CREATE contexts that start inside the name.
        let mut body = Request::Create(create_request()).to_body().unwrap();
        body[48..52].copy_from_slice(&128u32.to_le_bytes());
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Overlap));
        // A NEGOTIATE response whose contexts start inside the security buffer.
        let resp = Response::Negotiate(NegotiateResponse {
            dialect: dialect::SMB_3_1_1,
            security_buffer: vec![0x60; 16],
            contexts: vec![NegotiateContext::preauth_integrity(&[1], &[2; 8]).unwrap()],
            ..Default::default()
        });
        let mut body = resp.to_body(command::NEGOTIATE, 0).unwrap();
        body[60..64].copy_from_slice(&136u32.to_le_bytes());
        assert_eq!(Response::parse(command::NEGOTIATE, 0, &body), Err(Error::Overlap));
        // NEGOTIATE request contexts over the dialect list.
        let req = Request::Negotiate(NegotiateRequest {
            dialects: vec![0x311; 8],
            contexts: vec![NegotiateContext { kind: 1, data: vec![] }],
            ..Default::default()
        });
        let mut body = req.to_body().unwrap();
        body[28..32].copy_from_slice(&104u32.to_le_bytes());
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::Overlap));
    }

    #[test]
    fn contexts_are_eight_byte_aligned() {
        // 2.2.3: the first negotiate context is 8-byte aligned.
        let req = Request::Negotiate(NegotiateRequest {
            dialects: vec![0x311],
            contexts: vec![NegotiateContext { kind: 1, data: vec![1; 6] }],
            ..Default::default()
        });
        let mut body = req.to_body().unwrap();
        body.insert(40, 0);
        body[28..32].copy_from_slice(&105u32.to_le_bytes());
        assert_eq!(Request::parse(command::NEGOTIATE, &body), Err(Error::Align(105)));
        // 2.2.13.2: create contexts, their Next and their DataOffset too.
        let good = Request::Create(create_request()).to_body().unwrap();
        let ctx = le32(&good, 48).unwrap() as usize - 64;
        let mut body = good.clone();
        body.insert(ctx, 0);
        body[48..52].copy_from_slice(&(ctx as u32 + 65).to_le_bytes());
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Align(ctx as u32 + 65)));
        let mut body = good.clone();
        body[ctx] = 20;
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Align(20)));
        let second = ctx + 24;
        let mut body = good.clone();
        body[second + 10] = 20;
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Align(20)));
        // A name inside the context's own header, or data over the name.
        let mut body = good.clone();
        body[second + 4] = 8;
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Buffer));
        let mut body = good;
        body[second + 10] = 16;
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Overlap));
    }

    #[test]
    fn bodies_read_from_the_longest_message_write_back() {
        // Every body read from a message of MAX_MESSAGE bytes writes back
        // no longer than it came.
        let n = MAX_MESSAGE - HEADER_LEN;
        let mut q = le(&[9, 72, (n - 8) as u64], &[2, 2, 4]);
        q.resize(n, 5);
        let m = Message { header: Header::new(command::QUERY_INFO, 0).reply(0), body: q };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        let Packet::Smb2(back) = Packet::parse(&bytes).unwrap() else { panic!() };
        let resp = back[0].response().unwrap();
        let again = Message::reply_to(&Header::new(command::QUERY_INFO, 0), 0, &resp).unwrap();
        assert_eq!(again.to_bytes().unwrap(), bytes);
    }

    // Each test below follows one finding of a review against MS-SMB2.

    #[test]
    fn every_entry_point_refuses_a_payload_past_max_message() {
        let mut chain = header_bytes(command::ECHO, 0, 0, 0, 1, 0, 0);
        chain.extend_from_slice(&[4, 0, 0, 0]);
        chain.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(parse_chain(&chain), Err(Error::TooLong));
        let mut t = protocol::TRANSFORM.to_vec();
        t.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Transform::parse(&t), Err(Error::TooLong));
        let mut c = protocol::COMPRESSION.to_vec();
        c.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Compressed::parse(&c), Err(Error::TooLong));
        let mut body = vec![4, 0, 0, 0];
        body.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Request::parse(command::ECHO, &body), Err(Error::TooLong));
        assert_eq!(Response::parse(command::ECHO, 0, &body), Err(Error::TooLong));
        // Writers refuse before they copy or convert.
        let long = Request::Create(CreateRequest { name: vec![0x41; 40000], ..Default::default() });
        assert_eq!(long.to_body(), Err(EncodeError::TooLong));
        let long = Request::QueryDirectory(QueryDirectoryRequest { pattern: vec![0x41; 40000], ..Default::default() });
        assert_eq!(long.to_body(), Err(EncodeError::TooLong));
        let long = Response::Other { body: vec![0; MAX_MESSAGE + 1] };
        assert_eq!(long.to_body(0x99, 0), Err(EncodeError::TooLong));
    }

    #[test]
    fn tree_connect_extension_is_written_at_the_buffer() {
        // 2.2.9.1: with EXTENSION_PRESENT the Buffer starts with the
        // extension's 16-byte header, then the path.
        let req = Request::TreeConnect(TreeConnectRequest { flags: 4, path: utf16("\\\\server\\share") });
        let body = req.to_body().unwrap();
        let path = u16s("\\\\server\\share");
        assert_eq!(le16(&body, 2), Ok(4));
        assert_eq!(le16(&body, 4), Ok(88));
        assert_eq!(le16(&body, 6), Ok(path.len() as u16));
        assert_eq!(body[8..24], [0; 16]);
        assert_eq!(body[24..], path[..]);
        assert_eq!(Request::parse(command::TREE_CONNECT, &body), Ok(req));
        // A request with contexts after the path reads, without them.
        let mut ext = le(&[9, 4, 88, path.len() as u64], &[2, 2, 2, 2]);
        ext.extend_from_slice(&le(&[112, 1, 0, 0], &[4, 2, 8, 2]));
        ext.extend_from_slice(&path);
        ext.resize(48, 0);
        ext.extend_from_slice(&le(&[1, 4, 0], &[2, 2, 4]));
        ext.extend_from_slice(&[1, 2, 3, 4]);
        let read = Request::parse(command::TREE_CONNECT, &ext).unwrap();
        let back = read.to_body().unwrap();
        assert!(back.len() <= ext.len());
        assert_eq!(Request::parse(command::TREE_CONNECT, &back), Ok(read));
        // The path over the extension's header is refused.
        let mut bad = le(&[9, 4, 72, path.len() as u64], &[2, 2, 2, 2]);
        bad.extend_from_slice(&path);
        assert_eq!(Request::parse(command::TREE_CONNECT, &bad), Err(Error::Buffer));
    }

    #[test]
    fn ioctl_response_output_is_eight_byte_aligned() {
        // 2.2.32: OutputOffset is InputOffset + InputCount rounded up to 8.
        let resp = Response::Ioctl(IoctlResponse { input: vec![1], output: vec![2], ..Default::default() });
        let body = resp.to_body(command::IOCTL, 0).unwrap();
        assert_eq!((le32(&body, 24), le32(&body, 28)), (Ok(112), Ok(1)));
        assert_eq!((le32(&body, 32), le32(&body, 36)), (Ok(120), Ok(1)));
        assert_eq!(body[56], 2);
        assert_eq!(Response::parse(command::IOCTL, 0, &body), Ok(resp));
        // Output right after the input, unaligned, is refused.
        let mut bad = le(&[49, 0, 0, 0, 0, 112, 1, 113, 1, 0, 0], &[2, 2, 4, 8, 8, 4, 4, 4, 4, 4, 4]);
        bad.extend_from_slice(&[1, 2]);
        assert_eq!(Response::parse(command::IOCTL, 0, &bad), Err(Error::Align(113)));
        // Aligned output before the end of the input is refused.
        let mut bad = le(&[49, 0, 0, 0, 0, 112, 9, 112, 1, 0, 0], &[2, 2, 4, 8, 8, 4, 4, 4, 4, 4, 4]);
        bad.resize(48 + 9, 0);
        assert_eq!(Response::parse(command::IOCTL, 0, &bad), Err(Error::Overlap));
        // No output: OutputOffset 0.
        let none = Response::Ioctl(IoctlResponse { input: vec![1], ..Default::default() });
        assert_eq!(le32(&none.to_body(command::IOCTL, 0).unwrap(), 32), Ok(0));
    }

    #[test]
    fn failures_get_error_bodies_but_for_the_listed_exceptions() {
        // 3.3.4.4: ACCESS_DENIED is a failure for ECHO, which has no
        // exception, so its body is an error body.
        assert_eq!(Response::Echo.to_body(command::ECHO, status::ACCESS_DENIED), Err(EncodeError::Status(0xc000_0022)));
        assert_eq!(Response::parse(command::ECHO, status::ACCESS_DENIED, &[4, 0, 0, 0]), Err(Error::StructureSize(4)));
        let read = Response::Read { data: vec![1], data_remaining: 0, flags: 0 };
        assert_eq!(read.to_body(command::READ, status::END_OF_FILE), Err(EncodeError::Status(status::END_OF_FILE)));
        let create = Response::Create(CreateResponse::default());
        assert_eq!(create.to_body(command::CREATE, status::BUFFER_OVERFLOW), Err(EncodeError::Status(0x8000_0005)));
        // The exceptions keep their own bodies.
        assert!(read.to_body(command::READ, status::BUFFER_OVERFLOW).is_ok());
        let ioctl = Response::Ioctl(IoctlResponse::default());
        assert!(ioctl.to_body(command::IOCTL, status::BUFFER_OVERFLOW).is_ok());
        assert!(ioctl.to_body(command::IOCTL, status::INVALID_PARAMETER).is_ok());
        assert_eq!(ioctl.to_body(command::IOCTL, status::ACCESS_DENIED), Err(EncodeError::Status(0xc000_0022)));
    }

    #[test]
    fn smb_311_negotiate_responses_carry_one_preauth_context() {
        let preauth = NegotiateContext::preauth_integrity(&[1], &[7; 32]).unwrap();
        let signing = NegotiateContext::algorithms(negotiate_context::SIGNING_CAPABILITIES, &[1]).unwrap();
        let response = |contexts: Vec<NegotiateContext>| {
            Response::Negotiate(NegotiateResponse { dialect: dialect::SMB_3_1_1, contexts, ..Default::default() })
        };
        // 3.2.5.2: a client refuses none, two, or two of one other kind.
        assert_eq!(response(vec![]).to_body(0, 0), Err(EncodeError::Dialect));
        assert_eq!(response(vec![preauth.clone(), preauth.clone()]).to_body(0, 0), Err(EncodeError::Dialect));
        let two_signing = response(vec![preauth.clone(), signing.clone(), signing.clone()]);
        assert_eq!(two_signing.to_body(0, 0), Err(EncodeError::Dialect));
        let good = response(vec![preauth, signing]);
        let mut body = good.to_body(0, 0).unwrap();
        assert_eq!(Response::parse(0, 0, &body), Ok(good));
        // The same bytes with the preauth context made a signing one.
        let first = le32(&body, 60).unwrap() as usize - HEADER_LEN;
        body[first..first + 2].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(Response::parse(0, 0, &body), Err(Error::NegotiateContexts));
        // A 3.1.1 response with a count of 0.
        body[6..8].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(Response::parse(0, 0, &body), Err(Error::NegotiateContexts));
    }

    #[test]
    fn channel_none_ignores_channel_info() {
        // 2.2.19: with SMB2_CHANNEL_NONE the server ignores
        // ReadChannelInfoOffset and ReadChannelInfoLength.
        let mut read = le(&[49, 0, 0, 10, 0, 1, 2, 0, 0, 0, 0xffff, 1], &[2, 1, 1, 4, 8, 8, 8, 4, 4, 4, 2, 2]);
        read.push(0);
        let Ok(Request::Read(r)) = Request::parse(command::READ, &read) else { panic!() };
        assert!(r.channel_info.is_empty());
        // With RDMA_V1 the same fields are read, and point nowhere.
        read[36] = 1;
        assert_eq!(Request::parse(command::READ, &read), Err(Error::Buffer));
        // 2.2.21: the same for WRITE.
        let mut write = le(&[49, 112, 3, 0, 1, 2, 0, 0, 0xffff, 1, 0], &[2, 2, 4, 8, 8, 8, 4, 4, 2, 2, 4]);
        write.extend_from_slice(b"abc");
        let Ok(Request::Write(w)) = Request::parse(command::WRITE, &write) else { panic!() };
        assert_eq!((w.data, w.channel_info), (b"abc".to_vec(), vec![]));
        // Writers refuse channel info with channel NONE.
        let r = Request::Read(ReadRequest { channel_info: vec![1], ..Default::default() });
        assert_eq!(r.to_body(), Err(EncodeError::Channel));
        let w = Request::Write(WriteRequest { channel_info: vec![1], ..Default::default() });
        assert_eq!(w.to_body(), Err(EncodeError::Channel));
    }

    /// A CREATE request body, with its file name at `name_at` and its
    /// context region at 120 + 8.
    fn create_with(name_at: u64, name: &[u8], region: &[u8]) -> Vec<u8> {
        let mut b = le(
            &[57, 0, 0, 0, 0, 0, 0, 0, 7, 1, 0, name_at, name.len() as u64],
            &[2, 1, 1, 4, 8, 8, 4, 4, 4, 4, 4, 2, 2],
        );
        let ctx_at = if region.is_empty() { 0 } else { 128 };
        b.extend_from_slice(&le(&[ctx_at, region.len() as u64], &[4, 4]));
        b.resize(name_at as usize - HEADER_LEN, 0);
        b.extend_from_slice(name);
        if !region.is_empty() {
            b.resize(128 - HEADER_LEN, 0);
            b.extend_from_slice(region);
        }
        b.resize(b.len().max(57), 0);
        b
    }

    #[test]
    fn create_context_data_may_come_before_its_name() {
        // 2.2.13.2: name and data have their own offsets, in no set order.
        let mut ctx = le(&[0, 24, 4, 0, 16, 8], &[4, 2, 2, 2, 2, 4]);
        ctx.extend_from_slice(&4096u64.to_le_bytes());
        ctx.extend_from_slice(b"AlSi");
        let body = create_with(120, &[], &ctx);
        let Ok(Request::Create(c)) = Request::parse(command::CREATE, &body) else { panic!() };
        let want = CreateContext { name: b"AlSi".to_vec(), data: 4096u64.to_le_bytes().to_vec() };
        assert_eq!(c.contexts, [want]);
        // Written back with the name first: at most 7 bytes longer.
        let back = Request::Create(c.clone()).to_body().unwrap();
        assert!(back.len() <= body.len() + 7);
        assert_eq!(Request::parse(command::CREATE, &back), Ok(Request::Create(c)));
        // Name and data over the same bytes are still refused.
        let mut ctx = le(&[0, 16, 4, 0, 16, 8], &[4, 2, 2, 2, 2, 4]);
        ctx.extend_from_slice(&[0; 8]);
        assert_eq!(Request::parse(command::CREATE, &create_with(120, &[], &ctx)), Err(Error::Overlap));
    }

    #[test]
    fn create_names_are_aligned_and_next_points_at_a_context() {
        // 2.2.13: the file name is 8-byte aligned.
        let body = create_with(122, &u16s("a"), &[]);
        assert_eq!(Request::parse(command::CREATE, &body), Err(Error::Align(122)));
        assert!(Request::parse(command::CREATE, &create_with(128, &u16s("a"), &[])).is_ok());
        // 2.2.13.2: a create context's name is 8-byte aligned.
        let mut ctx = le(&[0, 17, 4, 0, 0, 0], &[4, 2, 2, 2, 2, 4]);
        ctx.extend_from_slice(b"\0MxAc");
        assert_eq!(Request::parse(command::CREATE, &create_with(120, &[], &ctx)), Err(Error::Align(17)));
        // A Next of 24 that reaches the end of the region, with no context
        // there.
        let mut ctx = le(&[24, 16, 4, 0, 0, 0], &[4, 2, 2, 2, 2, 4]);
        ctx.extend_from_slice(b"MxAc");
        ctx.resize(24, 0);
        assert_eq!(Request::parse(command::CREATE, &create_with(120, &[], &ctx)), Err(Error::Buffer));
        ctx[0] = 0;
        assert!(Request::parse(command::CREATE, &create_with(120, &[], &ctx)).is_ok());
    }

    #[test]
    fn create_request_buffer_is_at_least_one_byte() {
        // 2.2.13: "the Buffer field MUST be at least one byte in length".
        let body = create_with(120, &[], &[]);
        assert_eq!(body.len(), 57);
        assert!(Request::parse(command::CREATE, &body).is_ok());
        assert_eq!(Request::parse(command::CREATE, &body[..56]), Err(Error::Truncated));
    }

    #[test]
    fn transform_headers_need_flags_one_and_a_message() {
        // 2.2.41 and 3.3.5.2.1.1.
        assert_eq!(Transform::default().to_bytes(), Err(EncodeError::Transform));
        assert_eq!(Transform { flags: 1, ..Default::default() }.to_bytes(), Err(EncodeError::Transform));
        assert_eq!(Transform { flags: 2, data: vec![1], ..Default::default() }.to_bytes(), Err(EncodeError::Transform));
        let good = Transform { flags: 1, data: vec![1], ..Default::default() };
        let mut b = good.to_bytes().unwrap();
        assert_eq!(Packet::parse(&b), Ok(Packet::Transform(good)));
        b[42] = 0;
        assert_eq!(Packet::parse(&b), Err(Error::TransformFlags(0)));
        b[42] = 2;
        assert_eq!(Packet::parse(&b), Err(Error::TransformFlags(2)));
    }

    #[test]
    fn chained_payloads_hold_their_original_payload_size() {
        // 2.2.42.2.1: LZNT1, LZ77, LZ77+Huffman and LZ4 carry a 4-byte
        // OriginalPayloadSize inside Length.
        for algorithm in [1, 2, 3, 5] {
            let short = ChainedPayload { algorithm, flags: 1, data: vec![0; 3] };
            let c = Compressed::Chained { original_size: 9, payloads: vec![short] };
            assert_eq!(c.to_bytes(), Err(EncodeError::Chained), "{algorithm}");
            let ok = ChainedPayload { algorithm, flags: 1, data: vec![9, 0, 0, 0] };
            let c = Compressed::Chained { original_size: 9, payloads: vec![ok] };
            let mut b = c.to_bytes().unwrap();
            assert_eq!(Compressed::parse(&b), Ok(c));
            b[12] = 3;
            b.pop();
            assert_eq!(Compressed::parse(&b), Err(Error::Buffer), "{algorithm}");
        }
        // NONE and Pattern_V1 have no such field.
        let none = Compressed::Chained {
            original_size: 0,
            payloads: vec![ChainedPayload { algorithm: 0, flags: 1, data: vec![] }],
        };
        assert_eq!(Compressed::parse(&none.to_bytes().unwrap()), Ok(none));
    }

    #[test]
    fn error_contexts_fit_their_count() {
        // 2.2.2: ErrorContextCount contexts, each 8-byte aligned.
        let missing = Response::Error(ErrorResponse { context_count: 1, data: vec![] });
        assert_eq!(missing.to_body(command::CREATE, status::ACCESS_DENIED), Err(EncodeError::ErrorContexts));
        assert_eq!(
            Response::parse(command::CREATE, status::ACCESS_DENIED, &[9, 0, 1, 0, 0, 0, 0, 0, 0]),
            Err(Error::Buffer)
        );
        // Two contexts: 3 bytes of data, padding to 16, then an empty one.
        let mut data = le(&[3, 0], &[4, 4]);
        data.extend_from_slice(&[1, 2, 3, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&le(&[0, 0x7264_5253], &[4, 4]));
        let two = Response::Error(ErrorResponse { context_count: 2, data: data.clone() });
        let body = two.to_body(command::TREE_CONNECT, status::BAD_NETWORK_NAME).unwrap();
        assert_eq!(Response::parse(command::TREE_CONNECT, status::BAD_NETWORK_NAME, &body), Ok(two));
        // Without the padding the second context does not fit.
        data.drain(11..16);
        let unpadded = Response::Error(ErrorResponse { context_count: 2, data });
        assert_eq!(unpadded.to_body(command::TREE_CONNECT, status::BAD_NETWORK_NAME), Err(EncodeError::ErrorContexts));
    }

    #[test]
    fn ioctl_requests_carry_no_output() {
        // 2.2.31: "OutputCount: The client MUST set this to 0."
        let req = Request::Ioctl(IoctlRequest { output: vec![1], ..Default::default() });
        assert_eq!(req.to_body(), Err(EncodeError::IoctlOutput));
        let mut body = Request::Ioctl(IoctlRequest { input: vec![1; 8], ..Default::default() }).to_body().unwrap();
        assert_eq!((le32(&body, 36), le32(&body, 40)), (Ok(0), Ok(0)));
        body[36..40].copy_from_slice(&128u32.to_le_bytes());
        assert!(Request::parse(command::IOCTL, &body).is_ok());
        body[40..44].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(Request::parse(command::IOCTL, &body), Err(Error::Buffer));
    }

    /// One request of each kind, with buffers filled.
    fn requests() -> Vec<Request> {
        let fid = FileId { persistent: 3, volatile: 4 };
        vec![
            Request::Negotiate(NegotiateRequest {
                security_mode: 1,
                capabilities: 0x7f,
                client_guid: [5; 16],
                dialects: vec![0x202, 0x210, 0x300, 0x302, 0x311],
                client_start_time: 0,
                contexts: vec![
                    NegotiateContext::preauth_integrity(&[1], &[7; 32]).unwrap(),
                    NegotiateContext::algorithms(2, &[2, 1]).unwrap(),
                    NegotiateContext { kind: 5, data: u16s("fs1") },
                ],
            }),
            Request::Negotiate(NegotiateRequest { dialects: vec![0x202], client_start_time: 5, ..Default::default() }),
            Request::SessionSetup(SessionSetupRequest {
                flags: 1,
                security_mode: 2,
                security_buffer: vec![0x60; 40],
                previous_session_id: 8,
                ..Default::default()
            }),
            Request::Logoff,
            Request::TreeConnect(TreeConnectRequest { flags: 0, path: utf16("\\\\fs1\\share") }),
            Request::TreeDisconnect,
            Request::Create(create_request()),
            Request::Create(CreateRequest::default()),
            Request::Close { flags: 1, file_id: fid },
            Request::Flush { file_id: fid },
            Request::Read(ReadRequest {
                length: 10,
                file_id: fid,
                channel: 1,
                channel_info: vec![1, 2],
                ..Default::default()
            }),
            Request::Write(WriteRequest {
                offset: 5,
                file_id: fid,
                data: b"data".to_vec(),
                channel: 1,
                channel_info: vec![9],
                ..Default::default()
            }),
            Request::Lock(LockRequest {
                lock_sequence: 1,
                file_id: fid,
                locks: vec![Lock { offset: 1, length: 2, flags: 2 }; 3],
            }),
            Request::Ioctl(IoctlRequest {
                ctl_code: 0x0011_c017,
                file_id: fid,
                input: vec![1; 5],
                flags: 1,
                ..Default::default()
            }),
            Request::Cancel,
            Request::Echo,
            Request::QueryDirectory(QueryDirectoryRequest {
                file_information_class: 0x25,
                file_id: fid,
                pattern: utf16("*.txt"),
                output_buffer_length: 100,
                ..Default::default()
            }),
            Request::ChangeNotify(ChangeNotifyRequest {
                flags: 1,
                output_buffer_length: 9,
                file_id: fid,
                completion_filter: 3,
            }),
            Request::QueryInfo(QueryInfoRequest {
                info_type: 1,
                file_info_class: 18,
                input: vec![4; 4],
                file_id: fid,
                ..Default::default()
            }),
            Request::SetInfo(SetInfoRequest {
                info_type: 1,
                file_info_class: 4,
                file_id: fid,
                data: vec![1; 40],
                ..Default::default()
            }),
            Request::Other { command: command::OPLOCK_BREAK, body: vec![24, 0, 1, 0] },
        ]
    }

    /// One response of each kind, with the status it goes with.
    fn responses() -> Vec<(u16, u32, Response)> {
        vec![
            (
                0,
                0,
                Response::Negotiate(NegotiateResponse {
                    dialect: 0x311,
                    security_buffer: vec![0x60; 10],
                    contexts: vec![
                        NegotiateContext::preauth_integrity(&[1], &[3; 32]).unwrap(),
                        NegotiateContext::algorithms(8, &[1]).unwrap(),
                    ],
                    ..Default::default()
                }),
            ),
            (
                1,
                status::MORE_PROCESSING_REQUIRED,
                Response::SessionSetup { session_flags: 0, security_buffer: vec![0xa1; 9] },
            ),
            (1, 0, Response::SessionSetup { session_flags: 1, security_buffer: vec![] }),
            (2, 0, Response::Logoff),
            (
                3,
                0,
                Response::TreeConnect(TreeConnectResponse {
                    share_type: 1,
                    share_flags: 0,
                    capabilities: 0,
                    maximal_access: 0x1f01ff,
                }),
            ),
            (4, 0, Response::TreeDisconnect),
            (
                5,
                0,
                Response::Create(CreateResponse {
                    create_action: 2,
                    contexts: vec![CreateContext { name: b"QFid".to_vec(), data: vec![1; 32] }],
                    ..Default::default()
                }),
            ),
            (6, 0, Response::Close { flags: 1, info: FileInfo { end_of_file: 5, ..Default::default() } }),
            (7, 0, Response::Flush),
            (8, status::BUFFER_OVERFLOW, Response::Read { data: vec![1; 7], data_remaining: 0, flags: 0 }),
            (9, 0, Response::Write { count: 4, remaining: 0 }),
            (10, 0, Response::Lock),
            (
                11,
                0,
                Response::Ioctl(IoctlResponse {
                    ctl_code: 1,
                    input: vec![1],
                    output: vec![2, 2],
                    ..Default::default()
                }),
            ),
            (13, 0, Response::Echo),
            (14, 0, Response::QueryDirectory { data: vec![0; 104] }),
            (15, 0, Response::ChangeNotify { data: vec![] }),
            (16, status::BUFFER_OVERFLOW, Response::QueryInfo { data: vec![1; 3] }),
            (17, 0, Response::SetInfo),
            (5, status::OBJECT_NAME_NOT_FOUND, Response::Error(ErrorResponse::default())),
            (
                15,
                status::PENDING,
                Response::Error(ErrorResponse { context_count: 1, data: le(&[4, 0, 0x0101_0101], &[4, 4, 4]) }),
            ),
            (0x12, 0, Response::Other { body: vec![24, 0, 1, 0] }),
        ]
    }

    #[test]
    fn what_writers_accept_reads_back_the_same() {
        for req in requests() {
            let body = req.to_body().unwrap();
            assert_eq!(Request::parse(req.command(), &body), Ok(req.clone()), "{req:?}");
        }
        for (c, s, resp) in responses() {
            let body = resp.to_body(c, s).unwrap();
            assert_eq!(Response::parse(c, s, &body), Ok(resp.clone()), "{resp:?}");
        }
    }

    /// Every message bytes these tests know: requests and responses, whole.
    fn corpus() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (i, req) in requests().into_iter().enumerate() {
            let m = Message::from_request(Header::new(req.command(), i as u64), &req).unwrap();
            out.push(m.to_bytes().unwrap());
        }
        for (c, s, resp) in responses() {
            let m = Message::reply_to(&Header::new(c, 1), s, &resp).unwrap();
            out.push(m.to_bytes().unwrap());
        }
        out.push(write_chain(&chain()).unwrap());
        out.push(Transform { flags: 1, data: vec![1; 20], ..Default::default() }.to_bytes().unwrap());
        out.push(
            Compressed::Unchained { original_size: 9, algorithm: 2, offset: 1, data: vec![3; 9] }.to_bytes().unwrap(),
        );
        out.push(
            Compressed::Chained {
                original_size: 9,
                payloads: vec![ChainedPayload { algorithm: 0, flags: 1, data: vec![1; 9] }],
            }
            .to_bytes()
            .unwrap(),
        );
        out
    }

    /// Whether a body written back is no longer than the one read, or no
    /// longer than its own fixed part and one byte. Then a message read
    /// whole always fits [`MAX_MESSAGE`] when written back. A CREATE may
    /// grow by 7 bytes when its last create context put data before name
    /// (see [`Request::parse`]).
    fn no_longer(command: u16, new: &[u8], old: &[u8]) -> bool {
        let slack = if command == command::CREATE { 7 } else { 0 };
        new.len() <= old.len() + slack || le16(new, 0).is_ok_and(|size| new.len() <= usize::from(size))
    }

    /// Reads a payload every way there is, checks that what reads writes
    /// back and reads the same, and never panics.
    fn read_everything(payload: &[u8], status: u32) {
        let Ok(packet) = Packet::parse(payload) else { return };
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(packet.clone()));
        let Packet::Smb2(messages) = packet else { return };
        // A chain read writes back byte for byte.
        assert_eq!(bytes, payload);
        for m in &messages {
            if let Ok(req) = m.request() {
                let body = req.to_body().unwrap();
                assert!(no_longer(m.header.command, &body, &m.body), "{req:?}");
                assert_eq!(Request::parse(m.header.command, &body), Ok(req));
            }
            for s in [m.header.status, status] {
                if let Ok(resp) = Response::parse(m.header.command, s, &m.body) {
                    let body = resp.to_body(m.header.command, s).unwrap();
                    assert!(no_longer(m.header.command, &body, &m.body), "{resp:?}");
                    assert_eq!(Response::parse(m.header.command, s, &body), Ok(resp));
                }
            }
        }
    }

    #[test]
    fn every_truncated_prefix() {
        for whole in corpus() {
            for n in 0..whole.len() {
                // A cut message never panics, and a cut SMB2 header is refused.
                let _ = Packet::parse(&whole[..n]);
                if n < HEADER_LEN && whole[..4] == protocol::SMB2 {
                    assert!(Packet::parse(&whole[..n]).is_err());
                }
                read_everything(&whole[..n], status::BUFFER_OVERFLOW);
            }
            let f = frame(&whole).unwrap();
            for n in 0..f.len() {
                assert_eq!(parse_frame(&f[..n]), Ok(None));
            }
        }
        // Each body cut short of its fixed part is refused.
        for req in requests() {
            let body = req.to_body().unwrap();
            let size = usize::from(le16(&body, 0).unwrap() & !1);
            if matches!(req, Request::Other { .. }) {
                continue;
            }
            for n in 0..size {
                assert!(Request::parse(req.command(), &body[..n]).is_err(), "{req:?} at {n}");
            }
        }
        for (c, s, resp) in responses() {
            let body = resp.to_body(c, s).unwrap();
            if matches!(resp, Response::Other { .. }) {
                continue;
            }
            let size = usize::from(le16(&body, 0).unwrap() & !1);
            for n in 0..size {
                assert!(Response::parse(c, s, &body[..n]).is_err(), "{resp:?} at {n}");
            }
        }
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }

        fn below(&mut self, n: usize) -> usize {
            let x = (usize::from(self.next()) << 8) | usize::from(self.next());
            x % n.max(1)
        }
    }

    /// Bytes for the fuzz loop: a known message with a few bytes changed or
    /// cut, or random bytes behind a valid protocol ID.
    fn buffer(rng: &mut Lcg, corpus: &[Vec<u8>]) -> Vec<u8> {
        let mut b = if rng.next().is_multiple_of(4) {
            let len = rng.below(200);
            let mut b: Vec<u8> = (0..len).map(|_| rng.next()).collect();
            if b.len() >= 4 {
                b[..4].copy_from_slice(&[protocol::SMB2, protocol::TRANSFORM, protocol::COMPRESSION][rng.below(3)]);
            }
            b
        } else {
            corpus[rng.below(corpus.len())].clone()
        };
        if !b.is_empty() {
            for _ in 0..rng.below(4) {
                let i = rng.below(b.len());
                b[i] = rng.next();
            }
            // Small values in offset and length fields reach more code.
            if rng.next().is_multiple_of(3) {
                let i = rng.below(b.len());
                b[i] = rng.next() % 130;
            }
            if rng.next().is_multiple_of(4) {
                b.truncate(rng.below(b.len() + 1));
            }
        }
        b
    }

    /// Feeds `data` whole or a byte at a time. Every payload, then the error
    /// that broke the stream, if one did.
    fn split(data: &[u8], bytewise: bool) -> (Vec<Vec<u8>>, Option<FrameError>) {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        // A chunk at a time, without collecting the chunks.
        for chunk in data.chunks(if bytewise { 1 } else { data.len().max(1) }) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let took = d.feed(rest);
                assert!(d.buffered() <= MAX_BUFFERED);
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(r) = d.next_frame() {
                    match r {
                        Ok(p) => out.push(p),
                        Err(e) => return (out, Some(e)),
                    }
                    progress = true;
                }
                assert!(progress);
            }
        }
        (out, None)
    }

    #[test]
    fn fuzz_loop() {
        let corpus = corpus();
        let mut rng = Lcg(0x5eed);
        for _ in 0..50_000 {
            let payload = buffer(&mut rng, &corpus);
            let status = [
                0,
                status::BUFFER_OVERFLOW,
                status::MORE_PROCESSING_REQUIRED,
                status::ACCESS_DENIED,
                status::NOTIFY_ENUM_DIR,
            ][rng.below(5)];
            read_everything(&payload, status);
            // Bodies alone, under any command.
            let command = rng.below(0x16) as u16;
            let body = &payload[payload.len().min(HEADER_LEN)..];
            if let Ok(req) = Request::parse(command, body) {
                let back = req.to_body().unwrap();
                assert!(no_longer(command, &back, body), "{req:?}");
                assert_eq!(Request::parse(command, &back), Ok(req));
            }
            if let Ok(resp) = Response::parse(command, status, body) {
                let back = resp.to_body(command, status).unwrap();
                assert!(no_longer(command, &back, body), "{resp:?}");
                assert_eq!(Response::parse(command, status, &back), Ok(resp));
            }
            // The stream: framed payloads and raw bytes, whole and a byte at a time.
            let mut stream = frame(&payload).unwrap();
            if rng.next().is_multiple_of(2) {
                stream.extend(frame(&corpus[rng.below(corpus.len())]).unwrap());
            }
            if rng.next().is_multiple_of(3) {
                let i = rng.below(stream.len());
                stream[i] = rng.next();
            }
            let whole = split(&stream, false);
            assert_eq!(split(&stream, true), whole);
            for p in &whole.0 {
                read_everything(p, status);
            }
        }
    }
}
