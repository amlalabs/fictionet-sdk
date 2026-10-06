//! OPC UA over TCP: reading and writing the binary transport, its built-in
//! types and the OpenSecureChannel service, with no I/O.
//!
//! OPC UA is how much modern industrial equipment is read and controlled.
//! A server (a PLC, a gateway, a SCADA host) exposes an address space of
//! nodes, and a client reads, writes and subscribes to them. The binary
//! transport runs over TCP, usually on port 4840. This module follows OPC
//! UA Part 6 (Mappings), version 1.05: the UA TCP messages (HEL, ACK, ERR
//! and RHE), the secure conversation chunks (OPN, CLO and MSG), the binary
//! encoding of the built-in types, and the OpenSecureChannel and
//! CloseSecureChannel services with security policy None.
//!
//! Nothing here reads a socket. A world pushes connection bytes to a
//! [`Stream`](super::codec::Stream) of [`Messages`] and gets [`Message`]s back.
//! It answers a [`Hello`] with an [`Acknowledge`], gives the decoder the
//! negotiated [`Limits`], reads each [`SecureMessage`]'s body as a [`Service`],
//! and splits replies with [`Message::chunks`]. Each chunk is written with
//! [`Wire::write`].
//! Chunks of a long message are put back together before the world sees it.
//! What the address space holds, and which requests succeed, is up to world code.
//!
//! There is no cryptography. A secure message's body is kept exactly as it
//! came, which is the plain body under policy None. A world that is asked
//! for another policy answers with an [`ErrorMessage`] carrying
//! [`StatusCode::BAD_SECURITY_POLICY_REJECTED`]. Extension objects are kept
//! as raw bytes, with their type id, for world code to read.
//!
//! Every reader checks lengths, limits and nesting, because the agent can
//! send any bytes it likes. A stream that breaks the specification gives a
//! [`ChunkError`], whose [`ChunkError::status`] is the code a real server
//! sends back in an ERR message before it closes the connection. Every
//! message writer checks the same limits and returns an [`EncodeError`]
//! rather than write bytes a reader would refuse.
//!
//! Use [`Frames`] with [`Stream`](super::codec::Stream) to read
//! individual [`Chunk`]s under negotiated limits. [`Chunk`] implements
//! [`Wire`] for exact parsing and transactional writing under the module's
//! maximum chunk size. Message assembly and connection sequence checks
//! use [`Messages`]. [`Message::chunks`] takes explicit peer limits.
//!
//! Built-in binary values and services implement [`Wire`]. The borrowed
//! [`Reader`] and [`Binary`] trait read individual fields, including reserved
//! Variant types. Exact [`Wire`] parsing rejects those types because senders
//! may not write them. Writers reject dates, picoseconds, and namespace fields
//! that would read back differently. NaNs have a canonical wire form and
//! compare equal within the same floating type.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::opcua::{
//!     AsymmetricHeader, ChannelSecurityToken, Messages, Limits, Message, OpenSecureChannelRequest,
//!     OpenSecureChannelResponse, RequestHeader, RequestType, ResponseHeader, SecureKind,
//!     SecureMessage, SecurityMode, Service, SECURITY_POLICY_NONE,
//! };
//!
//! let mut server = Stream::new(Messages::new());
//!
//! // A client's Hello: version 0, 64 KiB buffers, no message or chunk
//! // limits, and its endpoint URL.
//! let url = b"opc.tcp://plc:4840";
//! let mut hel = b"HELF".to_vec();
//! hel.extend_from_slice(&(32 + url.len() as u32).to_le_bytes());
//! for v in [0u32, 65536, 65536, 0, 0] {
//!     hel.extend_from_slice(&v.to_le_bytes());
//! }
//! hel.extend_from_slice(&(url.len() as i32).to_le_bytes());
//! hel.extend_from_slice(url);
//! assert_eq!(server.push(&hel), hel.len());
//!
//! let Some(Ok(Message::Hello(hello))) = server.next() else { panic!() };
//! assert_eq!(hello.endpoint_url, "opc.tcp://plc:4840");
//! // The server takes chunks of up to 8192 bytes, the smallest allowed.
//! let ack = hello.acknowledge(&Limits::default());
//! assert_eq!(ack.receive_buffer_size, 8192);
//! server.decoder().set_limits(ack.limits());
//! let mut reply = Vec::new();
//! for chunk in Message::Acknowledge(ack).chunks(&hello.limits()).unwrap() {
//!     chunk.write(&mut reply).unwrap();
//! }
//! assert_eq!(&reply[..4], b"ACKF");
//! assert_eq!(reply.len(), 28);
//!
//! // The client opens a secure channel with no security.
//! let request = Service::OpenSecureChannelRequest(OpenSecureChannelRequest {
//!     header: RequestHeader { request_handle: 1, ..RequestHeader::default() },
//!     client_protocol_version: 0,
//!     request_type: RequestType::Issue,
//!     security_mode: SecurityMode::None,
//!     client_nonce: None,
//!     requested_lifetime: 600_000,
//! });
//! let opn = Message::Secure(SecureMessage {
//!     kind: SecureKind::Open(AsymmetricHeader::none()),
//!     channel_id: 0,
//!     sequence_number: 1,
//!     request_id: 1,
//!     body: request.to_bytes().unwrap(),
//! });
//! let mut bytes = Vec::new();
//! for chunk in opn.chunks(&ack.limits()).unwrap() { chunk.write(&mut bytes).unwrap(); }
//! assert_eq!(server.push(&bytes), bytes.len());
//!
//! let Some(Ok(Message::Secure(msg))) = server.next() else { panic!() };
//! let SecureKind::Open(security) = &msg.kind else { panic!() };
//! assert_eq!(security.policy_uri, SECURITY_POLICY_NONE);
//! let Ok(Service::OpenSecureChannelRequest(req)) = Service::parse(&msg.body) else { panic!() };
//!
//! // The server issues channel 7, token 1.
//! let response = Service::OpenSecureChannelResponse(OpenSecureChannelResponse {
//!     header: ResponseHeader {
//!         request_handle: req.header.request_handle,
//!         ..ResponseHeader::default()
//!     },
//!     server_protocol_version: 0,
//!     security_token: ChannelSecurityToken {
//!         channel_id: 7,
//!         token_id: 1,
//!         created_at: 0,
//!         revised_lifetime: req.requested_lifetime,
//!     },
//!     server_nonce: None,
//! });
//! let answer = Message::Secure(SecureMessage {
//!     kind: msg.kind.clone(),
//!     channel_id: 7,
//!     sequence_number: 1,
//!     request_id: msg.request_id,
//!     body: response.to_bytes().unwrap(),
//! });
//! let mut bytes = Vec::new();
//! for chunk in answer.chunks(&hello.limits()).unwrap() { chunk.write(&mut bytes).unwrap(); }
//! assert_eq!(&bytes[..4], b"OPNF");
//! assert_eq!(&bytes[8..12], &7u32.to_le_bytes());
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port OPC UA servers listen on.
pub const PORT: u16 = 4840;
/// The length of every chunk's header: the message type, the chunk type
/// and the size.
pub const HEADER_LEN: usize = 8;
/// The UA TCP protocol version this module speaks.
pub const PROTOCOL_VERSION: u32 = 0;
/// The smallest send or receive buffer a Hello or Acknowledge may name.
/// It is also the largest chunk a [`Messages`] takes before [`Limits`] are
/// negotiated.
pub const MIN_BUFFER_SIZE: u32 = 8192;
/// The largest chunk a [`Messages`] takes, whatever was negotiated.
pub const MAX_BUFFER_SIZE: u32 = 1 << 20;
/// The largest message body a [`Messages`] puts together from chunks,
/// whatever was negotiated.
pub const MAX_MESSAGE_SIZE: u32 = 1 << 24;
/// The most chunks one message may take, whatever was negotiated.
pub const MAX_CHUNK_COUNT: u32 = 4096;
/// The longest endpoint URL or server URI in a Hello or ReverseHello, in
/// bytes. Part 6 says each shall be less than 4096 bytes.
pub const MAX_URL_LEN: usize = 4095;
/// The longest reason in an Error message or an abort chunk, in bytes.
/// A reader drops a longer reason and reads it as empty, as Part 6 asks.
pub const MAX_REASON_LEN: usize = 4096;
/// The longest security policy URI in an OPN chunk, in bytes.
pub const MAX_POLICY_URI_LEN: usize = 255;
/// The largest HEL, ACK, ERR or RHE message a [`Messages`] takes, even
/// when the negotiated chunk size is smaller: a ReverseHello holding two
/// URLs of the longest length.
pub const MAX_HANDSHAKE_SIZE: u32 = (HEADER_LEN + 2 * (4 + MAX_URL_LEN)) as u32;
/// The longest String, ByteString or XmlElement, in bytes.
pub const MAX_STRING_LEN: usize = MAX_MESSAGE_SIZE as usize;
/// The most elements in one array.
pub const MAX_ARRAY_LEN: usize = 1 << 16;
/// The most values one [`Reader`] reads, or one [`Wire::write`] writes: every
/// array element, and every Variant, DataValue and DiagnosticInfo, counted
/// together. A value in memory can be a hundred times larger than its one
/// byte on the wire, so this bounds what a message can make a reader
/// allocate, to about 50 MB.
pub const MAX_VALUES: usize = 1 << 18;
/// The most dimensions a Variant's array may name.
pub const MAX_DIMENSIONS: usize = 32;
/// How deeply Variants, DataValues and DiagnosticInfos may nest inside
/// one another. Part 6 asks decoders to take at least 100 levels.
pub const MAX_DEPTH: usize = 100;
/// The longest String identifier of a NodeId, in characters, and the
/// longest Opaque one, in bytes (Part 3, 8.2.4).
pub const MAX_NODE_ID_LEN: usize = 4096;
/// The longest name of a QualifiedName, in characters (Part 3, 8.3).
pub const MAX_QUALIFIED_NAME_LEN: usize = 512;
/// The upper DateTime threshold: 9999-12-31 23:59:59 UTC. Readers map this
/// and later values to `i64::MAX`, and dates before the 1601 epoch to zero.
/// Writers require the mapped value and refuse values that would change.
pub const MAX_DATE_TIME: i64 = 2_650_467_743_990_000_000;
/// The largest picoseconds field of a DataValue. Readers map larger values
/// to this limit. Writers refuse values above it.
pub const MAX_PICOSECONDS: u16 = 9999;
/// The largest sequence number a legacy security policy may not wrap
/// after. Once a number is above it, the next may wrap around to a number
/// below 1024. A [`Messages`] accepts that wrap inside a message, as well
/// as the plain one past `u32::MAX`.
pub const LEGACY_WRAP: u32 = u32::MAX - 1024;
/// The URI of security policy None, the only policy this module carries.
pub const SECURITY_POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

// ---------------------------------------------------------------------
// Status codes and errors
// ---------------------------------------------------------------------

/// An OPC UA status code. The top two bits say whether it is good (00),
/// uncertain (01) or bad (10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StatusCode(pub u32);

impl StatusCode {
    /// Good: the operation succeeded.
    pub const GOOD: StatusCode = StatusCode(0);
    /// An unexpected error occurred.
    pub const BAD_UNEXPECTED_ERROR: StatusCode = StatusCode(0x8001_0000);
    /// A low level communication error occurred.
    pub const BAD_COMMUNICATION_ERROR: StatusCode = StatusCode(0x8005_0000);
    /// Encoding halted because of invalid data in the objects.
    pub const BAD_ENCODING_ERROR: StatusCode = StatusCode(0x8006_0000);
    /// Decoding halted because of invalid data in the stream.
    pub const BAD_DECODING_ERROR: StatusCode = StatusCode(0x8007_0000);
    /// The encoding or decoding limits of the stack were exceeded.
    pub const BAD_ENCODING_LIMITS_EXCEEDED: StatusCode = StatusCode(0x8008_0000);
    /// The server does not support the requested service.
    pub const BAD_SERVICE_UNSUPPORTED: StatusCode = StatusCode(0x800B_0000);
    /// An error occurred verifying security.
    pub const BAD_SECURITY_CHECKS_FAILED: StatusCode = StatusCode(0x8013_0000);
    /// The secure channel is no longer valid.
    pub const BAD_SECURE_CHANNEL_ID_INVALID: StatusCode = StatusCode(0x8022_0000);
    /// The security token request type is not valid.
    pub const BAD_REQUEST_TYPE_INVALID: StatusCode = StatusCode(0x8053_0000);
    /// The security mode does not meet the server's requirements.
    pub const BAD_SECURITY_MODE_REJECTED: StatusCode = StatusCode(0x8054_0000);
    /// The security policy does not meet the server's requirements.
    pub const BAD_SECURITY_POLICY_REJECTED: StatusCode = StatusCode(0x8055_0000);
    /// The server is too busy to process the request.
    pub const BAD_TCP_SERVER_TOO_BUSY: StatusCode = StatusCode(0x807D_0000);
    /// The message type in a chunk header is not valid.
    pub const BAD_TCP_MESSAGE_TYPE_INVALID: StatusCode = StatusCode(0x807E_0000);
    /// The secure channel id or token id is not in use.
    pub const BAD_TCP_SECURE_CHANNEL_UNKNOWN: StatusCode = StatusCode(0x807F_0000);
    /// The chunk size in a header is too large.
    pub const BAD_TCP_MESSAGE_TOO_LARGE: StatusCode = StatusCode(0x8080_0000);
    /// There are not enough resources to process the request.
    pub const BAD_TCP_NOT_ENOUGH_RESOURCES: StatusCode = StatusCode(0x8081_0000);
    /// An internal error occurred.
    pub const BAD_TCP_INTERNAL_ERROR: StatusCode = StatusCode(0x8082_0000);
    /// The server does not recognize the endpoint URL.
    pub const BAD_TCP_ENDPOINT_URL_INVALID: StatusCode = StatusCode(0x8083_0000);
    /// The secure channel has been closed.
    pub const BAD_SECURE_CHANNEL_CLOSED: StatusCode = StatusCode(0x8086_0000);
    /// The token has expired or is not recognized.
    pub const BAD_SECURE_CHANNEL_TOKEN_UNKNOWN: StatusCode = StatusCode(0x8087_0000);
    /// The sequence number is not valid.
    pub const BAD_SEQUENCE_NUMBER_INVALID: StatusCode = StatusCode(0x8088_0000);
    /// The request message is larger than the server allows.
    pub const BAD_REQUEST_TOO_LARGE: StatusCode = StatusCode(0x80B8_0000);
    /// The response message is larger than the client or server allows.
    pub const BAD_RESPONSE_TOO_LARGE: StatusCode = StatusCode(0x80B9_0000);
    /// The two sides do not share a protocol version.
    pub const BAD_PROTOCOL_VERSION_UNSUPPORTED: StatusCode = StatusCode(0x80BE_0000);

    /// Whether the code is bad: its top bit is set.
    pub fn is_bad(self) -> bool {
        self.0 & 0x8000_0000 != 0
    }

    /// Whether the code is good: its top two bits are clear.
    pub fn is_good(self) -> bool {
        self.0 & 0xC000_0000 == 0
    }
}

/// Why bytes are not a value in the OPC UA binary encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes ended before the value did.
    End,
    /// A length was below -1, above its limit, or longer than the bytes
    /// left.
    Length(i32),
    /// A String was not UTF-8.
    Utf8,
    /// A NodeId's encoding byte named no form, or set ExpandedNodeId flags
    /// where a plain NodeId belongs.
    NodeIdForm(u8),
    /// An encoding mask set bits that mean nothing for its type.
    Mask(u8),
    /// A Variant named a type that cannot appear where it did.
    VariantType(u8),
    /// A Variant's array dimensions were fewer than 2, more than
    /// [`MAX_DIMENSIONS`], not all above 0, or did not match its length.
    Dimensions,
    /// Values nested more than [`MAX_DEPTH`] deep.
    Depth,
    /// The bytes held more than [`MAX_VALUES`] values.
    TooManyValues,
    /// An enumeration held a value it does not define.
    Enum(i32),
    /// Bytes were left over after the value.
    Trailing(usize),
    /// A NodeId's String identifier or a QualifiedName's name held a C0
    /// or C1 control character, which Part 3 forbids.
    ControlChar,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::End => f.write_str("the bytes ended inside a value"),
            DecodeError::Length(n) => write!(f, "length {n} is out of range"),
            DecodeError::Utf8 => f.write_str("a string is not UTF-8"),
            DecodeError::NodeIdForm(b) => {
                write!(f, "NodeId encoding byte {b:#04x} is not valid here")
            }
            DecodeError::Mask(b) => write!(f, "encoding mask {b:#04x} sets unknown bits"),
            DecodeError::VariantType(t) => write!(f, "Variant type {t} is not allowed here"),
            DecodeError::Dimensions => f.write_str("array dimensions do not match the array"),
            DecodeError::Depth => write!(f, "values nest more than {MAX_DEPTH} deep"),
            DecodeError::TooManyValues => write!(f, "more than {MAX_VALUES} values"),
            DecodeError::Enum(n) => write!(f, "enumeration value {n} is not defined"),
            DecodeError::Trailing(n) => write!(f, "{n} bytes left over after the value"),
            DecodeError::ControlChar => f.write_str("a name holds a control character"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a value cannot be written: the bytes would break a limit or a rule
/// that a reader checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A string, array, chunk or message is longer than its limit allows.
    TooLong,
    /// Values nest more than [`MAX_DEPTH`] deep.
    TooDeep,
    /// There are more than [`MAX_VALUES`] values.
    TooManyValues,
    /// A Variant holds a value of the wrong type: an array element that
    /// does not match the array's type, a Variant directly inside a
    /// Variant, a DiagnosticInfo, a DataValue inside a DataValue, or a
    /// type id that does not exist or is reserved (26 to 31), which only
    /// readers take.
    VariantType,
    /// A Variant's array dimensions are fewer than 2, more than
    /// [`MAX_DIMENSIONS`], not all above 0, or do not multiply out to its
    /// length.
    Dimensions,
    /// A Hello or Acknowledge names a buffer smaller than
    /// [`MIN_BUFFER_SIZE`].
    BufferSize(u32),
    /// A [`Service::Other`] carries the type id of a service this module
    /// reads, so its body would be read as that service.
    KnownTypeId,
    /// A NodeId's String identifier or a QualifiedName's name holds a C0
    /// or C1 control character.
    ControlChar,
    /// An OPN's security header breaks its policy: a sender certificate or
    /// receiver thumbprint under policy None, or a thumbprint that is not
    /// 20 bytes.
    SecurityHeader,
    /// A field would read back as a different value.
    Value,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLong => f.write_str("a value is longer than its limit"),
            EncodeError::TooDeep => write!(f, "values nest more than {MAX_DEPTH} deep"),
            EncodeError::TooManyValues => write!(f, "more than {MAX_VALUES} values"),
            EncodeError::VariantType => f.write_str("a Variant holds a value of the wrong type"),
            EncodeError::Dimensions => f.write_str("array dimensions do not match the array"),
            EncodeError::BufferSize(n) => write!(f, "buffer size {n} is below {MIN_BUFFER_SIZE}"),
            EncodeError::KnownTypeId => f.write_str("an unread service carries a known type id"),
            EncodeError::ControlChar => f.write_str("a name holds a control character"),
            EncodeError::SecurityHeader => f.write_str("the security header breaks its policy"),
            EncodeError::Value => f.write_str("a field would change on the wire"),
        }
    }
}

impl std::error::Error for EncodeError {}

// ---------------------------------------------------------------------
// Reading and writing the binary encoding
// ---------------------------------------------------------------------

/// A cursor over bytes in the OPC UA binary encoding. All numbers are
/// little-endian. It counts nesting, so no value can recurse past
/// [`MAX_DEPTH`], and values, so it reads no more than [`MAX_VALUES`] in
/// all, however many values are read through it.
#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    values: usize,
    /// How many DataValues the value being read is inside.
    data_values: usize,
    writable: bool,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader {
            bytes,
            pos: 0,
            depth: 0,
            values: 0,
            data_values: 0,
            writable: false,
        }
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::End);
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Every byte left.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        out
    }

    /// Fails with [`DecodeError::Trailing`] if any bytes are left.
    pub fn finish(&self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(DecodeError::Trailing(n)),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// A Byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
    /// An SByte.
    pub fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(i8::from_le_bytes(self.array()?))
    }
    /// A Boolean: any byte but 0 is true.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }
    /// A UInt16.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    /// An Int16.
    pub fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_le_bytes(self.array()?))
    }
    /// A UInt32.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    /// An Int32.
    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.array()?))
    }
    /// A UInt64.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    /// An Int64, read as it is. A DateTime goes through
    /// [`Reader::date_time`].
    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.array()?))
    }
    /// A DateTime: 100-nanosecond intervals since January 1, 1601 (UTC).
    /// Anything at or before the
    /// epoch as 0, and anything at or after [`MAX_DATE_TIME`] as
    /// `i64::MAX`. Writers require these canonical values.
    pub fn date_time(&mut self) -> Result<i64, DecodeError> {
        Ok(clamp_date_time(self.i64()?))
    }
    /// A Float.
    pub fn f32(&mut self) -> Result<f32, DecodeError> {
        Ok(f32::from_le_bytes(self.array()?))
    }
    /// A Double.
    pub fn f64(&mut self) -> Result<f64, DecodeError> {
        Ok(f64::from_le_bytes(self.array()?))
    }

    /// A length prefix: `None` for -1 (null), and otherwise a length no
    /// larger than `max` or the bytes left.
    fn length(&mut self, max: usize) -> Result<Option<usize>, DecodeError> {
        let n = self.i32()?;
        if n == -1 {
            return Ok(None);
        }
        match usize::try_from(n) {
            Ok(len) if len <= max && len <= self.remaining() => Ok(Some(len)),
            _ => Err(DecodeError::Length(n)),
        }
    }

    /// A ByteString of at most `max` bytes. Null is `None`.
    pub fn byte_string_max(&mut self, max: usize) -> Result<Option<Vec<u8>>, DecodeError> {
        match self.length(max)? {
            None => Ok(None),
            Some(n) => Ok(Some(self.take(n)?.to_vec())),
        }
    }

    /// A ByteString of at most [`MAX_STRING_LEN`] bytes. Null is `None`.
    pub fn byte_string(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        self.byte_string_max(MAX_STRING_LEN)
    }

    /// A UTF-8 String of at most `max` bytes. Null is `None`.
    pub fn string_max(&mut self, max: usize) -> Result<Option<String>, DecodeError> {
        match self.byte_string_max(max)? {
            None => Ok(None),
            Some(b) => String::from_utf8(b)
                .map(Some)
                .map_err(|_| DecodeError::Utf8),
        }
    }

    /// A UTF-8 String of at most [`MAX_STRING_LEN`] bytes. Null is `None`.
    pub fn string(&mut self) -> Result<Option<String>, DecodeError> {
        self.string_max(MAX_STRING_LEN)
    }

    /// An array's length. A null array (-1) reads as empty. Every element
    /// of every array takes at least one byte, so a length past the bytes
    /// left is refused, as is one past [`MAX_ARRAY_LEN`]. Elements count
    /// toward [`MAX_VALUES`], and one that takes this reader past it fails
    /// with [`DecodeError::TooManyValues`].
    pub fn array_len(&mut self) -> Result<usize, DecodeError> {
        let n = self.length(MAX_ARRAY_LEN)?.unwrap_or(0);
        self.count(n)?;
        Ok(n)
    }

    /// Counts `n` more values toward [`MAX_VALUES`].
    fn count(&mut self, n: usize) -> Result<(), DecodeError> {
        match self.values.checked_add(n) {
            Some(total) if total <= MAX_VALUES => self.values = total,
            _ => return Err(DecodeError::TooManyValues),
        }
        Ok(())
    }

    /// A value of type `T`.
    pub fn read<T: Binary>(&mut self) -> Result<T, DecodeError> {
        T::decode(self)
    }

    /// An array of `T`: a length, then the elements.
    pub fn read_array<T: Binary>(&mut self) -> Result<Vec<T>, DecodeError> {
        let n = self.array_len()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(T::decode(self)?);
        }
        Ok(out)
    }

    /// Runs `f` one level deeper, failing past [`MAX_DEPTH`]. It counts
    /// one value toward [`MAX_VALUES`]. The depth is restored whether `f`
    /// succeeds or not.
    fn nested<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        if self.depth >= MAX_DEPTH {
            return Err(DecodeError::Depth);
        }
        self.count(1)?;
        self.depth += 1;
        let out = f(self);
        self.depth -= 1;
        out
    }
}

/// Builds bytes in the OPC UA binary encoding. It checks every limit a
/// [`Reader`] checks, so what it writes reads back.
#[derive(Debug, Default)]
struct Writer {
    out: Vec<u8>,
    error: Option<EncodeError>,
    depth: usize,
    values: usize,
    /// How many DataValues the value being written is inside.
    data_values: usize,
}

impl Writer {
    /// A writer holding no bytes.
    fn new() -> Writer {
        Writer::default()
    }

    /// The bytes written.
    fn into_bytes(self) -> Result<Vec<u8>, EncodeError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.out),
        }
    }

    /// Raw bytes, with no length.
    fn bytes(&mut self, b: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if self
            .out
            .len()
            .checked_add(b.len())
            .is_none_or(|n| n > MAX_MESSAGE_SIZE as usize)
        {
            self.error = Some(EncodeError::TooLong);
        } else {
            self.out.extend_from_slice(b);
        }
    }
    /// A Byte.
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    /// An SByte.
    fn i8(&mut self, v: i8) {
        self.bytes(&v.to_le_bytes());
    }
    /// A Boolean, as 1 or 0.
    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }
    /// A UInt16.
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    /// An Int16.
    fn i16(&mut self, v: i16) {
        self.bytes(&v.to_le_bytes());
    }
    /// A UInt32.
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    /// An Int32.
    fn i32(&mut self, v: i32) {
        self.bytes(&v.to_le_bytes());
    }
    /// A UInt64.
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
    /// An Int64, written as it is. A DateTime goes through
    /// [`Reader::date_time`].
    fn i64(&mut self, v: i64) {
        self.bytes(&v.to_le_bytes());
    }
    /// A canonical DateTime. Values changed by the reader are refused.
    fn date_time(&mut self, v: i64) {
        if v != clamp_date_time(v) {
            self.error = Some(EncodeError::Value);
        }
        self.i64(v);
    }
    /// A Float. Any NaN is written as the quiet NaN Part 6 names.
    fn f32(&mut self, v: f32) {
        let v = if v.is_nan() {
            f32::from_bits(0xffc0_0000)
        } else {
            v
        };
        self.bytes(&v.to_le_bytes());
    }
    /// A Double. Any NaN is written as the quiet NaN Part 6 names.
    fn f64(&mut self, v: f64) {
        let v = if v.is_nan() {
            f64::from_bits(0xfff8_0000_0000_0000)
        } else {
            v
        };
        self.bytes(&v.to_le_bytes());
    }

    /// A ByteString of at most `max` bytes. `None` is written as null.
    fn byte_string_max(&mut self, b: Option<&[u8]>, max: usize) -> Result<(), EncodeError> {
        match b {
            None => self.i32(-1),
            Some(b) => {
                let n = i32::try_from(b.len()).map_err(|_| EncodeError::TooLong)?;
                if b.len() > max {
                    return Err(EncodeError::TooLong);
                }
                self.i32(n);
                self.bytes(b);
            }
        }
        Ok(())
    }

    /// A ByteString of at most [`MAX_STRING_LEN`] bytes.
    fn byte_string(&mut self, b: Option<&[u8]>) -> Result<(), EncodeError> {
        self.byte_string_max(b, MAX_STRING_LEN)
    }

    /// A String of at most `max` bytes. `None` is written as null.
    fn string_max(&mut self, s: Option<&str>, max: usize) -> Result<(), EncodeError> {
        self.byte_string_max(s.map(str::as_bytes), max)
    }

    /// A String of at most [`MAX_STRING_LEN`] bytes.
    fn string(&mut self, s: Option<&str>) -> Result<(), EncodeError> {
        self.string_max(s, MAX_STRING_LEN)
    }

    /// An array's length, at most [`MAX_ARRAY_LEN`]. Its elements count
    /// toward [`MAX_VALUES`], as a [`Reader`] counts them.
    fn array_len(&mut self, n: usize) -> Result<(), EncodeError> {
        if n > MAX_ARRAY_LEN {
            return Err(EncodeError::TooLong);
        }
        self.count(n)?;
        self.i32(n as i32);
        Ok(())
    }

    /// Counts `n` more values toward [`MAX_VALUES`].
    fn count(&mut self, n: usize) -> Result<(), EncodeError> {
        match self.values.checked_add(n) {
            Some(total) if total <= MAX_VALUES => self.values = total,
            _ => return Err(EncodeError::TooManyValues),
        }
        Ok(())
    }

    /// An array of `T`: a length, then the elements.
    fn write_array<T: BinaryWrite>(&mut self, values: &[T]) -> Result<(), EncodeError> {
        self.array_len(values.len())?;
        for v in values {
            v.encode(self)?;
        }
        Ok(())
    }

    /// Runs `f` one level deeper, failing past [`MAX_DEPTH`]. It counts
    /// one value toward [`MAX_VALUES`], as a [`Reader`] does. The depth is
    /// restored whether `f` succeeds or not.
    fn nested(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        if self.depth >= MAX_DEPTH {
            return Err(EncodeError::TooDeep);
        }
        self.count(1)?;
        self.depth += 1;
        let out = f(self);
        self.depth -= 1;
        out
    }
}

/// A DateTime as Part 6 encodes it: 0 for any time at or before the
/// epoch, and `i64::MAX` for any at or after [`MAX_DATE_TIME`].
fn clamp_date_time(v: i64) -> i64 {
    if v <= 0 {
        0
    } else if v >= MAX_DATE_TIME {
        i64::MAX
    } else {
        v
    }
}

/// A type with an OPC UA binary encoding.
pub trait Binary: Sized {
    /// Reads one value from `r`.
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;
}

/// A type that writes an OPC UA binary encoding.
trait BinaryWrite {
    /// Writes one value to `w`.
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError>;
}

impl Binary for StatusCode {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(StatusCode(r.u32()?))
    }
}

// ---------------------------------------------------------------------
// Built-in types
// ---------------------------------------------------------------------

/// Built-in type ids, as a Variant's encoding mask names them.
pub mod type_id {
    /// Null (0).
    pub const NULL: u8 = 0;
    /// Boolean (1).
    pub const BOOLEAN: u8 = 1;
    /// SByte (2).
    pub const SBYTE: u8 = 2;
    /// Byte (3).
    pub const BYTE: u8 = 3;
    /// Int16 (4).
    pub const INT16: u8 = 4;
    /// UInt16 (5).
    pub const UINT16: u8 = 5;
    /// Int32 (6).
    pub const INT32: u8 = 6;
    /// UInt32 (7).
    pub const UINT32: u8 = 7;
    /// Int64 (8).
    pub const INT64: u8 = 8;
    /// UInt64 (9).
    pub const UINT64: u8 = 9;
    /// Float (10).
    pub const FLOAT: u8 = 10;
    /// Double (11).
    pub const DOUBLE: u8 = 11;
    /// String (12).
    pub const STRING: u8 = 12;
    /// DateTime (13).
    pub const DATE_TIME: u8 = 13;
    /// Guid (14).
    pub const GUID: u8 = 14;
    /// ByteString (15).
    pub const BYTE_STRING: u8 = 15;
    /// XmlElement (16).
    pub const XML_ELEMENT: u8 = 16;
    /// NodeId (17).
    pub const NODE_ID: u8 = 17;
    /// ExpandedNodeId (18).
    pub const EXPANDED_NODE_ID: u8 = 18;
    /// StatusCode (19).
    pub const STATUS_CODE: u8 = 19;
    /// QualifiedName (20).
    pub const QUALIFIED_NAME: u8 = 20;
    /// LocalizedText (21).
    pub const LOCALIZED_TEXT: u8 = 21;
    /// ExtensionObject (22).
    pub const EXTENSION_OBJECT: u8 = 22;
    /// DataValue (23).
    pub const DATA_VALUE: u8 = 23;
    /// Variant (24).
    pub const VARIANT: u8 = 24;
    /// DiagnosticInfo (25).
    pub const DIAGNOSTIC_INFO: u8 = 25;
    /// First reserved type id (26), read as a ByteString.
    pub const RESERVED_FIRST: u8 = 26;
    /// Last reserved type id (31), read as a ByteString.
    pub const RESERVED_LAST: u8 = 31;
}

/// A Guid, in its four fields. On the wire the first three are
/// little-endian and the last eight bytes are in order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Guid {
    /// The first 4 bytes.
    pub data1: u32,
    /// The next 2 bytes.
    pub data2: u16,
    /// The next 2 bytes.
    pub data3: u16,
    /// The last 8 bytes.
    pub data4: [u8; 8],
}

impl Binary for Guid {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Guid {
            data1: r.u32()?,
            data2: r.u16()?,
            data3: r.u16()?,
            data4: r.array()?,
        })
    }
}

/// The identifier part of a [`NodeId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Identifier {
    /// A number.
    Numeric(u32),
    /// A string of at most [`MAX_NODE_ID_LEN`] characters, with no
    /// control characters. A null string reads as empty.
    String(String),
    /// A Guid.
    Guid(Guid),
    /// At most [`MAX_NODE_ID_LEN`] opaque bytes. A null ByteString reads
    /// as empty.
    Opaque(Vec<u8>),
}

/// A NodeId: a namespace index and an identifier. The writer picks the
/// shortest encoding form; the reader takes all six.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    /// The index into the server's namespace table. 0 is the OPC UA
    /// namespace.
    pub namespace: u16,
    /// The identifier within the namespace.
    pub identifier: Identifier,
}

impl Default for NodeId {
    /// The null NodeId: numeric 0 in namespace 0.
    fn default() -> NodeId {
        NodeId::numeric(0, 0)
    }
}

impl NodeId {
    /// A numeric NodeId.
    pub fn numeric(namespace: u16, id: u32) -> NodeId {
        NodeId {
            namespace,
            identifier: Identifier::Numeric(id),
        }
    }

    /// A string NodeId.
    pub fn string(namespace: u16, id: &str) -> NodeId {
        NodeId {
            namespace,
            identifier: Identifier::String(id.to_string()),
        }
    }

    /// Whether this is a null NodeId: in namespace 0, numeric 0, an empty
    /// string, the all-zero Guid or empty opaque bytes. Part 3 counts all
    /// four as null.
    pub fn is_null(&self) -> bool {
        self.namespace == 0
            && match &self.identifier {
                Identifier::Numeric(id) => *id == 0,
                Identifier::String(s) => s.is_empty(),
                Identifier::Guid(g) => *g == Guid::default(),
                Identifier::Opaque(b) => b.is_empty(),
            }
    }

    /// The numeric id, if this is a numeric NodeId in namespace 0.
    pub fn ns0(&self) -> Option<u32> {
        match self.identifier {
            Identifier::Numeric(id) if self.namespace == 0 => Some(id),
            _ => None,
        }
    }

    /// Reads the rest of a NodeId after its encoding byte, whose low six
    /// bits name the form.
    fn decode_form(r: &mut Reader<'_>, form: u8) -> Result<NodeId, DecodeError> {
        Ok(match form & 0x3f {
            0 => NodeId::numeric(0, u32::from(r.u8()?)),
            1 => {
                let namespace = u16::from(r.u8()?);
                NodeId::numeric(namespace, u32::from(r.u16()?))
            }
            2 => {
                let namespace = r.u16()?;
                NodeId::numeric(namespace, r.u32()?)
            }
            3 => {
                let namespace = r.u16()?;
                NodeId {
                    namespace,
                    identifier: Identifier::String(read_name(r, MAX_NODE_ID_LEN)?),
                }
            }
            4 => {
                let namespace = r.u16()?;
                NodeId {
                    namespace,
                    identifier: Identifier::Guid(r.read()?),
                }
            }
            5 => {
                let namespace = r.u16()?;
                NodeId {
                    namespace,
                    identifier: Identifier::Opaque(
                        r.byte_string_max(MAX_NODE_ID_LEN)?.unwrap_or_default(),
                    ),
                }
            }
            _ => return Err(DecodeError::NodeIdForm(form)),
        })
    }

    /// Writes the NodeId with `flags` set in its encoding byte.
    fn encode_flags(&self, w: &mut Writer, flags: u8) -> Result<(), EncodeError> {
        let ns = self.namespace;
        match &self.identifier {
            Identifier::Numeric(id) => {
                if ns == 0 && *id <= 0xff {
                    w.u8(flags);
                    w.u8(*id as u8);
                } else if ns <= 0xff && *id <= 0xffff {
                    w.u8(flags | 1);
                    w.u8(ns as u8);
                    w.u16(*id as u16);
                } else {
                    w.u8(flags | 2);
                    w.u16(ns);
                    w.u32(*id);
                }
            }
            Identifier::String(s) => {
                check_name(s, MAX_NODE_ID_LEN)?;
                w.u8(flags | 3);
                w.u16(ns);
                w.string(Some(s))?;
            }
            Identifier::Guid(g) => {
                w.u8(flags | 4);
                w.u16(ns);
                g.encode(w)?;
            }
            Identifier::Opaque(b) => {
                if b.len() > MAX_NODE_ID_LEN {
                    return Err(EncodeError::TooLong);
                }
                w.u8(flags | 5);
                w.u16(ns);
                w.byte_string(Some(b))?;
            }
        }
        Ok(())
    }
}

/// Whether `c` is a Unicode C0 or C1 control character.
fn is_c0_c1(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{80}'..='\u{9f}')
}

/// Reads a NodeId String identifier or a QualifiedName's name: at most
/// `max` characters, none a control character. A null one reads as empty.
fn read_name(r: &mut Reader<'_>, max: usize) -> Result<String, DecodeError> {
    let s = r.string_max(max * 4)?.unwrap_or_default();
    let chars = s.chars().count();
    if chars > max {
        return Err(DecodeError::Length(
            i32::try_from(chars).unwrap_or(i32::MAX),
        ));
    }
    if s.chars().any(is_c0_c1) {
        return Err(DecodeError::ControlChar);
    }
    Ok(s)
}

/// Checks what [`read_name`] checks, before writing.
fn check_name(s: &str, max: usize) -> Result<(), EncodeError> {
    if s.chars().count() > max {
        return Err(EncodeError::TooLong);
    }
    if s.chars().any(is_c0_c1) {
        return Err(EncodeError::ControlChar);
    }
    Ok(())
}

impl Binary for NodeId {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let form = r.u8()?;
        if form & 0xc0 != 0 {
            return Err(DecodeError::NodeIdForm(form));
        }
        NodeId::decode_form(r, form)
    }
}

/// An ExpandedNodeId: a NodeId that may name its namespace by URI and a
/// server by index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExpandedNodeId {
    /// The NodeId. A namespace URI requires namespace index zero when writing.
    /// The reader sets the index to zero when a URI is present.
    pub node_id: NodeId,
    /// The namespace's URI, if given. A null or empty URI reads as `None`,
    /// and writers refuse an empty URI. Use None to omit it.
    pub namespace_uri: Option<String>,
    /// The index into the server table. 0 is the local server, and is
    /// left off the wire.
    pub server_index: u32,
}

impl From<NodeId> for ExpandedNodeId {
    /// The NodeId on the local server, with no namespace URI.
    fn from(node_id: NodeId) -> ExpandedNodeId {
        ExpandedNodeId {
            node_id,
            namespace_uri: None,
            server_index: 0,
        }
    }
}

impl Binary for ExpandedNodeId {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let form = r.u8()?;
        let mut node_id = NodeId::decode_form(r, form)?;
        let namespace_uri = if form & 0x80 != 0 {
            r.string()?.filter(|u| !u.is_empty())
        } else {
            None
        };
        if namespace_uri.is_some() {
            node_id.namespace = 0;
        }
        let server_index = if form & 0x40 != 0 { r.u32()? } else { 0 };
        Ok(ExpandedNodeId {
            node_id,
            namespace_uri,
            server_index,
        })
    }
}

/// A QualifiedName: a name with a namespace index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct QualifiedName {
    /// The namespace index.
    pub namespace: u16,
    /// The name: at most [`MAX_QUALIFIED_NAME_LEN`] characters, with no
    /// control characters. A null name reads as empty.
    pub name: String,
}

impl Binary for QualifiedName {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(QualifiedName {
            namespace: r.u16()?,
            name: read_name(r, MAX_QUALIFIED_NAME_LEN)?,
        })
    }
}

/// A LocalizedText: text, and the locale it is in. Either may be absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct LocalizedText {
    /// The locale, such as "en-US". A null one reads as `None`.
    pub locale: Option<String>,
    /// The text. A null one reads as `None`.
    pub text: Option<String>,
}

impl Binary for LocalizedText {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mask = r.u8()?;
        if mask & !0x03 != 0 {
            return Err(DecodeError::Mask(mask));
        }
        let locale = if mask & 0x01 != 0 { r.string()? } else { None };
        let text = if mask & 0x02 != 0 { r.string()? } else { None };
        Ok(LocalizedText { locale, text })
    }
}

/// The body of an [`ExtensionObject`], kept as raw bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ExtensionBody {
    /// No body.
    #[default]
    None,
    /// A body in the binary encoding. A null ByteString reads as empty.
    Binary(Vec<u8>),
    /// A body in the XML encoding. A null one reads as empty.
    Xml(Vec<u8>),
}

/// An ExtensionObject: a structure this module does not read, with the
/// NodeId of its encoding and its bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExtensionObject {
    /// The NodeId of the structure's encoding.
    pub type_id: NodeId,
    /// The structure's bytes.
    pub body: ExtensionBody,
}

impl Binary for ExtensionObject {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let type_id = r.read()?;
        let encoding = r.u8()?;
        let body = match encoding {
            0 => ExtensionBody::None,
            1 => ExtensionBody::Binary(r.byte_string()?.unwrap_or_default()),
            2 => ExtensionBody::Xml(r.byte_string()?.unwrap_or_default()),
            m => return Err(DecodeError::Mask(m)),
        };
        Ok(ExtensionObject { type_id, body })
    }
}

/// A DiagnosticInfo: where a status came from. Every field is optional.
/// The indexes point into a response header's string table.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DiagnosticInfo {
    /// The index of the symbolic id.
    pub symbolic_id: Option<i32>,
    /// The index of the namespace URI.
    pub namespace_uri: Option<i32>,
    /// The index of the locale.
    pub locale: Option<i32>,
    /// The index of the localized text.
    pub localized_text: Option<i32>,
    /// Details for a person to read. A null one reads as `None`.
    pub additional_info: Option<String>,
    /// The status code from a lower layer.
    pub inner_status_code: Option<StatusCode>,
    /// The diagnostics from a lower layer.
    pub inner_diagnostic_info: Option<Box<DiagnosticInfo>>,
}

impl Binary for DiagnosticInfo {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.nested(DiagnosticInfo::decode_inner)
    }
}

impl DiagnosticInfo {
    fn decode_inner(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mask = r.u8()?;
        if mask & 0x80 != 0 {
            return Err(DecodeError::Mask(mask));
        }
        let mut d = DiagnosticInfo::default();
        if mask & 0x01 != 0 {
            d.symbolic_id = Some(r.i32()?);
        }
        if mask & 0x02 != 0 {
            d.namespace_uri = Some(r.i32()?);
        }
        if mask & 0x08 != 0 {
            d.locale = Some(r.i32()?);
        }
        if mask & 0x04 != 0 {
            d.localized_text = Some(r.i32()?);
        }
        if mask & 0x10 != 0 {
            d.additional_info = r.string()?;
        }
        if mask & 0x20 != 0 {
            d.inner_status_code = Some(r.read()?);
        }
        if mask & 0x40 != 0 {
            d.inner_diagnostic_info = Some(Box::new(r.read()?));
        }
        Ok(d)
    }
    fn encode_inner(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let mut mask = 0;
        let bits = [
            (self.symbolic_id.is_some(), 0x01),
            (self.namespace_uri.is_some(), 0x02),
            (self.localized_text.is_some(), 0x04),
            (self.locale.is_some(), 0x08),
            (self.additional_info.is_some(), 0x10),
            (self.inner_status_code.is_some(), 0x20),
            (self.inner_diagnostic_info.is_some(), 0x40),
        ];
        for (set, bit) in bits {
            if set {
                mask |= bit;
            }
        }
        w.u8(mask);
        for v in [
            self.symbolic_id,
            self.namespace_uri,
            self.locale,
            self.localized_text,
        ]
        .into_iter()
        .flatten()
        {
            w.i32(v);
        }
        if let Some(s) = &self.additional_info {
            w.string(Some(s))?;
        }
        if let Some(s) = self.inner_status_code {
            s.encode(w)?;
        }
        if let Some(inner) = &self.inner_diagnostic_info {
            inner.encode(w)?;
        }
        Ok(())
    }
}

/// One value of a built-in type, as a Variant holds it.
/// NaNs of the same floating type compare equal. Their wire form is canonical.
#[derive(Clone, Debug)]
pub enum Value {
    /// The OPC UA Boolean value.
    Boolean(bool),
    /// The OPC UA SByte value.
    SByte(i8),
    /// The OPC UA Byte value.
    Byte(u8),
    /// The OPC UA Int16 value.
    Int16(i16),
    /// The OPC UA UInt16 value.
    UInt16(u16),
    /// The OPC UA Int32 value.
    Int32(i32),
    /// The OPC UA UInt32 value.
    UInt32(u32),
    /// The OPC UA Int64 value.
    Int64(i64),
    /// The OPC UA UInt64 value.
    UInt64(u64),
    /// The OPC UA Float value.
    Float(f32),
    /// The OPC UA Double value.
    Double(f64),
    /// A String. Null is `None`.
    String(Option<String>),
    /// 100-nanosecond intervals since January 1, 1601 (UTC), bounded as
    /// [`Reader::date_time`] bounds it.
    DateTime(i64),
    /// The OPC UA Guid value.
    Guid(Guid),
    /// A ByteString. Null is `None`.
    ByteString(Option<Vec<u8>>),
    /// An XmlElement's bytes, unread. Null is `None`.
    XmlElement(Option<Vec<u8>>),
    /// The OPC UA NodeId value.
    NodeId(NodeId),
    /// The OPC UA ExpandedNodeId value.
    ExpandedNodeId(ExpandedNodeId),
    /// The OPC UA StatusCode value.
    StatusCode(StatusCode),
    /// The OPC UA QualifiedName value.
    QualifiedName(QualifiedName),
    /// The OPC UA LocalizedText value.
    LocalizedText(LocalizedText),
    /// The OPC UA ExtensionObject value.
    ExtensionObject(Box<ExtensionObject>),
    /// The OPC UA DataValue value.
    DataValue(Box<DataValue>),
    /// A Variant, which may only appear as an array element.
    Variant(Box<Variant>),
    /// Part 6 forbids a DiagnosticInfo in a Variant: readers refuse one,
    /// and writers refuse to write one.
    DiagnosticInfo(Box<DiagnosticInfo>),
    /// A value of reserved type id 26 to 31, kept as a ByteString. Readers
    /// take one, as Part 6 asks, but writers refuse it, since encoders
    /// shall not use these ids.
    Reserved {
        /// The reserved built-in type id.
        type_id: u8,
        /// The opaque ByteString; None means null.
        bytes: Option<Vec<u8>>,
    },
}
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Boolean(a), Self::Boolean(b)) => a == b,
            (Self::SByte(a), Self::SByte(b)) => a == b,
            (Self::Byte(a), Self::Byte(b)) => a == b,
            (Self::Int16(a), Self::Int16(b)) => a == b,
            (Self::UInt16(a), Self::UInt16(b)) => a == b,
            (Self::Int32(a), Self::Int32(b)) => a == b,
            (Self::UInt32(a), Self::UInt32(b)) => a == b,
            (Self::Int64(a), Self::Int64(b)) => a == b,
            (Self::UInt64(a), Self::UInt64(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
            (Self::Double(a), Self::Double(b)) => a == b || (a.is_nan() && b.is_nan()),
            (Self::String(a), Self::String(b)) => a == b,
            (Self::DateTime(a), Self::DateTime(b)) => a == b,
            (Self::Guid(a), Self::Guid(b)) => a == b,
            (Self::ByteString(a), Self::ByteString(b)) => a == b,
            (Self::XmlElement(a), Self::XmlElement(b)) => a == b,
            (Self::NodeId(a), Self::NodeId(b)) => a == b,
            (Self::ExpandedNodeId(a), Self::ExpandedNodeId(b)) => a == b,
            (Self::StatusCode(a), Self::StatusCode(b)) => a == b,
            (Self::QualifiedName(a), Self::QualifiedName(b)) => a == b,
            (Self::LocalizedText(a), Self::LocalizedText(b)) => a == b,
            (Self::ExtensionObject(a), Self::ExtensionObject(b)) => a == b,
            (Self::DataValue(a), Self::DataValue(b)) => a == b,
            (Self::Variant(a), Self::Variant(b)) => a == b,
            (Self::DiagnosticInfo(a), Self::DiagnosticInfo(b)) => a == b,

            (
                Self::Reserved {
                    type_id: a,
                    bytes: ab,
                },
                Self::Reserved {
                    type_id: b,
                    bytes: bb,
                },
            ) => a == b && ab == bb,
            _ => false,
        }
    }
}

impl Value {
    /// The built-in type id of the value.
    pub fn type_id(&self) -> u8 {
        use type_id as t;
        match self {
            Value::Boolean(_) => t::BOOLEAN,
            Value::SByte(_) => t::SBYTE,
            Value::Byte(_) => t::BYTE,
            Value::Int16(_) => t::INT16,
            Value::UInt16(_) => t::UINT16,
            Value::Int32(_) => t::INT32,
            Value::UInt32(_) => t::UINT32,
            Value::Int64(_) => t::INT64,
            Value::UInt64(_) => t::UINT64,
            Value::Float(_) => t::FLOAT,
            Value::Double(_) => t::DOUBLE,
            Value::String(_) => t::STRING,
            Value::DateTime(_) => t::DATE_TIME,
            Value::Guid(_) => t::GUID,
            Value::ByteString(_) => t::BYTE_STRING,
            Value::XmlElement(_) => t::XML_ELEMENT,
            Value::NodeId(_) => t::NODE_ID,
            Value::ExpandedNodeId(_) => t::EXPANDED_NODE_ID,
            Value::StatusCode(_) => t::STATUS_CODE,
            Value::QualifiedName(_) => t::QUALIFIED_NAME,
            Value::LocalizedText(_) => t::LOCALIZED_TEXT,
            Value::ExtensionObject(_) => t::EXTENSION_OBJECT,
            Value::DataValue(_) => t::DATA_VALUE,
            Value::Variant(_) => t::VARIANT,
            Value::DiagnosticInfo(_) => t::DIAGNOSTIC_INFO,
            Value::Reserved { type_id, .. } => *type_id,
        }
    }

    /// Whether a reader takes type `t` in a Variant, inside
    /// `data_values` DataValues.
    fn readable(t: u8, data_values: usize) -> bool {
        match t {
            type_id::DATA_VALUE => data_values == 0,
            type_id::DIAGNOSTIC_INFO => false,
            1..=type_id::RESERVED_LAST => true,
            _ => false,
        }
    }

    /// Whether a writer writes type `t` in a Variant, inside
    /// `data_values` DataValues: what a reader takes, but no reserved ids.
    fn writable(t: u8, data_values: usize) -> bool {
        t < type_id::RESERVED_FIRST && Value::readable(t, data_values)
    }

    /// Reads a value of built-in type `t`, which [`Value::readable`] takes.
    fn decode(r: &mut Reader<'_>, t: u8) -> Result<Value, DecodeError> {
        use type_id as id;
        if !Value::readable(t, r.data_values) || (r.writable && !Value::writable(t, r.data_values))
        {
            return Err(DecodeError::VariantType(t));
        }
        Ok(match t {
            id::BOOLEAN => Value::Boolean(r.bool()?),
            id::SBYTE => Value::SByte(r.i8()?),
            id::BYTE => Value::Byte(r.u8()?),
            id::INT16 => Value::Int16(r.i16()?),
            id::UINT16 => Value::UInt16(r.u16()?),
            id::INT32 => Value::Int32(r.i32()?),
            id::UINT32 => Value::UInt32(r.u32()?),
            id::INT64 => Value::Int64(r.i64()?),
            id::UINT64 => Value::UInt64(r.u64()?),
            id::FLOAT => Value::Float(r.f32()?),
            id::DOUBLE => Value::Double(r.f64()?),
            id::STRING => Value::String(r.string()?),
            id::DATE_TIME => Value::DateTime(r.date_time()?),
            id::GUID => Value::Guid(r.read()?),
            id::BYTE_STRING => Value::ByteString(r.byte_string()?),
            id::XML_ELEMENT => Value::XmlElement(r.byte_string()?),
            id::NODE_ID => Value::NodeId(r.read()?),
            id::EXPANDED_NODE_ID => Value::ExpandedNodeId(r.read()?),
            id::STATUS_CODE => Value::StatusCode(r.read()?),
            id::QUALIFIED_NAME => Value::QualifiedName(r.read()?),
            id::LOCALIZED_TEXT => Value::LocalizedText(r.read()?),
            id::EXTENSION_OBJECT => Value::ExtensionObject(Box::new(r.read()?)),
            id::DATA_VALUE => Value::DataValue(Box::new(r.read()?)),
            id::VARIANT => Value::Variant(Box::new(r.read()?)),
            id::RESERVED_FIRST..=id::RESERVED_LAST => Value::Reserved {
                type_id: t,
                bytes: r.byte_string()?,
            },
            _ => return Err(DecodeError::VariantType(t)),
        })
    }

    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        if !Value::writable(self.type_id(), w.data_values) {
            return Err(EncodeError::VariantType);
        }
        match self {
            Value::Boolean(v) => w.bool(*v),
            Value::SByte(v) => w.i8(*v),
            Value::Byte(v) => w.u8(*v),
            Value::Int16(v) => w.i16(*v),
            Value::UInt16(v) => w.u16(*v),
            Value::Int32(v) => w.i32(*v),
            Value::UInt32(v) => w.u32(*v),
            Value::Int64(v) => w.i64(*v),
            Value::DateTime(v) => w.date_time(*v),
            Value::UInt64(v) => w.u64(*v),
            Value::Float(v) => w.f32(*v),
            Value::Double(v) => w.f64(*v),
            Value::String(s) => w.string(s.as_deref())?,
            Value::Guid(g) => g.encode(w)?,
            Value::ByteString(b) | Value::XmlElement(b) => w.byte_string(b.as_deref())?,
            Value::NodeId(n) => n.encode(w)?,
            Value::ExpandedNodeId(n) => n.encode(w)?,
            Value::StatusCode(s) => s.encode(w)?,
            Value::QualifiedName(q) => q.encode(w)?,
            Value::LocalizedText(l) => l.encode(w)?,
            Value::ExtensionObject(e) => e.encode(w)?,
            Value::DataValue(d) => d.encode(w)?,
            Value::Variant(v) => v.encode(w)?,
            Value::DiagnosticInfo(_) | Value::Reserved { .. } => {
                return Err(EncodeError::VariantType);
            }
        }
        Ok(())
    }
}

/// A Variant: a value of any built-in type, an array of them, or nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Variant {
    /// No value.
    #[default]
    Null,
    /// One value. It may not be a [`Value::Variant`].
    Scalar(Value),
    /// An array of values, all of built-in type `type_id`, which is never
    /// 0 or 25 (DiagnosticInfo). A null array reads as empty.
    /// With `dimensions`, the array is multi-dimensional: there are at least
    /// 2 dimensions, as Part 6 asks, every one is above 0, and they multiply
    /// out to its length.
    Array {
        /// The built-in type of every element, 1 to 31 but not 25.
        /// Writers also refuse the reserved ids, 26 to 31.
        type_id: u8,
        /// The elements. A multi-dimensional array is flattened with the
        /// last index changing fastest. A 2 by 2 array holds (0, 0),
        /// (0, 1), (1, 0), then (1, 1).
        values: Vec<Value>,
        /// The length of each dimension, if given.
        dimensions: Option<Vec<i32>>,
    },
}

impl From<Value> for Variant {
    /// The value as a scalar Variant.
    fn from(value: Value) -> Variant {
        Variant::Scalar(value)
    }
}

impl Binary for Variant {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.nested(Variant::decode_inner)
    }
}

impl Variant {
    fn decode_inner(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mask = r.u8()?;
        let t = mask & 0x3f;
        let is_array = mask & 0x80 != 0;
        let has_dims = mask & 0x40 != 0;
        let v = if t == type_id::NULL {
            if mask != 0 {
                return Err(DecodeError::VariantType(t));
            }
            Variant::Null
        } else if !is_array {
            if has_dims {
                return Err(DecodeError::Dimensions);
            }
            if t == type_id::VARIANT {
                return Err(DecodeError::VariantType(t));
            }
            Variant::Scalar(Value::decode(r, t)?)
        } else {
            // The type is checked before the length, so an empty array
            // of a type that cannot be there is refused too.
            if !Value::readable(t, r.data_values)
                || (r.writable && !Value::writable(t, r.data_values))
            {
                return Err(DecodeError::VariantType(t));
            }
            let n = r.array_len()?;
            let mut values = Vec::with_capacity(n);
            for _ in 0..n {
                values.push(Value::decode(r, t)?);
            }
            let dimensions = if has_dims {
                let count = r.i32()?;
                let count = match usize::try_from(count) {
                    Ok(c) if (2..=MAX_DIMENSIONS).contains(&c) => c,
                    _ => return Err(DecodeError::Dimensions),
                };
                let mut dims = Vec::with_capacity(count);
                for _ in 0..count {
                    dims.push(r.i32()?);
                }
                if !dims_match(&dims, n) {
                    return Err(DecodeError::Dimensions);
                }
                Some(dims)
            } else {
                None
            };
            Variant::Array {
                type_id: t,
                values,
                dimensions,
            }
        };
        Ok(v)
    }

    fn encode_inner(&self, w: &mut Writer) -> Result<(), EncodeError> {
        match self {
            Variant::Null => w.u8(0),
            Variant::Scalar(v) => {
                let t = v.type_id();
                if t == type_id::VARIANT {
                    return Err(EncodeError::VariantType);
                }
                w.u8(t);
                v.encode(w)?;
            }
            Variant::Array {
                type_id: t,
                values,
                dimensions,
            } => {
                if !Value::writable(*t, w.data_values) {
                    return Err(EncodeError::VariantType);
                }
                if values.iter().any(|v| v.type_id() != *t) {
                    return Err(EncodeError::VariantType);
                }
                if let Some(d) = dimensions
                    && (d.len() < 2 || d.len() > MAX_DIMENSIONS || !dims_match(d, values.len()))
                {
                    return Err(EncodeError::Dimensions);
                }
                w.u8(t | 0x80 | if dimensions.is_some() { 0x40 } else { 0 });
                w.array_len(values.len())?;
                for v in values {
                    v.encode(w)?;
                }
                if let Some(d) = dimensions {
                    w.i32(d.len() as i32);
                    for &n in d {
                        w.i32(n);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Whether every dimension is above 0 and they multiply out to `len`.
fn dims_match(dims: &[i32], len: usize) -> bool {
    let mut product: usize = 1;
    for &d in dims {
        let Ok(d) = usize::try_from(d) else {
            return false;
        };
        if d == 0 {
            return false;
        }
        match product.checked_mul(d) {
            Some(p) if p <= len => product = p,
            _ => return false,
        }
    }
    product == len
}

/// A DataValue: a value with its status and timestamps. Every field is
/// optional. A missing status means Good, and a missing timestamp means
/// none was given.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataValue {
    /// The value.
    pub value: Option<Variant>,
    /// The value's status.
    pub status: Option<StatusCode>,
    /// When the source made the value, as a DateTime.
    pub source_timestamp: Option<i64>,
    /// What to add to the source timestamp, in units of 10 picoseconds,
    /// up to [`MAX_PICOSECONDS`]. A reader reads a larger value as
    /// [`MAX_PICOSECONDS`]. Writers refuse a value above that limit.
    pub source_picoseconds: Option<u16>,
    /// When the server saw the value, as a DateTime.
    pub server_timestamp: Option<i64>,
    /// What to add to the server timestamp, in units of 10 picoseconds,
    /// up to [`MAX_PICOSECONDS`], as for the source.
    pub server_picoseconds: Option<u16>,
}

impl Binary for DataValue {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        // The Variant in a DataValue may not hold another DataValue, at
        // any depth.
        r.nested(|r| {
            r.data_values += 1;
            let out = DataValue::decode_inner(r);
            r.data_values -= 1;
            out
        })
    }
}

impl DataValue {
    fn decode_inner(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mask = r.u8()?;
        if mask & 0xc0 != 0 {
            return Err(DecodeError::Mask(mask));
        }
        let mut d = DataValue::default();
        if mask & 0x01 != 0 {
            d.value = Some(r.read()?);
        }
        if mask & 0x02 != 0 {
            d.status = Some(r.read()?);
        }
        if mask & 0x04 != 0 {
            d.source_timestamp = Some(r.date_time()?);
        }
        if mask & 0x10 != 0 {
            d.source_picoseconds = Some(r.u16()?.min(MAX_PICOSECONDS));
        }
        if mask & 0x08 != 0 {
            d.server_timestamp = Some(r.date_time()?);
        }
        if mask & 0x20 != 0 {
            d.server_picoseconds = Some(r.u16()?.min(MAX_PICOSECONDS));
        }
        Ok(d)
    }

    fn encode_inner(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let mut mask = 0;
        let bits = [
            (self.value.is_some(), 0x01),
            (self.status.is_some(), 0x02),
            (self.source_timestamp.is_some(), 0x04),
            (self.server_timestamp.is_some(), 0x08),
            (self.source_picoseconds.is_some(), 0x10),
            (self.server_picoseconds.is_some(), 0x20),
        ];
        for (set, bit) in bits {
            if set {
                mask |= bit;
            }
        }
        w.u8(mask);
        if let Some(v) = &self.value {
            v.encode(w)?;
        }
        if let Some(s) = self.status {
            s.encode(w)?;
        }
        if let Some(t) = self.source_timestamp {
            w.date_time(t);
        }
        if let Some(p) = self.source_picoseconds {
            if p > MAX_PICOSECONDS {
                return Err(EncodeError::Value);
            }
            w.u16(p);
        }
        if let Some(t) = self.server_timestamp {
            w.date_time(t);
        }
        if let Some(p) = self.server_picoseconds {
            if p > MAX_PICOSECONDS {
                return Err(EncodeError::Value);
            }
            w.u16(p);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Chunks and the connection protocol
// ---------------------------------------------------------------------

/// The message type in a chunk header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// HEL: the client opens the connection.
    Hello,
    /// ACK: the server accepts it.
    Acknowledge,
    /// ERR: either side reports an error and closes.
    Error,
    /// RHE: a server opens a connection to a client, which then sends a
    /// Hello.
    ReverseHello,
    /// OPN: opens or renews a secure channel.
    Open,
    /// CLO: closes a secure channel.
    Close,
    /// MSG: any other service request or response.
    Message,
}

impl MessageType {
    /// The three ASCII letters that name the type.
    pub fn code(self) -> [u8; 3] {
        *match self {
            MessageType::Hello => b"HEL",
            MessageType::Acknowledge => b"ACK",
            MessageType::Error => b"ERR",
            MessageType::ReverseHello => b"RHE",
            MessageType::Open => b"OPN",
            MessageType::Close => b"CLO",
            MessageType::Message => b"MSG",
        }
    }

    /// The type that `code` names, if any.
    pub fn from_code(code: [u8; 3]) -> Option<MessageType> {
        Some(match &code {
            b"HEL" => MessageType::Hello,
            b"ACK" => MessageType::Acknowledge,
            b"ERR" => MessageType::Error,
            b"RHE" => MessageType::ReverseHello,
            b"OPN" => MessageType::Open,
            b"CLO" => MessageType::Close,
            b"MSG" => MessageType::Message,
            _ => return None,
        })
    }

    /// Whether this is one of the connection protocol's messages (HEL,
    /// ACK, ERR, RHE) rather than a secure channel chunk.
    pub fn is_handshake(self) -> bool {
        matches!(
            self,
            MessageType::Hello
                | MessageType::Acknowledge
                | MessageType::Error
                | MessageType::ReverseHello
        )
    }
}

/// The chunk type, the fourth byte of a chunk header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChunkType {
    /// `F`: the last chunk of a message, or its only one.
    Final,
    /// `C`: a chunk with more to follow. Only MSG chunks may be one.
    Intermediate,
    /// `A`: the sender gave up on the message. Only MSG chunks may be one.
    Abort,
}

impl ChunkType {
    /// The ASCII byte for the type.
    pub fn byte(self) -> u8 {
        match self {
            ChunkType::Final => b'F',
            ChunkType::Intermediate => b'C',
            ChunkType::Abort => b'A',
        }
    }

    /// The type that `byte` names, if any.
    pub fn from_byte(byte: u8) -> Option<ChunkType> {
        match byte {
            b'F' => Some(ChunkType::Final),
            b'C' => Some(ChunkType::Intermediate),
            b'A' => Some(ChunkType::Abort),
            _ => None,
        }
    }
}

/// One chunk: its header's types and the bytes after the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The message type.
    pub message_type: MessageType,
    /// The chunk type.
    pub chunk_type: ChunkType,
    /// Every byte after the 8-byte header.
    pub body: Vec<u8>,
}

/// Why a byte stream is not OPC UA. Every one is fatal: the stream holds
/// no more messages a reader can find, and a real server sends an ERR
/// with [`ChunkError::status`] and closes the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// The first three bytes named no message type.
    MessageType([u8; 3]),
    /// The chunk type byte is not one this message type may have.
    ChunkType(MessageType, u8),
    /// The size in the header is smaller than the header.
    TooSmall(u32),
    /// The size in the header is larger than the receiver takes.
    TooLarge {
        /// The size in the header.
        size: u32,
        /// The largest size taken.
        limit: u32,
    },
    /// The chunk's fields did not read.
    Decode(MessageType, DecodeError),
    /// A Hello or Acknowledge named a buffer smaller than
    /// [`MIN_BUFFER_SIZE`].
    BufferSize(u32),
    /// A chunk of another message came before the last chunk of a MSG.
    Interleaved,
    /// A MSG chunk named a different channel or token from the chunks
    /// before it.
    Mismatch,
    /// An OPN, CLO or MSG chunk's sequence number did not follow the one
    /// before it on the connection.
    Sequence {
        /// The number that would have followed.
        expected: u32,
        /// The number that came.
        got: u32,
    },
    /// A message's body grew past the negotiated limit.
    MessageTooLarge(u32),
    /// A message took more chunks than the negotiated limit.
    TooManyChunks(u32),
    /// Input ended before the final chunk of a message.
    Incomplete,
}

impl ChunkError {
    /// The status code a server sends in an ERR message for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            ChunkError::MessageType(_) | ChunkError::ChunkType(..) => {
                StatusCode::BAD_TCP_MESSAGE_TYPE_INVALID
            }
            // The endpoint URL is the only length a Hello holds.
            ChunkError::Decode(MessageType::Hello, DecodeError::Length(_)) => {
                StatusCode::BAD_TCP_ENDPOINT_URL_INVALID
            }
            ChunkError::TooSmall(_)
            | ChunkError::Decode(..)
            | ChunkError::Interleaved
            | ChunkError::Incomplete => StatusCode::BAD_DECODING_ERROR,
            ChunkError::TooLarge { .. } => StatusCode::BAD_TCP_MESSAGE_TOO_LARGE,
            ChunkError::BufferSize(_) => StatusCode::BAD_TCP_NOT_ENOUGH_RESOURCES,
            ChunkError::Mismatch => StatusCode::BAD_TCP_SECURE_CHANNEL_UNKNOWN,
            ChunkError::Sequence { .. } => StatusCode::BAD_SEQUENCE_NUMBER_INVALID,
            ChunkError::MessageTooLarge(_) | ChunkError::TooManyChunks(_) => {
                StatusCode::BAD_REQUEST_TOO_LARGE
            }
        }
    }
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkError::MessageType(c) => write!(
                f,
                "message type {:?} is not OPC UA",
                String::from_utf8_lossy(c)
            ),
            ChunkError::ChunkType(t, b) => write!(f, "chunk type {b:#04x} is not valid for {t:?}"),
            ChunkError::TooSmall(n) => write!(f, "chunk size {n} is smaller than its header"),
            ChunkError::TooLarge { size, limit } => {
                write!(f, "chunk size {size} is over the limit of {limit}")
            }
            ChunkError::Decode(t, e) => write!(f, "{t:?} chunk: {e}"),
            ChunkError::BufferSize(n) => write!(f, "buffer size {n} is below {MIN_BUFFER_SIZE}"),
            ChunkError::Interleaved => f.write_str("chunks of two messages were interleaved"),
            ChunkError::Mismatch => f.write_str("a chunk named another channel or token"),
            ChunkError::Sequence { expected, got } => {
                write!(f, "sequence number {got}, expected {expected}")
            }
            ChunkError::MessageTooLarge(n) => write!(f, "message body over the limit of {n} bytes"),
            ChunkError::TooManyChunks(n) => write!(f, "message over the limit of {n} chunks"),
            ChunkError::Incomplete => f.write_str("incomplete OPC UA message"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// What one side of a connection takes in: the largest chunk, the largest
/// message body and the most chunks in one message. A limit of 0 means
/// none was set; the module's own caps apply either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest chunk, in bytes, with its header.
    pub receive_buffer_size: u32,
    /// The largest message body, put together from its chunks.
    pub max_message_size: u32,
    /// The most chunks in one message.
    pub max_chunk_count: u32,
}

impl Default for Limits {
    /// What a decoder takes before anything is negotiated: chunks of
    /// [`MIN_BUFFER_SIZE`], and no message or chunk count limit.
    fn default() -> Limits {
        Limits {
            receive_buffer_size: MIN_BUFFER_SIZE,
            max_message_size: 0,
            max_chunk_count: 0,
        }
    }
}

impl Limits {
    /// The largest chunk taken: the receive buffer size, raised to
    /// [`MIN_BUFFER_SIZE`] and capped at [`MAX_BUFFER_SIZE`].
    pub fn chunk_limit(&self) -> u32 {
        self.receive_buffer_size
            .clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE)
    }

    /// The largest message body taken, capped at [`MAX_MESSAGE_SIZE`].
    pub fn message_limit(&self) -> u32 {
        match self.max_message_size {
            0 => MAX_MESSAGE_SIZE,
            n => n.min(MAX_MESSAGE_SIZE),
        }
    }

    /// The most chunks taken in one message, capped at
    /// [`MAX_CHUNK_COUNT`].
    pub fn chunk_count_limit(&self) -> u32 {
        match self.max_chunk_count {
            0 => MAX_CHUNK_COUNT,
            n => n.min(MAX_CHUNK_COUNT),
        }
    }
}

impl Chunk {
    /// Reads the chunk at the start of `b`, refusing one larger than
    /// `limits` allow. A HEL, ACK, ERR or RHE may be as large as
    /// [`MAX_HANDSHAKE_SIZE`] whatever the limits. It returns `Ok(None)` if
    /// `b` holds only part of a chunk, and otherwise the chunk and how many
    /// bytes it took. A bad type is found from the first bytes, and a bad
    /// size from the header, before the rest comes.
    pub fn parse(b: &[u8], limits: &Limits) -> Result<Option<(Chunk, usize)>, ChunkError> {
        if b.len() < 3 {
            return Ok(None);
        }
        let code = [b[0], b[1], b[2]];
        let message_type = MessageType::from_code(code).ok_or(ChunkError::MessageType(code))?;
        let Some(&ct) = b.get(3) else { return Ok(None) };
        let chunk_type = match (ct, message_type) {
            // For HEL, ACK, ERR and RHE the byte is reserved: senders write
            // 'F' and receivers ignore it (Part 6, 7.1.2.2).
            (_, t) if t.is_handshake() => ChunkType::Final,
            (b'F', _) => ChunkType::Final,
            (b'C', MessageType::Message) => ChunkType::Intermediate,
            (b'A', MessageType::Message) => ChunkType::Abort,
            _ => return Err(ChunkError::ChunkType(message_type, ct)),
        };
        if b.len() < HEADER_LEN {
            return Ok(None);
        }
        let size = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let limit = if message_type.is_handshake() {
            limits.chunk_limit().max(MAX_HANDSHAKE_SIZE)
        } else {
            limits.chunk_limit()
        };
        if (size as usize) < HEADER_LEN {
            return Err(ChunkError::TooSmall(size));
        }
        if size > limit {
            return Err(ChunkError::TooLarge { size, limit });
        }
        let end = size as usize;
        if b.len() < end {
            return Ok(None);
        }
        Ok(Some((
            Chunk {
                message_type,
                chunk_type,
                body: b[HEADER_LEN..end].to_vec(),
            },
            end,
        )))
    }
}

/// Why an exact [`Wire`] parse did not read one complete chunk.
/// [`Chunk::parse`] reads a prefix under caller-supplied limits and returns
/// the bytes used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkParseError {
    /// The chunk header is invalid or exceeds [`MAX_BUFFER_SIZE`].
    Chunk(ChunkError),
    /// The input ended before a complete chunk, including empty input.
    Truncated,
    /// Bytes follow the first complete chunk.
    Trailing,
}

impl core::fmt::Display for ChunkParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Chunk(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete OPC UA chunk"),
            Self::Trailing => f.write_str("bytes follow the OPC UA chunk"),
        }
    }
}

impl core::error::Error for ChunkParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Chunk(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

impl Wire for Chunk {
    type ParseError = ChunkParseError;
    type WriteError = ChunkError;

    /// Reads exactly one chunk bounded by [`MAX_BUFFER_SIZE`].
    /// The body stays opaque. Negotiated limits belong to [`Frames`].
    /// Handshake chunk type bytes read as [`ChunkType::Final`].
    fn parse(b: &[u8]) -> Result<Self, ChunkParseError> {
        let limits = Limits {
            receive_buffer_size: MAX_BUFFER_SIZE,
            ..Limits::default()
        };
        match Self::parse(b, &limits).map_err(ChunkParseError::Chunk)? {
            Some((chunk, used)) if used == b.len() => Ok(chunk),
            Some(_) => Err(ChunkParseError::Trailing),
            None => Err(ChunkParseError::Truncated),
        }
    }

    /// Appends at most [`MAX_BUFFER_SIZE`] bytes, leaving `out` unchanged
    /// on error. Only MSG chunks may be intermediate or abort chunks.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), ChunkError> {
        if self.message_type != MessageType::Message && self.chunk_type != ChunkType::Final {
            return Err(ChunkError::ChunkType(
                self.message_type,
                self.chunk_type.byte(),
            ));
        }
        let size = self
            .body
            .len()
            .checked_add(HEADER_LEN)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ChunkError::TooLarge {
                size: u32::MAX,
                limit: MAX_BUFFER_SIZE,
            })?;
        if size > MAX_BUFFER_SIZE {
            return Err(ChunkError::TooLarge {
                size,
                limit: MAX_BUFFER_SIZE,
            });
        }
        out.extend_from_slice(&self.message_type.code());
        out.push(self.chunk_type.byte());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

/// Reads OPC UA TCP chunks without holding input bytes or joining messages.
///
/// Capacity is the larger of [`Limits::chunk_limit`] and
/// [`MAX_HANDSHAKE_SIZE`]. Oversized chunks fail from their header.
/// Partial chunks return [`Step::Need`], including at EOF, when
/// [`Stream`](super::codec::Stream) reports truncation.
/// Message bodies, chunk counts, and sequence numbers are not checked here.
/// Use [`Messages`] for message assembly and connection checks.
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames {
    limits: Limits,
}

impl Frames {
    /// Creates a chunk decoder with [`Limits::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a chunk decoder with the given receive buffer size.
    /// [`Limits::chunk_limit`] clamps it to the module's bounds.
    /// Message size and chunk count limits do not affect framing.
    pub fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }

    /// Sets negotiated limits between calls to the stream's `next` method.
    /// Chunks already returned are not checked again.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Returns the supplied limits before clamping the receive buffer size.
    pub fn limits(&self) -> Limits {
        self.limits
    }
}

impl Decode for Frames {
    type Item = Chunk;
    type Error = ChunkError;
    const NAME: &'static str = "OPC UA TCP";

    fn capacity(&self) -> usize {
        self.limits.chunk_limit().max(MAX_HANDSHAKE_SIZE) as usize
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Chunk>, ChunkError> {
        Ok(match Chunk::parse(input, &self.limits)? {
            Some((chunk, used)) => Step::Item(chunk, used),
            None => Step::Need,
        })
    }
}

/// Reads the reason of an Error message or abort chunk. One longer than
/// [`MAX_REASON_LEN`] is dropped unread and comes back empty, as Part 6
/// asks of receivers. A null one reads as empty.
fn read_reason(r: &mut Reader<'_>) -> Result<String, DecodeError> {
    match r.byte_string()? {
        Some(b) if b.len() <= MAX_REASON_LEN => String::from_utf8(b).map_err(|_| DecodeError::Utf8),
        _ => Ok(String::new()),
    }
}

/// Builds a chunk value from its body.
fn chunk(message_type: MessageType, chunk_type: ChunkType, body: Vec<u8>) -> Chunk {
    Chunk {
        message_type,
        chunk_type,
        body,
    }
}

/// A Hello: the first message a client sends, naming what it can take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The protocol version the client speaks; 0 today.
    pub protocol_version: u32,
    /// The largest chunk the client takes.
    pub receive_buffer_size: u32,
    /// The largest chunk the client will send.
    pub send_buffer_size: u32,
    /// The largest response body the client takes; 0 for no limit.
    pub max_message_size: u32,
    /// The most chunks in a response the client takes; 0 for no limit.
    pub max_chunk_count: u32,
    /// The URL the client is connecting to. A null one reads as empty.
    pub endpoint_url: String,
}

impl Hello {
    /// What the client takes in, for writing to it.
    pub fn limits(&self) -> Limits {
        Limits {
            receive_buffer_size: self.receive_buffer_size,
            max_message_size: self.max_message_size,
            max_chunk_count: self.max_chunk_count,
        }
    }

    /// The Acknowledge a server with receive limits `ours` answers with.
    /// Its buffer sizes are what both sides can take, and never below
    /// [`MIN_BUFFER_SIZE`]. Its message and chunk count limits are the
    /// ones a [`Messages`] with `ours` enforces, so they are never 0: the
    /// module's own caps always apply.
    pub fn acknowledge(&self, ours: &Limits) -> Acknowledge {
        Acknowledge {
            protocol_version: PROTOCOL_VERSION,
            receive_buffer_size: ours
                .chunk_limit()
                .min(self.send_buffer_size)
                .max(MIN_BUFFER_SIZE),
            send_buffer_size: self
                .receive_buffer_size
                .clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE),
            max_message_size: ours.message_limit(),
            max_chunk_count: ours.chunk_count_limit(),
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Hello, DecodeError> {
        Ok(Hello {
            protocol_version: r.u32()?,
            receive_buffer_size: r.u32()?,
            send_buffer_size: r.u32()?,
            max_message_size: r.u32()?,
            max_chunk_count: r.u32()?,
            endpoint_url: r.string_max(MAX_URL_LEN)?.unwrap_or_default(),
        })
    }

    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        check_buffers(self.receive_buffer_size, self.send_buffer_size)?;
        let mut w = Writer::new();
        for v in [
            self.protocol_version,
            self.receive_buffer_size,
            self.send_buffer_size,
            self.max_message_size,
            self.max_chunk_count,
        ] {
            w.u32(v);
        }
        w.string_max(Some(&self.endpoint_url), MAX_URL_LEN)?;
        w.into_bytes()
    }
}

/// An Acknowledge: the server's answer to a Hello, naming what it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acknowledge {
    /// The protocol version both sides speak.
    pub protocol_version: u32,
    /// The largest chunk the server takes. No larger than the client's
    /// send buffer.
    pub receive_buffer_size: u32,
    /// The largest chunk the server will send. No larger than the client's
    /// receive buffer.
    pub send_buffer_size: u32,
    /// The largest request body the server takes; 0 for no limit.
    pub max_message_size: u32,
    /// The most chunks in a request the server takes; 0 for no limit.
    pub max_chunk_count: u32,
}

impl Acknowledge {
    /// What the server takes in, for writing to it, and for its own
    /// [`Messages::set_limits`].
    pub fn limits(&self) -> Limits {
        Limits {
            receive_buffer_size: self.receive_buffer_size,
            max_message_size: self.max_message_size,
            max_chunk_count: self.max_chunk_count,
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Acknowledge, DecodeError> {
        Ok(Acknowledge {
            protocol_version: r.u32()?,
            receive_buffer_size: r.u32()?,
            send_buffer_size: r.u32()?,
            max_message_size: r.u32()?,
            max_chunk_count: r.u32()?,
        })
    }

    fn body(&self) -> Result<Vec<u8>, EncodeError> {
        check_buffers(self.receive_buffer_size, self.send_buffer_size)?;
        let mut w = Writer::new();
        for v in [
            self.protocol_version,
            self.receive_buffer_size,
            self.send_buffer_size,
            self.max_message_size,
            self.max_chunk_count,
        ] {
            w.u32(v);
        }
        w.into_bytes()
    }
}

fn check_buffers(receive: u32, send: u32) -> Result<(), EncodeError> {
    for n in [receive, send] {
        if n < MIN_BUFFER_SIZE {
            return Err(EncodeError::BufferSize(n));
        }
    }
    Ok(())
}

/// An Error message: why the sender is closing the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMessage {
    /// The status code.
    pub error: StatusCode,
    /// Text for a person to read. A null one reads as empty.
    pub reason: String,
}

/// A ReverseHello: a server behind a firewall opens a connection to a
/// client, which answers with a Hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseHello {
    /// The server's application URI. A null one reads as empty.
    pub server_uri: String,
    /// The URL the client uses in its Hello. A null one reads as empty.
    pub endpoint_url: String,
}

/// The length of a receiver certificate thumbprint that is present.
pub const THUMBPRINT_LEN: usize = 20;

/// The security header of an OPN chunk. Readers and writers both check
/// Part 6, 6.7.2.3: under policy None, where nothing is signed or
/// encrypted, the certificate and thumbprint are null or empty, and under
/// any policy a thumbprint is null, empty or [`THUMBPRINT_LEN`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsymmetricHeader {
    /// The security policy's URI. A null one reads as empty.
    pub policy_uri: String,
    /// The sender's certificate; null or empty under policy None.
    pub sender_certificate: Option<Vec<u8>>,
    /// The thumbprint of the receiver's certificate; null or empty under
    /// policy None.
    pub receiver_thumbprint: Option<Vec<u8>>,
}

impl AsymmetricHeader {
    /// The header for security policy None.
    pub fn none() -> AsymmetricHeader {
        AsymmetricHeader {
            policy_uri: SECURITY_POLICY_NONE.to_string(),
            sender_certificate: None,
            receiver_thumbprint: None,
        }
    }

    /// The length of the first field that breaks Part 6's rules for this
    /// policy, if any.
    fn bad_length(&self) -> Option<usize> {
        let len = |f: &Option<Vec<u8>>| f.as_ref().map_or(0, Vec::len);
        let (cert, thumb) = (
            len(&self.sender_certificate),
            len(&self.receiver_thumbprint),
        );
        if self.policy_uri == SECURITY_POLICY_NONE {
            [cert, thumb].into_iter().find(|&n| n != 0)
        } else {
            Some(thumb).filter(|&n| n != 0 && n != THUMBPRINT_LEN)
        }
    }
}

/// What kind of secure message this is, with its security header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecureKind {
    /// OPN: always one chunk.
    Open(AsymmetricHeader),
    /// CLO: always one chunk.
    Close {
        /// The security token the channel is using.
        token_id: u32,
    },
    /// MSG: one or more chunks.
    Message {
        /// The security token the channel is using.
        token_id: u32,
    },
}

impl SecureKind {
    /// The message type its chunks carry.
    pub fn message_type(&self) -> MessageType {
        match self {
            SecureKind::Open(_) => MessageType::Open,
            SecureKind::Close { .. } => MessageType::Close,
            SecureKind::Message { .. } => MessageType::Message,
        }
    }
}

/// A whole OPN, CLO or MSG message, its chunks put back together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureMessage {
    /// The kind and its security header.
    pub kind: SecureKind,
    /// The secure channel; 0 in a request to open a new one.
    pub channel_id: u32,
    /// The first chunk's sequence number. Each later chunk's is one more.
    pub sequence_number: u32,
    /// Chosen by the client and copied into the response.
    pub request_id: u32,
    /// The body. Under policy None it is a [`Service`] encoding.
    pub body: Vec<u8>,
}

/// An abort chunk: the sender gave up on a MSG partway through. Any
/// chunks of it already read are dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abort {
    /// The secure channel.
    pub channel_id: u32,
    /// The security token.
    pub token_id: u32,
    /// The abort chunk's sequence number.
    pub sequence_number: u32,
    /// The request given up on.
    pub request_id: u32,
    /// Why.
    pub error: StatusCode,
    /// Text for a person to read. A null one reads as empty.
    pub reason: String,
}

/// A whole message read from a stream, or one to write to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// HEL.
    Hello(Hello),
    /// ACK.
    Acknowledge(Acknowledge),
    /// ERR.
    Error(ErrorMessage),
    /// RHE.
    ReverseHello(ReverseHello),
    /// OPN, CLO or MSG.
    Secure(SecureMessage),
    /// An abort chunk of a MSG.
    Abort(Abort),
}

impl Message {
    /// Splits the message into as few chunks as a peer that takes
    /// `peer` allows. Write each chunk with [`Wire::write`]. It fails if the
    /// message breaks a rule or limit the peer's [`Messages`] checks:
    /// an OPN or CLO too large for one chunk, a MSG with too large a body or
    /// needing too many chunks, a buffer size below [`MIN_BUFFER_SIZE`], or a
    /// string past its limit.
    pub fn chunks(&self, peer: &Limits) -> Result<Vec<Chunk>, EncodeError> {
        Ok(vec![match self {
            Message::Hello(h) => chunk(MessageType::Hello, ChunkType::Final, h.body()?),
            Message::Acknowledge(a) => chunk(MessageType::Acknowledge, ChunkType::Final, a.body()?),
            Message::Error(e) => {
                let mut w = Writer::new();
                e.error.encode(&mut w)?;
                w.string_max(Some(&e.reason), MAX_REASON_LEN)?;
                chunk(MessageType::Error, ChunkType::Final, w.into_bytes()?)
            }
            Message::ReverseHello(rh) => {
                let mut w = Writer::new();
                w.string_max(Some(&rh.server_uri), MAX_URL_LEN)?;
                w.string_max(Some(&rh.endpoint_url), MAX_URL_LEN)?;
                chunk(MessageType::ReverseHello, ChunkType::Final, w.into_bytes()?)
            }
            Message::Secure(m) => return m.chunks(peer),
            Message::Abort(a) => {
                let mut w = Writer::new();
                for v in [a.channel_id, a.token_id, a.sequence_number, a.request_id] {
                    w.u32(v);
                }
                a.error.encode(&mut w)?;
                w.string_max(Some(&a.reason), MAX_REASON_LEN)?;
                // At most 4 * 5 + 4 + MAX_REASON_LEN bytes, under any chunk limit.
                chunk(MessageType::Message, ChunkType::Abort, w.into_bytes()?)
            }
        }])
    }
}

impl SecureMessage {
    /// Splits the message into chunks, each as large as a peer that takes `peer`
    /// allows. See [`Message::chunks`] for when it fails.
    pub fn chunks(&self, peer: &Limits) -> Result<Vec<Chunk>, EncodeError> {
        let chunk_limit = peer.chunk_limit() as usize;
        if self.body.len() > peer.message_limit() as usize {
            return Err(EncodeError::TooLong);
        }
        let mut w = Writer::new();
        w.u32(self.channel_id);
        match &self.kind {
            SecureKind::Open(h) => {
                if h.bad_length().is_some() {
                    return Err(EncodeError::SecurityHeader);
                }
                w.string_max(Some(&h.policy_uri), MAX_POLICY_URI_LEN)?;
                w.byte_string(h.sender_certificate.as_deref())?;
                w.byte_string(h.receiver_thumbprint.as_deref())?;
            }
            SecureKind::Close { token_id } | SecureKind::Message { token_id } => w.u32(*token_id),
        }
        let security = w.into_bytes()?;
        let message_type = self.kind.message_type();
        // The header, the security header and the sequence header.
        let overhead = HEADER_LEN + security.len() + 8;
        if overhead > chunk_limit || (overhead == chunk_limit && !self.body.is_empty()) {
            return Err(EncodeError::TooLong);
        }
        let per_chunk = chunk_limit - overhead;
        let single = !matches!(self.kind, SecureKind::Message { .. });
        // Count the chunks before making any, so a message that cannot be
        // sent allocates nothing for them.
        let count = if self.body.is_empty() {
            1
        } else {
            self.body.len().div_ceil(per_chunk)
        };
        if (single && count > 1) || count > peer.chunk_count_limit() as usize {
            return Err(EncodeError::TooLong);
        }
        let pieces: Box<dyn Iterator<Item = &[u8]>> = if self.body.is_empty() {
            Box::new(std::iter::once(&[][..]))
        } else {
            Box::new(self.body.chunks(per_chunk))
        };
        let last = count - 1;
        let mut out = Vec::with_capacity(count);
        for (i, piece) in pieces.enumerate() {
            let mut body = Vec::with_capacity(security.len() + 8 + piece.len());
            body.extend_from_slice(&security);
            body.extend_from_slice(&self.sequence_number.wrapping_add(i as u32).to_le_bytes());
            body.extend_from_slice(&self.request_id.to_le_bytes());
            body.extend_from_slice(piece);
            let chunk_type = if i == last {
                ChunkType::Final
            } else {
                ChunkType::Intermediate
            };
            out.push(chunk(message_type, chunk_type, body));
        }
        Ok(out)
    }
}

/// A MSG whose final chunk has not come yet.
#[derive(Debug)]
struct Partial {
    channel_id: u32,
    token_id: u32,
    first_sequence: u32,
    request_id: u32,
    body: Vec<u8>,
    chunks: u32,
}

/// The fields of one OPN, CLO or MSG chunk.
struct SecureChunk {
    kind: SecureKind,
    channel_id: u32,
    sequence_number: u32,
    request_id: u32,
    rest: Vec<u8>,
}

fn decode_secure(message_type: MessageType, body: &[u8]) -> Result<SecureChunk, DecodeError> {
    let mut r = Reader::new(body);
    let channel_id = r.u32()?;
    let kind = match message_type {
        MessageType::Open => {
            let h = AsymmetricHeader {
                policy_uri: r.string_max(MAX_POLICY_URI_LEN)?.unwrap_or_default(),
                sender_certificate: r.byte_string()?,
                receiver_thumbprint: r.byte_string()?,
            };
            if let Some(n) = h.bad_length() {
                return Err(DecodeError::Length(i32::try_from(n).unwrap_or(i32::MAX)));
            }
            SecureKind::Open(h)
        }
        MessageType::Close => SecureKind::Close { token_id: r.u32()? },
        _ => SecureKind::Message { token_id: r.u32()? },
    };
    let sequence_number = r.u32()?;
    let request_id = r.u32()?;
    Ok(SecureChunk {
        kind,
        channel_id,
        sequence_number,
        request_id,
        rest: r.rest().to_vec(),
    })
}

/// Whether `got` follows `prev`: one more, or a wrap to below 1024 from a
/// number above [`LEGACY_WRAP`].
fn follows(prev: u32, got: u32) -> bool {
    got == prev.wrapping_add(1) || (prev > LEGACY_WRAP && got < 1024)
}

/// Reads OPC UA messages and assembles MSG chunks under negotiated limits.
///
/// Use with [`Stream`](super::codec::Stream). Each secure chunk must follow
/// the previous sequence number, including across message boundaries.
/// Input stays in the stream. Only an unfinished message body is held here.
/// EOF during an assembly returns [`ChunkError::Incomplete`], including when
/// its body is empty. [`Decode::held`] counts body bytes, so zero held bytes
/// does not imply a complete message. Use [`Messages::is_between_messages`]
/// to check for an unfinished assembly. Set receive limits between messages
/// through [`Stream::decoder`](super::codec::Stream::decoder).
#[derive(Debug, Default)]
pub struct Messages {
    limits: Limits,
    partial: Option<Partial>,
    last_sequence: Option<u32>,
}

impl Messages {
    /// Creates a message decoder with [`Limits::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a message decoder with the supplied receive limits.
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Sets receive limits. Use [`Self::is_between_messages`] to check for
    /// an unfinished assembly first. Already consumed chunks are not checked
    /// again. A smaller limit applies to the next chunk.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Returns true when no partial message assembly is held.
    ///
    /// Empty intermediate MSG chunks still start an assembly, even when
    /// [`Decode::held`] is zero. This does not inspect unread stream bytes.
    pub fn is_between_messages(&self) -> bool {
        self.partial.is_none()
    }

    /// Returns the supplied receive limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Handles one chunk: a whole message, or `None` for part of a MSG.
    fn take(&mut self, chunk: Chunk) -> Result<Option<Message>, ChunkError> {
        let t = chunk.message_type;
        let de = |e| ChunkError::Decode(t, e);
        // An ERR may come at any time: the peer is closing the connection,
        // and any MSG it was sending is dropped.
        if t == MessageType::Error {
            self.partial = None;
        }
        if t != MessageType::Message && self.partial.is_some() {
            return Err(ChunkError::Interleaved);
        }
        let mut r = Reader::new(&chunk.body);
        let message = match t {
            MessageType::Hello => {
                let h = Hello::decode(&mut r).map_err(de)?;
                r.finish().map_err(de)?;
                for n in [h.receive_buffer_size, h.send_buffer_size] {
                    if n < MIN_BUFFER_SIZE {
                        return Err(ChunkError::BufferSize(n));
                    }
                }
                Message::Hello(h)
            }
            MessageType::Acknowledge => {
                let a = Acknowledge::decode(&mut r).map_err(de)?;
                r.finish().map_err(de)?;
                for n in [a.receive_buffer_size, a.send_buffer_size] {
                    if n < MIN_BUFFER_SIZE {
                        return Err(ChunkError::BufferSize(n));
                    }
                }
                Message::Acknowledge(a)
            }
            MessageType::Error => {
                let error = r.read().map_err(de)?;
                let reason = read_reason(&mut r).map_err(de)?;
                r.finish().map_err(de)?;
                Message::Error(ErrorMessage { error, reason })
            }
            MessageType::ReverseHello => {
                let server_uri = r.string_max(MAX_URL_LEN).map_err(de)?.unwrap_or_default();
                let endpoint_url = r.string_max(MAX_URL_LEN).map_err(de)?.unwrap_or_default();
                r.finish().map_err(de)?;
                Message::ReverseHello(ReverseHello {
                    server_uri,
                    endpoint_url,
                })
            }
            MessageType::Open | MessageType::Close | MessageType::Message => {
                let s = decode_secure(t, &chunk.body).map_err(de)?;
                return self.take_secure(chunk.chunk_type, s);
            }
        };
        Ok(Some(message))
    }

    fn take_secure(
        &mut self,
        chunk_type: ChunkType,
        s: SecureChunk,
    ) -> Result<Option<Message>, ChunkError> {
        if let Some(prev) = self.last_sequence
            && !follows(prev, s.sequence_number)
        {
            return Err(ChunkError::Sequence {
                expected: prev.wrapping_add(1),
                got: s.sequence_number,
            });
        }
        self.last_sequence = Some(s.sequence_number);
        let message_limit = self.limits.message_limit();
        let count_limit = self.limits.chunk_count_limit();
        let token_id = match s.kind {
            SecureKind::Message { token_id } => token_id,
            _ => {
                // OPN and CLO are one chunk, and come between messages.
                if s.rest.len() > message_limit as usize {
                    return Err(ChunkError::MessageTooLarge(message_limit));
                }
                return Ok(Some(Message::Secure(SecureMessage {
                    kind: s.kind,
                    channel_id: s.channel_id,
                    sequence_number: s.sequence_number,
                    request_id: s.request_id,
                    body: s.rest,
                })));
            }
        };
        let mut partial = match self.partial.take() {
            Some(p) => {
                if p.request_id != s.request_id {
                    return Err(ChunkError::Interleaved);
                }
                if p.channel_id != s.channel_id || p.token_id != token_id {
                    return Err(ChunkError::Mismatch);
                }
                p
            }
            None => Partial {
                channel_id: s.channel_id,
                token_id,
                first_sequence: s.sequence_number,
                request_id: s.request_id,
                body: Vec::new(),
                chunks: 0,
            },
        };
        if chunk_type == ChunkType::Abort {
            let mut r = Reader::new(&s.rest);
            let de = |e| ChunkError::Decode(MessageType::Message, e);
            let error = r.read().map_err(de)?;
            let reason = read_reason(&mut r).map_err(de)?;
            r.finish().map_err(de)?;
            return Ok(Some(Message::Abort(Abort {
                channel_id: s.channel_id,
                token_id,
                sequence_number: s.sequence_number,
                request_id: s.request_id,
                error,
                reason,
            })));
        }
        partial.chunks = partial
            .chunks
            .checked_add(1)
            .ok_or(ChunkError::TooManyChunks(count_limit))?;
        if partial.chunks > count_limit {
            return Err(ChunkError::TooManyChunks(count_limit));
        }
        if partial
            .body
            .len()
            .checked_add(s.rest.len())
            .is_none_or(|n| n > message_limit as usize)
        {
            return Err(ChunkError::MessageTooLarge(message_limit));
        }
        partial.body.extend_from_slice(&s.rest);
        if chunk_type == ChunkType::Intermediate {
            self.partial = Some(partial);
            return Ok(None);
        }
        Ok(Some(Message::Secure(SecureMessage {
            kind: SecureKind::Message { token_id },
            channel_id: partial.channel_id,
            sequence_number: partial.first_sequence,
            request_id: partial.request_id,
            body: partial.body,
        })))
    }
}

impl Decode for Messages {
    type Item = Message;
    type Error = ChunkError;
    const NAME: &'static str = "OPC UA messages";

    fn capacity(&self) -> usize {
        self.limits.chunk_limit().max(MAX_HANDSHAKE_SIZE) as usize
    }

    fn held(&self) -> usize {
        self.partial.as_ref().map_or(0, |p| p.body.len())
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Message>, ChunkError> {
        match Chunk::parse(input, &self.limits)? {
            Some((chunk, used)) => Ok(match self.take(chunk)? {
                Some(message) => Step::Item(message, used),
                None => Step::Skip(used),
            }),
            None if eof && self.partial.is_some() => Err(ChunkError::Incomplete),
            None => Ok(Step::Need),
        }
    }
}

// ---------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------

/// The numeric ids, in namespace 0, of the binary encodings of the
/// services this module reads. A message body starts with one.
pub mod encoding_id {
    /// ServiceFault binary encoding (397).
    pub const SERVICE_FAULT: u32 = 397;
    /// OpenSecureChannelRequest binary encoding (446).
    pub const OPEN_SECURE_CHANNEL_REQUEST: u32 = 446;
    /// OpenSecureChannelResponse binary encoding (449).
    pub const OPEN_SECURE_CHANNEL_RESPONSE: u32 = 449;
    /// CloseSecureChannelRequest binary encoding (452).
    pub const CLOSE_SECURE_CHANNEL_REQUEST: u32 = 452;
    /// CloseSecureChannelResponse binary encoding (455).
    pub const CLOSE_SECURE_CHANNEL_RESPONSE: u32 = 455;
}

/// The header at the start of every request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestHeader {
    /// The session's authentication token; null outside a session.
    pub authentication_token: NodeId,
    /// When the client sent the request, as a DateTime.
    pub timestamp: i64,
    /// Chosen by the client and copied into the response header.
    pub request_handle: u32,
    /// Bits saying which diagnostics the client wants back.
    pub return_diagnostics: u32,
    /// An id for audit logs. A null one reads as `None`.
    pub audit_entry_id: Option<String>,
    /// How long, in milliseconds, the client will wait; 0 for no limit.
    pub timeout_hint: u32,
    /// Extra fields, kept raw.
    pub additional_header: ExtensionObject,
}

impl Binary for RequestHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(RequestHeader {
            authentication_token: r.read()?,
            timestamp: r.date_time()?,
            request_handle: r.u32()?,
            return_diagnostics: r.u32()?,
            audit_entry_id: r.string()?,
            timeout_hint: r.u32()?,
            additional_header: r.read()?,
        })
    }
}

/// The header at the start of every response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseHeader {
    /// When the server sent the response, as a DateTime.
    pub timestamp: i64,
    /// The request's handle.
    pub request_handle: u32,
    /// Whether the service succeeded.
    pub service_result: StatusCode,
    /// Diagnostics for the service result.
    pub service_diagnostics: DiagnosticInfo,
    /// The strings the diagnostics point into. A null array reads as
    /// empty.
    pub string_table: Vec<Option<String>>,
    /// Extra fields, kept raw.
    pub additional_header: ExtensionObject,
}

impl Binary for Option<String> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.string()
    }
}

impl Binary for ResponseHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ResponseHeader {
            timestamp: r.date_time()?,
            request_handle: r.u32()?,
            service_result: r.read()?,
            service_diagnostics: r.read()?,
            string_table: r.read_array()?,
            additional_header: r.read()?,
        })
    }
}

/// Whether an OpenSecureChannel request makes a new token or renews one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    /// 0: open a new channel.
    Issue,
    /// 1: renew the token of an open channel.
    Renew,
}

/// How messages on a secure channel are protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    /// 0: not valid.
    Invalid,
    /// 1: no protection. The only mode policy None allows.
    None,
    /// 2: signed.
    Sign,
    /// 3: signed and encrypted.
    SignAndEncrypt,
}

impl Binary for RequestType {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.i32()? {
            0 => Ok(RequestType::Issue),
            1 => Ok(RequestType::Renew),
            n => Err(DecodeError::Enum(n)),
        }
    }
}

impl Binary for SecurityMode {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.i32()? {
            0 => Ok(SecurityMode::Invalid),
            1 => Ok(SecurityMode::None),
            2 => Ok(SecurityMode::Sign),
            3 => Ok(SecurityMode::SignAndEncrypt),
            n => Err(DecodeError::Enum(n)),
        }
    }
}

/// An OpenSecureChannel request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSecureChannelRequest {
    /// The request header.
    pub header: RequestHeader,
    /// The protocol version the client speaks.
    pub client_protocol_version: u32,
    /// Issue or renew.
    pub request_type: RequestType,
    /// The protection asked for.
    pub security_mode: SecurityMode,
    /// The client's nonce; null or empty under policy None.
    pub client_nonce: Option<Vec<u8>>,
    /// How long, in milliseconds, the client asks the token to last.
    pub requested_lifetime: u32,
}

impl Binary for OpenSecureChannelRequest {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(OpenSecureChannelRequest {
            header: r.read()?,
            client_protocol_version: r.u32()?,
            request_type: r.read()?,
            security_mode: r.read()?,
            client_nonce: r.byte_string()?,
            requested_lifetime: r.u32()?,
        })
    }
}

/// The token a secure channel uses, issued by the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelSecurityToken {
    /// The channel's id, which every later chunk carries.
    pub channel_id: u32,
    /// The token's id, which every CLO and MSG chunk carries.
    pub token_id: u32,
    /// When the token was made, as a DateTime.
    pub created_at: i64,
    /// How long, in milliseconds, the token lasts.
    pub revised_lifetime: u32,
}

impl Binary for ChannelSecurityToken {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ChannelSecurityToken {
            channel_id: r.u32()?,
            token_id: r.u32()?,
            created_at: r.date_time()?,
            revised_lifetime: r.u32()?,
        })
    }
}

/// An OpenSecureChannel response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSecureChannelResponse {
    /// The response header.
    pub header: ResponseHeader,
    /// The protocol version the server speaks.
    pub server_protocol_version: u32,
    /// The token issued.
    pub security_token: ChannelSecurityToken,
    /// The server's nonce; null or empty under policy None.
    pub server_nonce: Option<Vec<u8>>,
}

impl Binary for OpenSecureChannelResponse {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(OpenSecureChannelResponse {
            header: r.read()?,
            server_protocol_version: r.u32()?,
            security_token: r.read()?,
            server_nonce: r.byte_string()?,
        })
    }
}

/// A secure message's body under policy None: the NodeId of its encoding,
/// then the service's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Service {
    /// Encoding 446.
    OpenSecureChannelRequest(OpenSecureChannelRequest),
    /// Encoding 449.
    OpenSecureChannelResponse(OpenSecureChannelResponse),
    /// Encoding 452: just a request header.
    CloseSecureChannelRequest(RequestHeader),
    /// Encoding 455: just a response header.
    CloseSecureChannelResponse(ResponseHeader),
    /// Encoding 397: the response to any request that failed.
    ServiceFault(ResponseHeader),
    /// Any other service, with its fields unread.
    Other {
        /// The NodeId of its encoding.
        type_id: NodeId,
        /// Its fields.
        body: Vec<u8>,
    },
}

impl Service {
    /// Reads a message body. A known service must fill the body exactly.
    pub fn parse(body: &[u8]) -> Result<Service, DecodeError> {
        if body.len() > MAX_MESSAGE_SIZE as usize {
            return Err(DecodeError::Length(
                i32::try_from(body.len()).unwrap_or(i32::MAX),
            ));
        }
        let mut r = Reader::new(body);
        let type_id: NodeId = r.read()?;
        let service = match type_id.ns0() {
            Some(encoding_id::OPEN_SECURE_CHANNEL_REQUEST) => {
                Service::OpenSecureChannelRequest(r.read()?)
            }
            Some(encoding_id::OPEN_SECURE_CHANNEL_RESPONSE) => {
                Service::OpenSecureChannelResponse(r.read()?)
            }
            Some(encoding_id::CLOSE_SECURE_CHANNEL_REQUEST) => {
                Service::CloseSecureChannelRequest(r.read()?)
            }
            Some(encoding_id::CLOSE_SECURE_CHANNEL_RESPONSE) => {
                Service::CloseSecureChannelResponse(r.read()?)
            }
            Some(encoding_id::SERVICE_FAULT) => Service::ServiceFault(r.read()?),
            _ => {
                return Ok(Service::Other {
                    type_id,
                    body: r.rest().to_vec(),
                });
            }
        };
        r.finish()?;
        Ok(service)
    }

    /// The NodeId of the service's encoding.
    pub fn type_id(&self) -> NodeId {
        let id = match self {
            Service::OpenSecureChannelRequest(_) => encoding_id::OPEN_SECURE_CHANNEL_REQUEST,
            Service::OpenSecureChannelResponse(_) => encoding_id::OPEN_SECURE_CHANNEL_RESPONSE,
            Service::CloseSecureChannelRequest(_) => encoding_id::CLOSE_SECURE_CHANNEL_REQUEST,
            Service::CloseSecureChannelResponse(_) => encoding_id::CLOSE_SECURE_CHANNEL_RESPONSE,
            Service::ServiceFault(_) => encoding_id::SERVICE_FAULT,
            Service::Other { type_id, .. } => return type_id.clone(),
        };
        NodeId::numeric(0, id)
    }
}

impl BinaryWrite for StatusCode {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.u32(self.0);
        Ok(())
    }
}

impl BinaryWrite for Guid {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.u32(self.data1);
        w.u16(self.data2);
        w.u16(self.data3);
        w.bytes(&self.data4);
        Ok(())
    }
}

impl BinaryWrite for NodeId {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        self.encode_flags(w, 0)
    }
}

impl BinaryWrite for ExpandedNodeId {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        let uri = self.namespace_uri.as_deref().filter(|u| !u.is_empty());
        let mut flags = 0;
        if uri.is_some() {
            flags |= 0x80;
        }
        if self.server_index != 0 {
            flags |= 0x40;
        }
        if (uri.is_some() && self.node_id.namespace != 0)
            || self.namespace_uri.as_deref() == Some("")
        {
            return Err(EncodeError::Value);
        }
        self.node_id.encode_flags(w, flags)?;
        if let Some(uri) = uri {
            w.string(Some(uri))?;
        }
        if self.server_index != 0 {
            w.u32(self.server_index);
        }
        Ok(())
    }
}

impl BinaryWrite for QualifiedName {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        check_name(&self.name, MAX_QUALIFIED_NAME_LEN)?;
        w.u16(self.namespace);
        w.string(Some(&self.name))
    }
}

impl BinaryWrite for LocalizedText {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.u8(u8::from(self.locale.is_some()) | u8::from(self.text.is_some()) << 1);
        if let Some(l) = &self.locale {
            w.string(Some(l))?;
        }
        if let Some(t) = &self.text {
            w.string(Some(t))?;
        }
        Ok(())
    }
}

impl BinaryWrite for ExtensionObject {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        self.type_id.encode(w)?;
        match &self.body {
            ExtensionBody::None => w.u8(0),
            ExtensionBody::Binary(b) => {
                w.u8(1);
                w.byte_string(Some(b))?;
            }
            ExtensionBody::Xml(b) => {
                w.u8(2);
                w.byte_string(Some(b))?;
            }
        }
        Ok(())
    }
}

impl BinaryWrite for DiagnosticInfo {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.nested(|w| self.encode_inner(w))
    }
}

impl BinaryWrite for Variant {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.nested(|w| self.encode_inner(w))
    }
}

impl BinaryWrite for DataValue {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.nested(|w| {
            w.data_values += 1;
            let out = self.encode_inner(w);
            w.data_values -= 1;
            out
        })
    }
}

impl BinaryWrite for RequestHeader {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        self.authentication_token.encode(w)?;
        w.date_time(self.timestamp);
        w.u32(self.request_handle);
        w.u32(self.return_diagnostics);
        w.string(self.audit_entry_id.as_deref())?;
        w.u32(self.timeout_hint);
        self.additional_header.encode(w)
    }
}

impl BinaryWrite for Option<String> {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.string(self.as_deref())
    }
}

impl BinaryWrite for ResponseHeader {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.date_time(self.timestamp);
        w.u32(self.request_handle);
        self.service_result.encode(w)?;
        self.service_diagnostics.encode(w)?;
        w.write_array(&self.string_table)?;
        self.additional_header.encode(w)
    }
}

impl BinaryWrite for RequestType {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.i32(*self as i32);
        Ok(())
    }
}

impl BinaryWrite for SecurityMode {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.i32(*self as i32);
        Ok(())
    }
}

impl BinaryWrite for OpenSecureChannelRequest {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        self.header.encode(w)?;
        w.u32(self.client_protocol_version);
        self.request_type.encode(w)?;
        self.security_mode.encode(w)?;
        w.byte_string(self.client_nonce.as_deref())?;
        w.u32(self.requested_lifetime);
        Ok(())
    }
}

impl BinaryWrite for ChannelSecurityToken {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.u32(self.channel_id);
        w.u32(self.token_id);
        w.date_time(self.created_at);
        w.u32(self.revised_lifetime);
        Ok(())
    }
}

impl BinaryWrite for OpenSecureChannelResponse {
    fn encode(&self, w: &mut Writer) -> Result<(), EncodeError> {
        self.header.encode(w)?;
        w.u32(self.server_protocol_version);
        self.security_token.encode(w)?;
        w.byte_string(self.server_nonce.as_deref())
    }
}

macro_rules! binary_wire {
    ($($ty:ty),+ $(,)?) => { $(
        impl Wire for $ty {
            type ParseError = DecodeError;
            type WriteError = EncodeError;

            fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
                if bytes.len() > MAX_MESSAGE_SIZE as usize {
                    return Err(DecodeError::Length(i32::try_from(bytes.len()).unwrap_or(i32::MAX)));
                }
                let mut reader = Reader::new(bytes);
                reader.writable = true;
                let value = Self::decode(&mut reader)?;
                reader.finish()?;
                Ok(value)
            }

            fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
                let mut writer = Writer::new();
                self.encode(&mut writer)?;
                out.extend_from_slice(&writer.into_bytes()?);
                Ok(())
            }
        }
    )+ };
}

binary_wire!(
    StatusCode,
    Guid,
    NodeId,
    ExpandedNodeId,
    QualifiedName,
    LocalizedText,
    ExtensionObject,
    DiagnosticInfo,
    Variant,
    DataValue,
    RequestHeader,
    ResponseHeader,
    RequestType,
    SecurityMode,
    OpenSecureChannelRequest,
    ChannelSecurityToken,
    OpenSecureChannelResponse
);

impl Wire for Service {
    type ParseError = DecodeError;
    type WriteError = EncodeError;

    fn parse(b: &[u8]) -> Result<Self, DecodeError> {
        Self::parse(b)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut w = Writer::new();
        self.type_id().encode(&mut w)?;
        match self {
            Service::OpenSecureChannelRequest(s) => s.encode(&mut w)?,
            Service::OpenSecureChannelResponse(s) => s.encode(&mut w)?,
            Service::CloseSecureChannelRequest(h) => h.encode(&mut w)?,
            Service::CloseSecureChannelResponse(h) | Service::ServiceFault(h) => {
                h.encode(&mut w)?
            }
            Service::Other { type_id, body } => {
                let known = [
                    encoding_id::SERVICE_FAULT,
                    encoding_id::OPEN_SECURE_CHANNEL_REQUEST,
                    encoding_id::OPEN_SECURE_CHANNEL_RESPONSE,
                    encoding_id::CLOSE_SECURE_CHANNEL_REQUEST,
                    encoding_id::CLOSE_SECURE_CHANNEL_RESPONSE,
                ];
                if type_id.ns0().is_some_and(|id| known.contains(&id)) {
                    return Err(EncodeError::KnownTypeId);
                }
                w.bytes(body);
            }
        }
        out.extend_from_slice(&w.into_bytes()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Fail, Stream, contract, pump, test_support::Lcg};

    /// Writes chunks and fails the test with the original error on refusal.
    fn wire_chunks(chunks: Vec<Chunk>) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in chunks {
            chunk
                .write(&mut out)
                .expect("message chunks must be writable");
        }
        out
    }

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn hel_bytes(receive: u32, send: u32, url: &[u8]) -> Vec<u8> {
        let mut b = b"HELF".to_vec();
        b.extend_from_slice(&le32(32 + url.len() as u32));
        for v in [0, receive, send, 0, 0] {
            b.extend_from_slice(&le32(v));
        }
        b.extend_from_slice(&(url.len() as i32).to_le_bytes());
        b.extend_from_slice(url);
        b
    }

    fn msg(token_id: u32, seq: u32, request_id: u32, body: Vec<u8>) -> Message {
        Message::Secure(SecureMessage {
            kind: SecureKind::Message { token_id },
            channel_id: 7,
            sequence_number: seq,
            request_id,
            body,
        })
    }

    /// A raw MSG chunk.
    fn msg_chunk(ct: u8, channel: u32, token: u32, seq: u32, req: u32, body: &[u8]) -> Vec<u8> {
        let mut b = b"MSG".to_vec();
        b.push(ct);
        b.extend_from_slice(&le32(24 + body.len() as u32));
        for v in [channel, token, seq, req] {
            b.extend_from_slice(&le32(v));
        }
        b.extend_from_slice(body);
        b
    }

    fn all(
        d: &mut Stream<Messages>,
    ) -> Vec<Result<Message, crate::stdlib::codec::Fail<ChunkError>>> {
        let mut out = Vec::new();
        while let Some(m) = d.next() {
            let stop = m.is_err();
            out.push(m);
            if stop {
                break;
            }
        }
        out
    }

    // Examples from OPC UA Part 6, section 5.2.

    #[test]
    fn string_example() {
        // "水Boy" is 6 bytes of UTF-8.
        let mut w = Writer::new();
        w.string(Some("水Boy")).unwrap();
        assert_eq!(
            w.into_bytes().unwrap(),
            [0x06, 0, 0, 0, 0xe6, 0xb0, 0xb4, 0x42, 0x6f, 0x79]
        );
        let mut w = Writer::new();
        w.string(None).unwrap();
        assert_eq!(w.into_bytes().unwrap(), [0xff; 4]);
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
        assert_eq!(r.string(), Ok(None));
        assert_eq!(r.string(), Ok(Some(String::new())));
        assert_eq!(
            Reader::new(&[0xfe, 0xff, 0xff, 0xff]).string(),
            Err(DecodeError::Length(-2))
        );
        assert_eq!(
            Reader::new(&[5, 0, 0, 0, b'a']).string(),
            Err(DecodeError::Length(5))
        );
        assert_eq!(
            Reader::new(&[1, 0, 0, 0, 0xff]).string(),
            Err(DecodeError::Utf8)
        );
    }

    #[test]
    fn guid_example() {
        // 72962B91-FA75-4AE6-8D28-B404DC7DAF63
        let g = Guid {
            data1: 0x72962b91,
            data2: 0xfa75,
            data3: 0x4ae6,
            data4: [0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63],
        };
        let bytes = [
            0x91, 0x2b, 0x96, 0x72, 0x75, 0xfa, 0xe6, 0x4a, 0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d,
            0xaf, 0x63,
        ];
        assert_eq!(Wire::to_bytes(&g).unwrap(), bytes);
        assert_eq!(<Guid as Wire>::parse(&bytes), Ok(g));
    }

    #[test]
    fn node_id_examples() {
        // Two-byte form: 72 in namespace 0.
        assert_eq!(
            Wire::to_bytes(&NodeId::numeric(0, 72)).unwrap(),
            [0x00, 0x48]
        );
        // Four-byte form: 1025 in namespace 5.
        assert_eq!(
            Wire::to_bytes(&NodeId::numeric(5, 1025)).unwrap(),
            [0x01, 0x05, 0x01, 0x04]
        );
        // String form: "Hot水" in namespace 1.
        let hot = [
            0x03, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x48, 0x6f, 0x74, 0xe6, 0xb0, 0xb4,
        ];
        assert_eq!(Wire::to_bytes(&NodeId::string(1, "Hot水")).unwrap(), hot);
        assert_eq!(
            <NodeId as Wire>::parse(&hot),
            Ok(NodeId::string(1, "Hot水"))
        );
        // Numeric form when the short ones do not fit.
        assert_eq!(
            Wire::to_bytes(&NodeId::numeric(0, 70000)).unwrap(),
            [0x02, 0, 0, 0x70, 0x11, 0x01, 0x00]
        );
        assert_eq!(
            Wire::to_bytes(&NodeId::numeric(300, 1)).unwrap(),
            [0x02, 0x2c, 0x01, 1, 0, 0, 0]
        );
        // Readers take any form, so a long form reads as the same NodeId.
        assert_eq!(
            <NodeId as Wire>::parse(&[0x02, 0, 0, 72, 0, 0, 0]),
            Ok(NodeId::numeric(0, 72))
        );
        // Guid and opaque forms.
        let g = NodeId {
            namespace: 2,
            identifier: Identifier::Guid(Guid::default()),
        };
        assert_eq!(<NodeId as Wire>::parse(&Wire::to_bytes(&g).unwrap()), Ok(g));
        let o = NodeId {
            namespace: 2,
            identifier: Identifier::Opaque(vec![1, 2, 3]),
        };
        assert_eq!(<NodeId as Wire>::parse(&Wire::to_bytes(&o).unwrap()), Ok(o));
        // A null string identifier reads as empty.
        assert_eq!(
            <NodeId as Wire>::parse(&[0x03, 1, 0, 0xff, 0xff, 0xff, 0xff]),
            Ok(NodeId::string(1, ""))
        );
        // Bad forms.
        assert_eq!(
            <NodeId as Wire>::parse(&[0x06, 0]),
            Err(DecodeError::NodeIdForm(6))
        );
        assert_eq!(
            <NodeId as Wire>::parse(&[0x80, 0]),
            Err(DecodeError::NodeIdForm(0x80))
        );
        assert_eq!(
            <NodeId as Wire>::parse(&[0x00, 1, 2]),
            Err(DecodeError::Trailing(1))
        );
        assert_eq!(<NodeId as Wire>::parse(&[0x01, 1]), Err(DecodeError::End));
        assert!(NodeId::default().is_null());
    }

    #[test]
    fn expanded_node_id() {
        let e = ExpandedNodeId {
            node_id: NodeId::numeric(0, 85),
            namespace_uri: Some("urn:x".into()),
            server_index: 3,
        };
        let bytes = Wire::to_bytes(&e).unwrap();
        assert_eq!(bytes[..2], [0xc0, 85]);
        assert_eq!(<ExpandedNodeId as Wire>::parse(&bytes), Ok(e));
        let plain = ExpandedNodeId {
            node_id: NodeId::numeric(0, 85),
            ..Default::default()
        };
        assert_eq!(Wire::to_bytes(&plain).unwrap(), [0, 85]);
        // A null URI with the flag set reads as no URI.
        assert_eq!(
            <ExpandedNodeId as Wire>::parse(&[0x80, 85, 0xff, 0xff, 0xff, 0xff]),
            Ok(plain)
        );
        assert_eq!(
            <ExpandedNodeId as Wire>::parse(&[0x87, 85]),
            Err(DecodeError::NodeIdForm(0x87))
        );
    }

    #[test]
    fn names_and_texts() {
        let q = QualifiedName {
            namespace: 2,
            name: "Pump".into(),
        };
        assert_eq!(
            Wire::to_bytes(&q).unwrap(),
            [2, 0, 4, 0, 0, 0, b'P', b'u', b'm', b'p']
        );
        assert_eq!(
            <QualifiedName as Wire>::parse(&Wire::to_bytes(&q).unwrap()),
            Ok(q)
        );
        let t = LocalizedText {
            locale: Some("en".into()),
            text: Some("Hi".into()),
        };
        assert_eq!(
            Wire::to_bytes(&t).unwrap(),
            [3, 2, 0, 0, 0, b'e', b'n', 2, 0, 0, 0, b'H', b'i']
        );
        assert_eq!(
            <LocalizedText as Wire>::parse(&Wire::to_bytes(&t).unwrap()),
            Ok(t)
        );
        assert_eq!(Wire::to_bytes(&LocalizedText::default()).unwrap(), [0]);
        assert_eq!(
            <LocalizedText as Wire>::parse(&[4]),
            Err(DecodeError::Mask(4))
        );
    }

    #[test]
    fn extension_objects_stay_raw() {
        let e = ExtensionObject {
            type_id: NodeId::numeric(0, 324),
            body: ExtensionBody::Binary(vec![9, 8, 7]),
        };
        let bytes = Wire::to_bytes(&e).unwrap();
        assert_eq!(bytes, [0x01, 0, 0x44, 0x01, 1, 3, 0, 0, 0, 9, 8, 7]);
        assert_eq!(<ExtensionObject as Wire>::parse(&bytes), Ok(e));
        let x = ExtensionObject {
            type_id: NodeId::default(),
            body: ExtensionBody::Xml(b"<a/>".to_vec()),
        };
        assert_eq!(
            <ExtensionObject as Wire>::parse(&Wire::to_bytes(&x).unwrap()),
            Ok(x)
        );
        assert_eq!(
            Wire::to_bytes(&ExtensionObject::default()).unwrap(),
            [0, 0, 0]
        );
        assert_eq!(
            <ExtensionObject as Wire>::parse(&[0, 0, 3]),
            Err(DecodeError::Mask(3))
        );
    }

    #[test]
    fn variants() {
        // A scalar Int32.
        let v = Variant::Scalar(Value::Int32(-2));
        assert_eq!(Wire::to_bytes(&v).unwrap(), [6, 0xfe, 0xff, 0xff, 0xff]);
        assert_eq!(
            <Variant as Wire>::parse(&[6, 0xfe, 0xff, 0xff, 0xff]),
            Ok(v)
        );
        assert_eq!(Wire::to_bytes(&Variant::Null).unwrap(), [0]);
        // A 2 by 2 array of Bytes.
        let a = Variant::Array {
            type_id: type_id::BYTE,
            values: (1..=4).map(Value::Byte).collect(),
            dimensions: Some(vec![2, 2]),
        };
        let bytes = Wire::to_bytes(&a).unwrap();
        assert_eq!(
            bytes,
            [
                0xc3, 4, 0, 0, 0, 1, 2, 3, 4, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0
            ]
        );
        assert_eq!(<Variant as Wire>::parse(&bytes), Ok(a));
        // A null array reads as empty.
        let empty = Variant::Array {
            type_id: type_id::STRING,
            values: vec![],
            dimensions: None,
        };
        assert_eq!(
            <Variant as Wire>::parse(&[0x8c, 0xff, 0xff, 0xff, 0xff]),
            Ok(empty)
        );
        // An array of Variants, and every other type, round trip.
        let every = Variant::Array {
            type_id: type_id::VARIANT,
            values: sample_values()
                .into_iter()
                .map(|v| Value::Variant(Box::new(Variant::Scalar(v))))
                .collect(),
            dimensions: None,
        };
        let bytes = Wire::to_bytes(&every).unwrap();
        let back: Variant = Wire::parse(&bytes).unwrap();
        assert_eq!(Wire::to_bytes(&back).unwrap(), bytes);
    }

    #[test]
    fn reserved_variants_read_but_do_not_write() {
        for type_id in type_id::RESERVED_FIRST..=type_id::RESERVED_LAST {
            let reserved = Value::Reserved {
                type_id,
                bytes: Some(vec![5]),
            };
            let cases = [
                (
                    vec![type_id, 1, 0, 0, 0, 5],
                    Variant::Scalar(reserved.clone()),
                ),
                (
                    vec![type_id | 0x80, 1, 0, 0, 0, 1, 0, 0, 0, 5],
                    Variant::Array {
                        type_id,
                        values: vec![reserved],
                        dimensions: None,
                    },
                ),
                (
                    vec![type_id | 0x80, 0, 0, 0, 0],
                    Variant::Array {
                        type_id,
                        values: vec![],
                        dimensions: None,
                    },
                ),
            ];
            for (bytes, expected) in cases {
                let mut reader = Reader::new(&bytes);
                let value = reader.read::<Variant>().unwrap();
                assert_eq!(reader.finish(), Ok(()));
                assert_eq!(value, expected);
                assert_eq!(
                    <Variant as Wire>::parse(&bytes),
                    Err(DecodeError::VariantType(type_id))
                );
                let mut out = vec![0xa5];
                assert_eq!(value.write(&mut out), Err(EncodeError::VariantType));
                assert_eq!(out, [0xa5]);
                check_reader::<Variant>(&bytes);

                let mut data_value_bytes = vec![1];
                data_value_bytes.extend_from_slice(&bytes);
                let mut reader = Reader::new(&data_value_bytes);
                let value = reader.read::<DataValue>().unwrap();
                assert_eq!(reader.finish(), Ok(()));
                assert_eq!(value.value, Some(expected));
                assert_eq!(
                    <DataValue as Wire>::parse(&data_value_bytes),
                    Err(DecodeError::VariantType(type_id))
                );
                assert_eq!(value.write(&mut out), Err(EncodeError::VariantType));
                assert_eq!(out, [0xa5]);
                check_reader::<DataValue>(&data_value_bytes);
            }
        }
    }

    #[test]
    fn variant_errors() {
        assert_eq!(
            <Variant as Wire>::parse(&[32]),
            Err(DecodeError::VariantType(32))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[0x80]),
            Err(DecodeError::VariantType(0))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[24, 0]),
            Err(DecodeError::VariantType(24))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[0x46, 0, 0, 0, 0]),
            Err(DecodeError::Dimensions)
        );
        // Dimensions that do not multiply out, a zero dimension, none, or too many.
        let base = [0xc3u8, 2, 0, 0, 0, 1, 2];
        for dims in [vec![1i32, 3], vec![0], vec![], vec![-1, -2], vec![1; 33]] {
            let mut b = base.to_vec();
            b.extend_from_slice(&(dims.len() as i32).to_le_bytes());
            for d in &dims {
                b.extend_from_slice(&d.to_le_bytes());
            }
            assert_eq!(
                <Variant as Wire>::parse(&b),
                Err(DecodeError::Dimensions),
                "{dims:?}"
            );
        }
        // An array length past the bytes left.
        assert_eq!(
            <Variant as Wire>::parse(&[0x83, 9, 0, 0, 0, 1]),
            Err(DecodeError::Length(9))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[0x83, 0xfe, 0xff, 0xff, 0xff]),
            Err(DecodeError::Length(-2))
        );
        // Writers refuse what readers refuse.
        let nested = Variant::Scalar(Value::Variant(Box::new(Variant::Null)));
        assert_eq!(Wire::to_bytes(&nested), Err(EncodeError::VariantType));
        let mixed = Variant::Array {
            type_id: 3,
            values: vec![Value::Byte(1), Value::SByte(1)],
            dimensions: None,
        };
        assert_eq!(Wire::to_bytes(&mixed), Err(EncodeError::VariantType));
        let null = Variant::Array {
            type_id: 0,
            values: vec![],
            dimensions: None,
        };
        assert_eq!(Wire::to_bytes(&null), Err(EncodeError::VariantType));
        let dims = Variant::Array {
            type_id: 3,
            values: vec![Value::Byte(1)],
            dimensions: Some(vec![2]),
        };
        assert_eq!(Wire::to_bytes(&dims), Err(EncodeError::Dimensions));
        let reserved = Variant::Scalar(Value::Reserved {
            type_id: 5,
            bytes: None,
        });
        assert_eq!(Wire::to_bytes(&reserved), Err(EncodeError::VariantType));
        let long = Variant::Array {
            type_id: 3,
            values: vec![Value::Byte(0); MAX_ARRAY_LEN + 1],
            dimensions: None,
        };
        assert_eq!(Wire::to_bytes(&long), Err(EncodeError::TooLong));
    }

    /// `levels` Variants, each an array holding the next, around an Int32.
    fn nest(levels: usize) -> Variant {
        let mut v = Variant::Scalar(Value::Int32(1));
        for _ in 1..levels {
            v = Variant::Array {
                type_id: type_id::VARIANT,
                values: vec![Value::Variant(Box::new(v))],
                dimensions: None,
            };
        }
        v
    }

    #[test]
    fn nesting_is_bounded() {
        let bytes = Wire::to_bytes(&nest(MAX_DEPTH)).unwrap();
        assert_eq!(<Variant as Wire>::parse(&bytes), Ok(nest(MAX_DEPTH)));
        assert_eq!(
            Wire::to_bytes(&nest(MAX_DEPTH + 1)),
            Err(EncodeError::TooDeep)
        );
        // One level more, written by hand, does not read.
        let mut deep = Vec::new();
        for _ in 0..MAX_DEPTH {
            deep.extend_from_slice(&[0x98, 1, 0, 0, 0]);
        }
        deep.extend_from_slice(&[6, 1, 0, 0, 0]);
        assert_eq!(<Variant as Wire>::parse(&deep), Err(DecodeError::Depth));
        let mut diag = vec![0x40u8; MAX_DEPTH];
        diag.push(0);
        assert_eq!(
            <DiagnosticInfo as Wire>::parse(&diag),
            Err(DecodeError::Depth)
        );
        assert!(<DiagnosticInfo as Wire>::parse(&diag[1..]).is_ok());
        // A failed read leaves the reader's depth where it was.
        let mut r = Reader::new(&deep);
        assert!(r.read::<Variant>().is_err());
        let mut r2 = Reader::new(&bytes);
        assert!(r2.read::<Variant>().is_ok());
    }

    #[test]
    fn data_values() {
        let d = DataValue {
            value: Some(Variant::Scalar(Value::Double(1.5))),
            status: Some(StatusCode(0x4000_0000)),
            source_timestamp: Some(1),
            source_picoseconds: Some(2),
            server_timestamp: Some(3),
            server_picoseconds: Some(4),
        };
        let bytes = Wire::to_bytes(&d).unwrap();
        assert_eq!(bytes[0], 0x3f);
        // Source picoseconds come before the server timestamp: after the
        // mask (1), the Variant (9), the status (4) and the source timestamp (8).
        assert_eq!(bytes[22..24], [2, 0]);
        assert_eq!(<DataValue as Wire>::parse(&bytes), Ok(d));
        assert_eq!(Wire::to_bytes(&DataValue::default()).unwrap(), [0]);
        assert_eq!(
            <DataValue as Wire>::parse(&[0x40]),
            Err(DecodeError::Mask(0x40))
        );
    }

    #[test]
    fn diagnostic_infos() {
        let d = DiagnosticInfo {
            symbolic_id: Some(1),
            namespace_uri: Some(2),
            locale: Some(3),
            localized_text: Some(4),
            additional_info: Some("x".into()),
            inner_status_code: Some(StatusCode::BAD_DECODING_ERROR),
            inner_diagnostic_info: Some(Box::new(DiagnosticInfo {
                symbolic_id: Some(9),
                ..Default::default()
            })),
        };
        let bytes = Wire::to_bytes(&d).unwrap();
        // Locale comes before localized text on the wire.
        assert_eq!(
            bytes[..17],
            [0x7f, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]
        );
        assert_eq!(<DiagnosticInfo as Wire>::parse(&bytes), Ok(d));
        assert_eq!(
            <DiagnosticInfo as Wire>::parse(&[0x80]),
            Err(DecodeError::Mask(0x80))
        );
    }

    #[test]
    fn hello_and_acknowledge() {
        let bytes = hel_bytes(65536, 65536, b"opc.tcp://a:4840");
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        let Some(Ok(Message::Hello(h))) = d.next() else {
            panic!()
        };
        assert_eq!(h.endpoint_url, "opc.tcp://a:4840");
        assert_eq!(
            Message::Hello(h.clone())
                .chunks(&Limits::default())
                .map(wire_chunks)
                .unwrap(),
            bytes
        );
        let ours = Limits {
            receive_buffer_size: 32768,
            max_message_size: 1 << 20,
            max_chunk_count: 64,
        };
        let ack = h.acknowledge(&ours);
        assert_eq!(
            ack,
            Acknowledge {
                protocol_version: 0,
                receive_buffer_size: 32768,
                send_buffer_size: 65536,
                max_message_size: 1 << 20,
                max_chunk_count: 64
            }
        );
        let ack_bytes = Message::Acknowledge(ack)
            .chunks(&h.limits())
            .map(wire_chunks)
            .unwrap();
        assert_eq!(ack_bytes[..8], [b'A', b'C', b'K', b'F', 28, 0, 0, 0]);
        let mut c = Stream::new(Messages::new());
        assert_eq!(c.push(&ack_bytes), ack_bytes.len());
        assert_eq!(c.next(), Some(Ok(Message::Acknowledge(ack))));
        // The client's small send buffer caps what the server takes.
        let small = Hello {
            send_buffer_size: 8192,
            ..h.clone()
        };
        assert_eq!(small.acknowledge(&ours).receive_buffer_size, 8192);
        // Buffers below the minimum are refused both ways.
        let mut d = Stream::new(Messages::new());
        let input = &hel_bytes(1024, 65536, b"");
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::BufferSize(1024))))
        );
        let Some(Fail::Protocol(error)) = d.failed() else {
            panic!("expected protocol error")
        };
        assert_eq!(error.status(), StatusCode::BAD_TCP_NOT_ENOUGH_RESOURCES);
        let low = Hello {
            receive_buffer_size: 100,
            ..h.clone()
        };
        assert_eq!(
            Message::Hello(low)
                .chunks(&Limits::default())
                .map(wire_chunks),
            Err(EncodeError::BufferSize(100))
        );
        let low = Acknowledge {
            send_buffer_size: 100,
            ..ack
        };
        assert_eq!(
            Message::Acknowledge(low)
                .chunks(&Limits::default())
                .map(wire_chunks),
            Err(EncodeError::BufferSize(100))
        );
        let mut c = Stream::new(Messages::new());
        let mut low_ack = ack_bytes.clone();
        low_ack[12..16].copy_from_slice(&le32(10));
        assert_eq!(c.push(&low_ack), low_ack.len());
        assert_eq!(
            c.next(),
            Some(Err(Fail::Protocol(ChunkError::BufferSize(10))))
        );
        // A URL past the limit.
        let long = Hello {
            endpoint_url: "a".repeat(MAX_URL_LEN + 1),
            ..h.clone()
        };
        assert_eq!(
            Message::Hello(long)
                .chunks(&Limits::default())
                .map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        let longest = Hello {
            endpoint_url: "a".repeat(MAX_URL_LEN),
            ..h
        };
        let bytes = Message::Hello(longest.clone())
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap();
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(Message::Hello(longest))));
        let bad = hel_bytes(8192, 8192, &[b'a'; MAX_URL_LEN + 1]);
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bad), bad.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Decode(
                MessageType::Hello,
                DecodeError::Length(MAX_URL_LEN as i32 + 1)
            ))))
        );
        // Bytes after the Hello's fields.
        let mut trailing = hel_bytes(8192, 8192, b"x");
        trailing.push(0);
        trailing[4] += 1;
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&trailing), trailing.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Decode(
                MessageType::Hello,
                DecodeError::Trailing(1)
            ))))
        );
    }

    #[test]
    fn error_and_reverse_hello() {
        let e = Message::Error(ErrorMessage {
            error: StatusCode::BAD_TCP_ENDPOINT_URL_INVALID,
            reason: "no".into(),
        });
        let bytes = e.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(
            bytes,
            [
                b'E', b'R', b'R', b'F', 18, 0, 0, 0, 0, 0, 0x83, 0x80, 2, 0, 0, 0, b'n', b'o'
            ]
        );
        let rh = Message::ReverseHello(ReverseHello {
            server_uri: "a".repeat(MAX_URL_LEN),
            endpoint_url: "b".repeat(MAX_URL_LEN),
        });
        let rh_bytes = rh.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(rh_bytes.len() as u32, MAX_HANDSHAKE_SIZE);
        let mut d = Stream::with_buffer(Messages::new(), MAX_BUFFER_SIZE as usize);
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.push(&rh_bytes), rh_bytes.len());
        assert_eq!(all(&mut d), [Ok(e), Ok(rh)]);
        let long = ErrorMessage {
            error: StatusCode::GOOD,
            reason: "r".repeat(MAX_REASON_LEN + 1),
        };
        assert_eq!(
            Message::Error(long)
                .chunks(&Limits::default())
                .map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        // An ERR missing its reason.
        let mut d = Stream::new(Messages::new());
        let input = &[b'E', b'R', b'R', b'F', 12, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Decode(
                MessageType::Error,
                DecodeError::End
            ))))
        );
    }

    #[test]
    fn chunk_header_errors() {
        let l = Limits::default();
        assert_eq!(
            Chunk::parse(b"GET", &l),
            Err(ChunkError::MessageType(*b"GET"))
        );
        assert_eq!(Chunk::parse(b"HE", &l), Ok(None));
        // The fourth byte of a HEL, ACK, ERR or RHE is reserved and ignored.
        assert_eq!(Chunk::parse(b"HELC", &l), Ok(None));
        assert_eq!(
            Chunk::parse(b"OPNC", &l),
            Err(ChunkError::ChunkType(MessageType::Open, b'C'))
        );
        assert_eq!(
            Chunk::parse(b"CLOA", &l),
            Err(ChunkError::ChunkType(MessageType::Close, b'A'))
        );
        assert_eq!(
            Chunk::parse(b"MSGX", &l),
            Err(ChunkError::ChunkType(MessageType::Message, b'X'))
        );
        assert_eq!(
            Chunk::parse(b"MSGC\x07\0\0\0", &l),
            Err(ChunkError::TooSmall(7))
        );
        assert_eq!(
            Chunk::parse(b"MSGF\x01\x20\0\0", &l),
            Err(ChunkError::TooLarge {
                size: 8193,
                limit: MIN_BUFFER_SIZE
            })
        );
        assert_eq!(
            Chunk::parse(b"HELF\xff\xff\0\0", &l),
            Err(ChunkError::TooLarge {
                size: 65535,
                limit: MAX_HANDSHAKE_SIZE
            })
        );
        let big = Limits {
            receive_buffer_size: 65536,
            ..l
        };
        assert_eq!(Chunk::parse(b"MSGF\x01\x20\0\0", &big), Ok(None));
        assert_eq!(
            Chunk::parse(
                b"MSGF\0\0\0\x10",
                &Limits {
                    receive_buffer_size: u32::MAX,
                    ..l
                }
            ),
            Err(ChunkError::TooLarge {
                size: 1 << 28,
                limit: MAX_BUFFER_SIZE
            })
        );
        let (c, used) = Chunk::parse(b"MSGF\x08\0\0\0rest", &l).unwrap().unwrap();
        assert_eq!(
            (c.message_type, c.chunk_type, c.body.len(), used),
            (MessageType::Message, ChunkType::Final, 0, 8)
        );
        assert_eq!(
            ChunkError::MessageType(*b"GET").status(),
            StatusCode::BAD_TCP_MESSAGE_TYPE_INVALID
        );
        assert_eq!(
            ChunkError::TooLarge { size: 0, limit: 0 }.status(),
            StatusCode::BAD_TCP_MESSAGE_TOO_LARGE
        );
    }

    fn open_request() -> Service {
        Service::OpenSecureChannelRequest(OpenSecureChannelRequest {
            header: RequestHeader {
                authentication_token: NodeId::default(),
                timestamp: 133_000_000_000_000_000,
                request_handle: 1,
                return_diagnostics: 0,
                audit_entry_id: None,
                timeout_hint: 10_000,
                additional_header: ExtensionObject::default(),
            },
            client_protocol_version: 0,
            request_type: RequestType::Issue,
            security_mode: SecurityMode::None,
            client_nonce: Some(vec![]),
            requested_lifetime: 3_600_000,
        })
    }

    #[test]
    fn open_secure_channel() {
        let body = open_request().to_bytes().unwrap();
        // Encoding id 446 in the four-byte form.
        assert_eq!(body[..4], [0x01, 0x00, 0xbe, 0x01]);
        assert_eq!(Service::parse(&body), Ok(open_request()));
        let opn = Message::Secure(SecureMessage {
            kind: SecureKind::Open(AsymmetricHeader::none()),
            channel_id: 0,
            sequence_number: 51,
            request_id: 1,
            body,
        });
        let bytes = opn.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(bytes[..4], *b"OPNF");
        assert_eq!(bytes[8..12], [0, 0, 0, 0]);
        assert_eq!(bytes[12..16], le32(SECURITY_POLICY_NONE.len() as u32));
        assert_eq!(
            bytes[16..16 + SECURITY_POLICY_NONE.len()],
            *SECURITY_POLICY_NONE.as_bytes()
        );
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(opn)));

        let response = Service::OpenSecureChannelResponse(OpenSecureChannelResponse {
            header: ResponseHeader {
                request_handle: 1,
                string_table: vec![Some("a".into()), None],
                ..Default::default()
            },
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: 9,
                token_id: 1,
                created_at: 5,
                revised_lifetime: 600,
            },
            server_nonce: None,
        });
        let bytes = response.to_bytes().unwrap();
        assert_eq!(bytes[..4], [0x01, 0x00, 0xc1, 0x01]);
        assert_eq!(Service::parse(&bytes), Ok(response));

        // Enumeration values out of range.
        let mut bad = open_request().to_bytes().unwrap();
        let at = bad.len() - 4 - 4 - 4 - 4;
        bad[at..at + 4].copy_from_slice(&le32(2));
        assert_eq!(Service::parse(&bad), Err(DecodeError::Enum(2)));
        let mut bad = open_request().to_bytes().unwrap();
        let at = bad.len() - 4 - 4 - 4;
        bad[at..at + 4].copy_from_slice(&le32(4));
        assert_eq!(Service::parse(&bad), Err(DecodeError::Enum(4)));
        let mut trailing = open_request().to_bytes().unwrap();
        trailing.push(0);
        assert_eq!(Service::parse(&trailing), Err(DecodeError::Trailing(1)));
    }

    #[test]
    fn other_services() {
        for s in [
            Service::CloseSecureChannelRequest(RequestHeader::default()),
            Service::CloseSecureChannelResponse(ResponseHeader::default()),
            Service::ServiceFault(ResponseHeader {
                service_result: StatusCode::BAD_SERVICE_UNSUPPORTED,
                ..Default::default()
            }),
            Service::Other {
                type_id: NodeId::numeric(0, 631),
                body: vec![1, 2, 3],
            },
        ] {
            assert_eq!(Service::parse(&s.to_bytes().unwrap()), Ok(s));
        }
        let fake = Service::Other {
            type_id: NodeId::numeric(0, 446),
            body: vec![],
        };
        assert_eq!(fake.to_bytes(), Err(EncodeError::KnownTypeId));
        assert_eq!(Service::parse(&[]), Err(DecodeError::End));
    }

    #[test]
    fn close_secure_channel() {
        let clo = Message::Secure(SecureMessage {
            kind: SecureKind::Close { token_id: 1 },
            channel_id: 9,
            sequence_number: 60,
            request_id: 8,
            body: Service::CloseSecureChannelRequest(RequestHeader::default())
                .to_bytes()
                .unwrap(),
        });
        let bytes = clo.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(bytes[..4], *b"CLOF");
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(clo)));
        // A CLO too large for one chunk.
        let big = Message::Secure(SecureMessage {
            kind: SecureKind::Close { token_id: 1 },
            channel_id: 9,
            sequence_number: 0,
            request_id: 0,
            body: vec![0; MIN_BUFFER_SIZE as usize],
        });
        assert_eq!(
            big.chunks(&Limits::default()).map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        let opn = Message::Secure(SecureMessage {
            kind: SecureKind::Open(AsymmetricHeader {
                policy_uri: "p".repeat(256),
                ..AsymmetricHeader::none()
            }),
            channel_id: 0,
            sequence_number: 0,
            request_id: 0,
            body: vec![],
        });
        assert_eq!(
            opn.chunks(&Limits::default()).map(wire_chunks),
            Err(EncodeError::TooLong)
        );
    }

    #[test]
    fn messages_are_chunked_and_put_back_together() {
        let body: Vec<u8> = (0..30_000u32).map(|i| i as u8).collect();
        let m = msg(1, u32::MAX - 1, 5, body);
        let chunks = match &m {
            Message::Secure(s) => s.chunks(&Limits::default()).unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(chunks.len(), 4);
        assert!(
            chunks
                .iter()
                .all(|c| c.body.len() + HEADER_LEN <= MIN_BUFFER_SIZE as usize)
        );
        assert_eq!(chunks[0].chunk_type, ChunkType::Intermediate);
        assert_eq!(chunks[3].chunk_type, ChunkType::Final);
        // The sequence numbers wrap past u32::MAX.
        assert_eq!(chunks[2].body[8..12], le32(0));
        let bytes = wire_chunks(chunks);
        contract::check_decode_with_held_limit(Messages::new, &bytes, MAX_MESSAGE_SIZE as usize);
        let mut stream = Stream::new(Messages::new());
        let mut messages = Vec::new();
        pump(&mut stream, &bytes, |message| messages.push(message)).unwrap();
        assert_eq!(messages, [m]);
        assert_eq!(stream.held(), 0);
        // An empty MSG is one chunk.
        let e = msg(1, 1, 1, vec![]);
        assert_eq!(
            e.chunks(&Limits::default()).map(wire_chunks).unwrap().len(),
            24
        );
        // A legacy wrap below 1024 is accepted.
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'C', 7, 1, LEGACY_WRAP + 3, 5, b"ab");
        assert_eq!(d.push(input), input.len());
        let input = &msg_chunk(b'F', 7, 1, 2, 5, b"cd");
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Ok(msg(1, LEGACY_WRAP + 3, 5, b"abcd".to_vec())))
        );
    }

    #[test]
    fn aborts() {
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'C', 7, 1, 10, 5, b"part");
        assert_eq!(d.push(input), input.len());
        let mut tail = le32(StatusCode::BAD_RESPONSE_TOO_LARGE.0).to_vec();
        tail.extend_from_slice(&[1, 0, 0, 0, b'x']);
        let input = &msg_chunk(b'A', 7, 1, 11, 5, &tail);
        assert_eq!(d.push(input), input.len());
        let abort = Abort {
            channel_id: 7,
            token_id: 1,
            sequence_number: 11,
            request_id: 5,
            error: StatusCode::BAD_RESPONSE_TOO_LARGE,
            reason: "x".into(),
        };
        assert_eq!(d.next(), Some(Ok(Message::Abort(abort.clone()))));
        // The next message starts afresh.
        let input = &msg_chunk(b'F', 7, 1, 12, 6, b"z");
        assert_eq!(d.push(input), input.len());
        assert_eq!(d.next(), Some(Ok(msg(1, 12, 6, b"z".to_vec()))));
        let bytes = Message::Abort(abort.clone())
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap();
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(Message::Abort(abort))));
        // An abort with no status.
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'A', 7, 1, 1, 1, &[]);
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Decode(
                MessageType::Message,
                DecodeError::End
            ))))
        );
    }

    #[test]
    fn stream_errors() {
        let cases: Vec<(Vec<Vec<u8>>, Limits, ChunkError)> = vec![
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b""),
                    msg_chunk(b'F', 7, 1, 2, 6, b""),
                ],
                Limits::default(),
                ChunkError::Interleaved,
            ),
            (
                vec![msg_chunk(b'C', 7, 1, 1, 5, b""), hel_bytes(8192, 8192, b"")],
                Limits::default(),
                ChunkError::Interleaved,
            ),
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b""),
                    msg_chunk(b'F', 8, 1, 2, 5, b""),
                ],
                Limits::default(),
                ChunkError::Mismatch,
            ),
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b""),
                    msg_chunk(b'F', 7, 2, 2, 5, b""),
                ],
                Limits::default(),
                ChunkError::Mismatch,
            ),
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b""),
                    msg_chunk(b'F', 7, 1, 3, 5, b""),
                ],
                Limits::default(),
                ChunkError::Sequence {
                    expected: 2,
                    got: 3,
                },
            ),
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b""),
                    msg_chunk(b'F', 7, 1, 2, 5, b""),
                ],
                Limits {
                    max_chunk_count: 1,
                    ..Limits::default()
                },
                ChunkError::TooManyChunks(1),
            ),
            (
                vec![
                    msg_chunk(b'C', 7, 1, 1, 5, b"abc"),
                    msg_chunk(b'F', 7, 1, 2, 5, b"abc"),
                ],
                Limits {
                    max_message_size: 5,
                    ..Limits::default()
                },
                ChunkError::MessageTooLarge(5),
            ),
            (
                vec![b"MSGF\x0c\0\0\0\0\0\0\0".to_vec()],
                Limits::default(),
                ChunkError::Decode(MessageType::Message, DecodeError::End),
            ),
        ];
        for (chunks, limits, want) in cases {
            let mut d = Stream::new(Messages::with_limits(limits));
            for c in &chunks {
                assert_eq!(d.push(c), c.len());
            }
            let got = all(&mut d);
            assert_eq!(
                got.last(),
                Some(&Err(Fail::Protocol(want.clone()))),
                "{want}"
            );
            // A failed stream drops later input and retains its error.
            let unread = d.buffered();
            assert_eq!(d.push(&hel_bytes(8192, 8192, b"")), 32);
            assert_eq!(d.next(), None);
            assert_eq!(d.failed(), Some(&Fail::Protocol(want)));
            assert_eq!(d.buffered(), unread);
        }
        // An OPN body past the message limit.
        let opn = Message::Secure(SecureMessage {
            kind: SecureKind::Open(AsymmetricHeader::none()),
            channel_id: 0,
            sequence_number: 0,
            request_id: 0,
            body: vec![0; 10],
        });
        let small = Limits {
            max_message_size: 5,
            ..Limits::default()
        };
        assert_eq!(
            opn.chunks(&small).map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        let mut d = Stream::new(Messages::with_limits(small));
        let input = &opn.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::MessageTooLarge(5))))
        );
    }

    #[test]
    fn writers_respect_limits() {
        let peer = Limits {
            receive_buffer_size: 8192,
            max_message_size: 20_000,
            max_chunk_count: 2,
        };
        assert_eq!(
            msg(1, 0, 0, vec![0; 20_001]).chunks(&peer).map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        // 20000 bytes need 3 chunks of 8192.
        assert_eq!(
            msg(1, 0, 0, vec![0; 20_000]).chunks(&peer).map(wire_chunks),
            Err(EncodeError::TooLong)
        );
        let ok = msg(1, 0, 0, vec![0; 16_000]);
        let bytes = ok.chunks(&peer).map(wire_chunks).unwrap();
        let mut d = Stream::with_buffer(Messages::with_limits(peer), MAX_BUFFER_SIZE as usize);
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(ok)));
        // The module's caps apply over what a peer says.
        let huge = Limits {
            receive_buffer_size: u32::MAX,
            max_message_size: u32::MAX,
            max_chunk_count: u32::MAX,
        };
        assert_eq!(huge.chunk_limit(), MAX_BUFFER_SIZE);
        assert_eq!(huge.message_limit(), MAX_MESSAGE_SIZE);
        assert_eq!(huge.chunk_count_limit(), MAX_CHUNK_COUNT);
        let tiny = Limits {
            receive_buffer_size: 1,
            max_message_size: 0,
            max_chunk_count: 0,
        };
        assert_eq!(tiny.chunk_limit(), MIN_BUFFER_SIZE);
        let mut w = Writer::new();
        assert_eq!(w.array_len(MAX_ARRAY_LEN + 1), Err(EncodeError::TooLong));
        assert_eq!(w.string_max(Some("abc"), 2), Err(EncodeError::TooLong));
    }

    #[test]
    fn acknowledge_names_the_limits_the_decoder_enforces() {
        // A server with no message or chunk limit of its own still has the
        // module's caps, and must not tell the client there is no limit.
        let hello = Hello {
            protocol_version: 0,
            receive_buffer_size: 65536,
            send_buffer_size: 65536,
            max_message_size: 0,
            max_chunk_count: 0,
            endpoint_url: String::new(),
        };
        let ack = hello.acknowledge(&Limits::default());
        assert_eq!(ack.max_message_size, MAX_MESSAGE_SIZE);
        assert_eq!(ack.max_chunk_count, MAX_CHUNK_COUNT);
        let ours = Limits {
            receive_buffer_size: 8192,
            max_message_size: 100,
            max_chunk_count: 2,
        };
        let ack = hello.acknowledge(&ours);
        assert_eq!((ack.max_message_size, ack.max_chunk_count), (100, 2));
        let mut d = Stream::new(Messages::with_limits(ack.limits()));
        assert_eq!(d.decoder().limits().message_limit(), ack.max_message_size);
    }

    #[test]
    fn legacy_wrap_only_above_the_threshold() {
        // Part 6: a legacy sequence number shall not wrap until it is
        // greater than 4 294 966 271.
        assert_eq!(LEGACY_WRAP, 4_294_966_271);
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'C', 7, 1, LEGACY_WRAP, 5, b"ab");
        assert_eq!(d.push(input), input.len());
        let input = &msg_chunk(b'F', 7, 1, 2, 5, b"cd");
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Sequence {
                expected: LEGACY_WRAP + 1,
                got: 2
            })))
        );
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'C', 7, 1, LEGACY_WRAP + 1, 5, b"ab");
        assert_eq!(d.push(input), input.len());
        let input = &msg_chunk(b'F', 7, 1, 1023, 5, b"cd");
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            d.next(),
            Some(Ok(msg(1, LEGACY_WRAP + 1, 5, b"abcd".to_vec())))
        );
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'C', 7, 1, LEGACY_WRAP + 1, 5, b"ab");
        assert_eq!(d.push(input), input.len());
        let input = &msg_chunk(b'F', 7, 1, 1024, 5, b"cd");
        assert_eq!(d.push(input), input.len());
        assert!(matches!(
            d.next(),
            Some(Err(Fail::Protocol(ChunkError::Sequence { .. })))
        ));
    }

    #[test]
    fn long_reasons_are_dropped_not_fatal() {
        // Part 6: a reason longer than 4096 bytes is ignored.
        let long = vec![0xffu8; MAX_REASON_LEN + 1];
        let mut err = b"ERRF".to_vec();
        err.extend_from_slice(&le32(16 + long.len() as u32));
        err.extend_from_slice(&le32(StatusCode::BAD_TCP_INTERNAL_ERROR.0));
        err.extend_from_slice(&le32(long.len() as u32));
        err.extend_from_slice(&long);
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&err), err.len());
        let want = ErrorMessage {
            error: StatusCode::BAD_TCP_INTERNAL_ERROR,
            reason: String::new(),
        };
        assert_eq!(d.next(), Some(Ok(Message::Error(want))));
        let mut tail = le32(StatusCode::BAD_RESPONSE_TOO_LARGE.0).to_vec();
        tail.extend_from_slice(&le32(long.len() as u32));
        tail.extend_from_slice(&long);
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'A', 7, 1, 1, 5, &tail);
        assert_eq!(d.push(input), input.len());
        let Some(Ok(Message::Abort(a))) = d.next() else {
            panic!()
        };
        assert_eq!(a.reason, "");
        // A reason of the longest length is kept.
        let ok = ErrorMessage {
            error: StatusCode::GOOD,
            reason: "r".repeat(MAX_REASON_LEN),
        };
        let mut d = Stream::new(Messages::new());
        let input = &Message::Error(ok.clone())
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap();
        assert_eq!(d.push(input), input.len());
        assert_eq!(d.next(), Some(Ok(Message::Error(ok))));
    }

    #[test]
    fn urls_are_less_than_4096_bytes() {
        // Part 6: the endpoint URL shall be less than 4096 bytes, and a
        // server answers a longer one with Bad_TcpEndpointUrlInvalid.
        assert_eq!(MAX_URL_LEN, 4095);
        let mut d = Stream::new(Messages::new());
        let input = &hel_bytes(8192, 8192, &[b'a'; 4096]);
        assert_eq!(d.push(input), input.len());
        let Fail::Protocol(e) = d.next().unwrap().unwrap_err() else {
            panic!("expected protocol error")
        };
        assert_eq!(
            e,
            ChunkError::Decode(MessageType::Hello, DecodeError::Length(4096))
        );
        assert_eq!(e.status(), StatusCode::BAD_TCP_ENDPOINT_URL_INVALID);
        let rh = ReverseHello {
            server_uri: "a".repeat(4096),
            endpoint_url: String::new(),
        };
        assert_eq!(
            Message::ReverseHello(rh)
                .chunks(&Limits::default())
                .map(wire_chunks),
            Err(EncodeError::TooLong)
        );
    }

    #[test]
    fn array_dimensions_need_two_or_more() {
        // Part 6: ArrayDimensions are only present for 2 or more dimensions.
        let one = Variant::Array {
            type_id: 3,
            values: vec![Value::Byte(1), Value::Byte(2)],
            dimensions: Some(vec![2]),
        };
        assert_eq!(Wire::to_bytes(&one), Err(EncodeError::Dimensions));
        let bytes = [0xc3u8, 2, 0, 0, 0, 1, 2, 1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(
            <Variant as Wire>::parse(&bytes),
            Err(DecodeError::Dimensions)
        );
    }

    #[test]
    fn total_values_are_bounded() {
        // Arrays of 65536 Bytes, inside an array of Variants: each array
        // is within MAX_ARRAY_LEN, but together they pass MAX_VALUES. The
        // outer array's elements and each inner Variant count too.
        let inner = Variant::Array {
            type_id: 3,
            values: vec![Value::Byte(0); MAX_ARRAY_LEN],
            dimensions: None,
        };
        let outer = |n: usize| Variant::Array {
            type_id: type_id::VARIANT,
            values: vec![Value::Variant(Box::new(inner.clone())); n],
            dimensions: None,
        };
        let n = MAX_VALUES / MAX_ARRAY_LEN;
        let fits = Wire::to_bytes(&outer(n - 1)).unwrap();
        assert!(<Variant as Wire>::parse(&fits).is_ok());
        assert_eq!(Wire::to_bytes(&outer(n)), Err(EncodeError::TooManyValues));
        let mut bytes = vec![0x98];
        bytes.extend_from_slice(&le32(n as u32));
        for _ in 0..n {
            bytes.push(0x83);
            bytes.extend_from_slice(&le32(MAX_ARRAY_LEN as u32));
            bytes.extend_from_slice(&vec![0; MAX_ARRAY_LEN]);
        }
        assert_eq!(
            <Variant as Wire>::parse(&bytes),
            Err(DecodeError::TooManyValues)
        );
    }

    #[test]
    fn nested_values_count_toward_the_bound() {
        // A DiagnosticInfo nests one level per byte, and each level is a
        // 72-byte box. An array of them, each deeply nested, once made a
        // reader allocate far more than MAX_VALUES values from a short
        // message.
        let per = MAX_DEPTH - 1;
        let n = MAX_VALUES / per + 1;
        let mut bytes = le32(n as u32).to_vec();
        for _ in 0..n {
            bytes.extend_from_slice(&vec![0x40; per - 1]);
            bytes.push(0);
        }
        assert_eq!(
            Reader::new(&bytes).read_array::<DiagnosticInfo>(),
            Err(DecodeError::TooManyValues)
        );
        // The writer stops at the same count as the reader.
        let mut deep = DiagnosticInfo::default();
        for _ in 1..per {
            deep = DiagnosticInfo {
                inner_diagnostic_info: Some(Box::new(deep)),
                ..Default::default()
            };
        }
        let fill = |k: usize| {
            let mut w = Writer::new();
            w.write_array(&vec![deep.clone(); k])
                .map(|()| w.into_bytes().unwrap())
        };
        // Each element is 1 + per values.
        let most = MAX_VALUES / (1 + per);
        let ok = fill(most).unwrap();
        assert!(Reader::new(&ok).read_array::<DiagnosticInfo>().is_ok());
        assert_eq!(fill(most + 1), Err(EncodeError::TooManyValues));
        // A chain of Variant arrays counts each Variant and each element.
        let mut r = Reader::new(&[0x98, 1, 0, 0, 0, 0x98, 1, 0, 0, 0, 0]);
        assert!(r.read::<Variant>().is_ok());
        assert_eq!(r.values, 5);
    }

    #[test]
    fn helpers_for_world_authors() {
        for t in [ChunkType::Final, ChunkType::Intermediate, ChunkType::Abort] {
            assert_eq!(ChunkType::from_byte(t.byte()), Some(t));
        }
        assert_eq!(ChunkType::from_byte(b'X'), None);
        let e: ExpandedNodeId = NodeId::numeric(0, 85).into();
        assert_eq!(Wire::to_bytes(&e).unwrap(), [0, 85]);
        assert_eq!(
            Variant::from(Value::Int32(-2)),
            Variant::Scalar(Value::Int32(-2))
        );
        assert_eq!(
            DecodeError::TooManyValues.to_string(),
            format!("more than {MAX_VALUES} values")
        );
        assert_eq!(
            EncodeError::TooManyValues.to_string(),
            format!("more than {MAX_VALUES} values")
        );
    }

    /// Byte streams that each hold one whole message.
    fn samples() -> Vec<Vec<u8>> {
        let mut out = vec![
            hel_bytes(65536, 65536, b"opc.tcp://a"),
            Message::Error(ErrorMessage {
                error: StatusCode::BAD_DECODING_ERROR,
                reason: "r".into(),
            })
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap(),
            Message::ReverseHello(ReverseHello {
                server_uri: "u".into(),
                endpoint_url: "e".into(),
            })
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap(),
            Message::Secure(SecureMessage {
                kind: SecureKind::Open(AsymmetricHeader::none()),
                channel_id: 0,
                sequence_number: 1,
                request_id: 1,
                body: open_request().to_bytes().unwrap(),
            })
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap(),
            msg(1, 2, 3, vec![1; 9000])
                .chunks(&Limits::default())
                .map(wire_chunks)
                .unwrap(),
        ];
        let mut ack = b"ACKF".to_vec();
        ack.extend_from_slice(&le32(28));
        for v in [0, 8192, 8192, 0, 0] {
            ack.extend_from_slice(&le32(v));
        }
        out.push(ack);
        let mut abort = le32(1).to_vec();
        abort.extend_from_slice(&[0xff; 4]);
        out.push(msg_chunk(b'A', 1, 2, 3, 4, &abort));
        // A MSG holding a Variant, so mutations reach the value readers.
        let mut body = Wire::to_bytes(&NodeId::numeric(1, 999)).unwrap();
        body.extend_from_slice(&Wire::to_bytes(&every_variant()).unwrap());
        out.push(
            msg(1, 1, 1, body)
                .chunks(&Limits::default())
                .map(wire_chunks)
                .unwrap(),
        );
        out
    }

    fn sample_values() -> Vec<Value> {
        vec![
            Value::Boolean(true),
            Value::SByte(-1),
            Value::Byte(2),
            Value::Int16(-3),
            Value::UInt16(4),
            Value::Int32(-5),
            Value::UInt32(6),
            Value::Int64(-7),
            Value::UInt64(8),
            Value::Float(9.5),
            Value::Double(-10.25),
            Value::String(Some("s".into())),
            Value::String(None),
            Value::DateTime(11),
            Value::Guid(Guid {
                data1: 1,
                data2: 2,
                data3: 3,
                data4: [4; 8],
            }),
            Value::ByteString(Some(vec![1, 2])),
            Value::XmlElement(Some(b"<x/>".to_vec())),
            Value::NodeId(NodeId::string(3, "n")),
            Value::ExpandedNodeId(ExpandedNodeId {
                server_index: 1,
                ..Default::default()
            }),
            Value::StatusCode(StatusCode::BAD_UNEXPECTED_ERROR),
            Value::QualifiedName(QualifiedName {
                namespace: 1,
                name: "q".into(),
            }),
            Value::LocalizedText(LocalizedText {
                locale: None,
                text: Some("t".into()),
            }),
            Value::ExtensionObject(Box::new(ExtensionObject {
                type_id: NodeId::numeric(0, 1),
                body: ExtensionBody::Binary(vec![0]),
            })),
            Value::DataValue(Box::new(DataValue {
                status: Some(StatusCode(1)),
                ..Default::default()
            })),
        ]
    }

    fn every_variant() -> Variant {
        Variant::Array {
            type_id: type_id::VARIANT,
            values: sample_values()
                .into_iter()
                .map(|v| Value::Variant(Box::new(Variant::Scalar(v))))
                .collect(),
            dimensions: Some(vec![2, 12]),
        }
    }

    #[test]
    fn every_truncated_prefix_waits_or_fails() {
        for bytes in samples() {
            contract::check_decode_with_held_limit(
                Messages::new,
                &bytes,
                MAX_MESSAGE_SIZE as usize,
            );
            for cut in 0..bytes.len() {
                let mut stream = Stream::new(Messages::new());
                pump(&mut stream, &bytes[..cut], |_| {
                    panic!("partial message was emitted")
                })
                .unwrap();
                stream.end();
                if cut == 0 {
                    assert!(stream.next().is_none());
                } else {
                    assert!(stream.next().unwrap().is_err());
                }
            }
            let mut stream = Stream::new(Messages::new());
            let mut got = Vec::new();
            pump(&mut stream, &bytes, |message| got.push(message)).unwrap();
            stream.end();
            assert!(stream.next().is_none());
            assert_eq!(got.len(), 1);
        }
        // As values, prefixes end too soon.
        let req = open_request().to_bytes().unwrap();
        for n in 0..req.len() {
            assert_eq!(Service::parse(&req[..n]), Err(DecodeError::End), "{n}");
        }
        let full = DataValue {
            value: Some(Variant::Scalar(Value::Int32(1))),
            status: Some(StatusCode(2)),
            source_timestamp: Some(3),
            source_picoseconds: Some(4),
            server_timestamp: Some(5),
            server_picoseconds: Some(6),
        };
        let dv = Wire::to_bytes(&full).unwrap();
        for n in 0..dv.len() {
            assert_eq!(
                <DataValue as Wire>::parse(&dv[..n]),
                Err(DecodeError::End),
                "{n}"
            );
        }
        // A string's length can outrun a prefix before its bytes do.
        let v = Wire::to_bytes(&every_variant()).unwrap();
        for n in 0..v.len() {
            assert!(
                matches!(
                    <Variant as Wire>::parse(&v[..n]),
                    Err(DecodeError::End | DecodeError::Length(_))
                ),
                "{n}"
            );
        }
        let d = Wire::to_bytes(&DiagnosticInfo {
            additional_info: Some("abc".into()),
            ..Default::default()
        })
        .unwrap();
        for n in 0..d.len() {
            assert!(<DiagnosticInfo as Wire>::parse(&d[..n]).is_err());
        }
    }

    #[test]
    fn decoder_takes_many_small_messages_in_linear_time() {
        let mut stream = Vec::new();
        for seq in 0..100_000 {
            stream.extend_from_slice(
                &msg(1, seq, 1, vec![1, 2, 3])
                    .chunks(&Limits::default())
                    .map(wire_chunks)
                    .unwrap(),
            );
        }
        let started = std::time::Instant::now();
        let mut d = Stream::new(Messages::new());
        let mut n = 0;
        pump(&mut d, &stream, |_| n += 1).unwrap();
        assert_eq!(n, 100_000);
        assert_eq!(d.buffered(), 0);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn module_example() {
        let mut server = Stream::new(Messages::new());
        let url = b"opc.tcp://plc:4840";
        let input = &hel_bytes(65536, 65536, url);
        assert_eq!(server.push(input), input.len());
        let Some(Ok(Message::Hello(hello))) = server.next() else {
            panic!()
        };
        let ack = hello.acknowledge(&Limits::default());
        assert_eq!(ack.receive_buffer_size, 8192);
        server.decoder().set_limits(ack.limits());
        assert_eq!(server.decoder().limits(), ack.limits());
        let reply = Message::Acknowledge(ack)
            .chunks(&hello.limits())
            .map(wire_chunks)
            .unwrap();
        assert_eq!(&reply[..4], b"ACKF");
        assert_eq!(reply.len(), 28);
        let request = Service::OpenSecureChannelRequest(OpenSecureChannelRequest {
            header: RequestHeader {
                request_handle: 1,
                ..RequestHeader::default()
            },
            client_protocol_version: 0,
            request_type: RequestType::Issue,
            security_mode: SecurityMode::None,
            client_nonce: None,
            requested_lifetime: 600_000,
        });
        let opn = Message::Secure(SecureMessage {
            kind: SecureKind::Open(AsymmetricHeader::none()),
            channel_id: 0,
            sequence_number: 1,
            request_id: 1,
            body: request.to_bytes().unwrap(),
        });
        let input = &opn.chunks(&ack.limits()).map(wire_chunks).unwrap();
        assert_eq!(server.push(input), input.len());
        let Some(Ok(Message::Secure(msg))) = server.next() else {
            panic!()
        };
        let SecureKind::Open(security) = &msg.kind else {
            panic!()
        };
        assert_eq!(security.policy_uri, SECURITY_POLICY_NONE);
        let Ok(Service::OpenSecureChannelRequest(req)) = Service::parse(&msg.body) else {
            panic!()
        };
        let response = Service::OpenSecureChannelResponse(OpenSecureChannelResponse {
            header: ResponseHeader {
                request_handle: req.header.request_handle,
                ..ResponseHeader::default()
            },
            server_protocol_version: 0,
            security_token: ChannelSecurityToken {
                channel_id: 7,
                token_id: 1,
                created_at: 0,
                revised_lifetime: req.requested_lifetime,
            },
            server_nonce: None,
        });
        let answer = Message::Secure(SecureMessage {
            kind: msg.kind.clone(),
            channel_id: 7,
            sequence_number: 1,
            request_id: msg.request_id,
            body: response.to_bytes().unwrap(),
        });
        let bytes = answer.chunks(&hello.limits()).map(wire_chunks).unwrap();
        assert_eq!(&bytes[..4], b"OPNF");
        assert_eq!(&bytes[8..12], &7u32.to_le_bytes());
    }

    // Findings from review, each checked against Part 6 or Part 3.

    #[test]
    fn push_holds_a_bounded_amount() {
        let one = hel_bytes(8192, 8192, b"x");
        let stream: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(MAX_BUFFER_SIZE as usize + 1000 * one.len())
            .collect();
        let mut d = Stream::with_buffer(Messages::new(), MAX_BUFFER_SIZE as usize);
        let took = d.push(&stream);
        assert_eq!(took, MAX_BUFFER_SIZE as usize);
        assert_eq!(d.buffered(), MAX_BUFFER_SIZE as usize);
        assert_eq!(d.push(&stream[took..]), 0);
        // Taking a message out makes room again.
        assert!(matches!(d.next(), Some(Ok(Message::Hello(_)))));
        assert_eq!(d.push(&stream[took..]), one.len());
        assert!(d.buffered() <= MAX_BUFFER_SIZE as usize);
    }

    #[test]
    fn single_chunk_messages_are_counted_before_they_are_split() {
        // A header leaving one byte per chunk, and a 16 MiB body: refused
        // without first making 16 million slices.
        let policy = "urn:other".to_string();
        let fixed = HEADER_LEN + 4 + (4 + policy.len()) + 4 + 4 + 8;
        let header = AsymmetricHeader {
            policy_uri: policy,
            sender_certificate: Some(vec![0; MIN_BUFFER_SIZE as usize - fixed - 1]),
            receiver_thumbprint: None,
        };
        let opn = SecureMessage {
            kind: SecureKind::Open(header),
            channel_id: 0,
            sequence_number: 0,
            request_id: 0,
            body: vec![0; MAX_MESSAGE_SIZE as usize],
        };
        let started = std::time::Instant::now();
        assert_eq!(opn.chunks(&Limits::default()), Err(EncodeError::TooLong));
        assert!(
            started.elapsed().as_millis() < 500,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn sequence_numbers_follow_across_messages() {
        let mut d = Stream::new(Messages::new());
        let input = &msg_chunk(b'F', 7, 1, 10, 1, b"a");
        assert_eq!(d.push(input), input.len());
        let input = &msg_chunk(b'F', 7, 1, 10, 2, b"b");
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            all(&mut d),
            [
                Ok(msg(1, 10, 1, b"a".to_vec())),
                Err(Fail::Protocol(ChunkError::Sequence {
                    expected: 11,
                    got: 10
                }))
            ]
        );
        // OPN, then a MSG of two chunks, then a CLO, numbered in turn.
        let mut d = Stream::with_buffer(Messages::new(), MAX_BUFFER_SIZE as usize);
        let opn = Message::Secure(SecureMessage {
            kind: SecureKind::Open(AsymmetricHeader::none()),
            channel_id: 0,
            sequence_number: 5,
            request_id: 1,
            body: vec![],
        });
        let input = &opn.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(d.push(input), input.len());
        let input = &msg(1, 6, 2, vec![0; 9000])
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap();
        assert_eq!(d.push(input), input.len());
        let clo = Message::Secure(SecureMessage {
            kind: SecureKind::Close { token_id: 1 },
            channel_id: 7,
            sequence_number: 8,
            request_id: 3,
            body: vec![],
        });
        let input = &clo.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(d.push(input), input.len());
        assert!(all(&mut d).iter().all(Result::is_ok));
        let mut d = Stream::new(Messages::new());
        let input = &opn.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(d.push(input), input.len());
        let input = &clo.chunks(&Limits::default()).map(wire_chunks).unwrap();
        assert_eq!(d.push(input), input.len());
        assert_eq!(
            all(&mut d).last(),
            Some(&Err(Fail::Protocol(ChunkError::Sequence {
                expected: 6,
                got: 8
            })))
        );
    }

    #[test]
    fn messages_report_empty_partial_assemblies() {
        let mut stream = Stream::new(Messages::new());
        assert!(stream.decoder().is_between_messages());
        for sequence in [1, 2] {
            let chunk = msg_chunk(b'C', 7, 1, sequence, 5, b"");
            assert_eq!(stream.push(&chunk), chunk.len());
            assert_eq!(stream.next(), None);
            assert_eq!(stream.buffered(), 0);
            assert_eq!(stream.held(), 0);
            assert!(!stream.decoder().is_between_messages());
        }
        let chunk = msg_chunk(b'F', 7, 1, 3, 5, b"");
        assert_eq!(stream.push(&chunk), chunk.len());
        assert_eq!(stream.next(), Some(Ok(msg(1, 1, 5, vec![]))));
        assert!(stream.decoder().is_between_messages());
        stream.end();
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn message_completion_at_eof_includes_empty_bodies() {
        for body in [b"".as_slice(), b"part"] {
            for complete in [false, true] {
                let mut d = Stream::new(Messages::new());
                let input = msg_chunk(b'C', 7, 1, 1, 5, body);
                assert_eq!(d.push(&input), input.len());
                assert_eq!(d.next(), None);
                assert_eq!(d.buffered(), 0);
                assert_eq!(d.held(), body.len());
                assert!(d.failed().is_none());

                // Byte counts do not say whether an empty MSG is complete.
                if complete {
                    let input = msg_chunk(b'F', 7, 1, 2, 5, b"end");
                    assert_eq!(d.push(&input), input.len());
                    assert_eq!(d.next(), Some(Ok(msg(1, 1, 5, [body, b"end"].concat()))));
                    assert_eq!(d.buffered(), 0);
                    assert_eq!(d.held(), 0);
                }
                d.end();
                if complete {
                    assert_eq!(d.next(), None);
                    assert!(d.failed().is_none());
                } else {
                    let error = Fail::Protocol(ChunkError::Incomplete);
                    assert_eq!(d.next(), Some(Err(error.clone())));
                    assert_eq!(d.failed(), Some(&error));
                }
                assert!(d.is_done());
                assert_eq!(d.next(), None);
            }
        }
    }

    #[test]
    fn a_partial_header_after_a_message_is_truncated_at_eof() {
        let mut d = Stream::new(Messages::new());
        let input = msg_chunk(b'F', 7, 1, 1, 5, b"body");
        assert_eq!(d.push(&input), input.len());
        assert_eq!(d.next(), Some(Ok(msg(1, 1, 5, b"body".to_vec()))));
        assert_eq!(d.push(b"MSG"), 3);
        assert_eq!(d.next(), None);
        assert_eq!(d.buffered(), 3);
        d.end();
        assert_eq!(d.next(), Some(Err(Fail::Truncated { unread: 3 })));
    }

    #[test]
    fn an_error_message_ends_a_partial_message() {
        let err = Message::Error(ErrorMessage {
            error: StatusCode::BAD_TCP_INTERNAL_ERROR,
            reason: "bye".into(),
        });
        for body in [b"".as_slice(), b"part"] {
            let mut d = Stream::new(Messages::new());
            let input = msg_chunk(b'C', 7, 1, 1, 5, body);
            assert_eq!(d.push(&input), input.len());
            assert_eq!(d.next(), None);
            assert_eq!(d.held(), body.len());
            let input = err.chunks(&Limits::default()).map(wire_chunks).unwrap();
            assert_eq!(d.push(&input), input.len());
            assert_eq!(d.next(), Some(Ok(err.clone())));
            assert_eq!(d.buffered(), 0);
            assert_eq!(d.held(), 0);
            d.end();
            assert_eq!(d.next(), None);
            assert!(d.is_done());
            assert!(d.failed().is_none());
        }
    }

    #[test]
    fn variants_hold_no_diagnostic_infos_or_nested_data_values() {
        // Part 6, 5.1.9.
        assert_eq!(
            <Variant as Wire>::parse(&[0x19, 0]),
            Err(DecodeError::VariantType(25))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[0x99, 0, 0, 0, 0]),
            Err(DecodeError::VariantType(25))
        );
        assert_eq!(
            <Variant as Wire>::parse(&[0x17, 0x01, 0x17, 0]),
            Err(DecodeError::VariantType(23))
        );
        // Indirectly too: through an array of Variants.
        assert_eq!(
            <DataValue as Wire>::parse(&[0x01, 0x98, 1, 0, 0, 0, 0x17, 0]),
            Err(DecodeError::VariantType(23))
        );
        // A DataValue in a Variant that is not inside one is fine.
        assert!(<Variant as Wire>::parse(&[0x17, 0x01, 0x06, 1, 0, 0, 0]).is_ok());
        let diag = Variant::Scalar(Value::DiagnosticInfo(Box::default()));
        assert_eq!(Wire::to_bytes(&diag), Err(EncodeError::VariantType));
        let inner = DataValue {
            value: Some(Variant::Null),
            ..Default::default()
        };
        let outer = DataValue {
            value: Some(Variant::Array {
                type_id: type_id::VARIANT,
                values: vec![Value::Variant(Box::new(Variant::Scalar(Value::DataValue(
                    Box::new(inner.clone()),
                ))))],
                dimensions: None,
            }),
            ..Default::default()
        };
        assert_eq!(Wire::to_bytes(&outer), Err(EncodeError::VariantType));
        assert!(Wire::to_bytes(&Variant::Scalar(Value::DataValue(Box::new(inner)))).is_ok());
    }

    #[test]
    fn variant_types_are_checked_before_the_array_length() {
        // Part 6, 5.2.2.16: type 32 does not exist, even for an empty array.
        assert_eq!(
            <Variant as Wire>::parse(&[0xa0, 0, 0, 0, 0]),
            Err(DecodeError::VariantType(32))
        );
        // Encoders shall not use the reserved ids 26 to 31.
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::Reserved {
                type_id: 26,
                bytes: None
            })),
            Err(EncodeError::VariantType)
        );
        let empty = Variant::Array {
            type_id: 27,
            values: vec![],
            dimensions: None,
        };
        assert_eq!(Wire::to_bytes(&empty), Err(EncodeError::VariantType));
        // Binary readers accept reserved type ids.
        assert!(Reader::new(&[0x9b, 0, 0, 0, 0]).read::<Variant>().is_ok());
        assert_eq!(
            <Variant as Wire>::parse(&[0x9b, 0, 0, 0, 0]),
            Err(DecodeError::VariantType(27))
        );
    }

    #[test]
    fn a_hundred_levels_of_nesting_read() {
        // Part 6, 5.1.9: decoders support at least 100 nesting levels.
        const { assert!(MAX_DEPTH >= 100) };
        let mut deep = Vec::new();
        for _ in 0..99 {
            deep.extend_from_slice(&[0x98, 1, 0, 0, 0]);
        }
        deep.extend_from_slice(&[6, 1, 0, 0, 0]);
        let v = <Variant as Wire>::parse(&deep).unwrap();
        assert_eq!(Wire::to_bytes(&v).unwrap(), deep);
    }

    #[test]
    fn node_id_and_qualified_name_limits() {
        // Part 3, 8.2.4 and 8.3: lengths in characters, no C0 or C1.
        let longest = NodeId::string(1, &"水".repeat(MAX_NODE_ID_LEN));
        assert_eq!(
            <NodeId as Wire>::parse(&Wire::to_bytes(&longest).unwrap()),
            Ok(longest)
        );
        assert_eq!(
            Wire::to_bytes(&NodeId::string(1, &"a".repeat(MAX_NODE_ID_LEN + 1))),
            Err(EncodeError::TooLong)
        );
        let mut long = vec![0x03, 1, 0];
        long.extend_from_slice(&le32(MAX_NODE_ID_LEN as u32 + 1));
        long.extend_from_slice(&vec![b'a'; MAX_NODE_ID_LEN + 1]);
        assert_eq!(
            <NodeId as Wire>::parse(&long),
            Err(DecodeError::Length(MAX_NODE_ID_LEN as i32 + 1))
        );
        long[0] = 0x05;
        assert_eq!(
            <NodeId as Wire>::parse(&long),
            Err(DecodeError::Length(MAX_NODE_ID_LEN as i32 + 1))
        );
        let opaque = NodeId {
            namespace: 1,
            identifier: Identifier::Opaque(vec![0; MAX_NODE_ID_LEN + 1]),
        };
        assert_eq!(Wire::to_bytes(&opaque), Err(EncodeError::TooLong));
        assert_eq!(
            Wire::to_bytes(&NodeId::string(1, "a\nb")),
            Err(EncodeError::ControlChar)
        );
        assert_eq!(
            Wire::to_bytes(&NodeId::string(1, "a\u{85}b")),
            Err(EncodeError::ControlChar)
        );
        assert_eq!(
            <NodeId as Wire>::parse(&[0x03, 1, 0, 3, 0, 0, 0, b'a', b'\n', b'b']),
            Err(DecodeError::ControlChar)
        );
        let q = QualifiedName {
            namespace: 0,
            name: "q".repeat(MAX_QUALIFIED_NAME_LEN + 1),
        };
        assert_eq!(Wire::to_bytes(&q), Err(EncodeError::TooLong));
        let mut qb = vec![0, 0];
        qb.extend_from_slice(&le32(MAX_QUALIFIED_NAME_LEN as u32 + 1));
        qb.extend_from_slice(&vec![b'q'; MAX_QUALIFIED_NAME_LEN + 1]);
        assert_eq!(
            <QualifiedName as Wire>::parse(&qb),
            Err(DecodeError::Length(MAX_QUALIFIED_NAME_LEN as i32 + 1))
        );
        let ok = QualifiedName {
            namespace: 0,
            name: "q".repeat(MAX_QUALIFIED_NAME_LEN),
        };
        assert_eq!(
            <QualifiedName as Wire>::parse(&Wire::to_bytes(&ok).unwrap()),
            Ok(ok)
        );
        assert_eq!(
            Wire::to_bytes(&QualifiedName {
                namespace: 0,
                name: "\t".into()
            }),
            Err(EncodeError::ControlChar)
        );
    }

    #[test]
    fn every_null_node_id_is_null() {
        // Part 3, 8.2.4, Table 24.
        assert!(NodeId::string(0, "").is_null());
        assert!(
            NodeId {
                namespace: 0,
                identifier: Identifier::Guid(Guid::default())
            }
            .is_null()
        );
        assert!(
            NodeId {
                namespace: 0,
                identifier: Identifier::Opaque(vec![])
            }
            .is_null()
        );
        assert!(!NodeId::string(1, "").is_null());
        assert!(!NodeId::numeric(0, 1).is_null());
    }

    #[test]
    fn expanded_node_ids_require_namespace_zero_with_a_uri() {
        // Part 6, 5.2.2.10.
        let e = ExpandedNodeId {
            node_id: NodeId::numeric(7, 42),
            namespace_uri: Some("urn:x".into()),
            server_index: 0,
        };
        assert_eq!(e.to_bytes(), Err(EncodeError::Value));
        let e = ExpandedNodeId {
            node_id: NodeId::numeric(0, 42),
            ..e
        };
        let bytes = e.to_bytes().unwrap();
        assert_eq!(bytes[..2], [0x80, 42]);
        let back = <ExpandedNodeId as Wire>::parse(&bytes).unwrap();
        assert_eq!(back.node_id, NodeId::numeric(0, 42));
        // A namespace index sent beside a URI reads as 0.
        assert_eq!(
            <ExpandedNodeId as Wire>::parse(&[0x81, 7, 42, 0, 1, 0, 0, 0, b'u'])
                .unwrap()
                .node_id,
            NodeId::numeric(0, 42)
        );
        // An empty URI would read back as None and is refused.
        let empty = ExpandedNodeId {
            node_id: NodeId::numeric(0, 42),
            namespace_uri: Some(String::new()),
            server_index: 0,
        };
        assert_eq!(empty.to_bytes(), Err(EncodeError::Value));
        assert_eq!(
            <ExpandedNodeId as Wire>::parse(&[0x80, 42, 0, 0, 0, 0])
                .unwrap()
                .namespace_uri,
            None
        );
    }

    #[test]
    fn picoseconds_stay_below_ten_thousand() {
        // Part 6, 5.2.2.17.
        let bytes = [0x14, 1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        assert_eq!(
            <DataValue as Wire>::parse(&bytes)
                .unwrap()
                .source_picoseconds,
            Some(MAX_PICOSECONDS)
        );
        let d = DataValue {
            server_timestamp: Some(1),
            server_picoseconds: Some(10_000),
            ..Default::default()
        };
        assert_eq!(d.to_bytes(), Err(EncodeError::Value));
        let d = DataValue {
            server_picoseconds: Some(MAX_PICOSECONDS),
            ..d
        };
        contract::check_wire_value(&d);
    }

    #[test]
    fn policy_none_carries_no_certificate_or_thumbprint() {
        // Part 6, 6.7.2.3: an unsigned message has no sender certificate,
        // and a thumbprint is empty when nothing is encrypted.
        let opn = |h: AsymmetricHeader| {
            Message::Secure(SecureMessage {
                kind: SecureKind::Open(h),
                channel_id: 0,
                sequence_number: 1,
                request_id: 1,
                body: vec![],
            })
        };
        for h in [
            AsymmetricHeader {
                sender_certificate: Some(vec![1]),
                ..AsymmetricHeader::none()
            },
            AsymmetricHeader {
                receiver_thumbprint: Some(vec![1]),
                ..AsymmetricHeader::none()
            },
            AsymmetricHeader {
                policy_uri: "urn:p".into(),
                receiver_thumbprint: Some(vec![1]),
                sender_certificate: None,
            },
        ] {
            assert_eq!(
                opn(h.clone()).chunks(&Limits::default()).map(wire_chunks),
                Err(EncodeError::SecurityHeader)
            );
            // The same header, written by hand, does not read.
            let good = opn(AsymmetricHeader {
                policy_uri: h.policy_uri.clone(),
                ..AsymmetricHeader::none()
            });
            let mut bytes = good.chunks(&Limits::default()).map(wire_chunks).unwrap();
            let at = 12 + 4 + h.policy_uri.len();
            let mut fields = Writer::new();
            fields.byte_string(h.sender_certificate.as_deref()).unwrap();
            fields
                .byte_string(h.receiver_thumbprint.as_deref())
                .unwrap();
            bytes.splice(at..at + 8, fields.into_bytes().unwrap());
            let size = bytes.len() as u32;
            bytes[4..8].copy_from_slice(&le32(size));
            let mut d = Stream::new(Messages::new());
            assert_eq!(d.push(&bytes), bytes.len());
            assert_eq!(
                d.next(),
                Some(Err(Fail::Protocol(ChunkError::Decode(
                    MessageType::Open,
                    DecodeError::Length(1)
                ))))
            );
        }
        // Empty fields, and a 20-byte thumbprint under another policy, are fine.
        let empty = AsymmetricHeader {
            sender_certificate: Some(vec![]),
            receiver_thumbprint: Some(vec![]),
            ..AsymmetricHeader::none()
        };
        let bytes = opn(empty.clone())
            .chunks(&Limits::default())
            .map(wire_chunks)
            .unwrap();
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&bytes), bytes.len());
        assert_eq!(d.next(), Some(Ok(opn(empty))));
        let signed = AsymmetricHeader {
            policy_uri: "urn:p".into(),
            sender_certificate: Some(vec![1; 30]),
            receiver_thumbprint: Some(vec![2; THUMBPRINT_LEN]),
        };
        assert!(
            opn(signed)
                .chunks(&Limits::default())
                .map(wire_chunks)
                .is_ok()
        );
    }

    #[test]
    fn connection_messages_ignore_the_reserved_byte() {
        // Part 6, 7.1.2.2: receivers ignore the fourth byte of a HEL.
        let mut hel = hel_bytes(8192, 8192, b"x");
        hel[3] = 0;
        let mut d = Stream::new(Messages::new());
        assert_eq!(d.push(&hel), hel.len());
        let Some(Ok(m)) = d.next() else { panic!() };
        // Writers use 'F'.
        assert_eq!(
            m.chunks(&Limits::default()).map(wire_chunks).unwrap()[3],
            b'F'
        );
    }

    #[test]
    fn nans_are_written_quiet() {
        // Part 6, 5.2.2.3.
        let f =
            Wire::to_bytes(&Variant::Scalar(Value::Float(f32::from_bits(0x7f80_0001)))).unwrap();
        assert_eq!(f[1..], [0, 0, 0xc0, 0xff]);
        let d = Wire::to_bytes(&Variant::Scalar(Value::Double(f64::from_bits(
            0x7ff0_0000_0000_0001,
        ))))
        .unwrap();
        assert_eq!(d[1..], [0, 0, 0, 0, 0, 0, 0xf8, 0xff]);
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::Float(1.5))).unwrap()[1..],
            1.5f32.to_le_bytes()
        );
    }

    #[test]
    fn date_times_are_bounded() {
        // Part 6, 5.2.2.5.
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::DateTime(-1))),
            Err(EncodeError::Value)
        );
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::DateTime(MAX_DATE_TIME))),
            Err(EncodeError::Value)
        );
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::DateTime(MAX_DATE_TIME - 1))).unwrap()[1..],
            (MAX_DATE_TIME - 1).to_le_bytes()
        );
        // An Int64 is written as it is.
        assert_eq!(
            Wire::to_bytes(&Variant::Scalar(Value::Int64(-1))).unwrap()[1..],
            [0xff; 8]
        );
        let mut b = vec![13];
        b.extend_from_slice(&(-5i64).to_le_bytes());
        assert_eq!(
            <Variant as Wire>::parse(&b),
            Ok(Variant::Scalar(Value::DateTime(0)))
        );
        let h = RequestHeader {
            timestamp: -9,
            ..Default::default()
        };
        assert_eq!(Wire::to_bytes(&h), Err(EncodeError::Value));
    }

    /// Checks permissive reads, including reserved Variant types that cannot be written.
    fn check_reader<T: Binary + Wire<WriteError = EncodeError> + PartialEq + core::fmt::Debug>(
        bytes: &[u8],
    ) {
        let mut reader = Reader::new(bytes);
        if let Ok(value) = reader.read::<T>()
            && reader.finish().is_ok()
        {
            match value.to_bytes() {
                Ok(bytes) => assert_eq!(<T as Wire>::parse(&bytes).unwrap(), value),
                Err(EncodeError::VariantType) => {}
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5e_ed0f_0bca);
        let seeds = samples();
        let small = Limits {
            receive_buffer_size: 8192,
            max_message_size: 1 << 16,
            max_chunk_count: 8,
        };
        for round in 0..4000 {
            // Half random bytes, half a valid sample with a few bytes changed.
            let mut b: Vec<u8> = if round % 2 == 0 {
                let n = rng.below(300) as usize;
                let mut v: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                // Start some with a real header so the parsers go deeper.
                if n >= 8 && rng.below(2) == 0 {
                    let types: [&[u8; 4]; 7] = [
                        b"HELF", b"ACKF", b"ERRF", b"RHEF", b"OPNF", b"CLOF", b"MSGC",
                    ];
                    v[..4].copy_from_slice(types[rng.below(7) as usize]);
                    v[4..8].copy_from_slice(&le32(rng.below(n as u64 + 1) as u32));
                }
                v
            } else {
                let mut v = seeds[rng.below(seeds.len() as u64) as usize].clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(v.len() as u64) as usize;
                    v[i] = rng.next() as u8;
                }
                if rng.below(4) == 0 {
                    v.truncate(rng.below(v.len() as u64) as usize);
                }
                v
            };
            if round % 7 == 0 {
                b.extend_from_slice(&seeds[0]);
            }

            let limits = if round % 3 == 0 {
                small
            } else {
                Limits::default()
            };
            contract::check_decode_with_held_limit(
                || Messages::with_limits(limits),
                &b,
                limits.message_limit() as usize,
            );
            let mut stream = Stream::new(Messages::with_limits(limits));
            let mut first = Vec::new();
            let _ = pump(&mut stream, &b, |message| {
                first.push(Ok::<_, Fail<ChunkError>>(message))
            });
            for m in first.iter().flatten() {
                // A message read writes, and reads back the same.
                let out = m
                    .chunks(&limits)
                    .map(wire_chunks)
                    .expect("a message read can be written");
                let mut d =
                    Stream::with_buffer(Messages::with_limits(limits), MAX_BUFFER_SIZE as usize);
                assert_eq!(d.push(&out), out.len());
                assert_eq!(d.next().as_ref(), Some(&Ok(m.clone())));
                if let Message::Secure(s) = m {
                    contract::check_wire::<Service>(&s.body);
                    if let Ok(Service::Other { body, .. }) = Service::parse(&s.body) {
                        contract::check_wire::<Variant>(&body);
                        check_reader::<Variant>(&body);
                    }
                }
            }

            // The same bytes as values.
            contract::check_wire::<Variant>(&b);
            contract::check_wire::<DataValue>(&b);
            contract::check_wire::<DiagnosticInfo>(&b);
            check_reader::<Variant>(&b);
            check_reader::<DataValue>(&b);
            check_reader::<DiagnosticInfo>(&b);
            contract::check_wire::<ExpandedNodeId>(&b);
            contract::check_wire::<NodeId>(&b);
            contract::check_wire::<LocalizedText>(&b);
            contract::check_wire::<ExtensionObject>(&b);
            contract::check_wire::<ResponseHeader>(&b);
            contract::check_wire::<Service>(&b);
            // Every value at every offset, one byte at a time through a reader.
            let mut r = Reader::new(&b);
            while r.remaining() > 0 {
                let before = r.remaining();
                if r.read::<Variant>().is_err() {
                    let _ = r.take(1);
                }
                assert!(r.remaining() < before);
            }
        }
    }
}
