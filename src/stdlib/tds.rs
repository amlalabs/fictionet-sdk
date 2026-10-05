//! TDS (SQL Server): reading and writing packets, logins, SQL batches and
//! response tokens, with no I/O.
//!
//! TDS, the Tabular Data Stream, is how clients talk to Microsoft SQL
//! Server, usually over TCP port 1433. Every message travels in packets
//! with an 8-byte header: a type, a status, a length and a few other
//! fields. A message longer than one packet is split over several, and
//! the last one has the end-of-message bit set. The client opens with a
//! PRELOGIN message, logs in with a LOGIN7 message, and then sends
//! requests such as a SQL batch. The server answers each one with a
//! stream of tokens: a login acknowledgement, environment changes,
//! messages, column descriptions, rows and DONE tokens. This module
//! follows the Microsoft [MS-TDS] specification for TDS 7.2 to 7.4.
//!
//! Nothing here reads a socket. A world that plays a database server
//! feeds the bytes it reads from a TCP connection to a [`Decoder`], gets
//! [`Message`]s back, and reads each one as a [`Prelogin`], a [`Login7`]
//! or a [`SqlBatch`]. It answers with a [`Prelogin`] of its own, and with
//! [`Token`]s written by a [`TokenWriter`] for everything else. Which
//! users, databases and tables exist, and what a query returns, is up to
//! world code. So is whether a login succeeds. A world that plays a
//! client uses the same types the other way round, and a [`TokenReader`]
//! to read the server's answer.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Bad bytes give an [`Error`] or a [`FrameError`], never a panic.
//! Every buffer is bounded by a named limit, such as [`MAX_MESSAGE`].
//!
//! New stacks use [`Frames`] with [`codec::Stream`](super::codec::Stream)
//! to read individual packets. [`Packet`] implements [`Wire`] for exact
//! parsing and transactional writing. [`Packet::to_bytes`] still clips
//! oversized data. [`Decoder`] keeps its message assembly, status handling,
//! buffer limits, and repeated errors.
//!
//! [MS-TDS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
//!
//! ```
//! use fictionet::stdlib::tds::{
//!     data_type, done_status, encryption, packet_type, tds_version, Column, Decoder, Done, Login7,
//!     LoginAck, Message, Prelogin, SqlBatch, Token, TokenReader, TokenWriter, TypeInfo, Value,
//!     Version,
//! };
//!
//! // The agent's client opens with PRELOGIN. The world reads it.
//! let version = Version { major: 16, minor: 0, build: 1000, sub_build: 0 };
//! let hello = Prelogin::new(version, encryption::NOT_SUP);
//! let mut decoder = Decoder::new();
//! let packets = Message::new(packet_type::PRELOGIN, hello.to_bytes()).to_packets(4096).unwrap();
//! assert_eq!(decoder.feed(&packets), packets.len());
//! let message = decoder.next_message().unwrap().unwrap();
//! assert_eq!(message.packet_type, packet_type::PRELOGIN);
//! assert_eq!(Prelogin::parse(&message.data).unwrap().encryption(), Some(encryption::NOT_SUP));
//!
//! // Then it logs in. The password arrives obfuscated and is read back.
//! let mut login = Login7::new();
//! login.user_name = "sa".to_string();
//! login.password = "hunter2".to_string();
//! let packets = Message::new(packet_type::LOGIN7, login.to_bytes().unwrap()).to_packets(4096).unwrap();
//! assert_eq!(decoder.feed(&packets), packets.len());
//! let message = decoder.next_message().unwrap().unwrap();
//! let read = Login7::parse(&message.data).unwrap();
//! assert_eq!((read.user_name.as_str(), read.password.as_str()), ("sa", "hunter2"));
//!
//! // The world accepts the login.
//! let mut reply = TokenWriter::new();
//! let ack = LoginAck {
//!     interface: 1,
//!     tds_version: tds_version::V7_4,
//!     prog_name: "Microsoft SQL Server".to_string(),
//!     prog_version: [16, 0, 0x03, 0xe8],
//! };
//! reply.push(&Token::LoginAck(ack)).unwrap();
//! reply.push(&Token::Done(Done::new(0, 0))).unwrap();
//! let _bytes = Message::new(packet_type::TABULAR_RESULT, reply.into_bytes()).to_packets(4096).unwrap();
//!
//! // A query, and its answer: one column, one row, and a row count.
//! let batch = SqlBatch::new("SELECT name FROM users").to_bytes();
//! let packets = Message::new(packet_type::SQL_BATCH, batch).to_packets(4096).unwrap();
//! assert_eq!(decoder.feed(&packets), packets.len());
//! let message = decoder.next_message().unwrap().unwrap();
//! assert_eq!(SqlBatch::parse(&message.data, true).unwrap().text, "SELECT name FROM users");
//! let mut reply = TokenWriter::new();
//! let name = Column::new("name", TypeInfo::string(data_type::NVARCHAR, 100));
//! reply.push(&Token::ColMetadata(Some(vec![name]))).unwrap();
//! reply.push(&Token::Row(vec![Value::Text("alice".to_string())])).unwrap();
//! reply.push(&Token::Done(Done::new(done_status::COUNT, 1))).unwrap();
//! let bytes = reply.into_bytes();
//!
//! // A client reads the tokens back.
//! let tokens: Vec<Token> = TokenReader::new(&bytes).collect::<Result<_, _>>().unwrap();
//! assert_eq!(tokens[1], Token::Row(vec![Value::Text("alice".to_string())]));
//! assert_eq!(tokens[2], Token::Done(Done::new(done_status::COUNT, 1)));
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port SQL Server listens on.
pub const PORT: u16 = 1433;
/// The length of a packet header.
pub const HEADER_LEN: usize = 8;
/// The longest packet the header's 16-bit length can describe.
pub const MAX_PACKET: usize = 65535;
/// The smallest packet size a client and server may agree on.
pub const MIN_PACKET_SIZE: usize = 512;
/// The largest packet size a client and server may agree on.
pub const MAX_PACKET_SIZE: usize = 32767;
/// The longest message a [`Decoder`] puts back together, the most data
/// [`Message::to_packets`] writes, and the most bytes a [`TokenWriter`]
/// holds.
pub const MAX_MESSAGE: usize = 4 << 20;
/// The most options a PRELOGIN message may carry.
pub const MAX_PRELOGIN_OPTIONS: usize = 32;
/// The length of the fixed part of a LOGIN7 record, before its strings.
pub const LOGIN7_FIXED_LEN: usize = 94;
/// The longest LOGIN7 record the specification allows: 128K - 1 bytes.
pub const MAX_LOGIN7: usize = (128 << 10) - 1;
/// The most bytes the specification allows in a LOGIN7 extension block.
pub const MAX_LOGIN7_EXTENSION: usize = 255;
/// The most UTF-16 code units in the database name of an enhanced
/// routing ENVCHANGE.
pub const MAX_ROUTING_DATABASE: usize = 128;
/// The most UTF-16 code units in a LOGIN7 name, such as the user name or
/// the password.
pub const MAX_LOGIN_NAME: usize = 128;
/// The most UTF-16 code units in a LOGIN7 file name to attach.
pub const MAX_ATTACH_DB_FILE: usize = 260;
/// The most bytes of SSPI data a LOGIN7 record may carry here.
pub const MAX_SSPI: usize = 65534;
/// The most feature options in a LOGIN7 record or a FEATUREEXTACK token.
pub const MAX_FEATURES: usize = 32;
/// The most headers in a SQL batch's ALL_HEADERS block.
pub const MAX_HEADERS: usize = 16;
/// The most columns a COLMETADATA token may describe. SQL Server allows
/// 4096 in a SELECT.
pub const MAX_COLUMNS: usize = 4096;
/// The collation SQL Server sends by default: Latin1_General_CI_AS
/// (US English, case insensitive, accent sensitive).
pub const DEFAULT_COLLATION: [u8; 5] = [0x09, 0x04, 0xd0, 0x00, 0x34];

/// Packet types: what kind of message a packet belongs to.
pub mod packet_type {
    #![allow(missing_docs)]
    pub const SQL_BATCH: u8 = 0x01;
    pub const PRE_TDS7_LOGIN: u8 = 0x02;
    pub const RPC: u8 = 0x03;
    pub const TABULAR_RESULT: u8 = 0x04;
    pub const ATTENTION: u8 = 0x06;
    pub const BULK_LOAD: u8 = 0x07;
    pub const FEDAUTH_TOKEN: u8 = 0x08;
    pub const TRANSACTION_MANAGER: u8 = 0x0e;
    pub const LOGIN7: u8 = 0x10;
    pub const SSPI: u8 = 0x11;
    pub const PRELOGIN: u8 = 0x12;
}

/// Bits of a packet header's status.
pub mod status {
    /// The last packet of a message.
    pub const EOM: u8 = 0x01;
    /// The client gave up on this message; the server drops it.
    pub const IGNORE: u8 = 0x02;
    /// Reset the connection before running this request.
    pub const RESET_CONNECTION: u8 = 0x08;
    /// Reset the connection, keeping the transaction.
    pub const RESET_CONNECTION_SKIP_TRAN: u8 = 0x10;
}

/// PRELOGIN option tokens.
pub mod prelogin_option {
    #![allow(missing_docs)]
    pub const VERSION: u8 = 0x00;
    pub const ENCRYPTION: u8 = 0x01;
    pub const INSTOPT: u8 = 0x02;
    pub const THREADID: u8 = 0x03;
    pub const MARS: u8 = 0x04;
    pub const TRACEID: u8 = 0x05;
    pub const FEDAUTHREQUIRED: u8 = 0x06;
    pub const NONCEOPT: u8 = 0x07;
    /// Ends the option table. It is never an option of its own.
    pub const TERMINATOR: u8 = 0xff;
}

/// Values of the PRELOGIN ENCRYPTION option.
pub mod encryption {
    /// Encryption is available but off.
    pub const OFF: u8 = 0x00;
    /// Encryption is available and on.
    pub const ON: u8 = 0x01;
    /// Encryption is not available.
    pub const NOT_SUP: u8 = 0x02;
    /// Encryption is required.
    pub const REQ: u8 = 0x03;
    /// Added to the others: the client authenticates with a certificate.
    pub const CLIENT_CERT: u8 = 0x80;
}

/// TDS versions as a LOGIN7 record and a LOGINACK token carry them.
pub mod tds_version {
    #![allow(missing_docs)]
    pub const V7_0: u32 = 0x7000_0000;
    pub const V7_1: u32 = 0x7100_0001;
    pub const V7_2: u32 = 0x7209_0002;
    pub const V7_3A: u32 = 0x730a_0003;
    pub const V7_3B: u32 = 0x730b_0003;
    pub const V7_4: u32 = 0x7400_0004;
    pub const V8_0: u32 = 0x0800_0000;
}

/// Bits of a LOGIN7 record's third option byte.
pub mod option_flags3 {
    /// The login also changes the password.
    pub const CHANGE_PASSWORD: u8 = 0x01;
    /// The client reads XML in binary form.
    pub const BINARY_XML: u8 = 0x02;
    /// Start a user instance.
    pub const USER_INSTANCE: u8 = 0x04;
    /// The client copes with collations it does not know.
    pub const UNKNOWN_COLLATION_HANDLING: u8 = 0x08;
    /// The record has a feature extension block.
    pub const EXTENSION: u8 = 0x10;
}

/// Header types in a SQL batch's ALL_HEADERS block.
pub mod header_type {
    #![allow(missing_docs)]
    pub const QUERY_NOTIFICATIONS: u16 = 0x0001;
    pub const TRANSACTION_DESCRIPTOR: u16 = 0x0002;
    pub const TRACE_ACTIVITY: u16 = 0x0003;
}

/// Token types in a server's response.
pub mod token {
    #![allow(missing_docs)]
    pub const OFFSET: u8 = 0x78;
    pub const RETURNSTATUS: u8 = 0x79;
    pub const COLMETADATA: u8 = 0x81;
    pub const TABNAME: u8 = 0xa4;
    pub const COLINFO: u8 = 0xa5;
    pub const ORDER: u8 = 0xa9;
    pub const ERROR: u8 = 0xaa;
    pub const INFO: u8 = 0xab;
    pub const RETURNVALUE: u8 = 0xac;
    pub const LOGINACK: u8 = 0xad;
    pub const FEATUREEXTACK: u8 = 0xae;
    pub const ROW: u8 = 0xd1;
    pub const NBCROW: u8 = 0xd2;
    pub const SESSIONSTATE: u8 = 0xe4;
    pub const ENVCHANGE: u8 = 0xe3;
    pub const SSPI: u8 = 0xed;
    pub const FEDAUTHINFO: u8 = 0xee;
    pub const DONE: u8 = 0xfd;
    pub const DONEPROC: u8 = 0xfe;
    pub const DONEINPROC: u8 = 0xff;
}

/// ENVCHANGE types.
pub mod env_type {
    #![allow(missing_docs)]
    pub const DATABASE: u8 = 1;
    pub const LANGUAGE: u8 = 2;
    pub const CHARSET: u8 = 3;
    pub const PACKET_SIZE: u8 = 4;
    pub const SORT_LOCALE_ID: u8 = 5;
    pub const SORT_FLAGS: u8 = 6;
    pub const COLLATION: u8 = 7;
    pub const BEGIN_TRANSACTION: u8 = 8;
    pub const COMMIT_TRANSACTION: u8 = 9;
    pub const ROLLBACK_TRANSACTION: u8 = 10;
    pub const ENLIST_DTC: u8 = 11;
    pub const DEFECT_TRANSACTION: u8 = 12;
    pub const MIRROR_PARTNER: u8 = 13;
    pub const PROMOTE_TRANSACTION: u8 = 15;
    pub const TRANSACTION_MANAGER_ADDRESS: u8 = 16;
    pub const TRANSACTION_ENDED: u8 = 17;
    pub const RESET_ACK: u8 = 18;
    pub const USER_INSTANCE: u8 = 19;
    pub const ROUTING: u8 = 20;
    pub const ENHANCED_ROUTING: u8 = 21;
}

/// Bits of a DONE token's status.
pub mod done_status {
    /// More results follow.
    pub const MORE: u16 = 0x0001;
    /// The statement failed.
    pub const ERROR: u16 = 0x0002;
    /// A transaction is in progress.
    pub const INXACT: u16 = 0x0004;
    /// The row count is valid.
    pub const COUNT: u16 = 0x0010;
    /// The server acknowledges an attention.
    pub const ATTN: u16 = 0x0020;
    /// The server hit an error that ends the request.
    pub const SRVERROR: u16 = 0x0100;
}

/// Data type codes this module reads in COLMETADATA and ROW tokens.
pub mod data_type {
    #![allow(missing_docs)]
    // Fixed length.
    /// The NULL type. A column of this type is refused: it would take no
    /// bytes in a row.
    pub const NULL: u8 = 0x1f;
    pub const INT1: u8 = 0x30;
    pub const BIT: u8 = 0x32;
    pub const INT2: u8 = 0x34;
    pub const INT4: u8 = 0x38;
    pub const DATETIM4: u8 = 0x3a;
    pub const FLT4: u8 = 0x3b;
    pub const MONEY: u8 = 0x3c;
    pub const DATETIME: u8 = 0x3d;
    pub const FLT8: u8 = 0x3e;
    pub const MONEY4: u8 = 0x7a;
    pub const INT8: u8 = 0x7f;
    // A one-byte length.
    pub const GUID: u8 = 0x24;
    pub const INTN: u8 = 0x26;
    pub const BITN: u8 = 0x68;
    pub const DECIMALN: u8 = 0x6a;
    pub const NUMERICN: u8 = 0x6c;
    pub const FLTN: u8 = 0x6d;
    pub const MONEYN: u8 = 0x6e;
    pub const DATETIMN: u8 = 0x6f;
    pub const DATEN: u8 = 0x28;
    pub const TIMEN: u8 = 0x29;
    pub const DATETIME2N: u8 = 0x2a;
    pub const DATETIMEOFFSETN: u8 = 0x2b;
    // A two-byte length, or partly length-prefixed when the column's
    // maximum length is 0xFFFF.
    pub const BIGVARBINARY: u8 = 0xa5;
    pub const BIGVARCHAR: u8 = 0xa7;
    pub const BIGBINARY: u8 = 0xad;
    pub const BIGCHAR: u8 = 0xaf;
    pub const NVARCHAR: u8 = 0xe7;
    pub const NCHAR: u8 = 0xef;
    // A four-byte length.
    pub const SSVARIANT: u8 = 0x62;
}

// ---------------------------------------------------------------------
// Packets and messages.
// ---------------------------------------------------------------------

/// One packet: its header's fields and the data it carries. The length is
/// worked out from the data, so it is not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The kind of message the packet belongs to, from [`packet_type`].
    pub packet_type: u8,
    /// Bits from [`status`].
    pub status: u8,
    /// The server's process ID for the connection. Clients send 0.
    pub spid: u16,
    /// A packet number that counts up by 1 and wraps. Readers ignore it.
    pub id: u8,
    /// Unused; always 0.
    pub window: u8,
    /// The packet's part of the message.
    pub data: Vec<u8>,
}

/// Why bytes are not a TDS packet stream. Either way, the connection
/// holds no more messages a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The length field was below the header's 8 bytes.
    Length(u16),
    /// A packet's type differs from the earlier packets of its message.
    TypeChanged {
        /// The type of the message's first packet.
        expected: u8,
        /// The type of this packet.
        got: u8,
    },
    /// A message or packet would exceed its size limit.
    ///
    /// From [`Decoder`], the value is the assembled data length, including
    /// the packet that broke the limit. From [`Message::to_packets`], it is
    /// the message's data length. From [`Frames`], [`Packet::parse_limited`]
    /// or [`Packet`]'s [`Wire::write`], it is one packet's total length,
    /// including the header. Message lengths exclude packet headers.
    TooLong(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Length(n) => write!(f, "packet length {n}, below the 8-byte header"),
            FrameError::TypeChanged { expected, got } => {
                write!(
                    f,
                    "packet type {got:#04x} in the middle of a {expected:#04x} message"
                )
            }
            FrameError::TooLong(n) => write!(f, "message of {n} bytes, over the limit"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why an exact [`Wire`] parse did not read one complete packet.
/// [`Packet::parse`] keeps its separate prefix parsing behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketParseError {
    /// The packet header is invalid.
    Frame(FrameError),
    /// The input ended before a complete packet, including empty input.
    Truncated,
    /// Bytes follow the first complete packet.
    Trailing,
}

impl core::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("input ended before a complete TDS packet"),
            Self::Trailing => f.write_str("bytes follow the TDS packet"),
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
    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, FrameError> {
        if b.len() < 4 {
            return Ok(None);
        }
        let length = be16(b, 2);
        if usize::from(length) < HEADER_LEN {
            return Err(FrameError::Length(length));
        }
        let end = usize::from(length);
        if b.len() < end {
            return Ok(None);
        }
        let packet = Packet {
            packet_type: b[0],
            status: b[1],
            spid: be16(b, 4),
            id: b[6],
            window: b[7],
            data: b[HEADER_LEN..end].to_vec(),
        };
        Ok(Some((packet, end)))
    }

    /// Reads one packet prefix with at most `limit` bytes, header included.
    /// Clamps the limit to [`HEADER_LEN`] through [`MAX_PACKET`]. Refuses
    /// larger packets with [`FrameError::TooLong`] and their total length
    /// as soon as the first four header bytes arrive.
    pub fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, FrameError> {
        if let Some(&[_, _, hi, lo]) = b.get(..4) {
            let length = usize::from(u16::from_be_bytes([hi, lo]));
            if length > limit.clamp(HEADER_LEN, MAX_PACKET) {
                return Err(FrameError::TooLong(length));
            }
        }
        Packet::parse(b)
    }

    /// The packet's bytes: the header, then the data. Data longer than a
    /// packet can hold is cut to fit.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data = &self.data[..self.data.len().min(MAX_PACKET - HEADER_LEN)];
        let mut out = Vec::with_capacity(HEADER_LEN + data.len());
        out.push(self.packet_type);
        out.push(self.status);
        out.extend_from_slice(&((HEADER_LEN + data.len()) as u16).to_be_bytes());
        out.extend_from_slice(&self.spid.to_be_bytes());
        out.push(self.id);
        out.push(self.window);
        out.extend_from_slice(data);
        out
    }
}

impl Wire for Packet {
    type ParseError = PacketParseError;
    type WriteError = FrameError;

    /// Reads exactly one packet. Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, PacketParseError> {
        match Packet::parse(b).map_err(PacketParseError::Frame)? {
            Some((packet, used)) if used == b.len() => Ok(packet),
            Some(_) => Err(PacketParseError::Trailing),
            None => Err(PacketParseError::Truncated),
        }
    }

    /// Appends at most [`MAX_PACKET`] bytes. Refuses oversized data with
    /// [`FrameError::TooLong`] and the total packet length. Leaves `out`
    /// unchanged on error. All header fields are preserved.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let length = HEADER_LEN.saturating_add(self.data.len());
        if length > MAX_PACKET {
            return Err(FrameError::TooLong(length));
        }
        let length = u16::try_from(length).map_err(|_| FrameError::TooLong(length))?;
        out.extend_from_slice(&[self.packet_type, self.status]);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.spid.to_be_bytes());
        out.extend_from_slice(&[self.id, self.window]);
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Reads individual TDS packets without holding input bytes.
///
/// Use with [`codec::Stream`](super::codec::Stream) for a buffer bounded
/// by [`limit`](Self::limit), including the header. Oversized packets are
/// refused from the first four bytes. Partial packets return [`Step::Need`],
/// including at EOF, so the stream reports truncation. Message assembly
/// and status handling remain in [`Decoder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Reads packets up to [`MAX_PACKET`] bytes, header included.
    pub fn new() -> Self {
        Self::with_limit(MAX_PACKET)
    }

    /// Sets the packet limit, including the header. Clamps it to
    /// [`HEADER_LEN`] through [`MAX_PACKET`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(HEADER_LEN, MAX_PACKET) }
    }

    /// The maximum packet size, including its header.
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
    type Error = FrameError;
    const NAME: &'static str = "TDS";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, FrameError> {
        Ok(match Packet::parse_limited(input, self.limit)? {
            Some((packet, used)) => Step::Item(packet, used),
            None => Step::Need,
        })
    }
}

/// One whole message: the data of all its packets, joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The kind of message, from [`packet_type`].
    pub packet_type: u8,
    /// The message's status bits. A message read by a [`Decoder`] always
    /// has [`status::EOM`]. It has [`status::IGNORE`] only when its last
    /// packet has it, and then the client cancelled it and it is to be
    /// dropped. It has [`status::RESET_CONNECTION`] and
    /// [`status::RESET_CONNECTION_SKIP_TRAN`] only as its first packet
    /// has them, since the specification ignores them in later packets.
    /// Any other bits are those of all its packets, or'd together.
    pub status: u8,
    /// The SPID of its first packet.
    pub spid: u16,
    /// The message itself.
    pub data: Vec<u8>,
}

impl Message {
    /// A message of type `packet_type` holding `data`, with SPID 0 and the
    /// end-of-message bit.
    pub fn new(packet_type: u8, data: Vec<u8>) -> Message {
        Message {
            packet_type,
            status: status::EOM,
            spid: 0,
            data,
        }
    }

    /// The message's bytes, split into packets of at most `packet_size`
    /// bytes each. The size is held between [`MIN_PACKET_SIZE`] and
    /// [`MAX_PACKET_SIZE`]. Only the last packet carries [`status::EOM`]
    /// and [`status::IGNORE`], since IGNORE needs EOM with it. Only the
    /// first carries the reset bits, as the specification asks. Every
    /// packet carries the other status bits. Packet IDs count up from 1.
    /// Data longer than [`MAX_MESSAGE`] gives [`FrameError::TooLong`] and
    /// no bytes, so a message is never cut short.
    pub fn to_packets(&self, packet_size: usize) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_MESSAGE {
            return Err(FrameError::TooLong(self.data.len()));
        }
        let size = packet_size.clamp(MIN_PACKET_SIZE, MAX_PACKET_SIZE);
        let chunk = size - HEADER_LEN;
        let data = &self.data[..];
        let count = data.len().div_ceil(chunk).max(1);
        let last_only = status::EOM | status::IGNORE;
        let first_only = status::RESET_CONNECTION | status::RESET_CONNECTION_SKIP_TRAN;
        let mut out = Vec::with_capacity(data.len() + count * HEADER_LEN);
        let mut id: u8 = 1;
        for i in 0..count {
            let part = data
                .get(i * chunk..data.len().min((i + 1) * chunk))
                .unwrap_or(&[]);
            let mut s = self.status & !(last_only | first_only);
            if i == 0 {
                s |= self.status & first_only;
            }
            if i + 1 == count {
                s |= (self.status & status::IGNORE) | status::EOM;
            }
            out.push(self.packet_type);
            out.push(s);
            out.extend_from_slice(&((HEADER_LEN + part.len()) as u16).to_be_bytes());
            out.extend_from_slice(&self.spid.to_be_bytes());
            out.push(id);
            out.push(0);
            out.extend_from_slice(part);
            id = id.wrapping_add(1);
        }
        Ok(out)
    }
}

/// Splits a TDS byte stream into messages, joining the packets of each.
/// Feed it the bytes a connection reads, in order, and take messages out
/// until it has none.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet read start. Bytes before it are dropped in
    /// `feed` once they are half the buffer.
    start: usize,
    /// The message being joined, once its first packet has come.
    partial: Option<Message>,
    limit: usize,
    failed: Option<FrameError>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, for messages of up to [`MAX_MESSAGE`]
    /// bytes.
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_MESSAGE)
    }

    /// A decoder for messages of up to `limit` bytes. The limit is held at
    /// or below [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder {
            buf: Vec::new(),
            start: 0,
            partial: None,
            limit: limit.min(MAX_MESSAGE),
            failed: None,
        }
    }

    /// The most bytes not yet read into a message that a decoder holds:
    /// its limit and one packet more. That is always room for a whole
    /// packet, so taking messages out makes room again.
    fn raw_cap(&self) -> usize {
        self.limit + MAX_PACKET
    }

    /// Adds bytes read from the connection, as many as fit, and returns
    /// how many it took. It holds at most its limit plus [`MAX_PACKET`]
    /// bytes not yet read into a message, so a caller that gets back less
    /// than it gave takes messages out with [`Decoder::next_message`] and
    /// feeds the rest again. After a [`FrameError`] the stream cannot be
    /// read any further: every byte is taken and dropped.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        let cap = self.raw_cap();
        let pending = self.buf.len() - self.start;
        let take = bytes.len().min(cap.saturating_sub(pending));
        if self.start > 0 && (self.start >= self.buf.len() / 2 || self.buf.len() + take > cap) {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(&bytes[..take]);
        take
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder holds at most its limit in the data
    /// of a message not yet whole, and its limit plus [`MAX_PACKET`] in
    /// bytes not yet read into a message.
    pub fn next_message(&mut self) -> Option<Result<Message, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        loop {
            let rest = &self.buf[self.start..];
            // Check what the header says before the rest of the packet
            // comes, so an oversized message is refused early.
            if rest.len() >= 4 {
                let length = be16(rest, 2);
                if usize::from(length) >= HEADER_LEN {
                    if let Some(p) = &self.partial
                        && rest[0] != p.packet_type
                    {
                        return Some(Err(self.fail(FrameError::TypeChanged {
                            expected: p.packet_type,
                            got: rest[0],
                        })));
                    }
                    let have = self.partial.as_ref().map_or(0, |p| p.data.len());
                    let total = have.saturating_add(usize::from(length) - HEADER_LEN);
                    if total > self.limit {
                        return Some(Err(self.fail(FrameError::TooLong(total))));
                    }
                }
            }
            let (packet, used) = match Packet::parse(rest) {
                Ok(Some(p)) => p,
                Ok(None) => return None,
                Err(e) => return Some(Err(self.fail(e))),
            };
            self.start += used;
            let resets = status::RESET_CONNECTION | status::RESET_CONNECTION_SKIP_TRAN;
            let message = self.partial.get_or_insert_with(|| Message {
                packet_type: packet.packet_type,
                // The reset bits count only in the first packet.
                status: packet.status & resets,
                spid: packet.spid,
                data: Vec::new(),
            });
            // IGNORE counts only with EOM, in the last packet.
            let last = packet.status & status::EOM != 0;
            let mut bits = packet.status & !(resets | status::IGNORE);
            if last {
                bits |= packet.status & status::IGNORE;
            }
            message.status |= bits;
            message.data.extend_from_slice(&packet.data);
            if packet.status & status::EOM != 0 {
                return self.partial.take().map(Ok);
            }
        }
    }

    /// How many bytes are held: the data of a message not yet whole, and
    /// the bytes of a packet not yet whole.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start + self.partial.as_ref().map_or(0, |p| p.data.len())
    }

    fn fail(&mut self, e: FrameError) -> FrameError {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        self.partial = None;
        e
    }
}

// ---------------------------------------------------------------------
// Errors in message contents.
// ---------------------------------------------------------------------

/// Why a message's data is not what it should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The data ended in the middle of a field.
    Truncated,
    /// A field breaks the specification. The text says which.
    Invalid(&'static str),
    /// Something is longer or more numerous than this module's limits
    /// allow. The text says what.
    Limit(&'static str),
    /// A response token this module cannot find the end of.
    UnknownToken(u8),
    /// A column of a data type this module does not read.
    UnsupportedType(u8),
    /// A ROW or NBCROW token came before any COLMETADATA token.
    NoColumns,
    /// A writer cannot write the value so that it reads back the same: a
    /// value does not match its column, a string is too long, or a field
    /// breaks a rule the reader checks. Nothing is written.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "data ends in the middle of a field"),
            Error::Invalid(what) => write!(f, "invalid {what}"),
            Error::Limit(what) => write!(f, "too long or too many: {what}"),
            Error::UnknownToken(t) => write!(f, "unknown token {t:#04x}"),
            Error::UnsupportedType(t) => write!(f, "unsupported data type {t:#04x}"),
            Error::NoColumns => write!(f, "row before any column metadata"),
            Error::Unwritable => write!(f, "token cannot be written as given"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------
// PRELOGIN.
// ---------------------------------------------------------------------

/// A version as the PRELOGIN VERSION option carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Version {
    /// The major version, such as 16 for SQL Server 2022.
    pub major: u8,
    /// The minor version.
    pub minor: u8,
    /// The build number.
    pub build: u16,
    /// The sub-build number. Clients send 0.
    pub sub_build: u16,
}

impl Version {
    /// The option's 6 bytes.
    pub fn to_bytes(self) -> [u8; 6] {
        let [b0, b1] = self.build.to_be_bytes();
        let [s0, s1] = self.sub_build.to_be_bytes();
        [self.major, self.minor, b0, b1, s0, s1]
    }
}

/// One PRELOGIN option: its token and its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreloginOption {
    /// Which option, from [`prelogin_option`]. Never
    /// [`prelogin_option::TERMINATOR`] in an option read.
    pub token: u8,
    /// The option's data.
    pub data: Vec<u8>,
}

/// A PRELOGIN message: the options a client and server exchange before
/// the login. After an exchange that turns on encryption, PRELOGIN
/// packets carry TLS handshake bytes instead; those are not read here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Prelogin {
    /// The options, in the order of the option table.
    pub options: Vec<PreloginOption>,
}

impl Prelogin {
    /// A PRELOGIN message with the VERSION and ENCRYPTION options.
    pub fn new(version: Version, encryption: u8) -> Prelogin {
        let mut p = Prelogin::default();
        p.set(prelogin_option::VERSION, version.to_bytes().to_vec());
        p.set(prelogin_option::ENCRYPTION, vec![encryption]);
        p
    }

    /// Reads a PRELOGIN message's data. The first option must be VERSION,
    /// with 6 bytes of data. Each option's data must lie within the
    /// message, and all of it laid end to end after the table must fit in
    /// 65535 bytes, as a writer lays it out. The other options the
    /// specification defines must have the length and values it gives
    /// them (see [`Prelogin::option_valid`]).
    pub fn parse(data: &[u8]) -> Result<Prelogin, Error> {
        let mut options = Vec::new();
        let mut i = 0usize;
        let mut total = 1usize;
        loop {
            let token = *data.get(i).ok_or(Error::Truncated)?;
            if token == prelogin_option::TERMINATOR {
                break;
            }
            if options.len() == MAX_PRELOGIN_OPTIONS {
                return Err(Error::Limit("PRELOGIN options"));
            }
            let entry = data.get(i..i + 5).ok_or(Error::Truncated)?;
            let offset = usize::from(be16(entry, 1));
            let len = usize::from(be16(entry, 3));
            let bytes = data
                .get(offset..offset + len)
                .ok_or(Error::Invalid("PRELOGIN option outside the message"))?;
            total += 5 + len;
            if total > 0xffff {
                return Err(Error::Limit("PRELOGIN option data"));
            }
            options.push(PreloginOption {
                token,
                data: bytes.to_vec(),
            });
            i += 5;
        }
        match options.first() {
            Some(o) if o.token == prelogin_option::VERSION => {
                if o.data.len() != 6 {
                    return Err(Error::Invalid("PRELOGIN VERSION length"));
                }
            }
            _ => return Err(Error::Invalid("PRELOGIN VERSION not first")),
        }
        if !options.iter().all(Prelogin::option_valid) {
            return Err(Error::Invalid("PRELOGIN option length or value"));
        }
        Ok(Prelogin { options })
    }

    /// Whether an option's data has the length and values MS-TDS 2.2.6.5
    /// gives it: VERSION 6 bytes; ENCRYPTION one byte of 0 to 3, with
    /// the 0x20 and 0x80 bits allowed on top; INSTOPT at least one byte;
    /// THREADID 4 bytes, or none, as a server sends it; MARS and
    /// FEDAUTHREQUIRED one byte of 0 or 1; TRACEID 36 bytes; NONCEOPT 32
    /// bytes. Options the specification does not define may hold anything.
    /// The terminator is never valid as an option.
    pub fn option_valid(o: &PreloginOption) -> bool {
        use prelogin_option::*;
        let d = &o.data[..];
        match o.token {
            VERSION => d.len() == 6,
            ENCRYPTION => {
                matches!(d, [v] if v & !(0x20 | encryption::CLIENT_CERT) <= encryption::REQ)
            }
            INSTOPT => !d.is_empty(),
            THREADID => d.is_empty() || d.len() == 4,
            MARS | FEDAUTHREQUIRED => matches!(d, [0 | 1]),
            TRACEID => d.len() == 36,
            NONCEOPT => d.len() == 32,
            TERMINATOR => false,
            _ => true,
        }
    }

    /// The message's data: the option table, the terminator, then each
    /// option's data in order. The first VERSION option goes first, its
    /// data cut or padded with zeros to 6 bytes; without one, a VERSION of
    /// all zeros is added. Options past [`MAX_PRELOGIN_OPTIONS`], options
    /// that [`Prelogin::option_valid`] refuses (a terminator token among
    /// them), and options whose data would push an offset past 65535 are
    /// left out, so what it writes always reads.
    pub fn to_bytes(&self) -> Vec<u8> {
        let first = self
            .options
            .iter()
            .position(|o| o.token == prelogin_option::VERSION);
        let given = first.map_or(&[][..], |i| &self.options[i].data[..]);
        let mut version = given[..given.len().min(6)].to_vec();
        version.resize(6, 0);
        let version = PreloginOption {
            token: prelogin_option::VERSION,
            data: version,
        };
        let mut kept: Vec<&PreloginOption> = vec![&version];
        let mut sum = version.data.len();
        let rest = self
            .options
            .iter()
            .enumerate()
            .filter(|&(i, _)| Some(i) != first)
            .map(|(_, o)| o);
        for o in rest {
            if kept.len() == MAX_PRELOGIN_OPTIONS {
                break;
            }
            if !Prelogin::option_valid(o) {
                continue;
            }
            if 5 * (kept.len() + 1) + 1 + sum + o.data.len() > 0xffff {
                continue;
            }
            sum += o.data.len();
            kept.push(o);
        }
        let mut out = Vec::with_capacity(5 * kept.len() + 1 + sum);
        let mut offset = 5 * kept.len() + 1;
        for o in &kept {
            out.push(o.token);
            out.extend_from_slice(&(offset as u16).to_be_bytes());
            out.extend_from_slice(&(o.data.len() as u16).to_be_bytes());
            offset += o.data.len();
        }
        out.push(prelogin_option::TERMINATOR);
        for o in &kept {
            out.extend_from_slice(&o.data);
        }
        out
    }

    /// The data of the first option with `token`.
    pub fn get(&self, token: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.token == token)
            .map(|o| &o.data[..])
    }

    /// Sets the option with `token` to `data`, adding it at the end if it
    /// is not there.
    pub fn set(&mut self, token: u8, data: Vec<u8>) {
        match self.options.iter_mut().find(|o| o.token == token) {
            Some(o) => o.data = data,
            None => self.options.push(PreloginOption { token, data }),
        }
    }

    /// The VERSION option, if it is there and 6 bytes long.
    pub fn version(&self) -> Option<Version> {
        let b = self.get(prelogin_option::VERSION)?;
        if b.len() != 6 {
            return None;
        }
        Some(Version {
            major: b[0],
            minor: b[1],
            build: be16(b, 2),
            sub_build: be16(b, 4),
        })
    }

    /// The ENCRYPTION option's value, from [`encryption`].
    pub fn encryption(&self) -> Option<u8> {
        match self.get(prelogin_option::ENCRYPTION)? {
            [v] => Some(*v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// LOGIN7.
// ---------------------------------------------------------------------

/// One feature option: in a LOGIN7 record's feature extension block, or
/// in a FEATUREEXTACK token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feature {
    /// The feature's ID. Never 0xFF, which ends the list.
    pub id: u8,
    /// The feature's data.
    pub data: Vec<u8>,
}

/// A LOGIN7 record: who the client is and how it logs in. Strings are
/// read as UTF-16; units that are not valid UTF-16 become U+FFFD. The
/// password arrives obfuscated and is kept in plain text here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login7 {
    /// The highest TDS version the client speaks, from [`tds_version`].
    pub tds_version: u32,
    /// The packet size the client asks for.
    pub packet_size: u32,
    /// The version of the client library.
    pub client_prog_ver: u32,
    /// The client's process ID.
    pub client_pid: u32,
    /// The connection ID, for a client that reconnects. Usually 0.
    pub connection_id: u32,
    /// The first option byte: byte order, character set, and how the
    /// client wants warnings about the database and language.
    pub option_flags1: u8,
    /// The second option byte: the language and ODBC settings, and
    /// whether the login uses integrated security.
    pub option_flags2: u8,
    /// The type byte: the SQL dialect, and whether the session is
    /// read-only.
    pub type_flags: u8,
    /// Bits from [`option_flags3`]. A writer sets
    /// [`option_flags3::EXTENSION`] when `features` is `Some`, and clears
    /// it otherwise.
    pub option_flags3: u8,
    /// Minutes from UTC.
    pub client_time_zone: i32,
    /// The client's locale ID, such as 0x0409 for US English.
    pub client_lcid: u32,
    /// The client machine's name.
    pub host_name: String,
    /// The user to log in as. Empty for integrated security.
    pub user_name: String,
    /// The password, in plain text. It is obfuscated on the wire.
    pub password: String,
    /// The client application's name.
    pub app_name: String,
    /// The server name the client connected to.
    pub server_name: String,
    /// The client library's name, such as "ODBC".
    pub client_interface: String,
    /// The language to use. Empty for the server's default.
    pub language: String,
    /// The database to use. Empty for the user's default.
    pub database: String,
    /// Usually the client's MAC address.
    pub client_id: [u8; 6],
    /// Integrated authentication data, such as a Kerberos token.
    pub sspi: Vec<u8>,
    /// A database file to attach as the database, at most
    /// [`MAX_ATTACH_DB_FILE`] UTF-16 units.
    pub attach_db_file: String,
    /// The new password, in plain text, when the login changes it. It is
    /// obfuscated on the wire. It must be empty unless `option_flags3`
    /// has [`option_flags3::CHANGE_PASSWORD`].
    pub change_password: String,
    /// The feature extension block, from TDS 7.4. `Some` of an empty list
    /// is a block pointer of 0.
    pub features: Option<Vec<Feature>>,
}

impl Default for Login7 {
    fn default() -> Login7 {
        Login7::new()
    }
}

impl Login7 {
    /// A TDS 7.4 login asking for 4096-byte packets, with the option bits
    /// an ODBC client sends and every string empty.
    pub fn new() -> Login7 {
        Login7 {
            tds_version: tds_version::V7_4,
            packet_size: 4096,
            client_prog_ver: 0,
            client_pid: 0,
            connection_id: 0,
            option_flags1: 0xe0,
            option_flags2: 0x03,
            type_flags: 0,
            option_flags3: 0,
            client_time_zone: 0,
            client_lcid: 0x0409,
            host_name: String::new(),
            user_name: String::new(),
            password: String::new(),
            app_name: String::new(),
            server_name: String::new(),
            client_interface: String::new(),
            language: String::new(),
            database: String::new(),
            client_id: [0; 6],
            sspi: Vec::new(),
            attach_db_file: String::new(),
            change_password: String::new(),
            features: None,
        }
    }

    /// Reads a LOGIN7 message's data. It needs the 94-byte fixed part of
    /// TDS 7.2 and later, a length of at most [`MAX_LOGIN7`], a host name
    /// offset that points at the variable part, every field after the
    /// fixed part and within the record, strings within the
    /// specification's length limits, an extension block of 4 to
    /// [`MAX_LOGIN7_EXTENSION`] bytes, and SSPI data no longer than
    /// [`MAX_SSPI`]. A new password needs
    /// [`option_flags3::CHANGE_PASSWORD`]. The whole extension block must
    /// lie within the record. Fields may share bytes, but laid out one
    /// after the other, as a writer lays them out, they must still fit in
    /// [`MAX_LOGIN7`] bytes.
    pub fn parse(data: &[u8]) -> Result<Login7, Error> {
        if data.len() < LOGIN7_FIXED_LEN {
            return Err(Error::Truncated);
        }
        let length = le32(data, 0) as usize;
        if !(LOGIN7_FIXED_LEN..=MAX_LOGIN7).contains(&length) {
            return Err(Error::Invalid("LOGIN7 length"));
        }
        let b = data.get(..length).ok_or(Error::Truncated)?;
        // ibHostName marks where the variable part starts, even when the
        // host name is empty.
        let host_at = usize::from(le16(b, 36));
        if host_at < LOGIN7_FIXED_LEN || host_at > length {
            return Err(Error::Invalid("LOGIN7 host name offset"));
        }
        let field = |at: usize| (usize::from(le16(b, at)), usize::from(le16(b, at + 2)));
        let text = |at: usize, max: usize| -> Result<String, Error> {
            let (ib, cch) = field(at);
            Ok(utf16_string(login_bytes(b, ib, cch, max)?))
        };
        let option_flags3 = b[27];
        let password = {
            let (ib, cch) = field(44);
            utf16_string(&deobfuscate(login_bytes(b, ib, cch, MAX_LOGIN_NAME)?))
        };
        let change_password = {
            let (ib, cch) = field(86);
            // MS-TDS 2.2.6.4: without fChangePassword, ibChangePassword
            // MUST be 0, so there is no new password.
            if cch > 0 && option_flags3 & option_flags3::CHANGE_PASSWORD == 0 {
                return Err(Error::Invalid(
                    "LOGIN7 new password without fChangePassword",
                ));
            }
            utf16_string(&deobfuscate(login_bytes(b, ib, cch, MAX_LOGIN_NAME)?))
        };
        let sspi = {
            let (ib, cb) = field(78);
            let mut len = cb;
            if cb == 0xffff {
                let long = le32(b, 90) as usize;
                if long > 0 {
                    len = long;
                }
            }
            if len > MAX_SSPI {
                return Err(Error::Limit("LOGIN7 SSPI data"));
            }
            if len == 0 {
                Vec::new()
            } else {
                login_field(b, ib, len)?.to_vec()
            }
        };
        let features = if option_flags3 & option_flags3::EXTENSION != 0 {
            let (ib, cb) = field(56);
            if !(4..=MAX_LOGIN7_EXTENSION).contains(&cb) {
                return Err(Error::Invalid("LOGIN7 extension length"));
            }
            let pointer = login_field(b, ib, cb)?;
            let at = le32(pointer, 0) as usize;
            if at == 0 {
                Some(Vec::new())
            } else {
                if at < LOGIN7_FIXED_LEN {
                    return Err(Error::Invalid("LOGIN7 feature block outside the record"));
                }
                Some(
                    parse_features(
                        b.get(at..)
                            .ok_or(Error::Invalid("LOGIN7 feature block outside the record"))?,
                    )?
                    .0,
                )
            }
        } else {
            None
        };
        // Fields may share bytes on the wire. A writer lays them out one
        // after the other, so their lengths added up must fit too.
        let strings: usize = [36, 40, 44, 48, 52, 60, 64, 68, 82, 86]
            .iter()
            .map(|&at| 2 * field(at).1)
            .sum();
        let block = match &features {
            None => 0,
            Some(f) if f.is_empty() => 4,
            Some(f) => 4 + 1 + f.iter().map(|f| 5 + f.data.len()).sum::<usize>(),
        };
        if LOGIN7_FIXED_LEN + strings + sspi.len() + block > MAX_LOGIN7 {
            return Err(Error::Limit("LOGIN7 fields laid end to end"));
        }
        let mut client_id = [0u8; 6];
        client_id.copy_from_slice(&b[72..78]);
        Ok(Login7 {
            tds_version: le32(b, 4),
            packet_size: le32(b, 8),
            client_prog_ver: le32(b, 12),
            client_pid: le32(b, 16),
            connection_id: le32(b, 20),
            option_flags1: b[24],
            option_flags2: b[25],
            type_flags: b[26],
            option_flags3,
            client_time_zone: le32(b, 28) as i32,
            client_lcid: le32(b, 32),
            host_name: text(36, MAX_LOGIN_NAME)?,
            user_name: text(40, MAX_LOGIN_NAME)?,
            password,
            app_name: text(48, MAX_LOGIN_NAME)?,
            server_name: text(52, MAX_LOGIN_NAME)?,
            client_interface: text(60, MAX_LOGIN_NAME)?,
            language: text(64, MAX_LOGIN_NAME)?,
            database: text(68, MAX_LOGIN_NAME)?,
            client_id,
            sspi,
            attach_db_file: text(82, MAX_ATTACH_DB_FILE)?,
            change_password,
            features,
        })
    }

    /// The record's bytes, the password obfuscated. Without
    /// [`option_flags3::CHANGE_PASSWORD`], ibChangePassword is 0, as the
    /// specification asks. It gives [`Error::Unwritable`], and no bytes,
    /// for a record [`Login7::parse`] would refuse or read differently: a
    /// string past the specification's limit, SSPI data past
    /// [`MAX_SSPI`], a new password without the flag, more than
    /// [`MAX_FEATURES`] features, a feature with ID 0xFF, or a record
    /// past [`MAX_LOGIN7`] bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let change = self.option_flags3 & option_flags3::CHANGE_PASSWORD != 0;
        if !change && !self.change_password.is_empty() {
            return Err(Error::Unwritable);
        }
        if self.sspi.len() > MAX_SSPI {
            return Err(Error::Unwritable);
        }
        let mut fixed = vec![0u8; LOGIN7_FIXED_LEN];
        let mut var: Vec<u8> = Vec::new();
        let put =
            |fixed: &mut Vec<u8>, var: &mut Vec<u8>, at: usize, bytes: &[u8], count: usize| {
                let offset = LOGIN7_FIXED_LEN + var.len();
                fixed[at..at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
                fixed[at + 2..at + 4].copy_from_slice(&(count as u16).to_le_bytes());
                var.extend_from_slice(bytes);
            };
        // The strings in the order of the offset table. The extension
        // pointer goes after the server name, as clients lay it out, and is
        // filled in once the feature block's place is known.
        let names: [(usize, &str, usize, bool); 11] = [
            (36, &self.host_name, MAX_LOGIN_NAME, false),
            (40, &self.user_name, MAX_LOGIN_NAME, false),
            (44, &self.password, MAX_LOGIN_NAME, true),
            (48, &self.app_name, MAX_LOGIN_NAME, false),
            (52, &self.server_name, MAX_LOGIN_NAME, false),
            (56, "", 0, false),
            (60, &self.client_interface, MAX_LOGIN_NAME, false),
            (64, &self.language, MAX_LOGIN_NAME, false),
            (68, &self.database, MAX_LOGIN_NAME, false),
            (82, &self.attach_db_file, MAX_ATTACH_DB_FILE, false),
            (86, &self.change_password, MAX_LOGIN_NAME, true),
        ];
        let mut pointer_at = None;
        for (at, s, max, secret) in names {
            if at == 56 {
                if self.features.is_some() {
                    pointer_at = Some(var.len());
                    put(&mut fixed, &mut var, 56, &[0; 4], 4);
                } else {
                    put(&mut fixed, &mut var, 56, &[], 0);
                }
                continue;
            }
            let units: Vec<u16> = s.encode_utf16().collect();
            if units.len() > max {
                return Err(Error::Unwritable);
            }
            if at == 86 && !change {
                // ibChangePassword and cchChangePassword stay 0.
                continue;
            }
            let mut bytes = units_to_bytes(&units);
            if secret {
                obfuscate(&mut bytes);
            }
            put(&mut fixed, &mut var, at, &bytes, units.len());
        }
        // SSPI data last, so every 16-bit offset stays small.
        put(&mut fixed, &mut var, 78, &self.sspi, self.sspi.len());
        if let (Some(features), Some(p)) = (&self.features, pointer_at) {
            if features.len() > MAX_FEATURES || features.iter().any(|f| f.id == 0xff) {
                return Err(Error::Unwritable);
            }
            // The features and the 0xFF that ends them.
            let block = 1 + features.iter().map(|f| 5 + f.data.len()).sum::<usize>();
            if LOGIN7_FIXED_LEN + var.len() + block > MAX_LOGIN7 {
                return Err(Error::Unwritable);
            }
            let kept = features;
            if !kept.is_empty() {
                let at = (LOGIN7_FIXED_LEN + var.len()) as u32;
                var[p..p + 4].copy_from_slice(&at.to_le_bytes());
                for f in kept {
                    var.push(f.id);
                    var.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
                    var.extend_from_slice(&f.data);
                }
                var.push(0xff);
            }
        }
        let mut flags3 = self.option_flags3 & !option_flags3::EXTENSION;
        if self.features.is_some() {
            flags3 |= option_flags3::EXTENSION;
        }
        let total = (LOGIN7_FIXED_LEN + var.len()) as u32;
        fixed[0..4].copy_from_slice(&total.to_le_bytes());
        fixed[4..8].copy_from_slice(&self.tds_version.to_le_bytes());
        fixed[8..12].copy_from_slice(&self.packet_size.to_le_bytes());
        fixed[12..16].copy_from_slice(&self.client_prog_ver.to_le_bytes());
        fixed[16..20].copy_from_slice(&self.client_pid.to_le_bytes());
        fixed[20..24].copy_from_slice(&self.connection_id.to_le_bytes());
        fixed[24] = self.option_flags1;
        fixed[25] = self.option_flags2;
        fixed[26] = self.type_flags;
        fixed[27] = flags3;
        fixed[28..32].copy_from_slice(&self.client_time_zone.to_le_bytes());
        fixed[32..36].copy_from_slice(&self.client_lcid.to_le_bytes());
        fixed[72..78].copy_from_slice(&self.client_id);
        // cbSSPILong (bytes 90..94) stays 0: SSPI data here fits cbSSPI.
        fixed.extend_from_slice(&var);
        Ok(fixed)
    }
}

/// A string field of a LOGIN7 record: `cch` UTF-16 units at `ib`.
fn login_bytes(b: &[u8], ib: usize, cch: usize, max: usize) -> Result<&[u8], Error> {
    if cch > max {
        return Err(Error::Limit("LOGIN7 string"));
    }
    if cch == 0 {
        return Ok(&[]);
    }
    login_field(b, ib, 2 * cch)
}

/// `len` bytes at `ib` of a LOGIN7 record, which must lie after the fixed
/// part and within the record.
fn login_field(b: &[u8], ib: usize, len: usize) -> Result<&[u8], Error> {
    if ib < LOGIN7_FIXED_LEN {
        return Err(Error::Invalid("LOGIN7 field outside the record"));
    }
    b.get(ib..ib + len)
        .ok_or(Error::Invalid("LOGIN7 field outside the record"))
}

/// Obfuscates a password as a client sends it: each byte's halves are
/// swapped, then the byte is XORed with 0xA5.
pub fn obfuscate(bytes: &mut [u8]) {
    for b in bytes {
        *b = b.rotate_left(4) ^ 0xa5;
    }
}

/// Undoes [`obfuscate`]: each byte is XORed with 0xA5, then its halves
/// are swapped.
pub fn deobfuscate(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| (b ^ 0xa5).rotate_left(4)).collect()
}

/// Feature options up to the 0xFF that ends them, and how many bytes they
/// took with it.
fn parse_features(b: &[u8]) -> Result<(Vec<Feature>, usize), Error> {
    let mut c = Cur::new(b);
    let mut features = Vec::new();
    loop {
        let id = c.u8()?;
        if id == 0xff {
            return Ok((features, c.p));
        }
        if features.len() == MAX_FEATURES {
            return Err(Error::Limit("feature options"));
        }
        let len = c.u32()? as usize;
        features.push(Feature {
            id,
            data: c.take(len)?.to_vec(),
        });
    }
}

fn write_features(out: &mut Vec<u8>, features: &[Feature]) {
    for f in features {
        out.push(f.id);
        out.extend_from_slice(&(f.data.len().min(u32::MAX as usize) as u32).to_le_bytes());
        out.extend_from_slice(&f.data[..f.data.len().min(u32::MAX as usize)]);
    }
    out.push(0xff);
}

// ---------------------------------------------------------------------
// SQL batch.
// ---------------------------------------------------------------------

/// One header of a SQL batch's ALL_HEADERS block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    /// Which header, from [`header_type`].
    pub kind: u16,
    /// The header's data.
    pub data: Vec<u8>,
}

impl StreamHeader {
    /// A transaction descriptor header. Outside a transaction, clients
    /// send descriptor 0 and 1 outstanding request.
    pub fn transaction_descriptor(descriptor: u64, outstanding_requests: u32) -> StreamHeader {
        let mut data = descriptor.to_le_bytes().to_vec();
        data.extend_from_slice(&outstanding_requests.to_le_bytes());
        StreamHeader {
            kind: header_type::TRANSACTION_DESCRIPTOR,
            data,
        }
    }

    /// Whether the header's data has the layout MS-TDS 2.2.5.3 gives its
    /// type: a transaction descriptor is 12 bytes; a trace activity
    /// header is a 16-byte activity ID and a 4-byte sequence number; a
    /// query notifications header is two US_VARCHAR strings and an
    /// optional 4-byte timeout. Other types may hold anything.
    pub fn is_valid(&self) -> bool {
        match self.kind {
            header_type::TRANSACTION_DESCRIPTOR => self.data.len() == 12,
            header_type::TRACE_ACTIVITY => self.data.len() == 20,
            header_type::QUERY_NOTIFICATIONS => {
                let mut c = Cur::new(&self.data);
                let strings = (0..2).all(|_| c.us_varchar().is_ok());
                strings && matches!(self.data.len() - c.p, 0 | 4)
            }
            _ => true,
        }
    }
}

/// A SQL batch: the text of one or more statements, and, from TDS 7.2,
/// the ALL_HEADERS block before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlBatch {
    /// The ALL_HEADERS block, or `None` for a TDS 7.0 or 7.1 batch.
    pub headers: Option<Vec<StreamHeader>>,
    /// The SQL text, read as UTF-16; units that are not valid UTF-16
    /// become U+FFFD.
    pub text: String,
}

impl SqlBatch {
    /// A batch of `text` outside a transaction, as a TDS 7.2 or later
    /// client sends it.
    pub fn new(text: &str) -> SqlBatch {
        SqlBatch {
            headers: Some(vec![StreamHeader::transaction_descriptor(0, 1)]),
            text: text.to_string(),
        }
    }

    /// The transaction descriptor and the outstanding request count from
    /// the first transaction descriptor header, if there is one with 12
    /// bytes of data.
    pub fn transaction_descriptor(&self) -> Option<(u64, u32)> {
        let h = self
            .headers
            .as_ref()?
            .iter()
            .find(|h| h.kind == header_type::TRANSACTION_DESCRIPTOR)?;
        let d: &[u8; 12] = h.data.as_slice().try_into().ok()?;
        Some((
            u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]),
            u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
        ))
    }

    /// Reads a SQL batch message's data. `all_headers` says whether it
    /// starts with an ALL_HEADERS block, which it does from TDS 7.2. The
    /// block must hold a transaction descriptor, no header type twice, and
    /// only headers whose data fits their type (see
    /// [`StreamHeader::is_valid`]).
    pub fn parse(data: &[u8], all_headers: bool) -> Result<SqlBatch, Error> {
        let (headers, rest) = if all_headers {
            let mut c = Cur::new(data);
            let total = c.u32()? as usize;
            if total < 4 {
                return Err(Error::Invalid("ALL_HEADERS length"));
            }
            let block = data.get(4..total).ok_or(Error::Truncated)?;
            let mut c = Cur::new(block);
            let mut headers = Vec::new();
            while c.p < block.len() {
                if headers.len() == MAX_HEADERS {
                    return Err(Error::Limit("ALL_HEADERS headers"));
                }
                let len = c.u32()? as usize;
                if len < 6 {
                    return Err(Error::Invalid("header length"));
                }
                let kind = c.u16()?;
                if headers.iter().any(|h: &StreamHeader| h.kind == kind) {
                    return Err(Error::Invalid("header type repeated"));
                }
                let data = c.take(len - 6)?.to_vec();
                if kind == header_type::TRANSACTION_DESCRIPTOR && data.len() != 12 {
                    return Err(Error::Invalid("transaction descriptor length"));
                }
                let header = StreamHeader { kind, data };
                if !header.is_valid() {
                    return Err(Error::Invalid("header data"));
                }
                headers.push(header);
            }
            if !headers
                .iter()
                .any(|h| h.kind == header_type::TRANSACTION_DESCRIPTOR)
            {
                return Err(Error::Invalid(
                    "ALL_HEADERS without a transaction descriptor",
                ));
            }
            (Some(headers), &data[total..])
        } else {
            (None, data)
        };
        if rest.len() % 2 != 0 {
            return Err(Error::Invalid("UTF-16 text of odd length"));
        }
        Ok(SqlBatch {
            headers,
            text: utf16_string(rest),
        })
    }

    /// The message's data. Only the first header of each type is written.
    /// A transaction descriptor is always written: the first one given,
    /// its data cut or padded with zeros to 12 bytes, or else descriptor
    /// 0 with 1 outstanding request, in front. Other headers whose data
    /// does not fit their type, and headers past [`MAX_HEADERS`] in all,
    /// are left out.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(given) = &self.headers {
            let mut headers: Vec<StreamHeader> = Vec::new();
            let mut descriptor: Option<(usize, StreamHeader)> = None;
            for h in given {
                if h.kind == header_type::TRANSACTION_DESCRIPTOR {
                    if descriptor.is_none() {
                        let mut d = h.clone();
                        d.data.resize(12, 0);
                        descriptor = Some((headers.len(), d));
                    }
                } else if headers.len() < MAX_HEADERS - 1
                    && h.is_valid()
                    && !headers.iter().any(|k| k.kind == h.kind)
                {
                    headers.push(h.clone());
                }
            }
            let (at, d) = descriptor.unwrap_or((0, StreamHeader::transaction_descriptor(0, 1)));
            headers.insert(at, d);
            out.extend_from_slice(&[0; 4]);
            for h in &headers {
                let len = (6 + h.data.len()).min(u32::MAX as usize);
                out.extend_from_slice(&(len as u32).to_le_bytes());
                out.extend_from_slice(&h.kind.to_le_bytes());
                out.extend_from_slice(&h.data[..len - 6]);
            }
            let total = out.len().min(u32::MAX as usize) as u32;
            out[0..4].copy_from_slice(&total.to_le_bytes());
        }
        for u in self.text.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------
// Response tokens: types and values.
// ---------------------------------------------------------------------

/// A column's data type and its parameters. Which fields are on the wire
/// depends on the type; the others are 0 or `None` in a type read, and a
/// [`TokenWriter`] refuses a column whose other fields are not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInfo {
    /// The type code, from [`data_type`].
    pub ty: u8,
    /// The most bytes a value may take, for types with a length. 0xFFFF
    /// for a varchar(max), nvarchar(max) or varbinary(max) column.
    pub max_len: u32,
    /// For decimal and numeric columns: the number of digits, 1 to 38.
    pub precision: u8,
    /// For decimal and numeric columns, the digits after the point. For
    /// time, datetime2 and datetimeoffset, the digits of a second's
    /// fraction, 0 to 7.
    pub scale: u8,
    /// For character columns, the collation.
    pub collation: Option<[u8; 5]>,
}

impl TypeInfo {
    fn bare(ty: u8) -> TypeInfo {
        TypeInfo {
            ty,
            max_len: 0,
            precision: 0,
            scale: 0,
            collation: None,
        }
    }

    /// A fixed-length type, such as [`data_type::INT4`], or
    /// [`data_type::DATEN`].
    pub fn fixed(ty: u8) -> TypeInfo {
        TypeInfo::bare(ty)
    }

    /// A type with a one-byte length that may be null, such as
    /// [`data_type::INTN`] with `max_len` 4 for an int column.
    pub fn nullable(ty: u8, max_len: u8) -> TypeInfo {
        TypeInfo {
            max_len: u32::from(max_len),
            ..TypeInfo::bare(ty)
        }
    }

    /// A [`data_type::DECIMALN`] column.
    pub fn decimal(precision: u8, scale: u8) -> TypeInfo {
        TypeInfo {
            max_len: u32::from(decimal_len(precision)),
            precision,
            scale,
            ..TypeInfo::bare(data_type::DECIMALN)
        }
    }

    /// A time, datetime2 or datetimeoffset column with `scale` digits of a
    /// second's fraction.
    pub fn scaled(ty: u8, scale: u8) -> TypeInfo {
        TypeInfo {
            scale,
            ..TypeInfo::bare(ty)
        }
    }

    /// A character column, such as [`data_type::NVARCHAR`], of at most
    /// `max_len` bytes, with the [`DEFAULT_COLLATION`]. A `max_len` of
    /// 0xFFFF makes it varchar(max) or nvarchar(max).
    pub fn string(ty: u8, max_len: u16) -> TypeInfo {
        TypeInfo {
            max_len: u32::from(max_len),
            collation: Some(DEFAULT_COLLATION),
            ..TypeInfo::bare(ty)
        }
    }

    /// A binary column, such as [`data_type::BIGVARBINARY`], of at most
    /// `max_len` bytes. A `max_len` of 0xFFFF makes it varbinary(max).
    pub fn binary(ty: u8, max_len: u16) -> TypeInfo {
        TypeInfo {
            max_len: u32::from(max_len),
            ..TypeInfo::bare(ty)
        }
    }
}

/// One column, as a COLMETADATA token describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// The user type. 0 for most columns.
    pub user_type: u32,
    /// Flags; 0x0001 means the column may be null.
    pub flags: u16,
    /// The data type.
    pub type_info: TypeInfo,
    /// The column's name.
    pub name: String,
}

impl Column {
    /// A column that may be null, with user type 0.
    pub fn new(name: &str, type_info: TypeInfo) -> Column {
        Column {
            user_type: 0,
            flags: 0x0001,
            type_info,
            name: name.to_string(),
        }
    }
}

/// One value in a row. Floats are kept as their bits, so values compare
/// exactly; `f64::from_bits` gives the number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// A tinyint: 0 to 255.
    TinyInt(u8),
    /// A smallint.
    SmallInt(i16),
    /// An int.
    Int(i32),
    /// A bigint.
    BigInt(i64),
    /// A bit.
    Bit(bool),
    /// A real, as the bits of an `f32`.
    Real(u32),
    /// A float, as the bits of an `f64`.
    Float(u64),
    /// A smallmoney, in ten-thousandths.
    SmallMoney(i32),
    /// A money, in ten-thousandths.
    Money(i64),
    /// A smalldatetime: days since 1900-01-01, and minutes since midnight.
    SmallDateTime {
        /// Days since 1900-01-01.
        days: u16,
        /// Minutes since midnight.
        minutes: u16,
    },
    /// A datetime: days since 1900-01-01, and three-hundredths of a second
    /// since midnight.
    DateTime {
        /// Days since 1900-01-01.
        days: i32,
        /// Three-hundredths of a second since midnight.
        ticks: u32,
    },
    /// A uniqueidentifier, as its 16 bytes on the wire.
    Guid([u8; 16]),
    /// A decimal or numeric: its digits as an integer, without the point.
    /// The column's scale says where the point goes.
    Decimal {
        /// Whether it is 0 or above.
        positive: bool,
        /// The digits, as an integer.
        value: u128,
    },
    /// A date: days since 0001-01-01.
    Date(u32),
    /// A time: units of 10^-scale seconds since midnight.
    Time(u64),
    /// A datetime2.
    DateTime2 {
        /// Units of 10^-scale seconds since midnight.
        time: u64,
        /// Days since 0001-01-01.
        date: u32,
    },
    /// A datetimeoffset, in UTC.
    DateTimeOffset {
        /// Units of 10^-scale seconds since midnight.
        time: u64,
        /// Days since 0001-01-01.
        date: u32,
        /// Minutes from UTC of the original time zone.
        offset: i16,
    },
    /// Bytes: binary and varbinary values, char and varchar values in the
    /// column's code page, and sql_variant values as they are on the wire:
    /// the base type, the property count, the properties and the value.
    Bytes(Vec<u8>),
    /// An nchar or nvarchar value, read as UTF-16; units that are not
    /// valid UTF-16 become U+FFFD.
    Text(String),
}

/// How a data type's values are laid out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Always this many bytes.
    Fixed(usize),
    /// A one-byte length, 0 for null.
    ByteLen,
    /// A one-byte length, then a sign and the digits.
    Decimal,
    /// A one-byte length, 0 or 3.
    Date,
    /// A one-byte length fixed by the scale.
    Scaled,
    /// A two-byte length, 0xFFFF for null; or PLP chunks.
    UShort {
        /// Whether the type has a collation.
        chars: bool,
        /// Whether the type may be MAX.
        var: bool,
    },
    /// A four-byte length, 0 for null.
    Variant,
}

fn class(ty: u8) -> Option<Class> {
    use data_type::*;
    Some(match ty {
        NULL => Class::Fixed(0),
        INT1 | BIT => Class::Fixed(1),
        INT2 => Class::Fixed(2),
        INT4 | DATETIM4 | FLT4 | MONEY4 => Class::Fixed(4),
        MONEY | DATETIME | FLT8 | INT8 => Class::Fixed(8),
        GUID | INTN | BITN | FLTN | MONEYN | DATETIMN => Class::ByteLen,
        DECIMALN | NUMERICN => Class::Decimal,
        DATEN => Class::Date,
        TIMEN | DATETIME2N | DATETIMEOFFSETN => Class::Scaled,
        BIGVARBINARY => Class::UShort {
            chars: false,
            var: true,
        },
        BIGBINARY => Class::UShort {
            chars: false,
            var: false,
        },
        BIGVARCHAR | NVARCHAR => Class::UShort {
            chars: true,
            var: true,
        },
        BIGCHAR | NCHAR => Class::UShort {
            chars: true,
            var: false,
        },
        SSVARIANT => Class::Variant,
        _ => return None,
    })
}

/// The widths a value of a fixed or one-byte-length type may have.
fn widths(ty: u8) -> &'static [usize] {
    use data_type::*;
    match ty {
        INT1 | BIT | BITN => &[1],
        INT2 => &[2],
        INT4 | DATETIM4 | FLT4 | MONEY4 => &[4],
        MONEY | DATETIME | FLT8 | INT8 => &[8],
        INTN => &[1, 2, 4, 8],
        FLTN | MONEYN | DATETIMN => &[4, 8],
        GUID => &[16],
        _ => &[],
    }
}

/// A fixed or one-byte-length value of `ty`, from its bytes.
fn decode_number(ty: u8, b: &[u8]) -> Value {
    use data_type::*;
    let le = |n: usize| -> u64 {
        let mut x = [0u8; 8];
        x[..n].copy_from_slice(&b[..n]);
        u64::from_le_bytes(x)
    };
    match (ty, b.len()) {
        (BIT | BITN, _) => Value::Bit(b[0] != 0),
        (FLT4 | FLTN, 4) => Value::Real(le(4) as u32),
        (FLT8 | FLTN, 8) => Value::Float(le(8)),
        (MONEY4 | MONEYN, 4) => Value::SmallMoney(le(4) as u32 as i32),
        (MONEY | MONEYN, 8) => {
            Value::Money((((le(4) as u32 as u64) << 32) | u64::from(le32(b, 4))) as i64)
        }
        (DATETIM4 | DATETIMN, 4) => Value::SmallDateTime {
            days: le16(b, 0),
            minutes: le16(b, 2),
        },
        (DATETIME | DATETIMN, 8) => Value::DateTime {
            days: le32(b, 0) as i32,
            ticks: le32(b, 4),
        },
        (GUID, 16) => {
            let mut g = [0u8; 16];
            g.copy_from_slice(b);
            Value::Guid(g)
        }
        (_, 1) => Value::TinyInt(b[0]),
        (_, 2) => Value::SmallInt(le(2) as u16 as i16),
        (_, 4) => Value::Int(le(4) as u32 as i32),
        (_, 8) => Value::BigInt(le(8) as i64),
        _ => Value::Null,
    }
}

/// The bytes of a fixed or one-byte-length value, if it is one.
fn encode_number(v: &Value) -> Option<Vec<u8>> {
    Some(match v {
        Value::TinyInt(x) => vec![*x],
        Value::SmallInt(x) => x.to_le_bytes().to_vec(),
        Value::Int(x) => x.to_le_bytes().to_vec(),
        Value::BigInt(x) => x.to_le_bytes().to_vec(),
        Value::Bit(x) => vec![u8::from(*x)],
        Value::Real(x) => x.to_le_bytes().to_vec(),
        Value::Float(x) => x.to_le_bytes().to_vec(),
        Value::SmallMoney(x) => x.to_le_bytes().to_vec(),
        Value::Money(x) => {
            let x = *x as u64;
            let mut out = ((x >> 32) as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&(x as u32).to_le_bytes());
            out
        }
        Value::SmallDateTime { days, minutes } => {
            [days.to_le_bytes(), minutes.to_le_bytes()].concat()
        }
        Value::DateTime { days, ticks } => [days.to_le_bytes(), ticks.to_le_bytes()].concat(),
        Value::Guid(g) => g.to_vec(),
        _ => return None,
    })
}

/// The length byte of a decimal of `precision` digits: a sign and 4, 8,
/// 12 or 16 bytes of digits.
fn decimal_len(precision: u8) -> u8 {
    1 + match precision {
        0..=9 => 4,
        10..=19 => 8,
        20..=28 => 12,
        _ => 16,
    }
}

/// The bytes of a time of `scale`.
fn time_len(scale: u8) -> usize {
    match scale {
        0..=2 => 3,
        3..=4 => 4,
        _ => 5,
    }
}

/// The last date a date, datetime2 or datetimeoffset value may hold,
/// 9999-12-31, in days since 0001-01-01.
const MAX_DATE: u32 = 3_652_058;
/// The furthest a datetimeoffset's time zone may be from UTC, in minutes.
const MAX_OFFSET: i16 = 840;

/// Units of 10^-`scale` seconds in a day.
fn day_units(scale: u8) -> u64 {
    86_400 * 10u64.pow(u32::from(scale.min(7)))
}

/// Whether a decimal's digits fit `precision` digits.
fn decimal_fits(value: u128, precision: u8) -> bool {
    precision <= 38 && value < 10u128.pow(u32::from(precision))
}

/// Checks a non-null sql_variant value's layout, as MS-TDS 2.2.5.5.4
/// gives it: a base type, a property count and properties fixed by the
/// base type, then a value of a length the base type allows.
fn check_variant(b: &[u8]) -> Result<(), Error> {
    use data_type::*;
    let bad = Error::Invalid("sql_variant value");
    let [base, prop, rest @ ..] = b else {
        return Err(bad);
    };
    let props = rest.get(..usize::from(*prop)).ok_or(bad)?;
    let data = &rest[props.len()..];
    let ok = match *base {
        GUID | BIT | INT1 | INT2 | INT4 | INT8 | DATETIME | DATETIM4 | FLT4 | FLT8 | MONEY
        | MONEY4 => *prop == 0 && widths(*base) == [data.len()],
        DATEN => *prop == 0 && data.len() == 3 && le_uint(data) as u32 <= MAX_DATE,
        TIMEN | DATETIME2N | DATETIMEOFFSETN => {
            *prop == 1
                && props[0] <= 7
                && byte_len_value_ok(&TypeInfo::scaled(*base, props[0]), data)
        }
        DECIMALN | NUMERICN => {
            *prop == 2 && {
                let (precision, scale) = (props[0], props[1]);
                (1..=38).contains(&precision)
                    && scale <= precision
                    && byte_len_value_ok(&TypeInfo::decimal(precision, scale), data)
            }
        }
        BIGVARBINARY | BIGBINARY => *prop == 2 && data.len() <= usize::from(le16(props, 0)),
        BIGVARCHAR | BIGCHAR | NVARCHAR | NCHAR => {
            let even = !matches!(*base, NVARCHAR | NCHAR) || data.len() % 2 == 0;
            *prop == 7 && even && data.len() <= usize::from(le16(props, 5))
        }
        _ => false,
    };
    if ok { Ok(()) } else { Err(bad) }
}

/// Whether `data`, given a one-byte length in front, reads as one value
/// of `ty` other than null and takes all of it.
fn byte_len_value_ok(ty: &TypeInfo, data: &[u8]) -> bool {
    let Ok(n) = u8::try_from(data.len()) else {
        return false;
    };
    let mut framed = vec![n];
    framed.extend_from_slice(data);
    let mut c = Cur::new(&framed);
    read_value(&mut c, ty).is_ok_and(|v| v != Value::Null) && c.p == framed.len()
}

/// The partly length-prefixed (PLP) length that means null.
const PLP_NULL: u64 = u64::MAX;
/// The PLP length that means the length is not known in advance.
const PLP_UNKNOWN: u64 = u64::MAX - 1;
/// The most bytes in one PLP chunk a writer writes.
const PLP_CHUNK: usize = 1 << 20;

fn read_type_info(c: &mut Cur) -> Result<TypeInfo, Error> {
    let ty = c.u8()?;
    let mut t = TypeInfo::bare(ty);
    // A NULL-typed column takes no bytes in a row, so one byte of ROW
    // could stand for thousands of values. SQL Server does not describe
    // columns this way.
    if ty == data_type::NULL {
        return Err(Error::UnsupportedType(ty));
    }
    match class(ty).ok_or(Error::UnsupportedType(ty))? {
        Class::Fixed(_) | Class::Date => {}
        Class::ByteLen => {
            t.max_len = u32::from(c.u8()?);
            if !widths(ty).contains(&(t.max_len as usize)) {
                return Err(Error::Invalid("column length"));
            }
        }
        Class::Decimal => {
            t.max_len = u32::from(c.u8()?);
            t.precision = c.u8()?;
            t.scale = c.u8()?;
            if ![5, 9, 13, 17].contains(&t.max_len)
                || !(1..=38).contains(&t.precision)
                || t.scale > t.precision
            {
                return Err(Error::Invalid("decimal precision or scale"));
            }
        }
        Class::Scaled => {
            t.scale = c.u8()?;
            if t.scale > 7 {
                return Err(Error::Invalid("time scale"));
            }
        }
        Class::UShort { chars, var } => {
            t.max_len = u32::from(c.u16()?);
            if t.max_len == 0xffff && !var {
                return Err(Error::Invalid("column length"));
            }
            if chars {
                let mut col = [0u8; 5];
                col.copy_from_slice(c.take(5)?);
                t.collation = Some(col);
            }
        }
        Class::Variant => t.max_len = c.u32()?,
    }
    Ok(t)
}

fn write_type_info(out: &mut Vec<u8>, t: &TypeInfo) {
    out.push(t.ty);
    match class(t.ty) {
        Some(Class::ByteLen) => out.push(t.max_len as u8),
        Some(Class::Decimal) => out.extend_from_slice(&[t.max_len as u8, t.precision, t.scale]),
        Some(Class::Scaled) => out.push(t.scale),
        Some(Class::UShort { .. }) => {
            out.extend_from_slice(&(t.max_len as u16).to_le_bytes());
            if let Some(c) = t.collation {
                out.extend_from_slice(&c);
            }
        }
        Some(Class::Variant) => out.extend_from_slice(&t.max_len.to_le_bytes()),
        _ => {}
    }
}

/// Reads one value of type `t`. A value must fit its column: no longer
/// than the column's maximum length, a decimal within its precision, and
/// dates, times and time zone offsets within the ranges MS-TDS 2.2.5.5.1
/// gives them.
fn read_value(c: &mut Cur, t: &TypeInfo) -> Result<Value, Error> {
    let chars_text = t.ty == data_type::NVARCHAR || t.ty == data_type::NCHAR;
    match class(t.ty).ok_or(Error::UnsupportedType(t.ty))? {
        Class::Fixed(0) => Ok(Value::Null),
        Class::Fixed(n) => Ok(decode_number(t.ty, c.take(n)?)),
        Class::ByteLen => {
            let n = usize::from(c.u8()?);
            if n == 0 {
                return Ok(Value::Null);
            }
            if !widths(t.ty).contains(&n) || n > t.max_len as usize {
                return Err(Error::Invalid("value length"));
            }
            Ok(decode_number(t.ty, c.take(n)?))
        }
        Class::Decimal => {
            let n = usize::from(c.u8()?);
            if n == 0 {
                return Ok(Value::Null);
            }
            if ![5, 9, 13, 17].contains(&n) || n > t.max_len as usize {
                return Err(Error::Invalid("decimal length"));
            }
            let b = c.take(n)?;
            if b[0] > 1 {
                return Err(Error::Invalid("decimal sign"));
            }
            let mut x = [0u8; 16];
            x[..n - 1].copy_from_slice(&b[1..]);
            let value = u128::from_le_bytes(x);
            if !decimal_fits(value, t.precision) {
                return Err(Error::Invalid("decimal past its precision"));
            }
            Ok(Value::Decimal {
                positive: b[0] == 1,
                value,
            })
        }
        Class::Date => match c.u8()? {
            0 => Ok(Value::Null),
            3 => match le_uint(c.take(3)?) as u32 {
                d if d <= MAX_DATE => Ok(Value::Date(d)),
                _ => Err(Error::Invalid("date past 9999-12-31")),
            },
            _ => Err(Error::Invalid("date length")),
        },
        Class::Scaled => {
            let n = usize::from(c.u8()?);
            if n == 0 {
                return Ok(Value::Null);
            }
            let tl = time_len(t.scale);
            let want = match t.ty {
                data_type::TIMEN => tl,
                data_type::DATETIME2N => tl + 3,
                _ => tl + 5,
            };
            if n != want {
                return Err(Error::Invalid("time length"));
            }
            let b = c.take(n)?;
            let time = le_uint(&b[..tl]);
            if time >= day_units(t.scale) {
                return Err(Error::Invalid("time past the end of the day"));
            }
            if n > tl && le_uint(&b[tl..tl + 3]) as u32 > MAX_DATE {
                return Err(Error::Invalid("date past 9999-12-31"));
            }
            if n == tl + 5 && !(-MAX_OFFSET..=MAX_OFFSET).contains(&(le16(b, tl + 3) as i16)) {
                return Err(Error::Invalid("time zone offset"));
            }
            Ok(match t.ty {
                data_type::TIMEN => Value::Time(time),
                data_type::DATETIME2N => Value::DateTime2 {
                    time,
                    date: le_uint(&b[tl..tl + 3]) as u32,
                },
                _ => Value::DateTimeOffset {
                    time,
                    date: le_uint(&b[tl..tl + 3]) as u32,
                    offset: le16(b, tl + 3) as i16,
                },
            })
        }
        Class::UShort { .. } if t.max_len == 0xffff => {
            let total = c.u64()?;
            if total == PLP_NULL {
                return Ok(Value::Null);
            }
            let mut data = Vec::new();
            loop {
                let n = c.u32()? as usize;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(c.take(n)?);
            }
            if total != PLP_UNKNOWN && total != data.len() as u64 {
                return Err(Error::Invalid("PLP length"));
            }
            bytes_value(data, chars_text)
        }
        Class::UShort { .. } => {
            let n = c.u16()?;
            if n == 0xffff {
                return Ok(Value::Null);
            }
            if u32::from(n) > t.max_len {
                return Err(Error::Invalid("value longer than its column"));
            }
            bytes_value(c.take(usize::from(n))?.to_vec(), chars_text)
        }
        Class::Variant => {
            let n = c.u32()? as usize;
            if n == 0 {
                return Ok(Value::Null);
            }
            if n > t.max_len as usize {
                return Err(Error::Invalid("value longer than its column"));
            }
            let b = c.take(n)?;
            check_variant(b)?;
            Ok(Value::Bytes(b.to_vec()))
        }
    }
}

fn bytes_value(data: Vec<u8>, text: bool) -> Result<Value, Error> {
    if !text {
        return Ok(Value::Bytes(data));
    }
    if !data.len().is_multiple_of(2) {
        return Err(Error::Invalid("UTF-16 text of odd length"));
    }
    Ok(Value::Text(utf16_string(&data)))
}

/// Writes one value of type `t`, as well as it can. A value that does
/// not match its type is written so that reading it back differs, and
/// the [`TokenWriter`] refuses it.
fn write_value(out: &mut Vec<u8>, t: &TypeInfo, v: &Value) {
    let Some(cl) = class(t.ty) else { return };
    match (cl, v) {
        (Class::Fixed(_), Value::Null) => {}
        (Class::Fixed(_), v) => out.extend_from_slice(&encode_number(v).unwrap_or_default()),
        (Class::Variant, Value::Null) => out.extend_from_slice(&[0; 4]),
        (Class::Variant, Value::Bytes(b)) => {
            out.extend_from_slice(&(b.len().min(u32::MAX as usize) as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        (Class::UShort { .. }, Value::Null) if t.max_len == 0xffff => {
            out.extend_from_slice(&PLP_NULL.to_le_bytes())
        }
        (Class::UShort { .. }, Value::Null) => out.extend_from_slice(&[0xff, 0xff]),
        (Class::UShort { .. }, Value::Bytes(_) | Value::Text(_)) => {
            let data = match v {
                Value::Text(s) => units_to_bytes(&s.encode_utf16().collect::<Vec<_>>()),
                Value::Bytes(b) => b.clone(),
                _ => Vec::new(),
            };
            if t.max_len == 0xffff {
                out.extend_from_slice(&(data.len() as u64).to_le_bytes());
                for chunk in data.chunks(PLP_CHUNK) {
                    out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
                    out.extend_from_slice(chunk);
                }
                out.extend_from_slice(&[0; 4]);
            } else {
                out.extend_from_slice(&(data.len().min(0xfffe) as u16).to_le_bytes());
                out.extend_from_slice(&data);
            }
        }
        (_, Value::Null) => out.push(0),
        (Class::Decimal, Value::Decimal { positive, value }) => {
            let need = (128 - value.leading_zeros() as usize).div_ceil(8);
            let floor = usize::from(decimal_len(t.precision)) - 1;
            let w = [4, 8, 12, 16]
                .into_iter()
                .find(|&w| w >= need && w >= floor)
                .unwrap_or(16);
            out.push(w as u8 + 1);
            out.push(u8::from(*positive));
            out.extend_from_slice(&value.to_le_bytes()[..w]);
        }
        (Class::Date, Value::Date(d)) => {
            out.push(3);
            out.extend_from_slice(&d.to_le_bytes()[..3]);
        }
        (Class::Scaled, v) => {
            let tl = time_len(t.scale);
            let (time, date, offset) = match *v {
                Value::Time(time) => (time, None, None),
                Value::DateTime2 { time, date } => (time, Some(date), None),
                Value::DateTimeOffset { time, date, offset } => (time, Some(date), Some(offset)),
                _ => return,
            };
            let n = tl + if date.is_some() { 3 } else { 0 } + if offset.is_some() { 2 } else { 0 };
            out.push(n as u8);
            out.extend_from_slice(&time.to_le_bytes()[..tl]);
            if let Some(d) = date {
                out.extend_from_slice(&d.to_le_bytes()[..3]);
            }
            if let Some(o) = offset {
                out.extend_from_slice(&o.to_le_bytes());
            }
        }
        (Class::ByteLen, v) => {
            if let Some(b) = encode_number(v) {
                out.push(b.len() as u8);
                out.extend_from_slice(&b);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------
// Response tokens.
// ---------------------------------------------------------------------

/// A LOGINACK token: the server accepts the login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginAck {
    /// The SQL dialect: 1 for T-SQL.
    pub interface: u8,
    /// The TDS version the server will speak, from [`tds_version`].
    pub tds_version: u32,
    /// The server's name, such as "Microsoft SQL Server". At most 255
    /// UTF-16 units.
    pub prog_name: String,
    /// The server's version: major, minor, and the build's high and low
    /// bytes.
    pub prog_version: [u8; 4],
}

/// An ENVCHANGE token: a setting of the session changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvChange {
    /// Types 1 to 6, 13 and 19: the database, language, character set,
    /// packet size, sort order and so on, as text of at most 255 UTF-16
    /// units each. As MS-TDS 2.2.7.9 has it, a new packet size is a
    /// number from [`MIN_PACKET_SIZE`] to [`MAX_PACKET_SIZE`], and types
    /// 5, 6, 13 and 19 have an empty old value.
    Text {
        /// The type, from [`env_type`].
        kind: u8,
        /// The new value.
        new: String,
        /// The old value; empty for some types.
        old: String,
    },
    /// Types 7 to 12 and 16 to 18: the collation and transaction changes,
    /// as bytes, at most 255 each. As MS-TDS 2.2.7.9 has it, type 8 has an
    /// 8-byte new value and an empty old one, types 9 and 10 an empty new
    /// value and an 8-byte old one, type 16 an empty old value, and type
    /// 18 both values empty.
    Bytes {
        /// The type, from [`env_type`].
        kind: u8,
        /// The new value.
        new: Vec<u8>,
        /// The old value; empty for some types.
        old: Vec<u8>,
    },
    /// Type 15: a transaction was promoted. The DTC token. On the wire the
    /// token's length is 1, covering only the type, and the DTC token and
    /// an empty old value follow outside it. A reader also takes a length
    /// that covers them.
    PromoteTransaction(Vec<u8>),
    /// Types 20 and 21: the client is to connect to another server.
    Routing {
        /// The protocol. It must be 0, for TCP.
        protocol: u8,
        /// The TCP port. It must not be 0.
        port: u16,
        /// The server to connect to.
        server: String,
        /// For type 21, the database to use there, of at most
        /// [`MAX_ROUTING_DATABASE`] UTF-16 units.
        database: Option<String>,
    },
    /// Any other type, with its data unread.
    Other {
        /// The type.
        kind: u8,
        /// Everything after the type.
        data: Vec<u8>,
    },
}

/// An INFO or ERROR token: a message from the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMessage {
    /// The message number, such as 5701 for "Changed database context".
    pub number: i32,
    /// The error state.
    pub state: u8,
    /// The severity: 10 or below for information, above 10 for errors.
    pub class: u8,
    /// The message.
    pub text: String,
    /// The server's name. At most 255 UTF-16 units.
    pub server: String,
    /// The stored procedure's name, if one was running. At most 255 UTF-16
    /// units.
    pub procedure: String,
    /// The line of the batch or procedure.
    pub line: u32,
}

/// A DONE, DONEPROC or DONEINPROC token: a statement finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    /// Bits from [`done_status`].
    pub status: u16,
    /// The kind of statement, such as 0xC1 for SELECT. Readers rarely
    /// look.
    pub cur_cmd: u16,
    /// The rows affected or returned, when the status has
    /// [`done_status::COUNT`].
    pub row_count: u64,
}

impl Done {
    /// A DONE with `status` and `row_count`, and statement kind 0.
    pub fn new(status: u16, row_count: u64) -> Done {
        Done {
            status,
            cur_cmd: 0,
            row_count,
        }
    }
}

/// Bits of a RETURNVALUE token's status.
pub mod return_status {
    /// The value of an output parameter of a stored procedure.
    pub const OUTPUT: u8 = 0x01;
    /// The return value of a user-defined function.
    pub const UDF: u8 = 0x02;
}

/// The bit of a column's or a RETURNVALUE token's flags that says the
/// value is encrypted, from TDS 7.4. Encrypted values carry metadata
/// this module does not read.
pub const FLAG_ENCRYPTED: u16 = 0x0800;

/// A RETURNVALUE token: an output parameter or a function's return value,
/// after an RPC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnValue {
    /// The parameter's position in the RPC call.
    pub ordinal: u16,
    /// The parameter's name, such as "@total". At most 255 UTF-16 units.
    pub name: String,
    /// [`return_status::OUTPUT`] or [`return_status::UDF`].
    pub status: u8,
    /// The user type. 0 for most values.
    pub user_type: u32,
    /// Flags, as a column's. [`FLAG_ENCRYPTED`] is refused.
    pub flags: u16,
    /// The value's data type.
    pub type_info: TypeInfo,
    /// The value.
    pub value: Value,
}

/// One token of a server's response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// The server accepts the login.
    LoginAck(LoginAck),
    /// A session setting changed.
    EnvChange(EnvChange),
    /// An informational message.
    Info(ServerMessage),
    /// An error message.
    Error(ServerMessage),
    /// A statement in a batch finished.
    Done(Done),
    /// A stored procedure finished.
    DoneProc(Done),
    /// A statement in a stored procedure finished.
    DoneInProc(Done),
    /// The columns of the rows that follow. `None` is the count 0xFFFF,
    /// which says the earlier columns still apply.
    ColMetadata(Option<Vec<Column>>),
    /// A row, one value per column.
    Row(Vec<Value>),
    /// A row with a bitmap of nulls first, one value per column.
    NbcRow(Vec<Value>),
    /// A stored procedure's return value.
    ReturnStatus(i32),
    /// An output parameter or a function's return value.
    ReturnValue(ReturnValue),
    /// The features the server accepts, in answer to a LOGIN7 record's
    /// feature extension block.
    FeatureExtAck(Vec<Feature>),
    /// A token this module does not read further but whose length it
    /// knows: TABNAME, COLINFO, ORDER, SSPI, SESSIONSTATE, FEDAUTHINFO and
    /// OFFSET. `data` is what follows the token type and length.
    Other {
        /// The token type, from [`token`].
        token: u8,
        /// The token's data.
        data: Vec<u8>,
    },
}

/// How the length of a token read as [`Token::Other`] is given.
#[derive(Clone, Copy)]
enum OtherLen {
    U16,
    U32,
    Fixed(usize),
}

fn other_len(t: u8) -> Option<OtherLen> {
    match t {
        token::TABNAME | token::COLINFO | token::ORDER | token::SSPI => Some(OtherLen::U16),
        token::SESSIONSTATE | token::FEDAUTHINFO => Some(OtherLen::U32),
        token::OFFSET => Some(OtherLen::Fixed(4)),
        _ => None,
    }
}

/// Reads one token from the start of `b`, with `columns` the columns of
/// the last COLMETADATA token. It returns the token and how many bytes
/// it took.
fn read_token(b: &[u8], columns: Option<&[Column]>) -> Result<(Token, usize), Error> {
    let mut c = Cur::new(b);
    let t = c.u8()?;
    let token = match t {
        token::LOGINACK => {
            let body = c.u16_block()?;
            let mut d = Cur::new(body);
            let interface = d.u8()?;
            let tds_version = u32::from_be_bytes(d.array()?);
            let prog_name = d.b_varchar()?;
            let prog_version = d.array()?;
            d.end()?;
            Token::LoginAck(LoginAck {
                interface,
                tds_version,
                prog_name,
                prog_version,
            })
        }
        token::ENVCHANGE => {
            let body = c.u16_block()?;
            if body == [env_type::PROMOTE_TRANSACTION] {
                // The token's length covers only the type; the DTC token
                // and the old value follow it.
                let n = c.u32()? as usize;
                let dtc = c.take(n)?.to_vec();
                if c.u8()? != 0 {
                    return Err(Error::Invalid("ENVCHANGE old value"));
                }
                Token::EnvChange(EnvChange::PromoteTransaction(dtc))
            } else {
                Token::EnvChange(read_env_change(body)?)
            }
        }
        token::INFO | token::ERROR => {
            let body = c.u16_block()?;
            let mut d = Cur::new(body);
            let m = ServerMessage {
                number: d.u32()? as i32,
                state: d.u8()?,
                class: d.u8()?,
                text: d.us_varchar()?,
                server: d.b_varchar()?,
                procedure: d.b_varchar()?,
                line: d.u32()?,
            };
            d.end()?;
            if t == token::INFO {
                Token::Info(m)
            } else {
                Token::Error(m)
            }
        }
        token::DONE | token::DONEPROC | token::DONEINPROC => {
            let d = Done {
                status: c.u16()?,
                cur_cmd: c.u16()?,
                row_count: c.u64()?,
            };
            match t {
                token::DONE => Token::Done(d),
                token::DONEPROC => Token::DoneProc(d),
                _ => Token::DoneInProc(d),
            }
        }
        token::COLMETADATA => {
            let count = c.u16()?;
            if count == 0xffff {
                Token::ColMetadata(None)
            } else {
                let count = usize::from(count);
                if count > MAX_COLUMNS {
                    return Err(Error::Limit("columns"));
                }
                let mut cols = Vec::with_capacity(count);
                for _ in 0..count {
                    let user_type = c.u32()?;
                    let flags = c.u16()?;
                    let type_info = read_type_info(&mut c)?;
                    let name = c.b_varchar()?;
                    cols.push(Column {
                        user_type,
                        flags,
                        type_info,
                        name,
                    });
                }
                Token::ColMetadata(Some(cols))
            }
        }
        token::ROW | token::NBCROW => {
            let cols = columns.ok_or(Error::NoColumns)?;
            let bitmap = if t == token::NBCROW {
                c.take(cols.len().div_ceil(8))?
            } else {
                &[]
            };
            let mut values = Vec::with_capacity(cols.len());
            for (i, col) in cols.iter().enumerate() {
                let null = bitmap
                    .get(i / 8)
                    .is_some_and(|byte| byte & (1 << (i % 8)) != 0);
                values.push(if null {
                    Value::Null
                } else {
                    read_value(&mut c, &col.type_info)?
                });
            }
            if t == token::ROW {
                Token::Row(values)
            } else {
                Token::NbcRow(values)
            }
        }
        token::RETURNSTATUS => Token::ReturnStatus(c.u32()? as i32),
        token::RETURNVALUE => {
            let ordinal = c.u16()?;
            let name = c.b_varchar()?;
            let status = c.u8()?;
            if status != return_status::OUTPUT && status != return_status::UDF {
                return Err(Error::Invalid("RETURNVALUE status"));
            }
            let user_type = c.u32()?;
            let flags = c.u16()?;
            if flags & FLAG_ENCRYPTED != 0 {
                return Err(Error::Limit("encrypted RETURNVALUE"));
            }
            let type_info = read_type_info(&mut c)?;
            let value = read_value(&mut c, &type_info)?;
            Token::ReturnValue(ReturnValue {
                ordinal,
                name,
                status,
                user_type,
                flags,
                type_info,
                value,
            })
        }
        token::FEATUREEXTACK => {
            let (features, used) = parse_features(&b[1..])?;
            c.p += used;
            Token::FeatureExtAck(features)
        }
        _ => {
            let len = match other_len(t).ok_or(Error::UnknownToken(t))? {
                OtherLen::U16 => usize::from(c.u16()?),
                OtherLen::U32 => c.u32()? as usize,
                OtherLen::Fixed(n) => n,
            };
            Token::Other {
                token: t,
                data: c.take(len)?.to_vec(),
            }
        }
    };
    Ok((token, c.p))
}

fn read_env_change(body: &[u8]) -> Result<EnvChange, Error> {
    let mut d = Cur::new(body);
    let kind = d.u8()?;
    let env = match kind {
        1..=6 | 13 | 19 => EnvChange::Text {
            kind,
            new: d.b_varchar()?,
            old: d.b_varchar()?,
        },
        7..=12 | 16..=18 => {
            let n = usize::from(d.u8()?);
            let new = d.take(n)?.to_vec();
            let n = usize::from(d.u8()?);
            EnvChange::Bytes {
                kind,
                new,
                old: d.take(n)?.to_vec(),
            }
        }
        15 => {
            let n = d.u32()? as usize;
            let token = d.take(n)?.to_vec();
            if d.u8()? != 0 {
                return Err(Error::Invalid("ENVCHANGE old value"));
            }
            EnvChange::PromoteTransaction(token)
        }
        20 | 21 => {
            let n = usize::from(d.u16()?);
            let mut r = Cur::new(d.take(n)?);
            let protocol = r.u8()?;
            if protocol != 0 {
                return Err(Error::Invalid("routing protocol"));
            }
            let port = r.u16()?;
            if port == 0 {
                return Err(Error::Invalid("routing port"));
            }
            let server = r.us_varchar()?;
            let database = if kind == env_type::ENHANCED_ROUTING {
                let n = usize::from(r.u16()?);
                if n > MAX_ROUTING_DATABASE {
                    return Err(Error::Limit("routing database"));
                }
                Some(utf16_string(r.take(2 * n)?))
            } else {
                None
            };
            r.end()?;
            if d.u16()? != 0 {
                return Err(Error::Invalid("ENVCHANGE old value"));
            }
            EnvChange::Routing {
                protocol,
                port,
                server,
                database,
            }
        }
        _ => {
            let data = d.take(body.len() - 1)?.to_vec();
            EnvChange::Other { kind, data }
        }
    };
    d.end()?;
    check_env_change(&env)?;
    Ok(env)
}

/// Checks the rules MS-TDS 2.2.7.9 gives each ENVCHANGE type's values.
fn check_env_change(env: &EnvChange) -> Result<(), Error> {
    let ok = match env {
        EnvChange::Text { kind, new, old } => match *kind {
            env_type::PACKET_SIZE => {
                !new.is_empty()
                    && new.len() <= 5
                    && new.bytes().all(|b| b.is_ascii_digit())
                    && new
                        .parse::<usize>()
                        .is_ok_and(|n| (MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&n))
            }
            env_type::SORT_LOCALE_ID
            | env_type::SORT_FLAGS
            | env_type::MIRROR_PARTNER
            | env_type::USER_INSTANCE => old.is_empty(),
            _ => true,
        },
        EnvChange::Bytes { kind, new, old } => match *kind {
            env_type::BEGIN_TRANSACTION => new.len() == 8 && old.is_empty(),
            env_type::COMMIT_TRANSACTION | env_type::ROLLBACK_TRANSACTION => {
                new.is_empty() && old.len() == 8
            }
            env_type::TRANSACTION_MANAGER_ADDRESS => old.is_empty(),
            env_type::RESET_ACK => new.is_empty() && old.is_empty(),
            _ => true,
        },
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid("ENVCHANGE value for its type"))
    }
}

/// Writes a token's bytes as well as it can. Lengths that do not fit are
/// written cut short; the [`TokenWriter`] reads every token back and
/// refuses one that does not match.
fn write_token(out: &mut Vec<u8>, tok: &Token, columns: Option<&[Column]>) -> Result<(), Error> {
    match tok {
        Token::LoginAck(a) => {
            let mut body = vec![a.interface];
            body.extend_from_slice(&a.tds_version.to_be_bytes());
            put_b_varchar(&mut body, &a.prog_name);
            body.extend_from_slice(&a.prog_version);
            u16_block(out, token::LOGINACK, &body)?;
        }
        Token::EnvChange(e) => {
            let mut body = Vec::new();
            match e {
                EnvChange::Text { kind, new, old } => {
                    body.push(*kind);
                    put_b_varchar(&mut body, new);
                    put_b_varchar(&mut body, old);
                }
                EnvChange::Bytes { kind, new, old } => {
                    body.push(*kind);
                    for v in [new, old] {
                        let v = &v[..v.len().min(255)];
                        body.push(v.len() as u8);
                        body.extend_from_slice(v);
                    }
                }
                EnvChange::PromoteTransaction(t) => {
                    // The length covers only the type, as the
                    // specification has it.
                    let n = u32::try_from(t.len()).map_err(|_| Error::Unwritable)?;
                    out.extend_from_slice(&[token::ENVCHANGE, 1, 0, env_type::PROMOTE_TRANSACTION]);
                    out.extend_from_slice(&n.to_le_bytes());
                    out.extend_from_slice(t);
                    out.push(0);
                    return Ok(());
                }
                EnvChange::Routing {
                    protocol,
                    port,
                    server,
                    database,
                } => {
                    body.push(if database.is_some() {
                        env_type::ENHANCED_ROUTING
                    } else {
                        env_type::ROUTING
                    });
                    let mut r = vec![*protocol];
                    r.extend_from_slice(&port.to_le_bytes());
                    put_us_varchar(&mut r, server);
                    if let Some(db) = database {
                        put_us_varchar(&mut r, db);
                    }
                    if r.len() > 0xffff {
                        return Err(Error::Unwritable);
                    }
                    body.extend_from_slice(&(r.len() as u16).to_le_bytes());
                    body.extend_from_slice(&r);
                    body.extend_from_slice(&[0, 0]);
                }
                EnvChange::Other { kind, data } => {
                    body.push(*kind);
                    body.extend_from_slice(data);
                }
            }
            u16_block(out, token::ENVCHANGE, &body)?;
        }
        Token::Info(m) | Token::Error(m) => {
            let mut body = Vec::new();
            body.extend_from_slice(&m.number.to_le_bytes());
            body.push(m.state);
            body.push(m.class);
            put_us_varchar(&mut body, &m.text);
            put_b_varchar(&mut body, &m.server);
            put_b_varchar(&mut body, &m.procedure);
            body.extend_from_slice(&m.line.to_le_bytes());
            let t = if matches!(tok, Token::Info(_)) {
                token::INFO
            } else {
                token::ERROR
            };
            u16_block(out, t, &body)?;
        }
        Token::Done(d) | Token::DoneProc(d) | Token::DoneInProc(d) => {
            out.push(match tok {
                Token::Done(_) => token::DONE,
                Token::DoneProc(_) => token::DONEPROC,
                _ => token::DONEINPROC,
            });
            out.extend_from_slice(&d.status.to_le_bytes());
            out.extend_from_slice(&d.cur_cmd.to_le_bytes());
            out.extend_from_slice(&d.row_count.to_le_bytes());
        }
        Token::ColMetadata(None) => out.extend_from_slice(&[token::COLMETADATA, 0xff, 0xff]),
        Token::ColMetadata(Some(cols)) => {
            if cols.len() > MAX_COLUMNS {
                return Err(Error::Unwritable);
            }
            out.push(token::COLMETADATA);
            out.extend_from_slice(&(cols.len() as u16).to_le_bytes());
            for col in cols {
                out.extend_from_slice(&col.user_type.to_le_bytes());
                out.extend_from_slice(&col.flags.to_le_bytes());
                write_type_info(out, &col.type_info);
                put_b_varchar(out, &col.name);
            }
        }
        Token::Row(values) | Token::NbcRow(values) => {
            let cols = columns.ok_or(Error::NoColumns)?;
            if cols.len() != values.len() {
                return Err(Error::Unwritable);
            }
            let nbc = matches!(tok, Token::NbcRow(_));
            out.push(if nbc { token::NBCROW } else { token::ROW });
            if nbc {
                let mut bitmap = vec![0u8; cols.len().div_ceil(8)];
                for (i, v) in values.iter().enumerate() {
                    if *v == Value::Null {
                        bitmap[i / 8] |= 1 << (i % 8);
                    }
                }
                out.extend_from_slice(&bitmap);
            }
            for (col, v) in cols.iter().zip(values) {
                if !(nbc && *v == Value::Null) {
                    write_value(out, &col.type_info, v);
                }
            }
        }
        Token::ReturnStatus(s) => {
            out.push(token::RETURNSTATUS);
            out.extend_from_slice(&s.to_le_bytes());
        }
        Token::ReturnValue(r) => {
            out.push(token::RETURNVALUE);
            out.extend_from_slice(&r.ordinal.to_le_bytes());
            put_b_varchar(out, &r.name);
            out.push(r.status);
            out.extend_from_slice(&r.user_type.to_le_bytes());
            out.extend_from_slice(&r.flags.to_le_bytes());
            write_type_info(out, &r.type_info);
            write_value(out, &r.type_info, &r.value);
        }
        Token::FeatureExtAck(features) => {
            out.push(token::FEATUREEXTACK);
            write_features(out, features);
        }
        Token::Other { token: t, data } => {
            out.push(*t);
            match other_len(*t).ok_or(Error::Unwritable)? {
                OtherLen::U16 => {
                    out.extend_from_slice(&(data.len().min(0xffff) as u16).to_le_bytes())
                }
                OtherLen::U32 => {
                    out.extend_from_slice(&(data.len().min(u32::MAX as usize) as u32).to_le_bytes())
                }
                OtherLen::Fixed(_) => {}
            }
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

/// Checks columns given by world code as a COLMETADATA token's columns
/// are checked: the count, and each type read back from its bytes.
fn check_columns(columns: &[Column]) -> Result<(), Error> {
    if columns.len() > MAX_COLUMNS {
        return Err(Error::Limit("columns"));
    }
    for col in columns {
        let mut b = Vec::new();
        write_type_info(&mut b, &col.type_info);
        let mut c = Cur::new(&b);
        if read_type_info(&mut c)? != col.type_info || c.p != b.len() {
            return Err(Error::Invalid("column type parameters"));
        }
    }
    Ok(())
}

fn u16_block(out: &mut Vec<u8>, t: u8, body: &[u8]) -> Result<(), Error> {
    if body.len() > 0xffff {
        return Err(Error::Unwritable);
    }
    out.push(t);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    Ok(())
}

/// Reads the tokens of a server's response, one at a time. It keeps the
/// columns of the last COLMETADATA token to read the rows after it, and
/// stops after the first error.
#[derive(Debug)]
pub struct TokenReader<'a> {
    data: &'a [u8],
    pos: usize,
    columns: Option<Vec<Column>>,
    failed: bool,
}

impl<'a> TokenReader<'a> {
    /// A reader of the tokens in `data`, the data of one message.
    pub fn new(data: &'a [u8]) -> TokenReader<'a> {
        TokenReader {
            data,
            pos: 0,
            columns: None,
            failed: false,
        }
    }

    /// A reader that starts with `columns`, as if a COLMETADATA token
    /// with them had come before `data`. For a response split over
    /// several messages. The columns are checked as a COLMETADATA token's
    /// are: at most [`MAX_COLUMNS`], each of a type this module reads with
    /// parameters a COLMETADATA token could carry. Others give
    /// [`Error::Limit`], [`Error::UnsupportedType`] or [`Error::Invalid`].
    pub fn with_columns(data: &'a [u8], columns: Vec<Column>) -> Result<TokenReader<'a>, Error> {
        check_columns(&columns)?;
        Ok(TokenReader {
            data,
            pos: 0,
            columns: Some(columns),
            failed: false,
        })
    }

    /// The columns of the last COLMETADATA token, if one has come.
    pub fn columns(&self) -> Option<&[Column]> {
        self.columns.as_deref()
    }

    /// How many bytes of the data have been read.
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl Iterator for TokenReader<'_> {
    type Item = Result<Token, Error>;

    fn next(&mut self) -> Option<Result<Token, Error>> {
        if self.failed || self.pos >= self.data.len() {
            return None;
        }
        match read_token(&self.data[self.pos..], self.columns.as_deref()) {
            Ok((tok, used)) => {
                self.pos += used;
                if let Token::ColMetadata(Some(cols)) = &tok {
                    self.columns = Some(cols.clone());
                }
                Some(Ok(tok))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

/// Writes the tokens of a server's response. It keeps the columns of the
/// last COLMETADATA token to write the rows after it. It reads every
/// token back as it writes it, and refuses one that would not read back
/// the same, so what it writes always reads. It holds at most
/// [`MAX_MESSAGE`] bytes, the most one [`Message`] carries.
#[derive(Debug, Default)]
pub struct TokenWriter {
    out: Vec<u8>,
    columns: Option<Vec<Column>>,
}

impl TokenWriter {
    /// A writer with nothing written.
    pub fn new() -> TokenWriter {
        TokenWriter::default()
    }

    /// Adds `tok`. On an error nothing is added: [`Error::NoColumns`] for
    /// a row before any COLMETADATA, and [`Error::Unwritable`] for a token
    /// that would not read back the same, such as a row whose values do
    /// not match its columns or a string too long for its field.
    /// [`Error::Limit`] for a token that would take the bytes written past
    /// [`MAX_MESSAGE`].
    pub fn push(&mut self, tok: &Token) -> Result<(), Error> {
        let start = self.out.len();
        let checked =
            write_token(&mut self.out, tok, self.columns.as_deref()).and_then(
                |()| match read_token(&self.out[start..], self.columns.as_deref()) {
                    Ok((back, used)) if used == self.out.len() - start && back == *tok => Ok(()),
                    _ => Err(Error::Unwritable),
                },
            );
        let checked = checked.and(if self.out.len() > MAX_MESSAGE {
            Err(Error::Limit("response past MAX_MESSAGE"))
        } else {
            Ok(())
        });
        if let Err(e) = checked {
            self.out.truncate(start);
            self.out.shrink_to(MAX_MESSAGE);
            return Err(e);
        }
        if let Token::ColMetadata(Some(cols)) = tok {
            self.columns = Some(cols.clone());
        }
        Ok(())
    }

    /// The bytes written so far.
    pub fn bytes(&self) -> &[u8] {
        &self.out
    }

    /// The bytes written, for a [`Message`] of type
    /// [`packet_type::TABULAR_RESULT`].
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

/// A cursor over bytes whose reads fail with [`Error::Truncated`] at the
/// end.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, p: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.p.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.b.get(self.p..end).ok_or(Error::Truncated)?;
        self.p = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// A two-byte length and that many bytes.
    fn u16_block(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    /// A one-byte count of UTF-16 units and the units.
    fn b_varchar(&mut self) -> Result<String, Error> {
        let n = usize::from(self.u8()?);
        Ok(utf16_string(self.take(2 * n)?))
    }

    /// A two-byte count of UTF-16 units and the units.
    fn us_varchar(&mut self) -> Result<String, Error> {
        let n = usize::from(self.u16()?);
        Ok(utf16_string(self.take(2 * n)?))
    }

    /// Fails unless every byte has been read.
    fn end(&self) -> Result<(), Error> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err(Error::Invalid("bytes after the token's fields"))
        }
    }
}

/// UTF-16LE bytes as a string. A last odd byte is ignored.
fn utf16_string(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The UTF-16 units of `s`, stopping before a character that would take
/// the count past `max`.
fn utf16_capped(s: &str, max: usize) -> Vec<u16> {
    let mut units = Vec::new();
    let mut buf = [0u16; 2];
    for ch in s.chars() {
        let enc = ch.encode_utf16(&mut buf);
        if units.len() + enc.len() > max {
            break;
        }
        units.extend_from_slice(enc);
    }
    units
}

fn units_to_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn put_b_varchar(out: &mut Vec<u8>, s: &str) {
    let units = utf16_capped(s, 255);
    out.push(units.len() as u8);
    out.extend_from_slice(&units_to_bytes(&units));
}

fn put_us_varchar(out: &mut Vec<u8>, s: &str) {
    let units = utf16_capped(s, 0xffff);
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    out.extend_from_slice(&units_to_bytes(&units));
}

/// A little-endian unsigned integer of up to 8 bytes.
fn le_uint(b: &[u8]) -> u64 {
    b.iter()
        .rev()
        .take(8)
        .fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect()
    }

    // Examples from MS-TDS section 4.

    /// 4.1: a client's PRELOGIN request.
    const PRELOGIN_EXAMPLE: &str = "12 01 00 2F 00 00 01 00 00 00 1A 00 06 01 00 20
        00 01 02 00 21 00 01 03 00 22 00 04 04 00 26 00
        01 FF 09 00 00 00 00 00 01 00 B8 0D 00 00 01";

    /// 4.2: a LOGIN7 request.
    const LOGIN_EXAMPLE: &str = "10 01 00 90 00 00 01 00 88 00 00 00 02 00 09 72
        00 10 00 00 00 00 00 07 00 01 00 00 00 00 00 00
        E0 03 00 00 00 00 00 00 09 04 00 00 5E 00 08 00
        6E 00 02 00 72 00 00 00 72 00 07 00 80 00 00 00
        80 00 00 00 80 00 04 00 88 00 00 00 88 00 00 00
        00 50 8B E2 B7 8F 88 00 00 00 88 00 00 00 88 00
        00 00 00 00 00 00 73 00 6B 00 6F 00 73 00 74 00
        6F 00 76 00 31 00 73 00 61 00 4F 00 53 00 51 00
        4C 00 2D 00 33 00 32 00 4F 00 44 00 42 00 43 00";

    /// 4.6: a SQL batch.
    const BATCH_EXAMPLE: &str = "01 01 00 5C 00 00 01 00 16 00 00 00 12 00 00 00
        02 00 00 00 00 00 00 00 00 01 00 00 00 00 0A 00
        73 00 65 00 6C 00 65 00 63 00 74 00 20 00 27 00
        66 00 6F 00 6F 00 27 00 20 00 61 00 73 00 20 00
        27 00 62 00 61 00 72 00 27 00 0A 00 20 00 20 00
        20 00 20 00 20 00 20 00 20 00 20 00";

    /// 4.4: the server's answer to a login.
    const LOGIN_RESPONSE_EXAMPLE: &str = "04 01 01 61 00 00 01 00 E3 1B 00 01 06 6D 00 61
        00 73 00 74 00 65 00 72 00 06 6D 00 61 00 73 00
        74 00 65 00 72 00 AB 58 00 45 16 00 00 02 00 25
        00 43 00 68 00 61 00 6E 00 67 00 65 00 64 00 20
        00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65
        00 20 00 63 00 6F 00 6E 00 74 00 65 00 78 00 74
        00 20 00 74 00 6F 00 20 00 27 00 6D 00 61 00 73
        00 74 00 65 00 72 00 27 00 2E 00 00 00 00 00 00
        00 E3 08 00 07 05 09 04 D0 00 34 00 E3 17 00 02
        0A 75 00 73 00 5F 00 65 00 6E 00 67 00 6C 00 69
        00 73 00 68 00 00 E3 13 00 04 04 34 00 30 00 39
        00 36 00 04 34 00 30 00 39 00 36 00 AB 5C 00 47
        16 00 00 01 00 27 00 43 00 68 00 61 00 6E 00 67
        00 65 00 64 00 20 00 6C 00 61 00 6E 00 67 00 75
        00 61 00 67 00 65 00 20 00 73 00 65 00 74 00 74
        00 69 00 6E 00 67 00 20 00 74 00 6F 00 20 00 75
        00 73 00 5F 00 65 00 6E 00 67 00 6C 00 69 00 73
        00 68 00 2E 00 00 00 00 00 00 00 AD 36 00 01 72
        09 00 02 16 4D 00 69 00 63 00 72 00 6F 00 73 00
        6F 00 66 00 74 00 20 00 53 00 51 00 4C 00 20 00
        53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00
        00 00 00 00 FD 00 00 00 00 00 00 00 00 00 00 00
        00";

    /// 4.7: the server's answer to the batch.
    const BATCH_RESPONSE_EXAMPLE: &str = "04 01 00 33 00 00 01 00 81 01 00 00 00 00 00 20
        00 A7 03 00 09 04 D0 00 34 03 62 00 61 00 72 00
        D1 03 00 66 6F 6F FD 10 00 C1 00 01 00 00 00 00
        00 00 00";

    /// Feeds all of `b`, which must fit.
    fn put(d: &mut Decoder, b: &[u8]) {
        assert_eq!(d.feed(b), b.len());
    }

    fn one_message(bytes: &[u8]) -> Message {
        let mut d = Decoder::new();
        put(&mut d, bytes);
        let m = d.next_message().unwrap().unwrap();
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 0);
        m
    }

    #[test]
    fn prelogin_example() {
        let bytes = hex(PRELOGIN_EXAMPLE);
        let m = one_message(&bytes);
        assert_eq!(
            (m.packet_type, m.status, m.spid),
            (packet_type::PRELOGIN, status::EOM, 0)
        );
        let p = Prelogin::parse(&m.data).unwrap();
        assert_eq!(p.options.len(), 5);
        assert_eq!(
            p.version(),
            Some(Version {
                major: 9,
                minor: 0,
                build: 0,
                sub_build: 0
            })
        );
        assert_eq!(p.encryption(), Some(encryption::ON));
        assert_eq!(p.get(prelogin_option::INSTOPT), Some(&[0][..]));
        assert_eq!(
            p.get(prelogin_option::THREADID),
            Some(&[0xb8, 0x0d, 0, 0][..])
        );
        assert_eq!(p.get(prelogin_option::MARS), Some(&[1][..]));
        // Written back, it is the same bytes.
        assert_eq!(p.to_bytes(), m.data);
        assert_eq!(m.to_packets(4096).unwrap(), bytes);
    }

    #[test]
    fn login_example() {
        let bytes = hex(LOGIN_EXAMPLE);
        let m = one_message(&bytes);
        assert_eq!(m.packet_type, packet_type::LOGIN7);
        let l = Login7::parse(&m.data).unwrap();
        assert_eq!(l.tds_version, tds_version::V7_2);
        assert_eq!(l.packet_size, 4096);
        assert_eq!(l.client_prog_ver, 0x0700_0000);
        assert_eq!(l.client_pid, 256);
        assert_eq!(
            (
                l.option_flags1,
                l.option_flags2,
                l.type_flags,
                l.option_flags3
            ),
            (0xe0, 0x03, 0, 0)
        );
        assert_eq!(l.client_lcid, 0x0409);
        assert_eq!(l.host_name, "skostov1");
        assert_eq!(l.user_name, "sa");
        assert_eq!(l.password, "");
        assert_eq!(l.app_name, "OSQL-32");
        assert_eq!(l.client_interface, "ODBC");
        assert_eq!(l.client_id, [0x00, 0x50, 0x8b, 0xe2, 0xb7, 0x8f]);
        assert_eq!(l.features, None);
        // This writer lays the strings out the same way, but for
        // ibChangePassword: the example has 0x88 there without
        // fChangePassword, where 2.2.6.4 says it MUST be 0.
        let mut want = m.data.clone();
        assert_eq!(le16(&want, 86), 0x88);
        want[86..88].copy_from_slice(&[0, 0]);
        assert_eq!(l.to_bytes().unwrap(), want);
    }

    #[test]
    fn password_obfuscation() {
        // "a" is 0x61 0x00 in UTF-16: swapped 0x16, XOR 0xA5 = 0xB3;
        // 0x00 becomes 0xA5.
        let mut b = vec![0x61, 0x00];
        obfuscate(&mut b);
        assert_eq!(b, [0xb3, 0xa5]);
        assert_eq!(deobfuscate(&b), [0x61, 0x00]);
        let mut l = Login7::new();
        l.password = "s3cr\u{e9}t".to_string();
        l.option_flags3 = option_flags3::CHANGE_PASSWORD;
        l.change_password = "n\u{1f600}w".to_string();
        let bytes = l.to_bytes().unwrap();
        // The plain text is not on the wire.
        assert!(!bytes.windows(2).any(|w| w == [b's', 0]));
        assert_eq!(Login7::parse(&bytes).unwrap(), l);
    }

    #[test]
    fn login_round_trip_with_everything() {
        let mut l = Login7::new();
        l.host_name = "WS-17".into();
        l.user_name = "agent".into();
        l.password = "pw".into();
        l.app_name = "sqlcmd".into();
        l.server_name = "db.corp".into();
        l.client_interface = "ODBC".into();
        l.language = "us_english".into();
        l.database = "shop".into();
        l.attach_db_file = "C:\\data\\x.mdf".into();
        l.sspi = vec![0x60; 300];
        l.option_flags3 = option_flags3::USER_INSTANCE | option_flags3::EXTENSION;
        l.features = Some(vec![
            Feature {
                id: 0x04,
                data: vec![1, 2, 3],
            },
            Feature {
                id: 0x0a,
                data: vec![],
            },
        ]);
        let bytes = l.to_bytes().unwrap();
        assert_eq!(Login7::parse(&bytes).unwrap(), l);
        // An empty feature list is a pointer of 0.
        l.features = Some(vec![]);
        assert_eq!(Login7::parse(&l.to_bytes().unwrap()).unwrap(), l);
        // Without features the flag is cleared.
        l.features = None;
        let back = Login7::parse(&l.to_bytes().unwrap()).unwrap();
        assert_eq!(back.option_flags3, option_flags3::USER_INSTANCE);
    }

    /// Review finding: the writer cut a 129-character user name or
    /// password to 128 characters, so the login read back differently.
    /// It now refuses what it cannot write as given.
    #[test]
    fn login_writer_refuses_what_it_cannot_write() {
        let fits = Login7 {
            user_name: "u".repeat(MAX_LOGIN_NAME),
            password: "p".repeat(MAX_LOGIN_NAME),
            attach_db_file: "\u{1f600}".repeat(MAX_ATTACH_DB_FILE / 2),
            sspi: vec![1; MAX_SSPI],
            features: Some(
                (0..MAX_FEATURES)
                    .map(|i| Feature {
                        id: i as u8,
                        data: vec![],
                    })
                    .collect(),
            ),
            option_flags3: option_flags3::EXTENSION,
            ..Login7::new()
        };
        assert_eq!(Login7::parse(&fits.to_bytes().unwrap()), Ok(fits.clone()));
        let mut bad = Vec::new();
        let mut l = fits.clone();
        l.password.push('p');
        bad.push(l);
        let mut l = fits.clone();
        l.user_name.push('u');
        bad.push(l);
        let mut l = fits.clone();
        l.attach_db_file.push('a');
        bad.push(l);
        let mut l = fits.clone();
        l.sspi.push(1);
        bad.push(l);
        let mut l = fits.clone();
        l.features.as_mut().unwrap().push(Feature {
            id: 1,
            data: vec![],
        });
        bad.push(l);
        let mut l = fits.clone();
        l.features = Some(vec![Feature {
            id: 0xff,
            data: vec![],
        }]);
        bad.push(l);
        let mut l = fits.clone();
        l.features = Some(vec![Feature {
            id: 1,
            data: vec![0; MAX_LOGIN7],
        }]);
        bad.push(l);
        for l in bad {
            assert_eq!(l.to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn login_errors() {
        let good = Login7 {
            user_name: "sa".into(),
            ..Login7::new()
        }
        .to_bytes()
        .unwrap();
        assert_eq!(Login7::parse(&good[..93]), Err(Error::Truncated));
        // A length below the fixed part, and past the data.
        let mut b = good.clone();
        b[0] = 10;
        assert_eq!(Login7::parse(&b), Err(Error::Invalid("LOGIN7 length")));
        let mut b = good.clone();
        b[0] = 200;
        assert_eq!(Login7::parse(&b), Err(Error::Truncated));
        // A string past the record's end.
        let mut b = good.clone();
        b[40] = 0xf0;
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid("LOGIN7 field outside the record"))
        );
        // A string over its limit.
        let mut b = good.clone();
        b[42] = 200;
        assert_eq!(Login7::parse(&b), Err(Error::Limit("LOGIN7 string")));
        // SSPI over the limit, through cbSSPILong.
        let mut b = good.clone();
        b[80..82].copy_from_slice(&[0xff, 0xff]);
        b[90..94].copy_from_slice(&100_000u32.to_le_bytes());
        assert_eq!(Login7::parse(&b), Err(Error::Limit("LOGIN7 SSPI data")));
        // An extension flag with too short an extension.
        let mut b = good.clone();
        b[27] = option_flags3::EXTENSION;
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid("LOGIN7 extension length"))
        );
        // A feature block without its terminator, and one pointing away.
        let mut l = Login7::new();
        l.features = Some(vec![Feature {
            id: 1,
            data: vec![9],
        }]);
        let b = l.to_bytes().unwrap();
        let cut = b.len() - 1;
        let mut short = b[..cut].to_vec();
        short[0..4].copy_from_slice(&(cut as u32).to_le_bytes());
        assert_eq!(Login7::parse(&short), Err(Error::Truncated));
        let mut away = b.clone();
        let p = usize::from(le16(&b, 56));
        away[p..p + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(
            Login7::parse(&away),
            Err(Error::Invalid("LOGIN7 feature block outside the record"))
        );
        // Too many features.
        let mut many = vec![0u8; 0];
        for _ in 0..=MAX_FEATURES {
            many.extend_from_slice(&[1, 0, 0, 0, 0]);
        }
        many.push(0xff);
        assert_eq!(parse_features(&many), Err(Error::Limit("feature options")));
    }

    #[test]
    fn batch_example() {
        let bytes = hex(BATCH_EXAMPLE);
        let m = one_message(&bytes);
        let b = SqlBatch::parse(&m.data, true).unwrap();
        assert_eq!(
            b.headers,
            Some(vec![StreamHeader::transaction_descriptor(1 << 56, 0)])
        );
        assert_eq!(b.text, "\nselect 'foo' as 'bar'\n        ");
        assert_eq!(b.to_bytes(), m.data);
        let new = SqlBatch::new("SELECT 1");
        assert_eq!(
            new.headers,
            Some(vec![StreamHeader::transaction_descriptor(0, 1)])
        );
        assert_eq!(new.transaction_descriptor(), Some((0, 1)));
        assert_eq!(b.transaction_descriptor(), Some((1 << 56, 0)));
        assert_eq!(SqlBatch::parse(&new.to_bytes(), true), Ok(new));
        // Without headers: TDS 7.1.
        let old = SqlBatch {
            headers: None,
            text: "SELECT 1".into(),
        };
        assert_eq!(old.transaction_descriptor(), None);
        assert_eq!(SqlBatch::parse(&old.to_bytes(), false), Ok(old));
    }

    #[test]
    fn batch_errors() {
        assert_eq!(SqlBatch::parse(&[1, 0], true), Err(Error::Truncated));
        assert_eq!(
            SqlBatch::parse(&[2, 0, 0, 0], true),
            Err(Error::Invalid("ALL_HEADERS length"))
        );
        assert_eq!(
            SqlBatch::parse(&[9, 0, 0, 0, 0], true),
            Err(Error::Truncated)
        );
        // A header shorter than its own length and type.
        assert_eq!(
            SqlBatch::parse(&[8, 0, 0, 0, 5, 0, 0, 0], true),
            Err(Error::Invalid("header length"))
        );
        // A header running past the block.
        assert_eq!(
            SqlBatch::parse(&[10, 0, 0, 0, 7, 0, 0, 0, 2, 0], true),
            Err(Error::Truncated)
        );
        assert_eq!(
            SqlBatch::parse(&[b'a', 0, b'b'], false),
            Err(Error::Invalid("UTF-16 text of odd length"))
        );
        let many = SqlBatch {
            headers: Some(
                (0..=MAX_HEADERS as u16)
                    .map(|i| StreamHeader {
                        kind: 10 + i,
                        data: vec![],
                    })
                    .collect(),
            ),
            text: String::new(),
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(4 + 6 * (MAX_HEADERS as u32 + 1)).to_le_bytes());
        for i in 0..=MAX_HEADERS as u8 {
            bytes.extend_from_slice(&[6, 0, 0, 0, 10 + i, 0]);
        }
        assert_eq!(
            SqlBatch::parse(&bytes, true),
            Err(Error::Limit("ALL_HEADERS headers"))
        );
        // The writer leaves the extra header out.
        assert_eq!(
            SqlBatch::parse(&many.to_bytes(), true)
                .unwrap()
                .headers
                .unwrap()
                .len(),
            MAX_HEADERS
        );
    }

    #[test]
    fn login_response_example() {
        let bytes = hex(LOGIN_RESPONSE_EXAMPLE);
        let m = one_message(&bytes);
        assert_eq!(m.packet_type, packet_type::TABULAR_RESULT);
        let tokens: Vec<Token> = TokenReader::new(&m.data).collect::<Result<_, _>>().unwrap();
        assert_eq!(tokens.len(), 8);
        assert_eq!(
            tokens[0],
            Token::EnvChange(EnvChange::Text {
                kind: env_type::DATABASE,
                new: "master".into(),
                old: "master".into()
            })
        );
        let Token::Info(info) = &tokens[1] else {
            panic!()
        };
        assert_eq!((info.number, info.state, info.class), (5701, 2, 0));
        assert_eq!(info.text, "Changed database context to 'master'.");
        assert_eq!(
            tokens[2],
            Token::EnvChange(EnvChange::Bytes {
                kind: env_type::COLLATION,
                new: DEFAULT_COLLATION.to_vec(),
                old: vec![]
            })
        );
        assert_eq!(
            tokens[3],
            Token::EnvChange(EnvChange::Text {
                kind: env_type::LANGUAGE,
                new: "us_english".into(),
                old: "".into()
            })
        );
        assert_eq!(
            tokens[4],
            Token::EnvChange(EnvChange::Text {
                kind: env_type::PACKET_SIZE,
                new: "4096".into(),
                old: "4096".into()
            })
        );
        let Token::Info(info) = &tokens[5] else {
            panic!()
        };
        assert_eq!(info.number, 5703);
        assert_eq!(
            tokens[6],
            Token::LoginAck(LoginAck {
                interface: 1,
                tds_version: tds_version::V7_2,
                prog_name: "Microsoft SQL Server\0\0".into(),
                prog_version: [0, 0, 0, 0],
            })
        );
        assert_eq!(tokens[7], Token::Done(Done::new(0, 0)));
        // Written back, it is the same bytes.
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap();
        }
        assert_eq!(w.bytes(), &m.data[..]);
    }

    #[test]
    fn batch_response_example() {
        let bytes = hex(BATCH_RESPONSE_EXAMPLE);
        let m = one_message(&bytes);
        let tokens: Vec<Token> = TokenReader::new(&m.data).collect::<Result<_, _>>().unwrap();
        let col = Column {
            user_type: 0,
            flags: 0x0020,
            type_info: TypeInfo::string(data_type::BIGVARCHAR, 3),
            name: "bar".into(),
        };
        assert_eq!(
            tokens,
            [
                Token::ColMetadata(Some(vec![col])),
                Token::Row(vec![Value::Bytes(b"foo".to_vec())]),
                Token::Done(Done {
                    status: done_status::COUNT,
                    cur_cmd: 0xc1,
                    row_count: 1
                }),
            ]
        );
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap();
        }
        assert_eq!(w.into_bytes(), m.data);
    }

    #[test]
    fn packets_and_reassembly() {
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let m = Message {
            packet_type: packet_type::SQL_BATCH,
            status: status::EOM | status::RESET_CONNECTION,
            spid: 0,
            data,
        };
        let bytes = m.to_packets(512).unwrap();
        // 5000 bytes in packets of 504 bytes of data: 10 packets.
        assert_eq!(bytes.len(), 5000 + 10 * HEADER_LEN);
        let (first, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, 512);
        assert_eq!((first.status, first.id), (status::RESET_CONNECTION, 1));
        assert_eq!(first.to_bytes(), bytes[..512]);
        // Every prefix of a packet is incomplete.
        for n in 0..512 {
            assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{n} bytes");
        }
        // Byte by byte, the message comes out once, at the end.
        let mut d = Decoder::new();
        for (i, b) in bytes.iter().enumerate() {
            put(&mut d, std::slice::from_ref(b));
            let got = d.next_message();
            if i + 1 < bytes.len() {
                assert_eq!(got, None, "byte {i}");
            } else {
                assert_eq!(got, Some(Ok(m.clone())));
            }
        }
        // An empty message is one header.
        let empty = Message::new(packet_type::ATTENTION, vec![]);
        assert_eq!(empty.to_packets(4096).unwrap(), [6, 1, 0, 8, 0, 0, 1, 0]);
        assert_eq!(one_message(&empty.to_packets(4096).unwrap()), empty);
        // Packet sizes are held in range; packet IDs wrap.
        let big = Message::new(packet_type::BULK_LOAD, vec![7; 300 * 504]);
        let bytes = big.to_packets(1).unwrap();
        assert_eq!(bytes.len(), 300 * 512);
        assert_eq!(bytes[256 * 512 + 6], 1);
        assert_eq!(one_message(&bytes), big);
        assert_eq!(
            Message::new(1, vec![0; 70_000])
                .to_packets(100_000)
                .unwrap()[2..4],
            32767u16.to_be_bytes()
        );
    }

    #[test]
    fn frame_errors() {
        assert_eq!(Packet::parse(&[1, 1, 0, 7]), Err(FrameError::Length(7)));
        let mut d = Decoder::new();
        put(&mut d, &[1, 1, 0, 3]);
        assert_eq!(d.next_message(), Some(Err(FrameError::Length(3))));
        // A broken stream stays broken.
        put(&mut d, &Message::new(1, vec![]).to_packets(512).unwrap());
        assert_eq!(d.next_message(), Some(Err(FrameError::Length(3))));
        assert_eq!(d.buffered(), 0);
        // A type change in the middle of a message.
        let mut d = Decoder::new();
        put(&mut d, &[1, 0, 0, 9, 0, 0, 1, 0, b'x', 3, 1, 0, 8]);
        assert_eq!(
            d.next_message(),
            Some(Err(FrameError::TypeChanged {
                expected: 1,
                got: 3
            }))
        );
        // Too long, known from the header alone.
        let mut d = Decoder::with_limit(10);
        put(&mut d, &[1, 0, 0, 16, 0, 0, 1, 0]);
        assert_eq!(d.buffered(), 8);
        put(&mut d, &[1, 1, 0, 11]);
        assert_eq!(d.next_message(), None);
        let mut d = Decoder::with_limit(10);
        put(
            &mut d,
            &[1, 0, 0, 16, 0, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1, 0, 11],
        );
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLong(11))));
        for e in [
            FrameError::Length(1),
            FrameError::TypeChanged {
                expected: 1,
                got: 2,
            },
            FrameError::TooLong(5),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_takes_many_small_messages_in_linear_time() {
        let one = Message::new(packet_type::SQL_BATCH, vec![b'x', 0])
            .to_packets(512)
            .unwrap();
        let stream: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(one.len() * 200_000)
            .collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        put(&mut d, &stream);
        let mut n = 0;
        while let Some(m) = d.next_message() {
            m.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn prelogin_errors_and_limits() {
        assert_eq!(Prelogin::parse(&[]), Err(Error::Truncated));
        assert_eq!(Prelogin::parse(&[0, 0, 6]), Err(Error::Truncated));
        assert_eq!(
            Prelogin::parse(&[0, 0, 6, 0, 6, 0xff]),
            Err(Error::Invalid("PRELOGIN option outside the message"))
        );
        let mut many = Vec::new();
        for _ in 0..=MAX_PRELOGIN_OPTIONS {
            many.extend_from_slice(&[1, 0, 0, 0, 0]);
        }
        many.push(0xff);
        assert_eq!(
            Prelogin::parse(&many),
            Err(Error::Limit("PRELOGIN options"))
        );
        // Two options sharing 40000 bytes do not fit end to end.
        let mut shared = vec![0, 0, 11, 0x9c, 0x40, 1, 0, 11, 0x9c, 0x40, 0xff];
        shared.resize(11 + 40000, 0);
        assert_eq!(
            Prelogin::parse(&shared),
            Err(Error::Limit("PRELOGIN option data"))
        );
        // The writer leaves out what does not fit.
        let mut p = Prelogin::new(Version::default(), encryption::OFF);
        p.set(prelogin_option::TERMINATOR, vec![1]);
        p.set(prelogin_option::TRACEID, vec![0; 70000]);
        p.set(prelogin_option::MARS, vec![0]);
        let back = Prelogin::parse(&p.to_bytes()).unwrap();
        let tokens: Vec<u8> = back.options.iter().map(|o| o.token).collect();
        assert_eq!(
            tokens,
            [
                prelogin_option::VERSION,
                prelogin_option::ENCRYPTION,
                prelogin_option::MARS
            ]
        );
        // Version and encryption read as None when malformed.
        p.set(prelogin_option::VERSION, vec![1]);
        p.set(prelogin_option::ENCRYPTION, vec![]);
        assert_eq!((p.version(), p.encryption()), (None, None));
    }

    fn all_types() -> Vec<Column> {
        use data_type::*;
        let mut v: Vec<Column> = [
            INT1, BIT, INT2, INT4, DATETIM4, FLT4, MONEY, DATETIME, FLT8, MONEY4, INT8, DATEN,
        ]
        .iter()
        .map(|&t| Column::new("f", TypeInfo::fixed(t)))
        .collect();
        for (t, n) in [
            (INTN, 4),
            (BITN, 1),
            (FLTN, 8),
            (MONEYN, 8),
            (DATETIMN, 8),
            (GUID, 16),
        ] {
            v.push(Column::new("n", TypeInfo::nullable(t, n)));
        }
        v.push(Column::new("d", TypeInfo::decimal(18, 2)));
        v.push(Column::new("t", TypeInfo::scaled(TIMEN, 7)));
        v.push(Column::new("t2", TypeInfo::scaled(DATETIME2N, 3)));
        v.push(Column::new("to", TypeInfo::scaled(DATETIMEOFFSETN, 0)));
        v.push(Column::new("s", TypeInfo::string(NVARCHAR, 40)));
        v.push(Column::new("m", TypeInfo::string(NVARCHAR, 0xffff)));
        v.push(Column::new("c", TypeInfo::string(BIGCHAR, 4)));
        v.push(Column::new("b", TypeInfo::binary(BIGVARBINARY, 0xffff)));
        v.push(Column::new("bb", TypeInfo::binary(BIGBINARY, 2)));
        v.push(Column {
            user_type: 0,
            flags: 1,
            type_info: TypeInfo {
                max_len: 8016,
                ..TypeInfo::bare(SSVARIANT)
            },
            name: "v".into(),
        });
        v
    }

    fn all_values() -> Vec<Value> {
        vec![
            Value::TinyInt(200),
            Value::Bit(true),
            Value::SmallInt(-2),
            Value::Int(-70000),
            Value::SmallDateTime {
                days: 45000,
                minutes: 600,
            },
            Value::Real(1.5f32.to_bits()),
            Value::Money(-12_3456),
            Value::DateTime {
                days: -1,
                ticks: 300,
            },
            Value::Float(f64::NAN.to_bits()),
            Value::SmallMoney(5),
            Value::BigInt(i64::MIN),
            Value::Date(738000),
            Value::Int(5),
            Value::Null,
            Value::Float(2.0f64.to_bits()),
            Value::Money(1 << 40),
            Value::DateTime { days: 1, ticks: 2 },
            Value::Guid([7; 16]),
            Value::Decimal {
                positive: false,
                value: 123_456_789_012_345,
            },
            Value::Time(863_999_999_999),
            Value::DateTime2 {
                time: 1000,
                date: 3,
            },
            Value::DateTimeOffset {
                time: 86399,
                date: 9,
                offset: -300,
            },
            Value::Text("h\u{e9}llo".into()),
            Value::Text("x".repeat(3000)),
            Value::Bytes(b"abcd".to_vec()),
            Value::Bytes(vec![]),
            Value::Bytes(vec![1, 2]),
            Value::Bytes(vec![0x38, 0, 1, 0, 0, 0]),
        ]
    }

    #[test]
    fn rows_round_trip_for_every_type() {
        let cols = all_types();
        let values = all_values();
        let mut nulls: Vec<Value> = values.clone();
        // NBCROW can make even fixed columns null.
        for v in nulls.iter_mut().step_by(2) {
            *v = Value::Null;
        }
        let tokens = vec![
            Token::ColMetadata(Some(cols.clone())),
            Token::Row(values.clone()),
            Token::NbcRow(nulls),
            Token::NbcRow(values),
            Token::ColMetadata(None),
            Token::DoneInProc(Done::new(done_status::COUNT | done_status::MORE, 3)),
            Token::ReturnStatus(-6),
            Token::DoneProc(Done::new(0, 0)),
        ];
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap();
        }
        let bytes = w.into_bytes();
        let mut r = TokenReader::new(&bytes);
        let back: Vec<Token> = r.by_ref().collect::<Result<_, _>>().unwrap();
        assert_eq!(back, tokens);
        assert_eq!(r.position(), bytes.len());
        assert_eq!(r.columns(), Some(&cols[..]));
        // Every truncated prefix fails on its last token, never panics.
        let ends: Vec<usize> = {
            let mut r = TokenReader::new(&bytes);
            let mut ends = Vec::new();
            while r.next().is_some() {
                ends.push(r.position());
            }
            ends
        };
        for n in 0..bytes.len() {
            let got: Vec<_> = TokenReader::new(&bytes[..n]).collect();
            if ends.contains(&n) || n == 0 {
                assert!(got.iter().all(|t| t.is_ok()), "{n}");
            } else {
                assert!(got.last().unwrap().is_err(), "{n}");
            }
        }
    }

    #[test]
    fn other_tokens() {
        let tokens = vec![
            Token::EnvChange(EnvChange::Routing {
                protocol: 0,
                port: 1433,
                server: "replica.db".into(),
                database: None,
            }),
            Token::EnvChange(EnvChange::Routing {
                protocol: 0,
                port: 1,
                server: "a".into(),
                database: Some("b".into()),
            }),
            Token::EnvChange(EnvChange::PromoteTransaction(vec![1, 2, 3])),
            Token::EnvChange(EnvChange::Bytes {
                kind: env_type::BEGIN_TRANSACTION,
                new: vec![1; 8],
                old: vec![],
            }),
            Token::EnvChange(EnvChange::Other {
                kind: 99,
                data: vec![4, 5],
            }),
            Token::Error(ServerMessage {
                number: 208,
                state: 1,
                class: 16,
                text: "Invalid object name 'x'.".into(),
                server: "db".into(),
                procedure: "".into(),
                line: 1,
            }),
            Token::FeatureExtAck(vec![Feature {
                id: 1,
                data: vec![1],
            }]),
            Token::Other {
                token: token::ORDER,
                data: vec![1, 0],
            },
            Token::Other {
                token: token::SESSIONSTATE,
                data: vec![0; 9],
            },
            Token::Other {
                token: token::OFFSET,
                data: vec![1, 2, 3, 4],
            },
        ];
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap();
        }
        let back: Vec<Token> = TokenReader::new(w.bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(back, tokens);
    }

    #[test]
    fn writer_refuses_what_would_not_read_back() {
        let mut w = TokenWriter::new();
        assert_eq!(w.push(&Token::Row(vec![])), Err(Error::NoColumns));
        let cols = vec![Column::new("a", TypeInfo::fixed(data_type::INT4))];
        w.push(&Token::ColMetadata(Some(cols))).unwrap();
        let before = w.bytes().len();
        for bad in [
            Token::Row(vec![]),
            Token::Row(vec![Value::Null]),
            Token::Row(vec![Value::BigInt(1)]),
            Token::Row(vec![Value::Text("x".into())]),
            Token::Other {
                token: token::DONE,
                data: vec![],
            },
            Token::Other {
                token: token::OFFSET,
                data: vec![1],
            },
            Token::Other {
                token: 0x01,
                data: vec![],
            },
            Token::EnvChange(EnvChange::Text {
                kind: env_type::COLLATION,
                new: "x".into(),
                old: "".into(),
            }),
            Token::EnvChange(EnvChange::Text {
                kind: 1,
                new: "x".repeat(300),
                old: "".into(),
            }),
            Token::Info(ServerMessage {
                number: 0,
                state: 0,
                class: 0,
                text: "x".repeat(40000),
                server: "".into(),
                procedure: "".into(),
                line: 0,
            }),
            Token::ColMetadata(Some(vec![Column::new(
                "x",
                TypeInfo::nullable(data_type::INTN, 3),
            )])),
            Token::ColMetadata(Some(vec![Column::new("x", TypeInfo::decimal(0, 0))])),
            Token::ColMetadata(Some(vec![Column::new("x", TypeInfo::fixed(0x23))])),
            Token::ColMetadata(Some(vec![Column::new(
                "x",
                TypeInfo::nullable(data_type::INT4, 4),
            )])),
            Token::ColMetadata(Some(vec![
                Column::new("x", TypeInfo::fixed(data_type::INT4));
                MAX_COLUMNS + 1
            ])),
            Token::FeatureExtAck(vec![Feature {
                id: 0xff,
                data: vec![],
            }]),
        ] {
            assert_eq!(w.push(&bad), Err(Error::Unwritable), "{bad:?}");
            assert_eq!(w.bytes().len(), before);
        }
        // Still usable.
        w.push(&Token::Row(vec![Value::Int(1)])).unwrap();
    }

    #[test]
    fn token_errors() {
        let errs: Vec<(Vec<u8>, Error)> = vec![
            (vec![0x01], Error::UnknownToken(0x01)),
            (vec![token::ROW], Error::NoColumns),
            (vec![token::DONE, 0, 0], Error::Truncated),
            (
                vec![token::COLMETADATA, 0x01, 0x10],
                Error::Limit("columns"),
            ),
            (
                vec![token::COLMETADATA, 1, 0, 0, 0, 0, 0, 0, 0, 0x23],
                Error::UnsupportedType(0x23),
            ),
            (
                vec![token::COLMETADATA, 1, 0, 0, 0, 0, 0, 0, 0, 0x26, 3, 0],
                Error::Invalid("column length"),
            ),
            (
                vec![token::COLMETADATA, 1, 0, 0, 0, 0, 0, 0, 0, 0x6a, 5, 0, 0, 0],
                Error::Invalid("decimal precision or scale"),
            ),
            (
                vec![token::COLMETADATA, 1, 0, 0, 0, 0, 0, 0, 0, 0x29, 8, 0],
                Error::Invalid("time scale"),
            ),
            (
                vec![
                    token::COLMETADATA,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0xad,
                    0xff,
                    0xff,
                    0,
                ],
                Error::Invalid("column length"),
            ),
            (
                vec![token::LOGINACK, 11, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                Error::Invalid("bytes after the token's fields"),
            ),
            (
                vec![token::ENVCHANGE, 6, 0, 15, 0, 0, 0, 0, 1],
                Error::Invalid("ENVCHANGE old value"),
            ),
            (
                vec![token::ENVCHANGE, 10, 0, 20, 5, 0, 0, 1, 0, 0, 0, 1, 0],
                Error::Invalid("ENVCHANGE old value"),
            ),
            (vec![token::ENVCHANGE, 3, 0, 20, 0, 0], Error::Truncated),
        ];
        for (b, e) in errs {
            assert_eq!(TokenReader::new(&b).next(), Some(Err(e)), "{b:x?}");
        }
        // Row values out of their range.
        let one = |ti: TypeInfo, row: &[u8]| {
            let mut w = TokenWriter::new();
            w.push(&Token::ColMetadata(Some(vec![Column::new("c", ti)])))
                .unwrap();
            let mut b = w.into_bytes();
            b.push(token::ROW);
            b.extend_from_slice(row);
            TokenReader::new(&b).nth(1).unwrap()
        };
        assert_eq!(
            one(TypeInfo::nullable(data_type::INTN, 4), &[3, 0, 0, 0]),
            Err(Error::Invalid("value length"))
        );
        assert_eq!(
            one(TypeInfo::decimal(5, 0), &[3, 1, 0]),
            Err(Error::Invalid("decimal length"))
        );
        assert_eq!(
            one(TypeInfo::decimal(5, 0), &[5, 2, 0, 0, 0, 0]),
            Err(Error::Invalid("decimal sign"))
        );
        assert_eq!(
            one(TypeInfo::fixed(data_type::DATEN), &[2, 0, 0]),
            Err(Error::Invalid("date length"))
        );
        assert_eq!(
            one(TypeInfo::scaled(data_type::TIMEN, 7), &[3, 0, 0, 0]),
            Err(Error::Invalid("time length"))
        );
        assert_eq!(
            one(TypeInfo::string(data_type::NVARCHAR, 10), &[1, 0, 0]),
            Err(Error::Invalid("UTF-16 text of odd length"))
        );
        assert_eq!(
            one(
                TypeInfo::binary(data_type::BIGVARBINARY, 0xffff),
                &[5, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0]
            ),
            Err(Error::Invalid("PLP length"))
        );
        // A PLP of unknown length, in two chunks.
        let v = one(
            TypeInfo::binary(data_type::BIGVARBINARY, 0xffff),
            &[
                0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 9, 1, 0, 0, 0, 8, 0, 0,
                0, 0,
            ],
        );
        assert_eq!(v, Ok(Token::Row(vec![Value::Bytes(vec![9, 8])])));
        for e in [
            Error::Truncated,
            Error::Invalid("x"),
            Error::Limit("x"),
            Error::UnknownToken(1),
            Error::UnsupportedType(1),
            Error::NoColumns,
            Error::Unwritable,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    // Problems found in review against MS-TDS, one test each.

    /// 2.2.6.4: the offset table has ibAtchDBFile at byte 82 and
    /// ibChangePassword at byte 86, in that order.
    #[test]
    fn login_attach_file_and_change_password_offsets() {
        let mut l = Login7::new();
        l.attach_db_file = "a.mdf".into();
        l.option_flags3 = option_flags3::CHANGE_PASSWORD;
        l.change_password = "new".into();
        let b = l.to_bytes().unwrap();
        assert_eq!(le16(&b, 84), 5, "cchAtchDBFile");
        assert_eq!(le16(&b, 88), 3, "cchChangePassword");
        let at = usize::from(le16(&b, 82));
        assert_eq!(utf16_string(&b[at..at + 10]), "a.mdf");
        let at = usize::from(le16(&b, 86));
        assert_eq!(utf16_string(&deobfuscate(&b[at..at + 6])), "new");
    }

    /// 2.2.6.4: a LOGIN7 record is at most 128K-1 bytes, cbExtension is
    /// at most 255, ibHostName points at the variable part, and data lies
    /// after the fixed part.
    #[test]
    fn login_spec_rules() {
        let good = Login7 {
            user_name: "sa".into(),
            ..Login7::new()
        }
        .to_bytes()
        .unwrap();
        let mut b = good.clone();
        b[0..4].copy_from_slice(&(MAX_LOGIN7 as u32 + 1).to_le_bytes());
        b.resize(MAX_LOGIN7 + 1, 0);
        assert_eq!(Login7::parse(&b), Err(Error::Invalid("LOGIN7 length")));
        let mut b = good.clone();
        b[36..38].copy_from_slice(&[0, 0]);
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid("LOGIN7 host name offset"))
        );
        // The user name pointing into the fixed part.
        let mut b = good.clone();
        b[40..42].copy_from_slice(&[4, 0]);
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid("LOGIN7 field outside the record"))
        );
        let mut l = Login7::new();
        l.features = Some(vec![Feature {
            id: 1,
            data: vec![],
        }]);
        let b = l.to_bytes().unwrap();
        let mut long = b.clone();
        long[58..60].copy_from_slice(&256u16.to_le_bytes());
        assert_eq!(
            Login7::parse(&long),
            Err(Error::Invalid("LOGIN7 extension length"))
        );
        let mut inside = b.clone();
        let p = usize::from(le16(&b, 56));
        inside[p..p + 4].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(
            Login7::parse(&inside),
            Err(Error::Invalid("LOGIN7 feature block outside the record"))
        );
        // The writer refuses a record past the limit, and writes one at
        // it.
        l.sspi = vec![1; MAX_SSPI];
        l.features = Some(vec![
            Feature {
                id: 1,
                data: vec![2; 50_000],
            },
            Feature {
                id: 2,
                data: vec![3; 50_000],
            },
            Feature {
                id: 3,
                data: vec![4; 10],
            },
        ]);
        assert_eq!(l.to_bytes(), Err(Error::Unwritable));
        l.features.as_mut().unwrap().remove(1);
        let b = l.to_bytes().unwrap();
        assert!(b.len() <= MAX_LOGIN7);
        let back = Login7::parse(&b).unwrap();
        let ids: Vec<u8> = back.features.unwrap().iter().map(|f| f.id).collect();
        assert_eq!(ids, [1, 3]);
    }

    /// 2.2.6.5: VERSION is required, 6 bytes long, and the first option.
    #[test]
    fn prelogin_version_first() {
        // ENCRYPTION alone.
        assert_eq!(
            Prelogin::parse(&[1, 0, 6, 0, 1, 0xff, 2]),
            Err(Error::Invalid("PRELOGIN VERSION not first"))
        );
        assert_eq!(
            Prelogin::parse(&[0xff]),
            Err(Error::Invalid("PRELOGIN VERSION not first"))
        );
        assert_eq!(
            Prelogin::parse(&[0, 0, 6, 0, 2, 0xff, 9, 0]),
            Err(Error::Invalid("PRELOGIN VERSION length"))
        );
        // The writer puts VERSION first, at 6 bytes, adding one if needed.
        let mut p = Prelogin::default();
        p.set(prelogin_option::ENCRYPTION, vec![encryption::OFF]);
        p.set(prelogin_option::VERSION, vec![1, 2, 3]);
        let back = Prelogin::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.options[0].token, prelogin_option::VERSION);
        assert_eq!(back.options[0].data, [1, 2, 3, 0, 0, 0]);
        assert_eq!(back.encryption(), Some(encryption::OFF));
        let empty = Prelogin::parse(&Prelogin::default().to_bytes()).unwrap();
        assert_eq!(empty.version(), Some(Version::default()));
    }

    /// 2.2.7.9: a Promote Transaction ENVCHANGE has length 1, and its
    /// DTC token and old value follow outside that length.
    #[test]
    fn envchange_promote_transaction_length() {
        let spec = [
            token::ENVCHANGE,
            1,
            0,
            15,
            3,
            0,
            0,
            0,
            7,
            8,
            9,
            0,
            token::DONE,
        ];
        let mut r = TokenReader::new(&spec);
        assert_eq!(
            r.next(),
            Some(Ok(Token::EnvChange(EnvChange::PromoteTransaction(vec![
                7, 8, 9
            ]))))
        );
        assert_eq!(r.position(), 12);
        let mut w = TokenWriter::new();
        w.push(&Token::EnvChange(EnvChange::PromoteTransaction(vec![
            7, 8, 9,
        ])))
        .unwrap();
        assert_eq!(w.bytes(), &spec[..12]);
    }

    /// 2.2.7.9: routing needs protocol 0, a port other than 0, and a
    /// database name of at most 128 characters.
    #[test]
    fn envchange_routing_rules() {
        let route = |protocol: u8, port: u16, db: Option<String>| {
            let mut r = vec![protocol];
            r.extend_from_slice(&port.to_le_bytes());
            put_us_varchar(&mut r, "s");
            if let Some(db) = &db {
                put_us_varchar(&mut r, db);
            }
            let mut body = vec![if db.is_some() { 21 } else { 20 }];
            body.extend_from_slice(&(r.len() as u16).to_le_bytes());
            body.extend_from_slice(&r);
            body.extend_from_slice(&[0, 0]);
            let mut b = vec![token::ENVCHANGE];
            b.extend_from_slice(&(body.len() as u16).to_le_bytes());
            b.extend_from_slice(&body);
            TokenReader::new(&b).next().unwrap()
        };
        assert!(route(0, 1, None).is_ok());
        assert_eq!(route(1, 1, None), Err(Error::Invalid("routing protocol")));
        assert_eq!(route(0, 0, None), Err(Error::Invalid("routing port")));
        assert_eq!(
            route(0, 1, Some("d".repeat(129))),
            Err(Error::Limit("routing database"))
        );
    }

    /// 2.2.5.3: a SQL batch's ALL_HEADERS block needs a transaction
    /// descriptor of 12 bytes, and each header type at most once.
    #[test]
    fn batch_header_rules() {
        let block = |headers: &[(u16, &[u8])]| {
            let mut b = vec![0; 4];
            for (kind, data) in headers {
                b.extend_from_slice(&(6 + data.len() as u32).to_le_bytes());
                b.extend_from_slice(&kind.to_le_bytes());
                b.extend_from_slice(data);
            }
            let n = b.len() as u32;
            b[0..4].copy_from_slice(&n.to_le_bytes());
            SqlBatch::parse(&b, true)
        };
        let td: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
        assert!(block(&[(2, td)]).is_ok());
        assert_eq!(
            block(&[]),
            Err(Error::Invalid(
                "ALL_HEADERS without a transaction descriptor"
            ))
        );
        assert_eq!(
            block(&[(1, &[0, 0, 0, 0])]),
            Err(Error::Invalid(
                "ALL_HEADERS without a transaction descriptor"
            ))
        );
        assert_eq!(
            block(&[(2, &td[..8])]),
            Err(Error::Invalid("transaction descriptor length"))
        );
        assert_eq!(
            block(&[(2, td), (2, td)]),
            Err(Error::Invalid("header type repeated"))
        );
        // The writer adds a descriptor, keeps the first of each type, and
        // fixes the descriptor's length.
        let b = SqlBatch {
            headers: Some(vec![
                StreamHeader {
                    kind: 3,
                    data: vec![1; 20],
                },
                StreamHeader {
                    kind: 3,
                    data: vec![2; 20],
                },
            ]),
            text: "x".into(),
        };
        let back = SqlBatch::parse(&b.to_bytes(), true).unwrap();
        assert_eq!(
            back.headers.unwrap(),
            [
                StreamHeader::transaction_descriptor(0, 1),
                StreamHeader {
                    kind: 3,
                    data: vec![1; 20]
                },
            ]
        );
        let b = SqlBatch {
            headers: Some(vec![StreamHeader {
                kind: 2,
                data: vec![5],
            }]),
            text: String::new(),
        };
        let back = SqlBatch::parse(&b.to_bytes(), true).unwrap();
        assert_eq!(
            back.headers.unwrap()[0].data,
            [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    /// LOGIN7 fields may share bytes on the wire. A record whose feature
    /// block lies inside its SSPI data reads, but laid out one after the
    /// other the fields pass MAX_LOGIN7, and the writer would drop the
    /// features. The reader refuses such a record, so what it reads
    /// writes back the same.
    #[test]
    fn login_overlapping_fields_past_the_limit() {
        let mut block = vec![1u8];
        block.extend_from_slice(&65000u32.to_le_bytes());
        block.extend(std::iter::repeat_n(7u8, 65000));
        block.push(0xff);
        block.resize(MAX_SSPI, 0);
        let mut l = Login7::new();
        for s in [
            &mut l.host_name,
            &mut l.user_name,
            &mut l.app_name,
            &mut l.server_name,
            &mut l.client_interface,
            &mut l.language,
            &mut l.database,
        ] {
            *s = "h".repeat(MAX_LOGIN_NAME);
        }
        l.attach_db_file = "a".repeat(MAX_ATTACH_DB_FILE);
        l.sspi = block;
        l.features = Some(vec![]);
        let mut b = l.to_bytes().unwrap();
        // Point the extension at the SSPI data.
        let sspi_at = le16(&b, 78);
        let ext_at = usize::from(le16(&b, 56));
        b[ext_at..ext_at + 4].copy_from_slice(&u32::from(sspi_at).to_le_bytes());
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Limit("LOGIN7 fields laid end to end"))
        );
        // A smaller overlap still reads, and round trips.
        let mut small = l.clone();
        small.host_name.clear();
        small.attach_db_file.clear();
        small.sspi.truncate(64);
        small.sspi[1..5].copy_from_slice(&3u32.to_le_bytes());
        small.sspi[8] = 0xff;
        let mut b = small.to_bytes().unwrap();
        let sspi_at = le16(&b, 78);
        let ext_at = usize::from(le16(&b, 56));
        b[ext_at..ext_at + 4].copy_from_slice(&u32::from(sspi_at).to_le_bytes());
        let read = Login7::parse(&b).unwrap();
        assert_eq!(read.features.as_ref().map(Vec::len), Some(1));
        assert_eq!(Login7::parse(&read.to_bytes().unwrap()), Ok(read));
    }

    /// A NULL-typed column takes no bytes in a row, so a ROW token of one
    /// byte could stand for 4096 values. Such columns are refused.
    #[test]
    fn null_type_columns_are_refused() {
        let b = [
            token::COLMETADATA,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            data_type::NULL,
            0,
        ];
        assert_eq!(
            TokenReader::new(&b).next(),
            Some(Err(Error::UnsupportedType(data_type::NULL)))
        );
        let mut w = TokenWriter::new();
        let col = Column::new("n", TypeInfo::fixed(data_type::NULL));
        assert_eq!(
            w.push(&Token::ColMetadata(Some(vec![col]))),
            Err(Error::Unwritable)
        );
        assert!(w.bytes().is_empty());
    }

    // Findings from a second review, one test each.

    /// A writer with one column and nothing else written, and whether it
    /// takes a row of `v`.
    fn takes(ti: TypeInfo, v: Value) -> Result<(), Error> {
        let mut w = TokenWriter::new();
        w.push(&Token::ColMetadata(Some(vec![Column::new("c", ti)])))
            .unwrap();
        w.push(&Token::Row(vec![v]))
    }

    /// A decoder held its limit for messages, but `feed` copied every byte
    /// it was given, so a decoder with a 1-byte limit could hold any
    /// amount. Now it takes at most its limit and one packet.
    #[test]
    fn decoder_feed_is_bounded() {
        let mut d = Decoder::with_limit(1);
        let flood = vec![0x01u8; 1 << 20];
        let took = d.feed(&flood);
        assert_eq!(took, 1 + MAX_PACKET);
        assert!(d.buffered() <= 1 + MAX_PACKET);
        assert_eq!(d.feed(&flood), 0);
        // Many messages fed at once come out in full, a part at a time.
        let one = Message::new(packet_type::SQL_BATCH, vec![7; 600])
            .to_packets(512)
            .unwrap();
        let stream = one.repeat(400);
        let mut d = Decoder::with_limit(600);
        let mut rest = &stream[..];
        let mut n = 0;
        while !rest.is_empty() {
            let took = d.feed(rest);
            rest = &rest[took..];
            assert!(d.buffered() <= 600 + 600 + MAX_PACKET);
            while let Some(m) = d.next_message() {
                assert_eq!(m.unwrap().data.len(), 600);
                n += 1;
            }
        }
        assert_eq!(n, 400);
        // After an error every byte is taken and dropped.
        let mut d = Decoder::new();
        put(&mut d, &[1, 1, 0, 3]);
        assert!(d.next_message().unwrap().is_err());
        assert_eq!(d.feed(&flood), flood.len());
        assert_eq!(d.buffered(), 0);
    }

    /// `to_packets` cut a message at MAX_MESSAGE and marked the cut end
    /// EOM, so a batch could lose its WHERE clause. And a TokenWriter
    /// could hold more than one message carries.
    #[test]
    fn oversized_messages_are_refused_not_cut() {
        let big = Message::new(packet_type::SQL_BATCH, vec![b' '; MAX_MESSAGE + 1]);
        assert_eq!(
            big.to_packets(4096),
            Err(FrameError::TooLong(MAX_MESSAGE + 1))
        );
        let at = Message::new(packet_type::SQL_BATCH, vec![b' '; MAX_MESSAGE]);
        let mut d = Decoder::new();
        let bytes = at.to_packets(32767).unwrap();
        let mut rest = &bytes[..];
        let mut got = None;
        while !rest.is_empty() {
            rest = &rest[d.feed(rest)..];
            if let Some(m) = d.next_message() {
                got = Some(m.unwrap());
            }
        }
        assert_eq!(got.unwrap(), at);
        let mut w = TokenWriter::new();
        let col = Column::new("b", TypeInfo::binary(data_type::BIGVARBINARY, 0xffff));
        w.push(&Token::ColMetadata(Some(vec![col]))).unwrap();
        let before = w.bytes().len();
        assert_eq!(
            w.push(&Token::Row(vec![Value::Bytes(vec![1; MAX_MESSAGE])])),
            Err(Error::Limit("response past MAX_MESSAGE"))
        );
        assert_eq!(w.bytes().len(), before);
        w.push(&Token::Row(vec![Value::Bytes(vec![1; 1000])]))
            .unwrap();
    }

    /// MS-TDS 2.2.5.6: a value may not be longer than its column says.
    /// An INTN(4) column took a bigint and an nvarchar(1) column, of 2
    /// bytes, took two characters.
    #[test]
    fn values_fit_their_columns() {
        use data_type::*;
        let intn = TypeInfo::nullable(INTN, 4);
        assert_eq!(
            takes(intn.clone(), Value::BigInt(5)),
            Err(Error::Unwritable)
        );
        assert_eq!(takes(intn.clone(), Value::Int(5)), Ok(()));
        assert_eq!(takes(intn.clone(), Value::SmallInt(5)), Ok(()));
        let s = TypeInfo::string(NVARCHAR, 2);
        assert_eq!(
            takes(s.clone(), Value::Text("ab".into())),
            Err(Error::Unwritable)
        );
        assert_eq!(takes(s, Value::Text("a".into())), Ok(()));
        let b = TypeInfo::binary(BIGBINARY, 2);
        assert_eq!(
            takes(b, Value::Bytes(vec![1, 2, 3])),
            Err(Error::Unwritable)
        );
        // Read from the wire, too.
        let mut w = TokenWriter::new();
        w.push(&Token::ColMetadata(Some(vec![Column::new("c", intn)])))
            .unwrap();
        let mut bytes = w.into_bytes();
        bytes.extend_from_slice(&[token::ROW, 8, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            TokenReader::new(&bytes).nth(1),
            Some(Err(Error::Invalid("value length")))
        );
    }

    /// MS-TDS 2.2.5.5.1.6: a decimal's digits fit its precision. A
    /// decimal(1, 0) column took 10, and even u128::MAX.
    #[test]
    fn decimals_fit_their_precision() {
        let d = |value| Value::Decimal {
            positive: true,
            value,
        };
        let one = TypeInfo::decimal(1, 0);
        assert_eq!(takes(one.clone(), d(9)), Ok(()));
        assert_eq!(takes(one.clone(), d(10)), Err(Error::Unwritable));
        assert_eq!(takes(one, d(u128::MAX)), Err(Error::Unwritable));
        let max = TypeInfo::decimal(38, 0);
        assert_eq!(takes(max.clone(), d(10u128.pow(38) - 1)), Ok(()));
        assert_eq!(takes(max, d(10u128.pow(38))), Err(Error::Unwritable));
    }

    /// MS-TDS 2.2.5.5.1.8: a time is within a day, a date at most
    /// 9999-12-31, and an offset within 840 minutes of UTC.
    #[test]
    fn dates_and_times_in_range() {
        use data_type::*;
        let dto = TypeInfo::scaled(DATETIMEOFFSETN, 0);
        let v = |time, date, offset| Value::DateTimeOffset { time, date, offset };
        assert_eq!(takes(dto.clone(), v(0, 0, 840)), Ok(()));
        assert_eq!(takes(dto.clone(), v(0, 0, -840)), Ok(()));
        assert_eq!(takes(dto.clone(), v(0, 0, 841)), Err(Error::Unwritable));
        assert_eq!(
            takes(dto.clone(), v(0, 0, i16::MIN)),
            Err(Error::Unwritable)
        );
        assert_eq!(takes(dto.clone(), v(86_399, MAX_DATE, 0)), Ok(()));
        assert_eq!(takes(dto, v(0, MAX_DATE + 1, 0)), Err(Error::Unwritable));
        let t0 = TypeInfo::scaled(TIMEN, 0);
        assert_eq!(takes(t0.clone(), Value::Time(86_399)), Ok(()));
        assert_eq!(takes(t0, Value::Time(86_400)), Err(Error::Unwritable));
        let t7 = TypeInfo::scaled(TIMEN, 7);
        assert_eq!(
            takes(t7, Value::Time(864_000_000_000)),
            Err(Error::Unwritable)
        );
        let date = TypeInfo::fixed(DATEN);
        assert_eq!(takes(date.clone(), Value::Date(MAX_DATE)), Ok(()));
        assert_eq!(
            takes(date, Value::Date(MAX_DATE + 1)),
            Err(Error::Unwritable)
        );
    }

    /// MS-TDS 2.2.3.1.2: IGNORE needs EOM, and the reset bits count only
    /// in a message's first packet. Every packet used to carry IGNORE,
    /// and a reset bit in a later packet was or'd into the message.
    #[test]
    fn packet_status_bits_per_packet() {
        let m = Message {
            packet_type: packet_type::SQL_BATCH,
            status: status::EOM | status::IGNORE | status::RESET_CONNECTION,
            spid: 0,
            data: vec![1; 600],
        };
        let bytes = m.to_packets(512).unwrap();
        let (first, used) = Packet::parse(&bytes).unwrap().unwrap();
        let (last, _) = Packet::parse(&bytes[used..]).unwrap().unwrap();
        assert_eq!(first.status, status::RESET_CONNECTION);
        assert_eq!(last.status, status::EOM | status::IGNORE);
        assert_eq!(one_message(&bytes), m);
        // A reset bit or IGNORE in a packet where it does not count.
        let p = |status: u8| vec![packet_type::SQL_BATCH, status, 0, 9, 0, 0, 1, 0, 5];
        let mut bytes = p(status::IGNORE);
        bytes.extend(p(status::RESET_CONNECTION_SKIP_TRAN | status::EOM));
        let got = one_message(&bytes);
        assert_eq!(got.status, status::EOM);
    }

    /// MS-TDS 2.2.6.5: MARS and FEDAUTHREQUIRED are one byte of 0 or 1,
    /// ENCRYPTION one byte, NONCEOPT 32 bytes, TRACEID 36 bytes.
    #[test]
    fn prelogin_option_rules() {
        let base = Prelogin::new(Version::default(), encryption::OFF);
        for (token, data) in [
            (prelogin_option::MARS, vec![2]),
            (prelogin_option::ENCRYPTION, vec![]),
            (prelogin_option::ENCRYPTION, vec![0x04]),
            (prelogin_option::NONCEOPT, vec![0; 31]),
            (prelogin_option::TRACEID, vec![0; 35]),
            (prelogin_option::THREADID, vec![0; 3]),
            (prelogin_option::FEDAUTHREQUIRED, vec![1, 0]),
            (prelogin_option::INSTOPT, vec![]),
        ] {
            let mut p = base.clone();
            p.set(token, data.clone());
            // Written by hand, it is refused.
            let table = 5 * (base.options.len() + 1) + 1;
            let mut hand = Vec::new();
            let mut offset = table;
            let opts: Vec<PreloginOption> = base
                .options
                .iter()
                .cloned()
                .chain([PreloginOption {
                    token,
                    data: data.clone(),
                }])
                .collect();
            for o in &opts {
                hand.push(o.token);
                hand.extend_from_slice(&(offset as u16).to_be_bytes());
                hand.extend_from_slice(&(o.data.len() as u16).to_be_bytes());
                offset += o.data.len();
            }
            hand.push(0xff);
            for o in &opts {
                hand.extend_from_slice(&o.data);
            }
            assert_eq!(
                Prelogin::parse(&hand),
                Err(Error::Invalid("PRELOGIN option length or value")),
                "{token} {data:?}"
            );
            // The writer leaves the option out.
            if token != prelogin_option::ENCRYPTION {
                let back = Prelogin::parse(&p.to_bytes()).unwrap();
                assert_eq!(back.get(token), None, "{token}");
            }
        }
        let mut p = base.clone();
        p.set(prelogin_option::MARS, vec![1]);
        p.set(prelogin_option::ENCRYPTION, vec![0x81]);
        p.set(prelogin_option::NONCEOPT, vec![9; 32]);
        p.set(prelogin_option::THREADID, vec![]);
        assert_eq!(Prelogin::parse(&p.to_bytes()), Ok(p));
    }

    /// MS-TDS 2.2.6.4: without fChangePassword, ibChangePassword MUST be
    /// 0. A new password was written without the flag, and read.
    #[test]
    fn change_password_needs_its_flag() {
        let b = Login7::new().to_bytes().unwrap();
        assert_eq!(le16(&b, 86), 0);
        let mut l = Login7::new();
        l.change_password = "new".into();
        assert_eq!(l.to_bytes(), Err(Error::Unwritable));
        l.option_flags3 = option_flags3::CHANGE_PASSWORD;
        let mut b = l.to_bytes().unwrap();
        assert_eq!(Login7::parse(&b), Ok(l));
        b[27] = 0;
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid(
                "LOGIN7 new password without fChangePassword"
            ))
        );
    }

    /// MS-TDS 2.2.6.4: the extension block is cbExtension bytes at
    /// ibExtension, and must lie in the record. Only its first 4 bytes
    /// were checked.
    #[test]
    fn login_extension_within_record() {
        let l = Login7 {
            features: Some(vec![]),
            option_flags3: option_flags3::EXTENSION,
            ..Login7::new()
        };
        let mut b = l.to_bytes().unwrap();
        assert_eq!(b.len(), 98);
        assert_eq!(Login7::parse(&b), Ok(l));
        b[58..60].copy_from_slice(&255u16.to_le_bytes());
        assert_eq!(
            Login7::parse(&b),
            Err(Error::Invalid("LOGIN7 field outside the record"))
        );
    }

    /// MS-TDS 2.2.5.5.4: a sql_variant value is a base type, a property
    /// count, properties and a value, each fixed by the base type.
    #[test]
    fn sql_variant_layout() {
        let v = TypeInfo {
            max_len: 8016,
            ..TypeInfo::bare(data_type::SSVARIANT)
        };
        let ok = |b: &[u8]| takes(v.clone(), Value::Bytes(b.to_vec()));
        assert_eq!(ok(&[0x38]), Err(Error::Unwritable));
        assert_eq!(ok(&[0x38, 0, 1, 0, 0]), Err(Error::Unwritable));
        assert_eq!(ok(&[0x38, 2, 0, 0, 1, 0, 0, 0]), Err(Error::Unwritable));
        assert_eq!(ok(&[0x38, 0, 1, 0, 0, 0]), Ok(()));
        assert_eq!(ok(&[0x1f, 0]), Err(Error::Unwritable));
        // decimal(5, 2) of 12345, then one past its precision.
        assert_eq!(ok(&[0x6a, 2, 5, 2, 1, 0x39, 0x30, 0, 0]), Ok(()));
        assert_eq!(
            ok(&[0x6a, 2, 2, 0, 1, 0x39, 0x30, 0, 0]),
            Err(Error::Unwritable)
        );
        // time(7), then a scale past 7.
        assert_eq!(ok(&[0x29, 1, 7, 1, 0, 0, 0, 0]), Ok(()));
        assert_eq!(ok(&[0x29, 1, 8, 1, 0, 0, 0, 0]), Err(Error::Unwritable));
        // nvarchar of max length 4, holding "ab", then too long, then odd.
        let mut nv = vec![0xe7, 7];
        nv.extend_from_slice(&DEFAULT_COLLATION);
        nv.extend_from_slice(&4u16.to_le_bytes());
        assert_eq!(ok(&[&nv[..], &[b'a', 0, b'b', 0]].concat()), Ok(()));
        assert_eq!(
            ok(&[&nv[..], &[b'a', 0, b'b', 0, b'c', 0]].concat()),
            Err(Error::Unwritable)
        );
        assert_eq!(
            ok(&[&nv[..], &[b'a', 0, b'b']].concat()),
            Err(Error::Unwritable)
        );
        // varbinary of max length 2.
        assert_eq!(ok(&[0xa5, 2, 2, 0, 1, 2]), Ok(()));
        assert_eq!(ok(&[0xa5, 2, 2, 0, 1, 2, 3]), Err(Error::Unwritable));
    }

    /// MS-TDS 2.2.7.9: each ENVCHANGE type has rules for its values.
    #[test]
    fn envchange_value_rules() {
        let push = |e: EnvChange| TokenWriter::new().push(&Token::EnvChange(e));
        let bytes = |kind, new: &[u8], old: &[u8]| EnvChange::Bytes {
            kind,
            new: new.to_vec(),
            old: old.to_vec(),
        };
        let text = |kind, new: &str, old: &str| EnvChange::Text {
            kind,
            new: new.into(),
            old: old.into(),
        };
        use env_type::*;
        for bad in [
            bytes(RESET_ACK, &[1], &[]),
            bytes(RESET_ACK, &[], &[1]),
            bytes(BEGIN_TRANSACTION, &[1], &[]),
            bytes(BEGIN_TRANSACTION, &[1; 8], &[1; 8]),
            bytes(COMMIT_TRANSACTION, &[], &[1; 7]),
            bytes(ROLLBACK_TRANSACTION, &[1; 8], &[1; 8]),
            bytes(TRANSACTION_MANAGER_ADDRESS, &[1], &[1]),
            text(PACKET_SIZE, "1", "4096"),
            text(PACKET_SIZE, "40000", "4096"),
            text(PACKET_SIZE, "+512", ""),
            text(PACKET_SIZE, "", "4096"),
            text(SORT_FLAGS, "1", "2"),
            text(USER_INSTANCE, "x", "y"),
        ] {
            assert_eq!(push(bad.clone()), Err(Error::Unwritable), "{bad:?}");
        }
        for good in [
            bytes(RESET_ACK, &[], &[]),
            bytes(BEGIN_TRANSACTION, &[1; 8], &[]),
            bytes(COMMIT_TRANSACTION, &[], &[1; 8]),
            text(PACKET_SIZE, "512", "4096"),
            text(PACKET_SIZE, "32767", ""),
            text(SORT_FLAGS, "1", ""),
        ] {
            assert_eq!(push(good.clone()), Ok(()), "{good:?}");
        }
        // Read from the wire: RESET_ACK with a new value.
        let b = [token::ENVCHANGE, 4, 0, RESET_ACK, 1, 9, 0];
        assert_eq!(
            TokenReader::new(&b).next(),
            Some(Err(Error::Invalid("ENVCHANGE value for its type")))
        );
    }

    /// MS-TDS 2.2.5.3.3: a trace activity header is a 16-byte activity ID
    /// and a 4-byte sequence number.
    #[test]
    fn trace_activity_header_layout() {
        let td = StreamHeader::transaction_descriptor(0, 1);
        let with = |data: Vec<u8>| SqlBatch {
            headers: Some(vec![
                td.clone(),
                StreamHeader {
                    kind: header_type::TRACE_ACTIVITY,
                    data,
                },
            ]),
            text: "x".into(),
        };
        let good = with(vec![3; 20]);
        assert_eq!(SqlBatch::parse(&good.to_bytes(), true), Ok(good));
        // Written by hand with one byte of data, it is refused.
        let mut b = with(vec![3; 20]).to_bytes();
        let total = le32(&b, 0) - 19;
        // The block's length, the descriptor's 18 bytes, then the trace
        // header's length and type at 22, and its data at 28.
        b.drain(29..48);
        b[0..4].copy_from_slice(&total.to_le_bytes());
        b[22..26].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            SqlBatch::parse(&b, true),
            Err(Error::Invalid("header data"))
        );
        // The writer leaves such a header out.
        let back = SqlBatch::parse(&with(vec![1]).to_bytes(), true).unwrap();
        assert_eq!(back.headers, Some(vec![td]));
        // Query notifications: two strings and an optional timeout.
        let qn = |data: Vec<u8>| StreamHeader {
            kind: header_type::QUERY_NOTIFICATIONS,
            data,
        };
        assert!(qn(vec![2, 0, b'a', 0, b'b', 0, 0, 0]).is_valid());
        assert!(qn(vec![0, 0, 0, 0, 1, 0, 0, 0]).is_valid());
        assert!(!qn(vec![0, 0, 0, 0, 1]).is_valid());
        assert!(!qn(vec![5, 0]).is_valid());
    }

    /// MS-TDS 2.2.7.19: RETURNVALUE carries an RPC's output parameters.
    /// It was defined but not read, so the reader stopped at it.
    #[test]
    fn return_value_token() {
        let rv = ReturnValue {
            ordinal: 1,
            name: "@total".into(),
            status: return_status::OUTPUT,
            user_type: 0,
            flags: 0,
            type_info: TypeInfo::nullable(data_type::INTN, 4),
            value: Value::Int(42),
        };
        let tokens = vec![
            Token::ReturnStatus(0),
            Token::ReturnValue(rv.clone()),
            Token::ReturnValue(ReturnValue {
                value: Value::Null,
                ..rv.clone()
            }),
            Token::DoneProc(Done::new(0, 0)),
        ];
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap();
        }
        // The bytes as the specification lays them out.
        let mut want = vec![token::RETURNSTATUS, 0, 0, 0, 0, token::RETURNVALUE, 1, 0, 6];
        for c in "@total".encode_utf16() {
            want.extend_from_slice(&c.to_le_bytes());
        }
        want.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0x26, 4, 4, 42, 0, 0, 0]);
        assert_eq!(&w.bytes()[..want.len()], &want[..]);
        let back: Vec<Token> = TokenReader::new(w.bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(back, tokens);
        // A bad status, and encrypted values, are refused.
        for bad in [
            ReturnValue {
                status: 3,
                ..rv.clone()
            },
            ReturnValue {
                flags: FLAG_ENCRYPTED,
                ..rv.clone()
            },
            ReturnValue {
                value: Value::BigInt(1),
                ..rv
            },
        ] {
            assert!(TokenWriter::new().push(&Token::ReturnValue(bad)).is_err());
        }
    }

    /// `with_columns` took any columns, so more than MAX_COLUMNS of a
    /// type that takes no bytes let one ROW byte stand for them all.
    #[test]
    fn with_columns_checks_its_columns() {
        let null = Column::new("n", TypeInfo::fixed(data_type::NULL));
        assert_eq!(
            TokenReader::with_columns(&[token::ROW], vec![null]).err(),
            Some(Error::UnsupportedType(data_type::NULL))
        );
        let many = vec![Column::new("x", TypeInfo::fixed(data_type::INT1)); MAX_COLUMNS + 1];
        assert_eq!(
            TokenReader::with_columns(&[], many).err(),
            Some(Error::Limit("columns"))
        );
        let odd = Column::new("x", TypeInfo::nullable(data_type::INTN, 3));
        assert_eq!(
            TokenReader::with_columns(&[], vec![odd]).err(),
            Some(Error::Invalid("column length"))
        );
        let no_collation = Column::new("x", TypeInfo::binary(data_type::NVARCHAR, 10));
        assert!(TokenReader::with_columns(&[], vec![no_collation]).is_err());
        let mut r = TokenReader::with_columns(&[token::ROW, 7], all_types()[..1].to_vec()).unwrap();
        assert_eq!(r.next(), Some(Ok(Token::Row(vec![Value::TinyInt(7)]))));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// What every reader must do with any bytes: not panic, and read back
    /// what it wrote from what it read.
    fn check(b: &[u8]) {
        if let Ok(p) = Prelogin::parse(b) {
            assert_eq!(Prelogin::parse(&p.to_bytes()), Ok(p));
        }
        if let Ok(l) = Login7::parse(b) {
            assert_eq!(Login7::parse(&l.to_bytes().unwrap()), Ok(l));
        }
        for all in [true, false] {
            if let Ok(s) = SqlBatch::parse(b, all) {
                assert_eq!(SqlBatch::parse(&s.to_bytes(), all), Ok(s));
            }
        }
        let tokens: Vec<Token> = TokenReader::new(b).map_while(Result::ok).collect();
        let mut w = TokenWriter::new();
        for t in &tokens {
            w.push(t).unwrap_or_else(|e| panic!("{e}: {t:?}"));
        }
        let back: Vec<Token> = TokenReader::new(w.bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(back, tokens);
        if let Ok(Some((p, used))) = Packet::parse(b) {
            assert!(used <= b.len());
            assert_eq!(Packet::parse(&p.to_bytes()), Ok(Some((p, used))));
        }
    }

    fn samples() -> Vec<Vec<u8>> {
        let strip = |s: &str| one_message(&hex(s)).data;
        let mut s = vec![
            strip(PRELOGIN_EXAMPLE),
            strip(LOGIN_EXAMPLE),
            strip(BATCH_EXAMPLE),
            strip(LOGIN_RESPONSE_EXAMPLE),
            strip(BATCH_RESPONSE_EXAMPLE),
        ];
        let mut l = Login7::new();
        l.password = "pw".into();
        l.sspi = vec![1, 2, 3];
        l.features = Some(vec![Feature {
            id: 4,
            data: vec![1],
        }]);
        s.push(l.to_bytes().unwrap());
        let mut w = TokenWriter::new();
        w.push(&Token::ColMetadata(Some(all_types()))).unwrap();
        w.push(&Token::Row(all_values())).unwrap();
        w.push(&Token::NbcRow(all_values())).unwrap();
        w.push(&Token::Done(Done::new(done_status::COUNT, 2)))
            .unwrap();
        s.push(w.into_bytes());
        s
    }

    #[test]
    fn lcg_fuzz() {
        let samples = samples();
        let mut rng = Lcg(0x7d5_1433);
        for round in 0..6000 {
            let b: Vec<u8> = if round % 4 == 0 {
                (0..rng.below(120)).map(|_| rng.next() as u8).collect()
            } else {
                let mut b = samples[rng.below(samples.len())].clone();
                for _ in 0..rng.below(4) {
                    if !b.is_empty() {
                        let i = rng.below(b.len());
                        b[i] = match rng.below(4) {
                            0 => 0,
                            1 => 0xff,
                            _ => rng.next() as u8,
                        };
                    }
                }
                if rng.below(4) == 0 && !b.is_empty() {
                    let n = rng.below(b.len());
                    b.truncate(n);
                }
                b
            };
            check(&b);

            // The same bytes as a packet stream, whole and a byte at a
            // time, with small lengths so packets complete.
            let mut s = b.clone();
            for i in (0..s.len()).step_by(9) {
                if i + 3 < s.len() && rng.below(2) == 0 {
                    s[i] = rng.below(3) as u8 + 1;
                    s[i + 1] = rng.below(4) as u8;
                    s[i + 2] = 0;
                    s[i + 3] = 8 + rng.below(12) as u8;
                }
            }
            let run = |chunked: bool| {
                let mut d = Decoder::with_limit(64);
                let mut got = Vec::new();
                let pieces: Vec<&[u8]> = if chunked {
                    s.chunks(1).collect()
                } else {
                    vec![&s[..]]
                };
                'feed: for p in pieces {
                    put(&mut d, p);
                    while let Some(m) = d.next_message() {
                        let stop = m.is_err();
                        got.push(m);
                        if stop {
                            break 'feed;
                        }
                    }
                }
                got
            };
            let whole = run(false);
            assert_eq!(whole, run(true));
            for m in whole.into_iter().flatten() {
                assert!(m.data.len() <= 64);
                let mut d = Decoder::new();
                put(&mut d, &m.to_packets(512).unwrap());
                assert_eq!(d.next_message(), Some(Ok(m)));
            }
        }
    }
}
