//! MySQL: reading and writing the client/server protocol's packets, with
//! no I/O.
//!
//! MySQL clients talk to a server over TCP, usually on port 3306. Every
//! message travels in packets with a 4-byte header: a 3-byte length and a
//! 1-byte sequence ID. A packet holds at most 16 MiB less one byte. A
//! message of that length or longer is split over several packets. The
//! server speaks first with a greeting (the initial handshake), the client
//! answers with its user name and capabilities (the handshake response),
//! and from then on the client sends commands,
//! such as a query, and the server answers each one with an OK packet, an
//! ERR packet or a result set. This module follows the client/server
//! protocol chapter of the MySQL source documentation.
//!
//! Nothing here reads a socket. A world that plays a database server
//! writes a [`Handshake`] to the connection, feeds the bytes it reads to a
//! [`Decoder`], gets [`Message`]s back, reads each one as a
//! [`HandshakeResponse`] or a [`Command`], and writes an [`OkPacket`], an
//! [`ErrPacket`] or a [`ResultSet`] back. Which users, databases and
//! tables exist, and what a query returns, is up to world code. So is
//! whether a login succeeds. A world that plays a client uses the same
//! types the other way round, and a [`ResultReader`] to follow a result
//! set as it arrives.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Bad bytes give an [`Error`] or a [`FrameError`], never a panic.
//!
//! ```
//! use fictionet::stdlib::mysql::{
//!     capability, column_type, status, write_messages, Column, Command, Decoder, Handshake, Message,
//!     ResultEvent, ResultReader, ResultSet,
//! };
//!
//! let caps = capability::PROTOCOL_41
//!     | capability::SECURE_CONNECTION
//!     | capability::PLUGIN_AUTH
//!     | capability::DEPRECATE_EOF;
//!
//! // The greeting a server sends first, with sequence ID 0.
//! let greeting = Handshake {
//!     server_version: b"8.0.36".to_vec(),
//!     connection_id: 1,
//!     auth_data: b"abcdefghijklmnopqrst\0".to_vec(),
//!     capabilities: caps,
//!     charset: 255,
//!     status: status::AUTOCOMMIT,
//!     auth_plugin: b"mysql_native_password".to_vec(),
//! };
//! let bytes = Message { seq: 0, payload: greeting.to_payload().unwrap() }.to_bytes().unwrap();
//! assert_eq!(Handshake::parse(&bytes[4..]), Ok(greeting));
//!
//! // After the login, the agent's client sends a query.
//! let mut decoder = Decoder::new();
//! decoder.feed(b"\x09\x00\x00\x00\x03SELECT 1");
//! let query = decoder.next_message().unwrap().unwrap();
//! assert_eq!(Command::parse(&query.payload, caps), Ok(Command::Query(b"SELECT 1".to_vec())));
//!
//! // The world answers with one column and one row.
//! let result = ResultSet {
//!     columns: vec![Column::new(b"1", column_type::LONGLONG)],
//!     rows: vec![vec![Some(b"1".to_vec())]],
//!     status: status::AUTOCOMMIT,
//!     warnings: 0,
//! };
//! // The column count, the column, the row and the end: sequence IDs 1 to 4.
//! let (reply, next) = write_messages(query.next_seq(), &result.to_payloads(caps).unwrap()).unwrap();
//! assert_eq!(next, 5);
//!
//! // A client reads it back.
//! let mut client = Decoder::new();
//! client.feed(&reply);
//! let mut reader = ResultReader::new(caps);
//! let mut rows = Vec::new();
//! while let Some(message) = client.next_message() {
//!     if let ResultEvent::Row(row) = reader.push(&message.unwrap().payload).unwrap() {
//!         rows.push(row);
//!     }
//! }
//! assert_eq!(rows, [vec![Some(b"1".to_vec())]]);
//! assert!(reader.is_done());
//! ```

/// The TCP port MySQL servers listen on.
pub const PORT: u16 = 3306;
/// The length of a packet header: a 3-byte length and a sequence ID.
pub const HEADER_LEN: usize = 4;
/// The most payload one packet carries. A message this long or longer
/// goes on in the next packet, and a message whose length is a multiple
/// of it ends with an empty packet.
pub const MAX_PACKET_PAYLOAD: usize = 0xff_ffff;
/// The longest message a [`Decoder`] puts together, and the longest
/// [`Message::to_bytes`] writes: 1 GiB, the largest `max_allowed_packet`
/// a MySQL server accepts.
pub const MAX_MESSAGE: usize = 1 << 30;
/// The most columns a result set may have here. A result set that says it
/// has more is refused.
pub const MAX_COLUMNS: usize = 4096;
/// The most connection attributes a handshake response may carry here.
pub const MAX_ATTRIBUTES: usize = 1024;
/// The longest block of connection attributes a handshake response may
/// carry, in bytes. A MySQL server refuses a longer one.
pub const MAX_ATTRIBUTE_BYTES: usize = 0xffff;
/// The zstd compression levels a handshake response may ask for.
pub const ZSTD_LEVELS: std::ops::RangeInclusive<u8> = 1..=22;
/// The protocol version of the initial handshake this module reads.
pub const PROTOCOL_VERSION: u8 = 10;
/// The byte after a result set's column count, with
/// [`capability::OPTIONAL_RESULTSET_METADATA`], that says the column
/// definitions follow. A 0 there says they are left out.
pub const METADATA_FULL: u8 = 1;
/// The length of a payload that asks to switch to TLS (an [`SslRequest`]).
pub const SSL_REQUEST_LEN: usize = 32;

/// Capability flags. Client and server each send theirs in the handshake,
/// and the connection uses the flags both set. Several readers here take
/// those flags, since they change the layout of packets.
pub mod capability {
    #![allow(missing_docs)]
    pub const LONG_PASSWORD: u32 = 1;
    pub const FOUND_ROWS: u32 = 1 << 1;
    pub const LONG_FLAG: u32 = 1 << 2;
    pub const CONNECT_WITH_DB: u32 = 1 << 3;
    pub const NO_SCHEMA: u32 = 1 << 4;
    pub const COMPRESS: u32 = 1 << 5;
    pub const ODBC: u32 = 1 << 6;
    pub const LOCAL_FILES: u32 = 1 << 7;
    pub const IGNORE_SPACE: u32 = 1 << 8;
    pub const PROTOCOL_41: u32 = 1 << 9;
    pub const INTERACTIVE: u32 = 1 << 10;
    pub const SSL: u32 = 1 << 11;
    pub const IGNORE_SIGPIPE: u32 = 1 << 12;
    pub const TRANSACTIONS: u32 = 1 << 13;
    pub const RESERVED: u32 = 1 << 14;
    pub const SECURE_CONNECTION: u32 = 1 << 15;
    pub const MULTI_STATEMENTS: u32 = 1 << 16;
    pub const MULTI_RESULTS: u32 = 1 << 17;
    pub const PS_MULTI_RESULTS: u32 = 1 << 18;
    pub const PLUGIN_AUTH: u32 = 1 << 19;
    pub const CONNECT_ATTRS: u32 = 1 << 20;
    pub const PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
    pub const CAN_HANDLE_EXPIRED_PASSWORDS: u32 = 1 << 22;
    pub const SESSION_TRACK: u32 = 1 << 23;
    pub const DEPRECATE_EOF: u32 = 1 << 24;
    pub const OPTIONAL_RESULTSET_METADATA: u32 = 1 << 25;
    pub const ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
    pub const QUERY_ATTRIBUTES: u32 = 1 << 27;
    pub const MULTI_FACTOR_AUTHENTICATION: u32 = 1 << 28;
    pub const SSL_VERIFY_SERVER_CERT: u32 = 1 << 30;
    pub const REMEMBER_OPTIONS: u32 = 1 << 31;
}

/// Server status flags, sent in OK and EOF packets.
pub mod status {
    #![allow(missing_docs)]
    pub const IN_TRANS: u16 = 1;
    pub const AUTOCOMMIT: u16 = 1 << 1;
    /// Another result set follows this one.
    pub const MORE_RESULTS_EXISTS: u16 = 1 << 3;
    pub const NO_GOOD_INDEX_USED: u16 = 1 << 4;
    pub const NO_INDEX_USED: u16 = 1 << 5;
    pub const CURSOR_EXISTS: u16 = 1 << 6;
    pub const LAST_ROW_SENT: u16 = 1 << 7;
    pub const DB_DROPPED: u16 = 1 << 8;
    pub const NO_BACKSLASH_ESCAPES: u16 = 1 << 9;
    pub const METADATA_CHANGED: u16 = 1 << 10;
    pub const QUERY_WAS_SLOW: u16 = 1 << 11;
    pub const PS_OUT_PARAMS: u16 = 1 << 12;
    pub const IN_TRANS_READONLY: u16 = 1 << 13;
    /// The OK packet carries session state changes.
    pub const SESSION_STATE_CHANGED: u16 = 1 << 14;
}

/// Command bytes: the first byte of every message a client sends after
/// the handshake.
pub mod command {
    #![allow(missing_docs)]
    pub const SLEEP: u8 = 0x00;
    pub const QUIT: u8 = 0x01;
    pub const INIT_DB: u8 = 0x02;
    pub const QUERY: u8 = 0x03;
    pub const FIELD_LIST: u8 = 0x04;
    pub const CREATE_DB: u8 = 0x05;
    pub const DROP_DB: u8 = 0x06;
    pub const REFRESH: u8 = 0x07;
    pub const STATISTICS: u8 = 0x09;
    pub const PROCESS_INFO: u8 = 0x0a;
    pub const CONNECT: u8 = 0x0b;
    pub const PROCESS_KILL: u8 = 0x0c;
    pub const DEBUG: u8 = 0x0d;
    pub const PING: u8 = 0x0e;
    pub const TIME: u8 = 0x0f;
    pub const DELAYED_INSERT: u8 = 0x10;
    pub const CHANGE_USER: u8 = 0x11;
    pub const BINLOG_DUMP: u8 = 0x12;
    pub const TABLE_DUMP: u8 = 0x13;
    pub const CONNECT_OUT: u8 = 0x14;
    pub const REGISTER_SLAVE: u8 = 0x15;
    pub const STMT_PREPARE: u8 = 0x16;
    pub const STMT_EXECUTE: u8 = 0x17;
    pub const STMT_SEND_LONG_DATA: u8 = 0x18;
    pub const STMT_CLOSE: u8 = 0x19;
    pub const STMT_RESET: u8 = 0x1a;
    pub const SET_OPTION: u8 = 0x1b;
    pub const STMT_FETCH: u8 = 0x1c;
    pub const DAEMON: u8 = 0x1d;
    pub const BINLOG_DUMP_GTID: u8 = 0x1e;
    pub const RESET_CONNECTION: u8 = 0x1f;
    pub const CLONE: u8 = 0x20;
}

/// Column types, as a column definition names them.
pub mod column_type {
    #![allow(missing_docs)]
    pub const DECIMAL: u8 = 0x00;
    pub const TINY: u8 = 0x01;
    pub const SHORT: u8 = 0x02;
    pub const LONG: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const TIMESTAMP: u8 = 0x07;
    pub const LONGLONG: u8 = 0x08;
    pub const INT24: u8 = 0x09;
    pub const DATE: u8 = 0x0a;
    pub const TIME: u8 = 0x0b;
    pub const DATETIME: u8 = 0x0c;
    pub const YEAR: u8 = 0x0d;
    pub const NEWDATE: u8 = 0x0e;
    pub const VARCHAR: u8 = 0x0f;
    pub const BIT: u8 = 0x10;
    pub const TIMESTAMP2: u8 = 0x11;
    pub const DATETIME2: u8 = 0x12;
    pub const TIME2: u8 = 0x13;
    pub const VECTOR: u8 = 0xf2;
    pub const JSON: u8 = 0xf5;
    pub const NEWDECIMAL: u8 = 0xf6;
    pub const ENUM: u8 = 0xf7;
    pub const SET: u8 = 0xf8;
    pub const TINY_BLOB: u8 = 0xf9;
    pub const MEDIUM_BLOB: u8 = 0xfa;
    pub const LONG_BLOB: u8 = 0xfb;
    pub const BLOB: u8 = 0xfc;
    pub const VAR_STRING: u8 = 0xfd;
    pub const STRING: u8 = 0xfe;
    pub const GEOMETRY: u8 = 0xff;
}

/// Column definition flags.
pub mod column_flag {
    #![allow(missing_docs)]
    pub const NOT_NULL: u16 = 1;
    pub const PRI_KEY: u16 = 1 << 1;
    pub const UNIQUE_KEY: u16 = 1 << 2;
    pub const MULTIPLE_KEY: u16 = 1 << 3;
    pub const BLOB: u16 = 1 << 4;
    pub const UNSIGNED: u16 = 1 << 5;
    pub const ZEROFILL: u16 = 1 << 6;
    pub const BINARY: u16 = 1 << 7;
    pub const ENUM: u16 = 1 << 8;
    pub const AUTO_INCREMENT: u16 = 1 << 9;
    pub const TIMESTAMP: u16 = 1 << 10;
    pub const SET: u16 = 1 << 11;
    pub const NO_DEFAULT_VALUE: u16 = 1 << 12;
    pub const ON_UPDATE_NOW: u16 = 1 << 13;
    pub const NUM: u16 = 1 << 15;
}

/// A few character set and collation numbers, as the handshake and column
/// definitions name them.
pub mod charset {
    #![allow(missing_docs)]
    pub const LATIN1_SWEDISH_CI: u8 = 8;
    pub const UTF8MB3_GENERAL_CI: u8 = 33;
    pub const UTF8MB4_GENERAL_CI: u8 = 45;
    pub const BINARY: u8 = 63;
    pub const UTF8MB4_0900_AI_CI: u8 = 255;
}

/// Why a stream of packets cannot be read any further. A real server
/// closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A packet that continues a split message had the wrong sequence ID.
    Sequence {
        /// The ID the packet should have had: one more than the last.
        expected: u8,
        /// The ID it had.
        got: u8,
    },
    /// The message would be longer than the decoder's limit. The value is
    /// the length it had reached, counting the packet that broke the
    /// limit.
    TooLong(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Sequence { expected, got } => write!(f, "sequence ID {got}, expected {expected}"),
            FrameError::TooLong(n) => write!(f, "message of at least {n} bytes is over the limit"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why a payload is not the packet a reader expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The payload ended inside a field, or a string had no closing NUL.
    Truncated,
    /// The first byte is not the one this kind of packet starts with: a
    /// result set's column count of 0, a local file request on a
    /// connection without [`capability::LOCAL_FILES`], or a
    /// [`Command::Other`] whose byte another variant covers.
    Header(u8),
    /// A length-encoded integer started with 0xFB (NULL) where no NULL is
    /// allowed, or with 0xFF, which starts no integer.
    LengthPrefix(u8),
    /// The initial handshake's protocol version is not 10.
    Version(u8),
    /// A column definition's fixed fields have a length other than 12.
    FixedFields(u64),
    /// More columns or connection attributes than this module reads (see
    /// [`MAX_COLUMNS`] and [`MAX_ATTRIBUTES`]).
    TooMany,
    /// A packet layout this module does not read: a handshake response
    /// or a result set without [`capability::PROTOCOL_41`], query
    /// attributes with parameters, or a result set sent without its
    /// column definitions.
    Unsupported,
    /// Bytes came after the last field where none may.
    Trailing,
    /// A [`ResultReader`] got a packet after its last result had ended.
    Finished,
    /// A value is too long or too short for its field or packet: the
    /// length it had. Readers give it for a block of connection
    /// attributes over [`MAX_ATTRIBUTE_BYTES`]; writers give it for a
    /// value they cannot write as it is.
    Length(usize),
    /// A name that is written with a closing NUL holds a NUL, so it would
    /// read back cut short.
    Nul,
    /// A field holds a value the protocol does not allow, such as a zstd
    /// level outside [`ZSTD_LEVELS`] or a COM_QUERY parameter set count
    /// other than 1.
    Value(u64),
    /// An ERR packet with no SQLSTATE, under [`capability::PROTOCOL_41`],
    /// whose message starts with `#` and 5 more bytes. It would read back
    /// with those bytes as its SQLSTATE.
    SqlState,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("payload ended inside a field"),
            Error::Header(b) => write!(f, "unexpected first byte {b:#04x}"),
            Error::LengthPrefix(b) => write!(f, "{b:#04x} does not start a length here"),
            Error::Version(v) => write!(f, "handshake protocol version {v}, not 10"),
            Error::FixedFields(n) => write!(f, "column fixed fields length {n}, not 12"),
            Error::TooMany => f.write_str("too many columns or attributes"),
            Error::Unsupported => f.write_str("packet layout not supported"),
            Error::Trailing => f.write_str("bytes after the last field"),
            Error::Finished => f.write_str("packet after the last result ended"),
            Error::Length(n) => write!(f, "length {n} does not fit the field"),
            Error::Nul => f.write_str("NUL inside a NUL-terminated name"),
            Error::Value(v) => write!(f, "value {v} is not allowed in this field"),
            Error::SqlState => f.write_str("ERR message would read back as a SQLSTATE"),
        }
    }
}

impl std::error::Error for Error {}

/// One message: the payload of a packet, or of several packets put back
/// together, and the sequence ID of its first packet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The sequence ID of the first packet. It starts at 0 with each
    /// command and goes up by one with every packet either side sends.
    pub seq: u8,
    /// The message's bytes, without packet headers.
    pub payload: Vec<u8>,
}

impl Message {
    /// How many packets the message takes on the wire.
    pub fn packets(&self) -> usize {
        packets(self.payload.len())
    }

    /// The sequence ID of the packet that comes after this message.
    pub fn next_seq(&self) -> u8 {
        // The packet count is reduced mod 256 first, so it fits in a u8.
        self.seq.wrapping_add((self.packets() % 256) as u8)
    }

    /// The message's packets. A payload longer than [`MAX_MESSAGE`], which
    /// no decoder takes, gives [`FrameError::TooLong`] and no bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FrameError> {
        check_len(&self.payload)?;
        let mut out = Vec::with_capacity(self.payload.len() + HEADER_LEN * self.packets());
        put_packets(&mut out, self.seq, &self.payload);
        Ok(out)
    }
}

fn packets(len: usize) -> usize {
    len / MAX_PACKET_PAYLOAD + 1
}

fn check_len(payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_MESSAGE {
        return Err(FrameError::TooLong(payload.len()));
    }
    Ok(())
}

/// Appends `payload` as packets, the first with ID `seq`, and returns the
/// ID of the packet after them.
fn put_packets(out: &mut Vec<u8>, mut seq: u8, payload: &[u8]) -> u8 {
    let mut rest = payload;
    loop {
        let n = rest.len().min(MAX_PACKET_PAYLOAD);
        out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
        seq = seq.wrapping_add(1);
        if n < MAX_PACKET_PAYLOAD {
            return seq;
        }
    }
}

/// Writes `payloads` as messages, one after another, the first with
/// sequence ID `seq`. It returns the bytes and the sequence ID of the
/// packet that would come next. A payload longer than [`MAX_MESSAGE`]
/// gives [`FrameError::TooLong`], and then nothing is written.
pub fn write_messages(seq: u8, payloads: &[Vec<u8>]) -> Result<(Vec<u8>, u8), FrameError> {
    let mut total = 0usize;
    for p in payloads {
        check_len(p)?;
        total = total.saturating_add(p.len()).saturating_add(HEADER_LEN * packets(p.len()));
    }
    let mut out = Vec::with_capacity(total);
    let mut seq = seq;
    for p in payloads {
        seq = put_packets(&mut out, seq, p);
    }
    Ok((out, seq))
}

/// Splits a MySQL byte stream into messages, putting split packets back
/// together. Feed it the bytes a connection reads, in order, and take
/// messages out until it has none. It holds a bounded number of bytes,
/// so feed it again whatever [`Decoder::feed`] did not take.
///
/// It checks that the packets of one split message have consecutive
/// sequence IDs. Whether a message's first ID is the one the
/// conversation expects is up to the caller, since the IDs start again
/// with each command.
#[derive(Clone, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// How many bytes at the front of `buf` are already read. They are
    /// dropped on the next `feed`, so many small messages in one feed cost
    /// no more than one pass.
    start: usize,
    limit: usize,
    /// A split message so far: its first ID, its last ID and its bytes.
    partial: Option<(u8, u8, Vec<u8>)>,
    failed: Option<FrameError>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, taking messages up to [`MAX_MESSAGE`].
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_MESSAGE)
    }

    /// A decoder taking messages up to `limit` bytes, as a server's
    /// `max_allowed_packet` does. A limit above [`MAX_MESSAGE`] is
    /// lowered to it.
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, limit: limit.min(MAX_MESSAGE), partial: None, failed: None }
    }

    /// Adds bytes read from the connection and returns how many it took.
    /// It holds at most [`Decoder::capacity`] bytes, counting a split
    /// message's packets so far, so it may take fewer than it is given.
    /// Take messages out with [`Decoder::next_message`], then feed it the
    /// rest; once it is full, `next_message` always gives a message or an
    /// error. After a [`FrameError`] the stream cannot be read any
    /// further, and every byte is taken and dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        self.buf.drain(..self.start);
        self.start = 0;
        let n = bytes.len().min(self.capacity().saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The most bytes the decoder holds: its message limit and one packet
    /// header. A packet that is not whole yet, and the split message it
    /// belongs to, always fit.
    pub fn capacity(&self) -> usize {
        self.limit + HEADER_LEN
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. Bytes already read are dropped on the next
    /// `feed`.
    pub fn next_message(&mut self) -> Option<Result<Message, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        loop {
            let buf = &self.buf[self.start..];
            if buf.len() < HEADER_LEN {
                return None;
            }
            let len = usize::from(buf[0]) | usize::from(buf[1]) << 8 | usize::from(buf[2]) << 16;
            let seq = buf[3];
            // Both checks need only the header, so they come before the body.
            let have = match &self.partial {
                Some((_, last, bytes)) => {
                    let expected = last.wrapping_add(1);
                    if seq != expected {
                        return Some(Err(self.fail(FrameError::Sequence { expected, got: seq })));
                    }
                    bytes.len()
                }
                None => 0,
            };
            let total = have.saturating_add(len);
            if total > self.limit {
                return Some(Err(self.fail(FrameError::TooLong(total))));
            }
            let end = HEADER_LEN + len;
            if buf.len() < end {
                return None;
            }
            let (first, mut bytes) = match self.partial.take() {
                Some((first, _, bytes)) => (first, bytes),
                None => (seq, Vec::new()),
            };
            bytes.extend_from_slice(&self.buf[self.start + HEADER_LEN..self.start + end]);
            self.start += end;
            if len < MAX_PACKET_PAYLOAD {
                return Some(Ok(Message { seq: first, payload: bytes }));
            }
            self.partial = Some((first, seq, bytes));
        }
    }

    fn fail(&mut self, e: FrameError) -> FrameError {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        self.partial = None;
        e
    }

    /// How many bytes are held, waiting for the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start + self.partial.as_ref().map_or(0, |p| p.2.len())
    }
}

/// Reads the length-encoded integer at the start of `b`, and returns it
/// and how many bytes it took. Values below 251 take one byte; 0xFC, 0xFD
/// and 0xFE start 2-, 3- and 8-byte values. 0xFB (a NULL in a row) and
/// 0xFF give [`Error::LengthPrefix`].
pub fn read_lenenc_int(b: &[u8]) -> Result<(u64, usize), Error> {
    let mut r = Reader(b);
    let v = r.lenenc()?;
    Ok((v, b.len() - r.0.len()))
}

/// Appends `v` as a length-encoded integer, in as few bytes as it fits.
pub fn write_lenenc_int(out: &mut Vec<u8>, v: u64) {
    if v < 0xfb {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xff_ffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Reads the length-encoded string at the start of `b`: a length-encoded
/// integer, then that many bytes. It returns the bytes and how many bytes
/// of `b` the string took.
pub fn read_lenenc_str(b: &[u8]) -> Result<(&[u8], usize), Error> {
    let mut r = Reader(b);
    let s = r.lenenc_str()?;
    Ok((s, b.len() - r.0.len()))
}

/// Appends `s` as a length-encoded string.
pub fn write_lenenc_str(out: &mut Vec<u8>, s: &[u8]) {
    write_lenenc_int(out, s.len() as u64);
    out.extend_from_slice(s);
}

/// The initial handshake, version 10: the greeting a server sends as soon
/// as a client connects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handshake {
    /// The server's version, such as `8.0.36`.
    pub server_version: Vec<u8>,
    /// The connection's ID, as `CONNECTION_ID()` returns it.
    pub connection_id: u32,
    /// The random bytes the client's password hash mixes in, both parts
    /// as sent. MySQL sends 20 random bytes and a NUL. The first 8 come
    /// before the capability flags. The rest come later, at least 13 of
    /// them, and more only with [`capability::PLUGIN_AUTH`].
    pub auth_data: Vec<u8>,
    /// The server's capability flags.
    pub capabilities: u32,
    /// The server's default character set and collation.
    pub charset: u8,
    /// The server status flags.
    pub status: u16,
    /// The authentication method the server starts with, such as
    /// `caching_sha2_password`. Sent only with
    /// [`capability::PLUGIN_AUTH`].
    pub auth_plugin: Vec<u8>,
}

impl Handshake {
    /// Reads a handshake payload. A server that refuses a client may send
    /// an ERR packet instead, which gives [`Error::Version`] with 0xFF;
    /// read it with [`ErrPacket::parse`].
    ///
    /// Old servers stop after the lower capability flags. Then the
    /// character set, status and upper flags are 0 and `auth_data` holds
    /// 8 bytes.
    pub fn parse(payload: &[u8]) -> Result<Handshake, Error> {
        let mut r = Reader(payload);
        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(Error::Version(version));
        }
        let server_version = r.nul()?.to_vec();
        let connection_id = r.u32()?;
        let mut auth_data = r.take(8)?.to_vec();
        r.u8()?; // filler
        let mut capabilities = u32::from(r.u16()?);
        let mut h = Handshake { server_version, connection_id, capabilities, ..Handshake::default() };
        if r.0.is_empty() {
            h.auth_data = auth_data;
            return Ok(h);
        }
        h.charset = r.u8()?;
        h.status = r.u16()?;
        capabilities |= u32::from(r.u16()?) << 16;
        let data_len = usize::from(r.u8()?);
        r.take(10)?; // reserved
        // Part 2 comes whatever the flags; its length byte counts only with
        // PLUGIN_AUTH.
        let n = if capabilities & capability::PLUGIN_AUTH != 0 { data_len.saturating_sub(8).max(13) } else { 13 };
        auth_data.extend_from_slice(r.take(n)?);
        if capabilities & capability::PLUGIN_AUTH != 0 {
            // Some servers leave out the closing NUL.
            h.auth_plugin = r.nul_or_rest().to_vec();
        }
        h.capabilities = capabilities;
        h.auth_data = auth_data;
        Ok(h)
    }

    /// The handshake's payload. The plugin name is written only with
    /// [`capability::PLUGIN_AUTH`]. A payload that would not read back as
    /// the same handshake gives an error instead: [`Error::Nul`] for a
    /// name holding a NUL, and [`Error::Length`] for `auth_data` of a
    /// length the flags cannot carry. That is 21 bytes, 21 to 255 with
    /// [`capability::PLUGIN_AUTH`], or 8 in the short form old servers
    /// send (no character set, status, upper flags or plugin name).
    pub fn to_payload(&self) -> Result<Vec<u8>, Error> {
        let caps = self.capabilities;
        let plugin_auth = caps & capability::PLUGIN_AUTH != 0;
        let short = self.charset == 0
            && self.status == 0
            && caps >> 16 == 0
            && self.auth_data.len() == 8
            && self.auth_plugin.is_empty();
        let n = self.auth_data.len();
        if !short && (n < 8 + 13 || n > if plugin_auth { 255 } else { 8 + 13 }) {
            return Err(Error::Length(n));
        }
        let mut out = vec![PROTOCOL_VERSION];
        put_nul(&mut out, &self.server_version)?;
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out.extend_from_slice(&self.auth_data[..8]);
        out.push(0);
        out.extend_from_slice(&(caps as u16).to_le_bytes());
        if short {
            return Ok(out);
        }
        let part2 = &self.auth_data[8..];
        out.push(self.charset);
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
        let data_len = if plugin_auth { n } else { 0 };
        out.push(data_len as u8);
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(part2);
        if plugin_auth {
            put_nul(&mut out, &self.auth_plugin)?;
        }
        Ok(out)
    }
}

/// The client's answer to the handshake (HandshakeResponse41): who it
/// is, what it can do, and its answer to the server's challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandshakeResponse {
    /// The client's capability flags. [`capability::PROTOCOL_41`] is
    /// always set.
    pub capabilities: u32,
    /// The longest message the client will send.
    pub max_packet: u32,
    /// The character set and collation the client wants.
    pub charset: u8,
    /// The user name.
    pub username: Vec<u8>,
    /// The client's answer to the challenge in [`Handshake::auth_data`],
    /// as the authentication method computes it.
    pub auth_response: Vec<u8>,
    /// The database to start in, with [`capability::CONNECT_WITH_DB`].
    pub database: Vec<u8>,
    /// The authentication method the client used, with
    /// [`capability::PLUGIN_AUTH`].
    pub auth_plugin: Vec<u8>,
    /// Connection attributes as key and value pairs, such as
    /// `_client_name`, with [`capability::CONNECT_ATTRS`].
    pub attributes: Vec<(Vec<u8>, Vec<u8>)>,
    /// The zstd compression level, with
    /// [`capability::ZSTD_COMPRESSION_ALGORITHM`]: one of [`ZSTD_LEVELS`].
    /// MySQL's default is 3. Without the flag it is not sent and reads
    /// as 0.
    pub zstd_level: u8,
}

impl HandshakeResponse {
    /// Reads a handshake response payload. A 32-byte payload is an
    /// [`SslRequest`] instead, and gives [`Error::Truncated`] here.
    /// Without [`capability::PROTOCOL_41`] it gives
    /// [`Error::Unsupported`]. Every field the flags call for must be
    /// there, as a MySQL server reads them, except the plugin name: when
    /// it is left out it reads as empty, and its closing NUL may be left
    /// out at the very end. A block of connection attributes over
    /// [`MAX_ATTRIBUTE_BYTES`] gives [`Error::Length`], and a zstd level
    /// outside [`ZSTD_LEVELS`] gives [`Error::Value`].
    pub fn parse(payload: &[u8]) -> Result<HandshakeResponse, Error> {
        let mut r = Reader(payload);
        let capabilities = r.u32()?;
        if capabilities & capability::PROTOCOL_41 == 0 {
            return Err(Error::Unsupported);
        }
        let max_packet = r.u32()?;
        let charset = r.u8()?;
        r.take(23)?; // filler
        let username = r.nul()?.to_vec();
        let auth_response = if capabilities & capability::PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            r.lenenc_str()?
        } else if capabilities & capability::SECURE_CONNECTION != 0 {
            let n = usize::from(r.u8()?);
            r.take(n)?
        } else {
            r.nul()?
        }
        .to_vec();
        let mut h =
            HandshakeResponse { capabilities, max_packet, charset, username, auth_response, ..Default::default() };
        if capabilities & capability::CONNECT_WITH_DB != 0 {
            h.database = r.nul()?.to_vec();
        }
        if capabilities & capability::PLUGIN_AUTH != 0 && !r.0.is_empty() {
            h.auth_plugin = r.nul_or_rest().to_vec();
        }
        if capabilities & capability::CONNECT_ATTRS != 0 {
            let len = r.lenenc()?;
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > MAX_ATTRIBUTE_BYTES {
                return Err(Error::Length(len));
            }
            let mut block = Reader(r.take(len)?);
            while !block.0.is_empty() {
                if h.attributes.len() >= MAX_ATTRIBUTES {
                    return Err(Error::TooMany);
                }
                let key = block.lenenc_str()?.to_vec();
                let value = block.lenenc_str()?.to_vec();
                h.attributes.push((key, value));
            }
        }
        if capabilities & capability::ZSTD_COMPRESSION_ALGORITHM != 0 {
            h.zstd_level = r.u8()?;
            if !ZSTD_LEVELS.contains(&h.zstd_level) {
                return Err(Error::Value(u64::from(h.zstd_level)));
            }
        }
        Ok(h)
    }

    /// The response's payload. [`capability::PROTOCOL_41`] is set, and
    /// fields the flags leave out are not written. A payload that would
    /// not read back as the same response gives an error instead:
    /// [`Error::Nul`] for a name holding a NUL (or an auth response,
    /// when it is written with a closing NUL), [`Error::Length`] for an
    /// auth response over 255 bytes without
    /// [`capability::PLUGIN_AUTH_LENENC_CLIENT_DATA`] or an attribute
    /// block over [`MAX_ATTRIBUTE_BYTES`], [`Error::TooMany`] for more
    /// than [`MAX_ATTRIBUTES`] attributes, and [`Error::Value`] for a zstd
    /// level outside [`ZSTD_LEVELS`].
    pub fn to_payload(&self) -> Result<Vec<u8>, Error> {
        let caps = self.capabilities | capability::PROTOCOL_41;
        let mut out = Vec::new();
        out.extend_from_slice(&caps.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&[0; 23]);
        put_nul(&mut out, &self.username)?;
        if caps & capability::PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            write_lenenc_str(&mut out, &self.auth_response);
        } else if caps & capability::SECURE_CONNECTION != 0 {
            let a = &self.auth_response;
            let n = u8::try_from(a.len()).map_err(|_| Error::Length(a.len()))?;
            out.push(n);
            out.extend_from_slice(a);
        } else {
            put_nul(&mut out, &self.auth_response)?;
        }
        if caps & capability::CONNECT_WITH_DB != 0 {
            put_nul(&mut out, &self.database)?;
        }
        if caps & capability::PLUGIN_AUTH != 0 {
            put_nul(&mut out, &self.auth_plugin)?;
        }
        if caps & capability::CONNECT_ATTRS != 0 {
            if self.attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::TooMany);
            }
            let mut block = Vec::new();
            for (k, v) in &self.attributes {
                // Each pair is checked before it is copied, so the block
                // never grows far past the limit.
                let len = block.len().saturating_add(k.len()).saturating_add(v.len());
                if len > MAX_ATTRIBUTE_BYTES {
                    return Err(Error::Length(len));
                }
                write_lenenc_str(&mut block, k);
                write_lenenc_str(&mut block, v);
            }
            if block.len() > MAX_ATTRIBUTE_BYTES {
                return Err(Error::Length(block.len()));
            }
            write_lenenc_str(&mut out, &block);
        }
        if caps & capability::ZSTD_COMPRESSION_ALGORITHM != 0 {
            if !ZSTD_LEVELS.contains(&self.zstd_level) {
                return Err(Error::Value(u64::from(self.zstd_level)));
            }
            out.push(self.zstd_level);
        }
        Ok(out)
    }
}

/// The short handshake response a client sends to switch the connection
/// to TLS. The full [`HandshakeResponse`] follows inside TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SslRequest {
    /// The client's capability flags. [`capability::SSL`] and
    /// [`capability::PROTOCOL_41`] are always set.
    pub capabilities: u32,
    /// The longest message the client will send.
    pub max_packet: u32,
    /// The character set and collation the client wants.
    pub charset: u8,
}

impl SslRequest {
    /// Reads an SSL request: exactly [`SSL_REQUEST_LEN`] bytes, with
    /// [`capability::SSL`] and [`capability::PROTOCOL_41`] set. Other
    /// payloads give [`Error::Truncated`], [`Error::Trailing`] or
    /// [`Error::Unsupported`].
    pub fn parse(payload: &[u8]) -> Result<SslRequest, Error> {
        if payload.len() > SSL_REQUEST_LEN {
            return Err(Error::Trailing);
        }
        let mut r = Reader(payload);
        let capabilities = r.u32()?;
        let max_packet = r.u32()?;
        let charset = r.u8()?;
        r.take(23)?;
        let need = capability::SSL | capability::PROTOCOL_41;
        if capabilities & need != need {
            return Err(Error::Unsupported);
        }
        Ok(SslRequest { capabilities, max_packet, charset })
    }

    /// The request's payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let caps = self.capabilities | capability::SSL | capability::PROTOCOL_41;
        let mut out = Vec::with_capacity(SSL_REQUEST_LEN);
        out.extend_from_slice(&caps.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&[0; 23]);
        out
    }
}

/// An OK packet: the server's answer to a command that succeeded with no
/// result set. With [`capability::DEPRECATE_EOF`] it also ends a result
/// set, with 0xFE as its first byte instead of 0x00.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OkPacket {
    /// How many rows the command changed.
    pub affected_rows: u64,
    /// The ID of the last row inserted into an `AUTO_INCREMENT` column.
    pub last_insert_id: u64,
    /// The server status flags.
    pub status: u16,
    /// How many warnings the command raised.
    pub warnings: u16,
    /// A human-readable message, such as `Rows matched: 1  Changed: 1`.
    pub info: Vec<u8>,
    /// Session state changes, unread, with [`capability::SESSION_TRACK`]
    /// and [`status::SESSION_STATE_CHANGED`].
    pub session_state: Vec<u8>,
}

impl OkPacket {
    /// Reads an OK packet, with first byte 0x00 or 0xFE, under the
    /// connection's capability flags. With [`capability::SESSION_TRACK`]
    /// the packet may end after the status and warnings, as libmysql
    /// allows. Once the info text is there, the session state must follow
    /// when [`status::SESSION_STATE_CHANGED`] is set, and nothing may come
    /// after the last field.
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<OkPacket, Error> {
        let mut r = Reader(payload);
        let header = r.u8()?;
        if header != 0x00 && header != 0xfe {
            return Err(Error::Header(header));
        }
        let mut ok = OkPacket { affected_rows: r.lenenc()?, last_insert_id: r.lenenc()?, ..OkPacket::default() };
        if capabilities & capability::PROTOCOL_41 != 0 {
            ok.status = r.u16()?;
            ok.warnings = r.u16()?;
        } else if capabilities & capability::TRANSACTIONS != 0 {
            ok.status = r.u16()?;
        }
        if capabilities & capability::SESSION_TRACK != 0 {
            if !r.0.is_empty() {
                ok.info = r.lenenc_str()?.to_vec();
                if ok.status & status::SESSION_STATE_CHANGED != 0 {
                    ok.session_state = r.lenenc_str()?.to_vec();
                }
                if !r.0.is_empty() {
                    return Err(Error::Trailing);
                }
            }
        } else {
            ok.info = r.rest().to_vec();
        }
        Ok(ok)
    }

    /// The OK packet's payload, with first byte 0x00. Fields the flags
    /// leave out are not written.
    pub fn to_payload(&self, capabilities: u32) -> Vec<u8> {
        self.write(0x00, capabilities)
    }

    /// The payload that ends a result set when the connection uses
    /// [`capability::DEPRECATE_EOF`]: an OK packet with first byte 0xFE.
    /// A client tells it from a row by its length, under
    /// [`MAX_PACKET_PAYLOAD`], so a longer one gives [`Error::Length`].
    pub fn to_end_payload(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let out = self.write(0xfe, capabilities);
        if out.len() >= MAX_PACKET_PAYLOAD {
            return Err(Error::Length(out.len()));
        }
        Ok(out)
    }

    fn write(&self, header: u8, caps: u32) -> Vec<u8> {
        let mut out = vec![header];
        write_lenenc_int(&mut out, self.affected_rows);
        write_lenenc_int(&mut out, self.last_insert_id);
        if caps & capability::PROTOCOL_41 != 0 {
            out.extend_from_slice(&self.status.to_le_bytes());
            out.extend_from_slice(&self.warnings.to_le_bytes());
        } else if caps & capability::TRANSACTIONS != 0 {
            out.extend_from_slice(&self.status.to_le_bytes());
        }
        let info = &self.info;
        if caps & capability::SESSION_TRACK != 0 {
            let status_written = caps & (capability::PROTOCOL_41 | capability::TRANSACTIONS) != 0;
            write_lenenc_str(&mut out, info);
            if status_written && self.status & status::SESSION_STATE_CHANGED != 0 {
                write_lenenc_str(&mut out, &self.session_state);
            }
        } else {
            out.extend_from_slice(info);
        }
        out
    }
}

/// An ERR packet: the server's answer to a command that failed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ErrPacket {
    /// The MySQL error number, such as 1045 for a refused login.
    pub code: u16,
    /// The SQLSTATE, such as `28000`. Sent with
    /// [`capability::PROTOCOL_41`], after a `#`.
    pub sql_state: Option<[u8; 5]>,
    /// A human-readable message.
    pub message: Vec<u8>,
}

impl ErrPacket {
    /// An ERR packet with a SQLSTATE.
    pub fn new(code: u16, sql_state: &[u8; 5], message: &[u8]) -> ErrPacket {
        ErrPacket { code, sql_state: Some(*sql_state), message: message.to_vec() }
    }

    /// Reads an ERR packet, with first byte 0xFF, under the connection's
    /// capability flags. The SQLSTATE is read only when the flags include
    /// [`capability::PROTOCOL_41`] and a `#` marks it, since a server
    /// that refuses a connection before the handshake sends none.
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<ErrPacket, Error> {
        let mut r = Reader(payload);
        let header = r.u8()?;
        if header != 0xff {
            return Err(Error::Header(header));
        }
        let code = r.u16()?;
        let mut sql_state = None;
        if capabilities & capability::PROTOCOL_41 != 0 && r.0.len() >= 6 && r.0[0] == b'#' {
            let mut s = [0u8; 5];
            s.copy_from_slice(&r.0[1..6]);
            sql_state = Some(s);
            r.0 = &r.0[6..];
        }
        Ok(ErrPacket { code, sql_state, message: r.rest().to_vec() })
    }

    /// The ERR packet's payload. The SQLSTATE is written only with
    /// [`capability::PROTOCOL_41`]. Without a SQLSTATE under those flags,
    /// as a server sends before the handshake, a message that starts with
    /// `#` and 5 more bytes would read back as one, so it gives
    /// [`Error::SqlState`].
    pub fn to_payload(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let protocol_41 = capabilities & capability::PROTOCOL_41 != 0;
        if protocol_41 && self.sql_state.is_none() && self.message.len() >= 6 && self.message[0] == b'#' {
            return Err(Error::SqlState);
        }
        let mut out = vec![0xff];
        out.extend_from_slice(&self.code.to_le_bytes());
        if let (Some(s), true) = (self.sql_state, protocol_41) {
            out.push(b'#');
            out.extend_from_slice(&s);
        }
        out.extend_from_slice(&self.message);
        Ok(out)
    }
}

/// An EOF packet: it ends the column definitions and the rows of a result
/// set when the connection does not use [`capability::DEPRECATE_EOF`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Eof {
    /// How many warnings the command raised.
    pub warnings: u16,
    /// The server status flags.
    pub status: u16,
}

impl Eof {
    /// Reads an EOF packet: 0xFE, then the warnings and status with
    /// [`capability::PROTOCOL_41`]; without it the counts are 0. Bytes
    /// after them give [`Error::Trailing`].
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<Eof, Error> {
        let mut r = Reader(payload);
        let header = r.u8()?;
        if header != 0xfe {
            return Err(Error::Header(header));
        }
        let mut eof = Eof::default();
        if capabilities & capability::PROTOCOL_41 != 0 {
            eof = Eof { warnings: r.u16()?, status: r.u16()? };
        }
        if !r.0.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(eof)
    }

    /// The EOF packet's payload.
    pub fn to_payload(&self, capabilities: u32) -> Vec<u8> {
        let mut out = vec![0xfe];
        if capabilities & capability::PROTOCOL_41 != 0 {
            out.extend_from_slice(&self.warnings.to_le_bytes());
            out.extend_from_slice(&self.status.to_le_bytes());
        }
        out
    }
}

/// A command a client sends after the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// COM_QUIT: close the connection.
    Quit,
    /// COM_INIT_DB: change the default database, as `USE` does.
    InitDb(Vec<u8>),
    /// COM_QUERY: run the SQL text.
    Query(Vec<u8>),
    /// COM_FIELD_LIST: list a table's columns. Deprecated.
    FieldList {
        /// The table.
        table: Vec<u8>,
        /// A `LIKE` pattern the column names must match.
        wildcard: Vec<u8>,
    },
    /// COM_CREATE_DB: create a database. Deprecated.
    CreateDb(Vec<u8>),
    /// COM_DROP_DB: drop a database. Deprecated.
    DropDb(Vec<u8>),
    /// COM_REFRESH: flush tables, logs or caches, as the bits say.
    Refresh(u8),
    /// COM_STATISTICS: a line of server statistics.
    Statistics,
    /// COM_PROCESS_INFO: the list of threads. Deprecated.
    ProcessInfo,
    /// COM_PROCESS_KILL: end a connection by its ID.
    ProcessKill(u32),
    /// COM_DEBUG: dump debug output to the server log.
    Debug,
    /// COM_PING: check the server is alive.
    Ping,
    /// COM_STMT_PREPARE: prepare a statement from the SQL text.
    StmtPrepare(Vec<u8>),
    /// COM_STMT_CLOSE: free a prepared statement by its ID.
    StmtClose(u32),
    /// COM_STMT_RESET: reset a prepared statement's data.
    StmtReset(u32),
    /// COM_SET_OPTION: turn multi-statements on (0) or off (1).
    SetOption(u16),
    /// COM_RESET_CONNECTION: reset the session without logging in again.
    ResetConnection,
    /// Any other command, such as COM_STMT_EXECUTE or COM_CHANGE_USER,
    /// with its data unread. Its command byte must be one no other
    /// variant covers, or [`Command::to_payload`] gives
    /// [`Error::Header`].
    Other {
        /// The command byte.
        command: u8,
        /// The bytes after it.
        data: Vec<u8>,
    },
}

impl Command {
    /// Reads a command payload under the connection's capability flags.
    /// Bytes after a command's fixed fields are ignored, as MySQL ignores
    /// them. A COM_QUERY with query attributes that has parameters gives
    /// [`Error::Unsupported`], and one whose parameter set count is not 1
    /// gives [`Error::Value`], as MySQL refuses it.
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<Command, Error> {
        let mut r = Reader(payload);
        let code = r.u8()?;
        Ok(match code {
            command::QUIT => Command::Quit,
            command::INIT_DB => Command::InitDb(r.rest().to_vec()),
            command::QUERY => {
                if capabilities & capability::QUERY_ATTRIBUTES != 0 {
                    let parameters = r.lenenc()?;
                    let sets = r.lenenc()?;
                    if sets != 1 {
                        return Err(Error::Value(sets));
                    }
                    if parameters != 0 {
                        return Err(Error::Unsupported);
                    }
                }
                Command::Query(r.rest().to_vec())
            }
            command::FIELD_LIST => {
                let table = r.nul()?.to_vec();
                Command::FieldList { table, wildcard: r.rest().to_vec() }
            }
            command::CREATE_DB => Command::CreateDb(r.rest().to_vec()),
            command::DROP_DB => Command::DropDb(r.rest().to_vec()),
            command::REFRESH => Command::Refresh(r.u8()?),
            command::STATISTICS => Command::Statistics,
            command::PROCESS_INFO => Command::ProcessInfo,
            command::PROCESS_KILL => Command::ProcessKill(r.u32()?),
            command::DEBUG => Command::Debug,
            command::PING => Command::Ping,
            command::STMT_PREPARE => Command::StmtPrepare(r.rest().to_vec()),
            command::STMT_CLOSE => Command::StmtClose(r.u32()?),
            command::STMT_RESET => Command::StmtReset(r.u32()?),
            command::SET_OPTION => Command::SetOption(r.u16()?),
            command::RESET_CONNECTION => Command::ResetConnection,
            _ => Command::Other { command: code, data: r.rest().to_vec() },
        })
    }

    /// The command's byte.
    pub fn code(&self) -> u8 {
        match self {
            Command::Quit => command::QUIT,
            Command::InitDb(_) => command::INIT_DB,
            Command::Query(_) => command::QUERY,
            Command::FieldList { .. } => command::FIELD_LIST,
            Command::CreateDb(_) => command::CREATE_DB,
            Command::DropDb(_) => command::DROP_DB,
            Command::Refresh(_) => command::REFRESH,
            Command::Statistics => command::STATISTICS,
            Command::ProcessInfo => command::PROCESS_INFO,
            Command::ProcessKill(_) => command::PROCESS_KILL,
            Command::Debug => command::DEBUG,
            Command::Ping => command::PING,
            Command::StmtPrepare(_) => command::STMT_PREPARE,
            Command::StmtClose(_) => command::STMT_CLOSE,
            Command::StmtReset(_) => command::STMT_RESET,
            Command::SetOption(_) => command::SET_OPTION,
            Command::ResetConnection => command::RESET_CONNECTION,
            Command::Other { command, .. } => *command,
        }
    }

    /// The command's payload, for a world that plays a client. With
    /// [`capability::QUERY_ATTRIBUTES`], a query says it has no
    /// attributes. A table name holding a NUL gives [`Error::Nul`], and
    /// [`Command::Other`] with a command byte another variant covers
    /// gives [`Error::Header`], since neither would read back the same.
    pub fn to_payload(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        if let Command::Other { command, .. } = self {
            // A byte a variant covers reads as that variant, or gives an
            // error when it has no fields.
            if !matches!(Command::parse(&[*command], 0), Ok(Command::Other { .. })) {
                return Err(Error::Header(*command));
            }
        }
        let mut out = vec![self.code()];
        match self {
            Command::Quit
            | Command::Statistics
            | Command::ProcessInfo
            | Command::Debug
            | Command::Ping
            | Command::ResetConnection => {}
            Command::Query(sql) => {
                if capabilities & capability::QUERY_ATTRIBUTES != 0 {
                    out.extend_from_slice(&[0, 1]);
                }
                out.extend_from_slice(sql);
            }
            Command::InitDb(s) | Command::CreateDb(s) | Command::DropDb(s) | Command::StmtPrepare(s) => {
                out.extend_from_slice(s)
            }
            Command::FieldList { table, wildcard } => {
                put_nul(&mut out, table)?;
                out.extend_from_slice(wildcard);
            }
            Command::Refresh(b) => out.push(*b),
            Command::ProcessKill(id) | Command::StmtClose(id) | Command::StmtReset(id) => {
                out.extend_from_slice(&id.to_le_bytes())
            }
            Command::SetOption(o) => out.extend_from_slice(&o.to_le_bytes()),
            Command::Other { data, .. } => out.extend_from_slice(data),
        }
        Ok(out)
    }
}

/// A column definition (ColumnDefinition41), sent before the rows of a
/// result set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Column {
    /// Always `def`.
    pub catalog: Vec<u8>,
    /// The database.
    pub schema: Vec<u8>,
    /// The table's name in the query, which may be an alias.
    pub table: Vec<u8>,
    /// The table's real name.
    pub org_table: Vec<u8>,
    /// The column's name in the query, which may be an alias.
    pub name: Vec<u8>,
    /// The column's real name.
    pub org_name: Vec<u8>,
    /// The character set and collation of the values. 63 is binary.
    pub charset: u16,
    /// The longest a value can be.
    pub length: u32,
    /// The type, one of [`column_type`].
    pub column_type: u8,
    /// Flags from [`column_flag`].
    pub flags: u16,
    /// Digits after the decimal point.
    pub decimals: u8,
}

impl Column {
    /// A computed column named `name` of type `column_type`: catalog
    /// `def`, no table, `utf8mb4` text and room for 255 characters.
    pub fn new(name: &[u8], column_type: u8) -> Column {
        Column {
            catalog: b"def".to_vec(),
            name: name.to_vec(),
            charset: u16::from(charset::UTF8MB4_0900_AI_CI),
            length: 255 * 4,
            column_type,
            ..Column::default()
        }
    }

    /// Reads a column definition. Bytes after the fixed fields, which
    /// COM_FIELD_LIST uses for default values, are ignored.
    pub fn parse(payload: &[u8]) -> Result<Column, Error> {
        let mut r = Reader(payload);
        let mut c = Column {
            catalog: r.lenenc_str()?.to_vec(),
            schema: r.lenenc_str()?.to_vec(),
            table: r.lenenc_str()?.to_vec(),
            org_table: r.lenenc_str()?.to_vec(),
            name: r.lenenc_str()?.to_vec(),
            org_name: r.lenenc_str()?.to_vec(),
            ..Column::default()
        };
        let fixed = r.lenenc()?;
        if fixed != 0x0c {
            return Err(Error::FixedFields(fixed));
        }
        c.charset = r.u16()?;
        c.length = r.u32()?;
        c.column_type = r.u8()?;
        c.flags = r.u16()?;
        c.decimals = r.u8()?;
        r.take(2)?; // filler
        Ok(c)
    }

    /// The column definition's payload.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in [&self.catalog, &self.schema, &self.table, &self.org_table, &self.name, &self.org_name] {
            write_lenenc_str(&mut out, s);
        }
        out.push(0x0c);
        out.extend_from_slice(&self.charset.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.push(self.column_type);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.push(self.decimals);
        out.extend_from_slice(&[0, 0]);
        out
    }
}

/// One row of a text result set: each value as text, or `None` for NULL.
pub type Row = Vec<Option<Vec<u8>>>;

/// Reads a text result set row of `columns` values. Each is a
/// length-encoded string, or 0xFB for NULL. Fewer values give
/// [`Error::Truncated`], and bytes after the last give
/// [`Error::Trailing`].
pub fn parse_row(payload: &[u8], columns: usize) -> Result<Row, Error> {
    if columns > MAX_COLUMNS {
        return Err(Error::TooMany);
    }
    let mut r = Reader(payload);
    let mut row = Vec::new();
    for _ in 0..columns {
        if r.0.first() == Some(&0xfb) {
            r.0 = &r.0[1..];
            row.push(None);
        } else {
            row.push(Some(r.lenenc_str()?.to_vec()));
        }
    }
    if !r.0.is_empty() {
        return Err(Error::Trailing);
    }
    Ok(row)
}

/// A text result set row's payload. A row of more than [`MAX_COLUMNS`]
/// values gives [`Error::TooMany`], as [`parse_row`] does.
pub fn write_row(row: &[Option<Vec<u8>>]) -> Result<Vec<u8>, Error> {
    if row.len() > MAX_COLUMNS {
        return Err(Error::TooMany);
    }
    let mut out = Vec::new();
    for v in row {
        match v {
            Some(v) => write_lenenc_str(&mut out, v),
            None => out.push(0xfb),
        }
    }
    Ok(out)
}

/// The payload that asks the client to send a local file (the reply to
/// `LOAD DATA LOCAL INFILE`): 0xFB and the file name. The client sends
/// the file's bytes, then an empty message, and the server answers with
/// an OK or ERR packet. Send it only to a client that set
/// [`capability::LOCAL_FILES`].
pub fn local_infile_request(filename: &[u8]) -> Vec<u8> {
    let mut out = vec![0xfb];
    out.extend_from_slice(filename);
    out
}

/// A whole text result set, for a world that plays a server to write as
/// the answer to a query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResultSet {
    /// The columns.
    pub columns: Vec<Column>,
    /// The rows, each with one value per column.
    pub rows: Vec<Row>,
    /// The server status flags sent at the end.
    pub status: u16,
    /// The warning count sent at the end.
    pub warnings: u16,
}

impl ResultSet {
    /// The result set's payloads in order: the column count, the column
    /// definitions, an EOF unless the flags include
    /// [`capability::DEPRECATE_EOF`], the rows, and an EOF or an OK
    /// packet that ends them. Write them with [`write_messages`].
    ///
    /// Column definitions are written in the 4.1 layout, so the flags
    /// must include [`capability::PROTOCOL_41`], or a result set with
    /// columns gives [`Error::Unsupported`]. With
    /// [`capability::OPTIONAL_RESULTSET_METADATA`] the column count says
    /// the definitions follow.
    ///
    /// More than [`MAX_COLUMNS`] columns give [`Error::TooMany`], and a row
    /// whose value count is not the column count gives [`Error::Length`]
    /// with that count. A result set with no columns is written as an OK
    /// packet, since a column count of 0 cannot be told from one, so it
    /// may have no rows.
    pub fn to_payloads(&self, capabilities: u32) -> Result<Vec<Vec<u8>>, Error> {
        let columns = &self.columns;
        if columns.len() > MAX_COLUMNS {
            return Err(Error::TooMany);
        }
        if let Some(row) = self.rows.iter().find(|row| row.len() != columns.len()) {
            return Err(Error::Length(row.len()));
        }
        let end_ok = OkPacket { status: self.status, warnings: self.warnings, ..OkPacket::default() };
        if columns.is_empty() {
            if !self.rows.is_empty() {
                return Err(Error::Length(0));
            }
            return Ok(vec![end_ok.to_payload(capabilities)]);
        }
        if capabilities & capability::PROTOCOL_41 == 0 {
            return Err(Error::Unsupported);
        }
        let eof = Eof { warnings: self.warnings, status: self.status }.to_payload(capabilities);
        let deprecate_eof = capabilities & capability::DEPRECATE_EOF != 0;
        let mut out = Vec::with_capacity(columns.len() + self.rows.len() + 3);
        let mut count = Vec::new();
        write_lenenc_int(&mut count, columns.len() as u64);
        if capabilities & capability::OPTIONAL_RESULTSET_METADATA != 0 {
            count.push(METADATA_FULL);
        }
        out.push(count);
        out.extend(columns.iter().map(Column::to_payload));
        if !deprecate_eof {
            out.push(eof.clone());
        }
        for row in &self.rows {
            out.push(write_row(row)?);
        }
        out.push(if deprecate_eof { end_ok.to_end_payload(capabilities)? } else { eof });
        Ok(out)
    }
}

/// What a [`ResultReader`] made of one payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultEvent {
    /// The command succeeded with no result set.
    Ok(OkPacket),
    /// The command failed.
    Err(ErrPacket),
    /// The server asks for the named local file, on a connection with
    /// [`capability::LOCAL_FILES`]. The client sends it, and the reader
    /// then takes only the server's OK or ERR packet.
    LocalInfile(Vec<u8>),
    /// A result set starts, with this many columns.
    ColumnCount(usize),
    /// One column definition.
    Column(Column),
    /// The EOF packet after the column definitions.
    ColumnsEnd(Eof),
    /// One row.
    Row(Row),
    /// The rows ended. With [`capability::DEPRECATE_EOF`] this is the OK
    /// packet that ended them, with its info text and session state.
    /// Otherwise it holds the EOF packet's status and warning count, and
    /// the other fields are empty.
    End(OkPacket),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    Start,
    /// After a local file request: only an OK or ERR packet may come.
    InfileReply,
    Columns {
        left: usize,
    },
    ColumnsEof,
    Rows,
    Done,
}

/// Follows a server's answer to a COM_QUERY, one payload at a time, for
/// a world that plays a client. It reads an OK packet, an ERR packet, a
/// local file request or a text result set, and goes on to the next
/// result while the status flags include
/// [`status::MORE_RESULTS_EXISTS`].
#[derive(Clone, Debug)]
pub struct ResultReader {
    capabilities: u32,
    state: ReadState,
    columns: usize,
}

impl ResultReader {
    /// A reader for a connection with these capability flags.
    pub fn new(capabilities: u32) -> ResultReader {
        ResultReader { capabilities, state: ReadState::Start, columns: 0 }
    }

    /// Whether the last result has ended.
    pub fn is_done(&self) -> bool {
        self.state == ReadState::Done
    }

    /// How many columns the current result set has.
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// Reads the next payload. On an error the reader stays where it was.
    /// Payloads after the last result give [`Error::Finished`]. Result
    /// sets need [`capability::PROTOCOL_41`], and local file requests
    /// [`capability::LOCAL_FILES`]. With
    /// [`capability::OPTIONAL_RESULTSET_METADATA`], a result set the server
    /// sends without its column definitions gives [`Error::Unsupported`].
    pub fn push(&mut self, payload: &[u8]) -> Result<ResultEvent, Error> {
        let caps = self.capabilities;
        let first = *payload.first().ok_or(Error::Truncated)?;
        match self.state {
            ReadState::Done => Err(Error::Finished),
            ReadState::Start => match first {
                0x00 => {
                    let ok = OkPacket::parse(payload, caps)?;
                    self.after(ok.status);
                    Ok(ResultEvent::Ok(ok))
                }
                0xff => {
                    let e = ErrPacket::parse(payload, caps)?;
                    self.state = ReadState::Done;
                    Ok(ResultEvent::Err(e))
                }
                0xfb => {
                    if caps & capability::LOCAL_FILES == 0 {
                        return Err(Error::Header(first));
                    }
                    self.state = ReadState::InfileReply;
                    Ok(ResultEvent::LocalInfile(payload[1..].to_vec()))
                }
                _ => {
                    if caps & capability::PROTOCOL_41 == 0 {
                        return Err(Error::Unsupported);
                    }
                    let mut r = Reader(payload);
                    let n = r.lenenc()?;
                    // The flag byte comes after the count, as libmysql reads it.
                    if caps & capability::OPTIONAL_RESULTSET_METADATA != 0 && r.u8()? != METADATA_FULL {
                        return Err(Error::Unsupported);
                    }
                    if !r.0.is_empty() {
                        return Err(Error::Trailing);
                    }
                    if n == 0 {
                        // A count of 0 in a longer encoding than 0x00.
                        return Err(Error::Header(first));
                    }
                    let n = usize::try_from(n).ok().filter(|&n| n <= MAX_COLUMNS).ok_or(Error::TooMany)?;
                    self.columns = n;
                    self.state = ReadState::Columns { left: n };
                    Ok(ResultEvent::ColumnCount(n))
                }
            },
            ReadState::InfileReply => match first {
                0x00 => {
                    let ok = OkPacket::parse(payload, caps)?;
                    self.after(ok.status);
                    Ok(ResultEvent::Ok(ok))
                }
                0xff => {
                    let e = ErrPacket::parse(payload, caps)?;
                    self.state = ReadState::Done;
                    Ok(ResultEvent::Err(e))
                }
                _ => Err(Error::Header(first)),
            },
            ReadState::Columns { left } => {
                let c = Column::parse(payload)?;
                self.state = if left > 1 {
                    ReadState::Columns { left: left - 1 }
                } else if caps & capability::DEPRECATE_EOF != 0 {
                    ReadState::Rows
                } else {
                    ReadState::ColumnsEof
                };
                Ok(ResultEvent::Column(c))
            }
            ReadState::ColumnsEof => {
                let eof = Eof::parse(payload, caps)?;
                self.state = ReadState::Rows;
                Ok(ResultEvent::ColumnsEnd(eof))
            }
            ReadState::Rows => {
                // An EOF packet is under 9 bytes, so a longer payload that
                // starts with 0xFE is a row with an 8-byte length.
                let deprecate_eof = caps & capability::DEPRECATE_EOF != 0;
                let end_len = if deprecate_eof { MAX_PACKET_PAYLOAD } else { 9 };
                if first == 0xfe && payload.len() < end_len {
                    let end = if deprecate_eof {
                        OkPacket::parse(payload, caps)?
                    } else {
                        let eof = Eof::parse(payload, caps)?;
                        OkPacket { status: eof.status, warnings: eof.warnings, ..OkPacket::default() }
                    };
                    self.after(end.status);
                    return Ok(ResultEvent::End(end));
                }
                if first == 0xff {
                    let e = ErrPacket::parse(payload, caps)?;
                    self.state = ReadState::Done;
                    return Ok(ResultEvent::Err(e));
                }
                Ok(ResultEvent::Row(parse_row(payload, self.columns)?))
            }
        }
    }

    fn after(&mut self, status: u16) {
        self.state = if status & status::MORE_RESULTS_EXISTS != 0 { ReadState::Start } else { ReadState::Done };
    }
}

/// Appends `s` and a NUL. A NUL inside `s` gives [`Error::Nul`].
fn put_nul(out: &mut Vec<u8>, s: &[u8]) -> Result<(), Error> {
    if s.contains(&0) {
        return Err(Error::Nul);
    }
    out.extend_from_slice(s);
    out.push(0);
    Ok(())
}

/// Reads fields from the front of a payload. Every read checks the
/// length first.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-encoded integer.
    fn lenenc(&mut self) -> Result<u64, Error> {
        let first = *self.0.first().ok_or(Error::Truncated)?;
        let n = match first {
            0..=0xfa => {
                self.0 = &self.0[1..];
                return Ok(u64::from(first));
            }
            0xfc => 2,
            0xfd => 3,
            0xfe => 8,
            _ => return Err(Error::LengthPrefix(first)),
        };
        if self.0.len() < 1 + n {
            return Err(Error::Truncated);
        }
        self.0 = &self.0[1..];
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(self.take(n)?);
        Ok(u64::from_le_bytes(v))
    }

    /// A length-encoded string. Its length is checked against what is
    /// left before anything is taken.
    fn lenenc_str(&mut self) -> Result<&'a [u8], Error> {
        let mut probe = Reader(self.0);
        let n = probe.lenenc()?;
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        let s = probe.take(n)?;
        self.0 = probe.0;
        Ok(s)
    }

    /// A NUL-terminated string, without its NUL.
    fn nul(&mut self) -> Result<&'a [u8], Error> {
        let i = self.0.iter().position(|&b| b == 0).ok_or(Error::Truncated)?;
        let s = &self.0[..i];
        self.0 = &self.0[i + 1..];
        Ok(s)
    }

    /// A NUL-terminated string, or the rest of the payload if no NUL
    /// comes.
    fn nul_or_rest(&mut self) -> &'a [u8] {
        match self.nul() {
            Ok(s) => s,
            Err(_) => self.rest(),
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPS41: u32 = capability::PROTOCOL_41 | capability::SECURE_CONNECTION | capability::TRANSACTIONS;
    const CAPS_MODERN: u32 = CAPS41
        | capability::PLUGIN_AUTH
        | capability::PLUGIN_AUTH_LENENC_CLIENT_DATA
        | capability::CONNECT_WITH_DB
        | capability::CONNECT_ATTRS
        | capability::SESSION_TRACK
        | capability::DEPRECATE_EOF
        | capability::MULTI_RESULTS;
    /// Flag sets the readers are tried under.
    const CAPS_SETS: [u32; 5] =
        [0, capability::TRANSACTIONS, CAPS41, CAPS_MODERN, CAPS_MODERN | capability::QUERY_ATTRIBUTES];

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    /// Every strict prefix of `full` is refused or reads as something else.
    fn prefixes<T: PartialEq + std::fmt::Debug>(full: &[u8], parse: impl Fn(&[u8]) -> Result<T, Error>) {
        prefixes_but_nul(full, false, parse)
    }

    /// The same, but when `nul_optional` a closing NUL at the very end may
    /// be left out, as the handshakes allow.
    fn prefixes_but_nul<T: PartialEq + std::fmt::Debug>(
        full: &[u8],
        nul_optional: bool,
        parse: impl Fn(&[u8]) -> Result<T, Error>,
    ) {
        let whole = parse(full).unwrap();
        for n in 0..full.len() {
            match parse(&full[..n]) {
                Err(Error::Truncated) => {}
                Ok(v) if nul_optional && full[n..] == [0] => assert_eq!(v, whole),
                Ok(v) => assert_ne!(v, whole, "prefix of {n} bytes"),
                Err(e) => panic!("prefix of {n} bytes: {e:?}"),
            }
        }
    }

    // Examples from the client/server protocol chapter of the MySQL source
    // documentation.

    const HANDSHAKE_EXAMPLE: &str = "0a 35 2e 35 2e 32 2d 6d 32 00 52 00 00 00 22 3d 4e 50 29 75 39 56 00 ff ff 08 02 00 \
        00 00 00 00 00 00 00 00 00 00 00 00 00 29 64 40 52 5c 55 78 7a 7c 21 29 4b 00";

    #[test]
    fn handshake_example() {
        let bytes = hex(HANDSHAKE_EXAMPLE);
        assert_eq!(bytes.len(), 0x36);
        let h = Handshake::parse(&bytes).unwrap();
        assert_eq!(h.server_version, b"5.5.2-m2");
        assert_eq!(h.connection_id, 0x52);
        assert_eq!(h.capabilities, 0xffff);
        assert_eq!(h.charset, charset::LATIN1_SWEDISH_CI);
        assert_eq!(h.status, status::AUTOCOMMIT);
        assert_eq!(h.auth_data.len(), 21);
        assert_eq!(&h.auth_data[..8], &hex("22 3d 4e 50 29 75 39 56")[..]);
        assert!(h.auth_plugin.is_empty());
        assert_eq!(h.to_payload().unwrap(), bytes);
        prefixes_but_nul(&bytes, true, Handshake::parse);
    }

    #[test]
    fn handshake_with_plugin() {
        let h = Handshake {
            server_version: b"8.0.36".to_vec(),
            connection_id: 9,
            auth_data: (1..=21).collect(),
            capabilities: CAPS_MODERN,
            charset: 255,
            status: 2,
            auth_plugin: b"caching_sha2_password".to_vec(),
        };
        let p = h.to_payload().unwrap();
        // The auth data length field says 21.
        assert_eq!(p[1 + 7 + 4 + 8 + 1 + 2 + 1 + 2 + 2], 21);
        assert_eq!(Handshake::parse(&p), Ok(h.clone()));
        prefixes_but_nul(&p, true, Handshake::parse);
        // A server that leaves out the plugin name's NUL.
        assert_eq!(Handshake::parse(&p[..p.len() - 1]).unwrap().auth_plugin, b"caching_sha2_password");
        // A length below 21 still means 13 bytes in part 2.
        let mut q = p.clone();
        q[1 + 7 + 4 + 8 + 1 + 2 + 1 + 2 + 2] = 0;
        assert_eq!(Handshake::parse(&q), Ok(h));
    }

    #[test]
    fn handshake_short_form_and_errors() {
        let full = hex(HANDSHAKE_EXAMPLE);
        let short = &full[..1 + 9 + 4 + 8 + 1 + 2];
        let h = Handshake::parse(short).unwrap();
        assert_eq!((h.charset, h.status, h.auth_data.len()), (0, 0, 8));
        assert_eq!(h.to_payload().unwrap(), short);
        assert_eq!(Handshake::parse(&[9, b'x', 0]), Err(Error::Version(9)));
        assert_eq!(Handshake::parse(&[0xff, 0x15, 0x04]), Err(Error::Version(0xff)));
        // No NUL after the version.
        assert_eq!(Handshake::parse(&[10, b'5', b'.']), Err(Error::Truncated));
        // Writers refuse what would not read back the same: a NUL in a
        // name, and auth data of a length the flags cannot carry.
        let odd = Handshake {
            server_version: b"8\0junk".to_vec(),
            auth_data: vec![7; 21],
            capabilities: capability::SECURE_CONNECTION,
            charset: 8,
            ..Handshake::default()
        };
        assert_eq!(odd.to_payload(), Err(Error::Nul));
        let plugin = Handshake { capabilities: CAPS_MODERN, auth_plugin: b"a\0b".to_vec(), ..odd.clone() };
        assert_eq!(plugin.to_payload(), Err(Error::Nul));
        let fine = Handshake { server_version: b"8".to_vec(), ..odd.clone() };
        assert_eq!(Handshake::parse(&fine.to_payload().unwrap()), Ok(fine.clone()));
        for (n, caps) in [(3, 0), (20, 0), (22, 0), (20, CAPS_MODERN), (256, CAPS_MODERN)] {
            let h = Handshake { auth_data: vec![1; n], capabilities: caps, ..fine.clone() };
            assert_eq!(h.to_payload(), Err(Error::Length(n)), "{n} bytes, flags {caps:#x}");
        }
        let long = Handshake { auth_data: vec![1; 255], capabilities: CAPS_MODERN, charset: 8, ..Handshake::default() };
        assert_eq!(Handshake::parse(&long.to_payload().unwrap()), Ok(long));
    }

    #[test]
    fn handshake_part2_without_secure_connection() {
        // HandshakeV10 sends auth-plugin-data-part-2 in the long form
        // whatever the flags, at least 13 bytes, before the plugin name.
        let mut p = vec![10];
        p.extend_from_slice(b"8.0\0");
        p.extend_from_slice(&7u32.to_le_bytes());
        p.extend_from_slice(b"abcdefgh\0");
        p.extend_from_slice(&0u16.to_le_bytes());
        p.push(8);
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&((capability::PLUGIN_AUTH >> 16) as u16).to_le_bytes());
        p.push(21);
        p.extend_from_slice(&[0; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0");
        p.extend_from_slice(b"mysql_native_password\0");
        let h = Handshake::parse(&p).unwrap();
        assert_eq!(h.auth_data, b"abcdefghijklmnopqrst\0");
        assert_eq!(h.auth_plugin, b"mysql_native_password");
        assert_eq!(h.to_payload().unwrap(), p);
    }

    #[test]
    fn eof_rows_end_needs_short_packet() {
        // Without DEPRECATE_EOF, 0xFE ends the rows only in a packet under
        // 9 bytes. A longer one is a row whose first value has an 8-byte
        // length.
        let mut reader = ResultReader::new(CAPS41);
        reader.push(&[1]).unwrap();
        reader.push(&Column::new(b"a", column_type::VAR_STRING).to_payload()).unwrap();
        reader.push(&Eof::default().to_payload(CAPS41)).unwrap();
        let row = [0xfe, 1, 0, 0, 0, 0, 0, 0, 0, b'x'];
        assert_eq!(reader.push(&row), Ok(ResultEvent::Row(vec![Some(b"x".to_vec())])));
        let end = reader.push(&Eof::default().to_payload(CAPS41)).unwrap();
        assert_eq!(end, ResultEvent::End(OkPacket::default()));
    }

    const RESPONSE_EXAMPLE: &str = "8d a6 0f 00 00 00 00 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
        00 00 00 00 70 61 6d 00 14 ab 09 ee f6 bc b1 32 3e 61 14 38 65 c0 99 1d 95 7d 75 d4 47 74 65 73 74 00 6d 79 73 \
        71 6c 5f 6e 61 74 69 76 65 5f 70 61 73 73 77 6f 72 64 00";

    #[test]
    fn handshake_response_example() {
        let bytes = hex(RESPONSE_EXAMPLE);
        assert_eq!(bytes.len(), 0x54);
        let r = HandshakeResponse::parse(&bytes).unwrap();
        assert_eq!(r.capabilities, 0x000f_a68d);
        assert_eq!(r.max_packet, 16 * 1024 * 1024);
        assert_eq!(r.charset, 8);
        assert_eq!(r.username, b"pam");
        assert_eq!(r.auth_response.len(), 20);
        assert_eq!(r.database, b"test");
        assert_eq!(r.auth_plugin, b"mysql_native_password");
        assert_eq!(r.to_payload().unwrap(), bytes);
        prefixes_but_nul(&bytes, true, HandshakeResponse::parse);
    }

    #[test]
    fn handshake_response_modern() {
        let r = HandshakeResponse {
            capabilities: CAPS_MODERN | capability::ZSTD_COMPRESSION_ALGORITHM,
            max_packet: 1 << 24,
            charset: 255,
            username: b"root".to_vec(),
            auth_response: vec![0; 300],
            database: b"shop".to_vec(),
            auth_plugin: b"caching_sha2_password".to_vec(),
            attributes: vec![(b"_client_name".to_vec(), b"libmysql".to_vec()), (b"_pid".to_vec(), b"42".to_vec())],
            zstd_level: 3,
        };
        let p = r.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        prefixes(&p, HandshakeResponse::parse);
        // Without the length-encoded flag, an auth response over 255
        // bytes cannot be written.
        let short = HandshakeResponse { capabilities: CAPS41, ..r.clone() };
        assert_eq!(short.to_payload(), Err(Error::Length(300)));
        let short = HandshakeResponse { auth_response: vec![1; 255], ..short };
        assert_eq!(HandshakeResponse::parse(&short.to_payload().unwrap()).unwrap().auth_response, short.auth_response);
        // Without SECURE_CONNECTION it ends at a NUL, so it may hold none.
        let old = HandshakeResponse {
            capabilities: capability::PROTOCOL_41,
            auth_response: b"ab\0cd".to_vec(),
            ..HandshakeResponse::default()
        };
        assert_eq!(old.to_payload(), Err(Error::Nul));
        let user = HandshakeResponse { username: b"alice\0admin".to_vec(), ..r.clone() };
        assert_eq!(user.to_payload(), Err(Error::Nul));
        // Errors.
        let pre41 = [0u8; 40];
        assert_eq!(HandshakeResponse::parse(&pre41), Err(Error::Unsupported));
        let many = HandshakeResponse {
            capabilities: CAPS_MODERN,
            attributes: vec![(vec![], vec![]); MAX_ATTRIBUTES],
            ..HandshakeResponse::default()
        };
        let mut p = many.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p).unwrap().attributes.len(), MAX_ATTRIBUTES);
        // Two more bytes in the block: one more attribute.
        let block = MAX_ATTRIBUTES * 2;
        let at = p.len() - block - 3;
        assert_eq!(p[at], 0xfc);
        p[at + 1..at + 3].copy_from_slice(&((block + 2) as u16).to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        assert_eq!(HandshakeResponse::parse(&p), Err(Error::TooMany));
        let more = HandshakeResponse { attributes: vec![(vec![], vec![]); MAX_ATTRIBUTES + 1], ..many };
        assert_eq!(more.to_payload(), Err(Error::TooMany));
        // A bad length prefix in the auth response.
        let mut bad =
            HandshakeResponse { capabilities: CAPS_MODERN, ..HandshakeResponse::default() }.to_payload().unwrap();
        bad[33] = 0xff;
        assert_eq!(HandshakeResponse::parse(&bad), Err(Error::LengthPrefix(0xff)));
    }

    #[test]
    fn ssl_request() {
        let s = SslRequest { capabilities: CAPS41, max_packet: 1 << 24, charset: 45 };
        let p = s.to_payload();
        assert_eq!(p.len(), SSL_REQUEST_LEN);
        let back = SslRequest::parse(&p).unwrap();
        assert_eq!(back.capabilities, CAPS41 | capability::SSL);
        prefixes(&p, SslRequest::parse);
        assert_eq!(HandshakeResponse::parse(&p), Err(Error::Truncated));
        let mut long = p.clone();
        long.push(0);
        assert_eq!(SslRequest::parse(&long), Err(Error::Trailing));
        let mut no_ssl = p;
        no_ssl[1] &= !0x08;
        assert_eq!(SslRequest::parse(&no_ssl), Err(Error::Unsupported));
    }

    #[test]
    fn ok_example() {
        let bytes = hex("00 00 00 02 00 00 00");
        let ok = OkPacket::parse(&bytes, CAPS41).unwrap();
        assert_eq!(ok, OkPacket { status: status::AUTOCOMMIT, ..OkPacket::default() });
        assert_eq!(ok.to_payload(CAPS41), bytes);
        prefixes(&bytes, |b| OkPacket::parse(b, CAPS41));
        // With info text.
        let ok = OkPacket { affected_rows: 300, last_insert_id: 70000, info: b"Rows matched: 1".to_vec(), ..ok };
        let p = ok.to_payload(CAPS41);
        assert_eq!(&p[..7], &[0, 0xfc, 0x2c, 0x01, 0xfd, 0x70, 0x11]);
        assert_eq!(OkPacket::parse(&p, CAPS41), Ok(ok.clone()));
        // Session tracking.
        let tracked = OkPacket {
            status: status::SESSION_STATE_CHANGED,
            session_state: vec![0, 4, 3, b'a', b'b', b'c'],
            ..ok.clone()
        };
        let p = tracked.to_payload(CAPS_MODERN);
        assert_eq!(OkPacket::parse(&p, CAPS_MODERN), Ok(tracked.clone()));
        prefixes(&p, |b| OkPacket::parse(b, CAPS_MODERN));
        // The end of a result set.
        let end = tracked.to_end_payload(CAPS_MODERN).unwrap();
        assert_eq!(end[0], 0xfe);
        assert_eq!(OkPacket::parse(&end, CAPS_MODERN), Ok(tracked));
        // Before 4.1: the status goes only with TRANSACTIONS.
        let p = ok.to_payload(capability::TRANSACTIONS);
        assert_eq!(OkPacket::parse(&p, capability::TRANSACTIONS).unwrap().status, ok.status);
        assert_eq!(OkPacket::parse(&ok.to_payload(0), 0).unwrap().status, 0);
        // Errors.
        assert_eq!(OkPacket::parse(&[0x01, 0, 0], CAPS41), Err(Error::Header(1)));
        assert_eq!(OkPacket::parse(&[0x00, 0xfb, 0], CAPS41), Err(Error::LengthPrefix(0xfb)));
        // Long info is written whole.
        let big = OkPacket { info: vec![b'x'; 0x1_0010], ..OkPacket::default() };
        assert_eq!(OkPacket::parse(&big.to_payload(CAPS_MODERN), CAPS_MODERN), Ok(big));
    }

    #[test]
    fn err_example() {
        let bytes = hex("ff 48 04 23 48 59 30 30 30 4e 6f 20 74 61 62 6c 65 73 20 75 73 65 64");
        let e = ErrPacket::parse(&bytes, CAPS41).unwrap();
        assert_eq!(e, ErrPacket::new(1096, b"HY000", b"No tables used"));
        assert_eq!(e.to_payload(CAPS41).unwrap(), bytes);
        prefixes(&bytes, |b| ErrPacket::parse(b, CAPS41));
        // Before the handshake, or before 4.1: no SQLSTATE.
        let early = ErrPacket::parse(&hex("ff 15 04 48 6f 73 74"), CAPS41).unwrap();
        assert_eq!((early.code, early.sql_state, &early.message[..]), (1045, None, &b"Host"[..]));
        let old = ErrPacket::parse(&bytes, 0).unwrap();
        assert_eq!(old.sql_state, None);
        assert_eq!(&old.message[..6], b"#HY000");
        assert_eq!(ErrPacket::new(1, b"HY000", b"x").to_payload(0).unwrap(), [0xff, 1, 0, b'x']);
        assert_eq!(ErrPacket::parse(&[0x00, 1, 0], CAPS41), Err(Error::Header(0)));
    }

    #[test]
    fn eof_example() {
        let bytes = hex("fe 00 00 02 00");
        let eof = Eof::parse(&bytes, CAPS41).unwrap();
        assert_eq!(eof, Eof { warnings: 0, status: status::AUTOCOMMIT });
        assert_eq!(eof.to_payload(CAPS41), bytes);
        prefixes(&bytes, |b| Eof::parse(b, CAPS41));
        assert_eq!(Eof::parse(&[0xfe], 0), Ok(Eof::default()));
        assert_eq!(Eof::parse(&[0xfe; 9], CAPS41), Err(Error::Trailing));
        assert_eq!(Eof::parse(&[0x00, 0, 0, 0, 0], CAPS41), Err(Error::Header(0)));
    }

    #[test]
    fn query_example() {
        let bytes = hex(
            "21 00 00 00 03 73 65 6c 65 63 74 20 40 40 76 65 72 73 69 6f 6e 5f 63 6f 6d 6d 65 6e 74 20 6c 69 6d 69 74 20 31",
        );
        let mut d = Decoder::new();
        d.feed(&bytes);
        let m = d.next_message().unwrap().unwrap();
        assert_eq!(m.seq, 0);
        let c = Command::parse(&m.payload, CAPS41).unwrap();
        assert_eq!(c, Command::Query(b"select @@version_comment limit 1".to_vec()));
        assert_eq!(Message { seq: 0, payload: c.to_payload(CAPS41).unwrap() }.to_bytes().unwrap(), bytes);
        // With query attributes and none sent.
        let attrs = CAPS41 | capability::QUERY_ATTRIBUTES;
        let p = c.to_payload(attrs).unwrap();
        assert_eq!(&p[..3], &[3, 0, 1]);
        assert_eq!(Command::parse(&p, attrs), Ok(c));
        assert_eq!(Command::parse(&[3, 1, 1, 0, 0], attrs), Err(Error::Unsupported));
        assert_eq!(Command::parse(&[3, 0], attrs), Err(Error::Truncated));
    }

    #[test]
    fn commands_round_trip() {
        let all = [
            Command::Quit,
            Command::InitDb(b"shop".to_vec()),
            Command::Query(b"SELECT * FROM t".to_vec()),
            Command::FieldList { table: b"t".to_vec(), wildcard: b"a%".to_vec() },
            Command::CreateDb(b"x".to_vec()),
            Command::DropDb(b"x".to_vec()),
            Command::Refresh(1),
            Command::Statistics,
            Command::ProcessInfo,
            Command::ProcessKill(77),
            Command::Debug,
            Command::Ping,
            Command::StmtPrepare(b"SELECT ?".to_vec()),
            Command::StmtClose(5),
            Command::StmtReset(6),
            Command::SetOption(1),
            Command::ResetConnection,
            Command::Other { command: command::STMT_EXECUTE, data: vec![1, 0, 0, 0, 0, 1, 0, 0, 0] },
        ];
        for c in all {
            let p = c.to_payload(CAPS41).unwrap();
            assert_eq!(p[0], c.code());
            assert_eq!(Command::parse(&p, CAPS41), Ok(c.clone()));
            prefixes(&p, |b| Command::parse(b, CAPS41));
        }
        assert_eq!(Command::parse(&[], CAPS41), Err(Error::Truncated));
        assert_eq!(Command::parse(&[command::STMT_CLOSE, 1, 2], CAPS41), Err(Error::Truncated));
        assert_eq!(Command::parse(&[command::FIELD_LIST, b't'], CAPS41), Err(Error::Truncated));
        // Bytes after fixed fields are ignored.
        assert_eq!(Command::parse(&[command::PING, 9, 9], CAPS41), Ok(Command::Ping));
    }

    #[test]
    fn lenenc() {
        for (v, bytes) in [
            (0u64, vec![0x00]),
            (250, vec![0xfa]),
            (251, vec![0xfc, 0xfb, 0x00]),
            (0xffff, vec![0xfc, 0xff, 0xff]),
            (0x1_0000, vec![0xfd, 0x00, 0x00, 0x01]),
            (0xff_ffff, vec![0xfd, 0xff, 0xff, 0xff]),
            (0x100_0000, vec![0xfe, 0, 0, 0, 1, 0, 0, 0, 0]),
            (u64::MAX, vec![0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        ] {
            let mut out = Vec::new();
            write_lenenc_int(&mut out, v);
            assert_eq!(out, bytes);
            assert_eq!(read_lenenc_int(&bytes), Ok((v, bytes.len())));
            for n in 0..bytes.len() {
                assert_eq!(read_lenenc_int(&bytes[..n]), Err(Error::Truncated));
            }
        }
        // A longer encoding than needed is read too.
        assert_eq!(read_lenenc_int(&[0xfc, 5, 0]), Ok((5, 3)));
        assert_eq!(read_lenenc_int(&[0xfb]), Err(Error::LengthPrefix(0xfb)));
        assert_eq!(read_lenenc_int(&[0xff]), Err(Error::LengthPrefix(0xff)));
        let mut s = Vec::new();
        write_lenenc_str(&mut s, b"hello");
        assert_eq!(s, b"\x05hello");
        assert_eq!(read_lenenc_str(&s), Ok((&b"hello"[..], 6)));
        assert_eq!(read_lenenc_str(&s[..5]), Err(Error::Truncated));
        // A length past anything that could follow.
        assert_eq!(read_lenenc_str(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0x80]), Err(Error::Truncated));
    }

    #[test]
    fn result_set_example() {
        let caps = CAPS41;
        let column = Column {
            catalog: b"def".to_vec(),
            name: b"@@version_comment".to_vec(),
            charset: 8,
            length: 0x1c,
            column_type: column_type::VAR_STRING,
            decimals: 0x1f,
            ..Column::default()
        };
        let set = ResultSet {
            columns: vec![column.clone()],
            rows: vec![vec![Some(b"MySQL Community Server (GPL)".to_vec())]],
            status: status::AUTOCOMMIT,
            warnings: 0,
        };
        let (bytes, next) = write_messages(1, &set.to_payloads(caps).unwrap()).unwrap();
        let expected = hex("01 00 00 01 01 \
             27 00 00 02 03 64 65 66 00 00 00 11 40 40 76 65 72 73 69 6f 6e 5f 63 6f 6d 6d 65 6e 74 00 0c 08 00 1c 00 \
             00 00 fd 00 00 1f 00 00 \
             05 00 00 03 fe 00 00 02 00 \
             1d 00 00 04 1c 4d 79 53 51 4c 20 43 6f 6d 6d 75 6e 69 74 79 20 53 65 72 76 65 72 20 28 47 50 4c 29 \
             05 00 00 05 fe 00 00 02 00");
        assert_eq!(bytes, expected);
        assert_eq!(next, 6);
        prefixes(&column.to_payload(), Column::parse);

        // Read back.
        let mut d = Decoder::new();
        d.feed(&bytes);
        let mut r = ResultReader::new(caps);
        let mut events = Vec::new();
        while let Some(m) = d.next_message() {
            events.push(r.push(&m.unwrap().payload).unwrap());
        }
        assert_eq!(
            events,
            [
                ResultEvent::ColumnCount(1),
                ResultEvent::Column(column),
                ResultEvent::ColumnsEnd(Eof { warnings: 0, status: 2 }),
                ResultEvent::Row(set.rows[0].clone()),
                ResultEvent::End(OkPacket { status: 2, ..OkPacket::default() }),
            ]
        );
        assert!(r.is_done());
        assert_eq!(r.push(&[0]), Err(Error::Finished));
    }

    #[test]
    fn result_reader_paths() {
        let caps = CAPS_MODERN;
        // Two result sets, the first saying more follow, then the rows end.
        let first = ResultSet {
            columns: vec![Column::new(b"a", column_type::LONG), Column::new(b"b", column_type::VAR_STRING)],
            rows: vec![vec![Some(b"1".to_vec()), None], vec![None, Some(vec![])]],
            status: status::MORE_RESULTS_EXISTS,
            warnings: 1,
        };
        let mut payloads = first.to_payloads(caps).unwrap();
        payloads.push(OkPacket { affected_rows: 3, ..OkPacket::default() }.to_payload(caps));
        let mut r = ResultReader::new(caps);
        let events: Vec<_> = payloads.iter().map(|p| r.push(p).unwrap()).collect();
        assert_eq!(events.len(), 1 + 2 + 2 + 1 + 1);
        assert_eq!(events[3], ResultEvent::Row(vec![Some(b"1".to_vec()), None]));
        assert_eq!(events[4], ResultEvent::Row(vec![None, Some(vec![])]));
        assert_eq!(
            events[5],
            ResultEvent::End(OkPacket { status: status::MORE_RESULTS_EXISTS, warnings: 1, ..OkPacket::default() })
        );
        assert!(matches!(events[6], ResultEvent::Ok(OkPacket { affected_rows: 3, .. })));
        assert!(r.is_done());

        // ERR, mid rows and at the start.
        let err = ErrPacket::new(1146, b"42S02", b"Table 'x' doesn't exist").to_payload(caps).unwrap();
        let mut r = ResultReader::new(caps);
        assert!(matches!(r.push(&err), Ok(ResultEvent::Err(_))));
        assert!(r.is_done());
        let mut r = ResultReader::new(caps);
        r.push(&[1]).unwrap();
        r.push(&Column::new(b"a", 3).to_payload()).unwrap();
        assert_eq!(r.columns(), 1);
        assert!(matches!(r.push(&err), Ok(ResultEvent::Err(_))));

        // A local file request, then the OK after the file.
        let caps = caps | capability::LOCAL_FILES;
        let mut r = ResultReader::new(caps);
        assert_eq!(
            r.push(&local_infile_request(b"/etc/passwd")),
            Ok(ResultEvent::LocalInfile(b"/etc/passwd".to_vec()))
        );
        assert!(!r.is_done());
        assert!(matches!(r.push(&[0, 0, 0, 0, 0, 0, 0]), Ok(ResultEvent::Ok(_))));

        // No columns: written as an OK packet.
        let empty = ResultSet::default().to_payloads(caps).unwrap();
        assert_eq!(empty.len(), 1);
        assert!(matches!(ResultReader::new(caps).push(&empty[0]), Ok(ResultEvent::Ok(_))));

        // Errors leave the reader where it was.
        let mut r = ResultReader::new(caps);
        assert_eq!(r.push(&[]), Err(Error::Truncated));
        assert_eq!(r.push(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Header(0xfe)));
        assert_eq!(r.push(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 1]), Err(Error::TooMany));
        assert_eq!(r.push(&[0xfc, 0x01, 0x10]), Err(Error::TooMany));
        assert_eq!(r.push(&[2, 0]), Err(Error::Trailing));
        assert_eq!(ResultReader::new(0).push(&[1]), Err(Error::Unsupported));
        let optional = caps | capability::OPTIONAL_RESULTSET_METADATA;
        assert_eq!(ResultReader::new(optional).push(&[1]), Err(Error::Truncated));
        assert_eq!(ResultReader::new(optional).push(&[1, 0]), Err(Error::Unsupported));
        assert_eq!(ResultReader::new(optional).push(&[1, METADATA_FULL]), Ok(ResultEvent::ColumnCount(1)));
        assert_eq!(ResultReader::new(optional).push(&[1, METADATA_FULL, 0]), Err(Error::Trailing));
        r.push(&[1]).unwrap();
        let mut bad = Column::new(b"a", 3).to_payload();
        let at = bad.len() - 13;
        bad[at] = 0x0b;
        assert_eq!(r.push(&bad), Err(Error::FixedFields(0x0b)));
        assert_eq!(Column::parse(&bad), Err(Error::FixedFields(0x0b)));
        r.push(&Column::new(b"a", 3).to_payload()).unwrap();
        assert_eq!(r.push(&[1, b'x', 2]), Err(Error::Trailing));
        assert_eq!(r.push(&[0xfe, 0]), Err(Error::Truncated));
        assert_eq!(r.push(&[0xfb]), Ok(ResultEvent::Row(vec![None])));
    }

    #[test]
    fn result_sets_read_back_under_each_flag_set() {
        // Whatever the 4.1 flags, a result set written reads back whole.
        let set = ResultSet {
            columns: vec![Column::new(b"a", column_type::LONG), Column::new(b"b", column_type::VAR_STRING)],
            rows: vec![vec![Some(b"1".to_vec()), None], vec![None, Some(vec![0xfe; 300])]],
            status: status::AUTOCOMMIT,
            warnings: 2,
        };
        let extras = [
            0,
            capability::DEPRECATE_EOF,
            capability::SESSION_TRACK,
            capability::OPTIONAL_RESULTSET_METADATA,
            capability::OPTIONAL_RESULTSET_METADATA | capability::DEPRECATE_EOF | capability::SESSION_TRACK,
        ];
        for extra in extras {
            let caps = capability::PROTOCOL_41 | extra;
            let mut r = ResultReader::new(caps);
            let mut rows = Vec::new();
            let mut columns = Vec::new();
            for p in set.to_payloads(caps).unwrap() {
                match r.push(&p) {
                    Ok(ResultEvent::Row(row)) => rows.push(row),
                    Ok(ResultEvent::Column(c)) => columns.push(c),
                    Ok(ResultEvent::End(ok)) => assert_eq!((ok.status, ok.warnings), (2, 2)),
                    Ok(_) => {}
                    Err(e) => panic!("flags {caps:#x}: {e:?}"),
                }
            }
            assert!(r.is_done(), "flags {caps:#x}");
            assert_eq!((columns, &rows), (set.columns.clone(), &set.rows), "flags {caps:#x}");
        }
    }

    #[test]
    fn decoder_many_small_messages_in_one_feed() {
        // A megabyte of empty packets fed at once. Taking each message
        // out must not move the rest of the buffer, or the work grows
        // with the square of the input.
        let n = 1 << 18;
        let stream: Vec<u8> = (0..n).flat_map(|i| [0, 0, 0, i as u8]).collect();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut count = 0;
        while let Some(m) = d.next_message() {
            assert_eq!(m.unwrap().seq, count as u8);
            assert_eq!(d.buf.len(), stream.len());
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        // What was read is dropped on the next feed.
        d.feed(&[1, 0, 0, 0]);
        assert_eq!(d.buffered(), 4);
        assert_eq!(d.buf.len(), 4);
        d.feed(b"x");
        assert_eq!(d.next_message(), Some(Ok(Message { seq: 0, payload: b"x".to_vec() })));
    }

    #[test]
    fn rows() {
        let row = vec![Some(b"abc".to_vec()), None, Some(vec![])];
        let p = write_row(&row).unwrap();
        assert_eq!(p, [3, b'a', b'b', b'c', 0xfb, 0]);
        assert_eq!(parse_row(&p, 3), Ok(row.clone()));
        prefixes(&p, |b| parse_row(b, 3));
        assert_eq!(parse_row(&p, 2), Err(Error::Trailing));
        assert_eq!(parse_row(&p, 4), Err(Error::Truncated));
        assert_eq!(parse_row(&[0xff], 1), Err(Error::LengthPrefix(0xff)));
        assert_eq!(parse_row(&[], MAX_COLUMNS + 1), Err(Error::TooMany));
        assert_eq!(parse_row(&[], 0), Ok(vec![]));
    }

    #[test]
    fn split_packets() {
        // A payload one byte past a full packet takes two.
        let payload: Vec<u8> = (0..MAX_PACKET_PAYLOAD + 1).map(|i| i as u8).collect();
        let m = Message { seq: 254, payload };
        assert_eq!(m.packets(), 2);
        assert_eq!(m.next_seq(), 0);
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), m.payload.len() + 8);
        assert_eq!(&bytes[..4], &[0xff, 0xff, 0xff, 254]);
        assert_eq!(&bytes[HEADER_LEN + MAX_PACKET_PAYLOAD..][..4], &[1, 0, 0, 255]);
        let mut d = Decoder::new();
        for chunk in bytes.chunks(1 << 20) {
            d.feed(chunk);
        }
        assert_eq!(d.next_message(), Some(Ok(m.clone())));
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 0);

        // Exactly a full packet: an empty packet follows.
        let full = Message { seq: 3, payload: vec![9; MAX_PACKET_PAYLOAD] };
        let bytes = full.to_bytes().unwrap();
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        assert_eq!(full.next_seq(), 5);
        let mut d = Decoder::new();
        d.feed(&bytes[..bytes.len() - 1]);
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), MAX_PACKET_PAYLOAD + 3);
        d.feed(&bytes[bytes.len() - 1..]);
        assert_eq!(d.next_message(), Some(Ok(full)));

        // A continuation with the wrong sequence ID breaks the stream.
        let mut d = Decoder::new();
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] = 9;
        d.feed(&bad);
        assert_eq!(d.next_message(), Some(Err(FrameError::Sequence { expected: 4, got: 9 })));
        d.feed(&[1, 0, 0, 0, 1]);
        assert_eq!(d.next_message(), Some(Err(FrameError::Sequence { expected: 4, got: 9 })));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_limits_and_stream() {
        let mut d = Decoder::with_limit(10);
        d.feed(&[11, 0, 0, 0]);
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLong(11))));
        d.feed(&[1, 0, 0, 0, 1]);
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLong(11))));
        let mut d = Decoder::with_limit(10);
        d.feed(&[10, 0, 0, 0]);
        assert_eq!(d.next_message(), None);
        assert_eq!(Decoder::with_limit(usize::MAX).limit, MAX_MESSAGE);

        // Several messages, one byte at a time, and the empty message.
        let ms = [
            Message { seq: 0, payload: vec![] },
            Message { seq: 1, payload: b"abc".to_vec() },
            Message { seq: 0, payload: vec![3; 300] },
        ];
        let stream: Vec<u8> = ms.iter().flat_map(|m| m.to_bytes().unwrap()).collect();
        for n in 0..4 {
            let mut d = Decoder::new();
            d.feed(&stream[..n]);
            assert_eq!(d.next_message(), None);
        }
        let mut d = Decoder::default();
        let mut got = Vec::new();
        for b in &stream {
            d.feed(std::slice::from_ref(b));
            while let Some(m) = d.next_message() {
                got.push(m.unwrap());
            }
        }
        assert_eq!(got, ms);
        let (bytes, next) = write_messages(0, &[vec![], b"abc".to_vec()]).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 3, 0, 0, 1, b'a', b'b', b'c']);
        assert_eq!(next, 2);
    }

    #[test]
    fn errors_display() {
        for e in [
            Error::Truncated,
            Error::Header(1),
            Error::LengthPrefix(0xff),
            Error::Version(9),
            Error::FixedFields(3),
            Error::TooMany,
            Error::Unsupported,
            Error::Trailing,
            Error::Finished,
            Error::Length(3),
            Error::Nul,
            Error::Value(0),
            Error::SqlState,
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(!FrameError::TooLong(5).to_string().is_empty());
        assert!(!FrameError::Sequence { expected: 1, got: 2 }.to_string().is_empty());
    }

    // Regressions for an outside review of this module.

    #[test]
    fn decoder_holds_at_most_its_capacity() {
        // One large feed: only a header's worth past the limit is taken,
        // and the over-long message is refused from its header.
        let mut d = Decoder::with_limit(16);
        let mut big = vec![0x11, 0, 0, 0];
        big.resize(1 << 20, 0);
        let n = d.feed(&big);
        assert_eq!(n, d.capacity());
        assert_eq!(d.capacity(), 16 + HEADER_LEN);
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLong(17))));
        assert_eq!(d.feed(&big), big.len());
        assert_eq!(d.buffered(), 0);
        // Many feeds without taking messages out: the decoder fills up,
        // then takes nothing more.
        let mut d = Decoder::with_limit(16);
        let mut taken = 0;
        for _ in 0..1000 {
            taken += d.feed(&[1, 0, 0, 0, b'x']);
        }
        assert_eq!(taken, d.capacity());
        assert_eq!(d.buffered(), d.capacity());
        // Taking messages out makes room again.
        assert!(d.next_message().unwrap().is_ok());
        assert!(d.feed(&[1, 0, 0, 0, b'x']) > 0);
        // A split message counts against the capacity too.
        let m = Message { seq: 0, payload: vec![7; MAX_PACKET_PAYLOAD + 10] }.to_bytes().unwrap();
        let mut d = Decoder::with_limit(MAX_PACKET_PAYLOAD + 10);
        let (got, left) = read_stream(&mut d, &m, 1 << 16);
        assert_eq!(left, 0);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].as_ref().unwrap().payload.len(), MAX_PACKET_PAYLOAD + 10);
    }

    #[test]
    fn writers_refuse_messages_over_the_limit() {
        // Zeroed memory is not touched before the length check, so this
        // costs no real memory.
        let huge = vec![0u8; MAX_MESSAGE + 1];
        let m = Message { seq: 0, payload: huge };
        assert_eq!(m.to_bytes(), Err(FrameError::TooLong(MAX_MESSAGE + 1)));
        assert_eq!(m.packets(), (MAX_MESSAGE + 1) / MAX_PACKET_PAYLOAD + 1);
        let payloads = [b"ok".to_vec(), m.payload];
        assert_eq!(write_messages(0, &payloads), Err(FrameError::TooLong(MAX_MESSAGE + 1)));
    }

    #[test]
    fn ok_session_state_is_written_whole_and_reaches_the_end_event() {
        let caps = capability::PROTOCOL_41 | capability::DEPRECATE_EOF | capability::SESSION_TRACK;
        // 16384 schema-change-like blocks: 65536 bytes, past the old cut.
        let state: Vec<u8> = [3, 2, 1, b'1'].repeat(16384);
        let ok = OkPacket { status: status::SESSION_STATE_CHANGED, session_state: state, ..OkPacket::default() };
        assert_eq!(OkPacket::parse(&ok.to_payload(caps), caps), Ok(ok.clone()));
        assert_eq!(OkPacket::parse(&ok.to_end_payload(caps).unwrap(), caps), Ok(ok.clone()));
        // A result set ended by an OK packet that changed the schema.
        let end = OkPacket {
            status: status::SESSION_STATE_CHANGED,
            session_state: vec![1, 3, 2, b'd', b'b'],
            ..OkPacket::default()
        };
        let mut r = ResultReader::new(caps);
        r.push(&[1]).unwrap();
        r.push(&Column::new(b"a", 3).to_payload()).unwrap();
        assert_eq!(r.push(&end.to_end_payload(caps).unwrap()), Ok(ResultEvent::End(end)));
        // An end packet as long as a packet holds would read as a row.
        let long = OkPacket { info: vec![b'i'; MAX_PACKET_PAYLOAD], ..OkPacket::default() };
        assert!(matches!(long.to_end_payload(caps), Err(Error::Length(_))));
    }

    #[test]
    fn ok_needs_its_session_state_and_nothing_after() {
        let caps = capability::PROTOCOL_41 | capability::SESSION_TRACK;
        // The flag is set and the info is there, but no session state.
        assert_eq!(OkPacket::parse(&hex("00 00 00 00 40 00 00 00"), caps), Err(Error::Truncated));
        // Ending after the warnings is allowed, as libmysql allows it.
        let ok = OkPacket::parse(&hex("00 00 00 00 40 00 00"), caps).unwrap();
        assert_eq!(ok.status, status::SESSION_STATE_CHANGED);
        assert_eq!(OkPacket::parse(&ok.to_payload(caps), caps), Ok(ok));
        assert_eq!(OkPacket::parse(&hex("00 00 00 00 40 00 00 00 00 aa"), caps), Err(Error::Trailing));
        assert_eq!(OkPacket::parse(&hex("00 00 00 02 00 00 00 00 aa"), caps), Err(Error::Trailing));
    }

    #[test]
    fn handshake_response_needs_the_fields_its_flags_name() {
        let r = HandshakeResponse {
            capabilities: CAPS41 | capability::CONNECT_WITH_DB,
            username: b"u".to_vec(),
            database: b"db".to_vec(),
            ..HandshakeResponse::default()
        };
        let p = r.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        // The database's NUL left out, or the whole database.
        assert_eq!(HandshakeResponse::parse(&p[..p.len() - 1]), Err(Error::Truncated));
        assert_eq!(HandshakeResponse::parse(&p[..p.len() - 3]), Err(Error::Truncated));
        // The attribute block's length left out.
        let r = HandshakeResponse { capabilities: r.capabilities | capability::CONNECT_ATTRS, ..r };
        let p = r.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        assert_eq!(HandshakeResponse::parse(&p[..p.len() - 1]), Err(Error::Truncated));
        // The zstd level left out.
        let caps = r.capabilities | capability::ZSTD_COMPRESSION_ALGORITHM;
        let r = HandshakeResponse { capabilities: caps, zstd_level: 3, ..r };
        let p = r.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        assert_eq!(HandshakeResponse::parse(&p[..p.len() - 1]), Err(Error::Truncated));
    }

    #[test]
    fn handshake_response_attribute_block_limit() {
        let r = HandshakeResponse {
            capabilities: CAPS41 | capability::CONNECT_ATTRS,
            attributes: vec![(b"k".to_vec(), vec![b'v'; 65536])],
            ..HandshakeResponse::default()
        };
        assert!(matches!(r.to_payload(), Err(Error::Length(_))));
        // The most that fits: a 1-byte key and a value with a 3-byte length.
        let fits = HandshakeResponse { attributes: vec![(b"k".to_vec(), vec![b'v'; 65535 - 2 - 3])], ..r.clone() };
        let p = fits.to_payload().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(fits.clone()));
        let over = HandshakeResponse { attributes: vec![(b"k".to_vec(), vec![b'v'; 65535 - 2 - 2])], ..r };
        assert_eq!(over.to_payload(), Err(Error::Length(65536)));
        // The same block, read: its length is checked before anything else.
        let mut q = p[..p.len() - 65535 - 3].to_vec();
        write_lenenc_int(&mut q, 65536);
        q.extend_from_slice(&p[p.len() - 65535..]);
        q.push(0);
        assert_eq!(HandshakeResponse::parse(&q), Err(Error::Length(65536)));
    }

    #[test]
    fn zstd_level_must_be_valid() {
        let caps = CAPS41 | capability::ZSTD_COMPRESSION_ALGORITHM;
        for level in [0u8, 23, 255] {
            let r = HandshakeResponse { capabilities: caps, zstd_level: level, ..HandshakeResponse::default() };
            assert_eq!(r.to_payload(), Err(Error::Value(u64::from(level))));
            let mut p = HandshakeResponse { zstd_level: 3, ..r }.to_payload().unwrap();
            *p.last_mut().unwrap() = level;
            assert_eq!(HandshakeResponse::parse(&p), Err(Error::Value(u64::from(level))));
        }
        for level in ZSTD_LEVELS {
            let r = HandshakeResponse { capabilities: caps, zstd_level: level, ..HandshakeResponse::default() };
            assert_eq!(HandshakeResponse::parse(&r.to_payload().unwrap()), Ok(r));
        }
    }

    #[test]
    fn query_parameter_set_count_must_be_one() {
        let caps = CAPS41 | capability::QUERY_ATTRIBUTES;
        assert_eq!(Command::parse(&hex("03 00 00 53 45 4c 45 43 54 20 31"), caps), Err(Error::Value(0)));
        assert_eq!(Command::parse(&hex("03 00 02 53"), caps), Err(Error::Value(2)));
        assert_eq!(Command::parse(&hex("03 00 01 53"), caps), Ok(Command::Query(b"S".to_vec())));
    }

    #[test]
    fn local_infile_needs_the_flag_and_then_an_answer() {
        let request = local_infile_request(b"/etc/passwd");
        assert_eq!(ResultReader::new(CAPS41).push(&request), Err(Error::Header(0xfb)));
        let caps = CAPS41 | capability::LOCAL_FILES;
        let mut r = ResultReader::new(caps);
        assert_eq!(r.push(&request), Ok(ResultEvent::LocalInfile(b"/etc/passwd".to_vec())));
        // Only an OK or ERR packet may follow.
        assert_eq!(r.push(&request), Err(Error::Header(0xfb)));
        assert_eq!(r.push(&[1]), Err(Error::Header(1)));
        let err = ErrPacket::new(1290, b"HY000", b"no").to_payload(caps).unwrap();
        assert!(matches!(r.clone().push(&err), Ok(ResultEvent::Err(_))));
        assert!(matches!(r.push(&OkPacket::default().to_payload(caps)), Ok(ResultEvent::Ok(_))));
        assert!(r.is_done());
    }

    #[test]
    fn err_without_sqlstate_cannot_fake_one() {
        let e = ErrPacket { code: 1045, sql_state: None, message: b"#HY000oops".to_vec() };
        assert_eq!(e.to_payload(CAPS41), Err(Error::SqlState));
        // Before 4.1 no SQLSTATE is read, so it reads back the same.
        assert_eq!(ErrPacket::parse(&e.to_payload(0).unwrap(), 0), Ok(e));
        // A short message after `#` is no SQLSTATE.
        let e = ErrPacket { code: 1045, sql_state: None, message: b"#oops".to_vec() };
        assert_eq!(ErrPacket::parse(&e.to_payload(CAPS41).unwrap(), CAPS41), Ok(e));
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        assert_eq!(write_row(&vec![None; MAX_COLUMNS + 1]), Err(Error::TooMany));
        assert_eq!(write_row(&vec![None; MAX_COLUMNS]).map(|p| p.len()), Ok(MAX_COLUMNS));
        for code in [command::QUIT, command::QUERY, command::STMT_CLOSE, command::FIELD_LIST, command::SET_OPTION] {
            let c = Command::Other { command: code, data: vec![] };
            assert_eq!(c.to_payload(CAPS41), Err(Error::Header(code)));
        }
        let c = Command::Other { command: command::STMT_EXECUTE, data: vec![] };
        assert_eq!(Command::parse(&c.to_payload(CAPS41).unwrap(), CAPS41), Ok(c));
        let c = Command::FieldList { table: b"t\0x".to_vec(), wildcard: vec![] };
        assert_eq!(c.to_payload(CAPS41), Err(Error::Nul));
        let set = ResultSet { columns: vec![Column::new(b"a", 3)], rows: vec![], ..ResultSet::default() };
        assert_eq!(set.to_payloads(0), Err(Error::Unsupported));
        assert_eq!(
            ResultSet { columns: vec![Column::new(b"a", 3); MAX_COLUMNS + 1], ..set.clone() }.to_payloads(CAPS41),
            Err(Error::TooMany)
        );
    }

    #[test]
    fn result_set_rows_must_match_the_columns() {
        let two = vec![Column::new(b"a", 3), Column::new(b"b", 3)];
        let short = ResultSet { columns: two.clone(), rows: vec![vec![Some(b"1".to_vec())]], ..ResultSet::default() };
        assert_eq!(short.to_payloads(CAPS41), Err(Error::Length(1)));
        let long = ResultSet { columns: two, rows: vec![vec![None; 3]], ..ResultSet::default() };
        assert_eq!(long.to_payloads(CAPS41), Err(Error::Length(3)));
        let none = ResultSet { rows: vec![vec![]], ..ResultSet::default() };
        assert_eq!(none.to_payloads(CAPS41), Err(Error::Length(0)));
        // 4096 columns and empty rows are refused, not padded with NULLs.
        let wide = ResultSet {
            columns: vec![Column::new(b"c", 3); MAX_COLUMNS],
            rows: vec![vec![]; 1000],
            ..ResultSet::default()
        };
        assert_eq!(wide.to_payloads(CAPS41), Err(Error::Length(0)));
    }

    #[test]
    fn eof_takes_no_bytes_after_its_fields() {
        assert_eq!(Eof::parse(&hex("fe 00 00 02 00 aa"), CAPS41), Err(Error::Trailing));
        assert_eq!(Eof::parse(&hex("fe aa"), 0), Err(Error::Trailing));
        assert_eq!(Eof::parse(&hex("fe"), 0), Ok(Eof::default()));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// What every reader must do with any bytes: not panic, and give back
    /// what it read when its output is read again.
    fn check_payload(b: &[u8]) {
        if let Ok(h) = Handshake::parse(b) {
            assert_eq!(Handshake::parse(&h.to_payload().unwrap()), Ok(h));
        }
        if let Ok(h) = HandshakeResponse::parse(b) {
            assert_eq!(HandshakeResponse::parse(&h.to_payload().unwrap()), Ok(h));
        }
        if let Ok(s) = SslRequest::parse(b) {
            assert_eq!(SslRequest::parse(&s.to_payload()), Ok(s));
        }
        if let Ok(c) = Column::parse(b) {
            assert_eq!(Column::parse(&c.to_payload()), Ok(c));
        }
        for caps in CAPS_SETS {
            if let Ok(ok) = OkPacket::parse(b, caps) {
                assert_eq!(OkPacket::parse(&ok.to_payload(caps), caps), Ok(ok.clone()));
                assert_eq!(OkPacket::parse(&ok.to_end_payload(caps).unwrap(), caps), Ok(ok));
            }
            if let Ok(e) = ErrPacket::parse(b, caps) {
                assert_eq!(ErrPacket::parse(&e.to_payload(caps).unwrap(), caps), Ok(e));
            }
            if let Ok(e) = Eof::parse(b, caps) {
                assert_eq!(Eof::parse(&e.to_payload(caps), caps), Ok(e));
            }
            if let Ok(c) = Command::parse(b, caps) {
                assert_eq!(Command::parse(&c.to_payload(caps).unwrap(), caps), Ok(c));
            }
            let mut r = ResultReader::new(caps);
            let _ = r.push(b);
        }
        for n in 0..4 {
            if let Ok(row) = parse_row(b, n) {
                assert_eq!(parse_row(&write_row(&row).unwrap(), n), Ok(row));
            }
        }
        if let Ok((v, used)) = read_lenenc_int(b) {
            assert!(used <= b.len());
            let mut out = Vec::new();
            write_lenenc_int(&mut out, v);
            assert_eq!(read_lenenc_int(&out), Ok((v, out.len())));
        }
    }

    fn samples() -> Vec<Vec<u8>> {
        let mut s = vec![
            hex(HANDSHAKE_EXAMPLE),
            hex(RESPONSE_EXAMPLE),
            Handshake {
                server_version: b"8.0".to_vec(),
                auth_data: vec![5; 21],
                capabilities: CAPS_MODERN,
                charset: 255,
                auth_plugin: b"x".to_vec(),
                ..Handshake::default()
            }
            .to_payload()
            .unwrap(),
            HandshakeResponse {
                capabilities: CAPS_MODERN | capability::ZSTD_COMPRESSION_ALGORITHM,
                username: b"u".to_vec(),
                auth_response: vec![1, 2],
                database: b"d".to_vec(),
                auth_plugin: b"p".to_vec(),
                attributes: vec![(b"k".to_vec(), b"v".to_vec())],
                zstd_level: 3,
                ..HandshakeResponse::default()
            }
            .to_payload()
            .unwrap(),
            SslRequest::default().to_payload(),
            OkPacket {
                status: status::SESSION_STATE_CHANGED,
                info: b"i".to_vec(),
                session_state: vec![1, 2],
                ..OkPacket::default()
            }
            .to_payload(CAPS_MODERN),
            ErrPacket::new(1, b"HY000", b"m").to_payload(CAPS41).unwrap(),
            Eof::default().to_payload(CAPS41),
            Column::new(b"c", 3).to_payload(),
            write_row(&[Some(b"a".to_vec()), None]).unwrap(),
            Command::Query(b"q".to_vec()).to_payload(CAPS41 | capability::QUERY_ATTRIBUTES).unwrap(),
            Command::FieldList { table: b"t".to_vec(), wildcard: vec![] }.to_payload(0).unwrap(),
        ];
        let set = ResultSet {
            columns: vec![Column::new(b"a", 3)],
            rows: vec![vec![Some(b"1".to_vec())]],
            ..ResultSet::default()
        };
        s.extend(set.to_payloads(CAPS41).unwrap());
        s
    }

    #[test]
    fn lcg_fuzz() {
        let samples = samples();
        let mut rng = Lcg(0x5e_ed0f_3306);
        for round in 0..6000 {
            let mut b = if round % 3 == 0 {
                (0..rng.below(80)).map(|_| rng.next() as u8).collect()
            } else {
                let mut b = samples[rng.below(samples.len())].clone();
                for _ in 0..rng.below(4) {
                    if !b.is_empty() {
                        let i = rng.below(b.len());
                        b[i] = match rng.below(4) {
                            0 => 0,
                            1 => 0xfb + rng.below(5) as u8,
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
            check_payload(&b);

            // The same bytes as a stream, whole and a byte at a time.
            if round % 2 == 0 {
                // Keep lengths small so streams complete.
                for i in (0..b.len()).step_by(7) {
                    if i + 2 < b.len() && rng.below(2) == 0 {
                        b[i] = rng.below(12) as u8;
                        b[i + 1] = 0;
                        b[i + 2] = 0;
                    }
                }
            }
            let limit = 8 + rng.below(64);
            let (a, rest_a) = read_stream(&mut Decoder::with_limit(limit), &b, b.len().max(1));
            let (c, rest_c) = read_stream(&mut Decoder::with_limit(limit), &b, 1);
            assert_eq!((&a, rest_a), (&c, rest_c));
            for m in a.iter().flatten() {
                check_payload(&m.payload);
                let bytes = m.to_bytes().unwrap();
                let mut d = Decoder::new();
                d.feed(&bytes);
                assert_eq!(d.next_message().as_ref(), Some(&Ok(m.clone())));
            }
            // A result reader fed a run of payloads.
            for caps in CAPS_SETS {
                let mut r = ResultReader::new(caps);
                for m in a.iter().flatten() {
                    let _ = r.push(&m.payload);
                }
            }

            // A random result set, written and read back. One row in five
            // has the wrong number of values, which the writer refuses.
            let ncols = rng.below(4);
            let set = ResultSet {
                columns: (0..ncols).map(|i| Column::new(&[b'a' + i as u8], rng.next() as u8)).collect(),
                rows: (0..rng.below(4))
                    .map(|_| {
                        (0..if rng.below(5) == 0 { rng.below(ncols + 2) } else { ncols })
                            .map(|_| match rng.below(3) {
                                0 => None,
                                _ => Some((0..rng.below(300)).map(|_| 0xfa + rng.below(6) as u8).collect()),
                            })
                            .collect()
                    })
                    .collect(),
                status: rng.next() as u16 & !status::MORE_RESULTS_EXISTS,
                warnings: rng.next() as u16,
            };
            let caps = capability::PROTOCOL_41 | (rng.next() as u32 & !capability::PROTOCOL_41);
            let payloads = match set.to_payloads(caps) {
                Ok(p) => p,
                Err(e) => {
                    // With no columns any row is refused, and the first
                    // row of the wrong length is the one named.
                    let bad = set.rows.iter().find(|row| row.len() != ncols).map_or(0, |row| row.len());
                    assert_eq!(e, Error::Length(bad));
                    continue;
                }
            };
            let mut r = ResultReader::new(caps);
            let mut rows = Vec::new();
            for p in payloads {
                if let ResultEvent::Row(row) = r.push(&p).unwrap() {
                    rows.push(row);
                }
            }
            assert!(r.is_done());
            assert_eq!(rows, set.rows);
        }
    }

    /// Feeds `bytes` to `d` in chunks of `chunk`, taking messages out
    /// until the first error. It returns them and how many bytes the
    /// decoder never took.
    fn read_stream(d: &mut Decoder, bytes: &[u8], chunk: usize) -> (Vec<Result<Message, FrameError>>, usize) {
        let mut out = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = d.feed(&rest[..chunk.min(rest.len())]);
            rest = &rest[n..];
            let mut took = false;
            while let Some(m) = d.next_message() {
                took = true;
                let stop = m.is_err();
                out.push(m);
                if stop {
                    return (out, 0);
                }
            }
            // A full decoder always gives a message or an error.
            assert!(n > 0 || took, "decoder took nothing and gave nothing");
            assert!(d.buffered() <= d.capacity());
        }
        (out, rest.len())
    }
}
