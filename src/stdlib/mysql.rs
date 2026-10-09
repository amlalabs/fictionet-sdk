//! MySQL: reading and writing the client/server protocol's packets, with
//! no I/O.
//!
//! AuthMoreData, prepare-OK responses and binary rows are unsupported.
//!
//! `Packet` and `Message` implement `Wire`. Stream decoders join packets and
//! `ResultReader` tracks result-set parsing. That state is not a login or query
//! session. Authentication, SQL execution, a database `Service`, and TLS
//! transport are outside this module.
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
//! sends a [`Handshake`] inside a [`Message`]. A [`Service`](fictionet::stdlib::serve::Service) served by
//! [`serve::connection`](fictionet::stdlib::serve::connection) uses `codec::Frames<Packet>` for packets
//! or [`Messages`] to join split packets and check their sequence IDs. It reads
//! each payload as a [`HandshakeResponse`] or [`Command`], then builds
//! reply messages from [`OkPacket`], [`ErrPacket`], or [`ResultSet`].
//! World code decides which users, databases, and tables exist and what
//! queries return. A client uses [`ResultReader`] to follow a result set.
//!
//! Every reader checks lengths. Bad bytes give an [`Error`] or a
//! [`Error`]. Writers refuse fields that cannot be preserved.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::mysql::{
//!     capability, column_type, status, Column, Command, Handshake, Message, Messages,
//!     ResultEvent, ResultReader, ResultSet, Row,
//! };
//!
//! let caps = capability::PROTOCOL_41 | capability::SECURE_CONNECTION
//!     | capability::PLUGIN_AUTH | capability::DEPRECATE_EOF;
//! let greeting = Handshake {
//!     server_version: b"8.0.36".to_vec(), connection_id: 1,
//!     auth_data: b"abcdefghijklmnopqrst\0".to_vec(), capabilities: caps,
//!     charset: 255, status: status::AUTOCOMMIT,
//!     auth_plugin: b"mysql_native_password".to_vec(),
//! };
//! let bytes = Message::from_payload(0, &greeting).unwrap().to_bytes().unwrap();
//! assert_eq!(Handshake::parse(&Message::parse(&bytes).unwrap().payload), Ok(greeting));
//!
//! // Read a query after login.
//! let mut stream = Stream::new(Messages::new());
//! assert_eq!(stream.push(b"\x09\x00\x00\x00\x03SELECT 1"), 13);
//! let query = stream.next().unwrap().unwrap();
//! assert_eq!(Command::parse(&query.payload, caps), Ok(Command::Query(b"SELECT 1".to_vec())));
//!
//! let result = ResultSet {
//!     columns: vec![Column::new(b"1", column_type::LONGLONG)],
//!     rows: vec![Row(vec![Some(b"1".to_vec())])],
//!     status: status::AUTOCOMMIT, warnings: 0,
//! };
//! let messages = result.messages(query.next_seq(), caps).unwrap();
//! let mut reply = Vec::new();
//! for message in &messages { message.write(&mut reply).unwrap(); }
//! assert_eq!(messages.last().unwrap().next_seq(), 5);
//!
//! let mut client = Stream::new(Messages::new());
//! assert_eq!(client.push(&reply), reply.len());
//! let mut reader = ResultReader::new(caps);
//! let mut rows = Vec::new();
//! while let Some(message) = client.next() {
//!     if let ResultEvent::Row(row) = reader.push(&message.unwrap().payload).unwrap() {
//!         rows.push(row);
//!     }
//! }
//! assert_eq!(rows, result.rows);
//! assert!(reader.is_done());
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Prefixed;
use fictionet::stdlib::codec::{Decode, Reader, Step, Truncated, Wire};

/// The TCP port MySQL servers listen on.
pub const PORT: u16 = 3306;
/// The length of a packet header: a 3-byte length and a sequence ID.
pub const HEADER_LEN: usize = 4;
/// The most payload one packet carries. A message this long or longer
/// goes on in the next packet, and a message whose length is a multiple
/// of it ends with an empty packet.
pub const MAX_PACKET_PAYLOAD: usize = 0xff_ffff;
/// The longest wire packet, including its four-byte header.
/// This is the default input capacity of [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames).
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PACKET_PAYLOAD;
/// The longest message a [`Messages`] puts together, and the longest
/// [`Message`] writes: 1 GiB, the largest `max_allowed_packet`
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
    /// Uses the newer password authentication scheme.
    pub const LONG_PASSWORD: u32 = 1;
    /// Returns matched rows instead of changed rows.
    pub const FOUND_ROWS: u32 = 1 << 1;
    /// Supports the extended column flags.
    pub const LONG_FLAG: u32 = 1 << 2;
    /// Names the initial database in the handshake response.
    pub const CONNECT_WITH_DB: u32 = 1 << 3;
    /// Disallows database qualifiers in table names.
    pub const NO_SCHEMA: u32 = 1 << 4;
    /// Uses compressed protocol packets.
    pub const COMPRESS: u32 = 1 << 5;
    /// Identifies an ODBC client.
    pub const ODBC: u32 = 1 << 6;
    /// Allows local file requests.
    pub const LOCAL_FILES: u32 = 1 << 7;
    /// Allows spaces after function names.
    pub const IGNORE_SPACE: u32 = 1 << 8;
    /// Uses the protocol 4.1 packet layouts.
    pub const PROTOCOL_41: u32 = 1 << 9;
    /// Uses the interactive connection timeout.
    pub const INTERACTIVE: u32 = 1 << 10;
    /// Requests TLS after the SSL request.
    pub const SSL: u32 = 1 << 11;
    /// Suppresses SIGPIPE in the client library.
    pub const IGNORE_SIGPIPE: u32 = 1 << 12;
    /// Carries transaction status in pre-4.1 OK packets.
    pub const TRANSACTIONS: u32 = 1 << 13;
    /// Reserved capability bit.
    pub const RESERVED: u32 = 1 << 14;
    /// Uses a one-byte authentication response length.
    pub const SECURE_CONNECTION: u32 = 1 << 15;
    /// Allows multiple statements in one query.
    pub const MULTI_STATEMENTS: u32 = 1 << 16;
    /// Allows multiple result sets from a query.
    pub const MULTI_RESULTS: u32 = 1 << 17;
    /// Allows multiple result sets from prepared statements.
    pub const PS_MULTI_RESULTS: u32 = 1 << 18;
    /// Names the authentication plugin.
    pub const PLUGIN_AUTH: u32 = 1 << 19;
    /// Carries connection attribute pairs.
    pub const CONNECT_ATTRS: u32 = 1 << 20;
    /// Uses a length-encoded authentication response.
    pub const PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
    /// Allows login with an expired password.
    pub const CAN_HANDLE_EXPIRED_PASSWORDS: u32 = 1 << 22;
    /// Carries session tracking fields in OK packets.
    pub const SESSION_TRACK: u32 = 1 << 23;
    /// Uses OK packets in place of EOF packets.
    pub const DEPRECATE_EOF: u32 = 1 << 24;
    /// Carries the result-set metadata selection byte.
    pub const OPTIONAL_RESULTSET_METADATA: u32 = 1 << 25;
    /// Negotiates zstd compression and its level.
    pub const ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
    /// Carries query attributes before SQL text.
    pub const QUERY_ATTRIBUTES: u32 = 1 << 27;
    /// Supports multiple authentication factors.
    pub const MULTI_FACTOR_AUTHENTICATION: u32 = 1 << 28;
    /// Requests verification of the server TLS certificate.
    pub const SSL_VERIFY_SERVER_CERT: u32 = 1 << 30;
    /// Retains client options across reconnects.
    pub const REMEMBER_OPTIONS: u32 = 1 << 31;
}

/// Server status flags, sent in OK and EOF packets.
pub mod status {
    /// A transaction is active.
    pub const IN_TRANS: u16 = 1;
    /// Autocommit is enabled.
    pub const AUTOCOMMIT: u16 = 1 << 1;
    /// Another result set follows this one.
    pub const MORE_RESULTS_EXISTS: u16 = 1 << 3;
    /// The query used no suitable index.
    pub const NO_GOOD_INDEX_USED: u16 = 1 << 4;
    /// The query used no index.
    pub const NO_INDEX_USED: u16 = 1 << 5;
    /// A prepared-statement cursor is open.
    pub const CURSOR_EXISTS: u16 = 1 << 6;
    /// The last cursor row was sent.
    pub const LAST_ROW_SENT: u16 = 1 << 7;
    /// The current database was dropped.
    pub const DB_DROPPED: u16 = 1 << 8;
    /// Backslash escapes are disabled.
    pub const NO_BACKSLASH_ESCAPES: u16 = 1 << 9;
    /// Prepared-statement metadata changed.
    pub const METADATA_CHANGED: u16 = 1 << 10;
    /// The server marked this query as slow.
    pub const QUERY_WAS_SLOW: u16 = 1 << 11;
    /// The result set carries output parameters.
    pub const PS_OUT_PARAMS: u16 = 1 << 12;
    /// The active transaction is read-only.
    pub const IN_TRANS_READONLY: u16 = 1 << 13;
    /// The OK packet carries session state changes.
    pub const SESSION_STATE_CHANGED: u16 = 1 << 14;
}

/// Command bytes: the first byte of every message a client sends after
/// the handshake.
pub mod command {
    /// The `COM_SLEEP` command byte.
    pub const SLEEP: u8 = 0x00;
    /// The `COM_QUIT` command byte.
    pub const QUIT: u8 = 0x01;
    /// The `COM_INIT_DB` command byte.
    pub const INIT_DB: u8 = 0x02;
    /// The `COM_QUERY` command byte.
    pub const QUERY: u8 = 0x03;
    /// The `COM_FIELD_LIST` command byte.
    pub const FIELD_LIST: u8 = 0x04;
    /// The `COM_CREATE_DB` command byte.
    pub const CREATE_DB: u8 = 0x05;
    /// The `COM_DROP_DB` command byte.
    pub const DROP_DB: u8 = 0x06;
    /// The `COM_REFRESH` command byte.
    pub const REFRESH: u8 = 0x07;
    /// The `COM_STATISTICS` command byte.
    pub const STATISTICS: u8 = 0x09;
    /// The `COM_PROCESS_INFO` command byte.
    pub const PROCESS_INFO: u8 = 0x0a;
    /// The `COM_CONNECT` command byte.
    pub const CONNECT: u8 = 0x0b;
    /// The `COM_PROCESS_KILL` command byte.
    pub const PROCESS_KILL: u8 = 0x0c;
    /// The `COM_DEBUG` command byte.
    pub const DEBUG: u8 = 0x0d;
    /// The `COM_PING` command byte.
    pub const PING: u8 = 0x0e;
    /// The `COM_TIME` command byte.
    pub const TIME: u8 = 0x0f;
    /// The `COM_DELAYED_INSERT` command byte.
    pub const DELAYED_INSERT: u8 = 0x10;
    /// The `COM_CHANGE_USER` command byte.
    pub const CHANGE_USER: u8 = 0x11;
    /// The `COM_BINLOG_DUMP` command byte.
    pub const BINLOG_DUMP: u8 = 0x12;
    /// The `COM_TABLE_DUMP` command byte.
    pub const TABLE_DUMP: u8 = 0x13;
    /// The `COM_CONNECT_OUT` command byte.
    pub const CONNECT_OUT: u8 = 0x14;
    /// The `COM_REGISTER_SLAVE` command byte.
    pub const REGISTER_SLAVE: u8 = 0x15;
    /// The `COM_STMT_PREPARE` command byte.
    pub const STMT_PREPARE: u8 = 0x16;
    /// The `COM_STMT_EXECUTE` command byte.
    pub const STMT_EXECUTE: u8 = 0x17;
    /// The `COM_STMT_SEND_LONG_DATA` command byte.
    pub const STMT_SEND_LONG_DATA: u8 = 0x18;
    /// The `COM_STMT_CLOSE` command byte.
    pub const STMT_CLOSE: u8 = 0x19;
    /// The `COM_STMT_RESET` command byte.
    pub const STMT_RESET: u8 = 0x1a;
    /// The `COM_SET_OPTION` command byte.
    pub const SET_OPTION: u8 = 0x1b;
    /// The `COM_STMT_FETCH` command byte.
    pub const STMT_FETCH: u8 = 0x1c;
    /// The `COM_DAEMON` command byte.
    pub const DAEMON: u8 = 0x1d;
    /// The `COM_BINLOG_DUMP_GTID` command byte.
    pub const BINLOG_DUMP_GTID: u8 = 0x1e;
    /// The `COM_RESET_CONNECTION` command byte.
    pub const RESET_CONNECTION: u8 = 0x1f;
    /// The `COM_CLONE` command byte.
    pub const CLONE: u8 = 0x20;
}

/// Column types, as a column definition names them.
pub mod column_type {
    /// The `MYSQL_TYPE_DECIMAL` column code.
    pub const DECIMAL: u8 = 0x00;
    /// The `MYSQL_TYPE_TINY` column code.
    pub const TINY: u8 = 0x01;
    /// The `MYSQL_TYPE_SHORT` column code.
    pub const SHORT: u8 = 0x02;
    /// The `MYSQL_TYPE_LONG` column code.
    pub const LONG: u8 = 0x03;
    /// The `MYSQL_TYPE_FLOAT` column code.
    pub const FLOAT: u8 = 0x04;
    /// The `MYSQL_TYPE_DOUBLE` column code.
    pub const DOUBLE: u8 = 0x05;
    /// The `MYSQL_TYPE_NULL` column code.
    pub const NULL: u8 = 0x06;
    /// The `MYSQL_TYPE_TIMESTAMP` column code.
    pub const TIMESTAMP: u8 = 0x07;
    /// The `MYSQL_TYPE_LONGLONG` column code.
    pub const LONGLONG: u8 = 0x08;
    /// The `MYSQL_TYPE_INT24` column code.
    pub const INT24: u8 = 0x09;
    /// The `MYSQL_TYPE_DATE` column code.
    pub const DATE: u8 = 0x0a;
    /// The `MYSQL_TYPE_TIME` column code.
    pub const TIME: u8 = 0x0b;
    /// The `MYSQL_TYPE_DATETIME` column code.
    pub const DATETIME: u8 = 0x0c;
    /// The `MYSQL_TYPE_YEAR` column code.
    pub const YEAR: u8 = 0x0d;
    /// The `MYSQL_TYPE_NEWDATE` column code.
    pub const NEWDATE: u8 = 0x0e;
    /// The `MYSQL_TYPE_VARCHAR` column code.
    pub const VARCHAR: u8 = 0x0f;
    /// The `MYSQL_TYPE_BIT` column code.
    pub const BIT: u8 = 0x10;
    /// The `MYSQL_TYPE_TIMESTAMP2` column code.
    pub const TIMESTAMP2: u8 = 0x11;
    /// The `MYSQL_TYPE_DATETIME2` column code.
    pub const DATETIME2: u8 = 0x12;
    /// The `MYSQL_TYPE_TIME2` column code.
    pub const TIME2: u8 = 0x13;
    /// The `MYSQL_TYPE_VECTOR` column code.
    pub const VECTOR: u8 = 0xf2;
    /// The `MYSQL_TYPE_JSON` column code.
    pub const JSON: u8 = 0xf5;
    /// The `MYSQL_TYPE_NEWDECIMAL` column code.
    pub const NEWDECIMAL: u8 = 0xf6;
    /// The `MYSQL_TYPE_ENUM` column code.
    pub const ENUM: u8 = 0xf7;
    /// The `MYSQL_TYPE_SET` column code.
    pub const SET: u8 = 0xf8;
    /// The `MYSQL_TYPE_TINY_BLOB` column code.
    pub const TINY_BLOB: u8 = 0xf9;
    /// The `MYSQL_TYPE_MEDIUM_BLOB` column code.
    pub const MEDIUM_BLOB: u8 = 0xfa;
    /// The `MYSQL_TYPE_LONG_BLOB` column code.
    pub const LONG_BLOB: u8 = 0xfb;
    /// The `MYSQL_TYPE_BLOB` column code.
    pub const BLOB: u8 = 0xfc;
    /// The `MYSQL_TYPE_VAR_STRING` column code.
    pub const VAR_STRING: u8 = 0xfd;
    /// The `MYSQL_TYPE_STRING` column code.
    pub const STRING: u8 = 0xfe;
    /// The `MYSQL_TYPE_GEOMETRY` column code.
    pub const GEOMETRY: u8 = 0xff;
}

/// Column definition flags.
pub mod column_flag {
    /// The column cannot hold NULL.
    pub const NOT_NULL: u16 = 1;
    /// The column belongs to a primary key.
    pub const PRI_KEY: u16 = 1 << 1;
    /// The column belongs to a unique key.
    pub const UNIQUE_KEY: u16 = 1 << 2;
    /// The column belongs to a nonunique key.
    pub const MULTIPLE_KEY: u16 = 1 << 3;
    /// The column holds BLOB data.
    pub const BLOB: u16 = 1 << 4;
    /// The numeric value is unsigned.
    pub const UNSIGNED: u16 = 1 << 5;
    /// The displayed number has leading zeros.
    pub const ZEROFILL: u16 = 1 << 6;
    /// The column uses binary comparison.
    pub const BINARY: u16 = 1 << 7;
    /// The column is an ENUM.
    pub const ENUM: u16 = 1 << 8;
    /// The server assigns increasing values.
    pub const AUTO_INCREMENT: u16 = 1 << 9;
    /// The column is a TIMESTAMP.
    pub const TIMESTAMP: u16 = 1 << 10;
    /// The column is a SET.
    pub const SET: u16 = 1 << 11;
    /// The column has no default value.
    pub const NO_DEFAULT_VALUE: u16 = 1 << 12;
    /// Updates assign the current timestamp.
    pub const ON_UPDATE_NOW: u16 = 1 << 13;
    /// The column is numeric.
    pub const NUM: u16 = 1 << 15;
}

/// A few character set and collation numbers, as the handshake and column
/// definitions name them.
pub mod charset {
    /// The `latin1_swedish_ci` collation number.
    pub const LATIN1_SWEDISH_CI: u8 = 8;
    /// The `utf8mb3_general_ci` collation number.
    pub const UTF8MB3_GENERAL_CI: u8 = 33;
    /// The `utf8mb4_general_ci` collation number.
    pub const UTF8MB4_GENERAL_CI: u8 = 45;
    /// The `binary` collation number.
    pub const BINARY: u8 = 63;
    /// The `utf8mb4_0900_ai_ci` collation number.
    pub const UTF8MB4_0900_AI_CI: u8 = 255;
}

/// One wire packet, before split messages are assembled.
///
/// A full [`MAX_PACKET_PAYLOAD`] payload continues in the next packet.
/// An empty packet can terminate such a message. This type preserves both
/// forms and does not check sequence IDs across packets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    /// This packet's sequence ID.
    pub seq: u8,
    /// Payload bytes, without the four-byte header.
    pub payload: Vec<u8>,
}

impl Packet {
    fn parse_prefix(b: &[u8], limit: usize) -> Result<Option<(Self, usize)>, Error> {
        let Some(&[a, b0, c, seq]) = b.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let length = u32::from_le_bytes([a, b0, c, 0]);
        let len = usize::try_from(length).map_err(|_| Error::TooLong(usize::MAX))?;
        if len > limit.min(MAX_PACKET_PAYLOAD) {
            return Err(Error::TooLong(len));
        }
        let end = HEADER_LEN.checked_add(len).ok_or(Error::TooLong(len))?;
        Ok(b.get(HEADER_LEN..end).map(|payload| {
            (
                Self {
                    seq,
                    payload: payload.to_vec(),
                },
                end,
            )
        }))
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet. Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Packet::parse_prefix(b, MAX_PACKET_PAYLOAD)? {
            Some((packet, used)) if used == b.len() => Ok(packet),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends one packet. Refuses payloads above [`MAX_PACKET_PAYLOAD`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = self.payload.len();
        if len > MAX_PACKET_PAYLOAD {
            return Err(Error::Unwritable);
        }
        let [a, b, c, _] = u32::try_from(len)
            .map_err(|_| Error::Unwritable)?
            .to_le_bytes();
        out.extend_from_slice(&[a, b, c, self.seq]);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

/// Reads individual MySQL packets without holding input bytes.
///
/// Use with [`codec::Stream`](fictionet::stdlib::codec::Stream) for a buffer bounded
/// by [`HEADER_LEN`] plus [`limit`](fictionet::stdlib::codec::Frames::limit). Oversized payloads are
/// refused from the header. Partial packets return [`Step::Need`], including
/// at EOF, so the stream reports truncation. Sequence IDs are preserved;
/// message assembly and sequence checks remain in [`Messages`].
impl Prefixed for Packet {
    type Item = Packet;
    type Error = Error;
    type Limit = usize;
    const NAME: &'static str = "MySQL";

    #[inline]
    fn default_limit() -> Self::Limit {
        MAX_PACKET_PAYLOAD
    }

    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit {
        limit.min(MAX_PACKET_PAYLOAD)
    }

    #[inline]
    fn capacity(limit: &Self::Limit) -> usize {
        let limit = *limit;
        HEADER_LEN.saturating_add(limit)
    }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        Packet::parse_prefix(input, limit)
    }
}

/// Why bytes are not the packet or message a reader expected, why a
/// stream of packets cannot be read any further, or why a value cannot be
/// written. A real server closes the connection on a stream fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended before a complete packet or message, including
    /// empty input, or the payload ended inside a field, or a string had
    /// no closing NUL.
    Truncated,
    /// EOF arrived before the final packet of a split message.
    Incomplete,
    /// A packet that continues a split message had the wrong sequence ID.
    Sequence {
        /// The ID the packet should have had: one more than the last.
        expected: u8,
        /// The ID it had.
        got: u8,
    },
    /// A message or packet payload exceeds its size limit. For
    /// [`Messages`], this is the assembled payload length, including
    /// the packet that broke the limit. For [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames), it is one
    /// packet's payload length. Both exclude headers.
    TooLong(usize),
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
    /// Bytes came after the last field where none may, or after one
    /// complete packet or message.
    Trailing,
    /// A [`ResultReader`] got a packet after its last result had ended.
    Finished,
    /// A value is too long or too short for its field or packet: the
    /// length it had. Readers give it for a block of connection
    /// attributes over [`MAX_ATTRIBUTE_BYTES`].
    Length(usize),
    /// A field holds a value the protocol does not allow, such as a zstd
    /// level outside [`ZSTD_LEVELS`] or a COM_QUERY parameter set count
    /// other than 1.
    Value(u64),
    /// The value cannot be written without changing it.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => {
                f.write_str("input ended before a complete packet, or inside a field")
            }
            Error::Incomplete => f.write_str("incomplete split MySQL message"),
            Error::Sequence { expected, got } => {
                write!(f, "sequence ID {got}, expected {expected}")
            }
            Error::TooLong(n) => write!(f, "message of at least {n} bytes is over the limit"),
            Error::Header(b) => write!(f, "unexpected first byte {b:#04x}"),
            Error::LengthPrefix(b) => write!(f, "{b:#04x} does not start a length here"),
            Error::Version(v) => write!(f, "handshake protocol version {v}, not 10"),
            Error::FixedFields(n) => write!(f, "column fixed fields length {n}, not 12"),
            Error::TooMany => f.write_str("too many columns or attributes"),
            Error::Unsupported => f.write_str("packet layout not supported"),
            Error::Trailing => f.write_str("bytes after the last field or packet"),
            Error::Finished => f.write_str("packet after the last result ended"),
            Error::Length(n) => write!(f, "length {n} does not fit the field"),
            Error::Value(v) => write!(f, "value {v} is not allowed in this field"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
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

    /// Builds a message around one typed payload. Refuses an unwritable
    /// payload or one beyond [`MAX_MESSAGE`].
    pub fn from_payload(seq: u8, payload: &impl Wire<WriteError = Error>) -> Result<Self, Error> {
        let payload = payload.to_bytes()?;
        if payload.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        Ok(Self { seq, payload })
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one assembled message. Refuses sequence gaps, excess
    /// payload, missing final packets, incomplete packets, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Messages::new();
        let mut rest = bytes;
        loop {
            match decoder.decode(rest, true)? {
                Step::Skip(used) => rest = &rest[used..],
                Step::Item(value, used) if used == rest.len() => return Ok(value),
                Step::Item(_, _) => return Err(Error::Trailing),
                Step::Need | Step::End => return Err(Error::Truncated),
            }
        }
    }

    /// Appends packets with consecutive sequence IDs and the required
    /// short or empty final packet. Refuses payloads above [`MAX_MESSAGE`]
    /// before changing the destination.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.payload.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        put_packets(out, self.seq, &self.payload);
        Ok(())
    }
}

fn packets(len: usize) -> usize {
    len / MAX_PACKET_PAYLOAD + 1
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

/// Assembles split MySQL messages without holding unread input.
/// Sequence IDs are checked inside each message. The caller checks the
/// first sequence ID against its conversation state.
#[derive(Clone, Debug)]
pub struct Messages {
    limit: usize,
    partial: Option<(u8, u8, Vec<u8>)>,
}

impl Messages {
    /// Accepts messages up to [`MAX_MESSAGE`] payload bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }

    /// Sets the payload limit, clamped to [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_MESSAGE),
            partial: None,
        }
    }

    /// The maximum assembled payload size.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Messages {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Messages {
    type Item = Message;
    type Error = Error;
    const NAME: &'static str = "MySQL messages";

    fn capacity(&self) -> usize {
        HEADER_LEN + self.limit.min(MAX_PACKET_PAYLOAD)
    }
    fn held(&self) -> usize {
        self.partial.as_ref().map_or(0, |p| p.2.len())
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Message>, Error> {
        let Some(&[a, b, c, seq]) = input.get(..HEADER_LEN) else {
            if eof && input.is_empty() && self.partial.is_some() {
                return Err(Error::Incomplete);
            }
            return Ok(Step::Need);
        };
        let length = usize::from(a) | usize::from(b) << 8 | usize::from(c) << 16;
        if let Some((_, last, _)) = &self.partial {
            let expected = last.wrapping_add(1);
            if seq != expected {
                return Err(Error::Sequence { expected, got: seq });
            }
        }
        let total = self.held().saturating_add(length);
        if total > self.limit {
            return Err(Error::TooLong(total));
        }
        let used = HEADER_LEN + length;
        let Some(payload) = input.get(HEADER_LEN..used) else {
            return Ok(Step::Need);
        };
        let (first, mut bytes) = match self.partial.take() {
            Some((first, _, bytes)) => (first, bytes),
            None => (seq, Vec::new()),
        };
        if total > bytes.capacity() {
            let target = total
                .max(bytes.capacity().saturating_mul(2))
                .min(self.limit);
            bytes
                .try_reserve_exact(target.saturating_sub(bytes.len()))
                .map_err(|_| Error::TooLong(total))?;
        }
        bytes.extend_from_slice(payload);
        if length < MAX_PACKET_PAYLOAD {
            return Ok(Step::Item(
                Message {
                    seq: first,
                    payload: bytes,
                },
                used,
            ));
        }
        self.partial = Some((first, seq, bytes));
        Ok(Step::Skip(used))
    }
}

/// Appends `v` as a length-encoded integer, in as few bytes as it fits.
fn put_lenenc_int(out: &mut Vec<u8>, v: u64) {
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

/// Appends `s` as a length-encoded string.
fn put_lenenc_str(out: &mut Vec<u8>, s: &[u8]) {
    put_lenenc_int(out, s.len() as u64);
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
    fn read(payload: &[u8]) -> Result<Handshake, Error> {
        let mut r = Reader::new(payload);
        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(Error::Version(version));
        }
        let server_version = r.nul()?.to_vec();
        let connection_id = r.u32_le()?;
        let mut auth_data = r.take(8)?.to_vec();
        r.u8()?; // filler
        let mut capabilities = u32::from(r.u16_le()?);
        let mut h = Handshake {
            server_version,
            connection_id,
            capabilities,
            ..Handshake::default()
        };
        if r.is_empty() {
            h.auth_data = auth_data;
            return Ok(h);
        }
        h.charset = r.u8()?;
        h.status = r.u16_le()?;
        capabilities |= u32::from(r.u16_le()?) << 16;
        let data_len = usize::from(r.u8()?);
        r.take(10)?; // reserved
        // Part 2 comes whatever the flags; its length byte counts only with
        // PLUGIN_AUTH.
        let n = if capabilities & capability::PLUGIN_AUTH != 0 {
            data_len.saturating_sub(8).max(13)
        } else {
            13
        };
        auth_data.extend_from_slice(r.take(n)?);
        if capabilities & capability::PLUGIN_AUTH != 0 {
            // Some servers leave out the closing NUL.
            h.auth_plugin = r.nul_or_rest().to_vec();
        }
        h.capabilities = capabilities;
        h.auth_data = auth_data;
        if !r.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(h)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
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
        let overhead = if short {
            9
        } else {
            25 + usize::from(plugin_auth)
        };
        payload_size(
            overhead,
            [
                self.server_version.len(),
                self.auth_data.len(),
                if plugin_auth {
                    self.auth_plugin.len()
                } else {
                    0
                },
            ],
        )?;
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
    /// The client's capability flags. [`capability::PROTOCOL_41`]
    /// must be set.
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
    fn read(payload: &[u8]) -> Result<HandshakeResponse, Error> {
        let mut r = Reader::new(payload);
        let capabilities = r.u32_le()?;
        if capabilities & capability::PROTOCOL_41 == 0 {
            return Err(Error::Unsupported);
        }
        let max_packet = r.u32_le()?;
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
        let mut h = HandshakeResponse {
            capabilities,
            max_packet,
            charset,
            username,
            auth_response,
            ..Default::default()
        };
        if capabilities & capability::CONNECT_WITH_DB != 0 {
            h.database = r.nul()?.to_vec();
        }
        if capabilities & capability::PLUGIN_AUTH != 0 && !r.is_empty() {
            h.auth_plugin = r.nul_or_rest().to_vec();
        }
        if capabilities & capability::CONNECT_ATTRS != 0 {
            let len = r.lenenc()?;
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > MAX_ATTRIBUTE_BYTES {
                return Err(Error::Length(len));
            }
            let mut block = Reader::new(r.take(len)?);
            while !block.is_empty() {
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
        if !r.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(h)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let caps = self.capabilities;
        let attrs = if caps & capability::CONNECT_ATTRS != 0 {
            if self.attributes.len() > MAX_ATTRIBUTES {
                return Err(Error::Unwritable);
            }
            let mut size = 0usize;
            for (key, value) in &self.attributes {
                size = size
                    .checked_add(lenenc_size(key.len() as u64))
                    .and_then(|n| n.checked_add(key.len()))
                    .and_then(|n| n.checked_add(lenenc_size(value.len() as u64)))
                    .and_then(|n| n.checked_add(value.len()))
                    .ok_or(Error::Unwritable)?;
                if size > MAX_ATTRIBUTE_BYTES {
                    return Err(Error::Unwritable);
                }
            }
            size + lenenc_size(size as u64)
        } else {
            0
        };
        let auth_prefix = if caps & capability::PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            lenenc_size(self.auth_response.len() as u64)
        } else {
            1
        };
        payload_size(
            33 + auth_prefix,
            [
                self.username.len(),
                self.auth_response.len(),
                attrs,
                if caps & capability::CONNECT_WITH_DB != 0 {
                    self.database
                        .len()
                        .checked_add(1)
                        .ok_or(Error::Unwritable)?
                } else {
                    0
                },
                if caps & capability::PLUGIN_AUTH != 0 {
                    self.auth_plugin
                        .len()
                        .checked_add(1)
                        .ok_or(Error::Unwritable)?
                } else {
                    0
                },
                usize::from(caps & capability::ZSTD_COMPRESSION_ALGORITHM != 0),
            ],
        )?;
        let mut out = Vec::new();
        out.extend_from_slice(&caps.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&[0; 23]);
        put_nul(&mut out, &self.username)?;
        if caps & capability::PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            put_lenenc_str(&mut out, &self.auth_response);
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
                put_lenenc_str(&mut block, k);
                put_lenenc_str(&mut block, v);
            }
            if block.len() > MAX_ATTRIBUTE_BYTES {
                return Err(Error::Length(block.len()));
            }
            put_lenenc_str(&mut out, &block);
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
    /// [`capability::PROTOCOL_41`] must both be set.
    pub capabilities: u32,
    /// The longest message the client will send.
    pub max_packet: u32,
    /// The character set and collation the client wants.
    pub charset: u8,
}

impl SslRequest {
    fn read(payload: &[u8]) -> Result<SslRequest, Error> {
        if payload.len() > SSL_REQUEST_LEN {
            return Err(Error::Trailing);
        }
        let mut r = Reader::new(payload);
        let capabilities = r.u32_le()?;
        let max_packet = r.u32_le()?;
        let charset = r.u8()?;
        r.take(23)?;
        let need = capability::SSL | capability::PROTOCOL_41;
        if capabilities & need != need {
            return Err(Error::Unsupported);
        }
        Ok(SslRequest {
            capabilities,
            max_packet,
            charset,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let caps = self.capabilities;
        let mut out = Vec::with_capacity(SSL_REQUEST_LEN);
        out.extend_from_slice(&caps.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&[0; 23]);
        Ok(out)
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
    /// Refuses payloads above [`MAX_MESSAGE`].
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<OkPacket, Error> {
        read_size(payload)?;
        let mut r = Reader::new(payload);
        let header = r.u8()?;
        if header != 0x00 && header != 0xfe {
            return Err(Error::Header(header));
        }
        let mut ok = OkPacket {
            affected_rows: r.lenenc()?,
            last_insert_id: r.lenenc()?,
            ..OkPacket::default()
        };
        if capabilities & capability::PROTOCOL_41 != 0 {
            ok.status = r.u16_le()?;
            ok.warnings = r.u16_le()?;
        } else if capabilities & capability::TRANSACTIONS != 0 {
            ok.status = r.u16_le()?;
        }
        if capabilities & capability::SESSION_TRACK != 0 {
            if !r.is_empty() {
                ok.info = r.lenenc_str()?.to_vec();
                if ok.status & status::SESSION_STATE_CHANGED != 0 {
                    ok.session_state = r.lenenc_str()?.to_vec();
                }
                if !r.is_empty() {
                    return Err(Error::Trailing);
                }
            }
        } else {
            ok.info = r.rest().to_vec();
        }
        Ok(ok)
    }

    fn encode(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        self.encode_header(0x00, capabilities)
    }

    fn encode_end(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let out = self.encode_header(0xfe, capabilities)?;
        if out.len() >= MAX_PACKET_PAYLOAD {
            return Err(Error::Length(out.len()));
        }
        Ok(out)
    }

    fn encode_header(&self, header: u8, caps: u32) -> Result<Vec<u8>, Error> {
        let status_len = if caps & capability::PROTOCOL_41 != 0 {
            4
        } else if caps & capability::TRANSACTIONS != 0 {
            2
        } else {
            0
        };
        let tracked = caps & capability::SESSION_TRACK != 0;
        let state = tracked && status_len != 0 && self.status & status::SESSION_STATE_CHANGED != 0;
        let overhead = 1
            + lenenc_size(self.affected_rows)
            + lenenc_size(self.last_insert_id)
            + status_len
            + if tracked {
                lenenc_size(self.info.len() as u64)
            } else {
                0
            }
            + if state {
                lenenc_size(self.session_state.len() as u64)
            } else {
                0
            };
        payload_size(
            overhead,
            [
                self.info.len(),
                if state { self.session_state.len() } else { 0 },
            ],
        )?;
        let mut out = vec![header];
        put_lenenc_int(&mut out, self.affected_rows);
        put_lenenc_int(&mut out, self.last_insert_id);
        if caps & capability::PROTOCOL_41 != 0 {
            out.extend_from_slice(&self.status.to_le_bytes());
            out.extend_from_slice(&self.warnings.to_le_bytes());
        } else if caps & capability::TRANSACTIONS != 0 {
            out.extend_from_slice(&self.status.to_le_bytes());
        }
        let info = &self.info;
        if caps & capability::SESSION_TRACK != 0 {
            let status_written = caps & (capability::PROTOCOL_41 | capability::TRANSACTIONS) != 0;
            put_lenenc_str(&mut out, info);
            if status_written && self.status & status::SESSION_STATE_CHANGED != 0 {
                put_lenenc_str(&mut out, &self.session_state);
            }
        } else {
            out.extend_from_slice(info);
        }
        Ok(out)
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
        ErrPacket {
            code,
            sql_state: Some(*sql_state),
            message: message.to_vec(),
        }
    }

    /// Reads an ERR packet, with first byte 0xFF, under the connection's
    /// capability flags. The SQLSTATE is read only when the flags include
    /// [`capability::PROTOCOL_41`] and a `#` marks it, since a server
    /// that refuses a connection before the handshake sends none.
    /// Refuses payloads above [`MAX_MESSAGE`].
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<ErrPacket, Error> {
        read_size(payload)?;
        let mut r = Reader::new(payload);
        let header = r.u8()?;
        if header != 0xff {
            return Err(Error::Header(header));
        }
        let code = r.u16_le()?;
        let mut sql_state = None;
        if capabilities & capability::PROTOCOL_41 != 0
            && r.remaining() >= 6
            && r.clone().rest()[0] == b'#'
        {
            let mut s = [0u8; 5];
            s.copy_from_slice(&r.clone().rest()[1..6]);
            sql_state = Some(s);
            r.skip(6)?;
        }
        Ok(ErrPacket {
            code,
            sql_state,
            message: r.rest().to_vec(),
        })
    }

    fn encode(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let protocol_41 = capabilities & capability::PROTOCOL_41 != 0;
        payload_size(
            if protocol_41 && self.sql_state.is_some() {
                9
            } else {
                3
            },
            [self.message.len()],
        )?;
        if protocol_41
            && self.sql_state.is_none()
            && self.message.len() >= 6
            && self.message[0] == b'#'
        {
            return Err(Error::Unwritable);
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
    /// Refuses payloads above [`MAX_MESSAGE`].
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<Eof, Error> {
        read_size(payload)?;
        let mut r = Reader::new(payload);
        let header = r.u8()?;
        if header != 0xfe {
            return Err(Error::Header(header));
        }
        let mut eof = Eof::default();
        if capabilities & capability::PROTOCOL_41 != 0 {
            eof = Eof {
                warnings: r.u16_le()?,
                status: r.u16_le()?,
            };
        }
        if !r.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(eof)
    }

    fn encode(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let mut out = vec![0xfe];
        if capabilities & capability::PROTOCOL_41 != 0 {
            out.extend_from_slice(&self.warnings.to_le_bytes());
            out.extend_from_slice(&self.status.to_le_bytes());
        }
        Ok(out)
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
    /// COM_FIELD_LIST: list a table's columns. An older MySQL command.
    FieldList {
        /// The table.
        table: Vec<u8>,
        /// A `LIKE` pattern the column names must match.
        wildcard: Vec<u8>,
    },
    /// COM_CREATE_DB: create a database. An older MySQL command.
    CreateDb(Vec<u8>),
    /// COM_DROP_DB: drop a database. An older MySQL command.
    DropDb(Vec<u8>),
    /// COM_REFRESH: flush tables, logs or caches, as the bits say.
    Refresh(u8),
    /// COM_STATISTICS: a line of server statistics.
    Statistics,
    /// COM_PROCESS_INFO: the list of threads. An older MySQL command.
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
    /// variant covers, or [`Command::message`] gives
    /// [`Error::Unwritable`].
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
    /// Refuses payloads above [`MAX_MESSAGE`].
    pub fn parse(payload: &[u8], capabilities: u32) -> Result<Command, Error> {
        read_size(payload)?;
        let mut r = Reader::new(payload);
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
                Command::FieldList {
                    table,
                    wildcard: r.rest().to_vec(),
                }
            }
            command::CREATE_DB => Command::CreateDb(r.rest().to_vec()),
            command::DROP_DB => Command::DropDb(r.rest().to_vec()),
            command::REFRESH => Command::Refresh(r.u8()?),
            command::STATISTICS => Command::Statistics,
            command::PROCESS_INFO => Command::ProcessInfo,
            command::PROCESS_KILL => Command::ProcessKill(r.u32_le()?),
            command::DEBUG => Command::Debug,
            command::PING => Command::Ping,
            command::STMT_PREPARE => Command::StmtPrepare(r.rest().to_vec()),
            command::STMT_CLOSE => Command::StmtClose(r.u32_le()?),
            command::STMT_RESET => Command::StmtReset(r.u32_le()?),
            command::SET_OPTION => Command::SetOption(r.u16_le()?),
            command::RESET_CONNECTION => Command::ResetConnection,
            _ => Command::Other {
                command: code,
                data: r.rest().to_vec(),
            },
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

    fn encode(&self, capabilities: u32) -> Result<Vec<u8>, Error> {
        let (overhead, length) = match self {
            Self::Query(data) => (
                if capabilities & capability::QUERY_ATTRIBUTES != 0 {
                    3
                } else {
                    1
                },
                data.len(),
            ),
            Self::InitDb(data)
            | Self::CreateDb(data)
            | Self::DropDb(data)
            | Self::StmtPrepare(data)
            | Self::Other { data, .. } => (1, data.len()),
            Self::FieldList { table, wildcard } => (
                2,
                table
                    .len()
                    .checked_add(wildcard.len())
                    .ok_or(Error::Unwritable)?,
            ),
            _ => (1, 4),
        };
        payload_size(overhead, [length])?;
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
            Command::InitDb(s)
            | Command::CreateDb(s)
            | Command::DropDb(s)
            | Command::StmtPrepare(s) => out.extend_from_slice(s),
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

    fn read(payload: &[u8]) -> Result<Column, Error> {
        let mut r = Reader::new(payload);
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
        c.charset = r.u16_le()?;
        c.length = r.u32_le()?;
        c.column_type = r.u8()?;
        c.flags = r.u16_le()?;
        c.decimals = r.u8()?;
        r.take(2)?; // filler
        if !r.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(c)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        payload_size(
            13,
            [
                &self.catalog,
                &self.schema,
                &self.table,
                &self.org_table,
                &self.name,
                &self.org_name,
            ]
            .into_iter()
            .map(|v| v.len().saturating_add(lenenc_size(v.len() as u64))),
        )?;
        let mut out = Vec::new();
        for s in [
            &self.catalog,
            &self.schema,
            &self.table,
            &self.org_table,
            &self.name,
            &self.org_name,
        ] {
            put_lenenc_str(&mut out, s);
        }
        out.push(0x0c);
        out.extend_from_slice(&self.charset.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.push(self.column_type);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.push(self.decimals);
        out.extend_from_slice(&[0, 0]);
        Ok(out)
    }
}

/// One row of a text result set: each value as text, or `None` for NULL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row(
    /// Values in column order.
    pub Vec<Option<Vec<u8>>>,
);

/// Reads a text result set row of `columns` values. Each is a
/// length-encoded string, or 0xFB for NULL. Fewer values give
/// [`Error::Truncated`], and bytes after the last give
/// [`Error::Trailing`]. Refuses payloads above [`MAX_MESSAGE`].
pub fn parse_row(payload: &[u8], columns: usize) -> Result<Row, Error> {
    read_size(payload)?;
    if columns > MAX_COLUMNS {
        return Err(Error::TooMany);
    }
    let mut r = Reader::new(payload);
    let mut row = Vec::new();
    for _ in 0..columns {
        if r.clone().rest().first() == Some(&0xfb) {
            r.skip(1)?;
            row.push(None);
        } else {
            row.push(Some(r.lenenc_str()?.to_vec()));
        }
    }
    if !r.is_empty() {
        return Err(Error::Trailing);
    }
    Ok(Row(row))
}

impl Row {
    fn read(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(payload);
        let mut values = Vec::new();
        while !reader.is_empty() {
            if values.len() == MAX_COLUMNS {
                return Err(Error::TooMany);
            }
            if reader.clone().rest()[0] == 0xfb {
                reader.skip(1)?;
                values.push(None);
            } else {
                values.push(Some(reader.lenenc_str()?.to_vec()));
            }
        }
        Ok(Self(values))
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.0.len() > MAX_COLUMNS {
            return Err(Error::Unwritable);
        }
        payload_size(
            0,
            self.0.iter().map(|v| {
                v.as_ref()
                    .map_or(1, |v| v.len().saturating_add(lenenc_size(v.len() as u64)))
            }),
        )?;
        let mut out = Vec::new();
        for value in &self.0 {
            match value {
                Some(value) => put_lenenc_str(&mut out, value),
                None => out.push(0xfb),
            }
        }
        Ok(out)
    }
}

/// A local file request payload, sent only when LOCAL_FILES was negotiated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalInfile(
    /// Requested file name.
    pub Vec<u8>,
);
impl LocalInfile {
    fn read(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(payload);
        let first = reader.u8()?;
        if first != 0xfb {
            return Err(Error::Header(first));
        }
        Ok(Self(reader.rest().to_vec()))
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        payload_size(1, [self.0.len()])?;
        let mut out = vec![0xfb];
        out.extend_from_slice(&self.0);
        Ok(out)
    }
}

/// A non-NULL length-encoded integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LenencInt(
    /// Integer value.
    pub u64,
);
impl LenencInt {
    fn read(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(payload);
        let value = reader.lenenc()?;
        if !reader.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(Self(value))
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        put_lenenc_int(&mut out, self.0);
        Ok(out)
    }
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
    /// Builds the column count, definitions, rows, and final status as
    /// messages with consecutive sequence IDs. Refuses mismatched row widths,
    /// unsupported capability layouts, and payloads over their limits.
    pub fn messages(&self, mut seq: u8, capabilities: u32) -> Result<Vec<Message>, Error> {
        let columns = &self.columns;
        if columns.len() > MAX_COLUMNS || self.rows.iter().any(|r| r.0.len() != columns.len()) {
            return Err(Error::Unwritable);
        }
        let end = OkPacket {
            status: self.status,
            warnings: self.warnings,
            ..OkPacket::default()
        };
        if columns.is_empty() {
            if !self.rows.is_empty() {
                return Err(Error::Unwritable);
            }
            return Ok(vec![end.message(seq, capabilities)?]);
        }
        if capabilities & capability::PROTOCOL_41 == 0 {
            return Err(Error::Unwritable);
        }
        let mut count = LenencInt(columns.len() as u64).to_bytes()?;
        if capabilities & capability::OPTIONAL_RESULTSET_METADATA != 0 {
            count.push(METADATA_FULL);
        }
        let first = Message {
            seq,
            payload: count,
        };
        seq = first.next_seq();
        let mut out = vec![first];
        for column in columns {
            let message = Message::from_payload(seq, column)?;
            seq = message.next_seq();
            out.push(message);
        }
        let eof = Eof {
            warnings: self.warnings,
            status: self.status,
        };
        if capabilities & capability::DEPRECATE_EOF == 0 {
            let message = eof.message(seq, capabilities)?;
            seq = message.next_seq();
            out.push(message);
        }
        for row in &self.rows {
            let message = Message::from_payload(seq, row)?;
            seq = message.next_seq();
            out.push(message);
        }
        out.push(if capabilities & capability::DEPRECATE_EOF != 0 {
            end.end_message(seq, capabilities)?
        } else {
            eof.message(seq, capabilities)?
        });
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
        ResultReader {
            capabilities,
            state: ReadState::Start,
            columns: 0,
        }
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
                    let mut r = Reader::new(payload);
                    let n = r.lenenc()?;
                    // The flag byte comes after the count, as libmysql reads it.
                    if caps & capability::OPTIONAL_RESULTSET_METADATA != 0
                        && r.u8()? != METADATA_FULL
                    {
                        return Err(Error::Unsupported);
                    }
                    if !r.is_empty() {
                        return Err(Error::Trailing);
                    }
                    if n == 0 {
                        // A count of 0 in a longer encoding than 0x00.
                        return Err(Error::Header(first));
                    }
                    let n = usize::try_from(n)
                        .ok()
                        .filter(|&n| n <= MAX_COLUMNS)
                        .ok_or(Error::TooMany)?;
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
                        OkPacket {
                            status: eof.status,
                            warnings: eof.warnings,
                            ..OkPacket::default()
                        }
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
        self.state = if status & status::MORE_RESULTS_EXISTS != 0 {
            ReadState::Start
        } else {
            ReadState::Done
        };
    }
}

/// Appends `s` and a NUL. A NUL inside `s` gives [`Error::Unwritable`].
fn put_nul(out: &mut Vec<u8>, s: &[u8]) -> Result<(), Error> {
    if s.contains(&0) {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(s);
    out.push(0);
    Ok(())
}

trait ReadFields<'a> {
    fn lenenc(&mut self) -> Result<u64, Error>;
    fn lenenc_str(&mut self) -> Result<&'a [u8], Error>;
    fn nul(&mut self) -> Result<&'a [u8], Error>;
    fn nul_or_rest(&mut self) -> &'a [u8];
}

impl<'a> ReadFields<'a> for Reader<'a> {
    /// A length-encoded integer.
    fn lenenc(&mut self) -> Result<u64, Error> {
        let first = self.peek_u8().ok_or(Error::Truncated)?;
        let n = match first {
            0..=0xfa => {
                self.skip(1)?;
                return Ok(u64::from(first));
            }
            0xfc => 2,
            0xfd => 3,
            0xfe => 8,
            _ => return Err(Error::LengthPrefix(first)),
        };
        if self.remaining() < 1 + n {
            return Err(Error::Truncated);
        }
        self.skip(1)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(self.take(n)?);
        Ok(u64::from_le_bytes(v))
    }

    /// A length-encoded string. Its length is checked against what is
    /// left before anything is taken.
    fn lenenc_str(&mut self) -> Result<&'a [u8], Error> {
        let mut probe = self.clone();
        let n = probe.lenenc()?;
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        let s = probe.take(n)?;
        *self = probe;
        Ok(s)
    }

    /// A NUL-terminated string, without its NUL.
    fn nul(&mut self) -> Result<&'a [u8], Error> {
        let rest = self.clone().rest();
        let i = rest.iter().position(|&b| b == 0).ok_or(Error::Truncated)?;
        let s = &rest[..i];
        self.skip(i + 1)?;
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
}

fn read_size(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_MESSAGE {
        return Err(Error::Length(payload.len()));
    }
    Ok(())
}

fn lenenc_size(value: u64) -> usize {
    match value {
        0..=250 => 1,
        251..=0xffff => 3,
        0x1_0000..=0xff_ffff => 4,
        _ => 9,
    }
}

fn payload_size(base: usize, lengths: impl IntoIterator<Item = usize>) -> Result<(), Error> {
    let mut size = base;
    for length in lengths {
        size = size.checked_add(length).ok_or(Error::Unwritable)?;
        if size > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
    }
    Ok(())
}

macro_rules! payload_wire {
    ($ty:ty, $parse_doc:literal, $write_doc:literal) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            #[doc = $parse_doc]
            /// Refuses incomplete fields, trailing bytes, and payloads above
            /// [`MAX_MESSAGE`].
            fn parse(payload: &[u8]) -> Result<Self, Error> {
                read_size(payload)?;
                Self::read(payload)
            }

            #[doc = $write_doc]
            /// Leaves the destination unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let bytes = self.encode().map_err(|_| Error::Unwritable)?;
                if bytes.len() > MAX_MESSAGE || Self::parse(&bytes).as_ref() != Ok(self) {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&bytes);
                Ok(())
            }
        }
    };
}
payload_wire!(
    Handshake,
    "Reads a handshake payload. A server that refuses a client may send\nan ERR packet instead, which gives [`Error::Version`] with 0xFF;\nread it with [`ErrPacket::parse`].\n\nOld servers stop after the lower capability flags. Then the\ncharacter set, status and upper flags are 0 and `auth_data` holds\n8 bytes.",
    "Appends a HandshakeV10 payload. Refuses embedded NULs, omitted plugin names, and auth data lengths the flags cannot carry: 21 bytes normally, 21 to 255 with PLUGIN_AUTH, or 8 in the short form with no character set, status, upper flags, or plugin name."
);
payload_wire!(
    HandshakeResponse,
    "Reads a handshake response payload. A 32-byte payload is an\n[`SslRequest`] instead, and gives [`Error::Truncated`] here.\nWithout [`capability::PROTOCOL_41`] it gives\n[`Error::Unsupported`]. Every field the flags call for must be\nthere, as a MySQL server reads them, except the plugin name: when\nit is left out it reads as empty, and its closing NUL may be left\nout at the very end. A block of connection attributes over\n[`MAX_ATTRIBUTE_BYTES`] gives [`Error::Length`], and a zstd level\noutside [`ZSTD_LEVELS`] gives [`Error::Value`].",
    "Appends a HandshakeResponse41 payload. Refuses missing PROTOCOL_41, fields omitted by the capabilities, embedded NULs in terminated fields, auth data above 255 bytes without length encoding, more than MAX_ATTRIBUTES, an attribute block above MAX_ATTRIBUTE_BYTES, and a zstd level outside ZSTD_LEVELS."
);
payload_wire!(
    SslRequest,
    "Reads an SSL request: exactly [`SSL_REQUEST_LEN`] bytes, with\n[`capability::SSL`] and [`capability::PROTOCOL_41`] set. Other\npayloads give [`Error::Truncated`], [`Error::Trailing`] or\n[`Error::Unsupported`].",
    "Appends the 32-byte TLS request. Refuses missing SSL or PROTOCOL_41 capability flags."
);
payload_wire!(
    Column,
    "Reads one column definition. Refuses a fixed-field length other than 12, incomplete fields, and trailing bytes, including COM_FIELD_LIST defaults.",
    "Appends the six length-encoded names and 12 fixed-field bytes. Refuses a payload above MAX_MESSAGE."
);
payload_wire!(
    Row,
    "Reads length-encoded values and NULL markers until the payload ends. Refuses invalid prefixes, truncated values, and more than MAX_COLUMNS.",
    "Appends each value with its length, or 0xFB for NULL. Refuses more than MAX_COLUMNS or a payload above MAX_MESSAGE."
);
payload_wire!(
    LocalInfile,
    "Reads 0xFB followed by a file name. Refuses an empty payload or another first byte. Negotiated LOCAL_FILES is checked by ResultReader.",
    "Appends 0xFB and the full file name. Refuses a payload above MAX_MESSAGE."
);
payload_wire!(
    LenencInt,
    "Reads exactly one non-NULL length-encoded integer. Values below 251 use one byte. Prefixes 0xFC, 0xFD, and 0xFE introduce 2, 3, and 8 bytes. Refuses 0xFB (NULL), 0xFF, incomplete input, and trailing bytes.",
    "Appends a non-NULL integer in its shortest length-encoded form. Every integer value is representable."
);
macro_rules! contextual_message {
    ($($ty:ty),+ $(,)?) => {$ (
        impl $ty {
            /// Builds a message under the negotiated capabilities. Refuses
            /// oversized or invalid fields and fields the flags would omit.
            pub fn message(&self, seq: u8, capabilities: u32) -> Result<Message, Error> {
                let payload = self.encode(capabilities).map_err(|_| Error::Unwritable)?;
                if payload.len() > MAX_MESSAGE || Self::parse(&payload, capabilities).as_ref() != Ok(self) {
                    return Err(Error::Unwritable);
                }
                Ok(Message { seq, payload })
            }
        }
    )+};
}
contextual_message!(OkPacket, ErrPacket, Eof, Command);

impl OkPacket {
    /// Builds the OK message that ends a result set. Refuses fields omitted
    /// by the flags and a payload at least [`MAX_PACKET_PAYLOAD`] bytes.
    /// Uses header 0xFE under [`capability::DEPRECATE_EOF`].
    pub fn end_message(&self, seq: u8, capabilities: u32) -> Result<Message, Error> {
        let payload = self
            .encode_end(capabilities)
            .map_err(|_| Error::Unwritable)?;
        if Self::parse(&payload, capabilities).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        Ok(Message { seq, payload })
    }
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self {
        Error::Truncated
    }
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{
        Column, Command, Eof, ErrPacket, Handshake, HandshakeResponse, LenencInt, LocalInfile,
        OkPacket, ResultReader, Row, SslRequest, parse_row,
    };
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    /// Checks payload codecs under the supplied capability sets.
    pub fn check_payload(bytes: &[u8], capabilities: &[u32]) {
        contract::check_wire::<Handshake>(bytes);
        contract::check_wire::<HandshakeResponse>(bytes);
        contract::check_wire::<SslRequest>(bytes);
        contract::check_wire::<Column>(bytes);
        contract::check_wire::<Row>(bytes);
        contract::check_wire::<LenencInt>(bytes);
        if let Ok(row) = parse_row(bytes, 1) {
            contract::check_wire_value(&row);
        }
        contract::check_wire::<LocalInfile>(bytes);
        for &caps in capabilities {
            if let Ok(value) = OkPacket::parse(bytes, caps) {
                let message = value.message(0, caps).unwrap();
                assert!(message.to_bytes().is_ok(), "{message:?}");
                contract::check_wire_value(&message);
                assert_eq!(OkPacket::parse(&message.payload, caps), Ok(value.clone()));
                if let Ok(message) = value.end_message(0, caps) {
                    assert_eq!(OkPacket::parse(&message.payload, caps), Ok(value));
                }
            }
            if let Ok(value) = ErrPacket::parse(bytes, caps) {
                assert_eq!(
                    ErrPacket::parse(&value.message(0, caps).unwrap().payload, caps),
                    Ok(value)
                );
            }
            if let Ok(value) = Eof::parse(bytes, caps) {
                assert_eq!(
                    Eof::parse(&value.message(0, caps).unwrap().payload, caps),
                    Ok(value)
                );
            }
            if let Ok(value) = Command::parse(bytes, caps) {
                assert_eq!(
                    Command::parse(&value.message(0, caps).unwrap().payload, caps),
                    Ok(value)
                );
            }
            let _ = ResultReader::new(caps).push(bytes);
        }
        for columns in 0..4 {
            if let Ok(row) = parse_row(bytes, columns) {
                assert!(row.to_bytes().is_ok(), "{row:?}");
                contract::check_wire_value(&row);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::hex;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    const CAPS41: u32 =
        capability::PROTOCOL_41 | capability::SECURE_CONNECTION | capability::TRANSACTIONS;
    const CAPS_MODERN: u32 = CAPS41
        | capability::PLUGIN_AUTH
        | capability::PLUGIN_AUTH_LENENC_CLIENT_DATA
        | capability::CONNECT_WITH_DB
        | capability::CONNECT_ATTRS
        | capability::SESSION_TRACK
        | capability::DEPRECATE_EOF
        | capability::MULTI_RESULTS;
    /// Flag sets the readers are tried under.
    const CAPS_SETS: [u32; 5] = [
        0,
        capability::TRANSACTIONS,
        CAPS41,
        CAPS_MODERN,
        CAPS_MODERN | capability::QUERY_ATTRIBUTES,
    ];

    /// Every strict prefix of `full` is refused or reads as something else.
    fn prefixes<T: PartialEq + std::fmt::Debug>(
        full: &[u8],
        parse: impl Fn(&[u8]) -> Result<T, Error>,
    ) {
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
        assert_eq!(h.to_bytes().unwrap(), bytes);
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
        let p = h.to_bytes().unwrap();
        // The auth data length field says 21.
        assert_eq!(p[1 + 7 + 4 + 8 + 1 + 2 + 1 + 2 + 2], 21);
        assert_eq!(Handshake::parse(&p), Ok(h.clone()));
        prefixes_but_nul(&p, true, Handshake::parse);
        // A server that leaves out the plugin name's NUL.
        assert_eq!(
            Handshake::parse(&p[..p.len() - 1]).unwrap().auth_plugin,
            b"caching_sha2_password"
        );
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
        assert_eq!(h.to_bytes().unwrap(), short);
        assert_eq!(Handshake::parse(&[9, b'x', 0]), Err(Error::Version(9)));
        assert_eq!(
            Handshake::parse(&[0xff, 0x15, 0x04]),
            Err(Error::Version(0xff))
        );
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
        assert_eq!(odd.to_bytes(), Err(Error::Unwritable));
        let plugin = Handshake {
            capabilities: CAPS_MODERN,
            auth_plugin: b"a\0b".to_vec(),
            ..odd.clone()
        };
        assert_eq!(plugin.to_bytes(), Err(Error::Unwritable));
        let fine = Handshake {
            server_version: b"8".to_vec(),
            ..odd.clone()
        };
        assert_eq!(
            Handshake::parse(&fine.to_bytes().unwrap()),
            Ok(fine.clone())
        );
        for (n, caps) in [
            (3, 0),
            (20, 0),
            (22, 0),
            (20, CAPS_MODERN),
            (256, CAPS_MODERN),
        ] {
            let h = Handshake {
                auth_data: vec![1; n],
                capabilities: caps,
                ..fine.clone()
            };
            assert_eq!(
                h.to_bytes(),
                Err(Error::Unwritable),
                "{n} bytes, flags {caps:#x}"
            );
        }
        let long = Handshake {
            auth_data: vec![1; 255],
            capabilities: CAPS_MODERN,
            charset: 8,
            ..Handshake::default()
        };
        assert_eq!(Handshake::parse(&long.to_bytes().unwrap()), Ok(long));
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
        assert_eq!(h.to_bytes().unwrap(), p);
    }

    #[test]
    fn eof_rows_end_needs_short_packet() {
        // Without DEPRECATE_EOF, 0xFE ends the rows only in a packet under
        // 9 bytes. A longer one is a row whose first value has an 8-byte
        // length.
        let mut reader = ResultReader::new(CAPS41);
        reader.push(&[1]).unwrap();
        reader
            .push(
                &Column::new(b"a", column_type::VAR_STRING)
                    .to_bytes()
                    .unwrap(),
            )
            .unwrap();
        reader
            .push(&Eof::default().message(0, CAPS41).unwrap().payload)
            .unwrap();
        let row = [0xfe, 1, 0, 0, 0, 0, 0, 0, 0, b'x'];
        assert_eq!(
            reader.push(&row),
            Ok(ResultEvent::Row(Row(vec![Some(b"x".to_vec())])))
        );
        let end = reader
            .push(&Eof::default().message(0, CAPS41).unwrap().payload)
            .unwrap();
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
        assert_eq!(r.to_bytes().unwrap(), bytes);
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
            attributes: vec![
                (b"_client_name".to_vec(), b"libmysql".to_vec()),
                (b"_pid".to_vec(), b"42".to_vec()),
            ],
            zstd_level: 3,
        };
        let p = r.to_bytes().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        prefixes(&p, HandshakeResponse::parse);
        // Without the length-encoded flag, an auth response over 255
        // bytes cannot be written.
        let short = HandshakeResponse {
            capabilities: CAPS41,
            ..r.clone()
        };
        assert_eq!(short.to_bytes(), Err(Error::Unwritable));
        let short = HandshakeResponse {
            auth_response: vec![1; 255],
            database: vec![],
            auth_plugin: vec![],
            attributes: vec![],
            zstd_level: 0,
            ..short
        };
        assert_eq!(
            HandshakeResponse::parse(&short.to_bytes().unwrap())
                .unwrap()
                .auth_response,
            short.auth_response
        );
        // Without SECURE_CONNECTION it ends at a NUL, so it may hold none.
        let old = HandshakeResponse {
            capabilities: capability::PROTOCOL_41,
            auth_response: b"ab\0cd".to_vec(),
            ..HandshakeResponse::default()
        };
        assert_eq!(old.to_bytes(), Err(Error::Unwritable));
        let user = HandshakeResponse {
            username: b"alice\0admin".to_vec(),
            ..r.clone()
        };
        assert_eq!(user.to_bytes(), Err(Error::Unwritable));
        // Errors.
        let pre41 = [0u8; 40];
        assert_eq!(HandshakeResponse::parse(&pre41), Err(Error::Unsupported));
        let many = HandshakeResponse {
            capabilities: CAPS_MODERN,
            attributes: vec![(vec![], vec![]); MAX_ATTRIBUTES],
            ..HandshakeResponse::default()
        };
        let mut p = many.to_bytes().unwrap();
        assert_eq!(
            HandshakeResponse::parse(&p).unwrap().attributes.len(),
            MAX_ATTRIBUTES
        );
        // Two more bytes in the block: one more attribute.
        let block = MAX_ATTRIBUTES * 2;
        let at = p.len() - block - 3;
        assert_eq!(p[at], 0xfc);
        p[at + 1..at + 3].copy_from_slice(&((block + 2) as u16).to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        assert_eq!(HandshakeResponse::parse(&p), Err(Error::TooMany));
        let more = HandshakeResponse {
            attributes: vec![(vec![], vec![]); MAX_ATTRIBUTES + 1],
            ..many
        };
        assert_eq!(more.to_bytes(), Err(Error::Unwritable));
        // A bad length prefix in the auth response.
        let mut bad = HandshakeResponse {
            capabilities: CAPS_MODERN,
            ..HandshakeResponse::default()
        }
        .to_bytes()
        .unwrap();
        bad[33] = 0xff;
        assert_eq!(
            HandshakeResponse::parse(&bad),
            Err(Error::LengthPrefix(0xff))
        );
    }

    #[test]
    fn ssl_request() {
        let s = SslRequest {
            capabilities: CAPS41,
            max_packet: 1 << 24,
            charset: 45,
        };
        assert_eq!(s.to_bytes(), Err(Error::Unwritable));
        let s = SslRequest {
            capabilities: CAPS41 | capability::SSL,
            ..s
        };
        let p = s.to_bytes().unwrap();
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
        assert_eq!(
            ok,
            OkPacket {
                status: status::AUTOCOMMIT,
                ..OkPacket::default()
            }
        );
        assert_eq!(ok.message(0, CAPS41).unwrap().payload, bytes);
        prefixes(&bytes, |b| OkPacket::parse(b, CAPS41));
        // With info text.
        let ok = OkPacket {
            affected_rows: 300,
            last_insert_id: 70000,
            info: b"Rows matched: 1".to_vec(),
            ..ok
        };
        let p = ok.message(0, CAPS41).unwrap().payload;
        assert_eq!(&p[..7], &[0, 0xfc, 0x2c, 0x01, 0xfd, 0x70, 0x11]);
        assert_eq!(OkPacket::parse(&p, CAPS41), Ok(ok.clone()));
        // Session tracking.
        let tracked = OkPacket {
            status: status::SESSION_STATE_CHANGED,
            session_state: vec![0, 4, 3, b'a', b'b', b'c'],
            ..ok.clone()
        };
        let p = tracked.message(0, CAPS_MODERN).unwrap().payload;
        assert_eq!(OkPacket::parse(&p, CAPS_MODERN), Ok(tracked.clone()));
        prefixes(&p, |b| OkPacket::parse(b, CAPS_MODERN));
        // The end of a result set.
        let end = tracked.end_message(0, CAPS_MODERN).unwrap().payload;
        assert_eq!(end[0], 0xfe);
        assert_eq!(OkPacket::parse(&end, CAPS_MODERN), Ok(tracked));
        // Before 4.1: the status goes only with TRANSACTIONS.
        let p = ok.message(0, capability::TRANSACTIONS).unwrap().payload;
        assert_eq!(
            OkPacket::parse(&p, capability::TRANSACTIONS)
                .unwrap()
                .status,
            ok.status
        );
        assert_eq!(ok.message(0, 0), Err(Error::Unwritable));
        let without_status = OkPacket { status: 0, ..ok };
        assert_eq!(
            OkPacket::parse(&without_status.message(0, 0).unwrap().payload, 0),
            Ok(without_status)
        );
        // Errors.
        assert_eq!(
            OkPacket::parse(&[0x01, 0, 0], CAPS41),
            Err(Error::Header(1))
        );
        assert_eq!(
            OkPacket::parse(&[0x00, 0xfb, 0], CAPS41),
            Err(Error::LengthPrefix(0xfb))
        );
        // Long info is written whole.
        let big = OkPacket {
            info: vec![b'x'; 0x1_0010],
            ..OkPacket::default()
        };
        assert_eq!(
            OkPacket::parse(&big.message(0, CAPS_MODERN).unwrap().payload, CAPS_MODERN),
            Ok(big)
        );
    }

    #[test]
    fn err_example() {
        let bytes = hex("ff 48 04 23 48 59 30 30 30 4e 6f 20 74 61 62 6c 65 73 20 75 73 65 64");
        let e = ErrPacket::parse(&bytes, CAPS41).unwrap();
        assert_eq!(e, ErrPacket::new(1096, b"HY000", b"No tables used"));
        assert_eq!(e.message(0, CAPS41).unwrap().payload, bytes);
        prefixes(&bytes, |b| ErrPacket::parse(b, CAPS41));
        // Before the handshake, or before 4.1: no SQLSTATE.
        let early = ErrPacket::parse(&hex("ff 15 04 48 6f 73 74"), CAPS41).unwrap();
        assert_eq!(
            (early.code, early.sql_state, &early.message[..]),
            (1045, None, &b"Host"[..])
        );
        let old = ErrPacket::parse(&bytes, 0).unwrap();
        assert_eq!(old.sql_state, None);
        assert_eq!(&old.message[..6], b"#HY000");
        assert_eq!(
            ErrPacket::new(1, b"HY000", b"x").message(0, 0),
            Err(Error::Unwritable)
        );
        assert_eq!(
            ErrPacket {
                code: 1,
                sql_state: None,
                message: b"x".to_vec()
            }
            .message(0, 0)
            .unwrap()
            .payload,
            [0xff, 1, 0, b'x']
        );
        assert_eq!(
            ErrPacket::parse(&[0x00, 1, 0], CAPS41),
            Err(Error::Header(0))
        );
    }

    #[test]
    fn eof_example() {
        let bytes = hex("fe 00 00 02 00");
        let eof = Eof::parse(&bytes, CAPS41).unwrap();
        assert_eq!(
            eof,
            Eof {
                warnings: 0,
                status: status::AUTOCOMMIT
            }
        );
        assert_eq!(eof.message(0, CAPS41).unwrap().payload, bytes);
        prefixes(&bytes, |b| Eof::parse(b, CAPS41));
        assert_eq!(Eof::parse(&[0xfe], 0), Ok(Eof::default()));
        assert_eq!(Eof::parse(&[0xfe; 9], CAPS41), Err(Error::Trailing));
        assert_eq!(
            Eof::parse(&[0x00, 0, 0, 0, 0], CAPS41),
            Err(Error::Header(0))
        );
    }

    #[test]
    fn query_example() {
        let bytes = hex(
            "21 00 00 00 03 73 65 6c 65 63 74 20 40 40 76 65 72 73 69 6f 6e 5f 63 6f 6d 6d 65 6e 74 20 6c 69 6d 69 74 20 31",
        );
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.seq, 0);
        let c = Command::parse(&m.payload, CAPS41).unwrap();
        assert_eq!(
            c,
            Command::Query(b"select @@version_comment limit 1".to_vec())
        );
        assert_eq!(
            Message {
                seq: 0,
                payload: c.message(0, CAPS41).unwrap().payload
            }
            .to_bytes()
            .unwrap(),
            bytes
        );
        // With query attributes and none sent.
        let attrs = CAPS41 | capability::QUERY_ATTRIBUTES;
        let p = c.message(0, attrs).unwrap().payload;
        assert_eq!(&p[..3], &[3, 0, 1]);
        assert_eq!(Command::parse(&p, attrs), Ok(c));
        assert_eq!(
            Command::parse(&[3, 1, 1, 0, 0], attrs),
            Err(Error::Unsupported)
        );
        assert_eq!(Command::parse(&[3, 0], attrs), Err(Error::Truncated));
    }

    #[test]
    fn commands_round_trip() {
        let all = [
            Command::Quit,
            Command::InitDb(b"shop".to_vec()),
            Command::Query(b"SELECT * FROM t".to_vec()),
            Command::FieldList {
                table: b"t".to_vec(),
                wildcard: b"a%".to_vec(),
            },
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
            Command::Other {
                command: command::STMT_EXECUTE,
                data: vec![1, 0, 0, 0, 0, 1, 0, 0, 0],
            },
        ];
        for c in all {
            let p = c.message(0, CAPS41).unwrap().payload;
            assert_eq!(p[0], c.code());
            assert_eq!(Command::parse(&p, CAPS41), Ok(c.clone()));
            prefixes(&p, |b| Command::parse(b, CAPS41));
        }
        assert_eq!(Command::parse(&[], CAPS41), Err(Error::Truncated));
        assert_eq!(
            Command::parse(&[command::STMT_CLOSE, 1, 2], CAPS41),
            Err(Error::Truncated)
        );
        assert_eq!(
            Command::parse(&[command::FIELD_LIST, b't'], CAPS41),
            Err(Error::Truncated)
        );
        // Bytes after fixed fields are ignored.
        assert_eq!(
            Command::parse(&[command::PING, 9, 9], CAPS41),
            Ok(Command::Ping)
        );
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
            (
                u64::MAX,
                vec![0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ] {
            let mut out = Vec::new();
            LenencInt(v).write(&mut out).unwrap();
            assert_eq!(out, bytes);
            assert_eq!(LenencInt::parse(&bytes), Ok(LenencInt(v)));
            for n in 0..bytes.len() {
                assert_eq!(LenencInt::parse(&bytes[..n]), Err(Error::Truncated));
            }
        }
        // A longer encoding than needed is read too.
        assert_eq!(LenencInt::parse(&[0xfc, 5, 0]), Ok(LenencInt(5)));
        assert_eq!(LenencInt::parse(&[0xfb]), Err(Error::LengthPrefix(0xfb)));
        assert_eq!(LenencInt::parse(&[0xff]), Err(Error::LengthPrefix(0xff)));
        let mut s = Vec::new();
        Row(vec![Some(b"hello".to_vec())]).write(&mut s).unwrap();
        assert_eq!(s, b"\x05hello");
        assert_eq!(Row::parse(&s), Ok(Row(vec![Some(b"hello".to_vec())])));
        assert_eq!(Row::parse(&s[..5]), Err(Error::Truncated));
        // A length past anything that could follow.
        assert_eq!(
            Row::parse(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0x80]),
            Err(Error::Truncated)
        );
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
            rows: vec![Row(vec![Some(b"MySQL Community Server (GPL)".to_vec())])],
            status: status::AUTOCOMMIT,
            warnings: 0,
        };
        let messages = set.messages(1, caps).unwrap();
        let next = messages.last().unwrap().next_seq();
        let mut bytes = Vec::new();
        for message in messages {
            message.write(&mut bytes).unwrap();
        }
        let expected = hex("01 00 00 01 01 \
             27 00 00 02 03 64 65 66 00 00 00 11 40 40 76 65 72 73 69 6f 6e 5f 63 6f 6d 6d 65 6e 74 00 0c 08 00 1c 00 \
             00 00 fd 00 00 1f 00 00 \
             05 00 00 03 fe 00 00 02 00 \
             1d 00 00 04 1c 4d 79 53 51 4c 20 43 6f 6d 6d 75 6e 69 74 79 20 53 65 72 76 65 72 20 28 47 50 4c 29 \
             05 00 00 05 fe 00 00 02 00");
        assert_eq!(bytes, expected);
        assert_eq!(next, 6);
        prefixes(&column.to_bytes().unwrap(), Column::parse);

        // Read back.
        let (messages, failure) = decode_all(Messages::new, &bytes);
        assert_eq!(failure, None);
        let mut r = ResultReader::new(caps);
        let mut events = Vec::new();
        for message in messages {
            events.push(r.push(&message.payload).unwrap());
        }
        assert_eq!(
            events,
            [
                ResultEvent::ColumnCount(1),
                ResultEvent::Column(column),
                ResultEvent::ColumnsEnd(Eof {
                    warnings: 0,
                    status: 2
                }),
                ResultEvent::Row(set.rows[0].clone()),
                ResultEvent::End(OkPacket {
                    status: 2,
                    ..OkPacket::default()
                }),
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
            columns: vec![
                Column::new(b"a", column_type::LONG),
                Column::new(b"b", column_type::VAR_STRING),
            ],
            rows: vec![
                Row(vec![Some(b"1".to_vec()), None]),
                Row(vec![None, Some(vec![])]),
            ],
            status: status::MORE_RESULTS_EXISTS,
            warnings: 1,
        };
        let mut payloads = first
            .messages(0, caps)
            .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>())
            .unwrap();
        payloads.push(
            OkPacket {
                affected_rows: 3,
                ..OkPacket::default()
            }
            .message(0, caps)
            .unwrap()
            .payload,
        );
        let mut r = ResultReader::new(caps);
        let events: Vec<_> = payloads.iter().map(|p| r.push(p).unwrap()).collect();
        assert_eq!(events.len(), 1 + 2 + 2 + 1 + 1);
        assert_eq!(
            events[3],
            ResultEvent::Row(Row(vec![Some(b"1".to_vec()), None]))
        );
        assert_eq!(events[4], ResultEvent::Row(Row(vec![None, Some(vec![])])));
        assert_eq!(
            events[5],
            ResultEvent::End(OkPacket {
                status: status::MORE_RESULTS_EXISTS,
                warnings: 1,
                ..OkPacket::default()
            })
        );
        assert!(matches!(
            events[6],
            ResultEvent::Ok(OkPacket {
                affected_rows: 3,
                ..
            })
        ));
        assert!(r.is_done());

        // ERR, mid rows and at the start.
        let err = ErrPacket::new(1146, b"42S02", b"Table 'x' doesn't exist")
            .message(0, caps)
            .unwrap()
            .payload;
        let mut r = ResultReader::new(caps);
        assert!(matches!(r.push(&err), Ok(ResultEvent::Err(_))));
        assert!(r.is_done());
        let mut r = ResultReader::new(caps);
        r.push(&[1]).unwrap();
        r.push(&Column::new(b"a", 3).to_bytes().unwrap()).unwrap();
        assert_eq!(r.columns(), 1);
        assert!(matches!(r.push(&err), Ok(ResultEvent::Err(_))));

        // A local file request, then the OK after the file.
        let caps = caps | capability::LOCAL_FILES;
        let mut r = ResultReader::new(caps);
        assert_eq!(
            r.push(&LocalInfile(b"/etc/passwd".to_vec()).to_bytes().unwrap()),
            Ok(ResultEvent::LocalInfile(b"/etc/passwd".to_vec()))
        );
        assert!(!r.is_done());
        assert!(matches!(
            r.push(&[0, 0, 0, 0, 0, 0, 0]),
            Ok(ResultEvent::Ok(_))
        ));

        // No columns: written as an OK packet.
        let empty = ResultSet::default()
            .messages(0, caps)
            .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>())
            .unwrap();
        assert_eq!(empty.len(), 1);
        assert!(matches!(
            ResultReader::new(caps).push(&empty[0]),
            Ok(ResultEvent::Ok(_))
        ));

        // Errors leave the reader where it was.
        let mut r = ResultReader::new(caps);
        assert_eq!(r.push(&[]), Err(Error::Truncated));
        assert_eq!(
            r.push(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Header(0xfe))
        );
        assert_eq!(r.push(&[0xfe, 0, 0, 0, 0, 0, 0, 0, 1]), Err(Error::TooMany));
        assert_eq!(r.push(&[0xfc, 0x01, 0x10]), Err(Error::TooMany));
        assert_eq!(r.push(&[2, 0]), Err(Error::Trailing));
        assert_eq!(ResultReader::new(0).push(&[1]), Err(Error::Unsupported));
        let optional = caps | capability::OPTIONAL_RESULTSET_METADATA;
        assert_eq!(
            ResultReader::new(optional).push(&[1]),
            Err(Error::Truncated)
        );
        assert_eq!(
            ResultReader::new(optional).push(&[1, 0]),
            Err(Error::Unsupported)
        );
        assert_eq!(
            ResultReader::new(optional).push(&[1, METADATA_FULL]),
            Ok(ResultEvent::ColumnCount(1))
        );
        assert_eq!(
            ResultReader::new(optional).push(&[1, METADATA_FULL, 0]),
            Err(Error::Trailing)
        );
        r.push(&[1]).unwrap();
        let mut bad = Column::new(b"a", 3).to_bytes().unwrap();
        let at = bad.len() - 13;
        bad[at] = 0x0b;
        assert_eq!(r.push(&bad), Err(Error::FixedFields(0x0b)));
        assert_eq!(Column::parse(&bad), Err(Error::FixedFields(0x0b)));
        r.push(&Column::new(b"a", 3).to_bytes().unwrap()).unwrap();
        assert_eq!(r.push(&[1, b'x', 2]), Err(Error::Trailing));
        assert_eq!(r.push(&[0xfe, 0]), Err(Error::Truncated));
        assert_eq!(r.push(&[0xfb]), Ok(ResultEvent::Row(Row(vec![None]))));
    }

    #[test]
    fn result_sets_read_back_under_each_flag_set() {
        // Whatever the 4.1 flags, a result set written reads back whole.
        let set = ResultSet {
            columns: vec![
                Column::new(b"a", column_type::LONG),
                Column::new(b"b", column_type::VAR_STRING),
            ],
            rows: vec![
                Row(vec![Some(b"1".to_vec()), None]),
                Row(vec![None, Some(vec![0xfe; 300])]),
            ],
            status: status::AUTOCOMMIT,
            warnings: 2,
        };
        let extras = [
            0,
            capability::DEPRECATE_EOF,
            capability::SESSION_TRACK,
            capability::OPTIONAL_RESULTSET_METADATA,
            capability::OPTIONAL_RESULTSET_METADATA
                | capability::DEPRECATE_EOF
                | capability::SESSION_TRACK,
        ];
        for extra in extras {
            let caps = capability::PROTOCOL_41 | extra;
            let mut r = ResultReader::new(caps);
            let mut rows = Vec::new();
            let mut columns = Vec::new();
            for p in set
                .messages(0, caps)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>())
                .unwrap()
            {
                match r.push(&p) {
                    Ok(ResultEvent::Row(row)) => rows.push(row),
                    Ok(ResultEvent::Column(c)) => columns.push(c),
                    Ok(ResultEvent::End(ok)) => assert_eq!((ok.status, ok.warnings), (2, 2)),
                    Ok(_) => {}
                    Err(e) => panic!("flags {caps:#x}: {e:?}"),
                }
            }
            assert!(r.is_done(), "flags {caps:#x}");
            assert_eq!(
                (columns, &rows),
                (set.columns.clone(), &set.rows),
                "flags {caps:#x}"
            );
        }
    }

    #[test]
    fn stream_many_small_messages_in_one_push() {
        let n = rounds(1 << 18);
        let bytes: Vec<u8> = (0..n).flat_map(|i| [0, 0, 0, i as u8]).collect();
        let (messages, failure) = decode_all(Messages::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(messages.len(), n);
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(message.seq, index as u8);
        }
        let mut stream = Stream::new(Messages::new());
        assert_eq!(stream.push(&[1, 0, 0, 0]), 4);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"x"), 1);
        assert_eq!(
            stream.next(),
            Some(Ok(Message {
                seq: 0,
                payload: b"x".to_vec()
            }))
        );
    }

    #[test]
    fn rows() {
        let row = vec![Some(b"abc".to_vec()), None, Some(vec![])];
        let p = Row(row.clone()).to_bytes().unwrap();
        assert_eq!(p, [3, b'a', b'b', b'c', 0xfb, 0]);
        assert_eq!(parse_row(&p, 3), Ok(Row(row.clone())));
        prefixes(&p, |b| parse_row(b, 3));
        assert_eq!(parse_row(&p, 2), Err(Error::Trailing));
        assert_eq!(parse_row(&p, 4), Err(Error::Truncated));
        assert_eq!(parse_row(&[0xff], 1), Err(Error::LengthPrefix(0xff)));
        assert_eq!(parse_row(&[], MAX_COLUMNS + 1), Err(Error::TooMany));
        assert_eq!(parse_row(&[], 0), Ok(Row(vec![])));
    }

    #[test]
    fn split_packets() {
        let message = Message {
            seq: 254,
            payload: (0..MAX_PACKET_PAYLOAD + 1).map(|i| i as u8).collect(),
        };
        assert_eq!(message.packets(), 2);
        assert_eq!(message.next_seq(), 0);
        let bytes = message.to_bytes().unwrap();
        assert_eq!(bytes.len(), message.payload.len() + 8);
        assert_eq!(&bytes[..4], &[0xff, 0xff, 0xff, 254]);
        assert_eq!(
            &bytes[HEADER_LEN + MAX_PACKET_PAYLOAD..][..4],
            &[1, 0, 0, 255]
        );
        assert_eq!(Message::parse(&bytes), Ok(message.clone()));
        assert_eq!(decode_all(Messages::new, &bytes), (vec![message], None));
        let full = Message {
            seq: 3,
            payload: vec![9; MAX_PACKET_PAYLOAD],
        };
        let bytes = full.to_bytes().unwrap();
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 4]);
        assert_eq!(full.next_seq(), 5);
        let mut stream = Stream::new(Messages::new());
        assert_eq!(
            pump(&mut stream, &bytes[..bytes.len() - 1], |_| panic!(
                "premature message"
            )),
            Ok(bytes.len() - 1)
        );
        assert_eq!(stream.held(), MAX_PACKET_PAYLOAD);
        assert_eq!(stream.buffered(), 3);
        assert_eq!(stream.push(&bytes[bytes.len() - 1..]), 1);
        assert_eq!(stream.next(), Some(Ok(full)));
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() = 9;
        assert_eq!(
            decode_all(Messages::new, &bad).1,
            Some(Fail::Protocol(Error::Sequence {
                expected: 4,
                got: 9
            }))
        );
        assert_eq!(
            decode_all(Messages::new, &bytes[..bytes.len() - 4]).1,
            Some(Fail::Protocol(Error::Incomplete))
        );
    }

    #[test]
    fn message_limits_and_stream() {
        assert_eq!(
            decode_all(|| Messages::with_limit(10), &[11, 0, 0, 0]).1,
            Some(Fail::Protocol(Error::TooLong(11)))
        );
        assert_eq!(
            Messages::with_limit(10).decode(&[10, 0, 0, 0], false),
            Ok(Step::Need)
        );
        assert_eq!(Messages::with_limit(usize::MAX).limit(), MAX_MESSAGE);
        let messages = vec![
            Message {
                seq: 0,
                payload: vec![],
            },
            Message {
                seq: 1,
                payload: b"abc".to_vec(),
            },
        ];
        let mut bytes = Vec::new();
        for message in &messages {
            message.write(&mut bytes).unwrap();
        }
        assert_eq!(bytes, [0, 0, 0, 0, 3, 0, 0, 1, b'a', b'b', b'c']);
        assert_eq!(messages[1].next_seq(), 2);
        contract::check_decode_with_alloc_limit(Messages::new, &bytes, 2 * MAX_FRAME);
        assert_eq!(decode_all(Messages::new, &bytes), (messages, None));
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
            Error::Unwritable,
            Error::Value(0),
            Error::Unwritable,
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(!Error::TooLong(5).to_string().is_empty());
        assert!(
            !Error::Sequence {
                expected: 1,
                got: 2
            }
            .to_string()
            .is_empty()
        );
    }

    // Regressions for an outside review of this module.

    #[test]
    fn stream_holds_at_most_its_capacity() {
        let mut stream = Stream::new(Messages::with_limit(16));
        let mut big = vec![17, 0, 0, 0];
        big.resize(1 << 20, 0);
        assert_eq!(stream.push(&big), 16 + HEADER_LEN);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong(17)))));
        assert_eq!(stream.next(), None);
        let bytes = [1, 0, 0, 0, b'x'].repeat(1000);
        contract::check_decode_with_alloc_limit(
            || Messages::with_limit(16),
            &bytes,
            2 * (16 + HEADER_LEN),
        );
        let message = Message {
            seq: 0,
            payload: vec![7; MAX_PACKET_PAYLOAD + 10],
        };
        assert_eq!(
            decode_all(
                || Messages::with_limit(MAX_PACKET_PAYLOAD + 10),
                &message.to_bytes().unwrap()
            ),
            (vec![message], None)
        );
    }

    #[test]
    fn writers_refuse_messages_over_the_limit() {
        let message = Message {
            seq: 0,
            payload: vec![0; MAX_MESSAGE + 1],
        };
        assert_eq!(message.to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            message.packets(),
            (MAX_MESSAGE + 1) / MAX_PACKET_PAYLOAD + 1
        );
        let mut bytes = vec![7];
        assert_eq!(message.write(&mut bytes), Err(Error::Unwritable));
        assert_eq!(bytes, [7]);
    }

    #[test]
    fn ok_session_state_is_written_whole_and_reaches_the_end_event() {
        let caps = capability::PROTOCOL_41 | capability::DEPRECATE_EOF | capability::SESSION_TRACK;
        // 16384 schema-change-like blocks: 65536 bytes, past the old cut.
        let state: Vec<u8> = [3, 2, 1, b'1'].repeat(16384);
        let ok = OkPacket {
            status: status::SESSION_STATE_CHANGED,
            session_state: state,
            ..OkPacket::default()
        };
        assert_eq!(
            OkPacket::parse(&ok.message(0, caps).unwrap().payload, caps),
            Ok(ok.clone())
        );
        assert_eq!(
            OkPacket::parse(&ok.end_message(0, caps).unwrap().payload, caps),
            Ok(ok.clone())
        );
        // A result set ended by an OK packet that changed the schema.
        let end = OkPacket {
            status: status::SESSION_STATE_CHANGED,
            session_state: vec![1, 3, 2, b'd', b'b'],
            ..OkPacket::default()
        };
        let mut r = ResultReader::new(caps);
        r.push(&[1]).unwrap();
        r.push(&Column::new(b"a", 3).to_bytes().unwrap()).unwrap();
        assert_eq!(
            r.push(&end.end_message(0, caps).unwrap().payload),
            Ok(ResultEvent::End(end))
        );
        // An end packet as long as a packet holds would read as a row.
        let long = OkPacket {
            info: vec![b'i'; MAX_PACKET_PAYLOAD],
            ..OkPacket::default()
        };
        assert!(matches!(
            long.end_message(0, caps).map(|m| m.payload),
            Err(Error::Unwritable)
        ));
    }

    #[test]
    fn ok_needs_its_session_state_and_nothing_after() {
        let caps = capability::PROTOCOL_41 | capability::SESSION_TRACK;
        // The flag is set and the info is there, but no session state.
        assert_eq!(
            OkPacket::parse(&hex("00 00 00 00 40 00 00 00"), caps),
            Err(Error::Truncated)
        );
        // Ending after the warnings is allowed, as libmysql allows it.
        let ok = OkPacket::parse(&hex("00 00 00 00 40 00 00"), caps).unwrap();
        assert_eq!(ok.status, status::SESSION_STATE_CHANGED);
        assert_eq!(
            OkPacket::parse(&ok.message(0, caps).unwrap().payload, caps),
            Ok(ok)
        );
        assert_eq!(
            OkPacket::parse(&hex("00 00 00 00 40 00 00 00 00 aa"), caps),
            Err(Error::Trailing)
        );
        assert_eq!(
            OkPacket::parse(&hex("00 00 00 02 00 00 00 00 aa"), caps),
            Err(Error::Trailing)
        );
    }

    #[test]
    fn handshake_response_needs_the_fields_its_flags_name() {
        let r = HandshakeResponse {
            capabilities: CAPS41 | capability::CONNECT_WITH_DB,
            username: b"u".to_vec(),
            database: b"db".to_vec(),
            ..HandshakeResponse::default()
        };
        let p = r.to_bytes().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        // The database's NUL left out, or the whole database.
        assert_eq!(
            HandshakeResponse::parse(&p[..p.len() - 1]),
            Err(Error::Truncated)
        );
        assert_eq!(
            HandshakeResponse::parse(&p[..p.len() - 3]),
            Err(Error::Truncated)
        );
        // The attribute block's length left out.
        let r = HandshakeResponse {
            capabilities: r.capabilities | capability::CONNECT_ATTRS,
            ..r
        };
        let p = r.to_bytes().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        assert_eq!(
            HandshakeResponse::parse(&p[..p.len() - 1]),
            Err(Error::Truncated)
        );
        // The zstd level left out.
        let caps = r.capabilities | capability::ZSTD_COMPRESSION_ALGORITHM;
        let r = HandshakeResponse {
            capabilities: caps,
            zstd_level: 3,
            ..r
        };
        let p = r.to_bytes().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(r.clone()));
        assert_eq!(
            HandshakeResponse::parse(&p[..p.len() - 1]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn handshake_response_attribute_block_limit() {
        let r = HandshakeResponse {
            capabilities: CAPS41 | capability::CONNECT_ATTRS,
            attributes: vec![(b"k".to_vec(), vec![b'v'; 65536])],
            ..HandshakeResponse::default()
        };
        assert!(matches!(r.to_bytes(), Err(Error::Unwritable)));
        // The most that fits: a 1-byte key and a value with a 3-byte length.
        let fits = HandshakeResponse {
            attributes: vec![(b"k".to_vec(), vec![b'v'; 65535 - 2 - 3])],
            ..r.clone()
        };
        let p = fits.to_bytes().unwrap();
        assert_eq!(HandshakeResponse::parse(&p), Ok(fits.clone()));
        let over = HandshakeResponse {
            attributes: vec![(b"k".to_vec(), vec![b'v'; 65535 - 2 - 2])],
            ..r
        };
        assert_eq!(over.to_bytes(), Err(Error::Unwritable));
        // The same block, read: its length is checked before anything else.
        let mut q = p[..p.len() - 65535 - 3].to_vec();
        LenencInt(65536).write(&mut q).unwrap();
        q.extend_from_slice(&p[p.len() - 65535..]);
        q.push(0);
        assert_eq!(HandshakeResponse::parse(&q), Err(Error::Length(65536)));
    }

    #[test]
    fn zstd_level_must_be_valid() {
        let caps = CAPS41 | capability::ZSTD_COMPRESSION_ALGORITHM;
        for level in [0u8, 23, 255] {
            let r = HandshakeResponse {
                capabilities: caps,
                zstd_level: level,
                ..HandshakeResponse::default()
            };
            assert_eq!(r.to_bytes(), Err(Error::Unwritable));
            let mut p = HandshakeResponse { zstd_level: 3, ..r }.to_bytes().unwrap();
            *p.last_mut().unwrap() = level;
            assert_eq!(
                HandshakeResponse::parse(&p),
                Err(Error::Value(u64::from(level)))
            );
        }
        for level in ZSTD_LEVELS {
            let r = HandshakeResponse {
                capabilities: caps,
                zstd_level: level,
                ..HandshakeResponse::default()
            };
            assert_eq!(HandshakeResponse::parse(&r.to_bytes().unwrap()), Ok(r));
        }
    }

    #[test]
    fn query_parameter_set_count_must_be_one() {
        let caps = CAPS41 | capability::QUERY_ATTRIBUTES;
        assert_eq!(
            Command::parse(&hex("03 00 00 53 45 4c 45 43 54 20 31"), caps),
            Err(Error::Value(0))
        );
        assert_eq!(
            Command::parse(&hex("03 00 02 53"), caps),
            Err(Error::Value(2))
        );
        assert_eq!(
            Command::parse(&hex("03 00 01 53"), caps),
            Ok(Command::Query(b"S".to_vec()))
        );
    }

    #[test]
    fn local_infile_needs_the_flag_and_then_an_answer() {
        let request = LocalInfile(b"/etc/passwd".to_vec()).to_bytes().unwrap();
        assert_eq!(
            ResultReader::new(CAPS41).push(&request),
            Err(Error::Header(0xfb))
        );
        let caps = CAPS41 | capability::LOCAL_FILES;
        let mut r = ResultReader::new(caps);
        assert_eq!(
            r.push(&request),
            Ok(ResultEvent::LocalInfile(b"/etc/passwd".to_vec()))
        );
        // Only an OK or ERR packet may follow.
        assert_eq!(r.push(&request), Err(Error::Header(0xfb)));
        assert_eq!(r.push(&[1]), Err(Error::Header(1)));
        let err = ErrPacket::new(1290, b"HY000", b"no")
            .message(0, caps)
            .unwrap()
            .payload;
        assert!(matches!(r.clone().push(&err), Ok(ResultEvent::Err(_))));
        assert!(matches!(
            r.push(&OkPacket::default().message(0, caps).unwrap().payload),
            Ok(ResultEvent::Ok(_))
        ));
        assert!(r.is_done());
    }

    #[test]
    fn err_without_sqlstate_cannot_fake_one() {
        let e = ErrPacket {
            code: 1045,
            sql_state: None,
            message: b"#HY000oops".to_vec(),
        };
        assert_eq!(
            e.message(0, CAPS41).map(|m| m.payload),
            Err(Error::Unwritable)
        );
        // Before 4.1 no SQLSTATE is read, so it reads back the same.
        assert_eq!(
            ErrPacket::parse(&e.message(0, 0).unwrap().payload, 0),
            Ok(e)
        );
        // A short message after `#` is no SQLSTATE.
        let e = ErrPacket {
            code: 1045,
            sql_state: None,
            message: b"#oops".to_vec(),
        };
        assert_eq!(
            ErrPacket::parse(&e.message(0, CAPS41).unwrap().payload, CAPS41),
            Ok(e)
        );
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        assert_eq!(
            Row(vec![None; MAX_COLUMNS + 1]).to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Row(vec![None; MAX_COLUMNS]).to_bytes().map(|p| p.len()),
            Ok(MAX_COLUMNS)
        );
        for code in [
            command::QUIT,
            command::QUERY,
            command::STMT_CLOSE,
            command::FIELD_LIST,
            command::SET_OPTION,
        ] {
            let c = Command::Other {
                command: code,
                data: vec![],
            };
            assert_eq!(
                c.message(0, CAPS41).map(|m| m.payload),
                Err(Error::Unwritable)
            );
        }
        let c = Command::Other {
            command: command::STMT_EXECUTE,
            data: vec![],
        };
        assert_eq!(
            Command::parse(&c.message(0, CAPS41).unwrap().payload, CAPS41),
            Ok(c)
        );
        let c = Command::FieldList {
            table: b"t\0x".to_vec(),
            wildcard: vec![],
        };
        assert_eq!(
            c.message(0, CAPS41).map(|m| m.payload),
            Err(Error::Unwritable)
        );
        let set = ResultSet {
            columns: vec![Column::new(b"a", 3)],
            rows: vec![],
            ..ResultSet::default()
        };
        assert_eq!(
            set.messages(0, 0)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
        assert_eq!(
            ResultSet {
                columns: vec![Column::new(b"a", 3); MAX_COLUMNS + 1],
                ..set.clone()
            }
            .messages(0, CAPS41)
            .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn result_set_rows_must_match_the_columns() {
        let two = vec![Column::new(b"a", 3), Column::new(b"b", 3)];
        let short = ResultSet {
            columns: two.clone(),
            rows: vec![Row(vec![Some(b"1".to_vec())])],
            ..ResultSet::default()
        };
        assert_eq!(
            short
                .messages(0, CAPS41)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
        let long = ResultSet {
            columns: two,
            rows: vec![Row(vec![None; 3])],
            ..ResultSet::default()
        };
        assert_eq!(
            long.messages(0, CAPS41)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
        let none = ResultSet {
            rows: vec![Row(vec![])],
            ..ResultSet::default()
        };
        assert_eq!(
            none.messages(0, CAPS41)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
        // 4096 columns and empty rows are refused, not padded with NULLs.
        let wide = ResultSet {
            columns: vec![Column::new(b"c", 3); MAX_COLUMNS],
            rows: vec![Row(vec![]); 1000],
            ..ResultSet::default()
        };
        assert_eq!(
            wide.messages(0, CAPS41)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>()),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn eof_takes_no_bytes_after_its_fields() {
        assert_eq!(
            Eof::parse(&hex("fe 00 00 02 00 aa"), CAPS41),
            Err(Error::Trailing)
        );
        assert_eq!(Eof::parse(&hex("fe aa"), 0), Err(Error::Trailing));
        assert_eq!(Eof::parse(&hex("fe"), 0), Ok(Eof::default()));
    }

    fn check_payload(bytes: &[u8]) {
        super::harness::check_payload(bytes, &CAPS_SETS);
        for caps in CAPS_SETS {
            if let Ok(value) = OkPacket::parse(bytes, caps) {
                assert_eq!(
                    OkPacket::parse(&value.end_message(0, caps).unwrap().payload, caps),
                    Ok(value)
                );
            }
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
            .to_bytes()
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
            .to_bytes()
            .unwrap(),
            SslRequest {
                capabilities: CAPS41 | capability::SSL,
                ..SslRequest::default()
            }
            .to_bytes()
            .unwrap(),
            OkPacket {
                status: status::SESSION_STATE_CHANGED,
                info: b"i".to_vec(),
                session_state: vec![1, 2],
                ..OkPacket::default()
            }
            .message(0, CAPS_MODERN)
            .unwrap()
            .payload,
            ErrPacket::new(1, b"HY000", b"m")
                .message(0, CAPS41)
                .unwrap()
                .payload,
            Eof::default().message(0, CAPS41).unwrap().payload,
            Column::new(b"c", 3).to_bytes().unwrap(),
            Row(vec![Some(b"a".to_vec()), None]).to_bytes().unwrap(),
            Command::Query(b"q".to_vec())
                .message(0, CAPS41 | capability::QUERY_ATTRIBUTES)
                .unwrap()
                .payload,
            Command::FieldList {
                table: b"t".to_vec(),
                wildcard: vec![],
            }
            .message(0, 0)
            .unwrap()
            .payload,
        ];
        let set = ResultSet {
            columns: vec![Column::new(b"a", 3)],
            rows: vec![Row(vec![Some(b"1".to_vec())])],
            ..ResultSet::default()
        };
        s.extend(
            set.messages(0, CAPS41)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>())
                .unwrap(),
        );
        s
    }

    #[test]
    fn generated_inputs_obey_contracts() {
        let samples = samples();
        let mut rng = Lcg::new(0x5e_ed0f_3306);
        for _ in 0..6000 {
            let mut bytes = if rng.coin() {
                rng.bytes(80)
            } else {
                samples[rng.index(samples.len())].clone()
            };
            mutate(&mut rng, &mut bytes);
            check_payload(&bytes);
            for at in (0..bytes.len()).step_by(7) {
                if at + 2 < bytes.len() && rng.coin() {
                    bytes[at] = rng.index(12) as u8;
                    bytes[at + 1] = 0;
                    bytes[at + 2] = 0;
                }
            }
            let limit = 8 + rng.index(64);
            contract::check_decode_with_alloc_limit(
                || Messages::with_limit(limit),
                &bytes,
                2 * (limit + HEADER_LEN),
            );
            contract::check_decode_with_alloc_limit(
                || Frames::<Packet>::with_limit(limit),
                &bytes,
                2 * (limit + HEADER_LEN),
            );
            contract::check_wire::<Message>(&bytes);
            for message in decode_all(|| Messages::with_limit(limit), &bytes).0 {
                check_payload(&message.payload);
                assert!(message.to_bytes().is_ok(), "{message:?}");
                contract::check_wire_value(&message);
                for caps in CAPS_SETS {
                    let _ = ResultReader::new(caps).push(&message.payload);
                }
            }
            // A random result set, written and read back. One row in five
            // has the wrong number of values, which the writer refuses.
            let ncols = rng.index(4);
            let set = ResultSet {
                columns: (0..ncols)
                    .map(|i| Column::new(&[b'a' + i as u8], rng.next() as u8))
                    .collect(),
                rows: (0..rng.index(4))
                    .map(|_| {
                        Row((0..if rng.index(5) == 0 {
                            rng.index(ncols + 2)
                        } else {
                            ncols
                        })
                            .map(|_| match rng.index(3) {
                                0 => None,
                                _ => Some(
                                    (0..rng.index(300))
                                        .map(|_| 0xfa + rng.index(6) as u8)
                                        .collect(),
                                ),
                            })
                            .collect())
                    })
                    .collect(),
                status: rng.next() as u16 & !status::MORE_RESULTS_EXISTS,
                warnings: rng.next() as u16,
            };
            let caps = capability::PROTOCOL_41 | (rng.next() as u32 & !capability::PROTOCOL_41);
            let payloads = match set
                .messages(0, caps)
                .map(|ms| ms.into_iter().map(|m| m.payload).collect::<Vec<_>>())
            {
                Ok(p) => p,
                Err(e) => {
                    // With no columns any row is refused, and the first
                    // row of the wrong length is the one named.
                    assert!(ncols == 0 || set.rows.iter().any(|row| row.0.len() != ncols));
                    assert_eq!(e, Error::Unwritable);
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
}
