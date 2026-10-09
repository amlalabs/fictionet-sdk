//! PostgreSQL: reading and writing the frontend/backend protocol, version
//! 3, with no I/O.
//!
//! `FrontendMessage` and `BackendMessage` implement `Wire`. Directional
//! decoders track startup and encryption-reply framing. They do not implement a
//! database session, authentication, SQL execution, a `Service`, or encrypted
//! transport.
//!
//! A PostgreSQL client talks to its server over one TCP connection,
//! usually on port 5432. The connection opens with a startup phase, in
//! which the client sends messages with no type byte: a StartupMessage
//! that names the user and the database, or first an SSLRequest or a
//! GSSENCRequest to ask for encryption. A CancelRequest, sent on a
//! connection of its own, asks the server to stop a running query. After
//! the StartupMessage every message, both ways, is a type byte, a 4-byte
//! length that counts itself, and a body. This module follows chapter 54,
//! "Frontend/Backend Protocol", of the PostgreSQL 18 documentation. It
//! reads protocols 3.0 and 3.2, which differ only in the length of the
//! cancel key.
//!
//! A database [`Service`](fictionet::stdlib::serve::Service) served by
//! [`serve::connection`](fictionet::stdlib::serve::connection) uses [`FrontendMessages`] to receive each
//! [`FrontendMessage`]. In `on_item`, call `driver.decoder().refuse_encryption()`
//! after answering an encryption request with N. It answers with a [`BackendMessage`] for each
//! reply, written by [`Wire::write`].
//! Which users exist, which passwords they have, and what a query returns
//! are up to world code. A world that plays a client does the reverse,
//! with [`BackendEvents`] and [`Wire::write`] on [`FrontendMessage`].
//!
//! Every reader checks lengths, counts, format codes and text, because
//! the agent can send any bytes it likes. A message longer than
//! PostgreSQL itself accepts is refused as soon as its length arrives,
//! before its body comes. Text must be UTF-8, as on a connection whose
//! `client_encoding` is UTF8, which [`Startup::new`] asks for. A server
//! world that is asked for another encoding should refuse it, since
//! these readers cannot read that text. Text-format parameters must be
//! UTF-8 with no NUL byte as well. [`Wire`] refuses values that cannot
//! be written unchanged.
//!
//! ```
//! use fictionet::stdlib::postgres::{
//!     oid, Authentication, BackendMessage, Field, FrontendMessage, FrontendMessages, Startup, TransactionStatus,
//! };
//! use fictionet::stdlib::codec::{Stream, Wire};
//!
//! let mut stream = Stream::new(FrontendMessages::new());
//! // What psql sends: a StartupMessage, then a simple query.
//! let mut input = Wire::to_bytes(&FrontendMessage::Startup(Startup::new("alice", "shop"))).unwrap();
//! FrontendMessage::Query("SELECT 1".into()).write(&mut input).unwrap();
//! assert_eq!(stream.push(&input), input.len());
//! stream.end();
//!
//! let mut replies = Vec::new();
//! while let Some(message) = stream.next() {
//!     match message.unwrap().unwrap() {
//!         FrontendMessage::Startup(startup) => {
//!             assert_eq!(startup.get("user"), Some("alice"));
//!             assert_eq!(startup.database(), Some("shop"));
//!             replies.push(BackendMessage::Authentication(Authentication::Ok));
//!             replies.push(BackendMessage::ParameterStatus { name: "server_version".into(), value: "16.4".into() });
//!             replies.push(BackendMessage::BackendKeyData { process_id: 4242, secret_key: vec![1, 2, 3, 4] });
//!             replies.push(BackendMessage::ReadyForQuery(TransactionStatus::Idle));
//!         }
//!         FrontendMessage::Query(sql) => {
//!             assert_eq!(sql, "SELECT 1");
//!             replies.push(BackendMessage::RowDescription(vec![Field::new("?column?", oid::INT4)]));
//!             replies.push(BackendMessage::DataRow(vec![Some(b"1".to_vec())]));
//!             replies.push(BackendMessage::CommandComplete("SELECT 1".into()));
//!             replies.push(BackendMessage::ReadyForQuery(TransactionStatus::Idle));
//!         }
//!         other => panic!("unexpected {other:?}"),
//!     }
//! }
//! let mut bytes = Vec::new();
//! for reply in replies { reply.write(&mut bytes).unwrap(); }
//! // AuthenticationOk: the letter R, length 8, and request code 0.
//! assert_eq!(bytes[..9], *b"R\0\0\0\x08\0\0\0\0");
//! // ReadyForQuery, idle, ends the reply.
//! assert_eq!(bytes[bytes.len() - 6..], *b"Z\0\0\0\x05I");
//! ```

use fictionet::stdlib::codec::Reader as ByteReader;
use fictionet::stdlib::codec::be32;

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The TCP port PostgreSQL servers listen on.
pub const PORT: u16 = 5432;
/// Protocol version 3.0, as a StartupMessage carries it: the major
/// version in the high 16 bits and the minor version in the low 16.
pub const PROTOCOL_3_0: u32 = 3 << 16;
/// Protocol version 3.2, from PostgreSQL 18, whose cancel keys may be
/// longer than 4 bytes.
pub const PROTOCOL_3_2: u32 = (3 << 16) | 2;
/// The code an SSLRequest carries where a StartupMessage has its version.
pub const SSL_REQUEST_CODE: u32 = 80_877_103;
/// The code a GSSENCRequest carries where a StartupMessage has its
/// version.
pub const GSSENC_REQUEST_CODE: u32 = 80_877_104;
/// The code a CancelRequest carries where a StartupMessage has its
/// version.
pub const CANCEL_REQUEST_CODE: u32 = 80_877_102;
/// The byte a server sends to accept an SSLRequest. TLS starts right
/// after it.
pub const ACCEPT_SSL: u8 = b'S';
/// The byte a server sends to accept a GSSENCRequest. GSSAPI encryption
/// starts right after it.
pub const ACCEPT_GSSENC: u8 = b'G';
/// The byte a server sends to refuse an SSLRequest or a GSSENCRequest.
/// The client may then go on without encryption.
pub const REFUSE_ENCRYPTION: u8 = b'N';

/// The most bytes a startup-phase message may hold after its length
/// field. PostgreSQL refuses a longer one.
pub const MAX_STARTUP: usize = 10_000;
/// The largest length field PostgreSQL accepts for the frontend messages
/// that carry no data of their own: Close, Describe, Execute, Flush,
/// Sync, Terminate, CopyDone and CopyFail.
pub const SMALL_MESSAGE: usize = 10_000;
/// The largest length field PostgreSQL accepts for a password, SASL or
/// GSSAPI response.
pub const MAX_AUTH_MESSAGE: usize = 65_535;
/// The largest length field this module reads or writes for any other
/// message: just under 1 GiB, PostgreSQL's own limit.
pub const MAX_MESSAGE: usize = 0x3fff_fffe;
/// The default length-field limit for [`FrontendMessages`] and
/// [`BackendEvents`]: 1 MiB. Set it with their `with_limit` constructors.
pub const DEFAULT_MAX_MESSAGE: usize = 1 << 20;
/// The longest cancel key, in bytes. Protocol 3.0 keys are always 4
/// bytes; protocol 3.2 keys may be up to this long.
pub const MAX_SECRET_KEY: usize = 256;
/// The shortest key a BackendKeyData may carry, in bytes. A
/// CancelRequest key may be shorter: PostgreSQL reads one of 1 byte or
/// more.
pub const MIN_BACKEND_KEY: usize = 4;
/// The most items a list with a 16-bit count may hold: parameters,
/// columns, formats and parameter types.
pub const MAX_COUNT: usize = 65_535;

/// The type bytes of frontend messages, sent by a client.
pub mod frontend_tag {
    /// Bind: fills in a prepared statement's parameters, making a portal.
    pub const BIND: u8 = b'B';
    /// Close: drops a prepared statement or a portal.
    pub const CLOSE: u8 = b'C';
    /// CopyData: a chunk of COPY data. The backend uses the same byte.
    pub const COPY_DATA: u8 = b'd';
    /// CopyDone: the end of COPY data. The backend uses the same byte.
    pub const COPY_DONE: u8 = b'c';
    /// CopyFail: the client gives up on a COPY FROM STDIN.
    pub const COPY_FAIL: u8 = b'f';
    /// Describe: asks for a statement's or a portal's columns.
    pub const DESCRIBE: u8 = b'D';
    /// Execute: runs a portal.
    pub const EXECUTE: u8 = b'E';
    /// Flush: asks the server to send what it has queued.
    pub const FLUSH: u8 = b'H';
    /// FunctionCall: calls a function by its OID.
    pub const FUNCTION_CALL: u8 = b'F';
    /// PasswordMessage, SASLInitialResponse, SASLResponse and
    /// GSSResponse all use this byte.
    pub const AUTH_RESPONSE: u8 = b'p';
    /// Parse: prepares a statement.
    pub const PARSE: u8 = b'P';
    /// Query: a simple query, one or more SQL statements as text.
    pub const QUERY: u8 = b'Q';
    /// Sync: ends an extended-query batch.
    pub const SYNC: u8 = b'S';
    /// Terminate: the client is closing the connection.
    pub const TERMINATE: u8 = b'X';
}

/// The type bytes of backend messages, sent by a server.
pub mod backend_tag {
    /// Every Authentication request.
    pub const AUTHENTICATION: u8 = b'R';
    /// BackendKeyData: the process ID and key a client cancels with.
    pub const BACKEND_KEY_DATA: u8 = b'K';
    /// BindComplete.
    pub const BIND_COMPLETE: u8 = b'2';
    /// CloseComplete.
    pub const CLOSE_COMPLETE: u8 = b'3';
    /// CommandComplete: a statement finished, with its command tag.
    pub const COMMAND_COMPLETE: u8 = b'C';
    /// CopyData.
    pub const COPY_DATA: u8 = b'd';
    /// CopyDone.
    pub const COPY_DONE: u8 = b'c';
    /// CopyInResponse: the server is ready for COPY FROM STDIN data.
    pub const COPY_IN_RESPONSE: u8 = b'G';
    /// CopyOutResponse: COPY TO STDOUT data follows.
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    /// CopyBothResponse: streaming replication starts.
    pub const COPY_BOTH_RESPONSE: u8 = b'W';
    /// DataRow: one row of a result.
    pub const DATA_ROW: u8 = b'D';
    /// EmptyQueryResponse: the query string was empty.
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
    /// ErrorResponse.
    pub const ERROR_RESPONSE: u8 = b'E';
    /// FunctionCallResponse.
    pub const FUNCTION_CALL_RESPONSE: u8 = b'V';
    /// NegotiateProtocolVersion: the server speaks an older minor version.
    pub const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
    /// NoData: the statement or portal returns no rows.
    pub const NO_DATA: u8 = b'n';
    /// NoticeResponse.
    pub const NOTICE_RESPONSE: u8 = b'N';
    /// NotificationResponse: a NOTIFY on a channel the client listens to.
    pub const NOTIFICATION_RESPONSE: u8 = b'A';
    /// ParameterDescription: a prepared statement's parameter types.
    pub const PARAMETER_DESCRIPTION: u8 = b't';
    /// ParameterStatus: a run-time setting the client should know.
    pub const PARAMETER_STATUS: u8 = b'S';
    /// ParseComplete.
    pub const PARSE_COMPLETE: u8 = b'1';
    /// PortalSuspended: an Execute hit its row limit.
    pub const PORTAL_SUSPENDED: u8 = b's';
    /// ReadyForQuery: the server waits for the next query.
    pub const READY_FOR_QUERY: u8 = b'Z';
    /// RowDescription: the columns of the rows that follow.
    pub const ROW_DESCRIPTION: u8 = b'T';
}

/// The codes of the fields in an ErrorResponse or a NoticeResponse.
pub mod field_code {
    /// The severity, possibly translated: ERROR, FATAL or PANIC in an
    /// error, and WARNING, NOTICE, DEBUG, INFO or LOG in a notice.
    pub const SEVERITY: u8 = b'S';
    /// The severity, never translated.
    pub const SEVERITY_NONLOCALIZED: u8 = b'V';
    /// The SQLSTATE code; see [`sqlstate`](super::sqlstate).
    pub const CODE: u8 = b'C';
    /// The primary message: short, one line.
    pub const MESSAGE: u8 = b'M';
    /// A longer explanation, which may run over several lines.
    pub const DETAIL: u8 = b'D';
    /// A suggestion of what to do.
    pub const HINT: u8 = b'H';
    /// A 1-based character position in the query string, in decimal.
    pub const POSITION: u8 = b'P';
    /// A position in an internally generated query.
    pub const INTERNAL_POSITION: u8 = b'p';
    /// The internally generated query.
    pub const INTERNAL_QUERY: u8 = b'q';
    /// Where the error happened, such as a function call stack.
    pub const WHERE: u8 = b'W';
    /// The schema of the object involved.
    pub const SCHEMA: u8 = b's';
    /// The table involved.
    pub const TABLE: u8 = b't';
    /// The column involved.
    pub const COLUMN: u8 = b'c';
    /// The data type involved.
    pub const DATA_TYPE: u8 = b'd';
    /// The constraint involved.
    pub const CONSTRAINT: u8 = b'n';
    /// The server source file that raised the error.
    pub const FILE: u8 = b'F';
    /// The line in that file.
    pub const LINE: u8 = b'L';
    /// The server routine that raised the error.
    pub const ROUTINE: u8 = b'R';
}

/// SQLSTATE codes a simple server is likely to send, from appendix A of
/// the PostgreSQL documentation.
pub mod sqlstate {
    /// 00000: success, for notices.
    pub const SUCCESSFUL_COMPLETION: &str = "00000";
    /// 01000: a warning.
    pub const WARNING: &str = "01000";
    /// 08P01: the client broke the protocol.
    pub const PROTOCOL_VIOLATION: &str = "08P01";
    /// 0A000: the server does not do this.
    pub const FEATURE_NOT_SUPPORTED: &str = "0A000";
    /// 22P02: text that does not read as the type it should be.
    pub const INVALID_TEXT_REPRESENTATION: &str = "22P02";
    /// 23505: a unique constraint was broken.
    pub const UNIQUE_VIOLATION: &str = "23505";
    /// 25P02: the transaction failed; commands are ignored until it ends.
    pub const IN_FAILED_SQL_TRANSACTION: &str = "25P02";
    /// 26000: no prepared statement has this name.
    pub const INVALID_SQL_STATEMENT_NAME: &str = "26000";
    /// 28000: the user may not connect.
    pub const INVALID_AUTHORIZATION_SPECIFICATION: &str = "28000";
    /// 28P01: wrong password.
    pub const INVALID_PASSWORD: &str = "28P01";
    /// 34000: no portal has this name.
    pub const INVALID_CURSOR_NAME: &str = "34000";
    /// 3D000: no database has this name.
    pub const INVALID_CATALOG_NAME: &str = "3D000";
    /// 42501: the user lacks a privilege.
    pub const INSUFFICIENT_PRIVILEGE: &str = "42501";
    /// 42601: a syntax error.
    pub const SYNTAX_ERROR: &str = "42601";
    /// 42703: no column has this name.
    pub const UNDEFINED_COLUMN: &str = "42703";
    /// 42883: no function has this name and these argument types.
    pub const UNDEFINED_FUNCTION: &str = "42883";
    /// 42P01: no table has this name.
    pub const UNDEFINED_TABLE: &str = "42P01";
    /// 42P05: a prepared statement with this name already exists.
    pub const DUPLICATE_PREPARED_STATEMENT: &str = "42P05";
    /// 53300: the server has no room for another connection.
    pub const TOO_MANY_CONNECTIONS: &str = "53300";
    /// 57014: the query was canceled.
    pub const QUERY_CANCELED: &str = "57014";
    /// 57P01: the server is shutting down.
    pub const ADMIN_SHUTDOWN: &str = "57P01";
    /// XX000: an internal error.
    pub const INTERNAL_ERROR: &str = "XX000";
}

/// The OIDs of common built-in types, for [`Field::type_oid`] and Parse
/// parameter types.
pub mod oid {
    /// boolean.
    pub const BOOL: u32 = 16;
    /// bytea.
    pub const BYTEA: u32 = 17;
    /// "char", a single byte.
    pub const CHAR: u32 = 18;
    /// name, a 64-byte identifier.
    pub const NAME: u32 = 19;
    /// bigint.
    pub const INT8: u32 = 20;
    /// smallint.
    pub const INT2: u32 = 21;
    /// integer.
    pub const INT4: u32 = 23;
    /// text.
    pub const TEXT: u32 = 25;
    /// oid.
    pub const OID: u32 = 26;
    /// json.
    pub const JSON: u32 = 114;
    /// real.
    pub const FLOAT4: u32 = 700;
    /// double precision.
    pub const FLOAT8: u32 = 701;
    /// unknown: a literal whose type is not settled yet.
    pub const UNKNOWN: u32 = 705;
    /// character(n).
    pub const BPCHAR: u32 = 1042;
    /// character varying(n).
    pub const VARCHAR: u32 = 1043;
    /// date.
    pub const DATE: u32 = 1082;
    /// time without time zone.
    pub const TIME: u32 = 1083;
    /// timestamp without time zone.
    pub const TIMESTAMP: u32 = 1114;
    /// timestamp with time zone.
    pub const TIMESTAMPTZ: u32 = 1184;
    /// numeric.
    pub const NUMERIC: u32 = 1700;
    /// uuid.
    pub const UUID: u32 = 2950;
    /// jsonb.
    pub const JSONB: u32 = 3802;
}

/// A parameter or column value: its bytes, or `None` for SQL NULL.
pub type Value = Option<Vec<u8>>;

/// How a value is written: as text, or in the type's binary form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Format {
    /// Format code 0: text.
    #[default]
    Text,
    /// Format code 1: binary.
    Binary,
}

impl Format {
    /// The format code: 0 or 1.
    pub fn code(self) -> i16 {
        match self {
            Format::Text => 0,
            Format::Binary => 1,
        }
    }

    /// The format with code `c`, if there is one.
    pub fn from_code(c: i16) -> Option<Format> {
        match c {
            0 => Some(Format::Text),
            1 => Some(Format::Binary),
            _ => None,
        }
    }
}

/// What a Close or a Describe is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// `S`: a prepared statement.
    Statement,
    /// `P`: a portal.
    Portal,
}

impl Target {
    /// The byte that names this target.
    pub fn byte(self) -> u8 {
        match self {
            Target::Statement => b'S',
            Target::Portal => b'P',
        }
    }

    /// The target byte `b` names, if any.
    pub fn from_byte(b: u8) -> Option<Target> {
        match b {
            b'S' => Some(Target::Statement),
            b'P' => Some(Target::Portal),
            _ => None,
        }
    }
}

/// Where a session stands, as ReadyForQuery reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransactionStatus {
    /// `I`: not in a transaction block.
    Idle,
    /// `T`: in a transaction block.
    InTransaction,
    /// `E`: in a failed transaction block. Queries are refused until it
    /// ends.
    Failed,
}

impl TransactionStatus {
    /// The byte that names this status.
    pub fn byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    /// The status byte `b` names, if any.
    pub fn from_byte(b: u8) -> Option<TransactionStatus> {
        match b {
            b'I' => Some(TransactionStatus::Idle),
            b'T' => Some(TransactionStatus::InTransaction),
            b'E' => Some(TransactionStatus::Failed),
            _ => None,
        }
    }
}

/// A StartupMessage: the protocol version the client asks for and its
/// parameters. The major version is always 3.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Startup {
    /// The minor version: 0 for protocol 3.0, 2 for 3.2. A server that
    /// speaks an older minor version answers with
    /// [`BackendMessage::NegotiateProtocolVersion`].
    pub minor_version: u16,
    /// The parameters, in the order sent: `user` (required), `database`,
    /// `application_name`, `client_encoding`, `options`, any run-time
    /// setting, and protocol options whose names start with `_pq_.`.
    pub params: Vec<(String, String)>,
}

impl Startup {
    /// A protocol 3.0 StartupMessage for `user` and `database`, with
    /// `client_encoding` set to `UTF8`. This module reads UTF-8 text only,
    /// and without the setting the server would send text in the
    /// database's own encoding.
    pub fn new(user: &str, database: &str) -> Startup {
        Startup {
            minor_version: 0,
            params: vec![
                ("user".into(), user.into()),
                ("database".into(), database.into()),
                ("client_encoding".into(), "UTF8".into()),
            ],
        }
    }

    /// This StartupMessage with one more parameter, such as
    /// `application_name` or `client_encoding`.
    pub fn with(mut self, name: &str, value: &str) -> Startup {
        self.params.push((name.into(), value.into()));
        self
    }

    /// The value of the last parameter called `name`. A client may send
    /// a name twice, and PostgreSQL then uses the last value, for `user`
    /// and `database` as for run-time settings.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The user name, or `None` if it is missing or empty. PostgreSQL
    /// refuses a StartupMessage without one.
    pub fn user(&self) -> Option<&str> {
        self.get("user").filter(|u| !u.is_empty())
    }

    /// The database: the `database` parameter, or the user name when it
    /// is missing or empty, as PostgreSQL does.
    pub fn database(&self) -> Option<&str> {
        self.get("database")
            .filter(|d| !d.is_empty())
            .or_else(|| self.user())
    }
}

/// A Bind message: a prepared statement's parameters, making a portal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bind {
    /// The portal to make. Empty names the unnamed portal.
    pub portal: String,
    /// The prepared statement to bind. Empty names the unnamed statement.
    pub statement: String,
    /// The parameters' formats: none (all text), one (for all), or one
    /// per parameter. [`Bind::param_format`] applies this rule.
    pub param_formats: Vec<Format>,
    /// The parameter values.
    pub params: Vec<Value>,
    /// The result columns' formats, by the same rule.
    pub result_formats: Vec<Format>,
}

impl Bind {
    /// The format of parameter `i`.
    pub fn param_format(&self, i: usize) -> Format {
        format_for(&self.param_formats, i)
    }

    /// The format of result column `i`.
    pub fn result_format(&self, i: usize) -> Format {
        format_for(&self.result_formats, i)
    }
}

/// A FunctionCall message: calls a function by its OID with arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionCall {
    /// The function's OID.
    pub function: u32,
    /// The arguments' formats: none, one, or one per argument.
    pub arg_formats: Vec<Format>,
    /// The argument values.
    pub args: Vec<Value>,
    /// The format the result should come back in.
    pub result_format: Format,
}

/// A message a client sends. The first four are the startup phase's,
/// which have no type byte; the rest are typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrontendMessage {
    /// StartupMessage: opens a session.
    Startup(Startup),
    /// SSLRequest: asks to switch to TLS. The server answers with one
    /// byte, [`ACCEPT_SSL`] or [`REFUSE_ENCRYPTION`]. A server that
    /// accepts calls [`fictionet::stdlib::codec::Stream::into_parts`], then
    /// [`FrontendMessages::start_encryption`] on the returned decoder.
    /// The decoder refuses a second SSLRequest on one connection.
    SslRequest,
    /// GSSENCRequest: asks to switch to GSSAPI encryption. The server
    /// answers with one byte, [`ACCEPT_GSSENC`] or [`REFUSE_ENCRYPTION`],
    /// then calls [`fictionet::stdlib::codec::Stream::into_parts`] if it accepts and
    /// [`FrontendMessages::start_encryption`] on the returned decoder.
    /// The decoder refuses a second GSSENCRequest on one connection.
    GssEncRequest,
    /// CancelRequest: stop the query running in another session. The
    /// server answers nothing and closes the connection.
    CancelRequest {
        /// The process ID from that session's BackendKeyData.
        process_id: u32,
        /// The secret key from that session's BackendKeyData: 4 bytes in
        /// protocol 3.0, up to [`MAX_SECRET_KEY`] in 3.2.
        secret_key: Vec<u8>,
    },
    /// Bind.
    Bind(Bind),
    /// Close: drop a prepared statement or a portal.
    Close {
        /// A statement or a portal.
        target: Target,
        /// Its name; empty names the unnamed one.
        name: String,
    },
    /// CopyData: a chunk of COPY FROM STDIN data.
    CopyData(Vec<u8>),
    /// CopyDone: the end of COPY FROM STDIN data.
    CopyDone,
    /// CopyFail: the client gives up on a COPY, with a reason.
    CopyFail(String),
    /// Describe: ask for a statement's parameters and columns, or a
    /// portal's columns.
    Describe {
        /// A statement or a portal.
        target: Target,
        /// Its name; empty names the unnamed one.
        name: String,
    },
    /// Execute: run a portal.
    Execute {
        /// The portal; empty names the unnamed portal.
        portal: String,
        /// The most rows to return; 0 (or less) means no limit.
        max_rows: i32,
    },
    /// Flush: send whatever is queued.
    Flush,
    /// FunctionCall.
    FunctionCall(FunctionCall),
    /// The body of a PasswordMessage, SASLInitialResponse, SASLResponse
    /// or GSSResponse. They share one type byte, and which one it is
    /// depends on the Authentication request it answers. Read it with
    /// [`Password`] or [`SaslInitialResponse`]; a SASLResponse
    /// and a GSSResponse are the bytes as they are.
    AuthResponse(Vec<u8>),
    /// Parse: prepare a statement.
    Parse {
        /// The statement's name; empty names the unnamed statement.
        name: String,
        /// The SQL, with parameters written `$1`, `$2` and so on.
        query: String,
        /// Parameter type OIDs; 0 leaves a parameter's type to the server.
        /// There may be fewer than the query has parameters.
        param_types: Vec<u32>,
    },
    /// Query: a simple query, one or more SQL statements.
    Query(String),
    /// Sync: ends an extended-query batch. The server answers
    /// ReadyForQuery.
    Sync,
    /// Terminate: the client is closing the connection.
    Terminate,
}

/// A SASLInitialResponse, read from or written as an
/// [`FrontendMessage::AuthResponse`] body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SaslInitialResponse {
    /// The mechanism the client chose, such as `SCRAM-SHA-256`.
    pub mechanism: String,
    /// The mechanism's first message, if it has one.
    pub data: Option<Vec<u8>>,
}

impl FrontendMessage {
    /// Wraps a password in an authentication message. Refuses NUL and
    /// passwords whose UTF-8 bytes exceed the authentication message limit.
    pub fn password(password: &str) -> Result<FrontendMessage, Error> {
        Ok(FrontendMessage::AuthResponse(
            Password(password.into()).to_bytes()?,
        ))
    }

    /// Whether this is a startup-phase message, written with no type
    /// byte.
    pub fn is_startup(&self) -> bool {
        matches!(
            self,
            Self::Startup(_) | Self::SslRequest | Self::GssEncRequest | Self::CancelRequest { .. }
        )
    }

    /// The type byte, or `None` for a startup-phase message.
    pub fn tag(&self) -> Option<u8> {
        use frontend_tag as t;
        Some(match self {
            Self::Startup(_)
            | Self::SslRequest
            | Self::GssEncRequest
            | Self::CancelRequest { .. } => {
                return None;
            }
            FrontendMessage::Bind(_) => t::BIND,
            FrontendMessage::Close { .. } => t::CLOSE,
            FrontendMessage::CopyData(_) => t::COPY_DATA,
            FrontendMessage::CopyDone => t::COPY_DONE,
            FrontendMessage::CopyFail(_) => t::COPY_FAIL,
            FrontendMessage::Describe { .. } => t::DESCRIBE,
            FrontendMessage::Execute { .. } => t::EXECUTE,
            FrontendMessage::Flush => t::FLUSH,
            FrontendMessage::FunctionCall(_) => t::FUNCTION_CALL,
            FrontendMessage::AuthResponse(_) => t::AUTH_RESPONSE,
            FrontendMessage::Parse { .. } => t::PARSE,
            FrontendMessage::Query(_) => t::QUERY,
            FrontendMessage::Sync => t::SYNC,
            FrontendMessage::Terminate => t::TERMINATE,
        })
    }
}

/// An Authentication request: what the server asks of the client, or
/// that it is done asking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// Code 0, AuthenticationOk: the client is in.
    Ok,
    /// Code 2: Kerberos V5, which PostgreSQL no longer supports.
    KerberosV5,
    /// Code 3: send the password as text.
    CleartextPassword,
    /// Code 5: send `md5` and the hex MD5 of the MD5 of password and user,
    /// salted with these 4 bytes.
    Md5Password([u8; 4]),
    /// Code 7: start GSSAPI.
    Gss,
    /// Code 8: more GSSAPI data.
    GssContinue(Vec<u8>),
    /// Code 9: start SSPI.
    Sspi,
    /// Code 10: start SASL with one of these mechanisms, such as
    /// `SCRAM-SHA-256`.
    Sasl(Vec<String>),
    /// Code 11: a SASL challenge.
    SaslContinue(Vec<u8>),
    /// Code 12: SASL's last message, sent before AuthenticationOk.
    SaslFinal(Vec<u8>),
}

impl Authentication {
    /// The request's code.
    pub fn code(&self) -> u32 {
        match self {
            Authentication::Ok => 0,
            Authentication::KerberosV5 => 2,
            Authentication::CleartextPassword => 3,
            Authentication::Md5Password(_) => 5,
            Authentication::Gss => 7,
            Authentication::GssContinue(_) => 8,
            Authentication::Sspi => 9,
            Authentication::Sasl(_) => 10,
            Authentication::SaslContinue(_) => 11,
            Authentication::SaslFinal(_) => 12,
        }
    }
}

/// The fields of an ErrorResponse or a NoticeResponse: a code from
/// [`field_code`] and its text, in the order sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diagnostic {
    /// The fields. Code 0 and repeated codes are refused by the writer.
    pub fields: Vec<(u8, String)>,
}

impl Diagnostic {
    /// A diagnostic with the fields every one should have: the severity,
    /// twice (`S` and `V`), the SQLSTATE code and the message.
    pub fn new(severity: &str, code: &str, message: &str) -> Diagnostic {
        Diagnostic {
            fields: vec![
                (field_code::SEVERITY, severity.into()),
                (field_code::SEVERITY_NONLOCALIZED, severity.into()),
                (field_code::CODE, code.into()),
                (field_code::MESSAGE, message.into()),
            ],
        }
    }

    /// An ERROR: the statement failed and the session goes on.
    pub fn error(code: &str, message: &str) -> Diagnostic {
        Diagnostic::new("ERROR", code, message)
    }

    /// A FATAL error: the server closes the connection after it.
    pub fn fatal(code: &str, message: &str) -> Diagnostic {
        Diagnostic::new("FATAL", code, message)
    }

    /// This diagnostic with one more field.
    pub fn with(mut self, code: u8, value: &str) -> Diagnostic {
        self.fields.push((code, value.into()));
        self
    }

    /// The text of the first field with `code`.
    pub fn get(&self, code: u8) -> Option<&str> {
        self.fields
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_str())
    }
}

/// One column in a RowDescription.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Field {
    /// The column's name.
    pub name: String,
    /// The OID of the table it comes from, or 0.
    pub table_oid: u32,
    /// Its attribute number in that table, or 0.
    pub column: i16,
    /// Its type's OID; see [`oid`].
    pub type_oid: u32,
    /// Its type's size in bytes, or a negative number for a type of
    /// varying size (-1 for most).
    pub type_size: i16,
    /// The type modifier, such as a varchar's length; -1 for none.
    pub type_modifier: i32,
    /// The format values come in. It is text in a Describe of a
    /// statement, where the format is not known yet.
    pub format: Format,
}

impl Field {
    /// A text-format column called `name` of type `type_oid`, from no
    /// table. The type size is filled in for the fixed-size types in
    /// [`oid`], and is -1 for the rest.
    pub fn new(name: &str, type_oid: u32) -> Field {
        let type_size = match type_oid {
            oid::BOOL | oid::CHAR => 1,
            oid::INT2 => 2,
            oid::INT4 | oid::OID | oid::FLOAT4 | oid::DATE => 4,
            oid::INT8 | oid::FLOAT8 | oid::TIME | oid::TIMESTAMP | oid::TIMESTAMPTZ => 8,
            oid::UUID => 16,
            oid::NAME => 64,
            _ => -1,
        };
        Field {
            name: name.into(),
            table_oid: 0,
            column: 0,
            type_oid,
            type_size,
            type_modifier: -1,
            format: Format::Text,
        }
    }
}

/// The formats in a CopyInResponse, CopyOutResponse or CopyBothResponse.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyFormat {
    /// The overall format. With text, every column is text too.
    pub format: Format,
    /// Each column's format.
    pub columns: Vec<Format>,
}

/// A message a server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendMessage {
    /// An Authentication request, or AuthenticationOk.
    Authentication(Authentication),
    /// BackendKeyData: what the client needs to cancel this session's
    /// queries later.
    BackendKeyData {
        /// The server process's ID.
        process_id: u32,
        /// The secret key: 4 bytes in protocol 3.0, and from
        /// [`MIN_BACKEND_KEY`] to [`MAX_SECRET_KEY`] in 3.2.
        secret_key: Vec<u8>,
    },
    /// BindComplete.
    BindComplete,
    /// CloseComplete.
    CloseComplete,
    /// CommandComplete, with its command tag, such as `SELECT 3`,
    /// `INSERT 0 1`, `UPDATE 2` or `BEGIN`.
    CommandComplete(String),
    /// CopyData: a chunk of COPY TO STDOUT data.
    CopyData(Vec<u8>),
    /// CopyDone.
    CopyDone,
    /// CopyInResponse: send COPY FROM STDIN data in these formats.
    CopyInResponse(CopyFormat),
    /// CopyOutResponse: COPY TO STDOUT data in these formats follows.
    CopyOutResponse(CopyFormat),
    /// CopyBothResponse: streaming replication starts.
    CopyBothResponse(CopyFormat),
    /// DataRow: one row, a value per column.
    DataRow(Vec<Value>),
    /// EmptyQueryResponse: the query was empty, in place of
    /// CommandComplete.
    EmptyQueryResponse,
    /// ErrorResponse.
    ErrorResponse(Diagnostic),
    /// FunctionCallResponse: the function's result.
    FunctionCallResponse(Value),
    /// NegotiateProtocolVersion: the server speaks an older minor version
    /// than the client asked for, or does not know some `_pq_.` options.
    NegotiateProtocolVersion {
        /// The newest protocol version the server speaks, written as a
        /// StartupMessage writes it: [`PROTOCOL_3_0`] or [`PROTOCOL_3_2`].
        /// The documentation calls it the minor version, but PostgreSQL
        /// sends the whole version, and libpq refuses one below 3.0.
        version: u32,
        /// The protocol options it did not recognize.
        unrecognized: Vec<String>,
    },
    /// NoData: the statement or portal returns no rows.
    NoData,
    /// NoticeResponse.
    NoticeResponse(Diagnostic),
    /// NotificationResponse: a NOTIFY the client listens for.
    NotificationResponse {
        /// The notifying session's process ID.
        process_id: u32,
        /// The channel.
        channel: String,
        /// The payload; empty if there was none.
        payload: String,
    },
    /// ParameterDescription: the type OIDs of a statement's parameters.
    ParameterDescription(Vec<u32>),
    /// ParameterStatus: a run-time setting, such as `server_version`,
    /// `client_encoding` or `TimeZone`, at startup or when it changes.
    ParameterStatus {
        /// The setting's name.
        name: String,
        /// Its value.
        value: String,
    },
    /// ParseComplete.
    ParseComplete,
    /// PortalSuspended: an Execute hit its row limit before the portal
    /// ran out.
    PortalSuspended,
    /// ReadyForQuery.
    ReadyForQuery(TransactionStatus),
    /// RowDescription: the columns of the rows that follow.
    RowDescription(Vec<Field>),
}

impl BackendMessage {
    /// The type byte.
    pub fn tag(&self) -> u8 {
        use backend_tag as t;
        match self {
            BackendMessage::Authentication(_) => t::AUTHENTICATION,
            BackendMessage::BackendKeyData { .. } => t::BACKEND_KEY_DATA,
            BackendMessage::BindComplete => t::BIND_COMPLETE,
            BackendMessage::CloseComplete => t::CLOSE_COMPLETE,
            BackendMessage::CommandComplete(_) => t::COMMAND_COMPLETE,
            BackendMessage::CopyData(_) => t::COPY_DATA,
            BackendMessage::CopyDone => t::COPY_DONE,
            BackendMessage::CopyInResponse(_) => t::COPY_IN_RESPONSE,
            BackendMessage::CopyOutResponse(_) => t::COPY_OUT_RESPONSE,
            BackendMessage::CopyBothResponse(_) => t::COPY_BOTH_RESPONSE,
            BackendMessage::DataRow(_) => t::DATA_ROW,
            BackendMessage::EmptyQueryResponse => t::EMPTY_QUERY_RESPONSE,
            BackendMessage::ErrorResponse(_) => t::ERROR_RESPONSE,
            BackendMessage::FunctionCallResponse(_) => t::FUNCTION_CALL_RESPONSE,
            BackendMessage::NegotiateProtocolVersion { .. } => t::NEGOTIATE_PROTOCOL_VERSION,
            BackendMessage::NoData => t::NO_DATA,
            BackendMessage::NoticeResponse(_) => t::NOTICE_RESPONSE,
            BackendMessage::NotificationResponse { .. } => t::NOTIFICATION_RESPONSE,
            BackendMessage::ParameterDescription(_) => t::PARAMETER_DESCRIPTION,
            BackendMessage::ParameterStatus { .. } => t::PARAMETER_STATUS,
            BackendMessage::ParseComplete => t::PARSE_COMPLETE,
            BackendMessage::PortalSuspended => t::PORTAL_SUSPENDED,
            BackendMessage::ReadyForQuery(_) => t::READY_FOR_QUERY,
            BackendMessage::RowDescription(_) => t::ROW_DESCRIPTION,
        }
    }
}

/// Why bytes are not one PostgreSQL message, or a value cannot be written.
/// It is the [`Wire`] error of every type here, and the error item of
/// [`FrontendMessages`] and [`BackendEvents`] for a complete typed body.
/// During authentication, world code also treats a malformed typed body
/// as fatal. A body fault carries the message's type byte, or 0 for a
/// startup-phase message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// A startup-phase message with a code that is neither protocol
    /// version 3 nor a known request.
    UnsupportedProtocol(u32),
    /// A type byte that no message in this direction has.
    UnknownType(u8),
    /// A length field below the least its message can have: 8 in the
    /// startup phase, 4 after.
    BadLength(u32),
    /// A length field above what the message may have.
    TooLong {
        /// The length field.
        length: u32,
        /// The limit it broke.
        max: usize,
    },
    /// The input ends before the message is complete.
    Incomplete,
    /// Bytes follow the message.
    Trailing,
    /// The body ended inside a field.
    Truncated {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
    },
    /// Bytes were left after the last field.
    TrailingBytes {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
    },
    /// A string had no NUL before the end of the body.
    UnterminatedString {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
    },
    /// A string was not UTF-8, or a text-format parameter or function
    /// argument was not UTF-8 text: PostgreSQL checks those against the
    /// client encoding, which counts a NUL byte as invalid.
    NotUtf8 {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
    },
    /// A format code other than 0 (text) or 1 (binary), or a binary
    /// column in a copy response whose overall format is text.
    BadFormat {
        /// The type byte.
        tag: u8,
        /// The format code.
        code: i16,
    },
    /// A Bind or FunctionCall with a format count that is not 0, 1 or
    /// the number of values.
    FormatCount {
        /// The type byte.
        tag: u8,
    },
    /// A value length below -1 (which means NULL).
    BadValueLength {
        /// The type byte.
        tag: u8,
        /// The length field.
        length: i32,
    },
    /// A Close or Describe target other than `S` or `P`.
    BadTarget {
        /// The type byte.
        tag: u8,
        /// The target byte.
        target: u8,
    },
    /// A ReadyForQuery status other than `I`, `T` or `E`.
    BadStatus {
        /// The type byte.
        tag: u8,
        /// The status byte.
        status: u8,
    },
    /// A cancel key that is empty or longer than [`MAX_SECRET_KEY`], or a
    /// BackendKeyData key shorter than [`MIN_BACKEND_KEY`].
    BadKeyLength {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
        /// The key's length.
        length: usize,
    },
    /// An Authentication request code this module does not know.
    BadAuth {
        /// The type byte.
        tag: u8,
        /// The request code.
        code: u32,
    },
    /// A list with no count of its own, or a 32-bit count, holding more
    /// than [`MAX_COUNT`] items: SASL mechanisms, error fields or
    /// unrecognized protocol options.
    TooManyItems {
        /// The type byte.
        tag: u8,
    },
    /// An error or notice field code that came twice. "Any given field
    /// type should appear at most once per message."
    DuplicateField {
        /// The type byte.
        tag: u8,
        /// The field code.
        code: u8,
    },
}

impl Error {
    /// The type byte of a body fault, or `None` for any other error.
    fn tag(&self) -> Option<u8> {
        match *self {
            Error::Truncated { tag }
            | Error::TrailingBytes { tag }
            | Error::UnterminatedString { tag }
            | Error::NotUtf8 { tag }
            | Error::BadFormat { tag, .. }
            | Error::FormatCount { tag }
            | Error::BadValueLength { tag, .. }
            | Error::BadTarget { tag, .. }
            | Error::BadStatus { tag, .. }
            | Error::BadKeyLength { tag, .. }
            | Error::BadAuth { tag, .. }
            | Error::TooManyItems { tag }
            | Error::DuplicateField { tag, .. } => Some(tag),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.tag() {
            Some(0) => f.write_str("invalid startup packet: ")?,
            Some(tag) => write!(f, "invalid message {}: ", show_tag(tag))?,
            None => {}
        }
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::UnsupportedProtocol(code) => {
                write!(
                    f,
                    "unsupported frontend protocol {}.{}",
                    code >> 16,
                    code & 0xffff
                )
            }
            Error::UnknownType(t) => write!(f, "invalid message type {}", show_tag(*t)),
            Error::BadLength(n) => write!(f, "invalid message length {n}"),
            Error::TooLong { length, max } => {
                write!(f, "message length {length} is over the limit of {max}")
            }
            Error::Incomplete => f.write_str("PostgreSQL message ended early"),
            Error::Trailing => f.write_str("bytes follow the PostgreSQL message"),
            Error::Truncated { .. } => f.write_str("the body ends inside a field"),
            Error::TrailingBytes { .. } => f.write_str("bytes are left after the last field"),
            Error::UnterminatedString { .. } => f.write_str("a string has no terminating NUL"),
            Error::NotUtf8 { .. } => f.write_str("a string is not UTF-8"),
            Error::BadFormat { code, .. } => write!(f, "unsupported format code {code}"),
            Error::FormatCount { .. } => {
                f.write_str("the format count matches neither 0, 1 nor the values")
            }
            Error::BadValueLength { length, .. } => write!(f, "invalid value length {length}"),
            Error::BadTarget { target, .. } => write!(f, "invalid target {}", show_tag(*target)),
            Error::BadStatus { status, .. } => {
                write!(f, "invalid transaction status {}", show_tag(*status))
            }
            Error::BadKeyLength { length, .. } => write!(f, "invalid cancel key length {length}"),
            Error::BadAuth { code, .. } => write!(f, "unknown authentication request {code}"),
            Error::TooManyItems { .. } => write!(f, "a list holds more than {MAX_COUNT} items"),
            Error::DuplicateField { code, .. } => {
                write!(f, "field {} appears twice", show_tag(*code))
            }
        }
    }
}

impl std::error::Error for Error {}

/// Why [`FrontendMessages`] or [`BackendEvents`] cannot find the next
/// message. It ends the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The connection opened with a TLS record, not a startup-phase
    /// message: the client asked for direct TLS (`sslnegotiation=direct`).
    /// A server that supports it starts TLS with the bytes
    /// [`fictionet::stdlib::codec::Stream::into_parts`] retains, then calls
    /// [`FrontendMessages::start_encryption`] on the returned decoder.
    /// A new stream uses that decoder for decrypted bytes. As in
    /// PostgreSQL, only the first byte of a connection is read this way.
    DirectTls,
    /// A startup-phase message with a code that is neither protocol
    /// version 3 nor a known request, or a second SSLRequest or
    /// GSSENCRequest on one connection (PostgreSQL reads that as a
    /// StartupMessage of protocol 1234.5679 or 1234.5680).
    UnsupportedProtocol(u32),
    /// A type byte that no message in this direction has, or a byte other
    /// than `S`, `G` or `N` where [`BackendEvents`] expects an encryption
    /// response.
    UnknownType(u8),
    /// A length field below the least its message can have: 8 in the
    /// startup phase, 4 after.
    BadLength(u32),
    /// A length field above what the message may have.
    TooLong {
        /// The length field.
        length: u32,
        /// The limit it broke.
        max: usize,
    },
    /// A startup-phase message whose body does not match its layout. The
    /// [`Error`] says what was wrong.
    Startup(Error),
}

impl FrameError {
    /// The fault that ends the stream, for an error met while finding or
    /// reading a startup-phase message.
    fn from_error(e: Error) -> FrameError {
        match e {
            Error::UnsupportedProtocol(code) => FrameError::UnsupportedProtocol(code),
            Error::UnknownType(t) => FrameError::UnknownType(t),
            Error::BadLength(n) => FrameError::BadLength(n),
            Error::TooLong { length, max } => FrameError::TooLong { length, max },
            e => FrameError::Startup(e),
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::DirectTls => {
                f.write_str("the connection opened with TLS, not a startup message")
            }
            FrameError::UnsupportedProtocol(code) => {
                write!(
                    f,
                    "unsupported frontend protocol {}.{}",
                    code >> 16,
                    code & 0xffff
                )
            }
            FrameError::UnknownType(t) => write!(f, "invalid message type {}", show_tag(*t)),
            FrameError::BadLength(n) => write!(f, "invalid message length {n}"),
            FrameError::TooLong { length, max } => {
                write!(f, "message length {length} is over the limit of {max}")
            }
            FrameError::Startup(_) => f.write_str("malformed startup-phase message"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Startup(e) => Some(e),
            _ => None,
        }
    }
}

// Sizes include the length field but exclude the type byte. Use the
// original field lengths.
fn size_sum(fixed: usize, fields: impl IntoIterator<Item = usize>) -> usize {
    fields.into_iter().fold(fixed, usize::saturating_add)
}

fn frontend_size(message: &FrontendMessage) -> usize {
    match message {
        FrontendMessage::Startup(s) => size_sum(
            9,
            s.params
                .iter()
                .map(|(n, v)| size_sum(2, [n.len(), v.len()])),
        ),
        FrontendMessage::SslRequest | FrontendMessage::GssEncRequest => 8,
        FrontendMessage::CancelRequest { secret_key, .. } => secret_key.len().saturating_add(12),
        FrontendMessage::Bind(b) => size_sum(
            12,
            [
                b.portal.len(),
                b.statement.len(),
                b.param_formats.len().saturating_mul(2),
                size_sum(0, b.params.iter().map(|v| value_size(v.as_deref()))),
                b.result_formats.len().saturating_mul(2),
            ],
        ),
        FrontendMessage::Close { name, .. } | FrontendMessage::Describe { name, .. } => {
            name.len().saturating_add(6)
        }
        FrontendMessage::CopyData(d) | FrontendMessage::AuthResponse(d) => {
            d.len().saturating_add(4)
        }
        FrontendMessage::CopyFail(s) | FrontendMessage::Query(s) => s.len().saturating_add(5),
        FrontendMessage::Execute { portal, .. } => portal.len().saturating_add(9),
        FrontendMessage::FunctionCall(f) => size_sum(
            14,
            [
                f.arg_formats.len().saturating_mul(2),
                size_sum(0, f.args.iter().map(|v| value_size(v.as_deref()))),
            ],
        ),
        FrontendMessage::Parse {
            name,
            query,
            param_types,
        } => size_sum(
            8,
            [name.len(), query.len(), param_types.len().saturating_mul(4)],
        ),
        FrontendMessage::CopyDone
        | FrontendMessage::Flush
        | FrontendMessage::Sync
        | FrontendMessage::Terminate => 4,
    }
}

fn backend_size(message: &BackendMessage) -> usize {
    match message {
        BackendMessage::Authentication(a) => match a {
            Authentication::Md5Password(_) => 12,
            Authentication::GssContinue(d)
            | Authentication::SaslContinue(d)
            | Authentication::SaslFinal(d) => d.len().saturating_add(8),
            Authentication::Sasl(names) => {
                size_sum(9, names.iter().map(|s| s.len().saturating_add(1)))
            }
            _ => 8,
        },
        BackendMessage::BackendKeyData { secret_key, .. } => secret_key.len().saturating_add(8),
        BackendMessage::CommandComplete(s) => s.len().saturating_add(5),
        BackendMessage::CopyData(d) => d.len().saturating_add(4),
        BackendMessage::CopyInResponse(c)
        | BackendMessage::CopyOutResponse(c)
        | BackendMessage::CopyBothResponse(c) => {
            c.columns.len().saturating_mul(2).saturating_add(7)
        }
        BackendMessage::DataRow(values) => {
            size_sum(6, values.iter().map(|v| value_size(v.as_deref())))
        }
        BackendMessage::ErrorResponse(d) | BackendMessage::NoticeResponse(d) => {
            size_sum(5, d.fields.iter().map(|(_, s)| s.len().saturating_add(2)))
        }
        BackendMessage::FunctionCallResponse(v) => value_size(v.as_deref()).saturating_add(4),
        BackendMessage::NegotiateProtocolVersion { unrecognized, .. } => {
            size_sum(12, unrecognized.iter().map(|s| s.len().saturating_add(1)))
        }
        BackendMessage::NotificationResponse {
            channel, payload, ..
        } => size_sum(10, [channel.len(), payload.len()]),
        BackendMessage::ParameterDescription(types) => {
            types.len().saturating_mul(4).saturating_add(6)
        }
        BackendMessage::ParameterStatus { name, value } => size_sum(6, [name.len(), value.len()]),
        BackendMessage::ReadyForQuery(_) => 5,
        BackendMessage::RowDescription(fields) => {
            size_sum(6, fields.iter().map(|f| f.name.len().saturating_add(19)))
        }
        BackendMessage::BindComplete
        | BackendMessage::CloseComplete
        | BackendMessage::CopyDone
        | BackendMessage::EmptyQueryResponse
        | BackendMessage::NoData
        | BackendMessage::ParseComplete
        | BackendMessage::PortalSuspended => 4,
    }
}

/// A PasswordMessage body: UTF-8 text followed by one NUL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Password(
    /// The password, or the MD5 response text including its `md5` prefix.
    pub String,
);

impl Wire for Password {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one NUL-terminated UTF-8 password. Refuses trailing bytes,
    /// missing NUL, invalid UTF-8, and bodies beyond [`MAX_AUTH_MESSAGE`] minus four.
    fn parse(body: &[u8]) -> Result<Self, Error> {
        auth_body_limit(body)?;
        let mut r = Fields {
            cursor: ByteReader::new(body),
            tag: frontend_tag::AUTH_RESPONSE,
        };
        let password = r.cstr()?;
        r.end()?;
        Ok(Self(password))
    }

    /// Appends the password and NUL. Refuses embedded NUL and oversized
    /// passwords with [`Error::Unwritable`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_AUTH_MESSAGE - 5 || self.0.contains('\0') {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(self.0.as_bytes());
        out.push(0);
        Ok(())
    }
}

impl SaslInitialResponse {
    /// Wraps this response in an authentication message. Refuses a NUL in
    /// the mechanism or fields that exceed the authentication message limit.
    pub fn to_message(&self) -> Result<FrontendMessage, Error> {
        Ok(FrontendMessage::AuthResponse(self.to_bytes()?))
    }
}

fn auth_body_limit(body: &[u8]) -> Result<(), Error> {
    if body.len() > MAX_AUTH_MESSAGE - 4 {
        return Err(Error::TooLong {
            length: u32::try_from(body.len().saturating_add(4)).unwrap_or(u32::MAX),
            max: MAX_AUTH_MESSAGE,
        });
    }
    Ok(())
}

impl Wire for SaslInitialResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one AuthResponse body: a NUL-terminated mechanism, a signed
    /// data length, and the data. Minus one means no initial data. Refuses
    /// invalid UTF-8, other negative lengths, incomplete or trailing bytes,
    /// and bodies beyond [`MAX_AUTH_MESSAGE`] minus four.
    fn parse(body: &[u8]) -> Result<Self, Error> {
        auth_body_limit(body)?;
        let mut r = Fields {
            cursor: ByteReader::new(body),
            tag: frontend_tag::AUTH_RESPONSE,
        };
        let mechanism = r.cstr()?;
        let data = r.value()?;
        r.end()?;
        Ok(Self { mechanism, data })
    }

    /// Appends the mechanism and optional data. Refuses
    /// NUL in the mechanism and oversized bodies. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let size = self
            .mechanism
            .len()
            .saturating_add(1)
            .saturating_add(value_size(self.data.as_deref()));
        if size > MAX_AUTH_MESSAGE - 4 {
            return Err(Error::Unwritable);
        }
        let mut body = Out { buf: Vec::new() };
        body.cstr(&self.mechanism)?;
        body.value(self.data.as_deref())?;
        out.extend_from_slice(&body.buf);
        Ok(())
    }
}

// Field writing is shared by both directions. Callers bound the complete
// message size before staging. Every variable count is checked.
struct Out {
    buf: Vec<u8>,
}

impl Out {
    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }
    fn put(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }
    fn u16(&mut self, value: u16) {
        self.put(&value.to_be_bytes());
    }
    fn i16(&mut self, value: i16) {
        self.put(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.put(&value.to_be_bytes());
    }
    fn i32(&mut self, value: i32) {
        self.put(&value.to_be_bytes());
    }
    fn count(&mut self, count: usize) -> Result<(), Error> {
        self.u16(u16::try_from(count).map_err(|_| Error::Unwritable)?);
        Ok(())
    }
    fn cstr(&mut self, value: &str) -> Result<(), Error> {
        if value.contains('\0') {
            return Err(Error::Unwritable);
        }
        self.put(value.as_bytes());
        self.u8(0);
        Ok(())
    }
    fn formats(&mut self, formats: &[Format]) -> Result<(), Error> {
        self.count(formats.len())?;
        for format in formats {
            self.i16(format.code());
        }
        Ok(())
    }
    fn value(&mut self, value: Option<&[u8]>) -> Result<(), Error> {
        match value {
            None => self.i32(-1),
            Some(bytes) => {
                self.i32(i32::try_from(bytes.len()).map_err(|_| Error::Unwritable)?);
                self.put(bytes);
            }
        }
        Ok(())
    }
    fn values(&mut self, values: &[Value]) -> Result<(), Error> {
        self.count(values.len())?;
        for value in values {
            self.value(value.as_deref())?;
        }
        Ok(())
    }
}

fn exact<M>(parsed: Option<(M, usize)>, length: usize) -> Result<M, Error> {
    match parsed {
        Some((message, used)) if used == length => Ok(message),
        Some(_) => Err(Error::Trailing),
        None => Err(Error::Incomplete),
    }
}

impl Wire for FrontendMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one startup or typed message. Startup lengths begin
    /// with zero; typed messages begin with a tag. Refuses incomplete or
    /// trailing bytes, unknown tags or protocols, oversized messages, and
    /// malformed fields, counts, formats, keys, or UTF-8 text.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = if bytes.first() == Some(&0) {
            split_startup(bytes).and_then(|part| {
                part.map(|(body, used)| startup_body(body).map(|message| (message, used)))
                    .transpose()
            })
        } else {
            split_typed(bytes, frontend_limit, MAX_MESSAGE).and_then(|part| {
                part.map(|(tag, body, used)| {
                    frontend_body(tag, body).map(|message| (message, used))
                })
                .transpose()
            })
        };
        exact(parsed?, bytes.len())
    }

    /// Appends the length and complete body, with a type byte for typed messages. Refuses embedded
    /// NUL in strings, empty startup names, invalid cancel keys, mismatched
    /// format counts, invalid text parameters, and fields or lists beyond
    /// their limits. Stages at most [`MAX_MESSAGE`] plus one byte. Returns
    /// [`Error::Unwritable`] without changing `out` on refusal.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let size = frontend_size(self);
        let limit = self
            .tag()
            .and_then(frontend_limit)
            .unwrap_or(MAX_STARTUP + 4);
        if size > limit {
            return Err(Error::Unwritable);
        }
        let mut o = Out { buf: Vec::new() };
        if let Some(tag) = self.tag() {
            o.u8(tag);
        }
        o.u32(u32::try_from(size).map_err(|_| Error::Unwritable)?);
        match self {
            Self::Startup(s) => {
                o.u32(PROTOCOL_3_0 | u32::from(s.minor_version));
                for (name, value) in &s.params {
                    if name.is_empty() {
                        return Err(Error::Unwritable);
                    }
                    o.cstr(name)?;
                    o.cstr(value)?;
                }
                o.u8(0);
            }
            Self::SslRequest => o.u32(SSL_REQUEST_CODE),
            Self::GssEncRequest => o.u32(GSSENC_REQUEST_CODE),
            Self::CancelRequest {
                process_id,
                secret_key,
            } => {
                if !(1..=MAX_SECRET_KEY).contains(&secret_key.len()) {
                    return Err(Error::Unwritable);
                }
                o.u32(CANCEL_REQUEST_CODE);
                o.u32(*process_id);
                o.put(secret_key);
            }
            Self::Bind(b) => {
                check_format_count(frontend_tag::BIND, b.param_formats.len(), b.params.len())
                    .map_err(|_| Error::Unwritable)?;
                check_text_values(frontend_tag::BIND, &b.param_formats, &b.params)
                    .map_err(|_| Error::Unwritable)?;
                o.cstr(&b.portal)?;
                o.cstr(&b.statement)?;
                o.formats(&b.param_formats)?;
                o.values(&b.params)?;
                o.formats(&b.result_formats)?;
            }
            Self::Close { target, name } | Self::Describe { target, name } => {
                o.u8(target.byte());
                o.cstr(name)?;
            }
            Self::CopyData(bytes) | Self::AuthResponse(bytes) => o.put(bytes),
            Self::CopyFail(text) | Self::Query(text) => o.cstr(text)?,
            Self::Execute { portal, max_rows } => {
                o.cstr(portal)?;
                o.i32(*max_rows);
            }
            Self::FunctionCall(f) => {
                check_format_count(
                    frontend_tag::FUNCTION_CALL,
                    f.arg_formats.len(),
                    f.args.len(),
                )
                .map_err(|_| Error::Unwritable)?;
                check_text_values(frontend_tag::FUNCTION_CALL, &f.arg_formats, &f.args)
                    .map_err(|_| Error::Unwritable)?;
                o.u32(f.function);
                o.formats(&f.arg_formats)?;
                o.values(&f.args)?;
                o.i16(f.result_format.code());
            }
            Self::Parse {
                name,
                query,
                param_types,
            } => {
                o.cstr(name)?;
                o.cstr(query)?;
                o.count(param_types.len())?;
                for oid in param_types {
                    o.u32(*oid);
                }
            }
            Self::CopyDone | Self::Flush | Self::Sync | Self::Terminate => {}
        }
        out.extend_from_slice(&o.buf);
        Ok(())
    }
}

impl Wire for BackendMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one typed message. Refuses unknown tags, incomplete
    /// or trailing bytes, lengths above [`MAX_MESSAGE`], malformed fields,
    /// invalid UTF-8, duplicate diagnostic codes, and invalid counts or keys.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = split_typed(bytes, backend_limit, MAX_MESSAGE)?
            .map(|(tag, body, used)| backend_body(tag, body).map(|message| (message, used)))
            .transpose()?;
        exact(parsed, bytes.len())
    }

    /// Appends the complete message. Refuses oversized fields or lists,
    /// embedded NUL, short or long keys, binary columns in text COPY,
    /// empty SASL names, and zero or duplicate diagnostic codes. Stages at
    /// most [`MAX_MESSAGE`] plus one byte. Returns [`Error::Unwritable`]
    /// without changing `out` on refusal.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let size = backend_size(self);
        if size > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        let mut o = Out { buf: Vec::new() };
        o.u8(self.tag());
        o.u32(u32::try_from(size).map_err(|_| Error::Unwritable)?);
        match self {
            Self::Authentication(a) => {
                o.u32(a.code());
                match a {
                    Authentication::Md5Password(salt) => o.put(salt),
                    Authentication::GssContinue(d)
                    | Authentication::SaslContinue(d)
                    | Authentication::SaslFinal(d) => o.put(d),
                    Authentication::Sasl(names) => {
                        if names.len() > MAX_COUNT {
                            return Err(Error::Unwritable);
                        }
                        for name in names {
                            if name.is_empty() {
                                return Err(Error::Unwritable);
                            }
                            o.cstr(name)?;
                        }
                        o.u8(0);
                    }
                    _ => {}
                }
            }
            Self::BackendKeyData {
                process_id,
                secret_key,
            } => {
                if !(MIN_BACKEND_KEY..=MAX_SECRET_KEY).contains(&secret_key.len()) {
                    return Err(Error::Unwritable);
                }
                o.u32(*process_id);
                o.put(secret_key);
            }
            Self::CommandComplete(s) => o.cstr(s)?,
            Self::CopyData(d) => o.put(d),
            Self::CopyInResponse(c) | Self::CopyOutResponse(c) | Self::CopyBothResponse(c) => {
                if c.format == Format::Text && c.columns.contains(&Format::Binary) {
                    return Err(Error::Unwritable);
                }
                o.u8(c.format.code() as u8);
                o.formats(&c.columns)?;
            }
            Self::DataRow(values) => o.values(values)?,
            Self::ErrorResponse(d) | Self::NoticeResponse(d) => {
                let mut seen = [false; 256];
                for (code, value) in &d.fields {
                    if *code == 0 || std::mem::replace(&mut seen[usize::from(*code)], true) {
                        return Err(Error::Unwritable);
                    }
                    o.u8(*code);
                    o.cstr(value)?;
                }
                o.u8(0);
            }
            Self::FunctionCallResponse(v) => o.value(v.as_deref())?,
            Self::NegotiateProtocolVersion {
                version,
                unrecognized,
            } => {
                if unrecognized.len() > MAX_COUNT {
                    return Err(Error::Unwritable);
                }
                o.u32(*version);
                o.u32(u32::try_from(unrecognized.len()).map_err(|_| Error::Unwritable)?);
                for name in unrecognized {
                    o.cstr(name)?;
                }
            }
            Self::NotificationResponse {
                process_id,
                channel,
                payload,
            } => {
                o.u32(*process_id);
                o.cstr(channel)?;
                o.cstr(payload)?;
            }
            Self::ParameterDescription(types) => {
                o.count(types.len())?;
                for oid in types {
                    o.u32(*oid);
                }
            }
            Self::ParameterStatus { name, value } => {
                o.cstr(name)?;
                o.cstr(value)?;
            }
            Self::ReadyForQuery(status) => o.u8(status.byte()),
            Self::RowDescription(fields) => {
                o.count(fields.len())?;
                for f in fields {
                    o.cstr(&f.name)?;
                    o.u32(f.table_oid);
                    o.i16(f.column);
                    o.u32(f.type_oid);
                    o.i16(f.type_size);
                    o.i32(f.type_modifier);
                    o.i16(f.format.code());
                }
            }
            Self::BindComplete
            | Self::CloseComplete
            | Self::CopyDone
            | Self::EmptyQueryResponse
            | Self::NoData
            | Self::ParseComplete
            | Self::PortalSuspended => {}
        }
        out.extend_from_slice(&o.buf);
        Ok(())
    }
}

/// Reads frontend startup and typed messages without retaining input.
///
/// Items are `Result<FrontendMessage, Error>`; an error item is always a
/// body fault of a complete typed message, which carries its tag.
/// Invalid framing, malformed startup-phase bodies, unsupported protocols,
/// repeated encryption requests, and over-limit lengths end the stream
/// with a [`FrameError`].
/// Partial messages return [`Step::Need`], so [`fictionet::stdlib::codec::Stream`]
/// reports truncation at EOF.
///
/// A StartupMessage selects typed messages after its item. SSLRequest and
/// GSSENCRequest each yield an item followed by [`Step::End`]. Call
/// [`fictionet::stdlib::codec::Stream::into_parts`] and give its unread bytes to TLS or GSS,
/// then call [`start_encryption`](Self::start_encryption) on the returned
/// decoder and use a new stream for decrypted bytes. A direct ClientHello
/// returns [`FrameError::DirectTls`] without consuming any bytes; the same
/// transfer applies. CancelRequest and Terminate also yield an item then End.
///
/// To answer `N`, call [`refuse_encryption`](Self::refuse_encryption)
/// between the request item and the next poll. If End was already polled,
/// clone the decoder, refuse on that clone, and use [`fictionet::stdlib::codec::Stream::swap`].
/// [`fictionet::stdlib::codec::pump`] polls End after the item, so its users take this swap route.
/// Keep any unaccepted part of a pushed slice for the next transport.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, postgres::{FrontendMessage, FrontendMessages, Startup}};
///
/// let mut input = Wire::to_bytes(&FrontendMessage::SslRequest).unwrap();
/// FrontendMessage::Startup(Startup::new("alice", "shop")).write(&mut input).unwrap();
/// let mut stream = Stream::new(FrontendMessages::new());
/// assert_eq!(stream.push(&input), input.len());
/// let mut count = 0;
/// while let Some(item) = stream.next() {
///     match item.unwrap().unwrap() {
///         FrontendMessage::SslRequest => {
///             // The world answers N, then changes mode between items.
///             stream.decoder().refuse_encryption();
///         }
///         FrontendMessage::Startup(startup) => assert_eq!(startup.user(), Some("alice")),
///         other => panic!("unexpected {other:?}"),
///     }
///     count += 1;
/// }
/// assert_eq!(count, 2);
/// stream.end();
/// assert_eq!(stream.next(), None);
/// ```
#[derive(Clone, Debug)]
pub struct FrontendMessages {
    phase: Phase,
    limit: usize,
    started: bool,
    ssl_seen: bool,
    gss_seen: bool,
    handoff: bool,
}

impl FrontendMessages {
    /// Starts in the startup phase with [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_MESSAGE)
    }

    /// Sets the maximum typed length field, clamped to 4 through
    /// [`MAX_MESSAGE`]. Startup bodies remain bounded by [`MAX_STARTUP`].
    /// A limit of 4 accepts only empty typed bodies; even Close and Describe
    /// exceed it.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            phase: Phase::Startup,
            limit: limit.clamp(4, MAX_MESSAGE),
            started: false,
            ssl_seen: false,
            gss_seen: false,
            handoff: false,
        }
    }

    /// Selects typed messages for an already established session.
    /// The length-field limit is clamped as in [`Self::with_limit`].
    /// Use this when the connection's startup has already been read.
    pub fn established(limit: usize) -> Self {
        let mut messages = Self::with_limit(limit);
        messages.start_messages();
        messages
    }

    /// Selects typed messages for an already established session.
    /// Call before reading its bytes, between items.
    pub fn start_messages(&mut self) {
        self.phase = Phase::Messages;
        self.started = true;
        self.handoff = false;
    }

    /// The maximum typed length field, including its four length bytes.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The current startup, typed, or closed phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Resumes startup after an encryption request was refused with `N`.
    /// Call between items. Repeated requests remain refused. After End,
    /// apply this to a clone and swap it into the stream to resume polling.
    pub fn refuse_encryption(&mut self) {
        if self.phase == Phase::Startup {
            self.handoff = false;
        }
    }

    /// Prepares this decoder for decrypted startup bytes after handoff.
    /// Call on the decoder returned by [`fictionet::stdlib::codec::Stream::into_parts`].
    /// After a negotiated upgrade, further SSL and GSS requests are refused.
    /// Inside direct TLS, encryption requests may still be refused with `N`.
    pub fn start_encryption(&mut self) {
        if self.phase == Phase::Startup {
            if self.started {
                self.ssl_seen = true;
                self.gss_seen = true;
            }
            self.started = true;
            self.handoff = false;
        }
    }
}

impl Default for FrontendMessages {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for FrontendMessages {
    type Item = Result<FrontendMessage, Error>;
    type Error = FrameError;
    const NAME: &'static str = "PostgreSQL frontend";

    fn capacity(&self) -> usize {
        (MAX_STARTUP + 4).max(self.limit + 1)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, FrameError> {
        if self.handoff || self.phase == Phase::Closed {
            return Ok(Step::End);
        }
        let (message, used) = if self.phase == Phase::Startup {
            // A TLS handshake record starts with 22. No startup length can,
            // since it would be far over the limit.
            if !self.started && input.first() == Some(&0x16) {
                return Err(FrameError::DirectTls);
            }
            let Some((body, used)) = split_startup(input).map_err(FrameError::from_error)? else {
                return Ok(Step::Need);
            };
            (
                Ok(startup_body(body).map_err(FrameError::from_error)?),
                used,
            )
        } else {
            let split =
                split_typed(input, frontend_limit, self.limit).map_err(FrameError::from_error)?;
            let Some((tag, body, used)) = split else {
                return Ok(Step::Need);
            };
            (frontend_body(tag, body), used)
        };
        match &message {
            Ok(FrontendMessage::SslRequest) => {
                if self.ssl_seen {
                    return Err(FrameError::UnsupportedProtocol(SSL_REQUEST_CODE));
                }
                self.ssl_seen = true;
                self.handoff = true;
            }
            Ok(FrontendMessage::GssEncRequest) => {
                if self.gss_seen {
                    return Err(FrameError::UnsupportedProtocol(GSSENC_REQUEST_CODE));
                }
                self.gss_seen = true;
                self.handoff = true;
            }
            Ok(FrontendMessage::Startup(_)) => self.phase = Phase::Messages,
            Ok(FrontendMessage::CancelRequest { .. } | FrontendMessage::Terminate) => {
                self.phase = Phase::Closed
            }
            _ => {}
        }
        self.started = true;
        Ok(Step::Item(message, used))
    }
}

/// The one-byte response to an SSLRequest or GSSENCRequest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionReply {
    /// `S`: continue with TLS.
    Ssl,
    /// `G`: continue with GSS encryption.
    Gss,
    /// `N`: continue without this encryption method.
    Refused,
}

impl Wire for EncryptionReply {
    type ParseError = Error;
    type WriteError = core::convert::Infallible;

    /// Reads one `S`, `G`, or `N`. Refuses empty input, other bytes, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            [ACCEPT_SSL] => Ok(Self::Ssl),
            [ACCEPT_GSSENC] => Ok(Self::Gss),
            [REFUSE_ENCRYPTION] => Ok(Self::Refused),
            [] => Err(Error::Incomplete),
            [byte] => Err(Error::UnknownType(*byte)),
            _ => Err(Error::Trailing),
        }
    }

    /// Appends the response byte. Every variant is writable; none is refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.push(match self {
            Self::Ssl => ACCEPT_SSL,
            Self::Gss => ACCEPT_GSSENC,
            Self::Refused => REFUSE_ENCRYPTION,
        });
        Ok(())
    }
}

/// One backend negotiation response or typed message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendEvent {
    /// A one-byte encryption response.
    Encryption(EncryptionReply),
    /// A typed backend message.
    Message(BackendMessage),
}

/// Reads backend messages and optional one-byte encryption responses.
///
/// Malformed complete bodies are error items. Framing errors end the
/// stream. Partial messages return [`Step::Need`], including at EOF.
/// Call [`expect_encryption`](Self::expect_encryption) before the response
/// to an SSLRequest or GSSENCRequest. An `S` or `G` item is followed by
/// [`Step::End`]; unread bytes go to the next transport through
/// [`fictionet::stdlib::codec::Stream::into_parts`]. Use a new decoder for decrypted messages.
/// An `N` item resumes typed messages. World code may request another
/// negotiation response between items if it sends another request.
/// This mode accepts only `S`, `G` and `N`: an `E` ErrorResponse from an
/// older server ends the stream with [`FrameError::UnknownType`].
///
/// ```
/// use fictionet::stdlib::codec::{Stream, finish, pump};
/// use fictionet::stdlib::postgres::{BackendEvent, BackendEvents, BackendMessage, EncryptionReply, TransactionStatus};
///
/// let mut decoder = BackendEvents::with_limit(64);
/// decoder.expect_encryption();
/// let mut stream = Stream::new(decoder);
/// let mut items = Vec::new();
/// pump(&mut stream, b"NZ\0\0\0\x05I", |item| items.push(item.unwrap()))?;
/// finish(&mut stream, |_| unreachable!())?;
/// assert_eq!(items, [
///     BackendEvent::Encryption(EncryptionReply::Refused),
///     BackendEvent::Message(BackendMessage::ReadyForQuery(TransactionStatus::Idle)),
/// ]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::postgres::FrameError>>(())
/// ```
#[derive(Clone, Debug)]
pub struct BackendEvents {
    limit: usize,
    encryption: bool,
    handoff: bool,
}

impl BackendEvents {
    /// Reads typed messages up to [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_MESSAGE)
    }

    /// Sets the maximum length field, clamped to 4 through [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.clamp(4, MAX_MESSAGE),
            encryption: false,
            handoff: false,
        }
    }

    /// The maximum length field, including its four length bytes.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Selects a single encryption response as the next item.
    /// Call only between items, before reading any part of the next message.
    pub fn expect_encryption(&mut self) {
        self.encryption = true;
    }
}

impl Default for BackendEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for BackendEvents {
    type Item = Result<BackendEvent, Error>;
    type Error = FrameError;
    const NAME: &'static str = "PostgreSQL backend";

    fn capacity(&self) -> usize {
        self.limit + 1
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, FrameError> {
        if self.handoff {
            return Ok(Step::End);
        }
        if self.encryption {
            let Some(&byte) = input.first() else {
                return Ok(Step::Need);
            };
            let reply = match byte {
                ACCEPT_SSL => EncryptionReply::Ssl,
                ACCEPT_GSSENC => EncryptionReply::Gss,
                REFUSE_ENCRYPTION => EncryptionReply::Refused,
                _ => return Err(FrameError::UnknownType(byte)),
            };
            self.encryption = false;
            self.handoff = reply != EncryptionReply::Refused;
            return Ok(Step::Item(Ok(BackendEvent::Encryption(reply)), 1));
        }
        let split =
            split_typed(input, backend_limit, self.limit).map_err(FrameError::from_error)?;
        let Some((tag, body, used)) = split else {
            return Ok(Step::Need);
        };
        let message = backend_body(tag, body).map(BackendEvent::Message);
        Ok(Step::Item(message, used))
    }
}

/// Where [`FrontendMessages`] is in a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Before the StartupMessage: messages have no type byte.
    Startup,
    /// After the StartupMessage: every message is typed.
    Messages,
    /// After a CancelRequest or a Terminate. [`FrontendMessages`] returns
    /// End with remaining bytes unread.
    Closed,
}

/// The largest length field each frontend type may have, or `None` for a
/// byte that is not a frontend type. These are PostgreSQL's own limits.
fn frontend_limit(tag: u8) -> Option<usize> {
    use frontend_tag as t;
    match tag {
        t::BIND | t::COPY_DATA | t::FUNCTION_CALL | t::PARSE | t::QUERY => Some(MAX_MESSAGE),
        t::AUTH_RESPONSE => Some(MAX_AUTH_MESSAGE),
        t::CLOSE
        | t::COPY_DONE
        | t::COPY_FAIL
        | t::DESCRIBE
        | t::EXECUTE
        | t::FLUSH
        | t::SYNC
        | t::TERMINATE => Some(SMALL_MESSAGE),
        _ => None,
    }
}

/// The largest length field each backend type may have, or `None` for a
/// byte that is not a backend type.
fn backend_limit(tag: u8) -> Option<usize> {
    match tag {
        b'R' | b'K' | b'2' | b'3' | b'C' | b'd' | b'c' | b'G' | b'H' | b'W' | b'D' | b'I'
        | b'E' | b'V' | b'v' | b'n' | b'N' | b'A' | b't' | b'S' | b'1' | b's' | b'Z' | b'T' => {
            Some(MAX_MESSAGE)
        }
        _ => None,
    }
}

/// A typed message split from the stream: its type byte, its body, and
/// how many bytes of the stream it took.
type Typed<'a> = (u8, &'a [u8], usize);

/// The type byte, body and total size of the typed message at the start
/// of `b`, if it has all come. Each check runs as soon as the bytes it
/// needs are there, so an error never depends on how the stream was cut.
fn split_typed(
    b: &[u8],
    limit: fn(u8) -> Option<usize>,
    max: usize,
) -> Result<Option<Typed<'_>>, Error> {
    let Some(&tag) = b.first() else {
        return Ok(None);
    };
    let limit = limit(tag).ok_or(Error::UnknownType(tag))?.min(max);
    if b.len() < 5 {
        return Ok(None);
    }
    let Some(length) = be32(b, 1) else {
        return Ok(None);
    };
    if length < 4 {
        return Err(Error::BadLength(length));
    }
    let size = usize::try_from(length).unwrap_or(usize::MAX);
    if size > limit {
        return Err(Error::TooLong { length, max: limit });
    }
    let end = 1 + size;
    if b.len() < end {
        return Ok(None);
    }
    Ok(Some((tag, &b[5..end], end)))
}

/// The body (after the length) and total size of the startup-phase
/// message at the start of `b`, if it has all come.
fn split_startup(b: &[u8]) -> Result<Option<(&[u8], usize)>, Error> {
    if b.len() < 4 {
        return Ok(None);
    }
    let Some(length) = be32(b, 0) else {
        return Ok(None);
    };
    if length < 8 {
        return Err(Error::BadLength(length));
    }
    let size = usize::try_from(length).unwrap_or(usize::MAX);
    if size - 4 > MAX_STARTUP {
        return Err(Error::TooLong {
            length,
            max: MAX_STARTUP + 4,
        });
    }
    if b.len() >= 8 {
        let code = be32(b, 4).ok_or(Error::Incomplete)?;
        let known = matches!(
            code,
            SSL_REQUEST_CODE | GSSENC_REQUEST_CODE | CANCEL_REQUEST_CODE
        ) || code >> 16 == 3;
        if !known {
            return Err(Error::UnsupportedProtocol(code));
        }
    }
    if b.len() < size {
        return Ok(None);
    }
    Ok(Some((&b[4..size], size)))
}

/// Reads a startup-phase body, which starts with a known code.
fn startup_body(body: &[u8]) -> Result<FrontendMessage, Error> {
    let mut r = Fields {
        cursor: ByteReader::new(body),
        tag: 0,
    };
    let code = r.u32()?;
    let message = match code {
        SSL_REQUEST_CODE => FrontendMessage::SslRequest,
        GSSENC_REQUEST_CODE => FrontendMessage::GssEncRequest,
        CANCEL_REQUEST_CODE => {
            let process_id = r.u32()?;
            let key = r.rest();
            if key.is_empty() || key.len() > MAX_SECRET_KEY {
                return Err(Error::BadKeyLength {
                    tag: 0,
                    length: key.len(),
                });
            }
            FrontendMessage::CancelRequest {
                process_id,
                secret_key: key.to_vec(),
            }
        }
        _ => {
            let mut params = Vec::new();
            loop {
                let name = r.cstr()?;
                if name.is_empty() {
                    break;
                }
                let value = r.cstr()?;
                params.push((name, value));
            }
            FrontendMessage::Startup(Startup {
                minor_version: code as u16,
                params,
            })
        }
    };
    r.end()?;
    Ok(message)
}

/// Reads a typed frontend body. `tag` is a known frontend type.
fn frontend_body(tag: u8, body: &[u8]) -> Result<FrontendMessage, Error> {
    use frontend_tag as t;
    let mut r = Fields {
        cursor: ByteReader::new(body),
        tag,
    };
    let message = match tag {
        t::BIND => {
            let portal = r.cstr()?;
            let statement = r.cstr()?;
            let param_formats = r.formats()?;
            let params = r.values()?;
            let result_formats = r.formats()?;
            check_format_count(tag, param_formats.len(), params.len())?;
            check_text_values(tag, &param_formats, &params)?;
            FrontendMessage::Bind(Bind {
                portal,
                statement,
                param_formats,
                params,
                result_formats,
            })
        }
        t::CLOSE => {
            let target = r.target()?;
            FrontendMessage::Close {
                target,
                name: r.cstr()?,
            }
        }
        t::COPY_DATA => FrontendMessage::CopyData(r.rest().to_vec()),
        t::COPY_DONE => FrontendMessage::CopyDone,
        t::COPY_FAIL => FrontendMessage::CopyFail(r.cstr()?),
        t::DESCRIBE => {
            let target = r.target()?;
            FrontendMessage::Describe {
                target,
                name: r.cstr()?,
            }
        }
        t::EXECUTE => {
            let portal = r.cstr()?;
            FrontendMessage::Execute {
                portal,
                max_rows: r.i32()?,
            }
        }
        t::FLUSH => FrontendMessage::Flush,
        t::FUNCTION_CALL => {
            let function = r.u32()?;
            let arg_formats = r.formats()?;
            let args = r.values()?;
            let result_format = r.format()?;
            check_format_count(tag, arg_formats.len(), args.len())?;
            check_text_values(tag, &arg_formats, &args)?;
            FrontendMessage::FunctionCall(FunctionCall {
                function,
                arg_formats,
                args,
                result_format,
            })
        }
        t::AUTH_RESPONSE => FrontendMessage::AuthResponse(r.rest().to_vec()),
        t::PARSE => {
            let name = r.cstr()?;
            let query = r.cstr()?;
            let n = r.u16()?;
            let mut param_types = Vec::new();
            for _ in 0..n {
                param_types.push(r.u32()?);
            }
            FrontendMessage::Parse {
                name,
                query,
                param_types,
            }
        }
        t::QUERY => FrontendMessage::Query(r.cstr()?),
        t::SYNC => FrontendMessage::Sync,
        _ => FrontendMessage::Terminate,
    };
    r.end()?;
    Ok(message)
}

/// Reads a backend body. `tag` is a known backend type.
fn backend_body(tag: u8, body: &[u8]) -> Result<BackendMessage, Error> {
    use backend_tag as t;
    let mut r = Fields {
        cursor: ByteReader::new(body),
        tag,
    };
    let message = match tag {
        t::AUTHENTICATION => {
            let code = r.u32()?;
            BackendMessage::Authentication(match code {
                0 => Authentication::Ok,
                2 => Authentication::KerberosV5,
                3 => Authentication::CleartextPassword,
                5 => {
                    let s = r.take(4)?;
                    Authentication::Md5Password([s[0], s[1], s[2], s[3]])
                }
                7 => Authentication::Gss,
                8 => Authentication::GssContinue(r.rest().to_vec()),
                9 => Authentication::Sspi,
                10 => {
                    let mut names = Vec::new();
                    loop {
                        let name = r.cstr()?;
                        if name.is_empty() {
                            break;
                        }
                        if names.len() == MAX_COUNT {
                            return Err(Error::TooManyItems { tag });
                        }
                        names.push(name);
                    }
                    Authentication::Sasl(names)
                }
                11 => Authentication::SaslContinue(r.rest().to_vec()),
                12 => Authentication::SaslFinal(r.rest().to_vec()),
                c => return Err(Error::BadAuth { tag, code: c }),
            })
        }
        t::BACKEND_KEY_DATA => {
            let process_id = r.u32()?;
            let key = r.rest();
            if key.len() < MIN_BACKEND_KEY || key.len() > MAX_SECRET_KEY {
                return Err(Error::BadKeyLength {
                    tag,
                    length: key.len(),
                });
            }
            BackendMessage::BackendKeyData {
                process_id,
                secret_key: key.to_vec(),
            }
        }
        t::BIND_COMPLETE => BackendMessage::BindComplete,
        t::CLOSE_COMPLETE => BackendMessage::CloseComplete,
        t::COMMAND_COMPLETE => BackendMessage::CommandComplete(r.cstr()?),
        t::COPY_DATA => BackendMessage::CopyData(r.rest().to_vec()),
        t::COPY_DONE => BackendMessage::CopyDone,
        t::COPY_IN_RESPONSE | t::COPY_OUT_RESPONSE | t::COPY_BOTH_RESPONSE => {
            let overall = r.u8()?;
            let format = Format::from_code(i16::from(overall)).ok_or(Error::BadFormat {
                tag,
                code: i16::from(overall),
            })?;
            let columns = r.formats()?;
            if format == Format::Text && columns.contains(&Format::Binary) {
                return Err(Error::BadFormat { tag, code: 1 });
            }
            let c = CopyFormat { format, columns };
            match tag {
                t::COPY_IN_RESPONSE => BackendMessage::CopyInResponse(c),
                t::COPY_OUT_RESPONSE => BackendMessage::CopyOutResponse(c),
                _ => BackendMessage::CopyBothResponse(c),
            }
        }
        t::DATA_ROW => BackendMessage::DataRow(r.values()?),
        t::EMPTY_QUERY_RESPONSE => BackendMessage::EmptyQueryResponse,
        t::ERROR_RESPONSE | t::NOTICE_RESPONSE => {
            let mut fields = Vec::new();
            // Each code comes once, so there are at most 255 fields.
            let mut seen = [false; 256];
            loop {
                let code = r.u8()?;
                if code == 0 {
                    break;
                }
                if std::mem::replace(&mut seen[usize::from(code)], true) {
                    return Err(Error::DuplicateField { tag, code });
                }
                fields.push((code, r.cstr()?));
            }
            let d = Diagnostic { fields };
            if tag == t::ERROR_RESPONSE {
                BackendMessage::ErrorResponse(d)
            } else {
                BackendMessage::NoticeResponse(d)
            }
        }
        t::FUNCTION_CALL_RESPONSE => BackendMessage::FunctionCallResponse(r.value()?),
        t::NEGOTIATE_PROTOCOL_VERSION => {
            let version = r.u32()?;
            let n = r.u32()?;
            // Each name takes one byte on the wire and far more in memory,
            // so the count is held to the cap.
            if usize::try_from(n).map_or(true, |n| n > MAX_COUNT) {
                return Err(Error::TooManyItems { tag });
            }
            let mut unrecognized = Vec::new();
            for _ in 0..n {
                unrecognized.push(r.cstr()?);
            }
            BackendMessage::NegotiateProtocolVersion {
                version,
                unrecognized,
            }
        }
        t::NO_DATA => BackendMessage::NoData,
        t::NOTIFICATION_RESPONSE => {
            let process_id = r.u32()?;
            let channel = r.cstr()?;
            BackendMessage::NotificationResponse {
                process_id,
                channel,
                payload: r.cstr()?,
            }
        }
        t::PARAMETER_DESCRIPTION => {
            let n = r.u16()?;
            let mut types = Vec::new();
            for _ in 0..n {
                types.push(r.u32()?);
            }
            BackendMessage::ParameterDescription(types)
        }
        t::PARAMETER_STATUS => {
            let name = r.cstr()?;
            BackendMessage::ParameterStatus {
                name,
                value: r.cstr()?,
            }
        }
        t::PARSE_COMPLETE => BackendMessage::ParseComplete,
        t::PORTAL_SUSPENDED => BackendMessage::PortalSuspended,
        t::READY_FOR_QUERY => {
            let b = r.u8()?;
            BackendMessage::ReadyForQuery(
                TransactionStatus::from_byte(b).ok_or(Error::BadStatus { tag, status: b })?,
            )
        }
        _ => {
            let n = r.u16()?;
            let mut fields = Vec::new();
            for _ in 0..n {
                fields.push(Field {
                    name: r.cstr()?,
                    table_oid: r.u32()?,
                    column: r.i16()?,
                    type_oid: r.u32()?,
                    type_size: r.i16()?,
                    type_modifier: r.i32()?,
                    format: r.format()?,
                });
            }
            BackendMessage::RowDescription(fields)
        }
    };
    r.end()?;
    Ok(message)
}

/// PostgreSQL's rule for format lists: none, one for all, or one each.
fn check_format_count(tag: u8, formats: usize, values: usize) -> Result<(), Error> {
    if formats <= 1 || formats == values {
        Ok(())
    } else {
        Err(Error::FormatCount { tag })
    }
}

/// Refuses a text-format value that is not UTF-8 text with no NUL.
fn check_text_values(tag: u8, formats: &[Format], values: &[Value]) -> Result<(), Error> {
    for (i, v) in values.iter().enumerate() {
        if let Some(b) = v
            && format_for(formats, i) == Format::Text
            && (b.contains(&0) || std::str::from_utf8(b).is_err())
        {
            return Err(Error::NotUtf8 { tag });
        }
    }
    Ok(())
}

/// The format of item `i` under that rule.
fn format_for(formats: &[Format], i: usize) -> Format {
    match formats {
        [] => Format::Text,
        [only] => *only,
        all => all.get(i).copied().unwrap_or_default(),
    }
}

/// Reads fields from the front of a body.
struct Fields<'a> {
    cursor: ByteReader<'a>,
    /// The message's type byte, or 0 for a startup-phase message.
    tag: u8,
}

impl<'a> Fields<'a> {
    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.cursor
            .take(n)
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    #[inline]
    fn u8(&mut self) -> Result<u8, Error> {
        self.cursor
            .u8()
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    #[inline]
    fn u16(&mut self) -> Result<u16, Error> {
        self.cursor
            .u16_be()
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    #[inline]
    fn i16(&mut self) -> Result<i16, Error> {
        self.cursor
            .i16_be()
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    #[inline]
    fn u32(&mut self) -> Result<u32, Error> {
        self.cursor
            .u32_be()
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    #[inline]
    fn i32(&mut self) -> Result<i32, Error> {
        self.cursor
            .i32_be()
            .map_err(|_| Error::Truncated { tag: self.tag })
    }

    fn cstr(&mut self) -> Result<String, Error> {
        let rest = self.cursor.clone().rest();
        let end = rest
            .iter()
            .position(|&c| c == 0)
            .ok_or(Error::UnterminatedString { tag: self.tag })?;
        let s = std::str::from_utf8(&rest[..end]).map_err(|_| Error::NotUtf8 { tag: self.tag })?;
        self.cursor
            .skip(end + 1)
            .map_err(|_| Error::Truncated { tag: self.tag })?;
        Ok(s.to_owned())
    }

    fn format(&mut self) -> Result<Format, Error> {
        let c = self.i16()?;
        Format::from_code(c).ok_or(Error::BadFormat {
            tag: self.tag,
            code: c,
        })
    }

    /// A 16-bit count, then that many format codes.
    fn formats(&mut self) -> Result<Vec<Format>, Error> {
        let n = self.u16()?;
        (0..n).map(|_| self.format()).collect()
    }

    fn target(&mut self) -> Result<Target, Error> {
        let b = self.u8()?;
        Target::from_byte(b).ok_or(Error::BadTarget {
            tag: self.tag,
            target: b,
        })
    }

    /// A 32-bit length (-1 for NULL), then that many bytes.
    fn value(&mut self) -> Result<Value, Error> {
        let n = self.i32()?;
        match n {
            -1 => Ok(None),
            n if n < 0 => Err(Error::BadValueLength {
                tag: self.tag,
                length: n,
            }),
            n => Ok(Some(self.take(n as usize)?.to_vec())),
        }
    }

    /// A 16-bit count, then that many values. Each value takes at least
    /// 4 bytes, so the body bounds the list.
    fn values(&mut self) -> Result<Vec<Value>, Error> {
        let n = self.u16()?;
        (0..n).map(|_| self.value()).collect()
    }

    #[inline]
    fn rest(&mut self) -> &'a [u8] {
        self.cursor.rest()
    }

    #[inline]
    fn end(&self) -> Result<(), Error> {
        self.cursor
            .finish()
            .map_err(|_| Error::TrailingBytes { tag: self.tag })
    }
}

/// The bytes a value takes: its length field and its bytes.
fn value_size(v: Option<&[u8]>) -> usize {
    4usize.saturating_add(v.map_or(0, <[u8]>::len))
}

/// A type byte for a message: the letter in quotes, or its number.
fn show_tag(t: u8) -> String {
    if t.is_ascii_graphic() {
        format!("'{}'", t as char)
    } else {
        format!("0x{t:02x}")
    }
}

#[cfg(test)]
mod tests {
    fn fixture_frontend_message_cancel_request(
        process_id: u32,
        secret_key: Vec<u8>,
    ) -> FrontendMessage {
        FrontendMessage::CancelRequest {
            process_id,
            secret_key,
        }
    }

    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    #[test]
    fn all_message_variants_obey_wire_contract() {
        for message in all_frontend() {
            contract::check_wire_value(&message);
            let bytes = Wire::to_bytes(&message).unwrap();
            assert_eq!(
                frontend_size(&message),
                bytes.len() - usize::from(message.tag().is_some())
            );
            contract::check_wire::<FrontendMessage>(&bytes);
        }
        for message in all_backend() {
            contract::check_wire_value(&message);
            let bytes = Wire::to_bytes(&message).unwrap();
            assert_eq!(backend_size(&message), bytes.len() - 1);
            contract::check_wire::<BackendMessage>(&bytes);
        }
    }

    #[test]
    fn strict_writes_enforce_frontend_type_sizes() {
        for (fixed, limit, make) in [
            (
                6,
                SMALL_MESSAGE,
                (|n| FrontendMessage::Close {
                    target: Target::Statement,
                    name: "x".repeat(n),
                }) as fn(usize) -> FrontendMessage,
            ),
            (
                4,
                MAX_AUTH_MESSAGE,
                (|n| FrontendMessage::AuthResponse(vec![0; n])) as fn(usize) -> FrontendMessage,
            ),
            (
                12,
                MAX_STARTUP + 4,
                (|n| {
                    FrontendMessage::Startup(Startup {
                        minor_version: 0,
                        params: vec![("u".into(), "x".repeat(n))],
                    })
                }) as fn(usize) -> FrontendMessage,
            ),
        ] {
            let message = make(limit - fixed);
            let bytes = Wire::to_bytes(&message).unwrap();
            assert_eq!(bytes.len(), limit + usize::from(message.tag().is_some()));
            let mut out = b"prefix".to_vec();
            assert_eq!(
                make(limit - fixed + 1).write(&mut out),
                Err(Error::Unwritable)
            );
            assert_eq!(out, b"prefix");
        }
    }

    // Byte layouts from chapter 54 of the PostgreSQL 18 documentation,
    // "Message Formats".

    fn startup_bytes() -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0, 0, 3, 0, 0];
        b.extend_from_slice(b"user\0alice\0database\0shop\0client_encoding\0UTF8\0\0");
        let n = b.len() as u32;
        b[..4].copy_from_slice(&n.to_be_bytes());
        b
    }

    #[test]
    fn startup_message() {
        let bytes = startup_bytes();
        assert_eq!(bytes.len(), 55);
        let m = FrontendMessage::parse(&bytes).unwrap();
        assert_eq!(m, FrontendMessage::Startup(Startup::new("alice", "shop")));
        assert_eq!(m.to_bytes().unwrap(), bytes);
        let FrontendMessage::Startup(s) = m else {
            panic!()
        };
        assert_eq!(s.user(), Some("alice"));
        // With no database parameter, the database is the user's name.
        let s = Startup {
            minor_version: 2,
            params: vec![("user".into(), "bob".into())],
        };
        assert_eq!(s.database(), Some("bob"));
        let bytes = FrontendMessage::Startup(s.clone()).to_bytes().unwrap();
        assert_eq!(&bytes[4..8], &PROTOCOL_3_2.to_be_bytes());
        assert_eq!(
            FrontendMessage::parse(&bytes).unwrap(),
            FrontendMessage::Startup(s)
        );
        // No parameters at all is the terminator alone.
        let empty = FrontendMessage::Startup(Startup::default())
            .to_bytes()
            .unwrap();
        assert_eq!(empty, [0, 0, 0, 9, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn encryption_and_cancel_requests() {
        let ssl = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(
            FrontendMessage::parse(&ssl),
            Ok(FrontendMessage::SslRequest)
        );
        assert_eq!(FrontendMessage::SslRequest.to_bytes().unwrap(), ssl);
        let gss = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];
        assert_eq!(
            FrontendMessage::parse(&gss),
            Ok(FrontendMessage::GssEncRequest)
        );
        assert_eq!(FrontendMessage::GssEncRequest.to_bytes().unwrap(), gss);
        let cancel = [
            0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x10, 0x92, 1, 2, 3, 4,
        ];
        let m = fixture_frontend_message_cancel_request(4242, vec![1, 2, 3, 4]);
        assert_eq!(FrontendMessage::parse(&cancel), Ok(m.clone()));
        assert_eq!(m.to_bytes().unwrap(), cancel);
        // A protocol 3.2 key of 32 bytes.
        let long = fixture_frontend_message_cancel_request(1, vec![9; 32]);
        assert_eq!(
            FrontendMessage::parse(&long.to_bytes().unwrap()).unwrap(),
            long
        );
        assert!(m.is_startup() && m.tag().is_none());
    }

    #[test]
    fn simple_query_replies() {
        assert_eq!(
            FrontendMessage::parse(b"Q\0\0\0\x0dSELECT 1\0"),
            Ok(FrontendMessage::Query("SELECT 1".into()))
        );
        let cases: Vec<(BackendMessage, &[u8])> = vec![
            (
                BackendMessage::Authentication(Authentication::Ok),
                b"R\0\0\0\x08\0\0\0\0",
            ),
            (
                BackendMessage::Authentication(Authentication::CleartextPassword),
                b"R\0\0\0\x08\0\0\0\x03",
            ),
            (
                BackendMessage::Authentication(Authentication::Md5Password(*b"salt")),
                b"R\0\0\0\x0c\0\0\0\x05salt",
            ),
            (
                BackendMessage::Authentication(Authentication::Sasl(vec!["SCRAM-SHA-256".into()])),
                b"R\0\0\0\x17\0\0\0\x0aSCRAM-SHA-256\0\0",
            ),
            (
                BackendMessage::Authentication(Authentication::SaslFinal(b"v=xyz".to_vec())),
                b"R\0\0\0\x0d\0\0\0\x0cv=xyz",
            ),
            (
                BackendMessage::ParameterStatus {
                    name: "client_encoding".into(),
                    value: "UTF8".into(),
                },
                b"S\0\0\0\x19client_encoding\0UTF8\0",
            ),
            (
                BackendMessage::BackendKeyData {
                    process_id: 7,
                    secret_key: vec![0, 0, 0, 9],
                },
                b"K\0\0\0\x0c\0\0\0\x07\0\0\0\x09",
            ),
            (
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
                b"Z\0\0\0\x05I",
            ),
            (
                BackendMessage::ReadyForQuery(TransactionStatus::Failed),
                b"Z\0\0\0\x05E",
            ),
            (
                BackendMessage::CommandComplete("SELECT 1".into()),
                b"C\0\0\0\x0dSELECT 1\0",
            ),
            (BackendMessage::EmptyQueryResponse, b"I\0\0\0\x04"),
            (BackendMessage::ParseComplete, b"1\0\0\0\x04"),
            (BackendMessage::BindComplete, b"2\0\0\0\x04"),
            (BackendMessage::CloseComplete, b"3\0\0\0\x04"),
            (BackendMessage::NoData, b"n\0\0\0\x04"),
            (BackendMessage::PortalSuspended, b"s\0\0\0\x04"),
            (BackendMessage::CopyDone, b"c\0\0\0\x04"),
            (
                BackendMessage::DataRow(vec![Some(b"42".to_vec()), None]),
                b"D\0\0\0\x10\0\x02\0\0\0\x02\x34\x32\xff\xff\xff\xff",
            ),
            (
                BackendMessage::ParameterDescription(vec![oid::INT4]),
                b"t\0\0\0\x0a\0\x01\0\0\0\x17",
            ),
            (
                BackendMessage::CopyOutResponse(CopyFormat {
                    format: Format::Text,
                    columns: vec![Format::Text; 2],
                }),
                b"H\0\0\0\x0b\0\0\x02\0\0\0\0",
            ),
            (
                BackendMessage::FunctionCallResponse(None),
                b"V\0\0\0\x08\xff\xff\xff\xff",
            ),
            (
                BackendMessage::NotificationResponse {
                    process_id: 1,
                    channel: "c".into(),
                    payload: "".into(),
                },
                b"A\0\0\0\x0b\0\0\0\x01c\0\0",
            ),
            (
                BackendMessage::NegotiateProtocolVersion {
                    version: PROTOCOL_3_0,
                    unrecognized: vec!["_pq_.x".into()],
                },
                b"v\0\0\0\x13\0\x03\0\0\0\0\0\x01_pq_.x\0",
            ),
        ];
        for (message, bytes) in cases {
            assert_eq!(message.to_bytes().unwrap(), bytes, "{message:?}");
            assert_eq!(BackendMessage::parse(bytes), Ok(message));
        }
    }

    #[test]
    fn row_description_layout() {
        let field = Field::new("id", oid::INT4);
        let bytes = BackendMessage::RowDescription(vec![field.clone()])
            .to_bytes()
            .unwrap();
        let mut want = b"T\0\0\0\x1b\0\x01id\0".to_vec();
        want.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xff, 0xff, 0xff, 0xff, 0, 0,
        ]);
        assert_eq!(bytes, want);
        assert_eq!(
            BackendMessage::parse(&bytes).unwrap(),
            BackendMessage::RowDescription(vec![field])
        );
        assert_eq!(Field::new("t", oid::TEXT).type_size, -1);
    }

    #[test]
    fn error_response_layout() {
        let d = Diagnostic::error(sqlstate::UNDEFINED_TABLE, "relation \"x\" does not exist")
            .with(field_code::POSITION, "15");
        let bytes = BackendMessage::ErrorResponse(d.clone()).to_bytes().unwrap();
        let mut body = b"SERROR\0VERROR\0C42P01\0Mrelation \"x\" does not exist\0P15\0\0".to_vec();
        let mut want = vec![b'E'];
        want.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
        want.append(&mut body);
        assert_eq!(bytes, want);
        let back = BackendMessage::parse(&bytes).unwrap();
        assert_eq!(back, BackendMessage::ErrorResponse(d.clone()));
        assert_eq!(d.get(field_code::CODE), Some("42P01"));
        assert_eq!(d.get(field_code::HINT), None);
        let notice = BackendMessage::NoticeResponse(Diagnostic::new(
            "NOTICE",
            sqlstate::SUCCESSFUL_COMPLETION,
            "hi",
        ));
        assert_eq!(
            BackendMessage::parse(&notice.to_bytes().unwrap()).unwrap(),
            notice
        );
        assert_eq!(
            Diagnostic::fatal(sqlstate::INVALID_PASSWORD, "no").get(field_code::SEVERITY),
            Some("FATAL")
        );
    }

    /// Parse, Bind, Describe, Execute and Sync, as libpq sends a
    /// parameterized query.
    fn extended_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"P\0\0\0\x15\0SELECT $1\0\0\x01\0\0\0\x17");
        b.extend_from_slice(b"B\0\0\0\x13\0\0\0\0\0\x01\0\0\0\x015\0\x01\0\x01");
        b.extend_from_slice(b"D\0\0\0\x06P\0");
        b.extend_from_slice(b"E\0\0\0\x09\0\0\0\0\0");
        b.extend_from_slice(b"S\0\0\0\x04");
        b
    }

    fn extended_messages() -> Vec<FrontendMessage> {
        vec![
            FrontendMessage::Parse {
                name: "".into(),
                query: "SELECT $1".into(),
                param_types: vec![oid::INT4],
            },
            FrontendMessage::Bind(Bind {
                params: vec![Some(b"5".to_vec())],
                result_formats: vec![Format::Binary],
                ..Bind::default()
            }),
            FrontendMessage::Describe {
                target: Target::Portal,
                name: "".into(),
            },
            FrontendMessage::Execute {
                portal: "".into(),
                max_rows: 0,
            },
            FrontendMessage::Sync,
        ]
    }

    #[test]
    fn extended_query() {
        let bytes = extended_bytes();
        let (got, failure) = decode_all(|| FrontendMessages::established(SMALL_MESSAGE), &bytes);
        assert_eq!(failure, None);
        assert_eq!(
            got,
            extended_messages().into_iter().map(Ok).collect::<Vec<_>>()
        );
        let mut written = Vec::new();
        for message in got {
            message.unwrap().write(&mut written).unwrap();
        }
        assert_eq!(written, bytes);
        let FrontendMessage::Bind(b) = &extended_messages()[1] else {
            panic!()
        };
        assert_eq!(b.param_format(0), Format::Text);
        assert_eq!(b.result_format(3), Format::Binary);
    }

    #[test]
    fn other_frontend_messages() {
        let cases: Vec<(FrontendMessage, &[u8])> = vec![
            (
                FrontendMessage::Close {
                    target: Target::Statement,
                    name: "s1".into(),
                },
                b"C\0\0\0\x08Ss1\0",
            ),
            (
                FrontendMessage::CopyData(b"1\tx\n".to_vec()),
                b"d\0\0\0\x081\tx\n",
            ),
            (FrontendMessage::CopyDone, b"c\0\0\0\x04"),
            (FrontendMessage::CopyFail("no".into()), b"f\0\0\0\x07no\0"),
            (FrontendMessage::Flush, b"H\0\0\0\x04"),
            (FrontendMessage::Terminate, b"X\0\0\0\x04"),
            (FrontendMessage::password("pw").unwrap(), b"p\0\0\0\x07pw\0"),
            (
                FrontendMessage::FunctionCall(FunctionCall {
                    function: 1598,
                    arg_formats: vec![],
                    args: vec![None],
                    result_format: Format::Binary,
                }),
                b"F\0\0\0\x12\0\0\x06\x3e\0\0\0\x01\xff\xff\xff\xff\0\x01",
            ),
        ];
        for (message, bytes) in cases {
            assert_eq!(message.to_bytes().unwrap(), bytes, "{message:?}");
            assert_eq!(FrontendMessage::parse(bytes), Ok(message));
        }
    }

    #[test]
    fn auth_responses() {
        let FrontendMessage::AuthResponse(body) = FrontendMessage::password("md5abc").unwrap()
        else {
            panic!()
        };
        fictionet::assert_cases! {
            Password::parse;
            (&body) => Ok(Password("md5abc".into())),
            (b"pw") => Err(Error::UnterminatedString {
                tag: frontend_tag::AUTH_RESPONSE,
            }),
            (b"pw\0x") => Err(Error::TrailingBytes {
                tag: frontend_tag::AUTH_RESPONSE,
            }),
        }
        for data in [None, Some(vec![]), Some(b"n,,n=,r=abc".to_vec())] {
            let sasl = SaslInitialResponse {
                mechanism: "SCRAM-SHA-256".into(),
                data,
            };
            let FrontendMessage::AuthResponse(body) = sasl.to_message().unwrap() else {
                panic!()
            };
            assert_eq!(&body[..14], b"SCRAM-SHA-256\0");
            let length = sasl.data.as_ref().map_or(-1, |bytes| bytes.len() as i32);
            assert_eq!(&body[14..18], &length.to_be_bytes());
            assert_eq!(SaslInitialResponse::parse(&body), Ok(sasl.clone()));
            contract::check_wire_value(&sasl);
            contract::check_wire::<SaslInitialResponse>(&body);
        }
        let none = SaslInitialResponse {
            mechanism: "X".into(),
            data: None,
        };
        assert_eq!(none.to_bytes().unwrap(), b"X\0\xff\xff\xff\xff");
        assert_eq!(
            SaslInitialResponse::parse(b"X\0\0\0\0\x05ab"),
            Err(Error::Truncated {
                tag: frontend_tag::AUTH_RESPONSE
            })
        );
        assert_eq!(
            SaslInitialResponse::parse(b"X\0\xff\xff\xff\xfe"),
            Err(Error::BadValueLength {
                tag: frontend_tag::AUTH_RESPONSE,
                length: -2
            })
        );
        for value in [
            SaslInitialResponse {
                mechanism: "M".into(),
                data: Some(vec![7; rounds(100_000)]),
            },
            SaslInitialResponse {
                mechanism: "M\0N".into(),
                data: None,
            },
        ] {
            assert_unwritable(&value);
        }
        assert_eq!(
            FrontendMessage::password(&"é".repeat(40_000)),
            Err(Error::Unwritable)
        );
        assert_eq!(FrontendMessage::password("a\0b"), Err(Error::Unwritable));
        let oversized = vec![0; MAX_AUTH_MESSAGE - 3];
        let too_long = Error::TooLong {
            length: MAX_AUTH_MESSAGE as u32 + 1,
            max: MAX_AUTH_MESSAGE,
        };
        assert_eq!(Password::parse(&oversized), Err(too_long));
        assert_eq!(SaslInitialResponse::parse(&oversized), Err(too_long));
        for len in [MAX_AUTH_MESSAGE - 5, MAX_AUTH_MESSAGE - 4] {
            let password = Password("x".repeat(len));
            assert_eq!(password.to_bytes().is_ok(), len == MAX_AUTH_MESSAGE - 5);
            contract::check_wire_value(&password);
        }
    }

    fn startup_with(code: u32, rest: &[u8]) -> Vec<u8> {
        let mut b = ((8 + rest.len()) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(rest);
        b
    }

    fn typed(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut b = vec![tag];
        b.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn startup_errors() {
        // A TLS ClientHello, known from its first byte.
        assert_eq!(
            FrontendMessages::new().decode(&[0x16], false),
            Err(FrameError::DirectTls)
        );
        fictionet::assert_cases! {
            FrontendMessage::parse;
            (&[0, 0, 0, 7]) => Err(Error::BadLength(7)),
            (&[0, 0, 0x27, 0x15]) => Err(Error::TooLong {
                length: 10_005,
                max: MAX_STARTUP + 4,
            }),
            (&[0, 0, 0x27, 0x14]) => Err(Error::Incomplete),
            // Protocol 2.0, refused as soon as its version arrives.
            (&[0, 0, 0, 9, 0, 2, 0, 0]) => Err(Error::UnsupportedProtocol(0x2_0000)),
            (&startup_with(0x04d2_0000, b"\0")) => Err(Error::UnsupportedProtocol(0x04d2_0000)),
            // Requests with bytes they should not have.
            (&startup_with(SSL_REQUEST_CODE, b"x")) => Err(Error::TrailingBytes { tag: 0 }),
            (&startup_with(GSSENC_REQUEST_CODE, b"x")) => Err(Error::TrailingBytes { tag: 0 }),
            (&startup_with(CANCEL_REQUEST_CODE, b"\0\0")) => Err(Error::Truncated { tag: 0 }),
            (&startup_with(CANCEL_REQUEST_CODE, &[0, 0, 0, 1])) =>
                Err(Error::BadKeyLength { tag: 0, length: 0 }),
        }
        let mut long = vec![0, 0, 0, 1];
        long.extend_from_slice(&[5; 257]);
        assert_eq!(
            FrontendMessage::parse(&startup_with(CANCEL_REQUEST_CODE, &long)),
            Err(Error::BadKeyLength {
                tag: 0,
                length: 257
            })
        );
        // Parameters with no terminator, no value, bytes after it, or bad
        // text.
        let v3 = PROTOCOL_3_0;
        fictionet::assert_cases! {
            FrontendMessage::parse;
            (&startup_with(v3, b"")) => Err(Error::UnterminatedString { tag: 0 }),
            (&startup_with(v3, b"user\0")) => Err(Error::UnterminatedString { tag: 0 }),
            (&startup_with(v3, b"user\0a\0")) => Err(Error::UnterminatedString { tag: 0 }),
            (&startup_with(v3, b"user\0a\0\0x")) => Err(Error::TrailingBytes { tag: 0 }),
            (&startup_with(v3, b"user\0\xff\0\0")) => Err(Error::NotUtf8 { tag: 0 }),
        }
        assert!(FrontendMessage::parse(&startup_with(v3, b"user\0a\0\0")).is_ok());
    }

    #[test]
    fn typed_errors() {
        assert_eq!(FrontendMessage::parse(b"Z"), Err(Error::UnknownType(b'Z')));
        assert_eq!(
            FrontendMessages::established(SMALL_MESSAGE).decode(&[0], false),
            Err(FrameError::UnknownType(0))
        );
        assert_eq!(BackendMessage::parse(b"Q"), Err(Error::UnknownType(b'Q')));
        assert_eq!(
            FrontendMessage::parse(b"S\0\0\0\x03"),
            Err(Error::BadLength(3))
        );
        assert_eq!(
            BackendMessage::parse(b"Z\0\0\0\x00"),
            Err(Error::BadLength(0))
        );
        // Small messages are capped at 10000, as PostgreSQL does.
        fictionet::assert_cases! {
            FrontendMessage::parse;
            (b"S\0\0\x27\x11") => Err(Error::TooLong {
                length: 10_001,
                max: SMALL_MESSAGE,
            }),
            (b"p\0\x01\0\0") => Err(Error::TooLong {
                length: 65_536,
                max: MAX_AUTH_MESSAGE,
            }),
            (b"Q\x40\0\0\0") => Err(Error::TooLong {
                length: 0x4000_0000,
                max: MAX_MESSAGE,
            }),
        }
        assert_eq!(
            BackendMessage::parse(b"D\xff\xff\xff\xff"),
            Err(Error::TooLong {
                length: u32::MAX,
                max: MAX_MESSAGE
            })
        );
        assert_eq!(
            FrontendMessage::parse(b"Q\x3f\xff\xff\xfe"),
            Err(Error::Incomplete)
        );

        let f = |tag, body: &[u8]| FrontendMessage::parse(&typed(tag, body));
        fictionet::assert_cases! {
            f;
            (b'Q', b"abc") => Err(Error::UnterminatedString { tag: b'Q' }),
            (b'Q', b"a\0b") => Err(Error::TrailingBytes { tag: b'Q' }),
            (b'Q', b"\xc3\0") => Err(Error::NotUtf8 { tag: b'Q' }),
            (b'S', b"x") => Err(Error::TrailingBytes { tag: b'S' }),
            (b'C', b"X\0") => Err(Error::BadTarget {
                tag: b'C',
                target: b'X',
            }),
            (b'D', b"") => Err(Error::Truncated { tag: b'D' }),
            (b'E', b"\0\0\0") => Err(Error::Truncated { tag: b'E' }),
            (b'P', b"\0q\0\0\x02\0\0\0\x17") => Err(Error::Truncated { tag: b'P' }),
            // Bind: a format code of 2, a length of -2, and two formats for
            // three values.
            (b'B', b"\0\0\0\x01\0\x02\0\0\0\0") => Err(Error::BadFormat { tag: b'B', code: 2 }),
            (b'B', b"\0\0\0\0\0\x01\xff\xff\xff\xfe\0\0") => Err(Error::BadValueLength {
                tag: b'B',
                length: -2,
            }),
        }
        let mut three = b"\0\0\0\x02\0\0\0\x01\0\x03".to_vec();
        three.extend_from_slice(&[0xff; 12]);
        three.extend_from_slice(&[0, 0]);
        fictionet::assert_cases! {
            f;
            (b'B', &three) => Err(Error::FormatCount { tag: b'B' }),
            (b'B', b"\0\0\0\0\0\x01\0\0\0\x05ab\0\0") => Err(Error::Truncated { tag: b'B' }),
            (b'F', b"\0\0\0\x01\0\x02\0\0\0\0\0\0\0\0") => Err(Error::FormatCount { tag: b'F' }),
            (b'F', b"\0\0\0\x01\0\0\0\0\0\x07") => Err(Error::BadFormat { tag: b'F', code: 7 }),
        }

        let g = |tag, body: &[u8]| BackendMessage::parse(&typed(tag, body));
        fictionet::assert_cases! {
            g;
            (b'R', b"\0\0\0\x06") => Err(Error::BadAuth { tag: b'R', code: 6 }),
            (b'R', b"\0\0\0\x05ab") => Err(Error::Truncated { tag: b'R' }),
            (b'R', b"\0\0\0\x0aSCRAM\0") => Err(Error::UnterminatedString { tag: b'R' }),
            (b'R', b"\0\0\0\0x") => Err(Error::TrailingBytes { tag: b'R' }),
            (b'K', b"\0\0\0\x01") => Err(Error::BadKeyLength {
                tag: b'K',
                length: 0,
            }),
            (b'K', &[0; 261]) => Err(Error::BadKeyLength {
                tag: b'K',
                length: 257,
            }),
            (b'Z', b"") => Err(Error::Truncated { tag: b'Z' }),
            (b'G', b"\x02\0\0") => Err(Error::BadFormat { tag: b'G', code: 2 }),
            (
                b'T',
                b"\0\x01a\0\0\0\0\0\0\0\0\0\0\x17\0\x04\xff\xff\xff\xff\0\x05",
            ) => Err(Error::BadFormat { tag: b'T', code: 5 }),
            (b'E', b"SERROR\0") => Err(Error::Truncated { tag: b'E' }),
            (b'D', b"\0\x01\xff\xff\xff\xf0") => Err(Error::BadValueLength {
                tag: b'D',
                length: -16,
            }),
            (b'v', b"\0\0\0\0\0\0\0\x01") => Err(Error::UnterminatedString { tag: b'v' }),
            (b'v', b"\0\0\0\0\xff\xff\xff\xff") => Err(Error::TooManyItems { tag: b'v' }),
            (b't', b"\0\x02\0\0\0\x17") => Err(Error::Truncated { tag: b't' }),
        }
    }

    #[test]
    fn backend_key_is_at_least_4_bytes() {
        // The spec: "The minimum and maximum key length are 4 and 256
        // bytes", and libpq refuses a shorter key.
        let g = |body: &[u8]| BackendMessage::parse(&typed(b'K', body));
        assert_eq!(
            g(&[0, 0, 0, 1, 1, 2, 3]),
            Err(Error::BadKeyLength {
                tag: b'K',
                length: 3
            })
        );
        assert!(g(&[0, 0, 0, 1, 1, 2, 3, 4]).is_ok());
        assert_unwritable(&BackendMessage::BackendKeyData {
            process_id: 0,
            secret_key: vec![7],
        });
        // The server reads a cancel key of 1 to 256 bytes.
        let c = startup_with(CANCEL_REQUEST_CODE, &[0, 0, 0, 1, 9]);
        assert!(FrontendMessage::parse(&c).is_ok());
    }

    #[test]
    fn text_copy_has_text_columns() {
        // "All must be zero if the overall copy format is textual."
        let g = |body: &[u8]| BackendMessage::parse(&typed(b'G', body));
        assert_eq!(g(b"\0\0\0"), Err(Error::BadFormat { tag: b'G', code: 1 }));
        assert!(g(b"\0\0\0\0").is_ok());
        let m = BackendMessage::CopyOutResponse(CopyFormat {
            format: Format::Text,
            columns: vec![Format::Binary],
        });
        assert_unwritable(&m);
    }

    #[test]
    fn empty_database_is_the_user() {
        // PostgreSQL uses the user name when database is missing or empty,
        // and refuses an empty user name like a missing one.
        let s = Startup {
            minor_version: 0,
            params: vec![
                ("user".into(), "bob".into()),
                ("database".into(), "".into()),
            ],
        };
        assert_eq!(s.database(), Some("bob"));
        let s = Startup {
            minor_version: 0,
            params: vec![("user".into(), "".into())],
        };
        assert_eq!(s.user(), None);
        assert_eq!(s.database(), None);
    }

    #[test]
    fn each_encryption_request_comes_once() {
        for (first, second, code) in [
            (
                FrontendMessage::SslRequest,
                FrontendMessage::GssEncRequest,
                SSL_REQUEST_CODE,
            ),
            (
                FrontendMessage::GssEncRequest,
                FrontendMessage::SslRequest,
                GSSENC_REQUEST_CODE,
            ),
        ] {
            let mut input = first.to_bytes().unwrap();
            second.write(&mut input).unwrap();
            first.write(&mut input).unwrap();
            let mut stream = Stream::new(FrontendMessages::new());
            assert_eq!(stream.push(&input), input.len());
            assert_eq!(stream.next(), Some(Ok(Ok(first))));
            stream.decoder().refuse_encryption();
            assert_eq!(stream.next(), Some(Ok(Ok(second))));
            stream.decoder().refuse_encryption();
            assert_eq!(
                stream.next(),
                Some(Err(Fail::Protocol(FrameError::UnsupportedProtocol(code))))
            );
            assert_eq!(stream.next(), None);
        }
    }

    #[test]
    fn direct_tls_only_opens_a_connection() {
        let mut stream = Stream::new(FrontendMessages::new());
        let mut input = FrontendMessage::SslRequest.to_bytes().unwrap();
        input.extend_from_slice(&[0x16, 3, 1, 0, 5]);
        assert_eq!(stream.push(&input), input.len());
        assert_eq!(stream.next(), Some(Ok(Ok(FrontendMessage::SslRequest))));
        stream.decoder().refuse_encryption();
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::TooLong {
                length: 0x1603_0100,
                max: MAX_STARTUP + 4
            })))
        );
    }

    #[test]
    fn repeated_parameters_use_the_last() {
        // PostgreSQL overwrites user and database each time it meets them
        // (ProcessStartupPacket), so the last value is the one it uses.
        let s = Startup::new("alice", "shop")
            .with("user", "mallory")
            .with("database", "admin");
        assert_eq!(s.user(), Some("mallory"));
        assert_eq!(s.database(), Some("admin"));
        assert_eq!(s.get("user"), Some("mallory"));
        // An empty last database still falls back to the last user.
        let s = Startup::new("alice", "shop").with("database", "");
        assert_eq!(s.database(), Some("alice"));
        let s = Startup::new("alice", "shop").with("application_name", "psql");
        assert_eq!(s.get("application_name"), Some("psql"));
    }

    #[test]
    fn negotiate_carries_the_whole_version() {
        // The server sends FrontendProtocol, major and minor together, and
        // libpq refuses a version below PG_PROTOCOL(3, 0).
        let m = BackendMessage::NegotiateProtocolVersion {
            version: PROTOCOL_3_0,
            unrecognized: vec![],
        };
        assert_eq!(m.to_bytes().unwrap(), b"v\0\0\0\x0c\0\x03\0\0\0\0\0\0");
        let back = BackendMessage::parse(b"v\0\0\0\x0c\0\x03\0\x02\0\0\0\0").unwrap();
        assert_eq!(
            back,
            BackendMessage::NegotiateProtocolVersion {
                version: PROTOCOL_3_2,
                unrecognized: vec![]
            }
        );
    }

    #[test]
    fn accepted_encryption_ends_negotiation() {
        for (first, second, code) in [
            (
                FrontendMessage::SslRequest,
                FrontendMessage::GssEncRequest,
                GSSENC_REQUEST_CODE,
            ),
            (
                FrontendMessage::GssEncRequest,
                FrontendMessage::SslRequest,
                SSL_REQUEST_CODE,
            ),
        ] {
            let mut input = first.to_bytes().unwrap();
            input.extend_from_slice(b"injected");
            let mut stream = Stream::new(FrontendMessages::new());
            assert_eq!(stream.push(&input), input.len());
            assert_eq!(stream.next(), Some(Ok(Ok(first))));
            assert_eq!(stream.next(), None);
            let (buffer, mut decoder) = stream.into_parts();
            assert_eq!(buffer.unread(), b"injected");
            decoder.start_encryption();
            let startup = FrontendMessage::Startup(Startup::new("alice", "shop"));
            assert_eq!(
                decode_all(|| decoder.clone(), &startup.to_bytes().unwrap()),
                (vec![Ok(startup)], None)
            );
            assert_eq!(
                decoder.decode(&second.to_bytes().unwrap(), false),
                Err(FrameError::UnsupportedProtocol(code))
            );
        }
    }

    #[test]
    fn direct_tls_goes_on_in_the_same_decoder() {
        let hello = [0x16, 3, 1, 0, 5];
        let mut stream = Stream::new(FrontendMessages::new());
        assert_eq!(stream.push(&hello), hello.len());
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::DirectTls)))
        );
        let (buffer, mut decoder) = stream.into_parts();
        assert_eq!(buffer.unread(), hello);
        decoder.start_encryption();
        assert_eq!(
            decoder.clone().decode(&hello, false),
            Err(FrameError::TooLong {
                length: 0x1603_0100,
                max: MAX_STARTUP + 4
            })
        );
        let mut stream = Stream::new(decoder);
        let mut input = FrontendMessage::SslRequest.to_bytes().unwrap();
        input.extend(startup_bytes());
        assert_eq!(stream.push(&input), input.len());
        assert_eq!(stream.next(), Some(Ok(Ok(FrontendMessage::SslRequest))));
        stream.decoder().refuse_encryption();
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(FrontendMessage::Startup(_))))
        ));
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::Unwritable,
            Error::UnsupportedProtocol(0x2_0000),
            Error::UnknownType(0),
            Error::UnknownType(b'z'),
            Error::BadLength(1),
            Error::TooLong { length: 1, max: 0 },
            Error::Incomplete,
            Error::Trailing,
            Error::Truncated { tag: 0 },
            Error::TrailingBytes { tag: b'B' },
            Error::UnterminatedString { tag: b'B' },
            Error::NotUtf8 { tag: b'B' },
            Error::BadFormat { tag: b'B', code: 3 },
            Error::FormatCount { tag: b'B' },
            Error::BadValueLength {
                tag: b'B',
                length: -3,
            },
            Error::BadTarget {
                tag: b'C',
                target: b'Q',
            },
            Error::BadStatus {
                tag: b'Z',
                status: 1,
            },
            Error::BadKeyLength { tag: 0, length: 0 },
            Error::BadAuth {
                tag: b'R',
                code: 99,
            },
            Error::TooManyItems { tag: b'v' },
            Error::DuplicateField {
                tag: b'E',
                code: b'C',
            },
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
            let _: &dyn std::error::Error = &e;
        }
        assert_eq!(
            Error::UnsupportedProtocol(0x2_0000).to_string(),
            "unsupported frontend protocol 2.0"
        );
        assert_eq!(
            Error::UnknownType(b'z').to_string(),
            "invalid message type 'z'"
        );
        assert_eq!(
            Error::NotUtf8 { tag: b'B' }.to_string(),
            "invalid message 'B': a string is not UTF-8"
        );
        let frames = [
            FrameError::DirectTls,
            FrameError::UnsupportedProtocol(0x2_0000),
            FrameError::UnknownType(b'z'),
            FrameError::BadLength(1),
            FrameError::TooLong { length: 1, max: 0 },
            FrameError::Startup(Error::Truncated { tag: 0 }),
        ];
        for e in frames {
            assert!(!e.to_string().is_empty());
            let _: &dyn std::error::Error = &e;
        }
        let startup = FrameError::Startup(Error::BadKeyLength { tag: 0, length: 0 });
        assert_eq!(startup.to_string(), "malformed startup-phase message");
        assert_eq!(
            fictionet::ErrorChain(&startup).to_string(),
            "malformed startup-phase message: invalid startup packet: invalid cancel key length 0"
        );
        assert!(std::error::Error::source(&startup).is_some());
    }

    #[test]
    fn every_prefix_waits() {
        for message in all_frontend() {
            let bytes = message.to_bytes().unwrap();
            for n in 0..bytes.len() {
                let mut decoder = if message.is_startup() {
                    FrontendMessages::new()
                } else {
                    FrontendMessages::established(SMALL_MESSAGE)
                };
                assert_eq!(decoder.decode(&bytes[..n], false), Ok(Step::Need));
                assert_eq!(FrontendMessage::parse(&bytes[..n]), Err(Error::Incomplete));
            }
        }
        for message in all_backend() {
            let bytes = message.to_bytes().unwrap();
            for n in 0..bytes.len() {
                assert_eq!(
                    BackendEvents::new().decode(&bytes[..n], false),
                    Ok(Step::Need)
                );
                assert_eq!(BackendMessage::parse(&bytes[..n]), Err(Error::Incomplete));
            }
        }
    }

    #[test]
    fn decoder_follows_the_phases() {
        let mut input = FrontendMessage::SslRequest.to_bytes().unwrap();
        input.extend(startup_bytes());
        input.extend(extended_bytes());
        FrontendMessage::Terminate.write(&mut input).unwrap();
        input.extend_from_slice(b"Q\0\0\0\x05\0");
        let mut stream = Stream::new(FrontendMessages::new());
        assert_eq!(stream.push(&input), input.len());
        assert_eq!(stream.next(), Some(Ok(Ok(FrontendMessage::SslRequest))));
        assert_eq!(stream.decoder().phase(), Phase::Startup);
        stream.decoder().refuse_encryption();
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(FrontendMessage::Startup(_))))
        ));
        assert_eq!(stream.decoder().phase(), Phase::Messages);
        for message in extended_messages() {
            assert_eq!(stream.next(), Some(Ok(Ok(message))));
        }
        assert_eq!(stream.next(), Some(Ok(Ok(FrontendMessage::Terminate))));
        assert_eq!(stream.decoder().phase(), Phase::Closed);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), b"Q\0\0\0\x05\0");
        let cancel = fixture_frontend_message_cancel_request(1, vec![1; 4]);
        let mut input = cancel.to_bytes().unwrap();
        input.extend_from_slice(b"junk");
        let mut stream = Stream::new(FrontendMessages::default());
        assert_eq!(stream.push(&input), input.len());
        assert_eq!(stream.next(), Some(Ok(Ok(cancel))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), b"junk");
    }

    #[test]
    fn decoder_errors_are_returned_once() {
        for (input, expected) in [
            (
                b"Q\0\0\0\x05\0".as_slice(),
                FrameError::TooLong {
                    length: 0x5100_0000,
                    max: MAX_STARTUP + 4,
                },
            ),
            (&[0x16, 3, 1, 0, 5], FrameError::DirectTls),
        ] {
            let mut stream = Stream::new(FrontendMessages::new());
            assert_eq!(stream.push(input), input.len());
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(expected))));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.failed(), Some(&Fail::Protocol(expected)));
            assert_eq!(stream.unread(), input);
        }
        let mut input = startup_bytes();
        input.extend_from_slice(b"Q\0\0\x4e\x21");
        let (_, error) = decode_all(|| FrontendMessages::with_limit(20_000), &input);
        assert_eq!(
            error,
            Some(Fail::Protocol(FrameError::TooLong {
                length: 20_001,
                max: 20_000
            }))
        );
        let mut input = startup_bytes();
        input.push(b'?');
        assert_eq!(
            decode_all(FrontendMessages::new, &input).1,
            Some(Fail::Protocol(FrameError::UnknownType(b'?')))
        );
    }

    #[test]
    fn backend_decoder() {
        let messages = all_backend();
        let mut input = Vec::new();
        for message in &messages {
            message.write(&mut input).unwrap();
        }
        contract::check_decode_with_alloc_limit(
            BackendEvents::new,
            &input,
            2 * BackendEvents::new().capacity(),
        );
        assert_eq!(
            decode_all(BackendEvents::new, &input),
            (
                messages
                    .into_iter()
                    .map(|m| Ok(BackendEvent::Message(m)))
                    .collect(),
                None
            )
        );
        let (items, error) = decode_all(
            || BackendEvents::with_limit(10_000),
            b"D\0\0\x27\x11Z\0\0\0\x05I",
        );
        assert!(items.is_empty());
        assert_eq!(
            error,
            Some(Fail::Protocol(FrameError::TooLong {
                length: 10_001,
                max: 10_000
            }))
        );
    }

    #[test]
    fn stream_holds_at_most_its_capacity() {
        let input = vec![b'?'; 65_536];
        contract::check_decode_with_alloc_limit(
            || FrontendMessages::with_limit(10_000),
            &input,
            2 * (MAX_STARTUP + 4),
        );
        contract::check_decode_with_alloc_limit(
            || BackendEvents::with_limit(10_000),
            &input,
            2 * 10_001,
        );
    }

    #[test]
    fn interleaved_reads_preserve_the_backlog() {
        let one = BackendMessage::ParseComplete.to_bytes().unwrap();
        let input = one.repeat(100);
        let mut stream = Stream::new(BackendEvents::new());
        assert_eq!(stream.push(&input), input.len());
        for i in 1..=40 {
            assert_eq!(
                stream.next(),
                Some(Ok(Ok(BackendEvent::Message(BackendMessage::ParseComplete))))
            );
            assert_eq!(stream.push(&[]), 0);
            assert_eq!(stream.offset(), 5 * i);
        }
        assert_eq!(stream.push(&one), one.len());
        assert_eq!(stream.unread(), one.repeat(61));
    }

    #[test]
    fn malformed_body_drops_only_its_message() {
        let input = b"P\0\0\0\x09\0\0\0\0xS\0\0\0\x04S\0\0\0\x03";
        assert_eq!(
            decode_all(|| FrontendMessages::established(SMALL_MESSAGE), input),
            (
                vec![
                    Err(Error::TrailingBytes { tag: b'P' }),
                    Ok(FrontendMessage::Sync)
                ],
                Some(Fail::Protocol(FrameError::BadLength(3))),
            )
        );
        assert_eq!(
            decode_all(BackendEvents::new, b"Z\0\0\0\x05X1\0\0\0\x04"),
            (
                vec![
                    Err(Error::BadStatus {
                        tag: b'Z',
                        status: b'X'
                    }),
                    Ok(BackendEvent::Message(BackendMessage::ParseComplete))
                ],
                None,
            )
        );
        assert_eq!(
            decode_all(FrontendMessages::new, &startup_with(SSL_REQUEST_CODE, b"x")).1,
            Some(Fail::Protocol(FrameError::Startup(Error::TrailingBytes {
                tag: 0
            })))
        );
    }

    #[test]
    fn text_values_are_text() {
        // "The text format does not allow embedded nulls", and PostgreSQL
        // checks text values against the client encoding.
        let bind = |formats: &[u8], value: &[u8]| {
            let mut b = b"\0\0".to_vec();
            b.extend_from_slice(formats);
            b.extend_from_slice(&[0, 1]);
            b.extend_from_slice(&(value.len() as u32).to_be_bytes());
            b.extend_from_slice(value);
            b.extend_from_slice(&[0, 0]);
            FrontendMessage::parse(&typed(b'B', &b))
        };
        assert_eq!(bind(b"\0\0", b"a\0b"), Err(Error::NotUtf8 { tag: b'B' }));
        assert_eq!(
            bind(b"\0\x01\0\0", b"\xff"),
            Err(Error::NotUtf8 { tag: b'B' })
        );
        assert!(bind(b"\0\x01\0\x01", b"a\0\xff").is_ok());
        let call = |format: u8, value: &[u8]| {
            let mut b = vec![0, 0, 0, 1, 0, 1, 0, format, 0, 1];
            b.extend_from_slice(&(value.len() as u32).to_be_bytes());
            b.extend_from_slice(value);
            b.extend_from_slice(&[0, 0]);
            FrontendMessage::parse(&typed(b'F', &b))
        };
        assert_eq!(call(0, b"\0"), Err(Error::NotUtf8 { tag: b'F' }));
        assert!(call(1, b"\0").is_ok());
        assert_unwritable(&FrontendMessage::Bind(Bind {
            param_formats: vec![Format::Text, Format::Binary],
            params: vec![Some(b"a\0b".to_vec()), Some(b"a\0b".to_vec())],
            ..Bind::default()
        }));
        assert_unwritable(&FrontendMessage::FunctionCall(FunctionCall {
            args: vec![Some(b"ok\xc3".to_vec())],
            ..FunctionCall::default()
        }));
        let binary = FrontendMessage::Bind(Bind {
            param_formats: vec![Format::Binary],
            params: vec![Some(b"a\0\xff".to_vec())],
            ..Bind::default()
        });
        assert_eq!(
            FrontendMessage::parse(&binary.to_bytes().unwrap()),
            Ok(binary)
        );
    }

    #[test]
    fn startup_asks_for_utf8() {
        // The readers take UTF-8 text only, so a client asks for it rather
        // than taking the database's default encoding.
        assert_eq!(
            Startup::new("alice", "shop").get("client_encoding"),
            Some("UTF8")
        );
    }

    #[test]
    fn error_fields_come_once() {
        // "Any given field type should appear at most once per message."
        let g = |body: &[u8]| BackendMessage::parse(&typed(b'E', body));
        assert_eq!(
            g(b"C42P01\0C00000\0\0"),
            Err(Error::DuplicateField {
                tag: b'E',
                code: b'C'
            })
        );
        let d = Diagnostic::error(sqlstate::SYNTAX_ERROR, "x")
            .with(field_code::CODE, sqlstate::INTERNAL_ERROR);
        assert_unwritable(&BackendMessage::ErrorResponse(d));
    }

    #[test]
    fn unbounded_lists_are_capped() {
        // A million one-byte names would take far more memory than wire.
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(&1_000_000u32.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, 1_000_000));
        let m = typed(b'v', &body);
        assert_eq!(
            BackendMessage::parse(&m),
            Err(Error::TooManyItems { tag: b'v' })
        );
        let mut body = 10u32.to_be_bytes().to_vec();
        for _ in 0..=MAX_COUNT {
            body.extend_from_slice(b"a\0");
        }
        body.push(0);
        assert_eq!(
            BackendMessage::parse(&typed(b'R', &body)),
            Err(Error::TooManyItems { tag: b'R' })
        );
        let names = vec!["a".to_string(); MAX_COUNT + 5];
        assert_unwritable(&BackendMessage::NegotiateProtocolVersion {
            version: PROTOCOL_3_0,
            unrecognized: names.clone(),
        });
        assert_unwritable(&BackendMessage::Authentication(Authentication::Sasl(names)));
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        for message in [
            FrontendMessage::Startup(Startup {
                minor_version: 0,
                params: vec![("".into(), "x".into())],
            }),
            FrontendMessage::Startup(Startup::new("al\0ice", "shop")),
            FrontendMessage::Startup(Startup::default().with("a\0b", "c")),
            FrontendMessage::Startup(Startup {
                minor_version: 0,
                params: (0..2000)
                    .map(|i| (format!("p{i}"), "v".repeat(10)))
                    .collect(),
            }),
            fixture_frontend_message_cancel_request(0, vec![]),
            fixture_frontend_message_cancel_request(0, vec![1; 300]),
            FrontendMessage::Bind(Bind {
                param_formats: vec![Format::Binary, Format::Text],
                params: vec![None; 3],
                ..Bind::default()
            }),
            FrontendMessage::CopyFail("é".repeat(6000)),
            FrontendMessage::Execute {
                portal: "p".repeat(20_000),
                max_rows: 3,
            },
            FrontendMessage::Parse {
                name: "".into(),
                query: "".into(),
                param_types: vec![0; MAX_COUNT + 1],
            },
            FrontendMessage::Bind(Bind {
                result_formats: vec![Format::Text; MAX_COUNT + 1],
                ..Bind::default()
            }),
            FrontendMessage::FunctionCall(FunctionCall {
                arg_formats: vec![Format::Text; 2],
                args: vec![None; 3],
                ..FunctionCall::default()
            }),
        ] {
            assert_unwritable(&message);
        }
        for message in [
            BackendMessage::BackendKeyData {
                process_id: 0,
                secret_key: vec![],
            },
            BackendMessage::BackendKeyData {
                process_id: 0,
                secret_key: vec![0; MAX_SECRET_KEY + 1],
            },
            BackendMessage::ErrorResponse(Diagnostic {
                fields: vec![(0, "x".into()), (b'M', "m".into())],
            }),
            BackendMessage::Authentication(Authentication::Sasl(vec!["".into(), "A".into()])),
            BackendMessage::DataRow(vec![None; 70_000]),
            BackendMessage::ParameterDescription(vec![0; MAX_COUNT + 1]),
            BackendMessage::RowDescription(vec![Field::default(); MAX_COUNT + 1]),
        ] {
            assert_unwritable(&message);
        }
    }

    #[test]
    fn constructed_writes_are_transactional() {
        let mut rng = Lcg::new(7);
        for _ in 0..3000 {
            contract::check_wire_value(&random_frontend(&mut rng));
            contract::check_wire_value(&random_backend(&mut rng));
        }
    }

    #[test]
    fn random_messages_round_trip() {
        let mut rng = Lcg::new(1);
        for _ in 0..3000 {
            let message = random_frontend(&mut rng);
            contract::check_wire_value(&message);
            let bytes = message.to_bytes();
            assert_eq!(bytes.is_ok(), clean_frontend(&message), "{message:?}");
            if let Ok(bytes) = bytes {
                assert_eq!(FrontendMessage::parse(&bytes), Ok(message));
                contract::check_wire::<FrontendMessage>(&bytes);
            }
            let message = random_backend(&mut rng);
            contract::check_wire_value(&message);
            let bytes = message.to_bytes();
            assert_eq!(bytes.is_ok(), clean_backend(&message), "{message:?}");
            if let Ok(bytes) = bytes {
                assert_eq!(BackendMessage::parse(&bytes), Ok(message));
                contract::check_wire::<BackendMessage>(&bytes);
            }
        }
    }

    #[test]
    fn random_bytes_obey_contracts() {
        let mut rng = Lcg::new(42);
        let mut front = Vec::new();
        for message in all_frontend().iter().filter(|m| !m.is_startup()) {
            message.write(&mut front).unwrap();
        }
        let mut back = Vec::new();
        for message in all_backend() {
            message.write(&mut back).unwrap();
        }
        for i in 0..fictionet::stdlib::test_support::rounds(1000) {
            let mut data = match i % 3 {
                0 => rng.bytes(64),
                1 => front.clone(),
                _ => back.clone(),
            };
            mutate(&mut rng, &mut data);
            let mut startup = startup_bytes();
            startup.extend_from_slice(&data);
            let make: fn() -> FrontendMessages = || FrontendMessages::with_limit(64);
            for (make, input) in [
                (make, &data),
                (make, &startup),
                (|| FrontendMessages::established(SMALL_MESSAGE), &data),
            ] {
                contract::check_decode_with_alloc_limit(make, input, 2 * make().capacity());
                for m in decode_all(make, input).0.into_iter().flatten() {
                    let b = m.to_bytes().unwrap();
                    assert_eq!(FrontendMessage::parse(&b), Ok(m));
                    contract::check_wire::<FrontendMessage>(&b);
                }
            }
            contract::check_decode_with_alloc_limit(|| BackendEvents::with_limit(64), &data, 130);
            for item in decode_all(|| BackendEvents::with_limit(64), &data)
                .0
                .into_iter()
                .flatten()
            {
                if let BackendEvent::Message(m) = item {
                    let b = m.to_bytes().unwrap();
                    assert_eq!(BackendMessage::parse(&b), Ok(m));
                    contract::check_wire::<BackendMessage>(&b);
                }
            }
            contract::check_wire::<FrontendMessage>(&data);
            contract::check_wire::<BackendMessage>(&data);
            contract::check_wire::<Password>(&data);
            contract::check_wire::<SaslInitialResponse>(&data);
        }
    }

    #[test]
    fn large_inputs_come_out_whole() {
        let mut input = startup_bytes();
        for i in 0..3000 {
            if i == 1000 {
                input.extend_from_slice(b"P\0\0\0\x09\0\0\0\0x");
            }
            FrontendMessage::Query(format!("SELECT {i}"))
                .write(&mut input)
                .unwrap();
        }
        let make = || FrontendMessages::with_limit(SMALL_MESSAGE);
        contract::check_decode_with_alloc_limit(make, &input, 2 * make().capacity());
        let (got, failure) = decode_all(make, &input);
        assert_eq!(failure, None);
        assert_eq!(got.len(), 3002);
        assert_eq!(got[1001], Err(Error::TrailingBytes { tag: b'P' }));
        assert_eq!(got[3001], Ok(FrontendMessage::Query("SELECT 2999".into())));
        let input = BackendMessage::ParseComplete
            .to_bytes()
            .unwrap()
            .repeat(3000);
        let make = || BackendEvents::with_limit(SMALL_MESSAGE);
        contract::check_decode_with_alloc_limit(make, &input, 2 * make().capacity());
        assert_eq!(decode_all(make, &input).0.len(), 3000);
    }

    /// One of every message, in a valid form.
    fn all_frontend() -> Vec<FrontendMessage> {
        let mut all = vec![
            FrontendMessage::Startup(Startup::new("u", "d")),
            FrontendMessage::SslRequest,
            FrontendMessage::GssEncRequest,
            fixture_frontend_message_cancel_request(9, vec![1; 32]),
            FrontendMessage::Close {
                target: Target::Portal,
                name: "p".into(),
            },
            FrontendMessage::CopyData(vec![1, 2, 3]),
            FrontendMessage::CopyDone,
            FrontendMessage::CopyFail("stop".into()),
            FrontendMessage::Flush,
            FrontendMessage::FunctionCall(FunctionCall {
                function: 1,
                arg_formats: vec![Format::Binary, Format::Text],
                args: vec![Some(vec![1]), None],
                result_format: Format::Text,
            }),
            FrontendMessage::password("secret").unwrap(),
            FrontendMessage::Query("SELECT 'é'".into()),
            FrontendMessage::Terminate,
        ];
        all.extend(extended_messages());
        all
    }

    fn all_backend() -> Vec<BackendMessage> {
        let copy = CopyFormat {
            format: Format::Binary,
            columns: vec![Format::Binary],
        };
        vec![
            BackendMessage::Authentication(Authentication::Ok),
            BackendMessage::Authentication(Authentication::KerberosV5),
            BackendMessage::Authentication(Authentication::CleartextPassword),
            BackendMessage::Authentication(Authentication::Md5Password([1, 2, 3, 4])),
            BackendMessage::Authentication(Authentication::Gss),
            BackendMessage::Authentication(Authentication::GssContinue(vec![5])),
            BackendMessage::Authentication(Authentication::Sspi),
            BackendMessage::Authentication(Authentication::Sasl(vec![
                "SCRAM-SHA-256".into(),
                "SCRAM-SHA-256-PLUS".into(),
            ])),
            BackendMessage::Authentication(Authentication::SaslContinue(b"r=x".to_vec())),
            BackendMessage::Authentication(Authentication::SaslFinal(b"v=y".to_vec())),
            BackendMessage::BackendKeyData {
                process_id: 1,
                secret_key: vec![2; 4],
            },
            BackendMessage::BindComplete,
            BackendMessage::CloseComplete,
            BackendMessage::CommandComplete("INSERT 0 1".into()),
            BackendMessage::CopyData(b"a\n".to_vec()),
            BackendMessage::CopyDone,
            BackendMessage::CopyInResponse(copy.clone()),
            BackendMessage::CopyOutResponse(copy.clone()),
            BackendMessage::CopyBothResponse(copy),
            BackendMessage::DataRow(vec![Some(b"1".to_vec()), None, Some(vec![])]),
            BackendMessage::EmptyQueryResponse,
            BackendMessage::ErrorResponse(Diagnostic::error(
                sqlstate::SYNTAX_ERROR,
                "syntax error",
            )),
            BackendMessage::FunctionCallResponse(Some(vec![0, 1])),
            BackendMessage::NegotiateProtocolVersion {
                version: PROTOCOL_3_0,
                unrecognized: vec![],
            },
            BackendMessage::NoData,
            BackendMessage::NoticeResponse(Diagnostic::new(
                "WARNING",
                sqlstate::WARNING,
                "careful",
            )),
            BackendMessage::NotificationResponse {
                process_id: 3,
                channel: "jobs".into(),
                payload: "42".into(),
            },
            BackendMessage::ParameterDescription(vec![oid::TEXT, oid::INT8]),
            BackendMessage::ParameterStatus {
                name: "TimeZone".into(),
                value: "UTC".into(),
            },
            BackendMessage::ParseComplete,
            BackendMessage::PortalSuspended,
            BackendMessage::ReadyForQuery(TransactionStatus::InTransaction),
            BackendMessage::RowDescription(vec![
                Field::new("a", oid::TEXT),
                Field::new("b", oid::BOOL),
            ]),
        ]
    }

    fn assert_unwritable<M: Wire<WriteError = Error> + PartialEq + std::fmt::Debug>(value: &M) {
        contract::check_wire_value(value);
        assert_eq!(contract::check_refused(value), Error::Unwritable);
    }

    fn random_value(rng: &mut Lcg) -> Value {
        if rng.coin() {
            None
        } else {
            Some(rng.bytes(300))
        }
    }

    fn random_format(rng: &mut Lcg) -> Format {
        if rng.coin() {
            Format::Text
        } else {
            Format::Binary
        }
    }

    fn list<T>(rng: &mut Lcg, make: impl Fn(&mut Lcg) -> T) -> Vec<T> {
        (0..rng.index(5)).map(|_| make(rng)).collect()
    }

    fn clean_frontend(m: &FrontendMessage) -> bool {
        let ok = |s: &String| !s.contains('\0');
        if frontend_size(m) > m.tag().and_then(frontend_limit).unwrap_or(MAX_STARTUP + 4) {
            return false;
        }
        match m {
            FrontendMessage::Startup(s) => s
                .params
                .iter()
                .all(|(n, v)| ok(n) && ok(v) && !n.is_empty()),
            FrontendMessage::CancelRequest { secret_key, .. } => {
                (1..=MAX_SECRET_KEY).contains(&secret_key.len())
            }
            FrontendMessage::Bind(b) => {
                ok(&b.portal)
                    && ok(&b.statement)
                    && (b.param_formats.len() <= 1 || b.param_formats.len() == b.params.len())
                    && b.param_formats.len() <= MAX_COUNT
                    && b.params.len() <= MAX_COUNT
                    && b.result_formats.len() <= MAX_COUNT
                    && check_text_values(0, &b.param_formats, &b.params).is_ok()
            }
            FrontendMessage::FunctionCall(f) => {
                (f.arg_formats.len() <= 1 || f.arg_formats.len() == f.args.len())
                    && f.arg_formats.len() <= MAX_COUNT
                    && f.args.len() <= MAX_COUNT
                    && check_text_values(0, &f.arg_formats, &f.args).is_ok()
            }
            FrontendMessage::Close { name, .. } | FrontendMessage::Describe { name, .. } => {
                ok(name)
            }
            FrontendMessage::CopyFail(s)
            | FrontendMessage::Query(s)
            | FrontendMessage::Execute { portal: s, .. } => ok(s),
            FrontendMessage::Parse {
                name,
                query,
                param_types,
            } => ok(name) && ok(query) && param_types.len() <= MAX_COUNT,
            _ => true,
        }
    }

    fn clean_backend(m: &BackendMessage) -> bool {
        let ok = |s: &str| !s.contains('\0');
        if backend_size(m) > MAX_MESSAGE {
            return false;
        }
        match m {
            BackendMessage::Authentication(Authentication::Sasl(names)) => {
                names.len() <= MAX_COUNT && names.iter().all(|name| !name.is_empty() && ok(name))
            }
            BackendMessage::BackendKeyData { secret_key, .. } => {
                (MIN_BACKEND_KEY..=MAX_SECRET_KEY).contains(&secret_key.len())
            }
            BackendMessage::CommandComplete(s) => ok(s),
            BackendMessage::CopyInResponse(c)
            | BackendMessage::CopyOutResponse(c)
            | BackendMessage::CopyBothResponse(c) => {
                c.columns.len() <= MAX_COUNT
                    && (c.format == Format::Binary || c.columns.iter().all(|f| *f == Format::Text))
            }
            BackendMessage::DataRow(values) => values.len() <= MAX_COUNT,
            BackendMessage::ErrorResponse(d) | BackendMessage::NoticeResponse(d) => {
                let mut seen = [false; 256];
                d.fields.iter().all(|(code, value)| {
                    *code != 0
                        && !std::mem::replace(&mut seen[usize::from(*code)], true)
                        && ok(value)
                })
            }
            BackendMessage::NegotiateProtocolVersion { unrecognized, .. } => {
                unrecognized.len() <= MAX_COUNT && unrecognized.iter().all(|name| ok(name))
            }
            BackendMessage::NotificationResponse {
                channel, payload, ..
            } => ok(channel) && ok(payload),
            BackendMessage::ParameterDescription(types) => types.len() <= MAX_COUNT,
            BackendMessage::ParameterStatus { name, value } => ok(name) && ok(value),
            BackendMessage::RowDescription(fields) => {
                fields.len() <= MAX_COUNT && fields.iter().all(|f| ok(&f.name))
            }
            BackendMessage::Authentication(_)
            | BackendMessage::BindComplete
            | BackendMessage::CloseComplete
            | BackendMessage::CopyData(_)
            | BackendMessage::CopyDone
            | BackendMessage::EmptyQueryResponse
            | BackendMessage::FunctionCallResponse(_)
            | BackendMessage::NoData
            | BackendMessage::ParseComplete
            | BackendMessage::PortalSuspended
            | BackendMessage::ReadyForQuery(_) => true,
        }
    }

    fn random_text(rng: &mut Lcg) -> String {
        const PIECES: &[&str] = &["", "a", "hello", " ", "\0", "é", "漢"];
        (0..rng.index(40))
            .map(|_| PIECES[rng.index(PIECES.len())])
            .collect()
    }

    fn random_frontend(rng: &mut Lcg) -> FrontendMessage {
        let target = if rng.coin() {
            Target::Statement
        } else {
            Target::Portal
        };
        match rng.index(18) {
            0 => FrontendMessage::Startup(Startup {
                minor_version: rng.index(4) as u16,
                params: list(rng, |r| (random_text(r), random_text(r))),
            }),
            1 => FrontendMessage::SslRequest,
            2 => FrontendMessage::GssEncRequest,
            3 => fixture_frontend_message_cancel_request(rng.next() as u32, rng.bytes(300)),
            4 => {
                let params = list(rng, random_value);
                let param_formats = match rng.index(3) {
                    0 => vec![],
                    1 => vec![random_format(rng)],
                    _ => params.iter().map(|_| random_format(rng)).collect(),
                };
                FrontendMessage::Bind(Bind {
                    portal: random_text(rng),
                    statement: random_text(rng),
                    param_formats,
                    params,
                    result_formats: list(rng, random_format),
                })
            }
            5 => FrontendMessage::Close {
                target,
                name: random_text(rng),
            },
            6 => FrontendMessage::CopyData(rng.bytes(300)),
            7 => FrontendMessage::CopyDone,
            8 => FrontendMessage::CopyFail(random_text(rng)),
            9 => FrontendMessage::Describe {
                target,
                name: random_text(rng),
            },
            10 => FrontendMessage::Execute {
                portal: random_text(rng),
                max_rows: rng.next() as i32,
            },
            11 => FrontendMessage::Flush,
            12 => FrontendMessage::FunctionCall(FunctionCall {
                function: rng.next() as u32,
                arg_formats: list(rng, random_format),
                args: list(rng, random_value),
                result_format: random_format(rng),
            }),
            13 => FrontendMessage::AuthResponse(rng.bytes(300)),
            14 => FrontendMessage::Parse {
                name: random_text(rng),
                query: random_text(rng),
                param_types: list(rng, |r| r.next() as u32),
            },
            15 => FrontendMessage::Query(random_text(rng)),
            16 => FrontendMessage::Sync,
            _ => FrontendMessage::Terminate,
        }
    }

    fn random_backend(rng: &mut Lcg) -> BackendMessage {
        let diagnostic = |r: &mut Lcg| Diagnostic {
            fields: list(r, |r| (r.next() as u8, random_text(r))),
        };
        let copy = |r: &mut Lcg| CopyFormat {
            format: random_format(r),
            columns: list(r, random_format),
        };
        match rng.index(24) {
            0 => BackendMessage::Authentication(match rng.index(10) {
                0 => Authentication::Ok,
                1 => Authentication::KerberosV5,
                2 => Authentication::CleartextPassword,
                3 => Authentication::Md5Password([
                    rng.next() as u8,
                    rng.next() as u8,
                    rng.next() as u8,
                    rng.next() as u8,
                ]),
                4 => Authentication::Gss,
                5 => Authentication::GssContinue(rng.bytes(300)),
                6 => Authentication::Sspi,
                7 => Authentication::Sasl(list(rng, random_text)),
                8 => Authentication::SaslContinue(rng.bytes(300)),
                _ => Authentication::SaslFinal(rng.bytes(300)),
            }),
            1 => BackendMessage::BackendKeyData {
                process_id: rng.next() as u32,
                secret_key: rng.bytes(300),
            },
            2 => BackendMessage::BindComplete,
            3 => BackendMessage::CloseComplete,
            4 => BackendMessage::CommandComplete(random_text(rng)),
            5 => BackendMessage::CopyData(rng.bytes(300)),
            6 => BackendMessage::CopyDone,
            7 => BackendMessage::CopyInResponse(copy(rng)),
            8 => BackendMessage::CopyOutResponse(copy(rng)),
            9 => BackendMessage::CopyBothResponse(copy(rng)),
            10 => BackendMessage::DataRow(list(rng, random_value)),
            11 => BackendMessage::EmptyQueryResponse,
            12 => BackendMessage::ErrorResponse(diagnostic(rng)),
            13 => BackendMessage::FunctionCallResponse(random_value(rng)),
            14 => BackendMessage::NegotiateProtocolVersion {
                version: rng.next() as u32,
                unrecognized: list(rng, random_text),
            },
            15 => BackendMessage::NoData,
            16 => BackendMessage::NoticeResponse(diagnostic(rng)),
            17 => BackendMessage::NotificationResponse {
                process_id: rng.next() as u32,
                channel: random_text(rng),
                payload: random_text(rng),
            },
            18 => BackendMessage::ParameterDescription(list(rng, |r| r.next() as u32)),
            19 => BackendMessage::ParameterStatus {
                name: random_text(rng),
                value: random_text(rng),
            },
            20 => BackendMessage::ParseComplete,
            21 => BackendMessage::PortalSuspended,
            22 => BackendMessage::ReadyForQuery(match rng.index(3) {
                0 => TransactionStatus::Idle,
                1 => TransactionStatus::InTransaction,
                _ => TransactionStatus::Failed,
            }),
            _ => BackendMessage::RowDescription(list(rng, |r| Field {
                name: random_text(r),
                table_oid: r.next() as u32,
                column: r.next() as i16,
                type_oid: r.next() as u32,
                type_size: r.next() as i16,
                type_modifier: r.next() as i32,
                format: random_format(r),
            })),
        }
    }
}
