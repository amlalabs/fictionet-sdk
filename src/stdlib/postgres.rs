//! PostgreSQL: reading and writing the frontend/backend protocol, version
//! 3, with no I/O.
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
//! Nothing here reads a socket. A world that plays a database server
//! feeds the bytes it reads from a connection to a [`Decoder`], which
//! knows the startup phase, and takes [`Frontend`] messages out. It
//! answers with [`Backend`] messages, written by [`Backend::to_bytes`].
//! Which users exist, which passwords they have, and what a query returns
//! are up to world code. A world that plays a client does the reverse,
//! with a [`BackendDecoder`] and [`Frontend::to_bytes`].
//!
//! Every reader checks lengths, counts, format codes and text, because
//! the agent can send any bytes it likes. A message longer than
//! PostgreSQL itself accepts is refused as soon as its length arrives,
//! before its body comes. Text must be UTF-8, as on a connection whose
//! `client_encoding` is UTF8, which [`Startup::new`] asks for. A server
//! world that is asked for another encoding should refuse it, since
//! these readers cannot read that text. Text-format parameters must be
//! UTF-8 with no NUL byte as well. Every writer produces a message the
//! readers accept: strings and text values are cut at their first NUL
//! byte, and a message that would be too long loses items from the end
//! of its lists, or the end of its last string or byte field.
//!
//! The decoders hold at most one message's worth of bytes: `feed` says
//! how many bytes it took, and the rest is fed again once messages have
//! been taken out.
//!
//! New streams use [`FrontendMessages`] or [`BackendMessages`] with
//! [`super::codec::Stream`]. Encryption requests yield an item then End;
//! unread transport bytes remain available through `Stream::into_parts`.
//! [`Wire`] provides exact parsing and strict transactional writing for
//! both message directions. The old decoders and writers keep their behavior.
//!
//! ```
//! # #![allow(deprecated)]
//! use fictionet::stdlib::postgres::{
//!     oid, Authentication, Backend, Decoder, Field, Frontend, Startup, TransactionStatus,
//! };
//!
//! let mut decoder = Decoder::new();
//! // What psql sends: a StartupMessage, then a simple query.
//! decoder.feed(&Frontend::Startup(Startup::new("alice", "shop")).to_bytes());
//! decoder.feed(b"Q\0\0\0\x0dSELECT 1\0");
//!
//! let mut replies = Vec::new();
//! while let Some(message) = decoder.next_message() {
//!     match message.unwrap() {
//!         Frontend::Startup(startup) => {
//!             assert_eq!(startup.get("user"), Some("alice"));
//!             assert_eq!(startup.database(), Some("shop"));
//!             replies.push(Backend::Authentication(Authentication::Ok));
//!             replies.push(Backend::ParameterStatus { name: "server_version".into(), value: "16.4".into() });
//!             replies.push(Backend::BackendKeyData { process_id: 4242, secret_key: vec![1, 2, 3, 4] });
//!             replies.push(Backend::ReadyForQuery(TransactionStatus::Idle));
//!         }
//!         Frontend::Query(sql) => {
//!             assert_eq!(sql, "SELECT 1");
//!             replies.push(Backend::RowDescription(vec![Field::new("?column?", oid::INT4)]));
//!             replies.push(Backend::DataRow(vec![Some(b"1".to_vec())]));
//!             replies.push(Backend::CommandComplete("SELECT 1".into()));
//!             replies.push(Backend::ReadyForQuery(TransactionStatus::Idle));
//!         }
//!         other => panic!("unexpected {other:?}"),
//!     }
//! }
//! let bytes: Vec<u8> = replies.iter().flat_map(Backend::to_bytes).collect();
//! // AuthenticationOk: the letter R, length 8, and request code 0.
//! assert_eq!(bytes[..9], *b"R\0\0\0\x08\0\0\0\0");
//! // ReadyForQuery, idle, ends the reply.
//! assert_eq!(bytes[bytes.len() - 6..], *b"Z\0\0\0\x05I");
//! ```

use super::codec::{Decode, Step, Wire};

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
/// The largest length field a new [`Decoder`] or [`BackendDecoder`]
/// accepts: 1 MiB. Raise it with `with_max_message`.
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
    /// [`Backend::NegotiateProtocolVersion`].
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
        self.params.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The user name, or `None` if it is missing or empty. PostgreSQL
    /// refuses a StartupMessage without one.
    pub fn user(&self) -> Option<&str> {
        self.get("user").filter(|u| !u.is_empty())
    }

    /// The database: the `database` parameter, or the user name when it
    /// is missing or empty, as PostgreSQL does.
    pub fn database(&self) -> Option<&str> {
        self.get("database").filter(|d| !d.is_empty()).or_else(|| self.user())
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

impl FunctionCall {
    /// The format of argument `i`.
    pub fn arg_format(&self, i: usize) -> Format {
        format_for(&self.arg_formats, i)
    }
}

/// A message a client sends. The first four are the startup phase's,
/// which have no type byte; the rest are typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frontend {
    /// StartupMessage: opens a session.
    Startup(Startup),
    /// SSLRequest: asks to switch to TLS. The server answers with one
    /// byte, [`ACCEPT_SSL`] or [`REFUSE_ENCRYPTION`]. A server that
    /// accepts calls [`Decoder::start_encryption`]. A [`Decoder`] refuses
    /// a second SSLRequest on one connection.
    SslRequest,
    /// GSSENCRequest: asks to switch to GSSAPI encryption. The server
    /// answers with one byte, [`ACCEPT_GSSENC`] or [`REFUSE_ENCRYPTION`],
    /// and calls [`Decoder::start_encryption`] if it accepts. A
    /// [`Decoder`] refuses a second GSSENCRequest on one connection.
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
    /// [`read_password`] or [`SaslInitialResponse::parse`]; a SASLResponse
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
/// [`Frontend::AuthResponse`] body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SaslInitialResponse {
    /// The mechanism the client chose, such as `SCRAM-SHA-256`.
    pub mechanism: String,
    /// The mechanism's first message, if it has one.
    pub data: Option<Vec<u8>>,
}

impl SaslInitialResponse {
    /// Reads a SASLInitialResponse from an AuthResponse body.
    pub fn parse(body: &[u8]) -> Result<SaslInitialResponse, Malformed> {
        let mut r = Reader { b: body };
        let mechanism = r.cstr()?;
        let data = r.value()?;
        r.end()?;
        Ok(SaslInitialResponse { mechanism, data })
    }

    /// The message that carries this response. Data past what the
    /// message may hold is cut.
    pub fn to_message(&self) -> Frontend {
        let mechanism = until_nul(&self.mechanism);
        // The length field, the mechanism and its NUL, the data length.
        let room = MAX_AUTH_MESSAGE.saturating_sub(4 + 4);
        let mechanism = fit(mechanism, room.saturating_sub(1));
        let room = room.saturating_sub(mechanism.len() + 1);
        let mut out = mechanism.as_bytes().to_vec();
        out.push(0);
        match &self.data {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(d) => {
                let d = &d[..d.len().min(room)];
                out.extend_from_slice(&len32(d.len()).to_be_bytes());
                out.extend_from_slice(d);
            }
        }
        Frontend::AuthResponse(out)
    }
}

/// Reads the password in a PasswordMessage body: a string and its NUL,
/// with nothing after. With MD5 authentication the string is `md5`
/// followed by 32 hex digits.
pub fn read_password(body: &[u8]) -> Result<String, Malformed> {
    let mut r = Reader { b: body };
    let password = r.cstr()?;
    r.end()?;
    Ok(password)
}

impl Frontend {
    /// A PasswordMessage carrying `password`, cut at its first NUL and to
    /// what the message may hold.
    pub fn password(password: &str) -> Frontend {
        let p = fit(until_nul(password), MAX_AUTH_MESSAGE - 5);
        let mut body = p.as_bytes().to_vec();
        body.push(0);
        Frontend::AuthResponse(body)
    }

    /// Whether this is a startup-phase message, written with no type
    /// byte.
    pub fn is_startup(&self) -> bool {
        matches!(
            self,
            Frontend::Startup(_) | Frontend::SslRequest | Frontend::GssEncRequest | Frontend::CancelRequest { .. }
        )
    }

    /// The type byte, or `None` for a startup-phase message.
    pub fn tag(&self) -> Option<u8> {
        use frontend_tag as t;
        Some(match self {
            Frontend::Startup(_) | Frontend::SslRequest | Frontend::GssEncRequest | Frontend::CancelRequest { .. } => {
                return None;
            }
            Frontend::Bind(_) => t::BIND,
            Frontend::Close { .. } => t::CLOSE,
            Frontend::CopyData(_) => t::COPY_DATA,
            Frontend::CopyDone => t::COPY_DONE,
            Frontend::CopyFail(_) => t::COPY_FAIL,
            Frontend::Describe { .. } => t::DESCRIBE,
            Frontend::Execute { .. } => t::EXECUTE,
            Frontend::Flush => t::FLUSH,
            Frontend::FunctionCall(_) => t::FUNCTION_CALL,
            Frontend::AuthResponse(_) => t::AUTH_RESPONSE,
            Frontend::Parse { .. } => t::PARSE,
            Frontend::Query(_) => t::QUERY,
            Frontend::Sync => t::SYNC,
            Frontend::Terminate => t::TERMINATE,
        })
    }

    /// Reads the startup-phase message at the start of `b`. It returns
    /// `Ok(None)` if `b` holds only part of one, and otherwise the message
    /// and how many bytes of `b` it took.
    /// A first byte of 0x16 gives [`Error::DirectTls`].
    pub fn parse_startup(b: &[u8]) -> Result<Option<(Frontend, usize)>, Error> {
        parse_startup_from(b, true)
    }

    /// Reads the typed message at the start of `b`, after the startup
    /// phase. It returns `Ok(None)` if `b` holds only part of one, and
    /// otherwise the message and how many bytes of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Frontend, usize)>, Error> {
        Frontend::parse_max(b, MAX_MESSAGE)
    }

    fn parse_max(b: &[u8], max: usize) -> Result<Option<(Frontend, usize)>, Error> {
        let Some((tag, body, used)) = split_typed(b, frontend_limit, max)? else { return Ok(None) };
        let message = frontend_body(tag, body).map_err(|reason| Error::Malformed { tag, reason })?;
        Ok(Some((message, used)))
    }

    /// The message's bytes, with its type byte (if it has one) and
    /// length. Strings are cut at their first NUL. A message that would
    /// be longer than PostgreSQL accepts for its type loses list items
    /// from the end, or the end of its last string or byte field. A Bind
    /// or FunctionCall whose format count is not 0, 1 or the number of
    /// values gets the first format alone. A text-format parameter or
    /// argument is cut at its first NUL, and before any bytes that are not
    /// UTF-8; binary ones are written as they are. A cancel key is cut to
    /// [`MAX_SECRET_KEY`] bytes, and an empty one is written as 4 zero
    /// bytes, since PostgreSQL refuses an empty key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode(MAX_MESSAGE)
    }

    /// The message's bytes, with typed messages held to a length of `cap`.
    fn encode(&self, cap: usize) -> Vec<u8> {
        let tag = match self.tag() {
            Some(tag) => tag,
            None => return self.encode_startup(),
        };
        let limit = frontend_limit(tag).unwrap_or(SMALL_MESSAGE).min(cap);
        let mut o = Out::typed(tag, limit);
        match self {
            Frontend::Startup(_) | Frontend::SslRequest | Frontend::GssEncRequest | Frontend::CancelRequest { .. } => {}
            Frontend::Bind(b) => {
                let each = b.param_formats.len() > 1 && b.param_formats.len() == b.params.len();
                let single = !each && !b.param_formats.is_empty();
                let all: &[Format] = if each {
                    &b.param_formats
                } else if single {
                    &b.param_formats[..1]
                } else {
                    &[]
                };
                let params = written_values(all, &b.params);
                // Two NULs and three counts are always written.
                let fixed = 2 + 6 + if single { 2 } else { 0 };
                let mut avail = o.room().saturating_sub(fixed);
                let per = if each { 2 } else { 0 };
                let (np, used) = fit_count(&params, avail, |v| per + value_size(*v));
                avail -= used;
                let (nr, used_r) = fit_count(&b.result_formats, avail, |_| 2);
                let lists = fixed - 2 + used + used_r;
                o.cstr(&b.portal, 1 + lists);
                o.cstr(&b.statement, lists);
                let formats: &[Format] = if each {
                    &b.param_formats[..np]
                } else if single {
                    &b.param_formats[..1]
                } else {
                    &[]
                };
                o.formats(formats);
                o.u16(count16(np));
                for v in &params[..np] {
                    o.value(*v);
                }
                o.formats(&b.result_formats[..nr]);
            }
            Frontend::Close { target, name } | Frontend::Describe { target, name } => {
                o.u8(target.byte());
                o.cstr(name, 0);
            }
            Frontend::CopyData(d) | Frontend::AuthResponse(d) => o.bytes(d, 0),
            Frontend::CopyFail(s) | Frontend::Query(s) => o.cstr(s, 0),
            Frontend::Execute { portal, max_rows } => {
                o.cstr(portal, 4);
                o.i32(*max_rows);
            }
            Frontend::FunctionCall(f) => {
                let each = f.arg_formats.len() > 1 && f.arg_formats.len() == f.args.len();
                let single = !each && !f.arg_formats.is_empty();
                // The OID, two counts, the result format.
                o.u32(f.function);
                let fixed = 6 + if single { 2 } else { 0 };
                let per = if each { 2 } else { 0 };
                let all: &[Format] = if each {
                    &f.arg_formats
                } else if single {
                    &f.arg_formats[..1]
                } else {
                    &[]
                };
                let args = written_values(all, &f.args);
                let (na, _) = fit_count(&args, o.room().saturating_sub(fixed), |v| per + value_size(*v));
                let formats: &[Format] = if each {
                    &f.arg_formats[..na]
                } else if single {
                    &f.arg_formats[..1]
                } else {
                    &[]
                };
                o.formats(formats);
                o.u16(count16(na));
                for v in &args[..na] {
                    o.value(*v);
                }
                o.i16(f.result_format.code());
            }
            Frontend::Parse { name, query, param_types } => {
                // Two NULs and a count are always written.
                let (n, used) = fit_count(param_types, o.room().saturating_sub(4), |_| 4);
                o.cstr(name, 1 + 2 + used);
                o.cstr(query, 2 + used);
                o.u16(count16(n));
                for t in &param_types[..n] {
                    o.u32(*t);
                }
            }
            Frontend::CopyDone | Frontend::Flush | Frontend::Sync | Frontend::Terminate => {}
        }
        o.done()
    }

    fn encode_startup(&self) -> Vec<u8> {
        let mut o = Out::untagged(4 + MAX_STARTUP);
        match self {
            Frontend::Startup(s) => {
                o.u32(PROTOCOL_3_0 | u32::from(s.minor_version));
                // One byte stays for the terminator.
                let mut avail = o.room().saturating_sub(1);
                for (name, value) in &s.params {
                    let (name, value) = (until_nul(name), until_nul(value));
                    if name.is_empty() {
                        // An empty name would end the list.
                        continue;
                    }
                    let size = name.len().saturating_add(value.len()).saturating_add(2);
                    if size > avail {
                        break;
                    }
                    avail -= size;
                    o.cstr(name, 0);
                    o.cstr(value, 0);
                }
                o.u8(0);
            }
            Frontend::SslRequest => o.u32(SSL_REQUEST_CODE),
            Frontend::GssEncRequest => o.u32(GSSENC_REQUEST_CODE),
            Frontend::CancelRequest { process_id, secret_key } => {
                o.u32(CANCEL_REQUEST_CODE);
                o.u32(*process_id);
                o.put(key_bytes(secret_key));
            }
            _ => {}
        }
        o.done()
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
    /// The fields. Code 0 ends the list on the wire, so a writer leaves
    /// out a field with that code.
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
        self.fields.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_str())
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
pub enum Backend {
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

impl Backend {
    /// The type byte.
    pub fn tag(&self) -> u8 {
        use backend_tag as t;
        match self {
            Backend::Authentication(_) => t::AUTHENTICATION,
            Backend::BackendKeyData { .. } => t::BACKEND_KEY_DATA,
            Backend::BindComplete => t::BIND_COMPLETE,
            Backend::CloseComplete => t::CLOSE_COMPLETE,
            Backend::CommandComplete(_) => t::COMMAND_COMPLETE,
            Backend::CopyData(_) => t::COPY_DATA,
            Backend::CopyDone => t::COPY_DONE,
            Backend::CopyInResponse(_) => t::COPY_IN_RESPONSE,
            Backend::CopyOutResponse(_) => t::COPY_OUT_RESPONSE,
            Backend::CopyBothResponse(_) => t::COPY_BOTH_RESPONSE,
            Backend::DataRow(_) => t::DATA_ROW,
            Backend::EmptyQueryResponse => t::EMPTY_QUERY_RESPONSE,
            Backend::ErrorResponse(_) => t::ERROR_RESPONSE,
            Backend::FunctionCallResponse(_) => t::FUNCTION_CALL_RESPONSE,
            Backend::NegotiateProtocolVersion { .. } => t::NEGOTIATE_PROTOCOL_VERSION,
            Backend::NoData => t::NO_DATA,
            Backend::NoticeResponse(_) => t::NOTICE_RESPONSE,
            Backend::NotificationResponse { .. } => t::NOTIFICATION_RESPONSE,
            Backend::ParameterDescription(_) => t::PARAMETER_DESCRIPTION,
            Backend::ParameterStatus { .. } => t::PARAMETER_STATUS,
            Backend::ParseComplete => t::PARSE_COMPLETE,
            Backend::PortalSuspended => t::PORTAL_SUSPENDED,
            Backend::ReadyForQuery(_) => t::READY_FOR_QUERY,
            Backend::RowDescription(_) => t::ROW_DESCRIPTION,
        }
    }

    /// Reads the message at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the message and how many
    /// bytes of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Backend, usize)>, Error> {
        Backend::parse_max(b, MAX_MESSAGE)
    }

    fn parse_max(b: &[u8], max: usize) -> Result<Option<(Backend, usize)>, Error> {
        let Some((tag, body, used)) = split_typed(b, backend_limit, max)? else { return Ok(None) };
        let message = backend_body(tag, body).map_err(|reason| Error::Malformed { tag, reason })?;
        Ok(Some((message, used)))
    }

    /// The message's bytes. Strings are cut at their first NUL, and an
    /// error field with code 0 or an empty SASL mechanism name is left
    /// out, since either would end its list. An error field whose code
    /// came before is left out too, so [`Diagnostic::get`] reads the same
    /// field on both sides. SASL mechanisms and unrecognized options keep
    /// at most [`MAX_COUNT`] items. A message that would be
    /// longer than [`MAX_MESSAGE`] loses list items from the end, or the
    /// end of its last string or byte field. Lists with a 16-bit count
    /// keep at most [`MAX_COUNT`] items. A secret key is cut to
    /// [`MAX_SECRET_KEY`] bytes, and one shorter than [`MIN_BACKEND_KEY`]
    /// is padded with zero bytes. A copy response in text format writes
    /// every column as text.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode(MAX_MESSAGE)
    }

    /// The message's bytes, held to a length of `cap`.
    fn encode(&self, cap: usize) -> Vec<u8> {
        let mut o = Out::typed(self.tag(), MAX_MESSAGE.min(cap));
        match self {
            Backend::Authentication(a) => {
                o.u32(a.code());
                match a {
                    Authentication::Md5Password(salt) => o.put(salt),
                    Authentication::GssContinue(d) | Authentication::SaslContinue(d) | Authentication::SaslFinal(d) => {
                        o.bytes(d, 0)
                    }
                    Authentication::Sasl(names) => {
                        let mut avail = o.room().saturating_sub(1);
                        let mut n = 0;
                        for name in names {
                            let name = until_nul(name);
                            if name.is_empty() {
                                continue;
                            }
                            if name.len() + 1 > avail || n == MAX_COUNT {
                                break;
                            }
                            n += 1;
                            avail -= name.len() + 1;
                            o.cstr(name, 0);
                        }
                        o.u8(0);
                    }
                    _ => {}
                }
            }
            Backend::BackendKeyData { process_id, secret_key } => {
                o.u32(*process_id);
                let key = key_bytes(secret_key);
                o.bytes(key, 0);
                o.put(&[0; MIN_BACKEND_KEY][key.len().min(MIN_BACKEND_KEY)..]);
            }
            Backend::CommandComplete(s) => o.cstr(s, 0),
            Backend::CopyData(d) => o.bytes(d, 0),
            Backend::CopyInResponse(c) | Backend::CopyOutResponse(c) | Backend::CopyBothResponse(c) => {
                o.u8(c.format.code() as u8);
                let (n, _) = fit_count(&c.columns, o.room().saturating_sub(2), |_| 2);
                // A text copy has text columns only.
                let columns = if c.format == Format::Text { vec![Format::Text; n] } else { c.columns[..n].to_vec() };
                o.formats(&columns);
            }
            Backend::DataRow(values) => {
                let (n, _) = fit_count(values, o.room().saturating_sub(2), |v| value_size(v.as_deref()));
                o.u16(count16(n));
                for v in &values[..n] {
                    o.value(v.as_deref());
                }
            }
            Backend::ErrorResponse(d) | Backend::NoticeResponse(d) => {
                let mut avail = o.room().saturating_sub(1);
                let mut seen = [false; 256];
                for (code, value) in &d.fields {
                    if *code == 0 || seen[usize::from(*code)] {
                        continue;
                    }
                    seen[usize::from(*code)] = true;
                    let size = 1 + cstr_size(value);
                    if size > avail {
                        break;
                    }
                    avail -= size;
                    o.u8(*code);
                    o.cstr(value, 0);
                }
                o.u8(0);
            }
            Backend::FunctionCallResponse(v) => match v {
                None => o.i32(-1),
                Some(d) => {
                    let d = &d[..d.len().min(o.room().saturating_sub(4))];
                    o.u32(len32(d.len()));
                    o.put(d);
                }
            },
            Backend::NegotiateProtocolVersion { version, unrecognized } => {
                o.u32(*version);
                let mut avail = o.room().saturating_sub(4);
                let mut n = 0;
                for name in unrecognized {
                    let size = cstr_size(name);
                    if size > avail || n == MAX_COUNT {
                        break;
                    }
                    avail -= size;
                    n += 1;
                }
                o.u32(len32(n));
                for name in &unrecognized[..n] {
                    o.cstr(name, 0);
                }
            }
            Backend::NotificationResponse { process_id, channel, payload } => {
                o.u32(*process_id);
                o.cstr(channel, 1);
                o.cstr(payload, 0);
            }
            Backend::ParameterDescription(types) => {
                let (n, _) = fit_count(types, o.room().saturating_sub(2), |_| 4);
                o.u16(count16(n));
                for t in &types[..n] {
                    o.u32(*t);
                }
            }
            Backend::ParameterStatus { name, value } => {
                o.cstr(name, 1);
                o.cstr(value, 0);
            }
            Backend::ReadyForQuery(status) => o.u8(status.byte()),
            Backend::RowDescription(fields) => {
                let (n, _) = fit_count(fields, o.room().saturating_sub(2), |f| cstr_size(&f.name) + 18);
                o.u16(count16(n));
                for f in &fields[..n] {
                    o.cstr(&f.name, 0);
                    o.u32(f.table_oid);
                    o.i16(f.column);
                    o.u32(f.type_oid);
                    o.i16(f.type_size);
                    o.i32(f.type_modifier);
                    o.i16(f.format.code());
                }
            }
            Backend::BindComplete
            | Backend::CloseComplete
            | Backend::CopyDone
            | Backend::EmptyQueryResponse
            | Backend::NoData
            | Backend::ParseComplete
            | Backend::PortalSuspended => {}
        }
        o.done()
    }
}

/// Why bytes are not a message this module can read. Every one of them
/// is a protocol violation. PostgreSQL closes the connection after all of
/// them but one: a typed message whose body is malformed
/// ([`Error::is_recoverable`]) gets an ERROR, and the session goes on at
/// the next message (in an extended-query batch, at the next Sync). During
/// authentication that error is FATAL too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The connection opened with a TLS record, not a startup-phase
    /// message: the client asked for direct TLS (`sslnegotiation=direct`).
    /// A server that supports it starts TLS with the bytes
    /// [`Decoder::start_encryption`] hands back, and feeds the same
    /// decoder what TLS decrypts. As in PostgreSQL, only the first byte
    /// of a connection is read this way.
    DirectTls,
    /// A startup-phase message with a code that is neither protocol
    /// version 3 nor a known request, or a second SSLRequest or
    /// GSSENCRequest on one connection (PostgreSQL reads that as a
    /// StartupMessage of protocol 1234.5679 or 1234.5680).
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
    /// A message whose body does not match its type's layout.
    Malformed {
        /// The type byte, or 0 for a startup-phase message.
        tag: u8,
        /// What was wrong.
        reason: Malformed,
    },
}

impl Error {
    /// Whether the stream goes on after this error: true for a typed
    /// message whose length and type were sound but whose body was
    /// malformed. A [`Decoder`] or [`BackendDecoder`] drops that message
    /// and reads the next one; after any other error it reads nothing
    /// more.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Error::Malformed { tag, .. } if *tag != 0)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DirectTls => f.write_str("the connection opened with TLS, not a startup message"),
            Error::UnsupportedProtocol(code) => {
                write!(f, "unsupported frontend protocol {}.{}", code >> 16, code & 0xffff)
            }
            Error::UnknownType(t) => write!(f, "invalid message type {}", show_tag(*t)),
            Error::BadLength(n) => write!(f, "invalid message length {n}"),
            Error::TooLong { length, max } => write!(f, "message length {length} is over the limit of {max}"),
            Error::Malformed { tag: 0, reason } => write!(f, "invalid startup packet: {reason}"),
            Error::Malformed { tag, reason } => write!(f, "invalid message {}: {reason}", show_tag(*tag)),
        }
    }
}

impl std::error::Error for Error {}

/// What was wrong with a message's body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The body ended inside a field.
    Truncated,
    /// Bytes were left after the last field.
    TrailingBytes,
    /// A string had no NUL before the end of the body.
    UnterminatedString,
    /// A string was not UTF-8, or a text-format parameter or function
    /// argument was not UTF-8 text: PostgreSQL checks those against the
    /// client encoding, which counts a NUL byte as invalid.
    NotUtf8,
    /// A format code other than 0 (text) or 1 (binary), or a binary
    /// column in a copy response whose overall format is text.
    BadFormat(i16),
    /// A Bind or FunctionCall with a format count that is not 0, 1 or
    /// the number of values.
    FormatCount,
    /// A value length below -1 (which means NULL).
    BadValueLength(i32),
    /// A Close or Describe target other than `S` or `P`.
    BadTarget(u8),
    /// A ReadyForQuery status other than `I`, `T` or `E`.
    BadStatus(u8),
    /// A cancel key that is empty or longer than [`MAX_SECRET_KEY`], or a
    /// BackendKeyData key shorter than [`MIN_BACKEND_KEY`].
    BadKeyLength(usize),
    /// An Authentication request code this module does not know.
    BadAuth(u32),
    /// A list with no count of its own, or a 32-bit count, holding more
    /// than [`MAX_COUNT`] items: SASL mechanisms, error fields or
    /// unrecognized protocol options.
    TooManyItems,
    /// An error or notice field code that came twice. "Any given field
    /// type should appear at most once per message."
    DuplicateField(u8),
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Malformed::Truncated => f.write_str("the body ends inside a field"),
            Malformed::TrailingBytes => f.write_str("bytes are left after the last field"),
            Malformed::UnterminatedString => f.write_str("a string has no terminating NUL"),
            Malformed::NotUtf8 => f.write_str("a string is not UTF-8"),
            Malformed::BadFormat(c) => write!(f, "unsupported format code {c}"),
            Malformed::FormatCount => f.write_str("the format count matches neither 0, 1 nor the values"),
            Malformed::BadValueLength(n) => write!(f, "invalid value length {n}"),
            Malformed::BadTarget(b) => write!(f, "invalid target {}", show_tag(*b)),
            Malformed::BadStatus(b) => write!(f, "invalid transaction status {}", show_tag(*b)),
            Malformed::BadKeyLength(n) => write!(f, "invalid cancel key length {n}"),
            Malformed::BadAuth(c) => write!(f, "unknown authentication request {c}"),
            Malformed::TooManyItems => write!(f, "a list holds more than {MAX_COUNT} items"),
            Malformed::DuplicateField(c) => write!(f, "field {} appears twice", show_tag(*c)),
        }
    }
}

impl std::error::Error for Malformed {}

/// Why bytes do not contain exactly one PostgreSQL wire message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A message header or body was refused.
    Message(Error),
    /// The input ends before the message is complete.
    Truncated,
    /// Bytes follow the message.
    Trailing,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Message(e) => e.fmt(f),
            Self::Truncated => f.write_str("PostgreSQL message ended early"),
            Self::Trailing => f.write_str("bytes follow the PostgreSQL message"),
        }
    }
}
impl core::error::Error for ParseError {}

/// A message cannot be written without clipping or changing its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteError;

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PostgreSQL message cannot be represented without changing it")
    }
}
impl core::error::Error for WriteError {}

impl Wire for Frontend {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one startup or typed message under the module limits.
    /// Startup lengths begin with zero; typed messages begin with a tag.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let parsed = if bytes.first() == Some(&0) { Self::parse_startup(bytes) } else { Self::parse(bytes) };
        match parsed.map_err(ParseError::Message)? {
            Some((message, used)) if used == bytes.len() => Ok(message),
            Some(_) => Err(ParseError::Trailing),
            None => Err(ParseError::Truncated),
        }
    }

    /// Appends a strict encoding. Temporary bytes are bounded by
    /// `MAX_MESSAGE + 1` and temporary value lists by [`MAX_COUNT`].
    /// The legacy [`Frontend::to_bytes`] keeps its clipping behavior.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        // The legacy writer stages a borrowed list for these two variants.
        // Bound that list before entering it, then check its complete result.
        match self {
            Self::Bind(b) if b.params.len() > MAX_COUNT => return Err(WriteError),
            Self::FunctionCall(f) if f.args.len() > MAX_COUNT => return Err(WriteError),
            _ => {}
        }
        let bytes = self.to_bytes();
        if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
            return Err(WriteError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Backend {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one typed message under [`MAX_MESSAGE`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        match Self::parse(bytes).map_err(ParseError::Message)? {
            Some((message, used)) if used == bytes.len() => Ok(message),
            Some(_) => Err(ParseError::Trailing),
            None => Err(ParseError::Truncated),
        }
    }

    /// Appends a strict encoding, staging at most `MAX_MESSAGE + 1` bytes.
    /// Refusal leaves `out` unchanged. The legacy writer still clips.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.to_bytes();
        if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
            return Err(WriteError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads frontend startup and typed messages without retaining input.
///
/// Items are `Result<Frontend, Error>`. A malformed complete body is an
/// error item. Invalid framing, unsupported protocols, repeated encryption
/// requests, and over-limit lengths end the stream. Partial messages return
/// [`Step::Need`], so [`super::codec::Stream`] reports truncation at EOF.
///
/// A StartupMessage selects typed messages after its item. SSLRequest and
/// GSSENCRequest each yield an item followed by [`Step::End`]. Call
/// [`super::codec::Stream::into_parts`] and give its unread bytes to TLS or GSS,
/// then call [`start_encryption`](Self::start_encryption) on the returned
/// decoder and use a new stream for decrypted bytes. A direct ClientHello
/// returns [`Error::DirectTls`] without consuming any bytes; the same
/// transfer applies. CancelRequest and Terminate also yield an item then End.
///
/// To answer `N`, call [`refuse_encryption`](Self::refuse_encryption)
/// between the request item and the next poll. If End was already polled,
/// clone the decoder, refuse on that clone, and use [`super::codec::Stream::swap`].
/// Keep any unaccepted part of a pushed slice for the next transport.
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

    /// Starts at typed messages, for an already established session.
    pub fn typed(limit: usize) -> Self {
        Self { phase: Phase::Messages, started: true, ..Self::with_limit(limit) }
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
    /// Call on the decoder returned by [`super::codec::Stream::into_parts`].
    /// After a negotiated upgrade, further SSL and GSS requests are refused.
    /// Direct TLS retains the initial negotiation policy of the old API.
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
    type Item = Result<Frontend, Error>;
    type Error = Error;
    const NAME: &'static str = "PostgreSQL frontend";

    fn capacity(&self) -> usize {
        (MAX_STARTUP + 4).max(self.limit + 1)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.handoff || self.phase == Phase::Closed {
            return Ok(Step::End);
        }
        let (message, used) = if self.phase == Phase::Startup {
            let Some((body, used)) = split_startup(input, !self.started)? else { return Ok(Step::Need) };
            (startup_body(body), used)
        } else {
            let Some((tag, body, used)) = split_typed(input, frontend_limit, self.limit)? else {
                return Ok(Step::Need);
            };
            (frontend_body(tag, body).map_err(|reason| Error::Malformed { tag, reason }), used)
        };
        match &message {
            Ok(Frontend::SslRequest) => {
                if self.ssl_seen {
                    return Err(Error::UnsupportedProtocol(SSL_REQUEST_CODE));
                }
                self.ssl_seen = true;
                self.handoff = true;
            }
            Ok(Frontend::GssEncRequest) => {
                if self.gss_seen {
                    return Err(Error::UnsupportedProtocol(GSSENC_REQUEST_CODE));
                }
                self.gss_seen = true;
                self.handoff = true;
            }
            Ok(Frontend::Startup(_)) => self.phase = Phase::Messages,
            Ok(Frontend::CancelRequest { .. } | Frontend::Terminate) => self.phase = Phase::Closed,
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
    type ParseError = ParseError;
    type WriteError = core::convert::Infallible;

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        match bytes {
            [ACCEPT_SSL] => Ok(Self::Ssl),
            [ACCEPT_GSSENC] => Ok(Self::Gss),
            [REFUSE_ENCRYPTION] => Ok(Self::Refused),
            [] => Err(ParseError::Truncated),
            [byte] => Err(ParseError::Message(Error::UnknownType(*byte))),
            _ => Err(ParseError::Trailing),
        }
    }

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
    Message(Backend),
}

/// Reads backend messages and optional one-byte encryption responses.
///
/// Malformed complete bodies are error items. Framing errors end the
/// stream. Partial messages return [`Step::Need`], including at EOF.
/// Call [`expect_encryption`](Self::expect_encryption) before the response
/// to an SSLRequest or GSSENCRequest. An `S` or `G` item is followed by
/// [`Step::End`]; unread bytes go to the next transport through
/// [`super::codec::Stream::into_parts`]. Use a new decoder for decrypted messages.
/// An `N` item resumes typed messages. World code may request another
/// negotiation response between items if it sends another request.
#[derive(Clone, Debug)]
pub struct BackendMessages {
    limit: usize,
    encryption: bool,
    handoff: bool,
}

impl BackendMessages {
    /// Reads typed messages up to [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_MESSAGE)
    }

    /// Sets the maximum length field, clamped to 4 through [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(4, MAX_MESSAGE), encryption: false, handoff: false }
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

impl Default for BackendMessages {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for BackendMessages {
    type Item = Result<BackendEvent, Error>;
    type Error = Error;
    const NAME: &'static str = "PostgreSQL backend";

    fn capacity(&self) -> usize {
        self.limit + 1
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.handoff {
            return Ok(Step::End);
        }
        if self.encryption {
            let Some(&byte) = input.first() else { return Ok(Step::Need) };
            let reply = match byte {
                ACCEPT_SSL => EncryptionReply::Ssl,
                ACCEPT_GSSENC => EncryptionReply::Gss,
                REFUSE_ENCRYPTION => EncryptionReply::Refused,
                _ => return Err(Error::UnknownType(byte)),
            };
            self.encryption = false;
            self.handoff = reply != EncryptionReply::Refused;
            return Ok(Step::Item(Ok(BackendEvent::Encryption(reply)), 1));
        }
        let Some((tag, body, used)) = split_typed(input, backend_limit, self.limit)? else {
            return Ok(Step::Need);
        };
        let message =
            backend_body(tag, body).map(BackendEvent::Message).map_err(|reason| Error::Malformed { tag, reason });
        Ok(Step::Item(message, used))
    }
}

/// Where a [`Decoder`] is in a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Before the StartupMessage: messages have no type byte.
    Startup,
    /// After the StartupMessage: every message is typed.
    Messages,
    /// After a CancelRequest or a Terminate. No more messages come, and
    /// bytes fed are dropped.
    Closed,
}

/// Splits the bytes a client sends into [`Frontend`] messages, for a
/// world that plays a server. It starts in the startup phase and moves
/// on after the StartupMessage. Feed it the bytes a connection reads, in
/// order, and take messages out until it has none.
///
/// After an SSLRequest the decoder stays in the startup phase. A server
/// that accepts calls [`Decoder::start_encryption`] and goes on to feed
/// it the bytes TLS decrypts. A second SSLRequest, or a second
/// GSSENCRequest, is refused, as PostgreSQL does.
#[derive(Clone, Debug)]
#[deprecated(note = "use codec::Stream with postgres::FrontendMessages")]
pub struct Decoder {
    buf: Vec<u8>,
    pos: usize,
    phase: Phase,
    max: usize,
    failed: Option<Error>,
    /// Whether a message has been taken out, after which a TLS record
    /// is no longer looked for.
    started: bool,
    ssl_seen: bool,
    gss_seen: bool,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Decoder {
    /// A decoder in the startup phase, holding no bytes, that accepts
    /// messages up to [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> Decoder {
        Decoder {
            buf: Vec::new(),
            pos: 0,
            phase: Phase::Startup,
            max: DEFAULT_MAX_MESSAGE,
            failed: None,
            started: false,
            ssl_seen: false,
            gss_seen: false,
        }
    }

    /// This decoder, accepting typed messages whose length field is up to
    /// `max`. It is held between [`SMALL_MESSAGE`] and [`MAX_MESSAGE`],
    /// and a message type's own limit still applies.
    pub fn with_max_message(mut self, max: usize) -> Decoder {
        self.max = max.clamp(SMALL_MESSAGE, MAX_MESSAGE);
        self
    }

    /// Adds bytes read from the connection and returns how many it took.
    /// It holds at most [`Decoder::capacity`] bytes, so it may take fewer
    /// than it is given. Take messages out with
    /// [`Decoder::next_message`], then feed it the rest; once it is full,
    /// `next_message` always gives a message or an error. After an error
    /// that ends the stream, or once the connection is
    /// [`Phase::Closed`], every byte is taken and dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() || self.phase == Phase::Closed {
            return bytes.len();
        }
        let n = bytes.len().min(self.capacity().saturating_sub(self.buffered()));
        if n > 0 {
            compact(&mut self.buf, &mut self.pos);
            self.buf.extend_from_slice(&bytes[..n]);
        }
        n
    }

    /// The most bytes the decoder holds: its largest message and its
    /// header. A whole message always fits.
    pub fn capacity(&self) -> usize {
        self.max + 5
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes or the connection is closed. A typed message
    /// whose body is malformed gives an error that
    /// [`Error::is_recoverable`] and is dropped, and the next message
    /// follows, as in PostgreSQL. Any other error ends the stream, and
    /// the decoder keeps returning it.
    pub fn next_message(&mut self) -> Option<Result<Frontend, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        let parsed = match self.phase {
            Phase::Startup => parse_startup_from(rest, !self.started),
            Phase::Messages => match split_typed(rest, frontend_limit, self.max) {
                Ok(Some((tag, body, used))) => match frontend_body(tag, body) {
                    Ok(message) => Ok(Some((message, used))),
                    Err(reason) => {
                        self.pos += used;
                        return Some(Err(Error::Malformed { tag, reason }));
                    }
                },
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            },
            Phase::Closed => return None,
        };
        let parsed = match parsed {
            Ok(Some((Frontend::SslRequest, _))) if self.ssl_seen => Err(Error::UnsupportedProtocol(SSL_REQUEST_CODE)),
            Ok(Some((Frontend::GssEncRequest, _))) if self.gss_seen => {
                Err(Error::UnsupportedProtocol(GSSENC_REQUEST_CODE))
            }
            other => other,
        };
        match parsed {
            Ok(Some((message, used))) => {
                self.pos += used;
                self.started = true;
                match message {
                    Frontend::SslRequest => self.ssl_seen = true,
                    Frontend::GssEncRequest => self.gss_seen = true,
                    Frontend::Startup(_) => self.phase = Phase::Messages,
                    Frontend::CancelRequest { .. } | Frontend::Terminate => {
                        self.phase = Phase::Closed;
                        self.buf = Vec::new();
                        self.pos = 0;
                    }
                    _ => {}
                }
                Some(Ok(message))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                // A ClientHello stays for TLS to read; nothing else is
                // read again.
                if e != Error::DirectTls {
                    self.buf = Vec::new();
                    self.pos = 0;
                }
                Some(Err(e))
            }
        }
    }

    /// Where the connection is.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// How many bytes are held, waiting for the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Switches to the decrypted stream, once the server has accepted an
    /// SSLRequest or a GSSENCRequest, or has taken up [`Error::DirectTls`].
    /// It returns the bytes held, which came before encryption. After a
    /// request they were sent in the clear, and PostgreSQL refuses the
    /// connection if there are any. After [`Error::DirectTls`] they are
    /// the TLS ClientHello, and the error is cleared.
    ///
    /// After an accepted request, the decoder refuses another SSLRequest
    /// or GSSENCRequest, as PostgreSQL does. Inside direct TLS it still
    /// gives them out, and PostgreSQL answers both with
    /// [`REFUSE_ENCRYPTION`]. After the startup phase, or after any other
    /// error, this does nothing and returns no bytes.
    #[deprecated(note = "use codec::Stream::into_parts and FrontendMessages::start_encryption")]
    pub fn start_encryption(&mut self) -> Vec<u8> {
        match (self.failed, self.phase) {
            (Some(Error::DirectTls), _) => {
                self.failed = None;
                self.started = true;
            }
            (None, Phase::Startup) if self.started => {
                self.ssl_seen = true;
                self.gss_seen = true;
            }
            _ => return Vec::new(),
        }
        self.take_buffered()
    }

    /// Takes out the bytes held that no message has used.
    #[deprecated(note = "use codec::Stream::into_parts after FrontendMessages returns End")]
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let mut rest = std::mem::take(&mut self.buf);
        rest.drain(..self.pos.min(rest.len()));
        self.pos = 0;
        rest
    }
}

/// Splits the bytes a server sends into [`Backend`] messages, for a world
/// that plays a client. Every backend message is typed. The one byte a
/// server answers an SSLRequest with comes before any of them, and the
/// caller reads it itself.
#[derive(Clone, Debug)]
#[deprecated(note = "use codec::Stream with postgres::BackendMessages")]
pub struct BackendDecoder {
    buf: Vec<u8>,
    pos: usize,
    max: usize,
    failed: Option<Error>,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Default for BackendDecoder {
    fn default() -> BackendDecoder {
        BackendDecoder::new()
    }
}

#[allow(deprecated)] // Preserve the compatibility API.
impl BackendDecoder {
    /// A decoder holding no bytes, that accepts messages up to
    /// [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> BackendDecoder {
        BackendDecoder { buf: Vec::new(), pos: 0, max: DEFAULT_MAX_MESSAGE, failed: None }
    }

    /// This decoder, accepting messages whose length field is up to
    /// `max`, held between [`SMALL_MESSAGE`] and [`MAX_MESSAGE`].
    pub fn with_max_message(mut self, max: usize) -> BackendDecoder {
        self.max = max.clamp(SMALL_MESSAGE, MAX_MESSAGE);
        self
    }

    /// Adds bytes read from the connection and returns how many it took.
    /// It holds at most [`BackendDecoder::capacity`] bytes, so it may take
    /// fewer than it is given. Take messages out with
    /// [`BackendDecoder::next_message`], then feed it the rest; once it is
    /// full, `next_message` always gives a message or an error. After an
    /// error that ends the stream, every byte is taken and dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        let n = bytes.len().min(self.capacity().saturating_sub(self.buffered()));
        if n > 0 {
            compact(&mut self.buf, &mut self.pos);
            self.buf.extend_from_slice(&bytes[..n]);
        }
        n
    }

    /// The most bytes the decoder holds: its largest message and its
    /// header. A whole message always fits.
    pub fn capacity(&self) -> usize {
        self.max + 5
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes. A message whose body is malformed gives an error
    /// that [`Error::is_recoverable`] and is dropped, and the next message
    /// follows, as libpq does. Any other error ends the stream, and the
    /// decoder keeps returning it.
    pub fn next_message(&mut self) -> Option<Result<Backend, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let rest = self.buf.get(self.pos..).unwrap_or(&[]);
        match split_typed(rest, backend_limit, self.max) {
            Ok(Some((tag, body, used))) => {
                let parsed = backend_body(tag, body);
                self.pos += used;
                Some(parsed.map_err(|reason| Error::Malformed { tag, reason }))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.pos = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Drops the bytes before `pos` once they are at least as many as the
/// bytes after it, so each byte read is moved at most once on average.
fn compact(buf: &mut Vec<u8>, pos: &mut usize) {
    if *pos > 0 && *pos >= buf.len() - *pos {
        buf.drain(..*pos);
        *pos = 0;
    }
}

/// The largest length field each frontend type may have, or `None` for a
/// byte that is not a frontend type. These are PostgreSQL's own limits.
fn frontend_limit(tag: u8) -> Option<usize> {
    use frontend_tag as t;
    match tag {
        t::BIND | t::COPY_DATA | t::FUNCTION_CALL | t::PARSE | t::QUERY => Some(MAX_MESSAGE),
        t::AUTH_RESPONSE => Some(MAX_AUTH_MESSAGE),
        t::CLOSE | t::COPY_DONE | t::COPY_FAIL | t::DESCRIBE | t::EXECUTE | t::FLUSH | t::SYNC | t::TERMINATE => {
            Some(SMALL_MESSAGE)
        }
        _ => None,
    }
}

/// The largest length field each backend type may have, or `None` for a
/// byte that is not a backend type.
fn backend_limit(tag: u8) -> Option<usize> {
    match tag {
        b'R' | b'K' | b'2' | b'3' | b'C' | b'd' | b'c' | b'G' | b'H' | b'W' | b'D' | b'I' | b'E' | b'V' | b'v'
        | b'n' | b'N' | b'A' | b't' | b'S' | b'1' | b's' | b'Z' | b'T' => Some(MAX_MESSAGE),
        _ => None,
    }
}

/// A typed message split from the stream: its type byte, its body, and
/// how many bytes of the stream it took.
type Typed<'a> = (u8, &'a [u8], usize);

/// The type byte, body and total size of the typed message at the start
/// of `b`, if it has all come. Each check runs as soon as the bytes it
/// needs are there, so an error never depends on how the stream was cut.
fn split_typed(b: &[u8], limit: fn(u8) -> Option<usize>, max: usize) -> Result<Option<Typed<'_>>, Error> {
    let Some(&tag) = b.first() else { return Ok(None) };
    let limit = limit(tag).ok_or(Error::UnknownType(tag))?.min(max);
    if b.len() < 5 {
        return Ok(None);
    }
    let length = be32(b, 1);
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

/// Reads a startup-phase message, looking for a TLS record first when
/// `tls` is set: at the opening of a connection.
fn parse_startup_from(b: &[u8], tls: bool) -> Result<Option<(Frontend, usize)>, Error> {
    let Some((body, used)) = split_startup(b, tls)? else { return Ok(None) };
    Ok(Some((startup_body(body)?, used)))
}

/// The body (after the length) and total size of the startup-phase
/// message at the start of `b`, if it has all come.
fn split_startup(b: &[u8], tls: bool) -> Result<Option<(&[u8], usize)>, Error> {
    // A TLS handshake record starts with 22. No startup length can, since
    // it would be far over the limit.
    if tls && b.first() == Some(&0x16) {
        return Err(Error::DirectTls);
    }
    if b.len() < 4 {
        return Ok(None);
    }
    let length = be32(b, 0);
    if length < 8 {
        return Err(Error::BadLength(length));
    }
    let size = usize::try_from(length).unwrap_or(usize::MAX);
    if size - 4 > MAX_STARTUP {
        return Err(Error::TooLong { length, max: MAX_STARTUP + 4 });
    }
    if b.len() >= 8 {
        let code = be32(b, 4);
        let known = matches!(code, SSL_REQUEST_CODE | GSSENC_REQUEST_CODE | CANCEL_REQUEST_CODE) || code >> 16 == 3;
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
fn startup_body(body: &[u8]) -> Result<Frontend, Error> {
    let bad = |reason| Error::Malformed { tag: 0, reason };
    let mut r = Reader { b: body };
    let code = r.u32().map_err(bad)?;
    let message = match code {
        SSL_REQUEST_CODE => Frontend::SslRequest,
        GSSENC_REQUEST_CODE => Frontend::GssEncRequest,
        CANCEL_REQUEST_CODE => {
            let process_id = r.u32().map_err(bad)?;
            let key = r.rest();
            if key.is_empty() || key.len() > MAX_SECRET_KEY {
                return Err(bad(Malformed::BadKeyLength(key.len())));
            }
            Frontend::CancelRequest { process_id, secret_key: key.to_vec() }
        }
        _ => {
            let mut params = Vec::new();
            loop {
                let name = r.cstr().map_err(bad)?;
                if name.is_empty() {
                    break;
                }
                let value = r.cstr().map_err(bad)?;
                params.push((name, value));
            }
            Frontend::Startup(Startup { minor_version: code as u16, params })
        }
    };
    r.end().map_err(bad)?;
    Ok(message)
}

/// Reads a typed frontend body. `tag` is a known frontend type.
fn frontend_body(tag: u8, body: &[u8]) -> Result<Frontend, Malformed> {
    use frontend_tag as t;
    let mut r = Reader { b: body };
    let message = match tag {
        t::BIND => {
            let portal = r.cstr()?;
            let statement = r.cstr()?;
            let param_formats = r.formats()?;
            let params = r.values()?;
            let result_formats = r.formats()?;
            check_format_count(param_formats.len(), params.len())?;
            check_text_values(&param_formats, &params)?;
            Frontend::Bind(Bind { portal, statement, param_formats, params, result_formats })
        }
        t::CLOSE => {
            let target = r.target()?;
            Frontend::Close { target, name: r.cstr()? }
        }
        t::COPY_DATA => Frontend::CopyData(r.rest().to_vec()),
        t::COPY_DONE => Frontend::CopyDone,
        t::COPY_FAIL => Frontend::CopyFail(r.cstr()?),
        t::DESCRIBE => {
            let target = r.target()?;
            Frontend::Describe { target, name: r.cstr()? }
        }
        t::EXECUTE => {
            let portal = r.cstr()?;
            Frontend::Execute { portal, max_rows: r.i32()? }
        }
        t::FLUSH => Frontend::Flush,
        t::FUNCTION_CALL => {
            let function = r.u32()?;
            let arg_formats = r.formats()?;
            let args = r.values()?;
            let result_format = r.format()?;
            check_format_count(arg_formats.len(), args.len())?;
            check_text_values(&arg_formats, &args)?;
            Frontend::FunctionCall(FunctionCall { function, arg_formats, args, result_format })
        }
        t::AUTH_RESPONSE => Frontend::AuthResponse(r.rest().to_vec()),
        t::PARSE => {
            let name = r.cstr()?;
            let query = r.cstr()?;
            let n = r.u16()?;
            let mut param_types = Vec::new();
            for _ in 0..n {
                param_types.push(r.u32()?);
            }
            Frontend::Parse { name, query, param_types }
        }
        t::QUERY => Frontend::Query(r.cstr()?),
        t::SYNC => Frontend::Sync,
        _ => Frontend::Terminate,
    };
    r.end()?;
    Ok(message)
}

/// Reads a backend body. `tag` is a known backend type.
fn backend_body(tag: u8, body: &[u8]) -> Result<Backend, Malformed> {
    use backend_tag as t;
    let mut r = Reader { b: body };
    let message = match tag {
        t::AUTHENTICATION => {
            let code = r.u32()?;
            Backend::Authentication(match code {
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
                            return Err(Malformed::TooManyItems);
                        }
                        names.push(name);
                    }
                    Authentication::Sasl(names)
                }
                11 => Authentication::SaslContinue(r.rest().to_vec()),
                12 => Authentication::SaslFinal(r.rest().to_vec()),
                c => return Err(Malformed::BadAuth(c)),
            })
        }
        t::BACKEND_KEY_DATA => {
            let process_id = r.u32()?;
            let key = r.rest();
            if key.len() < MIN_BACKEND_KEY || key.len() > MAX_SECRET_KEY {
                return Err(Malformed::BadKeyLength(key.len()));
            }
            Backend::BackendKeyData { process_id, secret_key: key.to_vec() }
        }
        t::BIND_COMPLETE => Backend::BindComplete,
        t::CLOSE_COMPLETE => Backend::CloseComplete,
        t::COMMAND_COMPLETE => Backend::CommandComplete(r.cstr()?),
        t::COPY_DATA => Backend::CopyData(r.rest().to_vec()),
        t::COPY_DONE => Backend::CopyDone,
        t::COPY_IN_RESPONSE | t::COPY_OUT_RESPONSE | t::COPY_BOTH_RESPONSE => {
            let overall = r.u8()?;
            let format = Format::from_code(i16::from(overall)).ok_or(Malformed::BadFormat(i16::from(overall)))?;
            let columns = r.formats()?;
            if format == Format::Text && columns.contains(&Format::Binary) {
                return Err(Malformed::BadFormat(1));
            }
            let c = CopyFormat { format, columns };
            match tag {
                t::COPY_IN_RESPONSE => Backend::CopyInResponse(c),
                t::COPY_OUT_RESPONSE => Backend::CopyOutResponse(c),
                _ => Backend::CopyBothResponse(c),
            }
        }
        t::DATA_ROW => Backend::DataRow(r.values()?),
        t::EMPTY_QUERY_RESPONSE => Backend::EmptyQueryResponse,
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
                    return Err(Malformed::DuplicateField(code));
                }
                fields.push((code, r.cstr()?));
            }
            let d = Diagnostic { fields };
            if tag == t::ERROR_RESPONSE { Backend::ErrorResponse(d) } else { Backend::NoticeResponse(d) }
        }
        t::FUNCTION_CALL_RESPONSE => Backend::FunctionCallResponse(r.value()?),
        t::NEGOTIATE_PROTOCOL_VERSION => {
            let version = r.u32()?;
            let n = r.u32()?;
            // Each name takes one byte on the wire and far more in memory,
            // so the count is held to the cap.
            if usize::try_from(n).map_or(true, |n| n > MAX_COUNT) {
                return Err(Malformed::TooManyItems);
            }
            let mut unrecognized = Vec::new();
            for _ in 0..n {
                unrecognized.push(r.cstr()?);
            }
            Backend::NegotiateProtocolVersion { version, unrecognized }
        }
        t::NO_DATA => Backend::NoData,
        t::NOTIFICATION_RESPONSE => {
            let process_id = r.u32()?;
            let channel = r.cstr()?;
            Backend::NotificationResponse { process_id, channel, payload: r.cstr()? }
        }
        t::PARAMETER_DESCRIPTION => {
            let n = r.u16()?;
            let mut types = Vec::new();
            for _ in 0..n {
                types.push(r.u32()?);
            }
            Backend::ParameterDescription(types)
        }
        t::PARAMETER_STATUS => {
            let name = r.cstr()?;
            Backend::ParameterStatus { name, value: r.cstr()? }
        }
        t::PARSE_COMPLETE => Backend::ParseComplete,
        t::PORTAL_SUSPENDED => Backend::PortalSuspended,
        t::READY_FOR_QUERY => {
            let b = r.u8()?;
            Backend::ReadyForQuery(TransactionStatus::from_byte(b).ok_or(Malformed::BadStatus(b))?)
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
            Backend::RowDescription(fields)
        }
    };
    r.end()?;
    Ok(message)
}

/// PostgreSQL's rule for format lists: none, one for all, or one each.
fn check_format_count(formats: usize, values: usize) -> Result<(), Malformed> {
    if formats <= 1 || formats == values { Ok(()) } else { Err(Malformed::FormatCount) }
}

/// Refuses a text-format value that is not UTF-8 text with no NUL.
fn check_text_values(formats: &[Format], values: &[Value]) -> Result<(), Malformed> {
    for (i, v) in values.iter().enumerate() {
        if let Some(b) = v
            && format_for(formats, i) == Format::Text
            && text_value(b).len() != b.len()
        {
            return Err(Malformed::NotUtf8);
        }
    }
    Ok(())
}

/// A text-format value as it may be written: cut at its first NUL, and
/// before the first bytes that are not UTF-8.
fn text_value(b: &[u8]) -> &[u8] {
    let b = b.iter().position(|&c| c == 0).map_or(b, |i| &b[..i]);
    match std::str::from_utf8(b) {
        Ok(_) => b,
        Err(e) => &b[..e.valid_up_to()],
    }
}

/// The values of a Bind or FunctionCall as written, under the format
/// list that is written: text values go through [`text_value`].
fn written_values<'a>(formats: &[Format], values: &'a [Value]) -> Vec<Option<&'a [u8]>> {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_deref().map(|b| if format_for(formats, i) == Format::Text { text_value(b) } else { b })
        })
        .collect()
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
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.b.len() < n {
            return Err(Malformed::Truncated);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Malformed> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i16(&mut self) -> Result<i16, Malformed> {
        Ok(self.u16()? as i16)
    }

    fn u32(&mut self) -> Result<u32, Malformed> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32, Malformed> {
        Ok(self.u32()? as i32)
    }

    fn cstr(&mut self) -> Result<String, Malformed> {
        let end = self.b.iter().position(|&c| c == 0).ok_or(Malformed::UnterminatedString)?;
        let s = std::str::from_utf8(&self.b[..end]).map_err(|_| Malformed::NotUtf8)?;
        self.b = &self.b[end + 1..];
        Ok(s.to_owned())
    }

    fn format(&mut self) -> Result<Format, Malformed> {
        let c = self.i16()?;
        Format::from_code(c).ok_or(Malformed::BadFormat(c))
    }

    /// A 16-bit count, then that many format codes.
    fn formats(&mut self) -> Result<Vec<Format>, Malformed> {
        let n = self.u16()?;
        (0..n).map(|_| self.format()).collect()
    }

    fn target(&mut self) -> Result<Target, Malformed> {
        let b = self.u8()?;
        Target::from_byte(b).ok_or(Malformed::BadTarget(b))
    }

    /// A 32-bit length (-1 for NULL), then that many bytes.
    fn value(&mut self) -> Result<Value, Malformed> {
        let n = self.i32()?;
        match n {
            -1 => Ok(None),
            n if n < 0 => Err(Malformed::BadValueLength(n)),
            n => Ok(Some(self.take(n as usize)?.to_vec())),
        }
    }

    /// A 16-bit count, then that many values. Each value takes at least
    /// 4 bytes, so the body bounds the list.
    fn values(&mut self) -> Result<Vec<Value>, Malformed> {
        let n = self.u16()?;
        (0..n).map(|_| self.value()).collect()
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }

    fn end(&self) -> Result<(), Malformed> {
        if self.b.is_empty() { Ok(()) } else { Err(Malformed::TrailingBytes) }
    }
}

/// Builds one message, never past `end` bytes in all when the caller
/// reserves what later fields need.
struct Out {
    buf: Vec<u8>,
    end: usize,
    len_at: usize,
}

impl Out {
    /// A typed message whose length field may be up to `limit`.
    fn typed(tag: u8, limit: usize) -> Out {
        Out { buf: vec![tag, 0, 0, 0, 0], end: limit.saturating_add(1), len_at: 1 }
    }

    /// A startup-phase message whose length field may be up to `limit`.
    fn untagged(limit: usize) -> Out {
        Out { buf: vec![0, 0, 0, 0], end: limit, len_at: 0 }
    }

    /// The bytes left before the limit.
    fn room(&self) -> usize {
        self.end.saturating_sub(self.buf.len())
    }

    fn put(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }

    fn i16(&mut self, v: i16) {
        self.put(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.put(&v.to_be_bytes());
    }

    fn i32(&mut self, v: i32) {
        self.put(&v.to_be_bytes());
    }

    /// `s` up to its first NUL, cut to leave `reserve` bytes free, and a
    /// NUL.
    fn cstr(&mut self, s: &str, reserve: usize) {
        let s = fit(until_nul(s), self.room().saturating_sub(reserve).saturating_sub(1));
        self.put(s.as_bytes());
        self.buf.push(0);
    }

    /// `b`, cut to leave `reserve` bytes free.
    fn bytes(&mut self, b: &[u8], reserve: usize) {
        let n = b.len().min(self.room().saturating_sub(reserve));
        self.put(&b[..n]);
    }

    /// A 16-bit count and the format codes. The caller has checked that
    /// they fit.
    fn formats(&mut self, formats: &[Format]) {
        self.u16(count16(formats.len()));
        for f in formats {
            self.i16(f.code());
        }
    }

    /// A value's length (or -1) and bytes. The caller has checked that it
    /// fits.
    fn value(&mut self, v: Option<&[u8]>) {
        match v {
            None => self.i32(-1),
            Some(b) => {
                self.u32(len32(b.len()));
                self.put(b);
            }
        }
    }

    /// The message, with its length field filled in.
    fn done(mut self) -> Vec<u8> {
        let len = len32(self.buf.len() - self.len_at);
        self.buf[self.len_at..self.len_at + 4].copy_from_slice(&len.to_be_bytes());
        self.buf
    }
}

/// How many of `items`, from the first, fit in `avail` bytes, at most
/// [`MAX_COUNT`], and the bytes they take.
fn fit_count<T>(items: &[T], avail: usize, size: impl Fn(&T) -> usize) -> (usize, usize) {
    let mut used = 0usize;
    let mut n = 0;
    for item in items.iter().take(MAX_COUNT) {
        match used.checked_add(size(item)) {
            Some(u) if u <= avail => {
                used = u;
                n += 1;
            }
            _ => break,
        }
    }
    (n, used)
}

/// The bytes a value takes: its length field and its bytes.
fn value_size(v: Option<&[u8]>) -> usize {
    4usize.saturating_add(v.map_or(0, <[u8]>::len))
}

/// The bytes a string takes: up to its first NUL, and a NUL.
fn cstr_size(s: &str) -> usize {
    until_nul(s).len() + 1
}

/// `s` up to its first NUL.
fn until_nul(s: &str) -> &str {
    s.find('\0').map_or(s, |i| &s[..i])
}

/// `s`, cut to at most `max` bytes on a character boundary.
fn fit(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// The cancel key as written: at most [`MAX_SECRET_KEY`] bytes, and 4
/// zero bytes in place of an empty key.
fn key_bytes(key: &[u8]) -> &[u8] {
    if key.is_empty() { &[0; 4] } else { &key[..key.len().min(MAX_SECRET_KEY)] }
}

/// A count the writers have already held to [`MAX_COUNT`].
fn count16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// A length the writers have already held to [`MAX_MESSAGE`].
fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// A type byte for a message: the letter in quotes, or its number.
fn show_tag(t: u8) -> String {
    if t.is_ascii_graphic() { format!("'{}'", t as char) } else { format!("0x{t:02x}") }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the legacy API.
mod tests {
    use super::*;

    #[test]
    fn all_message_variants_obey_wire_contract() {
        use crate::stdlib::codec::contract;
        for message in all_frontend() {
            contract::check_wire_value(&message);
            let bytes = Wire::to_bytes(&message).unwrap();
            contract::check_wire::<Frontend>(&bytes);
        }
        for message in all_backend() {
            contract::check_wire_value(&message);
            let bytes = Wire::to_bytes(&message).unwrap();
            contract::check_wire::<Backend>(&bytes);
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
        let (m, used) = Frontend::parse_startup(&bytes).unwrap().unwrap();
        assert_eq!(used, 55);
        assert_eq!(m, Frontend::Startup(Startup::new("alice", "shop")));
        assert_eq!(m.to_bytes(), bytes);
        let Frontend::Startup(s) = m else { panic!() };
        assert_eq!(s.user(), Some("alice"));
        // With no database parameter, the database is the user's name.
        let s = Startup { minor_version: 2, params: vec![("user".into(), "bob".into())] };
        assert_eq!(s.database(), Some("bob"));
        let bytes = Frontend::Startup(s.clone()).to_bytes();
        assert_eq!(&bytes[4..8], &PROTOCOL_3_2.to_be_bytes());
        assert_eq!(Frontend::parse_startup(&bytes).unwrap().unwrap().0, Frontend::Startup(s));
        // No parameters at all is the terminator alone.
        let empty = Frontend::Startup(Startup::default()).to_bytes();
        assert_eq!(empty, [0, 0, 0, 9, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn encryption_and_cancel_requests() {
        let ssl = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        assert_eq!(Frontend::parse_startup(&ssl), Ok(Some((Frontend::SslRequest, 8))));
        assert_eq!(Frontend::SslRequest.to_bytes(), ssl);
        let gss = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30];
        assert_eq!(Frontend::parse_startup(&gss), Ok(Some((Frontend::GssEncRequest, 8))));
        assert_eq!(Frontend::GssEncRequest.to_bytes(), gss);
        let cancel = [0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x10, 0x92, 1, 2, 3, 4];
        let m = Frontend::CancelRequest { process_id: 4242, secret_key: vec![1, 2, 3, 4] };
        assert_eq!(Frontend::parse_startup(&cancel), Ok(Some((m.clone(), 16))));
        assert_eq!(m.to_bytes(), cancel);
        // A protocol 3.2 key of 32 bytes.
        let long = Frontend::CancelRequest { process_id: 1, secret_key: vec![9; 32] };
        assert_eq!(Frontend::parse_startup(&long.to_bytes()).unwrap().unwrap().0, long);
        assert!(m.is_startup() && m.tag().is_none());
    }

    #[test]
    fn simple_query_replies() {
        assert_eq!(Frontend::parse(b"Q\0\0\0\x0dSELECT 1\0"), Ok(Some((Frontend::Query("SELECT 1".into()), 14))));
        let cases: Vec<(Backend, &[u8])> = vec![
            (Backend::Authentication(Authentication::Ok), b"R\0\0\0\x08\0\0\0\0"),
            (Backend::Authentication(Authentication::CleartextPassword), b"R\0\0\0\x08\0\0\0\x03"),
            (Backend::Authentication(Authentication::Md5Password(*b"salt")), b"R\0\0\0\x0c\0\0\0\x05salt"),
            (
                Backend::Authentication(Authentication::Sasl(vec!["SCRAM-SHA-256".into()])),
                b"R\0\0\0\x17\0\0\0\x0aSCRAM-SHA-256\0\0",
            ),
            (Backend::Authentication(Authentication::SaslFinal(b"v=xyz".to_vec())), b"R\0\0\0\x0d\0\0\0\x0cv=xyz"),
            (
                Backend::ParameterStatus { name: "client_encoding".into(), value: "UTF8".into() },
                b"S\0\0\0\x19client_encoding\0UTF8\0",
            ),
            (
                Backend::BackendKeyData { process_id: 7, secret_key: vec![0, 0, 0, 9] },
                b"K\0\0\0\x0c\0\0\0\x07\0\0\0\x09",
            ),
            (Backend::ReadyForQuery(TransactionStatus::Idle), b"Z\0\0\0\x05I"),
            (Backend::ReadyForQuery(TransactionStatus::Failed), b"Z\0\0\0\x05E"),
            (Backend::CommandComplete("SELECT 1".into()), b"C\0\0\0\x0dSELECT 1\0"),
            (Backend::EmptyQueryResponse, b"I\0\0\0\x04"),
            (Backend::ParseComplete, b"1\0\0\0\x04"),
            (Backend::BindComplete, b"2\0\0\0\x04"),
            (Backend::CloseComplete, b"3\0\0\0\x04"),
            (Backend::NoData, b"n\0\0\0\x04"),
            (Backend::PortalSuspended, b"s\0\0\0\x04"),
            (Backend::CopyDone, b"c\0\0\0\x04"),
            (
                Backend::DataRow(vec![Some(b"42".to_vec()), None]),
                b"D\0\0\0\x10\0\x02\0\0\0\x02\x34\x32\xff\xff\xff\xff",
            ),
            (Backend::ParameterDescription(vec![oid::INT4]), b"t\0\0\0\x0a\0\x01\0\0\0\x17"),
            (
                Backend::CopyOutResponse(CopyFormat { format: Format::Text, columns: vec![Format::Text; 2] }),
                b"H\0\0\0\x0b\0\0\x02\0\0\0\0",
            ),
            (Backend::FunctionCallResponse(None), b"V\0\0\0\x08\xff\xff\xff\xff"),
            (
                Backend::NotificationResponse { process_id: 1, channel: "c".into(), payload: "".into() },
                b"A\0\0\0\x0b\0\0\0\x01c\0\0",
            ),
            (
                Backend::NegotiateProtocolVersion { version: PROTOCOL_3_0, unrecognized: vec!["_pq_.x".into()] },
                b"v\0\0\0\x13\0\x03\0\0\0\0\0\x01_pq_.x\0",
            ),
        ];
        for (message, bytes) in cases {
            assert_eq!(message.to_bytes(), bytes, "{message:?}");
            assert_eq!(Backend::parse(bytes), Ok(Some((message, bytes.len()))));
        }
    }

    #[test]
    fn row_description_layout() {
        let field = Field::new("id", oid::INT4);
        let bytes = Backend::RowDescription(vec![field.clone()]).to_bytes();
        let mut want = b"T\0\0\0\x1b\0\x01id\0".to_vec();
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xff, 0xff, 0xff, 0xff, 0, 0]);
        assert_eq!(bytes, want);
        assert_eq!(Backend::parse(&bytes).unwrap().unwrap().0, Backend::RowDescription(vec![field]));
        assert_eq!(Field::new("t", oid::TEXT).type_size, -1);
    }

    #[test]
    fn error_response_layout() {
        let d = Diagnostic::error(sqlstate::UNDEFINED_TABLE, "relation \"x\" does not exist")
            .with(field_code::POSITION, "15");
        let bytes = Backend::ErrorResponse(d.clone()).to_bytes();
        let mut body = b"SERROR\0VERROR\0C42P01\0Mrelation \"x\" does not exist\0P15\0\0".to_vec();
        let mut want = vec![b'E'];
        want.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
        want.append(&mut body);
        assert_eq!(bytes, want);
        let (back, _) = Backend::parse(&bytes).unwrap().unwrap();
        assert_eq!(back, Backend::ErrorResponse(d.clone()));
        assert_eq!(d.get(field_code::CODE), Some("42P01"));
        assert_eq!(d.get(field_code::HINT), None);
        let notice = Backend::NoticeResponse(Diagnostic::new("NOTICE", sqlstate::SUCCESSFUL_COMPLETION, "hi"));
        assert_eq!(Backend::parse(&notice.to_bytes()).unwrap().unwrap().0, notice);
        assert_eq!(Diagnostic::fatal(sqlstate::INVALID_PASSWORD, "no").get(field_code::SEVERITY), Some("FATAL"));
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

    fn extended_messages() -> Vec<Frontend> {
        vec![
            Frontend::Parse { name: "".into(), query: "SELECT $1".into(), param_types: vec![oid::INT4] },
            Frontend::Bind(Bind {
                params: vec![Some(b"5".to_vec())],
                result_formats: vec![Format::Binary],
                ..Bind::default()
            }),
            Frontend::Describe { target: Target::Portal, name: "".into() },
            Frontend::Execute { portal: "".into(), max_rows: 0 },
            Frontend::Sync,
        ]
    }

    #[test]
    fn extended_query() {
        let bytes = extended_bytes();
        let mut at = 0;
        let mut got = Vec::new();
        while let Some((m, used)) = Frontend::parse(&bytes[at..]).unwrap() {
            got.push(m);
            at += used;
        }
        assert_eq!(at, bytes.len());
        assert_eq!(got, extended_messages());
        let written: Vec<u8> = got.iter().flat_map(Frontend::to_bytes).collect();
        assert_eq!(written, bytes);
        let Frontend::Bind(b) = &got[1] else { panic!() };
        assert_eq!(b.param_format(0), Format::Text);
        assert_eq!(b.result_format(3), Format::Binary);
    }

    #[test]
    fn other_frontend_messages() {
        let cases: Vec<(Frontend, &[u8])> = vec![
            (Frontend::Close { target: Target::Statement, name: "s1".into() }, b"C\0\0\0\x08Ss1\0"),
            (Frontend::CopyData(b"1\tx\n".to_vec()), b"d\0\0\0\x081\tx\n"),
            (Frontend::CopyDone, b"c\0\0\0\x04"),
            (Frontend::CopyFail("no".into()), b"f\0\0\0\x07no\0"),
            (Frontend::Flush, b"H\0\0\0\x04"),
            (Frontend::Terminate, b"X\0\0\0\x04"),
            (Frontend::password("pw"), b"p\0\0\0\x07pw\0"),
            (
                Frontend::FunctionCall(FunctionCall {
                    function: 1598,
                    arg_formats: vec![],
                    args: vec![None],
                    result_format: Format::Binary,
                }),
                b"F\0\0\0\x12\0\0\x06\x3e\0\0\0\x01\xff\xff\xff\xff\0\x01",
            ),
        ];
        for (message, bytes) in cases {
            assert_eq!(message.to_bytes(), bytes, "{message:?}");
            assert_eq!(Frontend::parse(bytes), Ok(Some((message, bytes.len()))));
        }
    }

    #[test]
    fn auth_responses() {
        let Frontend::AuthResponse(body) = Frontend::password("md5abc") else { panic!() };
        assert_eq!(read_password(&body), Ok("md5abc".into()));
        assert_eq!(read_password(b"pw"), Err(Malformed::UnterminatedString));
        assert_eq!(read_password(b"pw\0x"), Err(Malformed::TrailingBytes));
        let sasl = SaslInitialResponse { mechanism: "SCRAM-SHA-256".into(), data: Some(b"n,,n=,r=abc".to_vec()) };
        let Frontend::AuthResponse(body) = sasl.to_message() else { panic!() };
        assert_eq!(&body[..14], b"SCRAM-SHA-256\0");
        assert_eq!(&body[14..18], &[0, 0, 0, 11]);
        assert_eq!(SaslInitialResponse::parse(&body), Ok(sasl));
        let none = SaslInitialResponse { mechanism: "X".into(), data: None };
        let Frontend::AuthResponse(body) = none.to_message() else { panic!() };
        assert_eq!(body, b"X\0\xff\xff\xff\xff");
        assert_eq!(SaslInitialResponse::parse(&body), Ok(none));
        assert_eq!(SaslInitialResponse::parse(b"X\0\0\0\0\x05ab"), Err(Malformed::Truncated));
        assert_eq!(SaslInitialResponse::parse(b"X\0\xff\xff\xff\xfe"), Err(Malformed::BadValueLength(-2)));
        // Writers cut what does not fit in an auth message.
        let big = SaslInitialResponse { mechanism: "M".into(), data: Some(vec![7; 100_000]) };
        let m = big.to_message();
        let bytes = m.to_bytes();
        assert!(bytes.len() - 1 <= MAX_AUTH_MESSAGE);
        let Frontend::AuthResponse(body) = Frontend::parse(&bytes).unwrap().unwrap().0 else { panic!() };
        assert!(SaslInitialResponse::parse(&body).is_ok());
        let p = Frontend::password(&"é".repeat(40_000)).to_bytes();
        let Frontend::AuthResponse(body) = Frontend::parse(&p).unwrap().unwrap().0 else { panic!() };
        assert!(read_password(&body).is_ok());
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

    fn bad(tag: u8, reason: Malformed) -> Error {
        Error::Malformed { tag, reason }
    }

    #[test]
    fn startup_errors() {
        // A TLS ClientHello, known from its first byte.
        assert_eq!(Frontend::parse_startup(&[0x16]), Err(Error::DirectTls));
        assert_eq!(Frontend::parse_startup(&[0, 0, 0, 7]), Err(Error::BadLength(7)));
        assert_eq!(
            Frontend::parse_startup(&[0, 0, 0x27, 0x15]),
            Err(Error::TooLong { length: 10_005, max: MAX_STARTUP + 4 })
        );
        assert!(Frontend::parse_startup(&[0, 0, 0x27, 0x14]).unwrap().is_none());
        // Protocol 2.0, refused as soon as its version arrives.
        assert_eq!(Frontend::parse_startup(&[0, 0, 0, 9, 0, 2, 0, 0]), Err(Error::UnsupportedProtocol(0x2_0000)));
        assert_eq!(
            Frontend::parse_startup(&startup_with(0x04d2_0000, b"\0")),
            Err(Error::UnsupportedProtocol(0x04d2_0000))
        );
        // Requests with bytes they should not have.
        assert_eq!(
            Frontend::parse_startup(&startup_with(SSL_REQUEST_CODE, b"x")),
            Err(bad(0, Malformed::TrailingBytes))
        );
        assert_eq!(
            Frontend::parse_startup(&startup_with(GSSENC_REQUEST_CODE, b"x")),
            Err(bad(0, Malformed::TrailingBytes))
        );
        assert_eq!(
            Frontend::parse_startup(&startup_with(CANCEL_REQUEST_CODE, b"\0\0")),
            Err(bad(0, Malformed::Truncated))
        );
        assert_eq!(
            Frontend::parse_startup(&startup_with(CANCEL_REQUEST_CODE, &[0, 0, 0, 1])),
            Err(bad(0, Malformed::BadKeyLength(0)))
        );
        let mut long = vec![0, 0, 0, 1];
        long.extend_from_slice(&[5; 257]);
        assert_eq!(
            Frontend::parse_startup(&startup_with(CANCEL_REQUEST_CODE, &long)),
            Err(bad(0, Malformed::BadKeyLength(257)))
        );
        // Parameters with no terminator, no value, bytes after it, or bad
        // text.
        let v3 = PROTOCOL_3_0;
        assert_eq!(Frontend::parse_startup(&startup_with(v3, b"")), Err(bad(0, Malformed::UnterminatedString)));
        assert_eq!(Frontend::parse_startup(&startup_with(v3, b"user\0")), Err(bad(0, Malformed::UnterminatedString)));
        assert_eq!(
            Frontend::parse_startup(&startup_with(v3, b"user\0a\0")),
            Err(bad(0, Malformed::UnterminatedString))
        );
        assert_eq!(Frontend::parse_startup(&startup_with(v3, b"user\0a\0\0x")), Err(bad(0, Malformed::TrailingBytes)));
        assert_eq!(Frontend::parse_startup(&startup_with(v3, b"user\0\xff\0\0")), Err(bad(0, Malformed::NotUtf8)));
        assert!(Frontend::parse_startup(&startup_with(v3, b"user\0a\0\0")).is_ok());
    }

    #[test]
    fn typed_errors() {
        assert_eq!(Frontend::parse(b"Z"), Err(Error::UnknownType(b'Z')));
        assert_eq!(Frontend::parse(&[0]), Err(Error::UnknownType(0)));
        assert_eq!(Backend::parse(b"Q"), Err(Error::UnknownType(b'Q')));
        assert_eq!(Frontend::parse(b"S\0\0\0\x03"), Err(Error::BadLength(3)));
        assert_eq!(Backend::parse(b"Z\0\0\0\x00"), Err(Error::BadLength(0)));
        // Small messages are capped at 10000, as PostgreSQL does.
        assert_eq!(Frontend::parse(b"S\0\0\x27\x11"), Err(Error::TooLong { length: 10_001, max: SMALL_MESSAGE }));
        assert_eq!(Frontend::parse(b"p\0\x01\0\0"), Err(Error::TooLong { length: 65_536, max: MAX_AUTH_MESSAGE }));
        assert_eq!(Frontend::parse(b"Q\x40\0\0\0"), Err(Error::TooLong { length: 0x4000_0000, max: MAX_MESSAGE }));
        assert_eq!(Backend::parse(b"D\xff\xff\xff\xff"), Err(Error::TooLong { length: u32::MAX, max: MAX_MESSAGE }));
        assert!(Frontend::parse(b"Q\x3f\xff\xff\xfe").unwrap().is_none());

        let f = |tag, body: &[u8]| Frontend::parse(&typed(tag, body));
        let m = bad;
        assert_eq!(f(b'Q', b"abc"), Err(m(b'Q', Malformed::UnterminatedString)));
        assert_eq!(f(b'Q', b"a\0b"), Err(m(b'Q', Malformed::TrailingBytes)));
        assert_eq!(f(b'Q', b"\xc3\0"), Err(m(b'Q', Malformed::NotUtf8)));
        assert_eq!(f(b'S', b"x"), Err(m(b'S', Malformed::TrailingBytes)));
        assert_eq!(f(b'C', b"X\0"), Err(m(b'C', Malformed::BadTarget(b'X'))));
        assert_eq!(f(b'D', b""), Err(m(b'D', Malformed::Truncated)));
        assert_eq!(f(b'E', b"\0\0\0"), Err(m(b'E', Malformed::Truncated)));
        assert_eq!(f(b'P', b"\0q\0\0\x02\0\0\0\x17"), Err(m(b'P', Malformed::Truncated)));
        // Bind: a format code of 2, a length of -2, and two formats for
        // three values.
        assert_eq!(f(b'B', b"\0\0\0\x01\0\x02\0\0\0\0"), Err(m(b'B', Malformed::BadFormat(2))));
        assert_eq!(f(b'B', b"\0\0\0\0\0\x01\xff\xff\xff\xfe\0\0"), Err(m(b'B', Malformed::BadValueLength(-2))));
        let mut three = b"\0\0\0\x02\0\0\0\x01\0\x03".to_vec();
        three.extend_from_slice(&[0xff; 12]);
        three.extend_from_slice(&[0, 0]);
        assert_eq!(f(b'B', &three), Err(m(b'B', Malformed::FormatCount)));
        assert_eq!(f(b'B', b"\0\0\0\0\0\x01\0\0\0\x05ab\0\0"), Err(m(b'B', Malformed::Truncated)));
        assert_eq!(f(b'F', b"\0\0\0\x01\0\x02\0\0\0\0\0\0\0\0"), Err(m(b'F', Malformed::FormatCount)));
        assert_eq!(f(b'F', b"\0\0\0\x01\0\0\0\0\0\x07"), Err(m(b'F', Malformed::BadFormat(7))));

        let g = |tag, body: &[u8]| Backend::parse(&typed(tag, body));
        assert_eq!(g(b'R', b"\0\0\0\x06"), Err(m(b'R', Malformed::BadAuth(6))));
        assert_eq!(g(b'R', b"\0\0\0\x05ab"), Err(m(b'R', Malformed::Truncated)));
        assert_eq!(g(b'R', b"\0\0\0\x0aSCRAM\0"), Err(m(b'R', Malformed::UnterminatedString)));
        assert_eq!(g(b'R', b"\0\0\0\0x"), Err(m(b'R', Malformed::TrailingBytes)));
        assert_eq!(g(b'K', b"\0\0\0\x01"), Err(m(b'K', Malformed::BadKeyLength(0))));
        assert_eq!(g(b'K', &[0; 261]), Err(m(b'K', Malformed::BadKeyLength(257))));
        assert_eq!(g(b'Z', b"X"), Err(m(b'Z', Malformed::BadStatus(b'X'))));
        assert_eq!(g(b'Z', b""), Err(m(b'Z', Malformed::Truncated)));
        assert_eq!(g(b'G', b"\x02\0\0"), Err(m(b'G', Malformed::BadFormat(2))));
        assert_eq!(
            g(b'T', b"\0\x01a\0\0\0\0\0\0\0\0\0\0\x17\0\x04\xff\xff\xff\xff\0\x05"),
            Err(m(b'T', Malformed::BadFormat(5)))
        );
        assert_eq!(g(b'E', b"SERROR\0"), Err(m(b'E', Malformed::Truncated)));
        assert_eq!(g(b'D', b"\0\x01\xff\xff\xff\xf0"), Err(m(b'D', Malformed::BadValueLength(-16))));
        assert_eq!(g(b'v', b"\0\0\0\0\0\0\0\x01"), Err(m(b'v', Malformed::UnterminatedString)));
        assert_eq!(g(b'v', b"\0\0\0\0\xff\xff\xff\xff"), Err(m(b'v', Malformed::TooManyItems)));
        assert_eq!(g(b't', b"\0\x02\0\0\0\x17"), Err(m(b't', Malformed::Truncated)));
    }

    #[test]
    fn backend_key_is_at_least_4_bytes() {
        // The spec: "The minimum and maximum key length are 4 and 256
        // bytes", and libpq refuses a shorter key.
        let g = |body: &[u8]| Backend::parse(&typed(b'K', body));
        assert_eq!(g(&[0, 0, 0, 1, 1, 2, 3]), Err(bad(b'K', Malformed::BadKeyLength(3))));
        assert!(g(&[0, 0, 0, 1, 1, 2, 3, 4]).is_ok());
        // A writer pads a short key with zeros.
        let b = Backend::BackendKeyData { process_id: 0, secret_key: vec![7] }.to_bytes();
        assert_eq!(
            Backend::parse(&b).unwrap().unwrap().0,
            Backend::BackendKeyData { process_id: 0, secret_key: vec![7, 0, 0, 0] }
        );
        // The server reads a cancel key of 1 to 256 bytes.
        let c = startup_with(CANCEL_REQUEST_CODE, &[0, 0, 0, 1, 9]);
        assert!(Frontend::parse_startup(&c).unwrap().is_some());
    }

    #[test]
    fn text_copy_has_text_columns() {
        // "All must be zero if the overall copy format is textual."
        let g = |body: &[u8]| Backend::parse(&typed(b'G', body));
        assert_eq!(g(b"   "), Err(bad(b'G', Malformed::BadFormat(1))));
        assert!(g(b"    ").is_ok());
        let m = Backend::CopyOutResponse(CopyFormat { format: Format::Text, columns: vec![Format::Binary] });
        assert_eq!(
            Backend::parse(&m.to_bytes()).unwrap().unwrap().0,
            Backend::CopyOutResponse(CopyFormat { format: Format::Text, columns: vec![Format::Text] })
        );
    }

    #[test]
    fn empty_database_is_the_user() {
        // PostgreSQL uses the user name when database is missing or empty,
        // and refuses an empty user name like a missing one.
        let s =
            Startup { minor_version: 0, params: vec![("user".into(), "bob".into()), ("database".into(), "".into())] };
        assert_eq!(s.database(), Some("bob"));
        let s = Startup { minor_version: 0, params: vec![("user".into(), "".into())] };
        assert_eq!(s.user(), None);
        assert_eq!(s.database(), None);
    }

    #[test]
    fn each_encryption_request_comes_once() {
        // PostgreSQL reads a second SSLRequest (or GSSENCRequest) as a
        // StartupMessage of protocol 1234.5679, which it refuses.
        let mut d = Decoder::new();
        d.feed(&Frontend::SslRequest.to_bytes());
        d.feed(&Frontend::GssEncRequest.to_bytes());
        d.feed(&Frontend::SslRequest.to_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::SslRequest)));
        assert_eq!(d.next_message(), Some(Ok(Frontend::GssEncRequest)));
        assert_eq!(d.next_message(), Some(Err(Error::UnsupportedProtocol(SSL_REQUEST_CODE))));
        let mut d = Decoder::new();
        d.feed(&Frontend::GssEncRequest.to_bytes());
        d.feed(&Frontend::GssEncRequest.to_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::GssEncRequest)));
        assert_eq!(d.next_message(), Some(Err(Error::UnsupportedProtocol(GSSENC_REQUEST_CODE))));
    }

    #[test]
    fn direct_tls_only_opens_a_connection() {
        // PostgreSQL looks for a TLS record only at the first byte of a
        // connection. Later, 0x16 starts a length far over the limit.
        let mut d = Decoder::new();
        d.feed(&Frontend::SslRequest.to_bytes());
        d.feed(&[0x16, 3, 1, 0, 5]);
        assert_eq!(d.next_message(), Some(Ok(Frontend::SslRequest)));
        assert_eq!(d.next_message(), Some(Err(Error::TooLong { length: 0x1603_0100, max: MAX_STARTUP + 4 })));
    }

    #[test]
    fn repeated_parameters_use_the_last() {
        // PostgreSQL overwrites user and database each time it meets them
        // (ProcessStartupPacket), so the last value is the one it uses.
        let s = Startup::new("alice", "shop").with("user", "mallory").with("database", "admin");
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
        let m = Backend::NegotiateProtocolVersion { version: PROTOCOL_3_0, unrecognized: vec![] };
        assert_eq!(m.to_bytes(), b"v\0\0\0\x0c\0\x03\0\0\0\0\0\0");
        let (back, _) = Backend::parse(b"v\0\0\0\x0c\0\x03\0\x02\0\0\0\0").unwrap().unwrap();
        assert_eq!(back, Backend::NegotiateProtocolVersion { version: PROTOCOL_3_2, unrecognized: vec![] });
    }

    #[test]
    fn accepted_encryption_ends_negotiation() {
        // After an accepted SSLRequest, PostgreSQL sets both ssl_done and
        // gss_done, so a GSSENCRequest is refused, and the reverse.
        for (first, second, code) in [
            (Frontend::SslRequest, Frontend::GssEncRequest, GSSENC_REQUEST_CODE),
            (Frontend::GssEncRequest, Frontend::SslRequest, SSL_REQUEST_CODE),
        ] {
            let mut d = Decoder::new();
            d.feed(&first.to_bytes());
            assert_eq!(d.next_message(), Some(Ok(first)));
            assert_eq!(d.start_encryption(), b"");
            d.feed(&second.to_bytes());
            assert_eq!(d.next_message(), Some(Err(Error::UnsupportedProtocol(code))));
        }
        // A refused request leaves the other one open.
        let mut d = Decoder::new();
        d.feed(&Frontend::SslRequest.to_bytes());
        d.feed(&Frontend::GssEncRequest.to_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::SslRequest)));
        assert_eq!(d.next_message(), Some(Ok(Frontend::GssEncRequest)));
        // Bytes sent in the clear before the switch come back.
        let mut d = Decoder::new();
        d.feed(&Frontend::SslRequest.to_bytes());
        d.feed(b"injected");
        assert_eq!(d.next_message(), Some(Ok(Frontend::SslRequest)));
        assert_eq!(d.start_encryption(), b"injected");
        assert_eq!(d.buffered(), 0);
        d.feed(&startup_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::Startup(Startup::new("alice", "shop")))));
        // After the startup phase, or before any request, it does nothing.
        d.feed(b"Q");
        assert_eq!(d.start_encryption(), b"");
        assert_eq!(d.buffered(), 1);
        assert_eq!(Decoder::new().start_encryption(), b"");
    }

    #[test]
    fn direct_tls_goes_on_in_the_same_decoder() {
        let mut d = Decoder::new();
        d.feed(&[0x16, 3, 1, 0, 5]);
        assert_eq!(d.next_message(), Some(Err(Error::DirectTls)));
        assert_eq!(d.start_encryption(), [0x16, 3, 1, 0, 5]);
        // The decrypted stream: a 0x16 there is a length, not TLS again.
        let mut probe = d.clone();
        probe.feed(&[0x16, 3, 1, 0]);
        assert_eq!(probe.next_message(), Some(Err(Error::TooLong { length: 0x1603_0100, max: MAX_STARTUP + 4 })));
        // Requests inside direct TLS still come out, for the server to
        // refuse with N.
        d.feed(&Frontend::SslRequest.to_bytes());
        d.feed(&startup_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::SslRequest)));
        assert!(matches!(d.next_message(), Some(Ok(Frontend::Startup(_)))));
        // Any other error stays.
        let mut d = Decoder::new();
        d.feed(&[0, 0, 0, 1]);
        assert_eq!(d.next_message(), Some(Err(Error::BadLength(1))));
        assert_eq!(d.start_encryption(), b"");
        assert_eq!(d.next_message(), Some(Err(Error::BadLength(1))));
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::DirectTls,
            Error::UnsupportedProtocol(0x2_0000),
            Error::UnknownType(0),
            Error::UnknownType(b'z'),
            Error::BadLength(1),
            Error::TooLong { length: 1, max: 0 },
            bad(0, Malformed::Truncated),
            bad(b'B', Malformed::TrailingBytes),
            bad(b'B', Malformed::UnterminatedString),
            bad(b'B', Malformed::NotUtf8),
            bad(b'B', Malformed::BadFormat(3)),
            bad(b'B', Malformed::FormatCount),
            bad(b'B', Malformed::BadValueLength(-3)),
            bad(b'C', Malformed::BadTarget(b'Q')),
            bad(b'Z', Malformed::BadStatus(1)),
            bad(0, Malformed::BadKeyLength(0)),
            bad(b'R', Malformed::BadAuth(99)),
            bad(b'v', Malformed::TooManyItems),
            bad(b'E', Malformed::DuplicateField(b'C')),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
            let _: &dyn std::error::Error = &e;
        }
        assert_eq!(Error::UnsupportedProtocol(0x2_0000).to_string(), "unsupported frontend protocol 2.0");
        assert_eq!(Error::UnknownType(b'z').to_string(), "invalid message type 'z'");
    }

    #[test]
    fn every_prefix_waits() {
        let mut streams: Vec<(bool, Vec<u8>)> = Vec::new();
        for m in all_frontend() {
            streams.push((m.is_startup(), m.to_bytes()));
        }
        streams.push((true, startup_bytes()));
        streams.push((false, extended_bytes()[..22].to_vec()));
        for (startup, bytes) in &streams {
            for n in 0..bytes.len() {
                let got = if *startup { Frontend::parse_startup(&bytes[..n]) } else { Frontend::parse(&bytes[..n]) };
                assert_eq!(got, Ok(None), "{n} bytes of {bytes:?}");
            }
        }
        for m in all_backend() {
            let bytes = m.to_bytes();
            for n in 0..bytes.len() {
                assert_eq!(Backend::parse(&bytes[..n]), Ok(None), "{n} bytes of {m:?}");
            }
        }
    }

    #[test]
    fn decoder_follows_the_phases() {
        let mut stream = Frontend::SslRequest.to_bytes();
        stream.extend(startup_bytes());
        stream.extend(extended_bytes());
        stream.extend(Frontend::Terminate.to_bytes());
        stream.extend(b"Q\0\0\0\x05\0");
        let mut want = vec![Frontend::SslRequest, Frontend::Startup(Startup::new("alice", "shop"))];
        want.extend(extended_messages());
        want.push(Frontend::Terminate);
        // All at once and a byte at a time give the same messages.
        for chunk in [stream.len(), 1, 7] {
            let mut d = Decoder::new();
            let mut got = Vec::new();
            let mut phases = Vec::new();
            for piece in stream.chunks(chunk) {
                d.feed(piece);
                while let Some(m) = d.next_message() {
                    got.push(m.unwrap());
                    phases.push(d.phase());
                }
            }
            assert_eq!(got, want);
            assert_eq!(phases[0], Phase::Startup);
            assert_eq!(phases[1], Phase::Messages);
            assert_eq!(d.phase(), Phase::Closed);
            assert_eq!(d.buffered(), 0);
        }
        // A cancel request closes its connection.
        let mut d = Decoder::default();
        d.feed(&Frontend::CancelRequest { process_id: 1, secret_key: vec![1; 4] }.to_bytes());
        d.feed(b"junk");
        assert!(matches!(d.next_message(), Some(Ok(Frontend::CancelRequest { .. }))));
        assert_eq!(d.phase(), Phase::Closed);
        d.feed(b"more");
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_errors_stick() {
        let mut d = Decoder::new();
        d.feed(&[0x16, 3, 1, 0, 5]);
        assert_eq!(d.next_message(), Some(Err(Error::DirectTls)));
        d.feed(b"more");
        assert_eq!(d.next_message(), Some(Err(Error::DirectTls)));
        // The ClientHello is still there for TLS to read.
        assert_eq!(d.take_buffered(), [0x16, 3, 1, 0, 5]);
        assert_eq!(d.buffered(), 0);

        // Typed messages before the startup message are refused.
        let mut d = Decoder::new();
        d.feed(b"Q\0\0\0\x05\0");
        assert_eq!(d.next_message(), Some(Err(Error::TooLong { length: 0x5100_0000, max: MAX_STARTUP + 4 })));

        // A lower maximum, and an unknown type after the startup.
        let mut d = Decoder::new().with_max_message(20_000);
        d.feed(&startup_bytes());
        assert!(d.next_message().unwrap().is_ok());
        d.feed(b"Q\0\0\x4e\x21");
        assert_eq!(d.next_message(), Some(Err(Error::TooLong { length: 20_001, max: 20_000 })));
        let mut d = Decoder::new();
        d.feed(&startup_bytes());
        d.feed(b"?");
        assert!(d.next_message().unwrap().is_ok());
        assert_eq!(d.next_message(), Some(Err(Error::UnknownType(b'?'))));
        // The limit cannot go below what small messages need.
        let mut d = Decoder::new().with_max_message(0);
        d.feed(&startup_bytes());
        d.feed(&Frontend::Query("x".repeat(9000)).to_bytes());
        assert!(d.next_message().unwrap().is_ok());
        assert!(d.next_message().unwrap().is_ok());
    }

    #[test]
    fn backend_decoder() {
        let messages = all_backend();
        let stream: Vec<u8> = messages.iter().flat_map(Backend::to_bytes).collect();
        for chunk in [stream.len(), 1, 5] {
            let mut d = BackendDecoder::default();
            let mut got = Vec::new();
            for piece in stream.chunks(chunk) {
                d.feed(piece);
                while let Some(m) = d.next_message() {
                    got.push(m.unwrap());
                }
            }
            assert_eq!(got, messages);
            assert_eq!(d.buffered(), 0);
        }
        let mut d = BackendDecoder::new().with_max_message(10_000);
        d.feed(b"D\0\0\x27\x11");
        assert_eq!(d.next_message(), Some(Err(Error::TooLong { length: 10_001, max: 10_000 })));
        d.feed(b"Z\0\0\0\x05I");
        assert_eq!(d.next_message(), Some(Err(Error::TooLong { length: 10_001, max: 10_000 })));
    }

    /// Startup, then `bytes`, in a decoder that has taken the startup out.
    fn after_startup() -> Decoder {
        let mut d = Decoder::new();
        d.feed(&startup_bytes());
        assert!(matches!(d.next_message(), Some(Ok(Frontend::Startup(_)))));
        d
    }

    #[test]
    fn feed_holds_at_most_its_capacity() {
        // A 64 KiB feed to a decoder of 10,000-byte messages is not copied
        // whole.
        let mut d = Decoder::new().with_max_message(10_000);
        let big = vec![b'?'; 65_536];
        let took = d.feed(&big);
        assert!(took <= d.capacity() && d.buffered() <= d.capacity(), "{took}");
        assert!(d.next_message().unwrap().is_err());
        // After an error that ends the stream, bytes are dropped and the
        // storage is let go.
        assert_eq!(d.feed(&big), big.len());
        assert_eq!(d.buf.capacity(), 0);
        // Feeding without taking messages out stops at the capacity, and
        // then every message comes out.
        let mut d = after_startup();
        let sync = Frontend::Sync.to_bytes();
        let mut fed = 0;
        while d.feed(&sync) == sync.len() {
            fed += 1;
        }
        assert!(d.buffered() <= d.capacity());
        let mut got = 0;
        while let Some(m) = d.next_message() {
            assert_eq!(m, Ok(Frontend::Sync));
            got += 1;
        }
        assert_eq!(got, fed);
        let mut d = BackendDecoder::new().with_max_message(10_000);
        assert!(d.feed(&big) <= d.capacity());
        assert!(d.next_message().unwrap().is_err());
        assert_eq!(d.feed(&big), big.len());
        assert_eq!(d.buf.capacity(), 0);
    }

    #[test]
    fn interleaved_reads_do_not_shift_the_backlog() {
        // An empty feed copies nothing, and the bytes taken out are only
        // dropped once they outweigh the rest, so a backlog is not moved
        // once per message.
        let mut d = BackendDecoder::new();
        let one = Backend::ParseComplete.to_bytes();
        let backlog: Vec<u8> = (0..100).flat_map(|_| one.clone()).collect();
        d.feed(&backlog);
        for i in 1..=40 {
            assert_eq!(d.next_message(), Some(Ok(Backend::ParseComplete)));
            d.feed(&[]);
            assert_eq!(d.pos, 5 * i);
        }
        d.feed(&one);
        assert_eq!(d.pos, 200);
        let mut d = after_startup();
        d.feed(&Frontend::Sync.to_bytes());
        d.feed(&Frontend::Sync.to_bytes());
        assert_eq!(d.next_message(), Some(Ok(Frontend::Sync)));
        let pos = d.pos;
        d.feed(&[]);
        assert_eq!(d.pos, pos);
    }

    #[test]
    fn malformed_body_drops_only_its_message() {
        // PostgreSQL raises an ERROR for a message whose body does not fit
        // its length and goes on at the next one (pq_getmsgend).
        let mut d = after_startup();
        d.feed(b"P\0\0\0\x09\0\0\0\0x");
        d.feed(&Frontend::Sync.to_bytes());
        let e = d.next_message().unwrap().unwrap_err();
        assert_eq!(e, bad(b'P', Malformed::TrailingBytes));
        assert!(e.is_recoverable());
        assert_eq!(d.next_message(), Some(Ok(Frontend::Sync)));
        // A broken frame still ends the stream.
        d.feed(b"S\0\0\0\x03");
        let e = d.next_message().unwrap().unwrap_err();
        assert!(!e.is_recoverable());
        assert_eq!(d.next_message(), Some(Err(e)));
        // The same for a client: libpq skips a message whose contents do
        // not agree with its length.
        let mut d = BackendDecoder::new();
        d.feed(b"Z\0\0\0\x05X");
        d.feed(&Backend::ParseComplete.to_bytes());
        assert_eq!(d.next_message(), Some(Err(bad(b'Z', Malformed::BadStatus(b'X')))));
        assert_eq!(d.next_message(), Some(Ok(Backend::ParseComplete)));
        // Startup-phase errors are fatal in PostgreSQL.
        assert!(!bad(0, Malformed::TrailingBytes).is_recoverable());
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
            Frontend::parse(&typed(b'B', &b))
        };
        assert_eq!(bind(b"\0\0", b"a\0b"), Err(bad(b'B', Malformed::NotUtf8)));
        assert_eq!(bind(b"\0\x01\0\0", b"\xff"), Err(bad(b'B', Malformed::NotUtf8)));
        assert!(bind(b"\0\x01\0\x01", b"a\0\xff").is_ok());
        let call = |format: u8, value: &[u8]| {
            let mut b = vec![0, 0, 0, 1, 0, 1, 0, format, 0, 1];
            b.extend_from_slice(&(value.len() as u32).to_be_bytes());
            b.extend_from_slice(value);
            b.extend_from_slice(&[0, 0]);
            Frontend::parse(&typed(b'F', &b))
        };
        assert_eq!(call(0, b"\0"), Err(bad(b'F', Malformed::NotUtf8)));
        assert!(call(1, b"\0").is_ok());
        // Writers cut a text value at its first NUL, or before bytes that
        // are not UTF-8, and leave binary values alone.
        let m = Frontend::Bind(Bind {
            param_formats: vec![Format::Text, Format::Binary],
            params: vec![Some(b"a\0b".to_vec()), Some(b"a\0b".to_vec())],
            ..Bind::default()
        });
        let Frontend::Bind(back) = Frontend::parse(&m.to_bytes()).unwrap().unwrap().0 else { panic!() };
        assert_eq!(back.params, [Some(b"a".to_vec()), Some(b"a\0b".to_vec())]);
        let m = Frontend::FunctionCall(FunctionCall { args: vec![Some(b"ok\xc3".to_vec())], ..FunctionCall::default() });
        let Frontend::FunctionCall(back) = Frontend::parse(&m.to_bytes()).unwrap().unwrap().0 else { panic!() };
        assert_eq!(back.args, [Some(b"ok".to_vec())]);
    }

    #[test]
    fn startup_asks_for_utf8() {
        // The readers take UTF-8 text only, so a client asks for it rather
        // than taking the database's default encoding.
        assert_eq!(Startup::new("alice", "shop").get("client_encoding"), Some("UTF8"));
    }

    #[test]
    fn error_fields_come_once() {
        // "Any given field type should appear at most once per message."
        let g = |body: &[u8]| Backend::parse(&typed(b'E', body));
        assert_eq!(g(b"C42P01\0C00000\0\0"), Err(bad(b'E', Malformed::DuplicateField(b'C'))));
        let d = Diagnostic::error(sqlstate::SYNTAX_ERROR, "x").with(field_code::CODE, sqlstate::INTERNAL_ERROR);
        let (back, _) = Backend::parse(&Backend::ErrorResponse(d).to_bytes()).unwrap().unwrap();
        assert_eq!(back, Backend::ErrorResponse(Diagnostic::error(sqlstate::SYNTAX_ERROR, "x")));
    }

    #[test]
    fn unbounded_lists_are_capped() {
        // A million one-byte names would take far more memory than wire.
        let mut body = PROTOCOL_3_0.to_be_bytes().to_vec();
        body.extend_from_slice(&1_000_000u32.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, 1_000_000));
        let m = typed(b'v', &body);
        assert_eq!(
            Backend::parse_max(&m, MAX_MESSAGE),
            Err(bad(b'v', Malformed::TooManyItems))
        );
        let mut body = 10u32.to_be_bytes().to_vec();
        for _ in 0..=MAX_COUNT {
            body.extend_from_slice(b"a\0");
        }
        body.push(0);
        assert_eq!(Backend::parse(&typed(b'R', &body)), Err(bad(b'R', Malformed::TooManyItems)));
        // Writers keep to the cap.
        let names = vec!["a".to_string(); MAX_COUNT + 5];
        let m = Backend::NegotiateProtocolVersion { version: PROTOCOL_3_0, unrecognized: names.clone() };
        let Backend::NegotiateProtocolVersion { unrecognized, .. } = Backend::parse(&m.to_bytes()).unwrap().unwrap().0
        else {
            panic!()
        };
        assert_eq!(unrecognized.len(), MAX_COUNT);
        let m = Backend::Authentication(Authentication::Sasl(names));
        let Backend::Authentication(Authentication::Sasl(back)) = Backend::parse(&m.to_bytes()).unwrap().unwrap().0
        else {
            panic!()
        };
        assert_eq!(back.len(), MAX_COUNT);
    }

    #[test]
    fn writers_keep_to_the_format() {
        // NUL bytes end strings, and empty names are left out.
        let s = Startup {
            minor_version: 0,
            params: vec![("".into(), "x".into()), ("user".into(), "al\0ice".into()), ("a\0b".into(), "c".into())],
        };
        let (back, _) = Frontend::parse_startup(&Frontend::Startup(s).to_bytes()).unwrap().unwrap();
        assert_eq!(
            back,
            Frontend::Startup(Startup {
                minor_version: 0,
                params: vec![("user".into(), "al".into()), ("a".into(), "c".into())]
            })
        );
        // A startup message stays within its limit.
        let s = Startup { minor_version: 0, params: (0..2000).map(|i| (format!("p{i}"), "v".repeat(10))).collect() };
        let bytes = Frontend::Startup(s).to_bytes();
        assert!(bytes.len() <= MAX_STARTUP + 4);
        assert!(Frontend::parse_startup(&bytes).unwrap().is_some());
        // Cancel keys: empty becomes 4 zero bytes, long ones are cut.
        let k = |key: Vec<u8>| Frontend::CancelRequest { process_id: 0, secret_key: key }.to_bytes();
        assert_eq!(&k(vec![])[12..], &[0, 0, 0, 0]);
        assert_eq!(k(vec![1; 300]).len(), 12 + MAX_SECRET_KEY);
        let b = Backend::BackendKeyData { process_id: 0, secret_key: vec![] }.to_bytes();
        assert!(Backend::parse(&b).is_ok());
        // Format counts that break the rule fall back to the first format.
        let bind = Frontend::Bind(Bind {
            param_formats: vec![Format::Binary, Format::Text],
            params: vec![None, None, None],
            ..Bind::default()
        });
        let Frontend::Bind(back) = Frontend::parse(&bind.to_bytes()).unwrap().unwrap().0 else { panic!() };
        assert_eq!(back.param_formats, [Format::Binary]);
        assert_eq!(back.params.len(), 3);
        // Code-0 error fields and empty SASL names are left out.
        let e = Backend::ErrorResponse(Diagnostic { fields: vec![(0, "x".into()), (b'M', "m".into())] });
        assert_eq!(
            Backend::parse(&e.to_bytes()).unwrap().unwrap().0,
            Backend::ErrorResponse(Diagnostic { fields: vec![(b'M', "m".into())] })
        );
        let a = Backend::Authentication(Authentication::Sasl(vec!["".into(), "A".into()]));
        assert_eq!(
            Backend::parse(&a.to_bytes()).unwrap().unwrap().0,
            Backend::Authentication(Authentication::Sasl(vec!["A".into()]))
        );
        // Small messages are cut to their limit, on a character boundary.
        let fail = Frontend::CopyFail("é".repeat(6000)).to_bytes();
        assert!(fail.len() - 1 <= SMALL_MESSAGE);
        assert!(Frontend::parse(&fail).unwrap().is_some());
        let exec = Frontend::Execute { portal: "p".repeat(20_000), max_rows: 3 }.to_bytes();
        let Frontend::Execute { max_rows, .. } = Frontend::parse(&exec).unwrap().unwrap().0 else { panic!() };
        assert_eq!(max_rows, 3);
        // 16-bit counts.
        let row = Backend::DataRow(vec![None; 70_000]).to_bytes();
        let Backend::DataRow(values) = Backend::parse(&row).unwrap().unwrap().0 else { panic!() };
        assert_eq!(values.len(), MAX_COUNT);
    }

    #[test]
    fn capped_writes_stay_readable() {
        let mut rng = Lcg(7);
        for _ in 0..3000 {
            let cap = 32 + rng.below(200);
            let m = random_frontend(&mut rng);
            let bytes = m.encode(cap);
            if m.is_startup() {
                assert!(Frontend::parse_startup(&bytes).unwrap().is_some());
            } else {
                assert!(bytes.len() - 1 <= cap, "{m:?}");
                let (back, used) = Frontend::parse_max(&bytes, cap).unwrap().unwrap();
                assert_eq!(used, bytes.len());
                assert_eq!(back.encode(cap), bytes);
            }
            let m = random_backend(&mut rng);
            let bytes = m.encode(cap);
            assert!(bytes.len() - 1 <= cap, "{m:?}");
            let (back, used) = Backend::parse_max(&bytes, cap).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(back.encode(cap), bytes);
        }
    }

    #[test]
    fn random_messages_round_trip() {
        let mut rng = Lcg(1);
        for _ in 0..3000 {
            let m = random_frontend(&mut rng);
            let bytes = m.to_bytes();
            let parsed = if m.is_startup() { Frontend::parse_startup(&bytes) } else { Frontend::parse(&bytes) };
            let (back, used) = parsed.unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(back.to_bytes(), bytes);
            if clean_frontend(&m) {
                assert_eq!(back, m);
            }
            let m = random_backend(&mut rng);
            let bytes = m.to_bytes();
            let (back, used) = Backend::parse(&bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(back.to_bytes(), bytes);
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Lcg(42);
        let valid: Vec<u8> = all_frontend().iter().filter(|m| !m.is_startup()).flat_map(Frontend::to_bytes).collect();
        let valid_back: Vec<u8> = all_backend().iter().flat_map(Backend::to_bytes).collect();
        for i in 0..4000 {
            let data: Vec<u8> = match i % 3 {
                0 => (0..rng.below(64)).map(|_| rng.byte()).collect(),
                1 => mutate(&mut rng, &valid),
                _ => mutate(&mut rng, &valid_back),
            };
            // A server decoder, with the startup message in front or not.
            for front in [Vec::new(), startup_bytes()] {
                let mut input = front.clone();
                input.extend_from_slice(&data);
                let whole = drain_frontend(&input, input.len());
                assert_eq!(whole, drain_frontend(&input, 1 + rng.below(9)));
                assert_eq!(whole, drain_frontend(&input, 1));
                for m in whole.iter().flatten() {
                    let bytes = m.to_bytes();
                    let parsed = if m.is_startup() { Frontend::parse_startup(&bytes) } else { Frontend::parse(&bytes) };
                    assert_eq!(parsed, Ok(Some((m.clone(), bytes.len()))));
                }
            }
            let whole = drain_backend(&data, data.len());
            assert_eq!(whole, drain_backend(&data, 1 + rng.below(9)));
            assert_eq!(whole, drain_backend(&data, 1));
            for m in whole.iter().flatten() {
                let bytes = m.to_bytes();
                assert_eq!(Backend::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
            }
            let _ = Frontend::parse(&data);
            let _ = Frontend::parse_startup(&data);
            let _ = read_password(&data);
            let _ = SaslInitialResponse::parse(&data);
        }
    }

    /// Every message, with the errors on the way and the one that breaks
    /// the stream, fed in pieces of `chunk` bytes. Whatever a feed does
    /// not take is fed again once the messages are out.
    fn drain<M>(
        input: &[u8],
        chunk: usize,
        mut feed: impl FnMut(&[u8]) -> usize,
        mut next: impl FnMut() -> Option<Result<M, Error>>,
    ) -> Vec<Result<M, Error>> {
        let mut out = Vec::new();
        for mut piece in input.chunks(chunk.max(1)) {
            loop {
                let took = feed(piece);
                piece = &piece[took..];
                let before = out.len();
                while let Some(m) = next() {
                    let stop = matches!(&m, Err(e) if !e.is_recoverable());
                    out.push(m);
                    if stop {
                        return out;
                    }
                }
                if piece.is_empty() {
                    break;
                }
                // A full decoder always has a message or an error.
                assert!(took > 0 || out.len() > before, "the decoder is stuck");
            }
        }
        out
    }

    fn drain_frontend(input: &[u8], chunk: usize) -> Vec<Result<Frontend, Error>> {
        let d = std::cell::RefCell::new(Decoder::new().with_max_message(SMALL_MESSAGE));
        drain(input, chunk, |b| d.borrow_mut().feed(b), || d.borrow_mut().next_message())
    }

    fn drain_backend(input: &[u8], chunk: usize) -> Vec<Result<Backend, Error>> {
        let d = std::cell::RefCell::new(BackendDecoder::new().with_max_message(SMALL_MESSAGE));
        drain(input, chunk, |b| d.borrow_mut().feed(b), || d.borrow_mut().next_message())
    }

    #[test]
    fn large_feeds_come_out_whole() {
        // A feed larger than the capacity is taken in parts, and every
        // message comes out, with a malformed one dropped on the way.
        let mut input = startup_bytes();
        for i in 0..3000 {
            if i == 1000 {
                input.extend_from_slice(b"P\0\0\0\x09\0\0\0\0x");
            }
            input.extend(Frontend::Query(format!("SELECT {i}")).to_bytes());
        }
        assert!(input.len() > SMALL_MESSAGE * 3);
        let got = drain_frontend(&input, input.len());
        assert_eq!(got.len(), 3002);
        assert_eq!(got[1001], Err(bad(b'P', Malformed::TrailingBytes)));
        assert_eq!(got[3001], Ok(Frontend::Query("SELECT 2999".into())));
        assert_eq!(got, drain_frontend(&input, 7));
        let stream: Vec<u8> = (0..3000).flat_map(|_| Backend::ParseComplete.to_bytes()).collect();
        assert_eq!(drain_backend(&stream, stream.len()).len(), 3000);
    }

    fn mutate(rng: &mut Lcg, valid: &[u8]) -> Vec<u8> {
        let start = rng.below(valid.len());
        let len = rng.below(valid.len() - start + 1);
        let mut data = valid[start..start + len].to_vec();
        for _ in 0..rng.below(4) {
            if !data.is_empty() {
                let at = rng.below(data.len());
                data[at] = rng.byte();
            }
        }
        data
    }

    /// One of every message, in a valid form.
    fn all_frontend() -> Vec<Frontend> {
        let mut all = vec![
            Frontend::Startup(Startup::new("u", "d")),
            Frontend::SslRequest,
            Frontend::GssEncRequest,
            Frontend::CancelRequest { process_id: 9, secret_key: vec![1; 32] },
            Frontend::Close { target: Target::Portal, name: "p".into() },
            Frontend::CopyData(vec![1, 2, 3]),
            Frontend::CopyDone,
            Frontend::CopyFail("stop".into()),
            Frontend::Flush,
            Frontend::FunctionCall(FunctionCall {
                function: 1,
                arg_formats: vec![Format::Binary, Format::Text],
                args: vec![Some(vec![1]), None],
                result_format: Format::Text,
            }),
            Frontend::password("secret"),
            Frontend::Query("SELECT 'é'".into()),
            Frontend::Terminate,
        ];
        all.extend(extended_messages());
        all
    }

    fn all_backend() -> Vec<Backend> {
        let copy = CopyFormat { format: Format::Binary, columns: vec![Format::Binary] };
        vec![
            Backend::Authentication(Authentication::Ok),
            Backend::Authentication(Authentication::KerberosV5),
            Backend::Authentication(Authentication::CleartextPassword),
            Backend::Authentication(Authentication::Md5Password([1, 2, 3, 4])),
            Backend::Authentication(Authentication::Gss),
            Backend::Authentication(Authentication::GssContinue(vec![5])),
            Backend::Authentication(Authentication::Sspi),
            Backend::Authentication(Authentication::Sasl(vec!["SCRAM-SHA-256".into(), "SCRAM-SHA-256-PLUS".into()])),
            Backend::Authentication(Authentication::SaslContinue(b"r=x".to_vec())),
            Backend::Authentication(Authentication::SaslFinal(b"v=y".to_vec())),
            Backend::BackendKeyData { process_id: 1, secret_key: vec![2; 4] },
            Backend::BindComplete,
            Backend::CloseComplete,
            Backend::CommandComplete("INSERT 0 1".into()),
            Backend::CopyData(b"a\n".to_vec()),
            Backend::CopyDone,
            Backend::CopyInResponse(copy.clone()),
            Backend::CopyOutResponse(copy.clone()),
            Backend::CopyBothResponse(copy),
            Backend::DataRow(vec![Some(b"1".to_vec()), None, Some(vec![])]),
            Backend::EmptyQueryResponse,
            Backend::ErrorResponse(Diagnostic::error(sqlstate::SYNTAX_ERROR, "syntax error")),
            Backend::FunctionCallResponse(Some(vec![0, 1])),
            Backend::NegotiateProtocolVersion { version: PROTOCOL_3_0, unrecognized: vec![] },
            Backend::NoData,
            Backend::NoticeResponse(Diagnostic::new("WARNING", sqlstate::WARNING, "careful")),
            Backend::NotificationResponse { process_id: 3, channel: "jobs".into(), payload: "42".into() },
            Backend::ParameterDescription(vec![oid::TEXT, oid::INT8]),
            Backend::ParameterStatus { name: "TimeZone".into(), value: "UTC".into() },
            Backend::ParseComplete,
            Backend::PortalSuspended,
            Backend::ReadyForQuery(TransactionStatus::InTransaction),
            Backend::RowDescription(vec![Field::new("a", oid::TEXT), Field::new("b", oid::BOOL)]),
        ]
    }

    /// A deterministic generator, so a failure always repeats.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, n: usize) -> usize {
            if n == 0 { 0 } else { (self.next() % n as u64) as usize }
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }

        fn string(&mut self) -> String {
            const PARTS: [&str; 8] = ["a", "Z", " ", "é", "漢", "\0", "$1", "'"];
            let n = if self.below(20) == 0 { 300 } else { self.below(8) };
            (0..n).map(|_| PARTS[self.below(PARTS.len())]).collect()
        }

        fn bytes(&mut self) -> Vec<u8> {
            let n = if self.below(20) == 0 { 300 } else { self.below(8) };
            (0..n).map(|_| self.byte()).collect()
        }

        fn value(&mut self) -> Value {
            if self.below(4) == 0 { None } else { Some(self.bytes()) }
        }

        fn format(&mut self) -> Format {
            if self.below(2) == 0 { Format::Text } else { Format::Binary }
        }

        fn list<T>(&mut self, f: impl Fn(&mut Lcg) -> T) -> Vec<T> {
            (0..self.below(5)).map(|_| f(self)).collect()
        }
    }

    fn random_frontend(rng: &mut Lcg) -> Frontend {
        let target = if rng.below(2) == 0 { Target::Statement } else { Target::Portal };
        match rng.below(18) {
            0 => Frontend::Startup(Startup {
                minor_version: rng.below(4) as u16,
                params: rng.list(|r| (r.string(), r.string())),
            }),
            1 => Frontend::SslRequest,
            2 => Frontend::GssEncRequest,
            3 => Frontend::CancelRequest { process_id: rng.next() as u32, secret_key: rng.bytes() },
            4 => {
                let params = rng.list(Lcg::value);
                let param_formats = match rng.below(3) {
                    0 => vec![],
                    1 => vec![rng.format()],
                    _ => params.iter().map(|_| rng.format()).collect(),
                };
                Frontend::Bind(Bind {
                    portal: rng.string(),
                    statement: rng.string(),
                    param_formats,
                    params,
                    result_formats: rng.list(Lcg::format),
                })
            }
            5 => Frontend::Close { target, name: rng.string() },
            6 => Frontend::CopyData(rng.bytes()),
            7 => Frontend::CopyDone,
            8 => Frontend::CopyFail(rng.string()),
            9 => Frontend::Describe { target, name: rng.string() },
            10 => Frontend::Execute { portal: rng.string(), max_rows: rng.next() as i32 },
            11 => Frontend::Flush,
            12 => Frontend::FunctionCall(FunctionCall {
                function: rng.next() as u32,
                arg_formats: rng.list(Lcg::format),
                args: rng.list(Lcg::value),
                result_format: rng.format(),
            }),
            13 => Frontend::AuthResponse(rng.bytes()),
            14 => {
                Frontend::Parse { name: rng.string(), query: rng.string(), param_types: rng.list(|r| r.next() as u32) }
            }
            15 => Frontend::Query(rng.string()),
            16 => Frontend::Sync,
            _ => Frontend::Terminate,
        }
    }

    /// Whether a message survives writing unchanged: no NUL in its
    /// strings, no empty startup names, a valid key, and format counts
    /// that keep the rule. All random messages are far below the limits.
    fn clean_frontend(m: &Frontend) -> bool {
        let ok = |s: &String| !s.contains('\0');
        match m {
            Frontend::Startup(s) => s.params.iter().all(|(n, v)| ok(n) && ok(v) && !n.is_empty()),
            Frontend::CancelRequest { secret_key, .. } => (1..=MAX_SECRET_KEY).contains(&secret_key.len()),
            Frontend::Bind(b) => {
                ok(&b.portal) && ok(&b.statement) && check_text_values(&b.param_formats, &b.params).is_ok()
            }
            Frontend::FunctionCall(f) => {
                (f.arg_formats.len() <= 1 || f.arg_formats.len() == f.args.len())
                    && check_text_values(&f.arg_formats, &f.args).is_ok()
            }
            Frontend::Close { name, .. } | Frontend::Describe { name, .. } => ok(name),
            Frontend::CopyFail(s) | Frontend::Query(s) | Frontend::Execute { portal: s, .. } => ok(s),
            Frontend::Parse { name, query, .. } => ok(name) && ok(query),
            _ => true,
        }
    }

    fn random_backend(rng: &mut Lcg) -> Backend {
        let diagnostic = |r: &mut Lcg| Diagnostic { fields: r.list(|r| (r.byte(), r.string())) };
        let copy = |r: &mut Lcg| CopyFormat { format: r.format(), columns: r.list(Lcg::format) };
        match rng.below(24) {
            0 => Backend::Authentication(match rng.below(10) {
                0 => Authentication::Ok,
                1 => Authentication::KerberosV5,
                2 => Authentication::CleartextPassword,
                3 => Authentication::Md5Password([rng.byte(), rng.byte(), rng.byte(), rng.byte()]),
                4 => Authentication::Gss,
                5 => Authentication::GssContinue(rng.bytes()),
                6 => Authentication::Sspi,
                7 => Authentication::Sasl(rng.list(Lcg::string)),
                8 => Authentication::SaslContinue(rng.bytes()),
                _ => Authentication::SaslFinal(rng.bytes()),
            }),
            1 => Backend::BackendKeyData { process_id: rng.next() as u32, secret_key: rng.bytes() },
            2 => Backend::BindComplete,
            3 => Backend::CloseComplete,
            4 => Backend::CommandComplete(rng.string()),
            5 => Backend::CopyData(rng.bytes()),
            6 => Backend::CopyDone,
            7 => Backend::CopyInResponse(copy(rng)),
            8 => Backend::CopyOutResponse(copy(rng)),
            9 => Backend::CopyBothResponse(copy(rng)),
            10 => Backend::DataRow(rng.list(Lcg::value)),
            11 => Backend::EmptyQueryResponse,
            12 => Backend::ErrorResponse(diagnostic(rng)),
            13 => Backend::FunctionCallResponse(rng.value()),
            14 => Backend::NegotiateProtocolVersion { version: rng.next() as u32, unrecognized: rng.list(Lcg::string) },
            15 => Backend::NoData,
            16 => Backend::NoticeResponse(diagnostic(rng)),
            17 => Backend::NotificationResponse {
                process_id: rng.next() as u32,
                channel: rng.string(),
                payload: rng.string(),
            },
            18 => Backend::ParameterDescription(rng.list(|r| r.next() as u32)),
            19 => Backend::ParameterStatus { name: rng.string(), value: rng.string() },
            20 => Backend::ParseComplete,
            21 => Backend::PortalSuspended,
            22 => Backend::ReadyForQuery(match rng.below(3) {
                0 => TransactionStatus::Idle,
                1 => TransactionStatus::InTransaction,
                _ => TransactionStatus::Failed,
            }),
            _ => Backend::RowDescription(rng.list(|r| Field {
                name: r.string(),
                table_oid: r.next() as u32,
                column: r.next() as i16,
                type_oid: r.next() as u32,
                type_size: r.next() as i16,
                type_modifier: r.next() as i32,
                format: r.format(),
            })),
        }
    }
}
