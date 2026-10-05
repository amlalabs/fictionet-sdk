//! RESP, the Redis protocol: reading and writing values and commands, in
//! both its versions, with no I/O.
//!
//! Redis, and the servers that copy it, speak RESP over TCP, usually on
//! port 6379. A client sends each command as an array of bulk strings, or
//! as one line of text typed into telnet (an inline command). The server
//! answers each command with one value. RESP2 has five types: simple
//! strings, errors, integers, bulk strings and arrays, plus null forms of
//! the last two. RESP3, which a client asks for with `HELLO 3`, adds null,
//! booleans, doubles, big numbers, bulk errors, verbatim strings, maps,
//! sets, pushes and attributes. It also lets a sender stream a string or
//! an aggregate whose size it does not know yet. This module follows the
//! RESP specification in the Redis documentation and the RESP3
//! specification in redis-specifications.
//!
//! Nothing here reads a socket. A world that plays a Redis server feeds
//! the bytes it reads from a TCP connection to a [`Decoder`], takes
//! [`Command`]s out, and writes each reply's bytes, made with
//! [`Value::write`], back to the connection. A world that plays a client
//! does the reverse with [`Decoder::next_value`]. Which commands exist and
//! what they do is up to world code.
//!
//! Every reader checks lengths, counts and nesting against [`Limits`],
//! because the agent can send any bytes it likes. Part of a value is not
//! an error: the readers say so and consume nothing until the rest comes.
//! A [`ParseError`] means the stream cannot be read any further. A real
//! server answers it with [`ParseError::reply`] and closes the connection.
//!
//! ```
//! use std::collections::HashMap;
//! use fictionet::stdlib::resp::{Decoder, Value, Version};
//!
//! let mut store: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
//! let mut decoder = Decoder::new();
//! // A SET as an array of bulk strings, then a GET typed into telnet.
//! decoder.feed(b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nhello\r\n");
//! decoder.feed(b"GET key\r\n");
//! let mut out = Vec::new();
//! while let Some(command) = decoder.next_command() {
//!     let command = command.unwrap();
//!     let reply = match (command.name().as_deref(), command.args.as_slice()) {
//!         (Some("SET"), [_, k, v]) => {
//!             store.insert(k.clone(), v.clone());
//!             Value::ok()
//!         }
//!         (Some("GET"), [_, k]) => store.get(k).map_or(Value::Null, |v| Value::Bulk(v.clone())),
//!         _ => Value::error("ERR unknown command"),
//!     };
//!     reply.write(Version::Resp2, &mut out);
//! }
//! assert_eq!(out, b"+OK\r\n$5\r\nhello\r\n");
//!
//! // A client reads a RESP3 map. The same value for a RESP2 client is a
//! // flat array of keys and values.
//! let (reply, used) = Value::parse(b"%1\r\n+role\r\n+master\r\n").unwrap().unwrap();
//! assert_eq!(used, 20);
//! assert_eq!(reply, Value::Map(vec![(Value::simple("role"), Value::simple("master"))]));
//! assert_eq!(reply.to_bytes(Version::Resp2), b"*2\r\n+role\r\n+master\r\n");
//! // Part of a value: the parser waits for the rest.
//! assert_eq!(Value::parse(b"$5\r\nhel"), Ok(None));
//! ```

/// The TCP port Redis servers listen on.
pub const PORT: u16 = 6379;
/// The longest bulk string, bulk error or verbatim string the readers
/// accept by default, in bytes. Redis allows 512 MB, which a world rarely
/// needs, so the default is smaller.
pub const MAX_BULK_LEN: usize = 16 * 1024 * 1024;
/// The most elements one array, set or push, or entries one map or
/// attribute, may have by default. Redis before 7.0 allowed the same
/// number of arguments in a command.
pub const MAX_ELEMENTS: usize = 1024 * 1024;
/// How many aggregates may nest inside each other by default. An
/// attribute counts as one level.
pub const MAX_DEPTH: usize = 32;
/// The longest line by default: the text of a simple string, an error, a
/// number or an inline command, without its type byte and line end. Redis
/// allows inline commands of the same length.
pub const MAX_LINE_LEN: usize = 64 * 1024;
/// The most bytes one whole value or command may take by default. A
/// [`Decoder`] holds at most this many unread bytes, plus one `feed`.
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

/// The byte each type's encoding starts with.
pub mod marker {
    /// A simple string: `+OK\r\n`.
    pub const SIMPLE: u8 = b'+';
    /// A simple error: `-ERR message\r\n`.
    pub const ERROR: u8 = b'-';
    /// An integer: `:1000\r\n`.
    pub const INTEGER: u8 = b':';
    /// A bulk string: `$5\r\nhello\r\n`.
    pub const BULK: u8 = b'$';
    /// An array: `*2\r\n` and two values.
    pub const ARRAY: u8 = b'*';
    /// RESP3 null: `_\r\n`.
    pub const NULL: u8 = b'_';
    /// RESP3 boolean: `#t\r\n` or `#f\r\n`.
    pub const BOOLEAN: u8 = b'#';
    /// RESP3 double: `,1.23\r\n`.
    pub const DOUBLE: u8 = b',';
    /// RESP3 big number: `(12345678901234567890\r\n`.
    pub const BIG_NUMBER: u8 = b'(';
    /// RESP3 bulk error: `!21\r\nSYNTAX invalid syntax\r\n`.
    pub const BULK_ERROR: u8 = b'!';
    /// RESP3 verbatim string: `=15\r\ntxt:Some string\r\n`.
    pub const VERBATIM: u8 = b'=';
    /// RESP3 map: `%1\r\n` and a key and a value.
    pub const MAP: u8 = b'%';
    /// RESP3 attribute: `|1\r\n`, a key and a value, then the value they
    /// describe.
    pub const ATTRIBUTE: u8 = b'|';
    /// RESP3 set: `~2\r\n` and two values.
    pub const SET: u8 = b'~';
    /// RESP3 push: `>2\r\n` and two values.
    pub const PUSH: u8 = b'>';
    /// One chunk of a RESP3 streamed string: `;5\r\nhello\r\n`.
    pub const CHUNK: u8 = b';';
    /// The end of a RESP3 streamed aggregate: `.\r\n`.
    pub const END: u8 = b'.';
}

/// The longest header a writer puts before an aggregate's elements: a
/// type byte, up to 20 digits and a line end.
const HEADER_MAX: usize = 23;

/// Which version of the protocol a writer speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// RESP2, what a connection speaks until the client sends `HELLO 3`.
    Resp2,
    /// RESP3.
    Resp3,
}

/// How much the readers accept. Anything over a limit is a
/// [`ParseError`]. The writers keep to [`Limits::DEFAULT`], so what they
/// write is always read back under the default limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The longest bulk string, bulk error or verbatim string, and the
    /// longest argument of a command, in bytes.
    pub max_bulk_len: usize,
    /// The most elements of one aggregate, or entries of one map.
    pub max_elements: usize,
    /// How many aggregates may nest inside each other.
    pub max_depth: usize,
    /// The longest line, without its type byte and line end.
    pub max_line_len: usize,
    /// The most bytes one whole value or command may take.
    pub max_frame_len: usize,
}

impl Limits {
    /// The limits named by this module's constants.
    pub const DEFAULT: Limits = Limits {
        max_bulk_len: MAX_BULK_LEN,
        max_elements: MAX_ELEMENTS,
        max_depth: MAX_DEPTH,
        max_line_len: MAX_LINE_LEN,
        max_frame_len: MAX_FRAME_LEN,
    };
}

impl Default for Limits {
    fn default() -> Limits {
        Limits::DEFAULT
    }
}

/// One RESP value, of either version. Strings are bytes, since RESP does
/// not say what encoding text is in.
///
/// A streamed string reads as a [`Value::Bulk`] and a streamed aggregate
/// as the plain aggregate, since the result is the same. The writers never
/// stream.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A simple string, such as `OK`. It holds no CR or LF.
    Simple(Vec<u8>),
    /// A simple error, such as `ERR unknown command`. It holds no CR or
    /// LF.
    Error(Vec<u8>),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A bulk string: any bytes.
    Bulk(Vec<u8>),
    /// An array of values.
    Array(Vec<Value>),
    /// No value: RESP3 null, or the RESP2 null bulk string (`$-1`).
    Null,
    /// The RESP2 null array (`*-1`), which Redis sends when, for example,
    /// BLPOP times out. RESP3 writes it as plain null.
    NullArray,
    /// RESP3 boolean.
    Boolean(bool),
    /// RESP3 double.
    Double(f64),
    /// RESP3 big number: an optional sign and decimal digits, as text.
    BigNumber(String),
    /// RESP3 bulk error: an error that may hold any bytes.
    BulkError(Vec<u8>),
    /// RESP3 verbatim string: text with a three-byte format, such as `txt`
    /// or `mkd`.
    Verbatim {
        /// The format, such as `txt`.
        format: [u8; 3],
        /// The text.
        text: Vec<u8>,
    },
    /// RESP3 map: keys and values, in the order they came.
    Map(Vec<(Value, Value)>),
    /// RESP3 set.
    Set(Vec<Value>),
    /// RESP3 push: data the server sends without being asked, such as a
    /// Pub/Sub message.
    Push(Vec<Value>),
    /// RESP3 attribute: extra data about the value that follows it.
    Attribute {
        /// The attribute's keys and values.
        attributes: Vec<(Value, Value)>,
        /// The value they describe.
        value: Box<Value>,
    },
}

/// Why bytes are not RESP. Either way, the stream holds no more values a
/// reader can find, and a server answers with [`ParseError::reply`] and
/// closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A value started with a byte that is no type's marker.
    UnknownType(u8),
    /// A line held a CR not followed by LF, or an LF with no CR before it.
    BadLineEnd,
    /// A line ran past [`Limits::max_line_len`] without ending.
    LineTooLong,
    /// A length or count was not a number this type allows.
    BadLength,
    /// A bulk string, or a command's argument, was longer than
    /// [`Limits::max_bulk_len`].
    BulkTooLong,
    /// An aggregate or a command had more than [`Limits::max_elements`]
    /// elements.
    TooManyElements,
    /// Aggregates nested deeper than [`Limits::max_depth`].
    TooDeep,
    /// A bulk string's data was not followed by CR LF.
    MissingCrlf,
    /// A value of the type with this marker had text that type does not
    /// allow, such as `:12a` or `#x`.
    Malformed(u8),
    /// An element of a command array did not start with `$`, but with
    /// this byte.
    ExpectedBulk(u8),
    /// An inline command had a quote that does not close, or a closing
    /// quote followed by something other than a space.
    UnbalancedQuotes,
    /// A value or command took more than [`Limits::max_frame_len`] bytes.
    FrameTooLarge,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownType(c) => write!(f, "unknown type byte '{}'", c.escape_ascii()),
            ParseError::BadLineEnd => f.write_str("a line ends with a lone CR or LF"),
            ParseError::LineTooLong => f.write_str("too big inline request"),
            ParseError::BadLength => f.write_str("invalid length"),
            ParseError::BulkTooLong => f.write_str("invalid bulk length"),
            ParseError::TooManyElements => f.write_str("invalid multibulk length"),
            ParseError::TooDeep => f.write_str("values nested too deep"),
            ParseError::MissingCrlf => f.write_str("bulk data not followed by CRLF"),
            ParseError::Malformed(c) => write!(f, "malformed value of type '{}'", c.escape_ascii()),
            ParseError::ExpectedBulk(c) => write!(f, "expected '$', got '{}'", c.escape_ascii()),
            ParseError::UnbalancedQuotes => f.write_str("unbalanced quotes in request"),
            ParseError::FrameTooLarge => f.write_str("value too large"),
        }
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    /// The error reply a Redis server sends before it closes the
    /// connection, such as `-ERR Protocol error: invalid bulk length`.
    pub fn reply(self) -> Value {
        Value::Error(format!("ERR Protocol error: {self}").into_bytes())
    }
}

/// Why a reader stopped: it needs at least this many bytes in all, or the
/// bytes are bad.
enum Fail {
    Need(usize),
    Bad(ParseError),
}

impl From<ParseError> for Fail {
    fn from(e: ParseError) -> Fail {
        Fail::Bad(e)
    }
}

type Step<T> = Result<(T, usize), Fail>;

impl Value {
    /// Reads the value at the start of `b` under [`Limits::DEFAULT`]. It
    /// returns `Ok(None)` if `b` holds only part of one, and otherwise the
    /// value and how many bytes of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Value, usize)>, ParseError> {
        Value::parse_with(b, &Limits::DEFAULT)
    }

    /// Reads the value at the start of `b`, as [`Value::parse`] does, under
    /// other limits.
    pub fn parse_with(b: &[u8], limits: &Limits) -> Result<Option<(Value, usize)>, ParseError> {
        finish(value_top(b, limits))
    }

    /// Appends the value's bytes in `version` to `out`.
    ///
    /// RESP2 has no RESP3 types, so it gets what Redis sends a RESP2
    /// client instead: null as `$-1`, a boolean as `:1` or `:0`, a double,
    /// big number or verbatim string as a bulk string, a bulk error as a
    /// simple error, a map as a flat array of keys and values, a set or
    /// push as an array, and an attribute not at all, only the value it
    /// describes.
    ///
    /// The bytes always read back under [`Limits::DEFAULT`], so the writer
    /// cuts what does not fit. A CR or LF in a simple string or error
    /// becomes a space, and the line is cut to [`MAX_LINE_LEN`] bytes. A
    /// bulk string is cut to [`MAX_BULK_LEN`] bytes. An aggregate keeps its
    /// first [`MAX_ELEMENTS`] elements (half that many map entries in
    /// RESP2), and as many as fit in [`MAX_FRAME_LEN`] bytes in all. An
    /// aggregate nested [`MAX_DEPTH`] deep becomes null. A big number that
    /// is not an optional sign and digits is written as 0.
    pub fn write(&self, version: Version, out: &mut Vec<u8>) {
        put(out, self, version, 0, &Limits::DEFAULT, MAX_FRAME_LEN);
    }

    /// The value's bytes in `version`, as [`Value::write`] makes them.
    pub fn to_bytes(&self, version: Version) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(version, &mut out);
        out
    }

    /// The simple string `OK`.
    pub fn ok() -> Value {
        Value::Simple(b"OK".to_vec())
    }

    /// A simple string.
    pub fn simple(s: impl Into<Vec<u8>>) -> Value {
        Value::Simple(s.into())
    }

    /// A simple error. By convention it starts with an upper-case word,
    /// such as `ERR` or `WRONGTYPE`.
    pub fn error(message: &str) -> Value {
        Value::Error(message.as_bytes().to_vec())
    }

    /// A bulk string.
    pub fn bulk(b: impl Into<Vec<u8>>) -> Value {
        Value::Bulk(b.into())
    }

    /// The bytes of a simple string, bulk string or verbatim string's
    /// text, or `None` for any other value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Simple(s) | Value::Bulk(s) => Some(s),
            Value::Verbatim { text, .. } => Some(text),
            _ => None,
        }
    }

    /// The number in an integer, or `None` for any other value.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Whether the value is either kind of null.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null | Value::NullArray)
    }

    /// Whether the value is a simple or bulk error.
    pub fn is_error(&self) -> bool {
        matches!(self, Value::Error(_) | Value::BulkError(_))
    }
}

/// A command, as a client sends it: the command's name and its
/// arguments, each a byte string. `args[0]` is the name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Command {
    /// The name, then the arguments.
    pub args: Vec<Vec<u8>>,
}

impl Command {
    /// A command from its name and arguments, such as
    /// `Command::new(["SET", "key", "value"])`.
    pub fn new<A: AsRef<[u8]>>(args: impl IntoIterator<Item = A>) -> Command {
        Command { args: args.into_iter().map(|a| a.as_ref().to_vec()).collect() }
    }

    /// Reads the command at the start of `b` under [`Limits::DEFAULT`],
    /// the way a Redis server does. Bytes that start with `*` are an array
    /// of bulk strings. Anything else is an inline command: one line,
    /// ended by LF with an optional CR before it, split at spaces, where
    /// double quotes allow the escapes `\n`, `\r`, `\t`, `\b`, `\a`, `\xHH`
    /// and a backslash before any other byte, and single quotes allow
    /// `\'`.
    ///
    /// It returns `Ok(None)` if `b` holds only part of a command, and
    /// otherwise the command and how many bytes of `b` it took. A blank
    /// line, or an array of zero or fewer elements, is a command with no
    /// arguments, which a server ignores.
    pub fn parse(b: &[u8]) -> Result<Option<(Command, usize)>, ParseError> {
        Command::parse_with(b, &Limits::DEFAULT)
    }

    /// Reads the command at the start of `b`, as [`Command::parse`] does,
    /// under other limits.
    pub fn parse_with(b: &[u8], limits: &Limits) -> Result<Option<(Command, usize)>, ParseError> {
        finish(command_top(b, limits))
    }

    /// The command's name in upper case, or `None` for a command with no
    /// arguments. Bytes that are not UTF-8 become U+FFFD.
    pub fn name(&self) -> Option<String> {
        self.args.first().map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
    }

    /// Whether the command's name is `name`, ignoring ASCII case.
    pub fn is(&self, name: &str) -> bool {
        self.args.first().is_some_and(|a| a.eq_ignore_ascii_case(name.as_bytes()))
    }

    /// Argument `i`, where 0 is the name.
    pub fn arg(&self, i: usize) -> Option<&[u8]> {
        self.args.get(i).map(Vec::as_slice)
    }

    /// The command in a value: an array of bulk strings or simple strings.
    /// Any other value gives `None`.
    pub fn from_value(v: &Value) -> Option<Command> {
        let Value::Array(items) = v else { return None };
        let args = items.iter().map(|i| match i {
            Value::Bulk(b) | Value::Simple(b) => Some(b.clone()),
            _ => None,
        });
        Some(Command { args: args.collect::<Option<Vec<_>>>()? })
    }

    /// The command as a value: an array of bulk strings.
    pub fn to_value(&self) -> Value {
        Value::Array(self.args.iter().map(|a| Value::Bulk(a.clone())).collect())
    }

    /// The command's bytes, as a client sends them: an array of bulk
    /// strings. Like [`Value::write`], it keeps to [`Limits::DEFAULT`]: an
    /// argument is cut to [`MAX_BULK_LEN`] bytes, and the command keeps its
    /// first [`MAX_ELEMENTS`] arguments, as many as fit in
    /// [`MAX_FRAME_LEN`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_command(&mut out, &self.args, &Limits::DEFAULT);
        out
    }
}

/// Splits a RESP byte stream into values or commands. Feed it the bytes a
/// connection reads, in order, and take values or commands out until it
/// has none.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the unread bytes in `buf` start.
    start: usize,
    limits: Limits,
    failed: Option<ParseError>,
    /// The fewest unread bytes the last attempt said it needs.
    need: usize,
    /// How far the last attempt checked the value or command it waits
    /// for, so the next one goes on from there.
    scan: Scan,
}

impl Decoder {
    /// A decoder holding no bytes, with the default limits.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// A decoder holding no bytes, with other limits.
    pub fn with_limits(limits: Limits) -> Decoder {
        Decoder { limits, ..Decoder::default() }
    }

    /// Adds bytes read from the connection. After a [`ParseError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole value, if one has come, as a client reads replies.
    /// It returns `None` when it needs more bytes, and keeps returning the
    /// same error once the stream has broken.
    pub fn next_value(&mut self) -> Option<Result<Value, ParseError>> {
        self.take(false, scan_value, value_top)
    }

    /// The next whole command, if one has come, as a server reads
    /// requests. Commands with no arguments are skipped, as Redis skips
    /// them. It returns `None` when it needs more bytes, and keeps
    /// returning the same error once the stream has broken.
    pub fn next_command(&mut self) -> Option<Result<Command, ParseError>> {
        loop {
            match self.take(true, scan_command, command_top) {
                Some(Ok(c)) if c.args.is_empty() => continue,
                other => return other,
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a value.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// The next value or command. A scan that keeps its place checks the
    /// bytes as they come, without building anything, and only once it
    /// finds the whole frame, or a fault, does `parse` read it from the
    /// start. So a large value fed a few bytes at a time is read in linear
    /// time.
    fn take<T>(
        &mut self,
        command: bool,
        scan: fn(&mut Scan, &[u8], &Limits) -> Option<usize>,
        parse: fn(&[u8], &Limits) -> Step<T>,
    ) -> Option<Result<T, ParseError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if self.scan.command != command {
            self.scan = Scan { command, ..Scan::default() };
            self.need = 0;
        }
        let b = frame(&self.buf[self.start..], &self.limits);
        if b.len() < self.need {
            return None;
        }
        if let Some(n) = scan(&mut self.scan, b, &self.limits)
            && n <= self.limits.max_frame_len
        {
            self.need = n;
            return None;
        }
        match parse(b, &self.limits) {
            Ok((v, used)) => {
                self.start += used;
                self.need = 0;
                self.scan = Scan { command, ..Scan::default() };
                Some(Ok(v))
            }
            Err(Fail::Need(n)) => {
                self.need = n;
                None
            }
            Err(Fail::Bad(e)) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                self.need = 0;
                self.scan = Scan::default();
                Some(Err(e))
            }
        }
    }
}

// Reading.

/// How far a [`Decoder`] has checked the value or command it waits for.
/// Positions count from the first unread byte.
#[derive(Debug, Default)]
struct Scan {
    /// Whether this is a command's scan, not a value's.
    command: bool,
    /// Where the next element starts.
    pos: usize,
    /// The aggregates still open, outermost first.
    open: Vec<Open>,
}

#[derive(Debug, Clone, Copy)]
enum Open {
    /// This many elements are still to come.
    Left(usize),
    /// A streamed aggregate and how many elements it has had, keys and
    /// values each counting one.
    Streamed { pairs: bool, seen: usize },
    /// A streamed string and how many bytes it has had.
    Chunks(usize),
}

/// Whether the scan has found a whole frame: one element has ended and
/// no aggregate is open.
enum Scanned {
    More,
    Whole,
}

impl Scan {
    /// One element has ended at `pos`: count it in the aggregate around
    /// it, and close each aggregate that it fills.
    fn ended(&mut self, pos: usize) -> Scanned {
        self.pos = pos;
        loop {
            match self.open.last_mut() {
                None => return Scanned::Whole,
                Some(Open::Left(n)) => {
                    *n -= 1;
                    if *n > 0 {
                        return Scanned::More;
                    }
                    self.open.pop();
                }
                Some(Open::Streamed { seen, .. }) => {
                    *seen += 1;
                    return Scanned::More;
                }
                Some(Open::Chunks(_)) => return Scanned::More,
            }
        }
    }
}

/// Goes on checking a value from where `s` stopped. It returns how many
/// bytes the value needs at least, or `None` when the value is whole or
/// faulty, and the full reader should read it. It follows [`value`] step
/// by step, so the two agree on what needs more bytes.
fn scan_value(s: &mut Scan, b: &[u8], lim: &Limits) -> Option<usize> {
    loop {
        match scan_step(s, b, lim) {
            Ok(Scanned::More) => {}
            Ok(Scanned::Whole) | Err(Fail::Bad(_)) => return None,
            Err(Fail::Need(n)) => return Some(n),
        }
    }
}

/// Checks one element, or one chunk of a streamed string, at `s.pos`.
/// It changes `s` only when the element is whole.
fn scan_step(s: &mut Scan, b: &[u8], lim: &Limits) -> Result<Scanned, Fail> {
    let pos = s.pos;
    match s.open.last().copied() {
        Some(Open::Chunks(len)) => {
            // As streamed_string reads one chunk.
            match b.get(pos) {
                None => return Err(Fail::Need(pos.saturating_add(1))),
                Some(&marker::CHUNK) => {}
                Some(_) => return Err(ParseError::Malformed(marker::BULK).into()),
            }
            let (l, e) = line(b, pos + 1, lim)?;
            let n = digits(l).ok_or(ParseError::BadLength)?;
            if n == 0 {
                s.open.pop();
                return Ok(s.ended(e));
            }
            if n > lim.max_bulk_len.saturating_sub(len) {
                return Err(ParseError::BulkTooLong.into());
            }
            let (_, e) = data(b, e, n, lim)?;
            s.open.pop();
            s.open.push(Open::Chunks(len + n));
            s.pos = e;
            return Ok(Scanned::More);
        }
        Some(Open::Streamed { pairs, seen }) if !pairs || seen % 2 == 0 => {
            // As streamed_list and streamed_pairs check before an element
            // or a key.
            if let Some(e) = stream_end(b, pos, lim)? {
                s.open.pop();
                return Ok(s.ended(e));
            }
            if (if pairs { seen / 2 } else { seen }) >= lim.max_elements {
                return Err(ParseError::TooManyElements.into());
            }
        }
        _ => {}
    }
    let Some(&t) = b.get(pos) else { return Err(Fail::Need(pos.saturating_add(1))) };
    let depth = s.open.len();
    match t {
        marker::ARRAY | marker::SET | marker::PUSH | marker::MAP | marker::ATTRIBUTE => {
            let (l, e) = line(b, pos + 1, lim)?;
            let len = length(l)?;
            if matches!(len, Len::Null) && t == marker::ARRAY {
                return Ok(s.ended(e));
            }
            if depth >= lim.max_depth {
                return Err(ParseError::TooDeep.into());
            }
            let pairs = matches!(t, marker::MAP | marker::ATTRIBUTE);
            let open = match len {
                Len::N(n) if n > lim.max_elements => return Err(ParseError::TooManyElements.into()),
                // An attribute's entries, then the value they describe.
                Len::N(n) if t == marker::ATTRIBUTE => Open::Left(n.saturating_mul(2).saturating_add(1)),
                Len::N(n) if pairs => Open::Left(n.saturating_mul(2)),
                Len::N(n) => Open::Left(n),
                Len::Streamed if t != marker::PUSH && t != marker::ATTRIBUTE => Open::Streamed { pairs, seen: 0 },
                _ => return Err(ParseError::BadLength.into()),
            };
            if matches!(open, Open::Left(0)) {
                return Ok(s.ended(e));
            }
            s.open.push(open);
            s.pos = e;
            Ok(Scanned::More)
        }
        marker::BULK if b.get(pos + 1) == Some(&b'?') => {
            let (l, e) = line(b, pos + 1, lim)?;
            if l != b"?" {
                return Err(ParseError::BadLength.into());
            }
            s.open.push(Open::Chunks(0));
            s.pos = e;
            Ok(Scanned::More)
        }
        // Every other type holds no values, and value reads it whole.
        _ => {
            let (_, e) = value(b, pos, depth, lim)?;
            Ok(s.ended(e))
        }
    }
}

/// Goes on checking a command from where `s` stopped, as [`scan_value`]
/// does a value. Only an array of bulk strings is scanned. An inline
/// command is one line, which [`inline`] reads.
fn scan_command(s: &mut Scan, b: &[u8], lim: &Limits) -> Option<usize> {
    match b.first() {
        None => return Some(1),
        Some(&marker::ARRAY) => {}
        Some(_) => {
            return match inline(b, lim) {
                Err(Fail::Need(n)) => Some(n),
                _ => None,
            };
        }
    }
    if s.open.is_empty() {
        // The count, as multibulk reads it.
        let (l, e) = match line(b, 1, lim) {
            Ok(r) => r,
            Err(Fail::Need(n)) => return Some(n),
            Err(Fail::Bad(_)) => return None,
        };
        let n = if l.first() == Some(&b'+') { None } else { int(l) };
        match n.and_then(|n| usize::try_from(n).ok()) {
            Some(n) if n > 0 && n <= lim.max_elements => {
                s.open.push(Open::Left(n));
                s.pos = e;
            }
            _ => return None,
        }
    }
    while let Some(&Open::Left(left)) = s.open.last() {
        if left == 0 {
            return None;
        }
        let pos = s.pos;
        // One argument, as multibulk reads it.
        let step = match b.get(pos) {
            None => Err(Fail::Need(pos.saturating_add(1))),
            Some(&marker::BULK) => line(b, pos + 1, lim).and_then(|(l, e)| {
                let n = digits(l).ok_or(ParseError::BulkTooLong)?;
                data(b, e, n, lim)
            }),
            Some(_) => return None,
        };
        match step {
            Ok((_, e)) => {
                s.open[0] = Open::Left(left - 1);
                s.pos = e;
            }
            Err(Fail::Need(n)) => return Some(n),
            Err(Fail::Bad(_)) => return None,
        }
    }
    None
}

fn finish<T>(r: Step<T>) -> Result<Option<(T, usize)>, ParseError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Fail::Need(_)) => Ok(None),
        Err(Fail::Bad(e)) => Err(e),
    }
}

/// The bytes a value or command may take: no more than
/// [`Limits::max_frame_len`]. The readers see only these, so what they
/// find does not depend on how many bytes past the limit have come, and
/// one-shot parsing agrees with a [`Decoder`] fed in pieces.
fn frame<'a>(b: &'a [u8], lim: &Limits) -> &'a [u8] {
    &b[..b.len().min(lim.max_frame_len)]
}

/// Holds a whole value or command to [`Limits::max_frame_len`]. A reader
/// that needs bytes past it has found a frame too large.
fn bounded<T>(r: Step<T>, lim: &Limits) -> Step<T> {
    match r {
        Ok((_, end)) if end > lim.max_frame_len => Err(Fail::Bad(ParseError::FrameTooLarge)),
        Err(Fail::Need(n)) if n > lim.max_frame_len => Err(Fail::Bad(ParseError::FrameTooLarge)),
        r => r,
    }
}

fn value_top(b: &[u8], lim: &Limits) -> Step<Value> {
    bounded(value(frame(b, lim), 0, 0, lim), lim)
}

fn command_top(b: &[u8], lim: &Limits) -> Step<Command> {
    bounded(command(frame(b, lim), lim), lim)
}

/// The line starting at `pos`, ended by CR LF, and where the next one
/// starts.
fn line<'a>(b: &'a [u8], pos: usize, lim: &Limits) -> Step<&'a [u8]> {
    let rest = b.get(pos..).unwrap_or(&[]);
    let window = &rest[..rest.len().min(lim.max_line_len.saturating_add(1))];
    match window.iter().position(|&c| c == b'\r' || c == b'\n') {
        Some(i) => {
            if window[i] == b'\n' {
                return Err(ParseError::BadLineEnd.into());
            }
            match rest.get(i + 1) {
                None => Err(Fail::Need(pos.saturating_add(i).saturating_add(2))),
                Some(b'\n') => Ok((&rest[..i], pos + i + 2)),
                Some(_) => Err(ParseError::BadLineEnd.into()),
            }
        }
        None if window.len() > lim.max_line_len => Err(ParseError::LineTooLong.into()),
        None => Err(Fail::Need(b.len().saturating_add(1))),
    }
}

/// `n` bytes of data from `pos`, then CR LF.
fn data<'a>(b: &'a [u8], pos: usize, n: usize, lim: &Limits) -> Step<&'a [u8]> {
    if n > lim.max_bulk_len {
        return Err(ParseError::BulkTooLong.into());
    }
    let end = pos.checked_add(n).ok_or(ParseError::BulkTooLong)?;
    let fin = end.checked_add(2).ok_or(ParseError::BulkTooLong)?;
    if b.len() < fin {
        return Err(Fail::Need(fin));
    }
    if &b[end..fin] != b"\r\n" {
        return Err(ParseError::MissingCrlf.into());
    }
    Ok((&b[pos..end], fin))
}

enum Len {
    Null,
    Streamed,
    N(usize),
}

fn length(l: &[u8]) -> Result<Len, ParseError> {
    match l {
        b"-1" => Ok(Len::Null),
        b"?" => Ok(Len::Streamed),
        _ => digits(l).map(Len::N).ok_or(ParseError::BadLength),
    }
}

/// An unsigned decimal number, at least one digit.
fn digits(l: &[u8]) -> Option<usize> {
    if l.is_empty() {
        return None;
    }
    l.iter().try_fold(0usize, |n, &c| {
        if !c.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(usize::from(c - b'0'))
    })
}

/// A signed decimal 64-bit integer, with an optional `+` or `-`.
fn int(l: &[u8]) -> Option<i64> {
    let (neg, ds) = match l.split_first()? {
        (b'-', r) => (true, r),
        (b'+', r) => (false, r),
        _ => (false, l),
    };
    if ds.is_empty() {
        return None;
    }
    ds.iter().try_fold(0i64, |n, &c| {
        if !c.is_ascii_digit() {
            return None;
        }
        let d = i64::from(c - b'0');
        let n = n.checked_mul(10)?;
        if neg { n.checked_sub(d) } else { n.checked_add(d) }
    })
}

/// How many ASCII digits `l` starts with.
fn leading_digits(l: &[u8]) -> usize {
    l.iter().take_while(|c| c.is_ascii_digit()).count()
}

/// A double, in the grammar the RESP3 specification gives:
/// `[+|-]digits[.digits][(e|E)[+|-]digits]`, or `inf`, `-inf` or `nan`.
/// It also reads the NaN forms the specification asks clients to read
/// from Redis before 7.2, which printed NaN as its C library did: a sign,
/// `nan` in any case, and a sequence in parentheses, as in `-nan` or
/// `nan(ind)`.
fn double(l: &[u8]) -> Option<f64> {
    match l {
        b"inf" | b"+inf" => return Some(f64::INFINITY),
        b"-inf" => return Some(f64::NEG_INFINITY),
        _ if legacy_nan(l) => return Some(f64::NAN),
        _ => {}
    }
    let mut i = usize::from(matches!(l.first(), Some(b'+' | b'-')));
    let n = leading_digits(&l[i..]);
    if n == 0 {
        return None;
    }
    i += n;
    if l.get(i) == Some(&b'.') {
        let n = leading_digits(&l[i + 1..]);
        if n == 0 {
            return None;
        }
        i += 1 + n;
    }
    if matches!(l.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(l.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let n = leading_digits(l.get(i..).unwrap_or(&[]));
        if n == 0 {
            return None;
        }
        i += n;
    }
    if i != l.len() {
        return None;
    }
    std::str::from_utf8(l).ok()?.parse().ok()
}

/// Whether `l` is NaN as C's `printf` writes it: an optional sign, `nan`
/// in any case, then an optional sequence of letters, digits and
/// underscores in parentheses.
fn legacy_nan(l: &[u8]) -> bool {
    let l = match l.first() {
        Some(b'+' | b'-') => &l[1..],
        _ => l,
    };
    let Some((nan, rest)) = l.split_at_checked(3) else { return false };
    if !nan.eq_ignore_ascii_case(b"nan") {
        return false;
    }
    match rest {
        [] => true,
        [b'(', seq @ .., b')'] => seq.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_'),
        _ => false,
    }
}

/// Whether `l` is a big number: an optional sign, then digits.
fn big_ok(l: &[u8]) -> bool {
    let ds = match l.first() {
        Some(b'+' | b'-') => &l[1..],
        _ => l,
    };
    !ds.is_empty() && ds.iter().all(u8::is_ascii_digit)
}

fn value(b: &[u8], pos: usize, depth: usize, lim: &Limits) -> Step<Value> {
    let Some(&t) = b.get(pos) else { return Err(Fail::Need(pos.saturating_add(1))) };
    let p = pos + 1;
    match t {
        marker::SIMPLE | marker::ERROR => {
            let (l, e) = line(b, p, lim)?;
            let v = if t == marker::SIMPLE { Value::Simple(l.to_vec()) } else { Value::Error(l.to_vec()) };
            Ok((v, e))
        }
        marker::INTEGER => {
            let (l, e) = line(b, p, lim)?;
            Ok((Value::Integer(int(l).ok_or(ParseError::Malformed(t))?), e))
        }
        marker::NULL => {
            let (l, e) = line(b, p, lim)?;
            if !l.is_empty() {
                return Err(ParseError::Malformed(t).into());
            }
            Ok((Value::Null, e))
        }
        marker::BOOLEAN => {
            let (l, e) = line(b, p, lim)?;
            let v = match l {
                b"t" => true,
                b"f" => false,
                _ => return Err(ParseError::Malformed(t).into()),
            };
            Ok((Value::Boolean(v), e))
        }
        marker::DOUBLE => {
            let (l, e) = line(b, p, lim)?;
            Ok((Value::Double(double(l).ok_or(ParseError::Malformed(t))?), e))
        }
        marker::BIG_NUMBER => {
            let (l, e) = line(b, p, lim)?;
            if !big_ok(l) {
                return Err(ParseError::Malformed(t).into());
            }
            Ok((Value::BigNumber(l.iter().map(|&c| char::from(c)).collect()), e))
        }
        marker::BULK => {
            let (l, e) = line(b, p, lim)?;
            match length(l)? {
                Len::Null => Ok((Value::Null, e)),
                Len::Streamed => streamed_string(b, e, lim),
                Len::N(n) => {
                    let (d, e) = data(b, e, n, lim)?;
                    Ok((Value::Bulk(d.to_vec()), e))
                }
            }
        }
        marker::BULK_ERROR | marker::VERBATIM => {
            let (l, e) = line(b, p, lim)?;
            let Len::N(n) = length(l)? else { return Err(ParseError::BadLength.into()) };
            let (d, e) = data(b, e, n, lim)?;
            if t == marker::BULK_ERROR {
                return Ok((Value::BulkError(d.to_vec()), e));
            }
            if d.len() < 4 || d[3] != b':' {
                return Err(ParseError::Malformed(t).into());
            }
            Ok((Value::Verbatim { format: [d[0], d[1], d[2]], text: d[4..].to_vec() }, e))
        }
        marker::ARRAY | marker::SET | marker::PUSH => {
            let (l, e) = line(b, p, lim)?;
            let len = length(l)?;
            if matches!(len, Len::Null) {
                return if t == marker::ARRAY { Ok((Value::NullArray, e)) } else { Err(ParseError::BadLength.into()) };
            }
            if depth >= lim.max_depth {
                return Err(ParseError::TooDeep.into());
            }
            let (items, e) = match len {
                Len::N(n) => list(b, e, n, depth, lim)?,
                Len::Streamed if t != marker::PUSH => streamed_list(b, e, depth, lim)?,
                _ => return Err(ParseError::BadLength.into()),
            };
            let v = match t {
                marker::ARRAY => Value::Array(items),
                marker::SET => Value::Set(items),
                _ => Value::Push(items),
            };
            Ok((v, e))
        }
        marker::MAP | marker::ATTRIBUTE => {
            let (l, e) = line(b, p, lim)?;
            let len = length(l)?;
            if depth >= lim.max_depth {
                return Err(ParseError::TooDeep.into());
            }
            let (entries, e) = match len {
                Len::N(n) => pairs(b, e, n, depth, lim)?,
                Len::Streamed if t == marker::MAP => streamed_pairs(b, e, depth, lim)?,
                _ => return Err(ParseError::BadLength.into()),
            };
            if t == marker::MAP {
                return Ok((Value::Map(entries), e));
            }
            let (v, e) = value(b, e, depth + 1, lim)?;
            Ok((Value::Attribute { attributes: entries, value: Box::new(v) }, e))
        }
        _ => Err(ParseError::UnknownType(t).into()),
    }
}

/// A capacity for `n` items of at least `min` bytes each, no more than
/// the bytes left could hold.
fn capacity(b: &[u8], pos: usize, n: usize, min: usize) -> usize {
    n.min(b.len().saturating_sub(pos) / min)
}

fn list(b: &[u8], mut pos: usize, n: usize, depth: usize, lim: &Limits) -> Step<Vec<Value>> {
    if n > lim.max_elements {
        return Err(ParseError::TooManyElements.into());
    }
    let mut items = Vec::with_capacity(capacity(b, pos, n, 3));
    for _ in 0..n {
        let (v, e) = value(b, pos, depth + 1, lim)?;
        items.push(v);
        pos = e;
    }
    Ok((items, pos))
}

fn pairs(b: &[u8], mut pos: usize, n: usize, depth: usize, lim: &Limits) -> Step<Vec<(Value, Value)>> {
    if n > lim.max_elements {
        return Err(ParseError::TooManyElements.into());
    }
    let mut entries = Vec::with_capacity(capacity(b, pos, n, 6));
    for _ in 0..n {
        let (k, e) = value(b, pos, depth + 1, lim)?;
        let (v, e) = value(b, e, depth + 1, lim)?;
        entries.push((k, v));
        pos = e;
    }
    Ok((entries, pos))
}

/// Whether a streamed aggregate ends at `pos`, and where the next value
/// starts if so.
fn stream_end(b: &[u8], pos: usize, lim: &Limits) -> Result<Option<usize>, Fail> {
    match b.get(pos) {
        None => Err(Fail::Need(pos.saturating_add(1))),
        Some(&marker::END) => {
            let (l, e) = line(b, pos + 1, lim)?;
            if !l.is_empty() {
                return Err(ParseError::Malformed(marker::END).into());
            }
            Ok(Some(e))
        }
        Some(_) => Ok(None),
    }
}

fn streamed_list(b: &[u8], mut pos: usize, depth: usize, lim: &Limits) -> Step<Vec<Value>> {
    let mut items = Vec::new();
    loop {
        if let Some(e) = stream_end(b, pos, lim)? {
            return Ok((items, e));
        }
        if items.len() >= lim.max_elements {
            return Err(ParseError::TooManyElements.into());
        }
        let (v, e) = value(b, pos, depth + 1, lim)?;
        items.push(v);
        pos = e;
    }
}

fn streamed_pairs(b: &[u8], mut pos: usize, depth: usize, lim: &Limits) -> Step<Vec<(Value, Value)>> {
    let mut entries = Vec::new();
    loop {
        if let Some(e) = stream_end(b, pos, lim)? {
            return Ok((entries, e));
        }
        if entries.len() >= lim.max_elements {
            return Err(ParseError::TooManyElements.into());
        }
        let (k, e) = value(b, pos, depth + 1, lim)?;
        let (v, e) = value(b, e, depth + 1, lim)?;
        entries.push((k, v));
        pos = e;
    }
}

fn streamed_string(b: &[u8], mut pos: usize, lim: &Limits) -> Step<Value> {
    let mut out = Vec::new();
    loop {
        match b.get(pos) {
            None => return Err(Fail::Need(pos.saturating_add(1))),
            Some(&marker::CHUNK) => {}
            Some(_) => return Err(ParseError::Malformed(marker::BULK).into()),
        }
        let (l, e) = line(b, pos + 1, lim)?;
        let n = digits(l).ok_or(ParseError::BadLength)?;
        if n == 0 {
            return Ok((Value::Bulk(out), e));
        }
        if n > lim.max_bulk_len.saturating_sub(out.len()) {
            return Err(ParseError::BulkTooLong.into());
        }
        let (d, e) = data(b, e, n, lim)?;
        out.extend_from_slice(d);
        pos = e;
    }
}

fn command(b: &[u8], lim: &Limits) -> Step<Command> {
    match b.first() {
        None => Err(Fail::Need(1)),
        Some(&marker::ARRAY) => multibulk(b, lim),
        Some(_) => inline(b, lim),
    }
}

fn multibulk(b: &[u8], lim: &Limits) -> Step<Command> {
    let (l, mut pos) = line(b, 1, lim)?;
    // Redis reads the count with string2ll, which takes a `-` but no `+`.
    let n = if l.first() == Some(&b'+') { None } else { int(l) };
    let n = n.ok_or(ParseError::TooManyElements)?;
    // Redis ignores an array of zero or fewer elements.
    let Ok(n) = usize::try_from(n) else { return Ok((Command::default(), pos)) };
    if n > lim.max_elements {
        return Err(ParseError::TooManyElements.into());
    }
    let mut args = Vec::with_capacity(capacity(b, pos, n, 6));
    for _ in 0..n {
        match b.get(pos) {
            None => return Err(Fail::Need(pos.saturating_add(1))),
            Some(&marker::BULK) => {}
            Some(&c) => return Err(ParseError::ExpectedBulk(c).into()),
        }
        let (l, e) = line(b, pos + 1, lim)?;
        let n = digits(l).ok_or(ParseError::BulkTooLong)?;
        let (d, e) = data(b, e, n, lim)?;
        args.push(d.to_vec());
        pos = e;
    }
    Ok((Command { args }, pos))
}

fn inline(b: &[u8], lim: &Limits) -> Step<Command> {
    // The text may be max_line_len bytes, then CR LF.
    let window = &b[..b.len().min(lim.max_line_len.saturating_add(2))];
    let Some(i) = window.iter().position(|&c| c == b'\n') else {
        // Without an LF, the bytes past the longest text can only be a CR.
        let over = window.len().saturating_sub(lim.max_line_len);
        if over > 1 || (over == 1 && window.last() != Some(&b'\r')) {
            return Err(ParseError::LineTooLong.into());
        }
        return Err(Fail::Need(b.len().saturating_add(1)));
    };
    let text = b[..i].strip_suffix(b"\r").unwrap_or(&b[..i]);
    if text.len() > lim.max_line_len {
        return Err(ParseError::LineTooLong.into());
    }
    let args = split_args(text)?;
    if args.len() > lim.max_elements {
        return Err(ParseError::TooManyElements.into());
    }
    if args.iter().any(|a| a.len() > lim.max_bulk_len) {
        return Err(ParseError::BulkTooLong.into());
    }
    Ok((Command { args }, i + 1))
}

/// Whether `c` is a space as C's `isspace` says.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn hex(c: Option<&u8>) -> Option<u8> {
    let c = *c?;
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Splits an inline command's line into arguments, as Redis's
/// `sdssplitargs` does. Like that C code, it stops at a NUL byte.
fn split_args(text: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
    let text = text.iter().position(|&c| c == 0).map_or(text, |i| &text[..i]);
    let after_quote_ok = |i: usize| text.get(i + 1).is_none_or(|&c| is_space(c));
    let mut args = Vec::new();
    let mut i = 0;
    loop {
        while i < text.len() && is_space(text[i]) {
            i += 1;
        }
        if i == text.len() {
            return Ok(args);
        }
        let mut arg = Vec::new();
        let (mut double, mut single) = (false, false);
        loop {
            let c = text.get(i).copied();
            if double {
                match c {
                    None => return Err(ParseError::UnbalancedQuotes),
                    Some(b'\\') if text.get(i + 1) == Some(&b'x') => {
                        if let (Some(h), Some(l)) = (hex(text.get(i + 2)), hex(text.get(i + 3))) {
                            arg.push(h << 4 | l);
                            i += 4;
                        } else {
                            arg.push(b'x');
                            i += 2;
                        }
                    }
                    Some(b'\\') if i + 1 < text.len() => {
                        arg.push(match text[i + 1] {
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            b'b' => 0x08,
                            b'a' => 0x07,
                            o => o,
                        });
                        i += 2;
                    }
                    Some(b'"') => {
                        if !after_quote_ok(i) {
                            return Err(ParseError::UnbalancedQuotes);
                        }
                        i += 1;
                        break;
                    }
                    Some(o) => {
                        arg.push(o);
                        i += 1;
                    }
                }
            } else if single {
                match c {
                    None => return Err(ParseError::UnbalancedQuotes),
                    Some(b'\\') if text.get(i + 1) == Some(&b'\'') => {
                        arg.push(b'\'');
                        i += 2;
                    }
                    Some(b'\'') => {
                        if !after_quote_ok(i) {
                            return Err(ParseError::UnbalancedQuotes);
                        }
                        i += 1;
                        break;
                    }
                    Some(o) => {
                        arg.push(o);
                        i += 1;
                    }
                }
            } else {
                match c {
                    None | Some(b' ' | b'\n' | b'\r' | b'\t') => break,
                    Some(b'"') => double = true,
                    Some(b'\'') => single = true,
                    Some(o) => arg.push(o),
                }
                i += 1;
            }
        }
        args.push(arg);
    }
}

// Writing.

/// Appends `v` to `out` in at most `budget` bytes, or appends nothing and
/// returns false if it cannot fit.
fn put(out: &mut Vec<u8>, v: &Value, ver: Version, depth: usize, lim: &Limits, budget: usize) -> bool {
    let start = out.len();
    if put_inner(out, v, ver, depth, lim, budget) && out.len() - start <= budget {
        return true;
    }
    out.truncate(start);
    false
}

fn put_inner(out: &mut Vec<u8>, v: &Value, ver: Version, depth: usize, lim: &Limits, budget: usize) -> bool {
    let r3 = ver == Version::Resp3;
    match v {
        Value::Simple(s) => line_out(out, marker::SIMPLE, s, lim),
        Value::Error(s) => line_out(out, marker::ERROR, s, lim),
        Value::Integer(n) => text_out(out, marker::INTEGER, &n.to_string()),
        Value::Bulk(d) => bulk_out(out, marker::BULK, d, lim),
        Value::Null | Value::NullArray if r3 => out.extend_from_slice(b"_\r\n"),
        Value::Null => out.extend_from_slice(b"$-1\r\n"),
        Value::NullArray => out.extend_from_slice(b"*-1\r\n"),
        Value::Boolean(x) => out.extend_from_slice(match (r3, x) {
            (true, true) => b"#t\r\n",
            (true, false) => b"#f\r\n",
            (false, true) => b":1\r\n",
            (false, false) => b":0\r\n",
        }),
        Value::Double(f) => {
            let s = fmt_double(*f);
            if r3 { text_out(out, marker::DOUBLE, &s) } else { bulk_out(out, marker::BULK, s.as_bytes(), lim) }
        }
        Value::BigNumber(s) => {
            let s = if big_ok(s.as_bytes()) && s.len() <= lim.max_line_len { s.as_str() } else { "0" };
            if r3 { text_out(out, marker::BIG_NUMBER, s) } else { bulk_out(out, marker::BULK, s.as_bytes(), lim) }
        }
        Value::BulkError(e) if r3 => bulk_out(out, marker::BULK_ERROR, e, lim),
        Value::BulkError(e) => line_out(out, marker::ERROR, e, lim),
        Value::Verbatim { format, text } if r3 && lim.max_bulk_len >= 4 => {
            let text = &text[..text.len().min(lim.max_bulk_len - 4)];
            text_out(out, marker::VERBATIM, &(text.len() + 4).to_string());
            out.extend_from_slice(format);
            out.push(b':');
            out.extend_from_slice(text);
            out.extend_from_slice(b"\r\n");
        }
        Value::Verbatim { text, .. } => bulk_out(out, marker::BULK, text, lim),
        Value::Array(items) => return list_out(out, marker::ARRAY, items, ver, depth, lim, budget),
        Value::Set(items) => {
            let m = if r3 { marker::SET } else { marker::ARRAY };
            return list_out(out, m, items, ver, depth, lim, budget);
        }
        Value::Push(items) => {
            let m = if r3 { marker::PUSH } else { marker::ARRAY };
            return list_out(out, m, items, ver, depth, lim, budget);
        }
        Value::Map(entries) => {
            let m = if r3 { marker::MAP } else { marker::ARRAY };
            return pairs_out(out, m, entries, ver, depth, lim, budget);
        }
        Value::Attribute { attributes, value } => {
            if depth >= lim.max_depth {
                null_out(out, ver);
                return true;
            }
            if !r3 {
                return put(out, value, ver, depth + 1, lim, budget);
            }
            let start = out.len();
            if !pairs_out(out, marker::ATTRIBUTE, attributes, ver, depth, lim, budget) {
                return false;
            }
            let used = out.len() - start;
            return put(out, value, ver, depth + 1, lim, budget.saturating_sub(used));
        }
    }
    true
}

fn null_out(out: &mut Vec<u8>, ver: Version) {
    out.extend_from_slice(if ver == Version::Resp3 { b"_\r\n" } else { b"$-1\r\n" });
}

/// A line of text with no CR or LF in it.
fn text_out(out: &mut Vec<u8>, m: u8, s: &str) {
    out.push(m);
    out.extend_from_slice(s.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// A line of any bytes: CR and LF become spaces, and it is cut to the
/// line limit.
fn line_out(out: &mut Vec<u8>, m: u8, s: &[u8], lim: &Limits) {
    out.push(m);
    out.extend(s.iter().take(lim.max_line_len).map(|&c| if c == b'\r' || c == b'\n' { b' ' } else { c }));
    out.extend_from_slice(b"\r\n");
}

fn bulk_out(out: &mut Vec<u8>, m: u8, d: &[u8], lim: &Limits) {
    let d = &d[..d.len().min(lim.max_bulk_len)];
    text_out(out, m, &d.len().to_string());
    out.extend_from_slice(d);
    out.extend_from_slice(b"\r\n");
}

fn header_at(out: &mut Vec<u8>, at: usize, m: u8, n: usize) {
    let mut h = vec![m];
    h.extend_from_slice(n.to_string().as_bytes());
    h.extend_from_slice(b"\r\n");
    out.splice(at..at, h);
}

fn list_out(
    out: &mut Vec<u8>,
    m: u8,
    items: &[Value],
    ver: Version,
    depth: usize,
    lim: &Limits,
    budget: usize,
) -> bool {
    if depth >= lim.max_depth {
        null_out(out, ver);
        return true;
    }
    let start = out.len();
    let room = budget.saturating_sub(HEADER_MAX);
    let mut n = 0;
    for item in items.iter().take(lim.max_elements) {
        let left = room.saturating_sub(out.len() - start);
        if !put(out, item, ver, depth + 1, lim, left) {
            break;
        }
        n += 1;
    }
    header_at(out, start, m, n);
    true
}

/// Map or attribute entries. Under the array marker (a RESP2 map) they
/// are a flat array of keys and values.
fn pairs_out(
    out: &mut Vec<u8>,
    m: u8,
    entries: &[(Value, Value)],
    ver: Version,
    depth: usize,
    lim: &Limits,
    budget: usize,
) -> bool {
    if depth >= lim.max_depth {
        null_out(out, ver);
        return true;
    }
    let flat = m == marker::ARRAY;
    let max = if flat { lim.max_elements / 2 } else { lim.max_elements };
    let start = out.len();
    let room = budget.saturating_sub(HEADER_MAX);
    let mut n = 0;
    for (k, v) in entries.iter().take(max) {
        let mark = out.len();
        let fits = put(out, k, ver, depth + 1, lim, room.saturating_sub(mark - start))
            && put(out, v, ver, depth + 1, lim, room.saturating_sub(out.len() - start));
        if !fits {
            out.truncate(mark);
            break;
        }
        n += 1;
    }
    header_at(out, start, m, if flat { n * 2 } else { n });
    true
}

fn put_command(out: &mut Vec<u8>, args: &[Vec<u8>], lim: &Limits) {
    let start = out.len();
    let room = lim.max_frame_len.saturating_sub(HEADER_MAX);
    let mut n = 0;
    for a in args.iter().take(lim.max_elements) {
        let mark = out.len();
        bulk_out(out, marker::BULK, a, lim);
        if out.len() - start > room {
            out.truncate(mark);
            break;
        }
        n += 1;
    }
    header_at(out, start, marker::ARRAY, n);
}

/// A double as RESP3 writes it. Rust prints the shortest digits that read
/// back to the same number, and never an exponent.
fn fmt_double(f: f64) -> String {
    if f.is_nan() {
        "nan".to_string()
    } else if f.is_infinite() {
        if f > 0.0 { "inf" } else { "-inf" }.to_string()
    } else {
        format!("{f}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(b: &[u8]) -> Value {
        let (v, used) = Value::parse(b).unwrap().unwrap();
        assert_eq!(used, b.len(), "{:?}", b.escape_ascii().to_string());
        v
    }

    fn s(x: &str) -> Value {
        Value::simple(x)
    }

    fn bulk(x: &str) -> Value {
        Value::bulk(x)
    }

    /// Every example of a whole value in the RESP and RESP3 specifications,
    /// and a few more.
    const VALID: &[&[u8]] = &[
        b"+OK\r\n",
        b"-Error message\r\n",
        b"-ERR unknown command 'asdf'\r\n",
        b":0\r\n",
        b":1000\r\n",
        b":-1000\r\n",
        b":+5\r\n",
        b"$5\r\nhello\r\n",
        b"$0\r\n\r\n",
        b"$-1\r\n",
        b"*0\r\n",
        b"*-1\r\n",
        b"*2\r\n$5\r\nhello\r\n$5\r\nworld\r\n",
        b"*3\r\n:1\r\n:2\r\n:3\r\n",
        b"*5\r\n:1\r\n:2\r\n:3\r\n:4\r\n$5\r\nhello\r\n",
        b"*2\r\n*3\r\n:1\r\n:2\r\n:3\r\n*2\r\n+Hello\r\n-World\r\n",
        b"*3\r\n$5\r\nhello\r\n$-1\r\n$5\r\nworld\r\n",
        b"_\r\n",
        b"#t\r\n",
        b"#f\r\n",
        b",1.23\r\n",
        b",10\r\n",
        b",inf\r\n",
        b",-inf\r\n",
        b",nan\r\n",
        b",-1.5e-3\r\n",
        b"(3492890328409238509324850943850943825024385\r\n",
        b"!21\r\nSYNTAX invalid syntax\r\n",
        b"=15\r\ntxt:Some string\r\n",
        b"%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n",
        b"~2\r\n+a\r\n:1\r\n",
        b">4\r\n+pubsub\r\n+message\r\n+somechannel\r\n+this is the message\r\n",
        b"|1\r\n+key-popularity\r\n%2\r\n$1\r\na\r\n,0.1923\r\n$1\r\nb\r\n,0.0012\r\n*2\r\n:2039123\r\n:9543892\r\n",
        b"*3\r\n:1\r\n:2\r\n|1\r\n+ttl\r\n:3600\r\n:3\r\n",
        b"$?\r\n;5\r\nHello\r\n;6\r\n world\r\n;0\r\n",
        b"*?\r\n:1\r\n:2\r\n:3\r\n.\r\n",
        b"~?\r\n.\r\n",
        b"%?\r\n+a\r\n:1\r\n+b\r\n:2\r\n.\r\n",
    ];

    #[test]
    fn resp2_examples() {
        assert_eq!(one(b"+OK\r\n"), Value::ok());
        assert_eq!(one(b"-Error message\r\n"), Value::error("Error message"));
        assert_eq!(one(b":1000\r\n"), Value::Integer(1000));
        assert_eq!(one(b":-1000\r\n"), Value::Integer(-1000));
        assert_eq!(one(b"$5\r\nhello\r\n"), bulk("hello"));
        assert_eq!(one(b"$0\r\n\r\n"), bulk(""));
        assert_eq!(one(b"$-1\r\n"), Value::Null);
        assert_eq!(one(b"*-1\r\n"), Value::NullArray);
        assert_eq!(one(b"*0\r\n"), Value::Array(vec![]));
        assert_eq!(one(b"*2\r\n$5\r\nhello\r\n$5\r\nworld\r\n"), Value::Array(vec![bulk("hello"), bulk("world")]));
        let nested = Value::Array(vec![
            Value::Array(vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]),
            Value::Array(vec![s("Hello"), Value::error("World")]),
        ]);
        assert_eq!(one(VALID[15]), nested);
        assert_eq!(nested.to_bytes(Version::Resp2), VALID[15]);
        let with_null = one(VALID[16]);
        assert_eq!(with_null, Value::Array(vec![bulk("hello"), Value::Null, bulk("world")]));
        assert_eq!(with_null.to_bytes(Version::Resp2), VALID[16]);
        assert_eq!(Value::NullArray.to_bytes(Version::Resp2), b"*-1\r\n");
        // Extremes of a 64-bit integer.
        assert_eq!(one(b":-9223372036854775808\r\n"), Value::Integer(i64::MIN));
        assert_eq!(one(b":9223372036854775807\r\n"), Value::Integer(i64::MAX));
    }

    #[test]
    fn resp3_examples() {
        assert_eq!(one(b"_\r\n"), Value::Null);
        assert_eq!(one(b"#t\r\n"), Value::Boolean(true));
        assert_eq!(one(b"#f\r\n"), Value::Boolean(false));
        assert_eq!(one(b",1.23\r\n"), Value::Double(1.23));
        assert_eq!(one(b",10\r\n"), Value::Double(10.0));
        assert_eq!(one(b",inf\r\n"), Value::Double(f64::INFINITY));
        assert_eq!(one(b",-inf\r\n"), Value::Double(f64::NEG_INFINITY));
        let Value::Double(nan) = one(b",nan\r\n") else { panic!() };
        assert!(nan.is_nan());
        assert_eq!(one(b",-1.5e-3\r\n"), Value::Double(-0.0015));
        assert_eq!(one(VALID[26]), Value::BigNumber("3492890328409238509324850943850943825024385".into()));
        assert_eq!(one(VALID[27]), Value::BulkError(b"SYNTAX invalid syntax".to_vec()));
        let verbatim = Value::Verbatim { format: *b"txt", text: b"Some string".to_vec() };
        assert_eq!(one(VALID[28]), verbatim);
        assert_eq!(one(VALID[29]), Value::Map(vec![(s("first"), Value::Integer(1)), (s("second"), Value::Integer(2))]));
        assert_eq!(one(VALID[30]), Value::Set(vec![s("a"), Value::Integer(1)]));
        assert_eq!(
            one(VALID[31]),
            Value::Push(vec![s("pubsub"), s("message"), s("somechannel"), s("this is the message")])
        );
        let popularity = Value::Attribute {
            attributes: vec![(
                s("key-popularity"),
                Value::Map(vec![(bulk("a"), Value::Double(0.1923)), (bulk("b"), Value::Double(0.0012))]),
            )],
            value: Box::new(Value::Array(vec![Value::Integer(2039123), Value::Integer(9543892)])),
        };
        assert_eq!(one(VALID[32]), popularity);
        assert_eq!(popularity.to_bytes(Version::Resp3), VALID[32]);
        // An attribute inside an array describes one element and is not one.
        let Value::Array(items) = one(VALID[33]) else { panic!() };
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[2],
            Value::Attribute { attributes: vec![(s("ttl"), Value::Integer(3600))], value: Box::new(Value::Integer(3)) }
        );
        // Streamed forms read as the plain ones.
        assert_eq!(one(VALID[34]), bulk("Hello world"));
        assert_eq!(one(VALID[35]), Value::Array(vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)]));
        assert_eq!(one(VALID[36]), Value::Set(vec![]));
        assert_eq!(one(VALID[37]), Value::Map(vec![(s("a"), Value::Integer(1)), (s("b"), Value::Integer(2))]));
    }

    #[test]
    fn writers_match_the_specification() {
        for (v, r2, r3) in [
            (Value::Null, &b"$-1\r\n"[..], &b"_\r\n"[..]),
            (Value::Boolean(true), b":1\r\n", b"#t\r\n"),
            (Value::Double(1.23), b"$4\r\n1.23\r\n", b",1.23\r\n"),
            (Value::Double(f64::NEG_INFINITY), b"$4\r\n-inf\r\n", b",-inf\r\n"),
            (Value::Double(f64::NAN), b"$3\r\nnan\r\n", b",nan\r\n"),
            (Value::BigNumber("-12".into()), b"$3\r\n-12\r\n", b"(-12\r\n"),
            (Value::BulkError(b"SYNTAX invalid syntax".to_vec()), b"-SYNTAX invalid syntax\r\n", VALID[27]),
            (Value::Verbatim { format: *b"txt", text: b"Some string".to_vec() }, b"$11\r\nSome string\r\n", VALID[28]),
            (Value::Map(vec![(s("first"), Value::Integer(1))]), b"*2\r\n+first\r\n:1\r\n", b"%1\r\n+first\r\n:1\r\n"),
            (Value::Set(vec![Value::Integer(1)]), b"*1\r\n:1\r\n", b"~1\r\n:1\r\n"),
            (Value::Push(vec![Value::Integer(1)]), b"*1\r\n:1\r\n", b">1\r\n:1\r\n"),
            (
                Value::Attribute { attributes: vec![(s("ttl"), Value::Integer(1))], value: Box::new(Value::ok()) },
                b"+OK\r\n",
                b"|1\r\n+ttl\r\n:1\r\n+OK\r\n",
            ),
        ] {
            assert_eq!(v.to_bytes(Version::Resp2), r2, "{v:?}");
            assert_eq!(v.to_bytes(Version::Resp3), r3, "{v:?}");
        }
    }

    #[test]
    fn commands() {
        let (c, used) = Command::parse(b"*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n").unwrap().unwrap();
        assert_eq!(used, 26);
        assert_eq!(c, Command::new(["LLEN", "mylist"]));
        assert_eq!(c.name().as_deref(), Some("LLEN"));
        assert!(c.is("llen"));
        assert_eq!(c.arg(1), Some(&b"mylist"[..]));
        assert_eq!(c.arg(2), None);
        assert_eq!(c.to_bytes(), b"*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n");
        assert_eq!(Command::from_value(&c.to_value()), Some(c));
        assert_eq!(Command::from_value(&Value::Array(vec![Value::Integer(1)])), None);
        assert_eq!(Command::from_value(&s("PING")), None);
        // Inline, with LF alone or CR LF.
        assert_eq!(Command::parse(b"PING\r\n"), Ok(Some((Command::new(["PING"]), 6))));
        assert_eq!(Command::parse(b"EXISTS  somekey\n"), Ok(Some((Command::new(["EXISTS", "somekey"]), 16))));
        // Quotes and escapes, as sdssplitargs reads them.
        let (c, _) = Command::parse(b"SET k \"a b\\x41\\n\\\"\" 'it\\'s' x\"y z\"\r\n").unwrap().unwrap();
        assert_eq!(c.args, [&b"SET"[..], b"k", b"a bA\n\"", b"it's", b"xy z"]);
        let (c, _) = Command::parse(b"ECHO \"\\xZZ\\q\" ''\n").unwrap().unwrap();
        assert_eq!(c.args, [&b"ECHO"[..], b"xZZq", b""]);
        // Blank lines and empty arrays are commands with no arguments.
        assert_eq!(Command::parse(b" \r\n"), Ok(Some((Command::default(), 3))));
        assert_eq!(Command::parse(b"*0\r\n"), Ok(Some((Command::default(), 4))));
        assert_eq!(Command::parse(b"*-1\r\n"), Ok(Some((Command::default(), 5))));
        // A NUL ends the line's text, as in C.
        assert_eq!(Command::parse(b"GET a\0b\n").unwrap().unwrap().0, Command::new(["GET", "a"]));
    }

    #[test]
    fn value_errors() {
        let lim = Limits { max_bulk_len: 8, max_elements: 3, max_depth: 2, max_line_len: 10, max_frame_len: 40 };
        let bad = |b: &[u8]| Value::parse_with(b, &lim).err().unwrap_or_else(|| panic!("{} parsed", b.escape_ascii()));
        assert_eq!(bad(b"x\r\n"), ParseError::UnknownType(b'x'));
        assert_eq!(bad(b".\r\n"), ParseError::UnknownType(b'.'));
        assert_eq!(bad(b"+OK\rX"), ParseError::BadLineEnd);
        assert_eq!(bad(b"+OK\n"), ParseError::BadLineEnd);
        assert_eq!(bad(b"+01234567890"), ParseError::LineTooLong);
        assert!(Value::parse_with(b"+0123456789", &lim).unwrap().is_none());
        assert_eq!(bad(b"$-2\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"$x\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"$\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"!-1\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"=?\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"~-1\r\n"), ParseError::BadLength);
        assert_eq!(bad(b">?\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"|?\r\n"), ParseError::BadLength);
        assert_eq!(Value::parse(b"$99999999999999999999999\r\n"), Err(ParseError::BadLength));
        assert_eq!(bad(b"$9\r\n"), ParseError::BulkTooLong);
        assert_eq!(bad(b"$?\r\n;5\r\nabcde\r\n;5\r\n"), ParseError::BulkTooLong);
        assert_eq!(bad(b"$?\r\n;x\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"$?\r\n+"), ParseError::Malformed(b'$'));
        assert_eq!(bad(b"*4\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"%4\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"*?\r\n_\r\n_\r\n_\r\n_\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"%?\r\n_\r\n_\r\n_\r\n_\r\n_\r\n_\r\n_\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"*1\r\n*1\r\n*1\r\n"), ParseError::TooDeep);
        assert_eq!(bad(b"|1\r\n_\r\n_\r\n|1\r\n_\r\n_\r\n|1\r\n"), ParseError::TooDeep);
        assert_eq!(bad(b"$2\r\nabXY"), ParseError::MissingCrlf);
        assert_eq!(Value::parse(b"$2\r\nabX"), Ok(None));
        assert_eq!(bad(b"$2\r\nab\rX"), ParseError::MissingCrlf);
        for (b, t) in [
            (&b":12a\r\n"[..], b':'),
            (b":\r\n", b':'),
            (b":-\r\n", b':'),
            (b"_x\r\n", b'_'),
            (b"#x\r\n", b'#'),
            (b",1.\r\n", b','),
            (b",.5\r\n", b','),
            (b",1e\r\n", b','),
            (b",Infinity\r\n", b','),
            (b"(1.5\r\n", b'('),
            (b"(-\r\n", b'('),
            (b"=3\r\ntxt\r\n", b'='),
            (b"=4\r\ntxt;\r\n", b'='),
            (b"*?\r\n.x\r\n", b'.'),
        ] {
            assert_eq!(bad(b), ParseError::Malformed(t), "{}", b.escape_ascii());
        }
        // One past the largest 64-bit integer.
        assert_eq!(Value::parse(b":9223372036854775808\r\n"), Err(ParseError::Malformed(b':')));
        assert_eq!(Value::parse(b":-9223372036854775809\r\n"), Err(ParseError::Malformed(b':')));
        let frame = Limits { max_frame_len: 10, ..Limits::DEFAULT };
        assert_eq!(Value::parse_with(b"$8\r\n", &frame), Err(ParseError::FrameTooLarge));
        assert_eq!(Value::parse_with(b"+0123456789\r\n", &frame), Err(ParseError::FrameTooLarge));
        assert_eq!(Value::parse_with(b"+0123456789", &frame), Err(ParseError::FrameTooLarge));
        assert_eq!(Value::parse_with(b"+0123456\r\n", &frame).unwrap().unwrap().1, 10);
        assert!(ParseError::BulkTooLong.reply() == Value::error("ERR Protocol error: invalid bulk length"));
    }

    #[test]
    fn command_errors() {
        let lim = Limits { max_bulk_len: 8, max_elements: 3, max_depth: 2, max_line_len: 10, max_frame_len: 40 };
        let bad =
            |b: &[u8]| Command::parse_with(b, &lim).err().unwrap_or_else(|| panic!("{} parsed", b.escape_ascii()));
        assert_eq!(bad(b"*1\r\n:1\r\n"), ParseError::ExpectedBulk(b':'));
        assert_eq!(bad(b"*x\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"*4\r\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"*1\r\n$-1\r\n"), ParseError::BulkTooLong);
        assert_eq!(bad(b"*1\r\n$9\r\n"), ParseError::BulkTooLong);
        assert_eq!(bad(b"*1\r\n$1\r\naXY"), ParseError::MissingCrlf);
        assert_eq!(bad(b"*1\n"), ParseError::BadLineEnd);
        assert_eq!(bad(b"a b c d e\n"), ParseError::TooManyElements);
        assert_eq!(bad(b"01234567890"), ParseError::LineTooLong);
        assert_eq!(bad(b"\"abc\n"), ParseError::UnbalancedQuotes);
        assert_eq!(bad(b"'abc\n"), ParseError::UnbalancedQuotes);
        assert_eq!(bad(b"\"a\"b\n"), ParseError::UnbalancedQuotes);
        assert_eq!(bad(b"'a'b\n"), ParseError::UnbalancedQuotes);
        assert_eq!(bad(b"\"a\\\n"), ParseError::UnbalancedQuotes);
        let frame = Limits { max_frame_len: 12, ..Limits::DEFAULT };
        assert_eq!(Command::parse_with(b"*1\r\n$20\r\n", &frame), Err(ParseError::FrameTooLarge));
        assert_eq!(
            ParseError::UnbalancedQuotes.reply(),
            Value::error("ERR Protocol error: unbalanced quotes in request")
        );
        assert_eq!(ParseError::ExpectedBulk(b':').to_string(), "expected '$', got ':'");
    }

    /// The lower bound on bytes needed that a truncated input reports.
    fn need(r: Step<impl Sized>) -> Option<usize> {
        match r {
            Err(Fail::Need(n)) => Some(n),
            _ => None,
        }
    }

    #[test]
    fn every_prefix_needs_more() {
        let commands: &[&[u8]] = &[b"*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n", b"SET k \"v w\"\r\n", b"PING\n"];
        for full in VALID {
            for n in 0..full.len() {
                assert_eq!(Value::parse(&full[..n]), Ok(None), "{} at {n}", full.escape_ascii());
                let hint = need(value_top(&full[..n], &Limits::DEFAULT)).unwrap();
                assert!(hint > n && hint <= full.len(), "{} at {n}: {hint}", full.escape_ascii());
            }
        }
        for full in commands {
            for n in 0..full.len() {
                assert_eq!(Command::parse(&full[..n]), Ok(None), "{} at {n}", full.escape_ascii());
                let hint = need(command_top(&full[..n], &Limits::DEFAULT)).unwrap();
                assert!(hint > n && hint <= full.len());
            }
            assert!(Command::parse(full).unwrap().is_some());
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let stream: Vec<u8> = VALID.concat();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(v) = d.next_value() {
                got.push(v.unwrap());
            }
        }
        assert_eq!(got.len(), VALID.len());
        assert_eq!(d.buffered(), 0);
        // All at once.
        let mut d = Decoder::new();
        d.feed(&stream);
        assert_eq!(std::iter::from_fn(|| d.next_value()).count(), VALID.len());
        // A broken stream stays broken.
        d.feed(b"+OK\n");
        assert_eq!(d.next_value(), Some(Err(ParseError::BadLineEnd)));
        d.feed(b"+OK\r\n");
        assert_eq!(d.next_value(), Some(Err(ParseError::BadLineEnd)));
        assert_eq!(d.buffered(), 0);
        // A frame over the limit is refused before it all comes.
        let mut d = Decoder::with_limits(Limits { max_frame_len: 100, ..Limits::DEFAULT });
        d.feed(b"$1000\r\n");
        assert_eq!(d.next_value(), Some(Err(ParseError::FrameTooLarge)));
        let mut d = Decoder::with_limits(Limits { max_frame_len: 100, ..Limits::DEFAULT });
        // A line of 98 bytes and its CR LF would fit; one more byte cannot.
        d.feed(&[b'+'; 99]);
        assert_eq!(d.next_value(), None);
        d.feed(b"+");
        assert_eq!(d.next_value(), Some(Err(ParseError::FrameTooLarge)));
    }

    #[test]
    fn decoder_reads_commands() {
        let mut d = Decoder::new();
        let stream = b"\r\n*0\r\nPING\r\n*1\r\n$4\r\nQUIT\r\n  \n";
        for byte in stream {
            d.feed(std::slice::from_ref(byte));
        }
        assert_eq!(d.next_command(), Some(Ok(Command::new(["PING"]))));
        assert_eq!(d.next_command(), Some(Ok(Command::new(["QUIT"]))));
        assert_eq!(d.next_command(), None);
        assert_eq!(d.buffered(), 0);
        // A big bulk string waits for its bytes without parsing again.
        d.feed(b"*1\r\n$10\r\n01234");
        assert_eq!(d.next_command(), None);
        assert_eq!(d.need, 21);
        d.feed(b"56789\r\n");
        assert_eq!(d.next_command(), Some(Ok(Command::new(["0123456789"]))));
        d.feed(b"*1\r\n+PING\r\n");
        assert_eq!(d.next_command(), Some(Err(ParseError::ExpectedBulk(b'+'))));
        assert_eq!(d.next_command(), Some(Err(ParseError::ExpectedBulk(b'+'))));
    }

    fn encode_with(v: &Value, ver: Version, lim: &Limits) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, v, ver, 0, lim, lim.max_frame_len);
        out
    }

    #[test]
    fn writers_cut_what_does_not_fit() {
        // Lines lose CR and LF.
        assert_eq!(s("a\r\nb").to_bytes(Version::Resp2), b"+a  b\r\n");
        assert_eq!(Value::BulkError(b"x\ny".to_vec()).to_bytes(Version::Resp2), b"-x y\r\n");
        assert_eq!(Value::BigNumber("12x".into()).to_bytes(Version::Resp3), b"(0\r\n");
        let long = s(&"a".repeat(MAX_LINE_LEN + 10)).to_bytes(Version::Resp3);
        assert_eq!(long.len(), MAX_LINE_LEN + 3);
        assert!(Value::parse(&long).unwrap().is_some());
        // Deep nesting becomes null.
        let mut deep = Value::Integer(1);
        for _ in 0..MAX_DEPTH + 5 {
            deep = Value::Array(vec![deep]);
        }
        for ver in [Version::Resp2, Version::Resp3] {
            assert!(Value::parse(&deep.to_bytes(ver)).unwrap().is_some());
        }
        let lim = Limits { max_bulk_len: 10, max_elements: 4, max_depth: 3, max_line_len: 400, max_frame_len: 100 };
        let ten: Vec<Value> = (0..10).map(|_| bulk("0123456789abc")).collect();
        for ver in [Version::Resp2, Version::Resp3] {
            let out = encode_with(&Value::Array(ten.clone()), ver, &lim);
            let (v, _) = Value::parse_with(&out, &lim).unwrap().unwrap();
            assert_eq!(v, Value::Array(vec![bulk("0123456789"); 4]));
            // The frame limit keeps fewer.
            let small = Limits { max_frame_len: 50, ..lim };
            let out = encode_with(&Value::Array(ten.clone()), ver, &small);
            assert!(out.len() <= 50);
            assert_eq!(Value::parse_with(&out, &small).unwrap().unwrap().0, Value::Array(vec![bulk("0123456789")]));
            // Maps keep whole entries, half as many in RESP2.
            let map = Value::Map((0..10).map(|i| (Value::Integer(i), Value::Integer(i))).collect());
            let (v, _) = Value::parse_with(&encode_with(&map, ver, &lim), &lim).unwrap().unwrap();
            match v {
                Value::Map(e) => assert_eq!(e.len(), 4),
                Value::Array(e) => assert_eq!(e.len(), 4),
                _ => panic!(),
            }
            let mut deep = Value::Integer(1);
            for _ in 0..5 {
                deep = Value::Set(vec![deep]);
            }
            assert!(Value::parse_with(&encode_with(&deep, ver, &lim), &lim).unwrap().is_some());
        }
        let mut out = Vec::new();
        put_command(&mut out, &Command::new(["a"; 10]).args, &lim);
        assert_eq!(Command::parse_with(&out, &lim).unwrap().unwrap().0.args.len(), 4);
        // An attribute whose value does not fit is left out whole.
        let tiny = Limits { max_frame_len: 30, ..lim };
        let attr = Value::Array(vec![
            Value::Integer(1),
            Value::Attribute { attributes: vec![(s("k"), s("v"))], value: Box::new(bulk("0123456789")) },
        ]);
        assert_eq!(encode_with(&attr, Version::Resp3, &tiny), b"*1\r\n:1\r\n");
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
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            (0..self.below(max + 1)).map(|_| self.next() as u8).collect()
        }
    }

    /// A random value. With `resp2`, only RESP2 types, the null array
    /// among them. Without, never the null array, which RESP3 writes as
    /// plain null.
    fn random(r: &mut Lcg, depth: usize, resp2: bool) -> Value {
        let kinds = if resp2 { 7 } else { 16 };
        let k = r.below(if depth >= 4 { 7 } else { kinds });
        let k = if resp2 { [0, 1, 2, 3, 5, 4, 6][k] } else { k };
        let line =
            |r: &mut Lcg| r.bytes(8).into_iter().map(|c| if c == b'\r' || c == b'\n' { b'x' } else { c }).collect();
        match k {
            0 => Value::Simple(line(r)),
            1 => Value::Error(line(r)),
            2 => Value::Integer(r.next() as i64 - (1 << 30)),
            3 => Value::Bulk(r.bytes(12)),
            4 => Value::Null,
            5 if resp2 => Value::NullArray,
            5 => Value::Boolean(r.below(2) == 1),
            6 if resp2 => Value::Array((0..r.below(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            6 => Value::Double([0.0, -1.5, 1e300, 1e-300, f64::INFINITY, 0.1][r.below(6)]),
            7 => Value::BigNumber(format!("{}{}", ["", "-", "+"][r.below(3)], r.next())),
            8 => Value::BulkError(r.bytes(12)),
            9 => Value::Verbatim { format: *b"mkd", text: r.bytes(12) },
            10 => Value::Array((0..r.below(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            11 => Value::Set((0..r.below(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            12 => Value::Push((0..r.below(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            13 => Value::Map(
                (0..r.below(3)).map(|_| (random(r, depth + 1, resp2), random(r, depth + 1, resp2))).collect(),
            ),
            14 => Value::Attribute {
                attributes: (0..r.below(3))
                    .map(|_| (random(r, depth + 1, resp2), random(r, depth + 1, resp2)))
                    .collect(),
                value: Box::new(random(r, depth + 1, resp2)),
            },
            _ => Value::Integer(0),
        }
    }

    #[test]
    fn round_trips() {
        let mut r = Lcg(7);
        for _ in 0..2000 {
            let v = random(&mut r, 0, false);
            let b3 = v.to_bytes(Version::Resp3);
            assert_eq!(Value::parse(&b3), Ok(Some((v.clone(), b3.len()))), "{v:?}");
            let b2 = v.to_bytes(Version::Resp2);
            let (v2, used) = Value::parse(&b2).unwrap().unwrap();
            assert_eq!(used, b2.len());
            assert_eq!(v2.to_bytes(Version::Resp2), b2);
            let w = random(&mut r, 0, true);
            let b = w.to_bytes(Version::Resp2);
            assert_eq!(Value::parse(&b), Ok(Some((w, b.len()))));
            let c = Command { args: (0..r.below(5)).map(|_| r.bytes(10)).collect() };
            let b = c.to_bytes();
            assert_eq!(Command::parse(&b), Ok(Some((c, b.len()))));
        }
    }

    /// A random input: random bytes from RESP's alphabet, or a valid
    /// encoding with a few bytes changed, added, removed or cut.
    fn fuzz_input(r: &mut Lcg) -> Vec<u8> {
        const ALPHABET: &[u8] = b"+-:$*_#,(!=%~|>;.?\r\n\r\n0123456789-tfinax \"'\\";
        if r.below(3) == 0 {
            return (0..r.below(40)).map(|_| ALPHABET[r.below(ALPHABET.len())]).collect();
        }
        let mut b = if r.below(4) == 0 {
            VALID[r.below(VALID.len())].to_vec()
        } else if r.below(3) == 0 {
            let mut out = Vec::new();
            let v = random(r, 0, false);
            streamed(r, &v, &mut out);
            out
        } else {
            random(r, 0, false).to_bytes(if r.below(2) == 0 { Version::Resp2 } else { Version::Resp3 })
        };
        for _ in 0..r.below(4) {
            if b.is_empty() {
                break;
            }
            let i = r.below(b.len());
            match r.below(4) {
                0 => b[i] = ALPHABET[r.below(ALPHABET.len())],
                1 => b.insert(i, r.next() as u8),
                2 => {
                    b.remove(i);
                }
                _ => b.truncate(i),
            }
        }
        b
    }

    /// `v` in RESP3, with each array, set, map and bulk string streamed
    /// or not at random, a streamed string in random chunks.
    fn streamed(r: &mut Lcg, v: &Value, out: &mut Vec<u8>) {
        let stream = r.below(2) == 0;
        match v {
            Value::Bulk(d) if stream => {
                out.extend_from_slice(b"$?\r\n");
                let mut rest = &d[..];
                while !rest.is_empty() {
                    let n = 1 + r.below(rest.len());
                    out.extend_from_slice(format!(";{n}\r\n").as_bytes());
                    out.extend_from_slice(&rest[..n]);
                    out.extend_from_slice(b"\r\n");
                    rest = &rest[n..];
                }
                out.extend_from_slice(b";0\r\n");
            }
            Value::Array(items) | Value::Set(items) | Value::Push(items) => {
                let m = match v {
                    Value::Array(_) => b'*',
                    Value::Set(_) => b'~',
                    _ => b'>',
                };
                let stream = stream && m != b'>';
                out.push(m);
                out.extend_from_slice(if stream { "?".to_string() } else { items.len().to_string() }.as_bytes());
                out.extend_from_slice(b"\r\n");
                for i in items {
                    streamed(r, i, out);
                }
                if stream {
                    out.extend_from_slice(b".\r\n");
                }
            }
            Value::Map(entries) | Value::Attribute { attributes: entries, .. } => {
                let attr = matches!(v, Value::Attribute { .. });
                let stream = stream && !attr;
                out.push(if attr { b'|' } else { b'%' });
                out.extend_from_slice(if stream { "?".to_string() } else { entries.len().to_string() }.as_bytes());
                out.extend_from_slice(b"\r\n");
                for (k, v) in entries {
                    streamed(r, k, out);
                    streamed(r, v, out);
                }
                if stream {
                    out.extend_from_slice(b".\r\n");
                }
                if let Value::Attribute { value, .. } = v {
                    streamed(r, value, out);
                }
            }
            v => v.write(Version::Resp3, out),
        }
    }

    fn check_value(b: &[u8], lim: &Limits) {
        let Ok(Some((v, used))) = Value::parse_with(b, lim) else { return };
        assert!(used <= b.len());
        for ver in [Version::Resp2, Version::Resp3] {
            let bytes = v.to_bytes(ver);
            let (again, n) = Value::parse(&bytes).unwrap().unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(again.to_bytes(ver), bytes);
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut r = Lcg(0x5eed);
        let small = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 30 };
        let rounds = std::env::var("RESP_FUZZ_ROUNDS").ok().and_then(|n| n.parse().ok()).unwrap_or(5000);
        for _ in 0..rounds {
            // One input, or a stream of several, commands among them.
            let mut b = Vec::new();
            for _ in 0..1 + r.below(3) {
                match r.below(4) {
                    0 => b.extend(Command { args: (0..r.below(4)).map(|_| r.bytes(6)).collect() }.to_bytes()),
                    1 => b.extend_from_slice([&b"GET k\r\n"[..], b"SET \"a b\" 'c'\n", b"\r\n", b"*0\r\n"][r.below(4)]),
                    _ => b.extend(fuzz_input(&mut r)),
                }
            }
            if r.below(3) == 0 && !b.is_empty() {
                let i = r.below(b.len());
                b[i] = r.next() as u8;
            }
            check_value(&b, &Limits::DEFAULT);
            check_value(&b, &small);
            if let Ok(Some((c, used))) = Command::parse(&b) {
                assert!(used <= b.len());
                let bytes = c.to_bytes();
                assert_eq!(Command::parse(&bytes), Ok(Some((c, bytes.len()))));
            }
            let _ = Command::parse_with(&b, &small);
            // A decoder fed in random pieces finds what one-shot parsing
            // finds, values and commands, under both limits.
            for lim in [Limits::DEFAULT, small] {
                let pieces = random_pieces(&mut r, b.len());
                let expect = one_shot(&b, |b| Value::parse_with(b, &lim), |v| v.to_bytes(Version::Resp3));
                let mut d = Decoder::with_limits(lim);
                let got = decode(&mut d, &b, &pieces, |d| d.next_value(), |v| v.to_bytes(Version::Resp3));
                assert_eq!(got, expect, "{} {lim:?}", b.escape_ascii());
                let expect = one_shot(&b, |b| Command::parse_with(b, &lim), |c| c.args.clone());
                let expect: Vec<_> =
                    expect.into_iter().filter(|c| c.as_ref().ok().is_none_or(|a| !a.is_empty())).collect();
                let mut d = Decoder::with_limits(lim);
                let got = decode(&mut d, &b, &pieces, |d| d.next_command(), |c| c.args.clone());
                assert_eq!(got, expect, "{} {lim:?}", b.escape_ascii());
            }
        }
    }

    /// Where to cut `n` bytes into pieces of 1 to 8 bytes.
    fn random_pieces(r: &mut Lcg, n: usize) -> Vec<usize> {
        let mut cuts = vec![0];
        while *cuts.last().unwrap() < n {
            let next = (cuts.last().unwrap() + 1 + r.below(8)).min(n);
            cuts.push(next);
        }
        cuts
    }

    /// Everything one-shot parsing finds in `b`, one after another, up to
    /// the first error.
    fn one_shot<T, K>(
        mut b: &[u8],
        parse: impl Fn(&[u8]) -> Result<Option<(T, usize)>, ParseError>,
        key: impl Fn(&T) -> K,
    ) -> Vec<Result<K, ParseError>> {
        let mut out = Vec::new();
        loop {
            match parse(b) {
                Ok(Some((v, used))) => {
                    out.push(Ok(key(&v)));
                    b = &b[used..];
                }
                Ok(None) => return out,
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }

    /// Everything a decoder finds in `b` fed in the pieces between `cuts`,
    /// up to the first error.
    fn decode<T, K>(
        d: &mut Decoder,
        b: &[u8],
        cuts: &[usize],
        next: impl Fn(&mut Decoder) -> Option<Result<T, ParseError>>,
        key: impl Fn(&T) -> K,
    ) -> Vec<Result<K, ParseError>> {
        let mut out = Vec::new();
        for w in cuts.windows(2) {
            d.feed(&b[w[0]..w[1]]);
            while let Some(v) = next(d) {
                match v {
                    Ok(v) => out.push(Ok(key(&v))),
                    Err(e) => {
                        out.push(Err(e));
                        return out;
                    }
                }
            }
        }
        out
    }

    /// The RESP3 specification asks clients to read the NaN forms Redis
    /// before 7.2 sent: `-nan`, `NAN`, `nan(...)`.
    #[test]
    fn reads_legacy_nan() {
        for b in [&b",-nan\r\n"[..], b",NAN\r\n", b",NaN\r\n", b",nan(123)\r\n", b",-nan(ind)\r\n"] {
            let Value::Double(f) = one(b) else { panic!("{}", b.escape_ascii()) };
            assert!(f.is_nan());
        }
        for b in [&b",nan(\r\n"[..], b",nan(1\r\n", b",nanx\r\n", b",-NaN)\r\n"] {
            assert_eq!(Value::parse(b), Err(ParseError::Malformed(b',')), "{}", b.escape_ascii());
        }
    }

    /// An inline command of exactly the longest line is read whether its
    /// line ends with LF or CR LF.
    #[test]
    fn inline_line_limit_counts_text_only() {
        let lim = Limits { max_line_len: 10, ..Limits::DEFAULT };
        assert_eq!(Command::parse_with(b"0123456789\n", &lim), Ok(Some((Command::new(["0123456789"]), 11))));
        assert_eq!(Command::parse_with(b"0123456789\r\n", &lim), Ok(Some((Command::new(["0123456789"]), 12))));
        assert_eq!(Command::parse_with(b"0123456789\r", &lim), Ok(None));
        assert_eq!(Command::parse_with(b"01234567890", &lim), Err(ParseError::LineTooLong));
        assert_eq!(Command::parse_with(b"0123456789x", &lim), Err(ParseError::LineTooLong));
        assert_eq!(Command::parse_with(b"01234567890\n", &lim), Err(ParseError::LineTooLong));
        assert_eq!(Command::parse_with(b"01234567890\r\n", &lim), Err(ParseError::LineTooLong));
    }

    /// An inline argument is held to the bulk limit, like an argument in
    /// an array.
    #[test]
    fn inline_arguments_keep_the_bulk_limit() {
        let lim = Limits { max_bulk_len: 8, ..Limits::DEFAULT };
        assert_eq!(Command::parse_with(b"GET 12345678\r\n", &lim).unwrap().unwrap().0.args.len(), 2);
        assert_eq!(Command::parse_with(b"GET 123456789\r\n", &lim), Err(ParseError::BulkTooLong));
        assert_eq!(Command::parse_with(b"GET \"123\\x41\\x42678\"\r\n", &lim).unwrap().unwrap().0.args[1], b"123AB678");
        assert_eq!(Command::parse_with(b"GET \"123\\x41\\x426789\"\r\n", &lim), Err(ParseError::BulkTooLong));
    }

    /// A command's array count is a number as Redis's string2ll reads it:
    /// no `+`, as the value reader also refuses.
    #[test]
    fn command_count_has_no_plus() {
        assert_eq!(Value::parse(b"*+1\r\n$1\r\na\r\n"), Err(ParseError::BadLength));
        assert_eq!(Command::parse(b"*+1\r\n$1\r\na\r\n"), Err(ParseError::TooManyElements));
        assert_eq!(Command::parse(b"*-1\r\n"), Ok(Some((Command::default(), 5))));
    }

    /// Parsing all the bytes at once gives what a decoder fed them in
    /// pieces gives, also when a frame runs over the limit.
    #[test]
    fn frame_limit_gives_one_answer() {
        let lim = Limits { max_frame_len: 10, ..Limits::DEFAULT };
        for b in [&b"*2\r\n+0123456789\r\nX"[..], b"*1\r\n$7\r\nabcdefgXY", b"*2\r\n:1\r\n:22\r\n:3\r\n"] {
            let whole = Value::parse_with(b, &lim);
            for split in 0..=b.len() {
                let mut d = Decoder::with_limits(lim);
                d.feed(&b[..split]);
                let first = d.next_value();
                d.feed(&b[split..]);
                let got = first.or_else(|| d.next_value());
                assert_eq!(
                    got,
                    whole.clone().transpose().map(|r| r.map(|(v, _)| v)),
                    "{} at {split}",
                    b.escape_ascii()
                );
            }
            assert_eq!(whole, Err(ParseError::FrameTooLarge), "{}", b.escape_ascii());
        }
        let mut d = Decoder::with_limits(Limits { max_frame_len: 12, ..Limits::DEFAULT });
        d.feed(b"*1\r\n$4\r\nabcdXY");
        assert_eq!(d.next_command(), Some(Err(ParseError::FrameTooLarge)));
        assert_eq!(
            Command::parse_with(b"*1\r\n$4\r\nabcdXY", &Limits { max_frame_len: 12, ..Limits::DEFAULT }),
            Err(ParseError::FrameTooLarge)
        );
    }

    /// A decoder fed any prefix of these, cut anywhere, finds what one-shot
    /// parsing of that prefix finds.
    #[test]
    fn decoder_agrees_on_every_prefix() {
        let lim = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 40 };
        let inputs: &[&[u8]] = &[
            b"%?\r\n+a\r\n.\r\n",
            b"%?\r\n+a\r\n:1\r\n+b\r\n:2\r\n+c\r\n:3\r\n+d\r\n:4\r\n.\r\n",
            b"*?\r\n:1\r\n:2\r\n:3\r\n:4\r\n.\r\n",
            b"$?\r\n;3\r\nabc\r\n;4\r\ndefg\r\n;0\r\n",
            b"$?\r\n;3\r\nabc\r\n+x\r\n",
            b"|1\r\n+k\r\n*1\r\n*1\r\n:1\r\n:2\r\n",
            b"|0\r\n|0\r\n|0\r\n:1\r\n",
            b"~1\r\n*?\r\n.x\r\n",
            b">?\r\n:1\r\n",
            b"*1\r\n$1\r\nab\r\n",
            b"*2\r\n$1\r\na\r\n+b\r\n",
            b"*4\r\n$1\r\na\r\n",
            b"\"a b\" 'c\r\n",
        ];
        for b in inputs {
            for end in 0..=b.len() {
                let p = &b[..end];
                let whole = one_shot(p, |b| Value::parse_with(b, &lim), |v| v.to_bytes(Version::Resp3));
                let cmds = one_shot(p, |b| Command::parse_with(b, &lim), |c| c.args.clone());
                for split in 0..=end {
                    let got = decode(
                        &mut Decoder::with_limits(lim),
                        p,
                        &[0, split, end],
                        |d| d.next_value(),
                        |v| v.to_bytes(Version::Resp3),
                    );
                    assert_eq!(got, whole, "{} at {split}", p.escape_ascii());
                    let got = decode(
                        &mut Decoder::with_limits(lim),
                        p,
                        &[0, split, end],
                        |d| d.next_command(),
                        |c| c.args.clone(),
                    );
                    assert_eq!(got, cmds, "{} at {split}", p.escape_ascii());
                }
            }
        }
    }

    /// One big value fed a few bytes at a time takes linear time: the
    /// decoder does not read its first elements again on every feed.
    #[test]
    fn decoder_is_linear_in_one_big_value() {
        const N: usize = 200_000;
        let start = std::time::Instant::now();
        // An array of nulls, a map inside an attribute, and a streamed
        // string of one-byte chunks.
        let mut values = Vec::new();
        values.extend_from_slice(format!("*{N}\r\n").as_bytes());
        values.extend(std::iter::repeat_n(&b"_\r\n"[..], N).flatten());
        values.extend_from_slice(format!("|1\r\n+a\r\n%{N}\r\n").as_bytes());
        values.extend(std::iter::repeat_n(&b":1\r\n#t\r\n"[..], N).flatten());
        values.extend_from_slice(b"+v\r\n*?\r\n~?\r\n%?\r\n");
        values.extend(std::iter::repeat_n(&b"$?\r\n;1\r\nx\r\n;0\r\n"[..], 8).flatten());
        values.extend_from_slice(b".\r\n.\r\n.\r\n$?\r\n");
        values.extend(std::iter::repeat_n(&b";1\r\nx\r\n"[..], N).flatten());
        values.extend_from_slice(b";0\r\n");
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for piece in values.chunks(5) {
            d.feed(piece);
            while let Some(v) = d.next_value() {
                got.push(v.unwrap());
            }
        }
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], Value::Array(vec![Value::Null; N]));
        let Value::Attribute { attributes, value } = &got[1] else { panic!() };
        assert!(matches!(&attributes[..], [(_, Value::Map(e))] if e.len() == N));
        assert_eq!(**value, s("v"));
        let streamed = Value::Array(vec![Value::Set(vec![Value::Map(vec![(bulk("x"), bulk("x")); 4])])]);
        assert_eq!(got[2], streamed);
        assert_eq!(got[3], Value::Bulk(vec![b'x'; N]));
        assert_eq!(d.buffered(), 0);
        // Commands, likewise.
        let mut c = format!("*{N}\r\n").into_bytes();
        c.extend(std::iter::repeat_n(&b"$1\r\nx\r\n"[..], N).flatten());
        let mut d = Decoder::new();
        let mut n = 0;
        for piece in c.chunks(5) {
            d.feed(piece);
            while let Some(c) = d.next_command() {
                assert_eq!(c.unwrap().args.len(), N);
                n += 1;
            }
        }
        assert_eq!(n, 1);
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "{:?}", start.elapsed());
    }
}
