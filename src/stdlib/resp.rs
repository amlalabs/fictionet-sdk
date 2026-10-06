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
//! Nothing here reads a socket. A world that plays a Redis server uses
//! [`Stream<Commands>`](super::codec::Stream) to read requests and
//! [`Value::write`] to send replies. A client uses
//! [`Stream<Values>`](super::codec::Stream) to read replies. Which commands
//! exist and what they do is up to world code.
//!
//! Every reader checks lengths, counts and nesting against [`Limits`].
//! A partial value waits for more input. At EOF it is truncated. A
//! [`ParseError`] ends the stream. A server can answer it with
//! [`ParseError::reply`] and close the connection.
//!
//! ```
//! use std::collections::HashMap;
//! use fictionet::stdlib::codec::{Stream, Wire, pump, finish};
//! use fictionet::stdlib::resp::{Commands, Value};
//!
//! let mut store: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
//! let mut stream = Stream::new(Commands::new());
//! let mut commands = Vec::new();
//! // A SET as an array of bulk strings, then a GET typed into telnet.
//! pump(&mut stream, b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nhello\r\nGET key\r\n",
//!     |command| commands.push(command)).unwrap();
//! finish(&mut stream, |command| commands.push(command)).unwrap();
//! let mut out = Vec::new();
//! for command in commands {
//!     let reply = match (command.name().as_deref(), command.args.as_slice()) {
//!         (Some("SET"), [_, k, v]) => {
//!             store.insert(k.clone(), v.clone());
//!             Value::ok()
//!         }
//!         (Some("GET"), [_, k]) => store.get(k).map_or(Value::Null, |v| Value::Bulk(v.clone())),
//!         _ => Value::error("ERR unknown command"),
//!     };
//!     reply.write(&mut out).unwrap();
//! }
//! assert_eq!(out, b"+OK\r\n$5\r\nhello\r\n");
//!
//! let reply = Value::parse(b"%1\r\n+role\r\n+master\r\n").unwrap();
//! assert_eq!(reply, Value::Map(vec![(Value::simple("role"), Value::simple("master"))]));
//! assert_eq!(reply.to_bytes().unwrap(), b"%1\r\n+role\r\n+master\r\n");
//! ```

extern crate alloc;

use super::codec::{self, Decode, Wire};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

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
/// The most bytes one whole value or command may take by default.
/// This also bounds the unread input in a default stream.
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

/// The deepest nesting the readers take, whatever [`Limits::max_depth`]
/// says, since they recurse once per level.
const DEPTH_CEILING: usize = 256;

/// The most elements a reader reserves room for before they come.
const PREALLOC: usize = 4096;

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
    /// How many aggregates may nest inside each other. The readers
    /// recurse once per level, so they take no more than 256 levels
    /// whatever this says.
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
    /// BLPOP times out. The writer preserves its `*-1` form.
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

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl core::error::Error for ParseError {}

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
}

/// Reads RESP reply values without retaining input bytes.
///
/// Use with [`codec::Stream`] for bounded input. Scanning resumes across
/// calls, so pushing one byte at a time takes linear time. Parse errors
/// end the stream. Partial values return [`codec::Step::Need`] at EOF,
/// which the driver reports as [`codec::Fail::Truncated`].
#[derive(Debug)]
pub struct Values {
    limits: Limits,
    need: usize,
    scan: Scan,
}

impl Default for Values {
    fn default() -> Self {
        Self::new()
    }
}

impl Values {
    /// Creates a decoder using [`Limits::DEFAULT`].
    pub fn new() -> Self {
        Self::with_limits(Limits::DEFAULT)
    }

    /// Creates a decoder with custom limits.
    /// The frame limit is clamped to [`MAX_FRAME_LEN`]. Zero refuses all
    /// nonempty input and uses one byte of input capacity.
    pub fn with_limits(mut limits: Limits) -> Self {
        limits.max_frame_len = limits.max_frame_len.min(MAX_FRAME_LEN);
        // Fixed room for nesting counters, including a streamed string
        // inside the deepest aggregate. No input bytes are stored here.
        let scan = Scan { open: Vec::with_capacity(depth_limit(&limits) + 1), ..Scan::default() };
        Self { limits, need: 0, scan }
    }

    /// The effective limits, including the clamped frame limit.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    fn read<T>(
        &mut self,
        input: &[u8],
        scan: fn(&mut Scan, &[u8], &Limits) -> Option<usize>,
        parse: fn(&[u8], &Limits) -> Step<T>,
    ) -> Result<codec::Step<T>, ParseError> {
        if input.is_empty() {
            return Ok(codec::Step::Need);
        }
        let bytes = frame(input, &self.limits);
        if bytes.len() < self.need {
            return Ok(codec::Step::Need);
        }
        if let Some(need) = scan(&mut self.scan, bytes, &self.limits)
            && need <= self.limits.max_frame_len
        {
            self.need = need;
            return Ok(codec::Step::Need);
        }
        match parse(bytes, &self.limits) {
            Ok((item, used)) => {
                self.need = 0;
                self.scan.pos = 0;
                self.scan.open.clear();
                self.scan.quiet = None;
                Ok(codec::Step::Item(item, used))
            }
            Err(Fail::Need(need)) => {
                self.need = need;
                Ok(codec::Step::Need)
            }
            Err(Fail::Bad(error)) => Err(error),
        }
    }
}

impl Decode for Values {
    type Item = Value;
    type Error = ParseError;
    const NAME: &'static str = "RESP values";

    fn capacity(&self) -> usize {
        self.limits.max_frame_len.max(1)
    }

    /// Reserved nesting counters, bounded by the 256-level depth ceiling
    /// plus one streamed string. This allocation stays fixed across `Need`.
    fn held(&self) -> usize {
        self.scan.open.capacity().saturating_mul(core::mem::size_of::<Open>())
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<codec::Step<Value>, ParseError> {
        self.read(input, scan_value, value_top)
    }
}

/// Reads RESP requests as a server does, including inline commands.
///
/// Use with [`codec::Stream`]. Commands with no arguments are skipped.
/// Limits, scanning, terminal parse errors, and EOF follow [`Values`].
#[derive(Debug, Default)]
pub struct Commands {
    values: Values,
}

impl Commands {
    /// Creates a decoder using [`Limits::DEFAULT`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a decoder with the same limit policy as [`Values::with_limits`].
    pub fn with_limits(limits: Limits) -> Self {
        Self { values: Values::with_limits(limits) }
    }

    /// The effective limits, including the clamped frame limit.
    pub fn limits(&self) -> Limits {
        self.values.limits()
    }
}

impl Decode for Commands {
    type Item = Command;
    type Error = ParseError;
    const NAME: &'static str = "RESP commands";

    fn capacity(&self) -> usize {
        self.values.capacity()
    }

    fn held(&self) -> usize {
        self.values.held()
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<codec::Step<Command>, ParseError> {
        Ok(match self.values.read(input, scan_command, command_top)? {
            codec::Step::Item(command, used) if command.args.is_empty() => codec::Step::Skip(used),
            step => step,
        })
    }
}

// Reading.

/// How far a decoder has checked the value or command it waits for.
/// Positions count from the first unread byte.
#[derive(Debug, Default)]
struct Scan {
    /// Where the next element starts.
    pos: usize,
    /// The aggregates still open, outermost first.
    open: Vec<Open>,
    /// A line the last attempt found no end of, so the next one searches
    /// only the bytes that came since.
    quiet: Option<Quiet>,
}

/// A line with no end yet: where it starts, how far it holds no line end,
/// and, for an inline command, whether a NUL came before any LF.
#[derive(Debug, Clone, Copy)]
struct Quiet {
    start: usize,
    to: usize,
    stuck: bool,
}

#[derive(Debug, Clone, Copy)]
enum Open {
    /// This many elements are still to come.
    Left(usize),
    /// An attribute, with this many keys, values and the value they
    /// describe still to come.
    Attr(usize),
    /// A push, none of whose elements has come yet: its first must be a
    /// string.
    Push(usize),
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
            let Some(slot) = self.open.last_mut() else {
                return Scanned::Whole;
            };
            let left = match *slot {
                Open::Left(n) | Open::Push(n) => {
                    *slot = Open::Left(n.saturating_sub(1));
                    n.saturating_sub(1)
                }
                Open::Attr(n) => {
                    *slot = Open::Attr(n.saturating_sub(1));
                    n.saturating_sub(1)
                }
                Open::Streamed { pairs, seen } => {
                    *slot = Open::Streamed { pairs, seen: seen.saturating_add(1) };
                    return Scanned::More;
                }
                Open::Chunks(_) => return Scanned::More,
            };
            if left > 0 {
                return Scanned::More;
            }
            self.open.pop();
        }
    }

    /// Whether the value about to start is at the top level, perhaps
    /// after attributes, where a push may be.
    fn top(&self) -> bool {
        self.open.iter().all(|o| matches!(o, Open::Attr(1)))
    }

    /// Whether the line from `start`, which the last attempt found no end
    /// of, still has none and is not too long: then the same attempt
    /// would need one more byte again. Only the new bytes are searched.
    fn line_waits(&mut self, b: &[u8], start: usize, max: usize) -> bool {
        let Some(q) = self.quiet else { return false };
        if q.start != start || q.to > b.len() || b.len() - start > max {
            return false;
        }
        if b[q.to..].iter().any(|&c| c == b'\r' || c == b'\n') {
            self.quiet = None;
            return false;
        }
        self.quiet = Some(Quiet { to: b.len(), ..q });
        true
    }

    /// After an attempt that needs `need` bytes: if that is one more, and
    /// the line from `start` holds no CR or LF, the line is what has no
    /// end yet, since every element's first line starts one byte after
    /// it, and every later line follows a line end.
    fn note_line(&mut self, b: &[u8], start: usize, need: usize, max: usize) {
        if need == b.len().saturating_add(1)
            && start < b.len()
            && b.len() - start <= max
            && !b[start..].iter().any(|&c| c == b'\r' || c == b'\n')
        {
            self.quiet = Some(Quiet { start, to: b.len(), stuck: false });
        }
    }
}

/// Goes on checking a value from where `s` stopped. It returns how many
/// bytes the value needs at least, or `None` when the value is whole or
/// faulty, and the full reader should read it. It follows [`value`] step
/// by step, so the two agree on what needs more bytes.
fn scan_value(s: &mut Scan, b: &[u8], lim: &Limits) -> Option<usize> {
    loop {
        let start = s.pos.saturating_add(1);
        if s.line_waits(b, start, lim.max_line_len) {
            return Some(b.len().saturating_add(1));
        }
        match scan_step(s, b, lim) {
            Ok(Scanned::More) => {}
            Ok(Scanned::Whole) | Err(Fail::Bad(_)) => return None,
            Err(Fail::Need(n)) => {
                s.note_line(b, start, n, lim.max_line_len);
                return Some(n);
            }
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
    let Some(&t) = b.get(pos) else {
        return Err(Fail::Need(pos.saturating_add(1)));
    };
    let depth = s.open.len();
    // As list checks a push's first element.
    let push_first = matches!(s.open.last(), Some(Open::Push(_)));
    if push_first && !is_string_marker(t) {
        return Err(ParseError::Malformed(marker::PUSH).into());
    }
    match t {
        marker::ARRAY | marker::SET | marker::PUSH | marker::MAP | marker::ATTRIBUTE => {
            let (l, e) = line(b, pos + 1, lim)?;
            let len = length(l)?;
            if matches!(len, Len::Null) && t == marker::ARRAY {
                return Ok(s.ended(e));
            }
            if t == marker::PUSH && (!s.top() || matches!(len, Len::N(0))) {
                return Err(ParseError::Malformed(marker::PUSH).into());
            }
            if depth >= depth_limit(lim) {
                return Err(ParseError::TooDeep.into());
            }
            let pairs = matches!(t, marker::MAP | marker::ATTRIBUTE);
            let open = match len {
                Len::N(n) if n > lim.max_elements => return Err(ParseError::TooManyElements.into()),
                // An attribute's entries, then the value they describe.
                Len::N(n) if t == marker::ATTRIBUTE => Open::Attr(n.saturating_mul(2).saturating_add(1)),
                Len::N(n) if pairs => Open::Left(n.saturating_mul(2)),
                Len::N(n) if t == marker::PUSH => Open::Push(n),
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
            let (v, e) = value(b, pos, depth, false, lim)?;
            if push_first && v == Value::Null {
                return Err(ParseError::Malformed(marker::PUSH).into());
            }
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
        Some(_) => return scan_inline(s, b, lim),
    }
    loop {
        let start = s.pos.saturating_add(1);
        if s.line_waits(b, start, lim.max_line_len) {
            return Some(b.len().saturating_add(1));
        }
        match command_step(s, b, lim) {
            Ok(true) => {}
            Ok(false) | Err(Fail::Bad(_)) => return None,
            Err(Fail::Need(n)) => {
                s.note_line(b, start, n, lim.max_line_len);
                return Some(n);
            }
        }
    }
}

/// Checks a command array's count, or one argument, at `s.pos`. It
/// returns whether there is more to check, and changes `s` only when the
/// part is whole.
fn command_step(s: &mut Scan, b: &[u8], lim: &Limits) -> Result<bool, Fail> {
    let Some(&Open::Left(left)) = s.open.last() else {
        // The count, as multibulk reads it.
        let (l, e) = line(b, 1, lim)?;
        return match redis_ll(l).and_then(|n| usize::try_from(n).ok()) {
            Some(n) if n > 0 && n <= lim.max_elements => {
                s.open.push(Open::Left(n));
                s.pos = e;
                Ok(true)
            }
            _ => Ok(false),
        };
    };
    if left == 0 {
        return Ok(false);
    }
    // One argument, as multibulk reads it.
    let pos = s.pos;
    match b.get(pos) {
        None => return Err(Fail::Need(pos.saturating_add(1))),
        Some(&marker::BULK) => {}
        Some(_) => return Ok(false),
    }
    let (l, e) = line(b, pos + 1, lim)?;
    let n = bulk_len(l).ok_or(ParseError::BulkTooLong)?;
    let (_, e) = data(b, e, n, lim)?;
    if let Some(slot) = s.open.last_mut() {
        *slot = Open::Left(left - 1);
    }
    s.pos = e;
    Ok(true)
}

/// Goes on checking an inline command, as [`inline`] reads it, searching
/// only the bytes that came since the last attempt for the line's end.
fn scan_inline(s: &mut Scan, b: &[u8], lim: &Limits) -> Option<usize> {
    if let Some(q) = s.quiet
        && q.start == 0
        && q.to <= b.len()
        && b.len() <= lim.max_line_len
    {
        let first = b[q.to..].iter().find(|&&c| c == b'\n' || c == 0);
        let stuck = q.stuck || first == Some(&0);
        if stuck || first.is_none() {
            s.quiet = Some(Quiet { start: 0, to: b.len(), stuck });
            return Some(b.len().saturating_add(1));
        }
    }
    match inline(b, lim) {
        Err(Fail::Need(n)) => {
            // Needing more, a line no longer than the limit holds no LF,
            // or a NUL before it.
            if b.len() <= lim.max_line_len {
                s.quiet = Some(Quiet { start: 0, to: b.len(), stuck: b.contains(&0) });
            }
            Some(n)
        }
        _ => None,
    }
}

/// The bytes a value or command may take: no more than
/// [`Limits::max_frame_len`]. The readers see only these, so what they
/// find does not depend on how many bytes past the limit have come, and
/// exact parsing agrees with a stream receiving chunks.
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
    bounded(value(frame(b, lim), 0, 0, true, lim), lim)
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

/// A number as Redis's `string2ll` reads a command's count or an
/// argument's length: `0`, or an optional `-` and digits that do not
/// start with 0, in 64 bits.
fn redis_ll(l: &[u8]) -> Option<i64> {
    if l == b"0" {
        return Some(0);
    }
    let ds = l.strip_prefix(b"-").unwrap_or(l);
    if !matches!(ds.first(), Some(b'1'..=b'9')) {
        return None;
    }
    int(l)
}

/// An argument's length in a command array, as Redis reads it.
fn bulk_len(l: &[u8]) -> Option<usize> {
    redis_ll(l).and_then(|n| usize::try_from(n).ok())
}

/// Whether a value with this marker can be a string: a simple, bulk or
/// verbatim string, as a push's first element must be.
fn is_string_marker(t: u8) -> bool {
    matches!(t, marker::SIMPLE | marker::BULK | marker::VERBATIM)
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
    core::str::from_utf8(l).ok()?.parse().ok()
}

/// Whether `l` is NaN as C's `printf` writes it: an optional sign, `nan`
/// in any case, then an optional sequence of letters, digits and
/// underscores in parentheses.
fn legacy_nan(l: &[u8]) -> bool {
    let l = match l.first() {
        Some(b'+' | b'-') => &l[1..],
        _ => l,
    };
    let Some((nan, rest)) = l.split_at_checked(3) else {
        return false;
    };
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

/// The value at `pos`, nested `depth` deep. `top` says whether it is at
/// the top level, perhaps after attributes, where a push may be.
fn value(b: &[u8], pos: usize, depth: usize, top: bool, lim: &Limits) -> Step<Value> {
    let Some(&t) = b.get(pos) else {
        return Err(Fail::Need(pos.saturating_add(1)));
    };
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
            let Len::N(n) = length(l)? else {
                return Err(ParseError::BadLength.into());
            };
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
            // A push comes only at the top level, and starts with a string.
            if t == marker::PUSH && (!top || matches!(len, Len::N(0))) {
                return Err(ParseError::Malformed(t).into());
            }
            if depth >= depth_limit(lim) {
                return Err(ParseError::TooDeep.into());
            }
            let (items, e) = match len {
                Len::N(n) => list(b, e, n, depth, t == marker::PUSH, lim)?,
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
            if depth >= depth_limit(lim) {
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
            let (v, e) = value(b, e, depth + 1, top, lim)?;
            Ok((Value::Attribute { attributes: entries, value: Box::new(v) }, e))
        }
        _ => Err(ParseError::UnknownType(t).into()),
    }
}

/// A capacity for `n` items of at least `min` bytes each, no more than
/// the bytes left could hold, nor [`PREALLOC`]. Nested aggregates share
/// the bytes left, so each reserves little and grows as its elements
/// come.
fn capacity(b: &[u8], pos: usize, n: usize, min: usize) -> usize {
    n.min(b.len().saturating_sub(pos) / min).min(PREALLOC)
}

/// How deep the readers let aggregates nest under `lim`.
fn depth_limit(lim: &Limits) -> usize {
    lim.max_depth.min(DEPTH_CEILING)
}

/// `n` elements from `pos`. With `push`, the first must be a string.
fn list(b: &[u8], mut pos: usize, n: usize, depth: usize, push: bool, lim: &Limits) -> Step<Vec<Value>> {
    if n > lim.max_elements {
        return Err(ParseError::TooManyElements.into());
    }
    let mut items = Vec::with_capacity(capacity(b, pos, n, 3));
    for i in 0..n {
        let first = push && i == 0;
        if first {
            match b.get(pos) {
                None => return Err(Fail::Need(pos.saturating_add(1))),
                Some(&t) if !is_string_marker(t) => {
                    return Err(ParseError::Malformed(marker::PUSH).into());
                }
                Some(_) => {}
            }
        }
        let (v, e) = value(b, pos, depth + 1, false, lim)?;
        if first && v == Value::Null {
            return Err(ParseError::Malformed(marker::PUSH).into());
        }
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
        let (k, e) = value(b, pos, depth + 1, false, lim)?;
        let (v, e) = value(b, e, depth + 1, false, lim)?;
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
        let (v, e) = value(b, pos, depth + 1, false, lim)?;
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
        let (k, e) = value(b, pos, depth + 1, false, lim)?;
        let (v, e) = value(b, e, depth + 1, false, lim)?;
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
    let n = redis_ll(l).ok_or(ParseError::TooManyElements)?;
    // Redis ignores an array of zero or fewer elements.
    let Ok(n) = usize::try_from(n) else {
        return Ok((Command::default(), pos));
    };
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
        let n = bulk_len(l).ok_or(ParseError::BulkTooLong)?;
        let (d, e) = data(b, e, n, lim)?;
        args.push(d.to_vec());
        pos = e;
    }
    Ok((Command { args }, pos))
}

fn inline(b: &[u8], lim: &Limits) -> Step<Command> {
    // The text may be max_line_len bytes, then CR LF.
    let window = &b[..b.len().min(lim.max_line_len.saturating_add(2))];
    // Redis finds the LF with strchr, which stops at a NUL, so after a
    // NUL the line never ends, and the bytes run into the limit.
    let end = window.iter().position(|&c| c == b'\n' || c == 0);
    let Some(i) = end.filter(|&i| window[i] == b'\n') else {
        // Without an LF, the bytes past the longest text can only be a CR,
        // and only before a LF that can still come.
        let over = window.len().saturating_sub(lim.max_line_len);
        if over > 1 || (over == 1 && (end.is_some() || window.last() != Some(&b'\r'))) {
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
/// `sdssplitargs` does. The line holds no NUL: [`inline`] ends no line
/// after one.
fn split_args(text: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
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

/// Why an exact RESP value or command cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The protocol parser rejected the frame.
    Parse(ParseError),
    /// The input ended inside a frame.
    Incomplete,
    /// Bytes follow the first complete frame.
    Trailing,
    /// The value cannot be written unchanged under [`Limits::DEFAULT`].
    Unwritable,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete RESP frame"),
            Self::Trailing => f.write_str("bytes follow the RESP frame"),
            Self::Unwritable => f.write_str("RESP value cannot be written unchanged under the default limits"),
        }
    }
}

impl core::error::Error for WireError {}

fn exact<T>(parsed: Step<T>, len: usize) -> Result<T, WireError> {
    match parsed {
        Ok((item, used)) if used == len => Ok(item),
        Ok(_) => Err(WireError::Trailing),
        Err(Fail::Need(_)) => Err(WireError::Incomplete),
        Err(Fail::Bad(error)) => Err(WireError::Parse(error)),
    }
}

impl Wire for Value {
    type ParseError = WireError;
    type WriteError = WireError;

    /// Reads one complete RESP2 or RESP3 value under [`Limits::DEFAULT`].
    /// Streamed strings and aggregates become their plain forms. Refuses
    /// malformed, incomplete, oversized, or trailing input and values whose
    /// strict encoding would exceed the default limits. Exponential doubles
    /// can expand when written.
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let value = exact(value_top(bytes, &Limits::DEFAULT), bytes.len())?;
        value.write(&mut Vec::new())?;
        Ok(value)
    }

    /// Appends a strict encoding under [`Limits::DEFAULT`].
    /// Uses RESP3 types and preserves [`Value::NullArray`] as RESP2 `*-1`.
    /// NaN is written as `nan`; its sign and payload are not wire fields.
    /// Refuses invalid fields, pushes outside the top level or without a
    /// first string, and values exceeding size, count, or nesting limits.
    /// An error leaves `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut bytes = Vec::new();
        strict_value(&mut bytes, self, 0, true)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Command {
    type ParseError = WireError;
    type WriteError = WireError;

    /// Reads one complete command under [`Limits::DEFAULT`], as Redis does.
    /// An initial `*` selects an array of bulk strings. Otherwise, a line
    /// ending with LF or CRLF is split at spaces. Double quotes allow
    /// `\n`, `\r`, `\t`, `\b`, `\a`, `\xHH`, and a backslash before any
    /// other byte. Single quotes allow `\'`. A NUL hides any later LF.
    /// Array counts and bulk lengths allow no `+`, leading zero, or `-0`.
    /// Blank lines and arrays with zero or negative counts have no arguments.
    /// Refuses malformed, incomplete, oversized, or trailing input and
    /// commands whose array encoding exceeds the default limits.
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let command = exact(command_top(bytes, &Limits::DEFAULT), bytes.len())?;
        command.write(&mut Vec::new())?;
        Ok(command)
    }

    /// Appends an array of bulk strings under [`Limits::DEFAULT`].
    /// Refuses oversized arguments, argument counts, or total frame sizes.
    /// An error leaves `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut bytes = Vec::new();
        strict_header(&mut bytes, marker::ARRAY, self.args.len(), 0)?;
        for arg in &self.args {
            strict_bulk(&mut bytes, marker::BULK, &[], arg)?;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

fn strict_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    if out.len().checked_add(bytes.len()).is_none_or(|n| n > MAX_FRAME_LEN) {
        return Err(WireError::Unwritable);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn strict_line(out: &mut Vec<u8>, marker: u8, text: &[u8]) -> Result<(), WireError> {
    if text.len() > MAX_LINE_LEN || text.iter().any(|b| matches!(b, b'\r' | b'\n')) {
        return Err(WireError::Unwritable);
    }
    strict_bytes(out, &[marker])?;
    strict_bytes(out, text)?;
    strict_bytes(out, b"\r\n")
}

fn strict_bulk(out: &mut Vec<u8>, marker: u8, prefix: &[u8], bytes: &[u8]) -> Result<(), WireError> {
    let len = prefix.len().checked_add(bytes.len()).filter(|&n| n <= MAX_BULK_LEN).ok_or(WireError::Unwritable)?;
    strict_line(out, marker, len.to_string().as_bytes())?;
    strict_bytes(out, prefix)?;
    strict_bytes(out, bytes)?;
    strict_bytes(out, b"\r\n")
}

fn strict_header(out: &mut Vec<u8>, marker: u8, count: usize, depth: usize) -> Result<(), WireError> {
    if count > MAX_ELEMENTS || depth >= MAX_DEPTH {
        return Err(WireError::Unwritable);
    }
    strict_line(out, marker, count.to_string().as_bytes())
}

// Recursion stops at MAX_DEPTH before inspecting deeper children.
fn strict_value(out: &mut Vec<u8>, value: &Value, depth: usize, top: bool) -> Result<(), WireError> {
    match value {
        Value::Simple(bytes) => strict_line(out, marker::SIMPLE, bytes),
        Value::Error(bytes) => strict_line(out, marker::ERROR, bytes),
        Value::Integer(n) => strict_line(out, marker::INTEGER, n.to_string().as_bytes()),
        Value::Bulk(bytes) => strict_bulk(out, marker::BULK, &[], bytes),
        Value::Null => strict_bytes(out, b"_\r\n"),
        Value::NullArray => strict_bytes(out, b"*-1\r\n"),
        Value::Boolean(b) => strict_bytes(out, if *b { b"#t\r\n" } else { b"#f\r\n" }),
        Value::Double(n) => strict_line(out, marker::DOUBLE, fmt_double(*n).as_bytes()),
        Value::BigNumber(text) => {
            if text.len() > MAX_LINE_LEN || !big_ok(text.as_bytes()) {
                return Err(WireError::Unwritable);
            }
            strict_line(out, marker::BIG_NUMBER, text.as_bytes())
        }
        Value::BulkError(bytes) => strict_bulk(out, marker::BULK_ERROR, &[], bytes),
        Value::Verbatim { format, text } => {
            let &[a, b, c] = format;
            let prefix = [a, b, c, b':'];
            strict_bulk(out, marker::VERBATIM, &prefix, text)
        }
        Value::Array(items) | Value::Set(items) | Value::Push(items) => {
            let marker = match value {
                Value::Array(_) => marker::ARRAY,
                Value::Set(_) => marker::SET,
                _ => {
                    if !top || items.first().and_then(Value::as_bytes).is_none() {
                        return Err(WireError::Unwritable);
                    }
                    marker::PUSH
                }
            };
            strict_header(out, marker, items.len(), depth)?;
            for item in items {
                strict_value(out, item, depth + 1, false)?;
            }
            Ok(())
        }
        Value::Map(entries) | Value::Attribute { attributes: entries, .. } => {
            let marker = if matches!(value, Value::Map(_)) { marker::MAP } else { marker::ATTRIBUTE };
            strict_header(out, marker, entries.len(), depth)?;
            for (key, value) in entries {
                strict_value(out, key, depth + 1, false)?;
                strict_value(out, value, depth + 1, false)?;
            }
            if let Value::Attribute { value, .. } = value {
                strict_value(out, value, depth + 1, top)?;
            }
            Ok(())
        }
    }
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
    use codec::{Step as Decoded, Stream, contract, test_support::{Lcg, decode_all, mutate}};

    fn value_step(b: &[u8], limits: Limits) -> Result<Decoded<Value>, ParseError> {
        Values::with_limits(limits).decode(b, false)
    }

    fn command_step(b: &[u8], limits: Limits) -> Result<Decoded<Command>, ParseError> {
        Commands::with_limits(limits).decode(b, false)
    }

    fn check_values(b: &[u8], limits: Limits) {
        // NaN compares through its canonical encoding.
        contract::check_decode_with_alloc_limit(
            || Values::with_limits(limits).map(|value| value.to_bytes()),
            b, 2 * limits.max_frame_len.clamp(1, MAX_FRAME_LEN),
        );
    }

    fn check_commands(b: &[u8], limits: Limits) {
        contract::check_decode_with_alloc_limit(
            || Commands::with_limits(limits), b,
            2 * limits.max_frame_len.clamp(1, MAX_FRAME_LEN),
        );
    }

    fn one(b: &[u8]) -> Value {
        Value::parse(b).unwrap()
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
        assert_eq!(nested.to_bytes().unwrap(), VALID[15]);
        let with_null = one(VALID[16]);
        assert_eq!(with_null, Value::Array(vec![bulk("hello"), Value::Null, bulk("world")]));
        assert_eq!(Value::parse(&with_null.to_bytes().unwrap()), Ok(with_null));
        assert_eq!(Value::NullArray.to_bytes().unwrap(), b"*-1\r\n");
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
        assert_eq!(popularity.to_bytes().unwrap(), VALID[32]);
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
        for (value, bytes) in [
            (Value::Null, &b"_\r\n"[..]),
            (Value::NullArray, b"*-1\r\n"),
            (Value::Boolean(true), b"#t\r\n"),
            (Value::Double(1.23), b",1.23\r\n"),
            (Value::Double(f64::NEG_INFINITY), b",-inf\r\n"),
            (Value::Double(f64::NAN), b",nan\r\n"),
            (Value::BigNumber("-12".into()), b"(-12\r\n"),
            (Value::BulkError(b"SYNTAX invalid syntax".to_vec()), VALID[27]),
            (Value::Verbatim { format: *b"txt", text: b"Some string".to_vec() }, VALID[28]),
            (Value::Map(vec![(s("first"), Value::Integer(1))]), b"%1\r\n+first\r\n:1\r\n"),
            (Value::Set(vec![Value::Integer(1)]), b"~1\r\n:1\r\n"),
            (Value::Push(vec![s("a"), Value::Integer(1)]), b">2\r\n+a\r\n:1\r\n"),
            (
                Value::Attribute { attributes: vec![(s("ttl"), Value::Integer(1))], value: Box::new(Value::ok()) },
                b"|1\r\n+ttl\r\n:1\r\n+OK\r\n",
            ),
        ] {
            assert_eq!(value.to_bytes().unwrap(), bytes, "{value:?}");
        }
    }

    #[test]
    fn commands() {
        let bytes = b"*2\r\n$4\r\nLLEN\r\n$6\r\nmylist\r\n";
        let c = Command::parse(bytes).unwrap();
        assert_eq!(c, Command::new(["LLEN", "mylist"]));
        assert_eq!(c.name().as_deref(), Some("LLEN"));
        assert!(c.is("llen"));
        assert_eq!(c.arg(1), Some(&b"mylist"[..]));
        assert_eq!(c.arg(2), None);
        assert_eq!(c.to_bytes().unwrap(), bytes);
        assert_eq!(Command::from_value(&c.to_value()), Some(c));
        assert_eq!(Command::from_value(&Value::Array(vec![Value::Integer(1)])), None);
        assert_eq!(Command::from_value(&s("PING")), None);
        for (bytes, args) in [
            (&b"PING\r\n"[..], vec![&b"PING"[..]]),
            (b"EXISTS  somekey\n", vec![b"EXISTS", b"somekey"]),
            (b"SET k \"a b\\x41\\n\\\"\" 'it\\'s' x\"y z\"\r\n", vec![b"SET", b"k", b"a bA\n\"", b"it's", b"xy z"]),
            (b"ECHO \"\\xZZ\\q\" ''\n", vec![b"ECHO", b"xZZq", b""]),
        ] {
            assert_eq!(Command::parse(bytes), Ok(Command::new(args)));
            check_commands(bytes, Limits::DEFAULT);
        }
        for bytes in [&b" \r\n"[..], b"*0\r\n", b"*-1\r\n"] {
            assert_eq!(Command::parse(bytes), Ok(Command::default()));
            assert_eq!(decode_all(Commands::new, bytes), (vec![], None));
        }
        assert_eq!(Command::parse(b"GET a\0b\n"), Err(WireError::Incomplete));
    }

    #[test]
    fn value_errors() {
        let lim = Limits { max_bulk_len: 8, max_elements: 3, max_depth: 2, max_line_len: 10, max_frame_len: 40 };
        let bad = |b: &[u8]| value_step(b, lim).err().unwrap_or_else(|| panic!("{} parsed", b.escape_ascii()));
        assert_eq!(bad(b"x\r\n"), ParseError::UnknownType(b'x'));
        assert_eq!(bad(b".\r\n"), ParseError::UnknownType(b'.'));
        assert_eq!(bad(b"+OK\rX"), ParseError::BadLineEnd);
        assert_eq!(bad(b"+OK\n"), ParseError::BadLineEnd);
        assert_eq!(bad(b"+01234567890"), ParseError::LineTooLong);
        assert_eq!(value_step(b"+0123456789", lim), Ok(Decoded::Need));
        assert_eq!(bad(b"$-2\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"$x\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"$\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"!-1\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"=?\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"~-1\r\n"), ParseError::BadLength);
        assert_eq!(bad(b">?\r\n"), ParseError::BadLength);
        assert_eq!(bad(b"|?\r\n"), ParseError::BadLength);
        assert_eq!(Value::parse(b"$99999999999999999999999\r\n"), Err(WireError::Parse(ParseError::BadLength)));
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
        assert_eq!(Value::parse(b"$2\r\nabX"), Err(WireError::Incomplete));
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
        assert_eq!(Value::parse(b":9223372036854775808\r\n"), Err(WireError::Parse(ParseError::Malformed(b':'))));
        assert_eq!(Value::parse(b":-9223372036854775809\r\n"), Err(WireError::Parse(ParseError::Malformed(b':'))));
        let frame = Limits { max_frame_len: 10, ..Limits::DEFAULT };
        assert_eq!(value_step(b"$8\r\n", frame), Err(ParseError::FrameTooLarge));
        assert_eq!(value_step(b"+0123456789\r\n", frame), Err(ParseError::FrameTooLarge));
        assert_eq!(value_step(b"+0123456789", frame), Err(ParseError::FrameTooLarge));
        assert_eq!(value_step(b"+0123456\r\n", frame), Ok(Decoded::Item(s("0123456"), 10)));
        assert!(ParseError::BulkTooLong.reply() == Value::error("ERR Protocol error: invalid bulk length"));
    }

    #[test]
    fn command_errors() {
        let lim = Limits { max_bulk_len: 8, max_elements: 3, max_depth: 2, max_line_len: 10, max_frame_len: 40 };
        let bad =
            |b: &[u8]| command_step(b, lim).err().unwrap_or_else(|| panic!("{} parsed", b.escape_ascii()));
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
        assert_eq!(command_step(b"*1\r\n$20\r\n", frame), Err(ParseError::FrameTooLarge));
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
            check_values(full, Limits::DEFAULT);
            for n in 0..full.len() {
                assert_eq!(value_step(&full[..n], Limits::DEFAULT), Ok(Decoded::Need));
                assert_eq!(Value::parse(&full[..n]), Err(WireError::Incomplete));
                let hint = need(value_top(&full[..n], &Limits::DEFAULT)).unwrap();
                assert!(hint > n && hint <= full.len(), "{} at {n}: {hint}", full.escape_ascii());
            }
        }
        for full in commands {
            check_commands(full, Limits::DEFAULT);
            for n in 0..full.len() {
                assert_eq!(command_step(&full[..n], Limits::DEFAULT), Ok(Decoded::Need));
                assert_eq!(Command::parse(&full[..n]), Err(WireError::Incomplete));
                let hint = need(command_top(&full[..n], &Limits::DEFAULT)).unwrap();
                assert!(hint > n && hint <= full.len());
            }
            assert!(Command::parse(full).is_ok());
        }
    }

    #[test]
    fn values_split_a_stream() {
        let bytes = VALID.concat();
        check_values(&bytes, Limits::DEFAULT);
        let (got, error) = decode_all(Values::new, &bytes);
        assert!(error.is_none());
        assert_eq!(got.len(), VALID.len());
        for (value, source) in got.iter().zip(VALID) {
            assert_eq!(value.to_bytes(), one(source).to_bytes());
        }
        let mut stream = Stream::new(Values::new());
        assert_eq!(stream.push(b"+OK\n"), 4);
        let error = codec::Fail::Protocol(ParseError::BadLineEnd);
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.push(b"+OK\r\n"), 5);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        let limits = Limits { max_frame_len: 100, ..Limits::DEFAULT };
        for bytes in [&b"$1000\r\n"[..], &[b'+'; 100]] {
            check_values(bytes, limits);
            assert_eq!(value_step(bytes, limits), Err(ParseError::FrameTooLarge));
        }
        assert_eq!(value_step(&[b'+'; 99], limits), Ok(Decoded::Need));
    }

    #[test]
    fn stream_reads_commands() {
        let bytes = b"\r\n*0\r\nPING\r\n*1\r\n$4\r\nQUIT\r\n  \n";
        check_commands(bytes, Limits::DEFAULT);
        assert_eq!(decode_all(Commands::new, bytes), (vec![Command::new(["PING"]), Command::new(["QUIT"])], None));
        let mut stream = Stream::new(Commands::new());
        assert_eq!(stream.push(b"*1\r\n$10\r\n01234"), 14);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().values.need, 21);
        assert_eq!(stream.push(b"56789\r\n"), 7);
        assert_eq!(stream.next(), Some(Ok(Command::new(["0123456789"]))));
        assert_eq!(stream.push(b"*1\r\n+PING\r\n"), 11);
        let error = codec::Fail::Protocol(ParseError::ExpectedBulk(b'+'));
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
    }

    #[test]
    fn writers_refuse_changes() {
        let mut deep = Value::Integer(1);
        for _ in 0..MAX_DEPTH + 5 {
            deep = Value::Array(vec![deep]);
        }
        for value in [
            s("a\r\nb"), Value::BigNumber("12x".into()),
            s(&"a".repeat(MAX_LINE_LEN + 10)), deep,
            Value::Bulk(vec![0; MAX_BULK_LEN + 1]),
            Value::BulkError(vec![0; MAX_BULK_LEN + 1]),
            Value::Verbatim { format: *b"txt", text: vec![0; MAX_BULK_LEN - 3] },
            Value::Array(vec![Value::Null; MAX_ELEMENTS + 1]),
            Value::Set(vec![Value::Null; MAX_ELEMENTS + 1]),
            Value::Map(vec![(Value::Null, Value::Null); MAX_ELEMENTS + 1]),
        ] {
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(WireError::Unwritable));
        }
        for command in [
            Command { args: vec![vec![0; MAX_BULK_LEN + 1]] },
            Command { args: vec![vec![]; MAX_ELEMENTS + 1] },
        ] {
            contract::check_wire_value(&command);
            assert_eq!(command.to_bytes(), Err(WireError::Unwritable));
        }
        // Bulk errors retain line breaks in their length-delimited form.
        let value = Value::BulkError(b"x\ny".to_vec());
        assert_eq!(Value::parse(&value.to_bytes().unwrap()), Ok(value));
    }

    /// A random value, optionally limited to RESP2 types.
    fn random(r: &mut Lcg, depth: usize, resp2: bool) -> Value {
        let kinds = if resp2 { 7 } else { 16 };
        let k = r.index(if depth >= 4 { 7 } else { kinds });
        let k = if resp2 { [0, 1, 2, 3, 5, 4, 6][k] } else { k };
        let line = |r: &mut Lcg| r.text(8).into_bytes();
        match k {
            0 => Value::Simple(line(r)),
            1 => Value::Error(line(r)),
            2 => Value::Integer(r.next() as i64 - (1 << 30)),
            3 => Value::Bulk(r.bytes(12)),
            4 => Value::Null,
            5 if resp2 => Value::NullArray,
            5 => Value::Boolean(r.coin()),
            6 if resp2 => Value::Array((0..r.index(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            6 => Value::Double([0.0, -1.5, 1e300, 1e-300, f64::INFINITY, 0.1][r.index(6)]),
            7 => Value::BigNumber(format!("{}{}", ["", "-", "+"][r.index(3)], r.next())),
            8 => Value::BulkError(r.bytes(12)),
            9 => Value::Verbatim { format: *b"mkd", text: r.bytes(12) },
            10 => Value::Array((0..r.index(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            11 => Value::Set((0..r.index(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            // A push comes only at the top level, and starts with a string.
            12 if depth == 0 => Value::Push(
                std::iter::once(Value::Bulk(r.bytes(6))).chain((0..r.index(3)).map(|_| random(r, 1, resp2))).collect(),
            ),
            12 => Value::Array((0..r.index(4)).map(|_| random(r, depth + 1, resp2)).collect()),
            13 => Value::Map(
                (0..r.index(3)).map(|_| (random(r, depth + 1, resp2), random(r, depth + 1, resp2))).collect(),
            ),
            14 => Value::Attribute {
                attributes: (0..r.index(3))
                    .map(|_| (random(r, depth + 1, resp2), random(r, depth + 1, resp2)))
                    .collect(),
                value: Box::new(random(r, depth + 1, resp2)),
            },
            _ => Value::Integer(0),
        }
    }

    #[test]
    fn round_trips() {
        let mut r = Lcg::new(7);
        for _ in 0..2000 {
            for resp2 in [true, false] {
                let value = random(&mut r, 0, resp2);
                contract::check_wire_value(&value);
                let bytes = value.to_bytes().unwrap();
                assert_eq!(Value::parse(&bytes), Ok(value));
            }
            let command = Command { args: (0..r.index(5)).map(|_| r.bytes(10)).collect() };
            contract::check_wire_value(&command);
            assert_eq!(Command::parse(&command.to_bytes().unwrap()), Ok(command));
        }
    }

    /// A random input: random bytes from RESP's alphabet, or a valid
    /// encoding with a few bytes changed, added, removed or cut.
    fn fuzz_input(r: &mut Lcg) -> Vec<u8> {
        const ALPHABET: &[u8] = b"+-:$*_#,(!=%~|>;.?\r\n\r\n0123456789-tfinax \"'\\\0";
        if r.index(3) == 0 {
            return (0..r.index(40)).map(|_| ALPHABET[r.index(ALPHABET.len())]).collect();
        }
        let mut b = if r.index(4) == 0 {
            VALID[r.index(VALID.len())].to_vec()
        } else if r.index(3) == 0 {
            let mut out = Vec::new();
            let v = random(r, 0, false);
            streamed(r, &v, &mut out);
            out
        } else {
            random(r, 0, false).to_bytes().unwrap()
        };
        for _ in 0..r.index(4) {
            mutate(r, &mut b);
        }
        b
    }

    /// `v` in RESP3, with each array, set, map and bulk string streamed
    /// or not at random, a streamed string in random chunks.
    fn streamed(r: &mut Lcg, v: &Value, out: &mut Vec<u8>) {
        let stream = r.index(2) == 0;
        match v {
            Value::Bulk(d) if stream => {
                out.extend_from_slice(b"$?\r\n");
                let mut rest = &d[..];
                while !rest.is_empty() {
                    let n = 1 + r.index(rest.len());
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
            v => v.write(out).unwrap(),
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut r = Lcg::new(0x5eed);
        let small = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 30 };
        let rounds = std::env::var("RESP_FUZZ_ROUNDS").ok().and_then(|n| n.parse().ok()).unwrap_or(5000);
        for _ in 0..rounds {
            let mut b = Vec::new();
            for _ in 0..1 + r.index(3) {
                match r.index(4) {
                    0 => Command { args: (0..r.index(4)).map(|_| r.bytes(6)).collect() }.write(&mut b).unwrap(),
                    1 => b.extend_from_slice([&b"GET k\r\n"[..], b"SET \"a b\" 'c'\n", b"\r\n", b"*0\r\n"][r.index(4)]),
                    _ => b.extend(fuzz_input(&mut r)),
                }
            }
            if r.index(3) == 0 {
                mutate(&mut r, &mut b);
            }
            for limits in [Limits::DEFAULT, small] {
                check_values(&b, limits);
                check_commands(&b, limits);
            }
            // NaN compares through its canonical wire bytes.
            if let Ok(value) = Value::parse(&b) {
                let bytes = value.to_bytes().unwrap();
                assert_eq!(Value::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
            }
            contract::check_wire::<Command>(&b);
        }
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
            assert_eq!(Value::parse(b), Err(WireError::Parse(ParseError::Malformed(b','))), "{}", b.escape_ascii());
        }
    }

    /// An inline command of exactly the longest line is read whether its
    /// line ends with LF or CR LF.
    #[test]
    fn inline_line_limit_counts_text_only() {
        let lim = Limits { max_line_len: 10, ..Limits::DEFAULT };
        assert_eq!(command_step(b"0123456789\n", lim), Ok(Decoded::Item(Command::new(["0123456789"]), 11)));
        assert_eq!(command_step(b"0123456789\r\n", lim), Ok(Decoded::Item(Command::new(["0123456789"]), 12)));
        assert_eq!(command_step(b"0123456789\r", lim), Ok(Decoded::Need));
        assert_eq!(command_step(b"01234567890", lim), Err(ParseError::LineTooLong));
        assert_eq!(command_step(b"0123456789x", lim), Err(ParseError::LineTooLong));
        assert_eq!(command_step(b"01234567890\n", lim), Err(ParseError::LineTooLong));
        assert_eq!(command_step(b"01234567890\r\n", lim), Err(ParseError::LineTooLong));
    }

    /// An inline argument is held to the bulk limit, like an argument in
    /// an array.
    #[test]
    fn inline_arguments_keep_the_bulk_limit() {
        let lim = Limits { max_bulk_len: 8, ..Limits::DEFAULT };
        for bytes in [&b"GET 12345678\r\n"[..], b"GET \"123\\x41\\x42678\"\r\n"] {
            let expected = Command::parse(bytes).unwrap();
            assert_eq!(command_step(bytes, lim), Ok(Decoded::Item(expected, bytes.len())));
            check_commands(bytes, lim);
        }
        for bytes in [&b"GET 123456789\r\n"[..], b"GET \"123\\x41\\x426789\"\r\n"] {
            assert_eq!(command_step(bytes, lim), Err(ParseError::BulkTooLong));
            check_commands(bytes, lim);
        }
    }

    /// A command's array count is a number as Redis's string2ll reads it:
    /// no `+`, as the value reader also refuses.
    #[test]
    fn command_count_has_no_plus() {
        assert_eq!(Value::parse(b"*+1\r\n$1\r\na\r\n"), Err(WireError::Parse(ParseError::BadLength)));
        assert_eq!(Command::parse(b"*+1\r\n$1\r\na\r\n"), Err(WireError::Parse(ParseError::TooManyElements)));
        assert_eq!(Command::parse(b"*-1\r\n"), Ok(Command::default()));
    }

    /// Parsing all the bytes at once gives what a decoder receiving
    /// chunks gives, also when a frame runs over the limit.
    #[test]
    fn frame_limit_gives_one_answer() {
        let limits = Limits { max_frame_len: 10, ..Limits::DEFAULT };
        for b in [&b"*2\r\n+0123456789\r\nX"[..], b"*1\r\n$7\r\nabcdefgXY", b"*2\r\n:1\r\n:22\r\n:3\r\n"] {
            check_values(b, limits);
            assert_eq!(decode_all(|| Values::with_limits(limits), b),
                (vec![], Some(codec::Fail::Protocol(ParseError::FrameTooLarge))));
        }
        let limits = Limits { max_frame_len: 12, ..Limits::DEFAULT };
        let b = b"*1\r\n$4\r\nabcdXY";
        check_commands(b, limits);
        assert_eq!(decode_all(|| Commands::with_limits(limits), b),
            (vec![], Some(codec::Fail::Protocol(ParseError::FrameTooLarge))));
    }

    /// Malformed and truncated inputs keep their results across chunk schedules.
    #[test]
    fn contracts_cover_malformed_prefixes() {
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
            b"*1\r\n>1\r\n+a\r\n",
            b">1\r\n$-1\r\n",
            b">2\r\n$?\r\n;1\r\na\r\n;0\r\n:1\r\n",
            b"|1\r\n+k\r\n+v\r\n>1\r\n+a\r\n",
            b"|1\r\n>1\r\n+a\r\n+v\r\n:1\r\n",
            b"GE\0b\nPI\n",
            b"*01\r\n$1\r\na\r\n",
            b"*1\r\n$01\r\na\r\n",
            b"+abcdef\r\n",
            b"+abcdefg\r\n",
            b"*1\r\n$1234567\r\n",
        ];
        for b in inputs {
            check_values(b, lim);
            check_commands(b, lim);
        }
    }

    /// One big value receiving a few bytes at a time takes linear time: the
    /// decoder does not read its first elements again after every push.
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
        check_values(&values, Limits::DEFAULT);
        let (got, error) = decode_all(Values::new, &values);
        assert_eq!(error, None);
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], Value::Array(vec![Value::Null; N]));
        let Value::Attribute { attributes, value } = &got[1] else { panic!() };
        assert!(matches!(&attributes[..], [(_, Value::Map(e))] if e.len() == N));
        assert_eq!(**value, s("v"));
        let streamed = Value::Array(vec![Value::Set(vec![Value::Map(vec![(bulk("x"), bulk("x")); 4])])]);
        assert_eq!(got[2], streamed);
        assert_eq!(got[3], Value::Bulk(vec![b'x'; N]));
        // Commands, likewise.
        let mut c = format!("*{N}\r\n").into_bytes();
        c.extend(std::iter::repeat_n(&b"$1\r\nx\r\n"[..], N).flatten());
        check_commands(&c, Limits::DEFAULT);
        let (commands, error) = decode_all(Commands::new, &c);
        assert_eq!(error, None);
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].args.len(), N);
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "{:?}", start.elapsed());
    }

    /// One long line receiving a byte at a time takes linear time: the decoder
    /// searches only the new bytes for the line's end.
    #[test]
    fn stream_is_linear_in_one_long_line() {
        let start = std::time::Instant::now();
        let n = MAX_LINE_LEN - 2;
        for (lead, byte) in [(&b"+"[..], b'a'), (b"$", b'1')] {
            let mut bytes = lead.to_vec();
            bytes.extend(std::iter::repeat_n(byte, n));
            bytes.extend_from_slice(b"\r\n");
            check_values(&bytes, Limits::DEFAULT);
            let (items, error) = decode_all(Values::new, &bytes);
            assert_eq!(items.len(), usize::from(byte == b'a'));
            assert_eq!(error.is_none(), byte == b'a');
        }
        for (lead, byte, end) in [(&b"x"[..], b'a', &b"\n"[..]), (b"*1\r\n$", b'1', b"\r\n")] {
            let mut bytes = lead.to_vec();
            bytes.extend(std::iter::repeat_n(byte, n));
            bytes.extend_from_slice(end);
            check_commands(&bytes, Limits::DEFAULT);
            let (items, error) = decode_all(Commands::new, &bytes);
            assert_eq!(items.len(), usize::from(byte == b'a'));
            assert_eq!(error.is_none(), byte == b'a');
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(20), "{:?}", start.elapsed());
    }

    /// Attributes retain every entry and their value, or writing fails.
    #[test]
    fn attributes_are_preserved_or_refused() {
        let attr = Value::Attribute { attributes: vec![(s("k"), s("v"))], value: Box::new(bulk("0123456789")) };
        assert_eq!(attr.to_bytes().unwrap(), b"|1\r\n+k\r\n+v\r\n$10\r\n0123456789\r\n");
        contract::check_wire_value(&attr);
        let big = Value::Attribute {
            attributes: (0..3).map(|_| (Value::Bulk(vec![0; MAX_BULK_LEN]), Value::Null)).collect(),
            value: Box::new(Value::Bulk(vec![1; MAX_BULK_LEN])),
        };
        assert_eq!(big.to_bytes(), Err(WireError::Unwritable));
        contract::check_wire_value(&big);
        let attr = Value::Attribute {
            attributes: vec![(s("k"), s("v"))],
            value: Box::new(Value::Array(vec![bulk("0123456789"); 3])),
        };
        contract::check_wire_value(&attr);
        assert_eq!(Value::parse(&attr.to_bytes().unwrap()), Ok(attr));
    }

    /// A depth limit set very high still cannot overflow the stack.
    #[test]
    fn depth_has_a_ceiling() {
        let limits = Limits { max_depth: 100_000, ..Limits::DEFAULT };
        let mut b = b"*1\r\n".repeat(100_000);
        b.extend_from_slice(b"_\r\n");
        check_values(&b, limits);
        assert_eq!(value_step(&b, limits), Err(ParseError::TooDeep));
        let mut ok = b"*1\r\n".repeat(DEPTH_CEILING);
        ok.extend_from_slice(b"_\r\n");
        assert!(matches!(value_step(&ok, limits), Ok(Decoded::Item(_, _))));
    }

    /// Nested aggregates that claim many elements reserve little before
    /// their elements come.
    #[test]
    fn aggregates_reserve_little_up_front() {
        let rest = vec![b'x'; 3 * MAX_ELEMENTS];
        assert!(capacity(&rest, 0, MAX_ELEMENTS, 3) <= PREALLOC);
        let mut b = b"*1048576\r\n".repeat(32);
        b.extend_from_slice(&rest);
        assert_eq!(Value::parse(&b), Err(WireError::Parse(ParseError::UnknownType(b'x'))));
    }

    /// What exactly fills the frame limit is written whole.
    #[test]
    fn writers_fill_the_frame_exactly() {
        let command = Command::new(["a"; 3]);
        assert_eq!(command.to_bytes().unwrap().len(), 25);
        let array = Value::Array(vec![bulk("a"); 3]);
        assert_eq!(array.to_bytes().unwrap().len(), 25);
        let map = Value::Map(vec![(s("a"), s("b")); 2]);
        assert_eq!(map.to_bytes().unwrap(), b"%2\r\n+a\r\n+b\r\n+a\r\n+b\r\n");
        let b = MAX_BULK_LEN;
        let mut command = Command { args: vec![b"MGET".to_vec(), vec![0; b], vec![1; b], vec![2; b], vec![3; b - 66]] };
        let bytes = command.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_FRAME_LEN);
        assert_eq!(Command::parse(&bytes), Ok(command.clone()));
        command.args[4].push(3);
        assert_eq!(command.to_bytes(), Err(WireError::Unwritable));
        let value = command.to_value();
        assert_eq!(value.to_bytes(), Err(WireError::Unwritable));
    }

    /// Pushing while values wait preserves the complete backlog.
    #[test]
    fn stream_keeps_a_backlog() {
        const N: usize = 1000;
        let mut d = Stream::new(Values::new());
        assert_eq!(d.push(&b"_\r\n".repeat(N)), 3 * N);
        let mut got = 0;
        for _ in 0..N {
            assert_eq!(d.next(), Some(Ok(Value::Null)));
            got += 1;
            assert_eq!(d.push(b"_\r\n"), 3);
        }
        while let Some(value) = d.next() {
            assert_eq!(value, Ok(Value::Null));
            got += 1;
        }
        assert_eq!(got, 2 * N);
        assert_eq!(d.buffered(), 0);
        d.end();
        assert_eq!(d.next(), None);
    }

    /// A push starts with a string and comes only at the top level,
    /// perhaps after an attribute.
    #[test]
    fn pushes_follow_the_specification() {
        for b in [
            &b">0\r\n"[..],
            b">1\r\n:1\r\n",
            b">1\r\n$-1\r\n",
            b">2\r\n*1\r\n+a\r\n+b\r\n",
            b"*1\r\n>1\r\n+a\r\n",
            b"%1\r\n+k\r\n>1\r\n+a\r\n",
            b"|1\r\n+k\r\n>1\r\n+a\r\n+v\r\n",
        ] {
            assert_eq!(Value::parse(b), Err(WireError::Parse(ParseError::Malformed(b'>'))), "{}", b.escape_ascii());
            check_values(b, Limits::DEFAULT);
            assert_eq!(decode_all(Values::new, b), (vec![], Some(codec::Fail::Protocol(ParseError::Malformed(b'>')))));
        }
        for b in [
            &b">1\r\n+a\r\n"[..],
            b">2\r\n$?\r\n;1\r\na\r\n;0\r\n:1\r\n",
            b">1\r\n=5\r\ntxt:a\r\n",
            b"|1\r\n+k\r\n+v\r\n>2\r\n$1\r\na\r\n*0\r\n",
        ] {
            one(b);
        }
        // Invalid pushes are refused without changing their type.
        assert_eq!(Value::Push(vec![Value::Integer(1)]).to_bytes(), Err(WireError::Unwritable));
        assert_eq!(Value::Push(vec![]).to_bytes(), Err(WireError::Unwritable));
        let nested = Value::Array(vec![Value::Push(vec![s("a")])]);
        assert_eq!(nested.to_bytes(), Err(WireError::Unwritable));
        let attr = Value::Attribute { attributes: vec![], value: Box::new(Value::Push(vec![bulk("a")])) };
        assert_eq!(attr.to_bytes().unwrap(), b"|0\r\n>1\r\n$1\r\na\r\n");
    }

    /// Redis looks for an inline command's LF with strchr, which stops at
    /// a NUL: after a NUL the line never ends, and runs into the limit.
    #[test]
    fn inline_nul_hides_the_line_end() {
        assert_eq!(Command::parse(b"GET a\0b\nPING\n"), Err(WireError::Incomplete));
        let limits = Limits { max_line_len: 12, ..Limits::DEFAULT };
        assert_eq!(command_step(b"GET a\0b\nPING\n", limits), Err(ParseError::LineTooLong));
        assert_eq!(command_step(b"GET a\0b\nPIN\n", limits), Ok(Decoded::Need));
        check_commands(b"GET a\0b\nPING\n", limits);
        assert_eq!(decode_all(|| Commands::with_limits(limits), b"GET a\0b\nPING\n"),
            (vec![], Some(codec::Fail::Protocol(ParseError::LineTooLong))));
    }

    /// A command's counts and lengths are numbers as Redis's string2ll
    /// reads them: no leading zero and no `-0`.
    #[test]
    fn command_numbers_follow_string2ll() {
        assert_eq!(Command::parse(b"*01\r\n$4\r\nPING\r\n"), Err(WireError::Parse(ParseError::TooManyElements)));
        assert_eq!(Command::parse(b"*-0\r\n"), Err(WireError::Parse(ParseError::TooManyElements)));
        assert_eq!(Command::parse(b"*00\r\n"), Err(WireError::Parse(ParseError::TooManyElements)));
        assert_eq!(Command::parse(b"*1\r\n$04\r\nPING\r\n"), Err(WireError::Parse(ParseError::BulkTooLong)));
        assert_eq!(Command::parse(b"*1\r\n$-0\r\n"), Err(WireError::Parse(ParseError::BulkTooLong)));
        assert_eq!(Command::parse(b"*1\r\n$0\r\n\r\n"), Ok(Command::new([""])));
        assert_eq!(Command::parse(b"*0\r\n"), Ok(Command::default()));
        assert_eq!(Command::parse(b"*-12\r\n"), Ok(Command::default()));
        for b in [&b"*01\r\n$4\r\nPING\r\n"[..], b"*1\r\n$04\r\nPING\r\n"] {
            check_commands(b, Limits::DEFAULT);
            assert!(matches!(decode_all(Commands::new, b).1, Some(codec::Fail::Protocol(_))));
        }
    }
}
